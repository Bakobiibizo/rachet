//! Deterministic fault scheduling over Commonware's real simulated P2P network.
//!
//! The supported corrupted-peer behavior is an authenticated peer sending arbitrary
//! application bytes under its own identity. Commonware 2026.7.0 does not expose
//! identity spoofing, unauthenticated injection, or in-flight payload mutation, so
//! those modes are reported by [`UNSUPPORTED_CORRUPTION_MODES`] and are not mocked.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    num::{NonZeroU32, NonZeroUsize},
    sync::{Arc, Mutex},
    time::Duration,
};

use commonware_cryptography::{Signer as _, ed25519};
use commonware_p2p::{
    Receiver as _, Recipients, Sender as _,
    simulated::{Config as CommonwareConfig, Link as CommonwareLink, Network, Oracle},
};
use commonware_runtime::{
    Clock as _, Quota, Runner as _, Spawner as _, Supervisor as _, deterministic,
};

const CHANNEL_FRAME_BYTES: u32 = size_of::<u64>() as u32;
const PEER_SEED_NAMESPACE: u64 = 0x5241_4348_4554_5032;

/// Corruption modes unavailable from the pinned Commonware simulated network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedCorruptionMode {
    IdentitySpoofing,
    UnauthenticatedInjection,
    InFlightPayloadMutation,
}

/// Machine-readable documentation of corruption modes that the lab does not fake.
pub const UNSUPPORTED_CORRUPTION_MODES: &[UnsupportedCorruptionMode] = &[
    UnsupportedCorruptionMode::IdentitySpoofing,
    UnsupportedCorruptionMode::UnauthenticatedInjection,
    UnsupportedCorruptionMode::InFlightPayloadMutation,
];

/// Stable index of a simulated, authenticated peer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PeerId(pub u16);

/// Delivery properties for one directed Commonware link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkCondition {
    latency_ms: u64,
    jitter_ms: u64,
    drop_basis_points: u16,
}

impl LinkCondition {
    /// Constructs a link condition. Drop rate is in basis points and may be 10,000.
    pub fn new(
        latency_ms: u64,
        jitter_ms: u64,
        drop_basis_points: u16,
    ) -> Result<Self, P2pLabError> {
        if drop_basis_points > 10_000 {
            return Err(P2pLabError::InvalidDropBasisPoints(drop_basis_points));
        }
        Ok(Self {
            latency_ms,
            jitter_ms,
            drop_basis_points,
        })
    }

    /// Constructs a lossless link with the given latency and no jitter.
    #[must_use]
    pub const fn lossless(latency_ms: u64) -> Self {
        Self {
            latency_ms,
            jitter_ms: 0,
            drop_basis_points: 0,
        }
    }

    #[must_use]
    pub const fn latency_ms(self) -> u64 {
        self.latency_ms
    }

    #[must_use]
    pub const fn jitter_ms(self) -> u64 {
        self.jitter_ms
    }

    #[must_use]
    pub const fn drop_basis_points(self) -> u16 {
        self.drop_basis_points
    }

    fn commonware(self) -> CommonwareLink {
        CommonwareLink {
            latency: Duration::from_millis(self.latency_ms),
            jitter: Duration::from_millis(self.jitter_ms),
            success_rate: f64::from(10_000 - self.drop_basis_points) / 10_000.0,
        }
    }
}

/// One topology mutation or transmission in a deterministic schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkAction {
    /// Reconfigure one directed link, exposing latency, jitter, and message drops.
    SetLink {
        from: PeerId,
        to: PeerId,
        condition: LinkCondition,
    },
    /// Remove every inbound and outbound link for a peer.
    Disconnect { peer: PeerId },
    /// Restore a peer's configured links, subject to any active partition.
    Reconnect { peer: PeerId },
    /// Split all peers into two nonempty groups and remove cross-group links.
    Partition {
        left: Vec<PeerId>,
        right: Vec<PeerId>,
    },
    /// Restore configured cross-group links after a partition.
    HealPartition,
    /// Send ordinary application bytes over the real simulated P2P sender.
    Send {
        from: PeerId,
        to: PeerId,
        payload: Vec<u8>,
    },
    /// Have an authenticated Byzantine peer send arbitrary bytes under its own identity.
    CorruptedPeerSend {
        from: PeerId,
        to: PeerId,
        payload: Vec<u8>,
    },
}

/// One action at a millisecond offset from network startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledNetworkEvent {
    pub at_ms: u64,
    pub action: NetworkAction,
}

impl ScheduledNetworkEvent {
    #[must_use]
    pub const fn new(at_ms: u64, action: NetworkAction) -> Self {
        Self { at_ms, action }
    }
}

/// Ordered, replayable network fault and traffic declaration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FaultSchedule {
    events: Vec<ScheduledNetworkEvent>,
}

impl FaultSchedule {
    pub fn new(events: Vec<ScheduledNetworkEvent>) -> Result<Self, P2pLabError> {
        for pair in events.windows(2) {
            if pair[0].at_ms > pair[1].at_ms {
                return Err(P2pLabError::NonMonotonicSchedule {
                    previous_ms: pair[0].at_ms,
                    next_ms: pair[1].at_ms,
                });
            }
        }
        Ok(Self { events })
    }

    #[must_use]
    pub fn events(&self) -> &[ScheduledNetworkEvent] {
        &self.events
    }
}

/// Fixed inputs for one bounded deterministic network run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pLabConfig {
    pub seed: u64,
    pub peer_count: u16,
    pub channel: u64,
    pub max_frame_size: u32,
    pub default_link: LinkCondition,
    /// Simulated time allowed for the final transmission to arrive.
    pub settle_ms: u64,
}

impl P2pLabConfig {
    #[must_use]
    pub const fn new(seed: u64, peer_count: u16, default_link: LinkCondition) -> Self {
        Self {
            seed,
            peer_count,
            channel: 0,
            max_frame_size: 1024 * 1024,
            default_link,
            settle_ms: 1_000,
        }
    }
}

/// A locally accepted scheduled transmission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Submission {
    pub event_index: usize,
    pub at_ms: u64,
    pub from: PeerId,
    pub to: PeerId,
    pub corrupted_peer: bool,
    pub accepted: bool,
    pub payload: Vec<u8>,
}

/// Bytes delivered by Commonware's network, with authenticated origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    pub received_at_ms: u64,
    pub from: PeerId,
    pub to: PeerId,
    pub payload: Vec<u8>,
}

/// Complete deterministic evidence from one network schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pRunOutput {
    pub submissions: Vec<Submission>,
    pub deliveries: Vec<Delivery>,
    pub runtime_audit: String,
}

/// Executes fault schedules with `commonware_p2p::simulated` and the deterministic runtime.
pub struct SimulatedP2pLab;

impl SimulatedP2pLab {
    pub fn run(config: P2pLabConfig, schedule: FaultSchedule) -> Result<P2pRunOutput, P2pLabError> {
        validate(&config, &schedule)?;
        let seed = config.seed;
        deterministic::Runner::seeded(seed).start(|context| async move {
            let keys = (0..config.peer_count)
                .map(|index| {
                    ed25519::PrivateKey::from_seed(
                        PEER_SEED_NAMESPACE ^ seed.wrapping_add(u64::from(index)),
                    )
                    .public_key()
                })
                .collect::<Vec<_>>();
            let key_to_peer = keys
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, key)| (key, PeerId(index as u16)))
                .collect::<BTreeMap<_, _>>();
            let network_config = CommonwareConfig {
                max_size: config.max_frame_size,
                disconnect_on_block: true,
                tracked_peer_sets: NonZeroUsize::MIN,
            };
            let (network, oracle) = Network::new_with_peers(
                context.child("simulated_p2p"),
                network_config,
                keys.clone(),
            )
            .await;
            let network_handle = network.start();

            let quota = Quota::per_second(NonZeroU32::MAX);
            let mut senders = Vec::with_capacity(keys.len());
            let mut receivers = Vec::with_capacity(keys.len());
            for key in keys.iter().cloned() {
                let (sender, receiver) = oracle
                    .control(key)
                    .register(config.channel, quota)
                    .await
                    .map_err(commonware_error)?;
                senders.push(sender);
                receivers.push(receiver);
            }

            let mut topology = Topology::fully_connected(config.peer_count, config.default_link);
            reconcile(&oracle, &keys, &mut topology).await?;

            let deliveries = Arc::new(Mutex::new(Vec::new()));
            let started_at = context.current();
            let mut receiver_handles = Vec::with_capacity(keys.len());
            for (index, mut receiver) in receivers.into_iter().enumerate() {
                let receiver_deliveries = deliveries.clone();
                let receiver_keys = key_to_peer.clone();
                let receiver_start = started_at;
                let recipient = PeerId(index as u16);
                let handle = context
                    .child("receiver")
                    .spawn(move |receiver_context| async move {
                        while let Ok((origin, payload)) = receiver.recv().await {
                            let Some(from) = receiver_keys.get(&origin).copied() else {
                                continue;
                            };
                            let received_at_ms = receiver_context
                                .current()
                                .duration_since(receiver_start)
                                .unwrap_or_default()
                                .as_millis()
                                .try_into()
                                .unwrap_or(u64::MAX);
                            receiver_deliveries
                                .lock()
                                .expect("delivery collector lock must remain healthy")
                                .push(Delivery {
                                    received_at_ms,
                                    from,
                                    to: recipient,
                                    payload: payload.as_ref().to_vec(),
                                });
                        }
                    });
                receiver_handles.push(handle);
            }
            let mut submissions = Vec::new();
            let mut previous_ms = 0;

            for (event_index, event) in schedule.events.into_iter().enumerate() {
                context
                    .sleep(Duration::from_millis(event.at_ms - previous_ms))
                    .await;
                previous_ms = event.at_ms;
                match event.action {
                    NetworkAction::SetLink {
                        from,
                        to,
                        condition,
                    } => {
                        topology.baseline.insert((from, to), condition);
                        reconcile(&oracle, &keys, &mut topology).await?;
                    }
                    NetworkAction::Disconnect { peer } => {
                        topology.disconnected.insert(peer);
                        reconcile(&oracle, &keys, &mut topology).await?;
                    }
                    NetworkAction::Reconnect { peer } => {
                        topology.disconnected.remove(&peer);
                        reconcile(&oracle, &keys, &mut topology).await?;
                    }
                    NetworkAction::Partition { left, right } => {
                        topology.partition =
                            Some((left.into_iter().collect(), right.into_iter().collect()));
                        reconcile(&oracle, &keys, &mut topology).await?;
                    }
                    NetworkAction::HealPartition => {
                        topology.partition = None;
                        reconcile(&oracle, &keys, &mut topology).await?;
                    }
                    NetworkAction::Send { from, to, payload } => submit(
                        &mut senders,
                        &keys,
                        &mut submissions,
                        Submission {
                            event_index,
                            at_ms: event.at_ms,
                            from,
                            to,
                            corrupted_peer: false,
                            accepted: false,
                            payload,
                        },
                    ),
                    NetworkAction::CorruptedPeerSend { from, to, payload } => submit(
                        &mut senders,
                        &keys,
                        &mut submissions,
                        Submission {
                            event_index,
                            at_ms: event.at_ms,
                            from,
                            to,
                            corrupted_peer: true,
                            accepted: false,
                            payload,
                        },
                    ),
                }
            }

            context.sleep(Duration::from_millis(config.settle_ms)).await;
            let runtime_audit = context.auditor().state();
            for handle in receiver_handles {
                handle.abort();
                let _ = handle.await;
            }
            network_handle.abort();
            let _ = network_handle.await;

            let mut deliveries = Arc::try_unwrap(deliveries)
                .map_err(|_| P2pLabError::Runtime("delivery collectors remained live".to_owned()))?
                .into_inner()
                .map_err(|_| {
                    P2pLabError::Runtime("delivery collector lock was poisoned".to_owned())
                })?;
            deliveries.sort_by(|left, right| {
                (
                    left.received_at_ms,
                    left.to,
                    left.from,
                    left.payload.as_slice(),
                )
                    .cmp(&(
                        right.received_at_ms,
                        right.to,
                        right.from,
                        right.payload.as_slice(),
                    ))
            });
            Ok(P2pRunOutput {
                submissions,
                deliveries,
                runtime_audit,
            })
        })
    }
}

fn submit<E: commonware_runtime::Clock>(
    senders: &mut [commonware_p2p::simulated::Sender<ed25519::PublicKey, E>],
    keys: &[ed25519::PublicKey],
    submissions: &mut Vec<Submission>,
    mut submission: Submission,
) {
    let recipient = keys[usize::from(submission.to.0)].clone();
    let recipients = senders[usize::from(submission.from.0)].send(
        Recipients::One(recipient.clone()),
        submission.payload.clone(),
        false,
    );
    submission.accepted = recipients == [recipient];
    submissions.push(submission);
}

struct Topology {
    baseline: BTreeMap<(PeerId, PeerId), LinkCondition>,
    active: BTreeMap<(PeerId, PeerId), LinkCondition>,
    disconnected: BTreeSet<PeerId>,
    partition: Option<(BTreeSet<PeerId>, BTreeSet<PeerId>)>,
}

impl Topology {
    fn fully_connected(peer_count: u16, condition: LinkCondition) -> Self {
        let mut baseline = BTreeMap::new();
        for from in 0..peer_count {
            for to in 0..peer_count {
                if from != to {
                    baseline.insert((PeerId(from), PeerId(to)), condition);
                }
            }
        }
        Self {
            baseline,
            active: BTreeMap::new(),
            disconnected: BTreeSet::new(),
            partition: None,
        }
    }

    fn desired(&self) -> BTreeMap<(PeerId, PeerId), LinkCondition> {
        self.baseline
            .iter()
            .filter(|((from, to), _)| {
                !self.disconnected.contains(from)
                    && !self.disconnected.contains(to)
                    && self.partition.as_ref().is_none_or(|(left, right)| {
                        (left.contains(from) && left.contains(to))
                            || (right.contains(from) && right.contains(to))
                    })
            })
            .map(|(pair, condition)| (*pair, *condition))
            .collect()
    }
}

async fn reconcile<E: commonware_runtime::Clock>(
    oracle: &Oracle<ed25519::PublicKey, E>,
    keys: &[ed25519::PublicKey],
    topology: &mut Topology,
) -> Result<(), P2pLabError> {
    let desired = topology.desired();
    let removals = topology
        .active
        .iter()
        .filter(|(pair, condition)| desired.get(pair) != Some(condition))
        .map(|(pair, _)| *pair)
        .collect::<Vec<_>>();
    let additions = desired
        .iter()
        .filter(|(pair, condition)| topology.active.get(pair) != Some(condition))
        .map(|(pair, condition)| (*pair, *condition))
        .collect::<Vec<_>>();

    for (from, to) in removals {
        oracle
            .remove_link(
                keys[usize::from(from.0)].clone(),
                keys[usize::from(to.0)].clone(),
            )
            .await
            .map_err(commonware_error)?;
        topology.active.remove(&(from, to));
    }
    for ((from, to), condition) in additions {
        oracle
            .add_link(
                keys[usize::from(from.0)].clone(),
                keys[usize::from(to.0)].clone(),
                condition.commonware(),
            )
            .await
            .map_err(commonware_error)?;
        topology.active.insert((from, to), condition);
    }
    Ok(())
}

fn validate(config: &P2pLabConfig, schedule: &FaultSchedule) -> Result<(), P2pLabError> {
    if config.peer_count < 2 {
        return Err(P2pLabError::TooFewPeers(config.peer_count));
    }
    if config.max_frame_size <= CHANNEL_FRAME_BYTES {
        return Err(P2pLabError::FrameSizeTooSmall(config.max_frame_size));
    }
    let max_payload = (config.max_frame_size - CHANNEL_FRAME_BYTES) as usize;
    for event in &schedule.events {
        match &event.action {
            NetworkAction::SetLink { from, to, .. } => {
                validate_pair(config.peer_count, *from, *to)?;
            }
            NetworkAction::Disconnect { peer } | NetworkAction::Reconnect { peer } => {
                validate_peer(config.peer_count, *peer)?;
            }
            NetworkAction::Partition { left, right } => {
                if left.is_empty() || right.is_empty() {
                    return Err(P2pLabError::InvalidPartition);
                }
                let mut seen = BTreeSet::new();
                for peer in left.iter().chain(right) {
                    validate_peer(config.peer_count, *peer)?;
                    if !seen.insert(*peer) {
                        return Err(P2pLabError::InvalidPartition);
                    }
                }
                if seen.len() != usize::from(config.peer_count) {
                    return Err(P2pLabError::InvalidPartition);
                }
            }
            NetworkAction::HealPartition => {}
            NetworkAction::Send { from, to, payload }
            | NetworkAction::CorruptedPeerSend { from, to, payload } => {
                validate_pair(config.peer_count, *from, *to)?;
                if payload.len() > max_payload {
                    return Err(P2pLabError::PayloadTooLarge {
                        size: payload.len(),
                        maximum: max_payload,
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_pair(peer_count: u16, from: PeerId, to: PeerId) -> Result<(), P2pLabError> {
    validate_peer(peer_count, from)?;
    validate_peer(peer_count, to)?;
    if from == to {
        return Err(P2pLabError::SelfLink(from));
    }
    Ok(())
}

fn validate_peer(peer_count: u16, peer: PeerId) -> Result<(), P2pLabError> {
    if peer.0 >= peer_count {
        return Err(P2pLabError::UnknownPeer(peer));
    }
    Ok(())
}

fn commonware_error(error: commonware_p2p::simulated::Error) -> P2pLabError {
    P2pLabError::Runtime(error.to_string())
}

/// Invalid schedule/configuration or a Commonware network failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum P2pLabError {
    InvalidDropBasisPoints(u16),
    NonMonotonicSchedule { previous_ms: u64, next_ms: u64 },
    TooFewPeers(u16),
    FrameSizeTooSmall(u32),
    UnknownPeer(PeerId),
    SelfLink(PeerId),
    InvalidPartition,
    PayloadTooLarge { size: usize, maximum: usize },
    Runtime(String),
}

impl fmt::Display for P2pLabError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDropBasisPoints(value) => {
                write!(formatter, "drop rate {value} exceeds 10,000 basis points")
            }
            Self::NonMonotonicSchedule {
                previous_ms,
                next_ms,
            } => write!(
                formatter,
                "network schedule moves backward from {previous_ms}ms to {next_ms}ms"
            ),
            Self::TooFewPeers(count) => write!(
                formatter,
                "network requires at least two peers, got {count}"
            ),
            Self::FrameSizeTooSmall(size) => write!(
                formatter,
                "frame size {size} cannot contain a channel prefix"
            ),
            Self::UnknownPeer(peer) => write!(formatter, "unknown simulated peer {}", peer.0),
            Self::SelfLink(peer) => {
                write!(formatter, "peer {} cannot link or send to itself", peer.0)
            }
            Self::InvalidPartition => formatter.write_str(
                "partition must contain every peer exactly once across two nonempty groups",
            ),
            Self::PayloadTooLarge { size, maximum } => {
                write!(formatter, "payload size {size} exceeds maximum {maximum}")
            }
            Self::Runtime(error) => write!(formatter, "simulated P2P failure: {error}"),
        }
    }
}

impl Error for P2pLabError {}
