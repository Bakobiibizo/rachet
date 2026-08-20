use commonware_actor::{
    Feedback,
    mailbox::{self, Policy, Sender},
};
use commonware_codec::Encode;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay, Reporter, Viewable as _,
    simplex::{
        self, Engine,
        config::{Config as SimplexConfig, Floor, ForwardingPolicy},
        elector::RoundRobin,
        scheme::ed25519 as simplex_ed25519,
        types::{Activity, Context as SimplexContext},
    },
    types::{Epoch, View, ViewDelta},
};
use commonware_cryptography::{
    Hasher as _, Sha256, Signer as _, ed25519, sha256::Digest as Sha256Digest,
};
use commonware_p2p::{
    Address, AddressableManager as _, Receiver as _, Recipients, Sender as _,
    authenticated::lookup,
    simulated::{Config as SimulatedConfig, Link, Network as SimulatedNetwork},
};
use commonware_runtime::{
    Clock, Quota, Runner as _, Spawner as _, Strategizer as _, Supervisor as _,
    buffer::paged::CacheRef, deterministic, telemetry::metrics::count_running_tasks,
};
use commonware_utils::{
    NZU16, NZU32, NZUsize,
    channel::{fallible::OneshotExt as _, oneshot},
    ordered::{Map, Set},
};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    num::NonZeroUsize,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

const EXPECTED_COMMONWARE_PACKAGES: &[&str] = &[
    "commonware-actor",
    "commonware-broadcast",
    "commonware-codec",
    "commonware-codec-macros",
    "commonware-coding",
    "commonware-conformance",
    "commonware-conformance-macros",
    "commonware-consensus",
    "commonware-cryptography",
    "commonware-formatting",
    "commonware-glue",
    "commonware-invariants",
    "commonware-macros",
    "commonware-macros-impl",
    "commonware-math",
    "commonware-p2p",
    "commonware-parallel",
    "commonware-resolver",
    "commonware-runtime",
    "commonware-runtime-macros",
    "commonware-storage",
    "commonware-stream",
    "commonware-utils",
];
const COMMONWARE_VERSION: &str = "2026.7.0";
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const REPLAY_SEED: u64 = 0x5241_4348_4554;
const EXPECTED_EVENTS: &[&str] = &[
    "event_actor:alpha:0",
    "event_actor:beta:0",
    "event_actor:beta:1",
    "event_actor:alpha:1",
    "event_actor:alpha:2",
    "event_actor:beta:2",
    "event_actor:stop",
];
const EXPECTED_RUNTIME_AUDIT: &str =
    "10f5d4043127419f2beb59158c7817998de636824d9ecc33f07cfa2694a1978e";

fn package_field<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    for line in block.lines().map(str::trim) {
        let Some((field, value)) = line.split_once(" = ") else {
            continue;
        };
        if field == key {
            return value.strip_prefix('"')?.strip_suffix('"');
        }
    }
    None
}

#[test]
fn locked_commonware_graph_matches_compatibility_baseline() {
    let lock_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let lock = fs::read_to_string(&lock_path).expect("workspace Cargo.lock must be readable");
    let mut packages = Vec::new();

    for block in lock.split("\n[[package]]") {
        let Some(name) = package_field(block, "name") else {
            continue;
        };
        if !name.starts_with("commonware-") {
            continue;
        }
        assert_eq!(
            package_field(block, "version"),
            Some(COMMONWARE_VERSION),
            "{name} must remain on the compatibility-tested Commonware release"
        );
        assert_eq!(
            package_field(block, "source"),
            Some(CRATES_IO_SOURCE),
            "{name} must remain registry-sourced; a Git revision requires a new spike decision"
        );
        packages.push(name);
    }

    packages.sort_unstable();
    assert_eq!(
        packages, EXPECTED_COMMONWARE_PACKAGES,
        "the complete locked Commonware package set is part of the compatibility baseline"
    );
}

#[derive(Debug)]
enum Message {
    Event {
        producer: &'static str,
        sequence: u8,
    },
    Stop,
}

impl Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Replay {
    events: Vec<String>,
    runtime_audit: String,
}

async fn produce(
    context: commonware_runtime::deterministic::Context,
    sender: Sender<Message>,
    producer: &'static str,
    pauses_ms: &[u64],
) {
    for (sequence, pause_ms) in pauses_ms.iter().copied().enumerate() {
        context.sleep(Duration::from_millis(pause_ms)).await;
        assert!(
            sender
                .enqueue(Message::Event {
                    producer,
                    sequence: u8::try_from(sequence).expect("test sequence fits in u8"),
                })
                .accepted(),
            "event actor mailbox must accept the bounded test workload"
        );
    }
}

fn replay(seed: u64) -> Replay {
    commonware_runtime::deterministic::Runner::seeded(seed).start(|context| async move {
        let trace = Arc::new(Mutex::new(Vec::new()));
        let actor_trace = Arc::clone(&trace);
        let (sender, mut receiver) = mailbox::new(
            context.child("event_mailbox"),
            NonZeroUsize::new(8).expect("mailbox capacity is non-zero"),
        );

        let actor = context.child("event_actor").spawn(move |_| async move {
            while let Some(message) = receiver.recv().await {
                match message {
                    Message::Event { producer, sequence } => actor_trace
                        .lock()
                        .expect("trace lock is not poisoned")
                        .push(format!("event_actor:{producer}:{sequence}")),
                    Message::Stop => {
                        actor_trace
                            .lock()
                            .expect("trace lock is not poisoned")
                            .push("event_actor:stop".to_string());
                        break;
                    }
                }
            }
        });

        let alpha = context.child("producer_alpha").spawn({
            let sender = sender.clone();
            move |producer_context| async move {
                produce(producer_context, sender, "alpha", &[0, 2, 1]).await;
            }
        });
        let beta = context.child("producer_beta").spawn({
            let sender = sender.clone();
            move |producer_context| async move {
                produce(producer_context, sender, "beta", &[1, 0, 2]).await;
            }
        });

        alpha.await.expect("alpha producer must exit cleanly");
        beta.await.expect("beta producer must exit cleanly");
        assert!(sender.enqueue(Message::Stop).accepted());
        actor.await.expect("event actor must exit cleanly");

        let events = Arc::into_inner(trace)
            .expect("all actor trace references must be dropped")
            .into_inner()
            .expect("trace lock is not poisoned");
        Replay {
            events,
            runtime_audit: context.auditor().state(),
        }
    })
}

#[test]
fn deterministic_runtime_actor_replays_declared_seed() {
    let first = replay(REPLAY_SEED);
    let second = replay(REPLAY_SEED);

    assert_eq!(first, second, "same-seed actor replay must be identical");
    assert_eq!(
        first.events.iter().map(String::as_str).collect::<Vec<_>>(),
        EXPECTED_EVENTS,
        "declared seed must retain its checked-in actor event trace"
    );
    assert_eq!(
        first.runtime_audit, EXPECTED_RUNTIME_AUDIT,
        "declared seed must retain its Commonware runtime audit"
    );
}

fn reserve_loopback_addresses(count: usize) -> Vec<SocketAddr> {
    let listeners = (0..count)
        .map(|_| {
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("the P2P smoke test must reserve a loopback port")
        })
        .collect::<Vec<_>>();
    listeners
        .iter()
        .map(|listener| {
            listener
                .local_addr()
                .expect("a reserved listener must have a local address")
        })
        .collect()
}

#[test]
fn authenticated_lookup_four_peer_exchange_rejects_unknown_and_stops_cleanly() {
    const COMMITTEE_SIZE: usize = 4;
    const CHANNEL: u64 = 7;
    const MAX_MESSAGE_SIZE: u32 = 1_024;
    const MESSAGE_BACKLOG: usize = 512;
    const CONNECT_ATTEMPTS: usize = 100;
    const UNKNOWN_ATTEMPTS: usize = 30;
    const RETRY_DELAY: Duration = Duration::from_millis(100);
    const RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
    const NAMESPACE: &[u8] = b"rachet/commonware-spike/authenticated-lookup/v1";

    let addresses = reserve_loopback_addresses(COMMITTEE_SIZE + 1);
    let addresses_after_shutdown = addresses.clone();
    let identities = (0..=COMMITTEE_SIZE)
        .map(|index| ed25519::PrivateKey::from_seed(0x5241_4348_4554 + index as u64))
        .collect::<Vec<_>>();
    let public_keys = identities
        .iter()
        .map(|identity| identity.public_key())
        .collect::<Vec<_>>();
    let committee = Map::try_from(
        public_keys
            .iter()
            .take(COMMITTEE_SIZE)
            .cloned()
            .zip(
                addresses
                    .iter()
                    .take(COMMITTEE_SIZE)
                    .copied()
                    .map(Address::from),
            )
            .collect::<Vec<_>>(),
    )
    .expect("the fixed committee has unique identities");
    let outsider_view = Map::try_from(
        public_keys
            .iter()
            .cloned()
            .zip(addresses.iter().copied().map(Address::from))
            .collect::<Vec<_>>(),
    )
    .expect("the outsider view has unique identities");

    let runner = commonware_runtime::tokio::Runner::new(
        commonware_runtime::tokio::Config::default()
            .with_worker_threads(COMMITTEE_SIZE + 1)
            .with_read_write_timeout(RECEIVE_TIMEOUT),
    );
    runner.start(move |context| async move {
        let mut senders = Vec::with_capacity(COMMITTEE_SIZE);
        let mut receivers = Vec::with_capacity(COMMITTEE_SIZE);
        let mut network_handles = Vec::with_capacity(COMMITTEE_SIZE + 1);

        for (index, identity) in identities.iter().take(COMMITTEE_SIZE).enumerate() {
            let peer_context = context.child("lookup_peer").with_attribute("index", index);
            let mut config = lookup::Config::local(
                identity.clone(),
                NAMESPACE,
                addresses[index],
                MAX_MESSAGE_SIZE,
            );
            config.dial_frequency = Duration::from_millis(50);
            config.peer_connection_cooldown = Duration::from_millis(100);

            let (mut network, mut oracle) =
                lookup::Network::new(peer_context.child("network"), config);
            oracle.track(0, committee.clone());
            let (sender, receiver) =
                network.register(CHANNEL, Quota::per_second(NZU32!(100)), MESSAGE_BACKLOG);
            senders.push(sender);
            receivers.push(receiver);
            network_handles.push(network.start());
        }

        let outsider_index = COMMITTEE_SIZE;
        let outsider_context = context
            .child("lookup_peer")
            .with_attribute("index", outsider_index);
        let mut outsider_config = lookup::Config::local(
            identities[outsider_index].clone(),
            NAMESPACE,
            addresses[outsider_index],
            MAX_MESSAGE_SIZE,
        );
        outsider_config.dial_frequency = Duration::from_millis(50);
        outsider_config.peer_connection_cooldown = Duration::from_millis(100);
        let (mut outsider_network, mut outsider_oracle) =
            lookup::Network::new(outsider_context.child("network"), outsider_config);
        outsider_oracle.track(0, outsider_view);
        let (mut outsider_sender, outsider_receiver) =
            outsider_network.register(CHANNEL, Quota::per_second(NZU32!(100)), MESSAGE_BACKLOG);
        network_handles.push(outsider_network.start());

        for (index, sender) in senders.iter_mut().enumerate() {
            let mut reached_entire_committee = false;
            for _ in 0..CONNECT_ATTEMPTS {
                let accepted =
                    sender.send(Recipients::All, public_keys[index].as_ref().to_vec(), true);
                if accepted.len() == COMMITTEE_SIZE - 1 {
                    reached_entire_committee = true;
                    break;
                }
                context.sleep(RETRY_DELAY).await;
            }
            assert!(
                reached_entire_committee,
                "authenticated peer {index} must connect and send to all other committee peers"
            );
        }

        for (index, mut receiver) in receivers.into_iter().enumerate() {
            let expected = public_keys
                .iter()
                .take(COMMITTEE_SIZE)
                .enumerate()
                .filter(|(peer_index, _)| *peer_index != index)
                .map(|(_, public_key)| public_key.clone())
                .collect::<HashSet<_>>();
            context
                .timeout(RECEIVE_TIMEOUT, async move {
                    let mut received = HashSet::with_capacity(COMMITTEE_SIZE - 1);
                    while received.len() < COMMITTEE_SIZE - 1 {
                        let (sender, message) = receiver
                            .recv()
                            .await
                            .expect("the authenticated channel must remain open");
                        assert!(
                            expected.contains(&sender),
                            "message sender must be authorized"
                        );
                        assert_eq!(
                            message,
                            sender.as_ref(),
                            "each peer must receive the expected authenticated identity payload"
                        );
                        received.insert(sender);
                    }
                })
                .await
                .expect("all committee messages must arrive before the bounded deadline");
        }

        let outsider_key = public_keys[outsider_index].clone();
        for _ in 0..UNKNOWN_ATTEMPTS {
            assert!(
                outsider_sender
                    .send(Recipients::All, outsider_key.as_ref().to_vec(), true)
                    .is_empty(),
                "a peer absent from the committee directory must not establish a send path"
            );
            context.sleep(RETRY_DELAY).await;
        }
        drop(senders);
        drop(outsider_sender);
        drop(outsider_receiver);
        assert!(
            count_running_tasks(&context, "lookup_peer") > 0,
            "lookup actors must be running before shutdown"
        );

        context
            .child("shutdown")
            .spawn(|shutdown_context| async move {
                shutdown_context
                    .stop(0, Some(SHUTDOWN_TIMEOUT))
                    .await
                    .expect("the runtime must complete graceful shutdown");
            });
        context
            .stopped()
            .await
            .expect("the runtime shutdown signal must be delivered");
        for handle in network_handles {
            context
                .timeout(SHUTDOWN_TIMEOUT, handle)
                .await
                .expect("each lookup network must stop before the shutdown deadline")
                .expect("each lookup network task must exit cleanly");
        }
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(
            count_running_tasks(&context, "lookup_peer"),
            0,
            "all authenticated lookup tasks must stop cleanly"
        );
    });

    for address in addresses_after_shutdown {
        TcpListener::bind(address).expect("clean teardown must release every lookup listen socket");
    }
}

const EMPTY_CHAIN_NAMESPACE: &[u8] = b"rachet/commonware-spike/empty-simplex/v1";
const EMPTY_CHAIN_EPOCH: Epoch = Epoch::new(7);
const FINALIZED_BLOCK_TARGET: usize = 100;

fn empty_block_digest(context: &SimplexContext<Sha256Digest, ed25519::PublicKey>) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(EMPTY_CHAIN_NAMESPACE);
    hasher.update(&context.encode());
    hasher.finalize()
}

#[derive(Clone, Default)]
struct EmptyApplication;

impl Automaton for EmptyApplication {
    type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;
    type Digest = Sha256Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();
        sender.send_lossy(empty_block_digest(&context));
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        sender.send_lossy(payload == empty_block_digest(&context));
        receiver
    }
}

impl CertifiableAutomaton for EmptyApplication {}

#[derive(Clone, Default)]
struct EmptyBlockRelay;

impl Relay for EmptyBlockRelay {
    type Digest = Sha256Digest;
    type PublicKey = ed25519::PublicKey;
    type Plan = simplex::Plan<Self::PublicKey>;

    fn broadcast(&mut self, _payload: Self::Digest, _plan: Self::Plan) -> Feedback {
        // An empty block has no body to distribute. Its digest is derived from the
        // consensus context, so every validator can verify it without a side channel.
        Feedback::Ok
    }
}

type FinalizedHistory = Arc<Mutex<BTreeMap<View, (View, Sha256Digest)>>>;

#[derive(Clone, Default)]
struct FinalizationReporter {
    history: FinalizedHistory,
}

impl FinalizationReporter {
    fn history(&self) -> FinalizedHistory {
        Arc::clone(&self.history)
    }
}

impl Reporter for FinalizationReporter {
    type Activity = Activity<simplex_ed25519::Scheme, Sha256Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Activity::Finalization(finalization) = activity {
            let proposal = finalization.proposal;
            self.history
                .lock()
                .expect("finalized history lock is not poisoned")
                .insert(proposal.view(), (proposal.parent, proposal.payload));
        }
        Feedback::Ok
    }
}

#[test]
fn four_node_ed25519_round_robin_simplex_finalizes_matching_empty_chain() {
    const COMMITTEE_SIZE: usize = 4;
    const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1_024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const CONSENSUS_QUOTA: Quota = Quota::per_second(std::num::NonZeroU32::MAX);

    deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let private_keys = (0..COMMITTEE_SIZE)
            .map(|index| ed25519::PrivateKey::from_seed(REPLAY_SEED + index as u64))
            .collect::<Vec<_>>();
        let participants = private_keys
            .iter()
            .map(|private_key| private_key.public_key())
            .collect::<Vec<_>>();
        let participant_set = Set::try_from(participants.clone())
            .expect("the four consensus identities must be unique");
        let schemes = private_keys
            .into_iter()
            .map(|private_key| {
                simplex_ed25519::Scheme::signer(
                    EMPTY_CHAIN_NAMESPACE,
                    participant_set.clone(),
                    private_key,
                )
                .expect("each consensus identity must occur in the participant set")
            })
            .collect::<Vec<_>>();

        let (network, oracle) = SimulatedNetwork::new_with_peers(
            context.child("empty_simplex_network"),
            SimulatedConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            participants.clone(),
        )
        .await;
        network.start();

        let mut registrations = HashMap::with_capacity(COMMITTEE_SIZE);
        for participant in &participants {
            let control = oracle.control(participant.clone());
            let pending = control
                .register(0, CONSENSUS_QUOTA)
                .await
                .expect("pending-vote channel registration must succeed");
            let recovered = control
                .register(1, CONSENSUS_QUOTA)
                .await
                .expect("recovered-certificate channel registration must succeed");
            let resolver = control
                .register(2, CONSENSUS_QUOTA)
                .await
                .expect("resolver channel registration must succeed");
            registrations.insert(participant.clone(), (pending, recovered, resolver));
        }

        for sender in &participants {
            for receiver in &participants {
                if sender == receiver {
                    continue;
                }
                oracle
                    .add_link(
                        sender.clone(),
                        receiver.clone(),
                        Link {
                            latency: Duration::from_millis(5),
                            jitter: Duration::from_millis(1),
                            success_rate: 1.0,
                        },
                    )
                    .await
                    .expect("all four consensus nodes must be linked");
            }
        }

        let genesis = Sha256::hash(b"rachet/commonware-spike/empty-simplex/genesis/v1");
        let mut histories = Vec::with_capacity(COMMITTEE_SIZE);
        for (index, participant) in participants.iter().enumerate() {
            let node_context = context
                .child("empty_simplex_node")
                .with_attribute("index", index);
            let reporter = FinalizationReporter::default();
            histories.push(reporter.history());
            let config = SimplexConfig {
                scheme: schemes[index].clone(),
                elector: RoundRobin::<Sha256>::default(),
                blocker: oracle.control(participant.clone()),
                automaton: EmptyApplication,
                relay: EmptyBlockRelay,
                reporter,
                strategy: node_context.strategy(NZUsize!(1)),
                partition: format!("empty-simplex-node-{index}"),
                mailbox_size: NZUsize!(1_024),
                epoch: EMPTY_CHAIN_EPOCH,
                floor: Floor::Genesis(genesis),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                fetch_concurrent: NZUsize!(4),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&node_context, PAGE_SIZE, PAGE_CACHE_SIZE),
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(node_context.child("engine"), config);
            let (pending, recovered, resolver) = registrations
                .remove(participant)
                .expect("every consensus node must have registered channels");
            engine.start(pending, recovered, resolver);
        }

        loop {
            let all_reached_target = histories.iter().all(|history| {
                history
                    .lock()
                    .expect("finalized history lock is not poisoned")
                    .len()
                    >= FINALIZED_BLOCK_TARGET
            });
            if all_reached_target {
                break;
            }
            context.sleep(Duration::from_millis(10)).await;
        }

        let canonical = histories[0]
            .lock()
            .expect("finalized history lock is not poisoned")
            .iter()
            .take(FINALIZED_BLOCK_TARGET)
            .map(|(view, block)| (*view, *block))
            .collect::<Vec<_>>();
        assert_eq!(canonical.len(), FINALIZED_BLOCK_TARGET);
        for history in histories.iter().skip(1) {
            let finalized = history
                .lock()
                .expect("finalized history lock is not poisoned")
                .iter()
                .take(FINALIZED_BLOCK_TARGET)
                .map(|(view, block)| (*view, *block))
                .collect::<Vec<_>>();
            assert_eq!(
                finalized, canonical,
                "all four nodes must finalize the same empty-block history"
            );
        }

        let mut expected_parent = View::zero();
        for (view, (parent, _payload)) in canonical {
            assert_eq!(
                view,
                expected_parent.next(),
                "the empty chain must finalize every consecutive view"
            );
            assert_eq!(
                parent, expected_parent,
                "each empty block must extend the previous finalized view"
            );
            expected_parent = view;
        }
    });
}
