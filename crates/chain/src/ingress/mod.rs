//! Validated external action ingress and authenticated peer forwarding.
//!
//! RPC JSON is deliberately only a transport wrapper around canonical action
//! bytes. Both external forms and every authenticated peer message converge on
//! the same bounded decoder, state snapshot, envelope verification, and pending
//! pool admission path. Consensus independently repeats authoritative action
//! verification while executing a candidate block.

use crate::{
    mempool::{InsertOutcome, PendingActionPool, PendingPoolError},
    observability::NodeMetrics,
};
use commonware_codec::{Encode as _, Write as _};
use commonware_cryptography::ed25519;
use commonware_p2p::{Recipients, Sender};
use rachet_core::{
    actions::{
        Action, ActionValidationError, ActionVerificationContext, SignedAction,
        decode_signed_action,
    },
    limits::MAX_ACTION_BYTES,
    primitives::ActorId,
};
use serde::Deserialize;
use std::{fmt, sync::Arc};

/// Dedicated Commonware channel for canonical signed-action forwarding.
pub const ACTION_CHANNEL: u64 = 0x5241_4348_4554_0001;

/// Maximum authenticated action-channel message size.
pub const ACTION_CHANNEL_MAX_MESSAGE_SIZE: u32 = MAX_ACTION_BYTES as u32;

/// Bounded RPC JSON size for one hex-encoded canonical action and its wrapper.
pub const MAX_ACTION_JSON_BYTES: usize = MAX_ACTION_BYTES * 2 + 128;

/// One coherent canonical-state view used for ingress admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionStateSnapshot {
    /// Current chain, protocol version, and finalized/proposed height context.
    pub verification: ActionVerificationContext,
    /// Next nonce in canonical state for the decoded action's actor.
    pub expected_nonce: u64,
}

impl ActionStateSnapshot {
    /// Constructs one coherent ingress state snapshot.
    pub const fn new(verification: ActionVerificationContext, expected_nonce: u64) -> Self {
        Self {
            verification,
            expected_nonce,
        }
    }
}

/// Failure to read the canonical state needed by ingress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressStateError {
    /// The current canonical state is temporarily unavailable.
    Unavailable,
    /// Canonical actor nonce state was not one big-endian `u64`.
    MalformedNonce { actual: usize },
}

impl fmt::Display for IngressStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("canonical ingress state is unavailable"),
            Self::MalformedNonce { actual } => write!(
                formatter,
                "canonical actor nonce state length {actual} is not the required 8 bytes"
            ),
        }
    }
}

impl std::error::Error for IngressStateError {}

/// Supplies an atomic state snapshot after the bounded envelope identifies its actor.
///
/// Implementations backed by QMDB must derive the verification context and actor
/// nonce from the same current canonical view rather than mixing heights.
pub trait IngressState: Send + Sync {
    /// Reads the current ingress context for `actor`.
    fn snapshot(&self, actor: &ActorId) -> Result<ActionStateSnapshot, IngressStateError>;
}

/// Stable rejection reasons shared by byte, JSON, and peer intake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressError {
    /// The non-consensus RPC JSON wrapper exceeds its node boundary.
    JsonTooLarge { maximum: usize, actual: usize },
    /// RPC JSON was malformed, had duplicate/unknown fields, or used the wrong shape.
    MalformedJson,
    /// `canonical_action` was not an even-length hexadecimal byte string.
    MalformedCanonicalHex,
    /// Canonical decoding or envelope validation failed.
    Action(ActionValidationError),
    /// Canonical state could not be read coherently.
    State(IngressStateError),
    /// Bounded pending-pool policy rejected the otherwise valid action.
    Pending(PendingPoolError),
}

impl IngressError {
    /// Returns a stable machine-readable boundary error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::JsonTooLarge { .. } => "ACTION_JSON_TOO_LARGE",
            Self::MalformedJson => "ACTION_JSON_MALFORMED",
            Self::MalformedCanonicalHex => "ACTION_CANONICAL_HEX_MALFORMED",
            Self::Action(error) => error.code(),
            Self::State(IngressStateError::Unavailable) => "ACTION_STATE_UNAVAILABLE",
            Self::State(IngressStateError::MalformedNonce { .. }) => "ACTION_NONCE_STATE_MALFORMED",
            Self::Pending(error) => error.code(),
        }
    }
}

impl fmt::Display for IngressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonTooLarge { maximum, actual } => write!(
                formatter,
                "action JSON length {actual} exceeds boundary maximum {maximum}"
            ),
            Self::MalformedJson => formatter.write_str("malformed action JSON"),
            Self::MalformedCanonicalHex => {
                formatter.write_str("malformed canonical action hexadecimal bytes")
            }
            Self::Action(error) => error.fmt(formatter),
            Self::State(error) => error.fmt(formatter),
            Self::Pending(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for IngressError {}

impl From<ActionValidationError> for IngressError {
    fn from(error: ActionValidationError) -> Self {
        Self::Action(error)
    }
}

impl From<IngressStateError> for IngressError {
    fn from(error: IngressStateError) -> Self {
        Self::State(error)
    }
}

impl From<PendingPoolError> for IngressError {
    fn from(error: PendingPoolError) -> Self {
        Self::Pending(error)
    }
}

/// Result of external admission and best-effort authenticated fanout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalIngressOutcome {
    /// Pending-pool insertion, duplicate, or replacement result.
    pub insertion: InsertOutcome,
    /// Connected, rate-permitted committee peers accepted by Commonware.
    pub forwarded_to: Vec<ed25519::PublicKey>,
}

/// Result of one authenticated peer-channel receive and admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIngressOutcome {
    /// Authenticated consensus-node identity supplied by Commonware.
    pub peer: ed25519::PublicKey,
    /// Pending-pool insertion, duplicate, or replacement result.
    pub insertion: InsertOutcome,
}

/// Failure while receiving one authenticated peer action.
#[derive(Debug)]
pub enum PeerIngressError<E> {
    /// The Commonware channel closed or failed before yielding a message.
    Network(E),
    /// An authenticated peer supplied an invalid or policy-rejected action.
    Rejected {
        peer: Box<ed25519::PublicKey>,
        error: IngressError,
    },
}

/// Shared validated action intake for one consensus node.
pub struct ActionIngress<S> {
    pool: Arc<PendingActionPool>,
    state: S,
    observability: Option<Arc<NodeMetrics>>,
}

impl<S> ActionIngress<S>
where
    S: IngressState,
{
    /// Binds canonical state reads to one bounded pending pool.
    pub const fn new(pool: Arc<PendingActionPool>, state: S) -> Self {
        Self {
            pool,
            state,
            observability: None,
        }
    }

    /// Attaches diagnostic admission counters.
    pub fn with_observability(mut self, observability: Arc<NodeMetrics>) -> Self {
        self.observability = Some(observability);
        self
    }

    /// Returns the node's shared pending pool.
    pub fn pool(&self) -> &Arc<PendingActionPool> {
        &self.pool
    }

    /// Accepts canonical signed-action bytes and forwards only a new admission.
    pub fn submit_canonical<N>(
        &self,
        canonical: &[u8],
        sender: &mut N,
    ) -> Result<ExternalIngressOutcome, IngressError>
    where
        N: Sender<PublicKey = ed25519::PublicKey>,
    {
        let (action, insertion) = self.admit_canonical(canonical)?;
        let forwarded_to = if should_forward(insertion) {
            let mut encoded = Vec::with_capacity(action.canonical_len());
            action.write(&mut encoded);
            sender.send(Recipients::All, encoded, false)
        } else {
            Vec::new()
        };
        Ok(ExternalIngressOutcome {
            insertion,
            forwarded_to,
        })
    }

    /// Accepts an already constructed canonical action and uses the same intake path.
    pub fn submit_action<N>(
        &self,
        action: &SignedAction<Action>,
        sender: &mut N,
    ) -> Result<ExternalIngressOutcome, IngressError>
    where
        N: Sender<PublicKey = ed25519::PublicKey>,
    {
        self.submit_canonical(action.encode().as_ref(), sender)
    }

    /// Accepts bounded RPC JSON of the form
    /// `{"canonical_action":"<hex canonical SignedAction<Action>>"}`.
    ///
    /// The JSON representation is transport-only and never becomes consensus
    /// encoding. Duplicate and unknown object fields are rejected.
    pub fn submit_json<N>(
        &self,
        json: &[u8],
        sender: &mut N,
    ) -> Result<ExternalIngressOutcome, IngressError>
    where
        N: Sender<PublicKey = ed25519::PublicKey>,
    {
        let canonical = decode_json_canonical(json)?;
        self.submit_canonical(&canonical, sender)
    }

    /// Receives exactly one message from a Commonware-authenticated action channel.
    ///
    /// Valid peer actions enter the local pool but are not retransmitted, which
    /// prevents committee forwarding loops. Callers may continue after
    /// [`PeerIngressError::Rejected`] to isolate malformed peers.
    pub async fn receive_one<R>(
        &self,
        receiver: &mut R,
    ) -> Result<PeerIngressOutcome, PeerIngressError<R::Error>>
    where
        R: commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
    {
        let (peer, message) = receiver.recv().await.map_err(PeerIngressError::Network)?;
        let (_, insertion) =
            self.admit_canonical(message.as_ref())
                .map_err(|error| PeerIngressError::Rejected {
                    peer: Box::new(peer.clone()),
                    error,
                })?;
        Ok(PeerIngressOutcome { peer, insertion })
    }

    fn admit_canonical(
        &self,
        canonical: &[u8],
    ) -> Result<(SignedAction<Action>, InsertOutcome), IngressError> {
        let result = self.admit_canonical_inner(canonical);
        if let Some(observability) = &self.observability {
            observability.observe_action(result.is_ok());
        }
        result
    }

    fn admit_canonical_inner(
        &self,
        canonical: &[u8],
    ) -> Result<(SignedAction<Action>, InsertOutcome), IngressError> {
        let action = decode_signed_action::<Action>(canonical, &())?;
        let snapshot = self.state.snapshot(&action.actor)?;

        // Stateless verification uses the envelope nonce to check every signed
        // field while the pool separately checks stale/future nonce policy
        // against canonical state. Consensus later requires exact contiguous
        // nonces and advances state transactionally.
        if action.nonce == u64::MAX {
            return Err(ActionValidationError::NonceExhausted.into());
        }
        action.verify(&snapshot.verification, action.nonce)?;
        let insertion = self.pool.insert(
            action.clone(),
            snapshot.expected_nonce,
            snapshot.verification.height,
        )?;
        Ok((action, insertion))
    }
}

const fn should_forward(insertion: InsertOutcome) -> bool {
    matches!(
        insertion,
        InsertOutcome::Inserted { .. } | InsertOutcome::Replaced { .. }
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalActionJson {
    canonical_action: String,
}

fn decode_json_canonical(json: &[u8]) -> Result<Vec<u8>, IngressError> {
    if json.len() > MAX_ACTION_JSON_BYTES {
        return Err(IngressError::JsonTooLarge {
            maximum: MAX_ACTION_JSON_BYTES,
            actual: json.len(),
        });
    }
    let request: CanonicalActionJson =
        serde_json::from_slice(json).map_err(|_| IngressError::MalformedJson)?;
    decode_hex(&request.canonical_action)
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, IngressError> {
    if !encoded.len().is_multiple_of(2) || encoded.len() / 2 > MAX_ACTION_BYTES {
        return Err(IngressError::MalformedCanonicalHex);
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(IngressError::MalformedCanonicalHex)?;
            let low = hex_nibble(pair[1]).ok_or(IngressError::MalformedCanonicalHex)?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};
    use rachet_core::{
        actions::{Action, CloseJob},
        primitives::{ChainId, JobId, ProtocolVersion},
        state::InMemoryStateBatch,
    };

    #[derive(Clone, Copy)]
    struct FixedState {
        snapshot: ActionStateSnapshot,
    }

    impl IngressState for FixedState {
        fn snapshot(&self, _: &ActorId) -> Result<ActionStateSnapshot, IngressStateError> {
            Ok(self.snapshot)
        }
    }

    fn signed(seed: u64, nonce: u64) -> SignedAction<Action> {
        SignedAction::sign(
            &ed25519::PrivateKey::from_seed(seed),
            ProtocolVersion::V1,
            ChainId::new([7; 32]),
            nonce,
            10,
            Action::CloseJob(CloseJob::new(JobId::derive(&seed.to_be_bytes()))),
        )
        .unwrap()
    }

    fn ingress(expected_nonce: u64) -> ActionIngress<FixedState> {
        ActionIngress::new(
            Arc::new(PendingActionPool::new(
                crate::mempool::PendingPoolLimits::new(8, 4, MAX_ACTION_BYTES * 2, 2),
            )),
            FixedState {
                snapshot: ActionStateSnapshot::new(
                    ActionVerificationContext::current(ChainId::new([7; 32]), 1),
                    expected_nonce,
                ),
            },
        )
    }

    #[test]
    fn every_intake_form_converges_on_bounded_canonical_validation() {
        let action = signed(1, 0);
        let canonical = action.encode();
        let intake = ingress(0);
        let (_, inserted) = intake.admit_canonical(canonical.as_ref()).unwrap();
        assert!(matches!(inserted, InsertOutcome::Inserted { .. }));
        let (_, duplicate) = intake.admit_canonical(canonical.as_ref()).unwrap();
        assert!(matches!(duplicate, InsertOutcome::Duplicate { .. }));

        let hex = canonical
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            decode_json_canonical(format!(r#"{{"canonical_action":"{hex}"}}"#).as_bytes()).unwrap(),
            canonical
        );
        assert_eq!(
            decode_json_canonical(br#"{"canonical_action":"00","extra":true}"#),
            Err(IngressError::MalformedJson)
        );
        assert_eq!(
            decode_json_canonical(br#"{"canonical_action":"00","canonical_action":"00"}"#),
            Err(IngressError::MalformedJson)
        );
        assert_eq!(
            decode_json_canonical(br#"{"canonical_action":"0z"}"#),
            Err(IngressError::MalformedCanonicalHex)
        );
    }

    #[test]
    fn malformed_invalid_oversized_and_nonce_bounded_actions_never_enter() {
        let intake = ingress(1);
        let baseline = signed(2, 1);
        let mut cases = Vec::new();

        let mut invalid_signature = baseline.clone();
        invalid_signature.signature = signed(3, 1).signature;
        cases.push((
            invalid_signature.encode().to_vec(),
            "ACTION_SIGNATURE_INVALID",
        ));
        let mut wrong_chain = baseline.clone();
        wrong_chain.chain_id = ChainId::new([8; 32]);
        cases.push((wrong_chain.encode().to_vec(), "ACTION_CHAIN_ID_INVALID"));
        let mut wrong_version = baseline.clone();
        wrong_version.version = ProtocolVersion::new(2);
        cases.push((
            wrong_version.encode().to_vec(),
            "ACTION_VERSION_UNSUPPORTED",
        ));
        cases.push((signed(2, 0).encode().to_vec(), "PENDING_NONCE_STALE"));
        cases.push((signed(2, 4).encode().to_vec(), "PENDING_NONCE_GAP"));
        cases.push((vec![0xff], "ACTION_MALFORMED"));
        cases.push((vec![0; MAX_ACTION_BYTES + 1], "ACTION_TOO_LARGE"));

        for (canonical, code) in cases {
            let error = intake.admit_canonical(&canonical).unwrap_err();
            assert_eq!(error.code(), code);
            assert!(intake.pool().is_empty());
        }
    }

    #[test]
    fn ingress_checks_are_repeated_by_consensus_nonce_execution() {
        let action = signed(4, 0);
        let intake = ingress(0);
        intake.admit_canonical(action.encode().as_ref()).unwrap();

        let mut state = InMemoryStateBatch::new();
        action
            .verify_and_advance_nonce(
                &mut state,
                &ActionVerificationContext::current(ChainId::new([7; 32]), 1),
            )
            .unwrap();
        assert_eq!(
            action.verify_and_advance_nonce(
                &mut state,
                &ActionVerificationContext::current(ChainId::new([7; 32]), 1),
            ),
            Err(ActionValidationError::InvalidNonce {
                expected: 1,
                received: 0,
            })
        );
    }
}
