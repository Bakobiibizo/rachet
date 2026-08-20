//! Signed, replay-resistant protocol action envelopes.
//!
//! The envelope is generic over the canonical action payload so action schemas
//! can evolve independently of signature and nonce enforcement. Production
//! execution uses the protocol's canonical `Action` enum as the payload.

mod commitments;
mod evidence;
mod jobs;
mod resolutions;

pub use commitments::{CommitmentSubject, CreateCommitment, RevealCommitment, reveal_digest};
pub use evidence::{RegisterEvidence, SubmitAttestation, Verdict};
pub use jobs::{ClaimDefinition, CloseJob, CreateJob, JobLifecycle, ResolutionPolicy};
pub use resolutions::{
    ChallengeTarget, CreateChallenge, ResolutionVerdict, ResolveChallenge, ResolveClaim,
};

use crate::{
    limits::MAX_ACTION_BYTES,
    primitives::{
        ActionId, ActorId, CURRENT_PROTOCOL_VERSION, ChainId, HashDomain, ProtocolVersion,
    },
    state::{StateBatch, StateKey},
};
use commonware_codec::{Decode, EncodeSize, Read, Write};
use commonware_cryptography::{Signer as _, Verifier as _, ed25519};
use core::fmt;

/// Every canonical state-transition payload accepted by protocol v1.
///
/// Discriminants are consensus bytes and follow the declaration order in
/// specification section 12.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Action {
    CreateJob(Box<CreateJob>) = 0,
    RegisterEvidence(RegisterEvidence) = 1,
    SubmitAttestation(SubmitAttestation) = 2,
    CreateCommitment(CreateCommitment) = 3,
    RevealCommitment(RevealCommitment) = 4,
    CreateChallenge(CreateChallenge) = 5,
    ResolveClaim(ResolveClaim) = 6,
    ResolveChallenge(ResolveChallenge) = 7,
    CloseJob(CloseJob) = 8,
}

/// The Ed25519 signature representation carried by a signed action.
pub type Ed25519Signature = ed25519::Signature;

/// The fixed encoded size of a signed action excluding its payload.
///
/// This includes the signature and every fixed-width envelope field.
pub const SIGNED_ACTION_FIXED_BYTES: usize = 2 + 32 + 32 + 8 + 8 + 64;

/// Context against which a signed action is validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionVerificationContext {
    /// Chain fixed by genesis.
    pub chain_id: ChainId,
    /// Protocol version executed by the candidate block.
    pub protocol_version: ProtocolVersion,
    /// Candidate block height, used for deterministic expiry.
    pub height: u64,
}

impl ActionVerificationContext {
    /// Constructs a verification context.
    pub const fn new(chain_id: ChainId, protocol_version: ProtocolVersion, height: u64) -> Self {
        Self {
            chain_id,
            protocol_version,
            height,
        }
    }

    /// Constructs a context for the current protocol version.
    pub const fn current(chain_id: ChainId, height: u64) -> Self {
        Self::new(chain_id, CURRENT_PROTOCOL_VERSION, height)
    }
}

/// A canonical action and the actor authorization needed to execute it.
///
/// The signature authenticates, in declaration order, `version`, `chain_id`,
/// `actor`, `nonce`, `valid_until_height`, and `payload`. The action signing
/// namespace supplies the object-class domain separation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SignedAction<P> {
    /// State-transition protocol version.
    pub version: ProtocolVersion,
    /// Genesis-fixed chain identifier.
    pub chain_id: ChainId,
    /// Actor's Ed25519 public key.
    pub actor: ActorId,
    /// Exact next nonce expected for this actor.
    pub nonce: u64,
    /// Last block height at which this action remains valid, inclusive.
    pub valid_until_height: u64,
    /// Canonically encoded protocol action.
    pub payload: P,
    /// Ed25519 signature over the bound envelope fields and payload.
    pub signature: Ed25519Signature,
}

impl<P: Write + EncodeSize> SignedAction<P> {
    /// Signs a canonical payload with an Ed25519 actor identity.
    ///
    /// The actor field is derived from `private_key`, so callers cannot
    /// accidentally produce a key/identity mismatch.
    pub fn sign(
        private_key: &ed25519::PrivateKey,
        version: ProtocolVersion,
        chain_id: ChainId,
        nonce: u64,
        valid_until_height: u64,
        payload: P,
    ) -> Result<Self, ActionValidationError> {
        ensure_size(payload.encode_size())?;
        let actor = ActorId::from(private_key.public_key());
        let message = signing_bytes(
            version,
            chain_id,
            &actor,
            nonce,
            valid_until_height,
            &payload,
        );
        let signature = private_key.sign(HashDomain::Action.as_bytes(), &message);
        Ok(Self {
            version,
            chain_id,
            actor,
            nonce,
            valid_until_height,
            payload,
            signature,
        })
    }

    /// Returns the exact number of bytes in the canonical signed envelope.
    pub fn canonical_len(&self) -> usize {
        SIGNED_ACTION_FIXED_BYTES.saturating_add(self.payload.encode_size())
    }

    /// Derives the action identifier from the complete canonical signed action.
    pub fn action_id(&self) -> ActionId {
        let mut canonical = Vec::with_capacity(self.canonical_len());
        self.write(&mut canonical);
        ActionId::derive(&canonical)
    }

    /// Verifies all stateless envelope checks and the exact expected nonce.
    ///
    /// `expected_nonce` is the next nonce stored for the actor. A new actor's
    /// initial expected nonce is zero.
    pub fn verify(
        &self,
        context: &ActionVerificationContext,
        expected_nonce: u64,
    ) -> Result<ActionId, ActionValidationError> {
        if !self.version.is_supported() {
            return Err(ActionValidationError::UnsupportedProtocolVersion {
                received: self.version.get(),
            });
        }
        if self.version != context.protocol_version {
            return Err(ActionValidationError::ProtocolVersionMismatch {
                expected: context.protocol_version.get(),
                received: self.version.get(),
            });
        }
        if self.chain_id != context.chain_id {
            return Err(ActionValidationError::ChainIdMismatch);
        }
        if self.valid_until_height < context.height {
            return Err(ActionValidationError::Expired {
                valid_until_height: self.valid_until_height,
                current_height: context.height,
            });
        }
        if self.nonce != expected_nonce {
            return Err(ActionValidationError::InvalidNonce {
                expected: expected_nonce,
                received: self.nonce,
            });
        }
        ensure_size(self.payload.encode_size())?;

        let message = signing_bytes(
            self.version,
            self.chain_id,
            &self.actor,
            self.nonce,
            self.valid_until_height,
            &self.payload,
        );
        if !self
            .actor
            .0
            .verify(HashDomain::Action.as_bytes(), &message, &self.signature)
        {
            return Err(ActionValidationError::InvalidSignature);
        }

        Ok(self.action_id())
    }

    /// Verifies an action against canonical actor state and advances its nonce.
    ///
    /// This method must run inside the caller's transactional block fork. If a
    /// later canonical transition fails, rolling back that fork also rolls back
    /// the nonce advancement.
    pub fn verify_and_advance_nonce(
        &self,
        state: &mut dyn StateBatch,
        context: &ActionVerificationContext,
    ) -> Result<ActionId, ActionValidationError> {
        let key = StateKey::account(&self.actor);
        let expected_nonce = read_expected_nonce(state, &key)?;
        let action_id = self.verify(context, expected_nonce)?;
        let next_nonce = expected_nonce
            .checked_add(1)
            .ok_or(ActionValidationError::NonceExhausted)?;
        state.put(key, Box::new(next_nonce.to_be_bytes()));
        Ok(action_id)
    }
}

/// Decodes one bounded canonical signed action.
///
/// All codec failures are deliberately collapsed to a stable protocol error at
/// this trust boundary. The concrete payload decoder remains responsible for
/// rejecting malformed fields and enum tags.
pub fn decode_signed_action<P>(
    encoded: &[u8],
    payload_cfg: &P::Cfg,
) -> Result<SignedAction<P>, ActionValidationError>
where
    P: Read + Write + EncodeSize,
{
    if encoded.len() > MAX_ACTION_BYTES {
        return Err(ActionValidationError::ActionTooLarge {
            maximum: MAX_ACTION_BYTES,
            actual: encoded.len(),
        });
    }
    SignedAction::<P>::decode_cfg(encoded, payload_cfg)
        .map_err(|_| ActionValidationError::MalformedEncoding)
}

fn ensure_size(payload_size: usize) -> Result<(), ActionValidationError> {
    let actual = SIGNED_ACTION_FIXED_BYTES.saturating_add(payload_size);
    if actual > MAX_ACTION_BYTES {
        return Err(ActionValidationError::ActionTooLarge {
            maximum: MAX_ACTION_BYTES,
            actual,
        });
    }
    Ok(())
}

fn signing_bytes<P: Write + EncodeSize>(
    version: ProtocolVersion,
    chain_id: ChainId,
    actor: &ActorId,
    nonce: u64,
    valid_until_height: u64,
    payload: &P,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SIGNED_ACTION_FIXED_BYTES
            .saturating_sub(64)
            .saturating_add(payload.encode_size()),
    );
    version.write(&mut message);
    chain_id.write(&mut message);
    actor.write(&mut message);
    nonce.write(&mut message);
    valid_until_height.write(&mut message);
    payload.write(&mut message);
    message
}

fn read_expected_nonce(
    state: &dyn StateBatch,
    key: &StateKey,
) -> Result<u64, ActionValidationError> {
    let Some(value) = state.get(key) else {
        return Ok(0);
    };
    let actual = value.len();
    let bytes: [u8; 8] = value
        .as_ref()
        .try_into()
        .map_err(|_| ActionValidationError::MalformedNonceState { actual })?;
    Ok(u64::from_be_bytes(bytes))
}

/// Stable failures produced while decoding or validating signed actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionValidationError {
    /// The envelope requests a protocol version this binary cannot execute.
    UnsupportedProtocolVersion { received: u16 },
    /// The envelope version differs from the candidate block context.
    ProtocolVersionMismatch { expected: u16, received: u16 },
    /// The envelope belongs to another chain.
    ChainIdMismatch,
    /// The inclusive validity height has passed.
    Expired {
        valid_until_height: u64,
        current_height: u64,
    },
    /// The actor nonce is duplicate, stale, or skipped.
    InvalidNonce { expected: u64, received: u64 },
    /// No later nonce can be represented after accepting this action.
    NonceExhausted,
    /// The Ed25519 signature does not authenticate the bound envelope.
    InvalidSignature,
    /// The full canonical envelope exceeds the action byte limit.
    ActionTooLarge { maximum: usize, actual: usize },
    /// Canonical decoding rejected the envelope or its payload.
    MalformedEncoding,
    /// Canonical actor state did not contain one fixed-width next nonce.
    MalformedNonceState { actual: usize },
}

impl ActionValidationError {
    /// Returns the stable machine-readable protocol error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedProtocolVersion { .. } => "ACTION_VERSION_UNSUPPORTED",
            Self::ProtocolVersionMismatch { .. } => "ACTION_VERSION_INVALID",
            Self::ChainIdMismatch => "ACTION_CHAIN_ID_INVALID",
            Self::Expired { .. } => "ACTION_EXPIRED",
            Self::InvalidNonce { .. } => "ACTION_NONCE_INVALID",
            Self::NonceExhausted => "ACTION_NONCE_EXHAUSTED",
            Self::InvalidSignature => "ACTION_SIGNATURE_INVALID",
            Self::ActionTooLarge { .. } => "ACTION_TOO_LARGE",
            Self::MalformedEncoding => "ACTION_MALFORMED",
            Self::MalformedNonceState { .. } => "ACTION_NONCE_STATE_MALFORMED",
        }
    }
}

impl fmt::Display for ActionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtocolVersion { received } => {
                write!(formatter, "unsupported protocol version {received}")
            }
            Self::ProtocolVersionMismatch { expected, received } => write!(
                formatter,
                "expected protocol version {expected}, received {received}"
            ),
            Self::ChainIdMismatch => formatter.write_str("action chain ID does not match context"),
            Self::Expired {
                valid_until_height,
                current_height,
            } => write!(
                formatter,
                "action expired at height {valid_until_height}, current height is {current_height}"
            ),
            Self::InvalidNonce { expected, received } => {
                write!(formatter, "expected nonce {expected}, received {received}")
            }
            Self::NonceExhausted => formatter.write_str("actor nonce is exhausted"),
            Self::InvalidSignature => formatter.write_str("invalid action signature"),
            Self::ActionTooLarge { maximum, actual } => write!(
                formatter,
                "canonical action length {actual} exceeds protocol maximum {maximum}"
            ),
            Self::MalformedEncoding => formatter.write_str("malformed canonical action encoding"),
            Self::MalformedNonceState { actual } => write!(
                formatter,
                "actor nonce state length {actual} is not the required 8 bytes"
            ),
        }
    }
}

impl std::error::Error for ActionValidationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Buf, BufMut};
    use commonware_codec::{Encode, Error as CodecError, FixedSize, Read, ReadExt as _};

    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(u8)]
    enum TestAction {
        Set(u64) = 0,
        Clear = 1,
    }

    impl Write for TestAction {
        fn write(&self, buf: &mut impl BufMut) {
            match self {
                Self::Set(value) => {
                    0_u8.write(buf);
                    value.write(buf);
                }
                Self::Clear => 1_u8.write(buf),
            }
        }
    }

    impl EncodeSize for TestAction {
        fn encode_size(&self) -> usize {
            match self {
                Self::Set(_) => 1 + u64::SIZE,
                Self::Clear => 1,
            }
        }
    }

    impl Read for TestAction {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            match u8::read(buf)? {
                0 => Ok(Self::Set(u64::read(buf)?)),
                1 => Ok(Self::Clear),
                tag => Err(CodecError::InvalidEnum(tag)),
            }
        }
    }

    fn key(seed: u64) -> ed25519::PrivateKey {
        ed25519::PrivateKey::from_seed(seed)
    }

    fn chain(byte: u8) -> ChainId {
        ChainId::new([byte; 32])
    }

    fn signed(seed: u64, nonce: u64) -> SignedAction<TestAction> {
        SignedAction::sign(
            &key(seed),
            ProtocolVersion::V1,
            chain(1),
            nonce,
            10,
            TestAction::Set(7),
        )
        .unwrap()
    }

    #[test]
    fn valid_actions_verify_and_nonce_state_is_exact_and_transactional() {
        let context = ActionVerificationContext::current(chain(1), 10);
        let mut state = crate::state::InMemoryStateBatch::new();
        state.fork();

        let first = signed(1, 0);
        let first_id = first
            .verify_and_advance_nonce(&mut state, &context)
            .unwrap();
        assert_eq!(first_id, first.action_id());
        assert_eq!(
            state.get(&StateKey::account(&first.actor)).as_deref(),
            Some(1_u64.to_be_bytes().as_slice())
        );

        let second = signed(1, 1);
        second
            .verify_and_advance_nonce(&mut state, &context)
            .unwrap();
        assert_eq!(
            state.get(&StateKey::account(&first.actor)).as_deref(),
            Some(2_u64.to_be_bytes().as_slice())
        );

        state.rollback().unwrap();
        assert!(state.get(&StateKey::account(&first.actor)).is_none());
    }

    #[test]
    fn duplicate_and_skipped_nonces_have_one_stable_error() {
        let context = ActionVerificationContext::current(chain(1), 1);
        let duplicate = signed(2, 4).verify(&context, 5).unwrap_err();
        let skipped = signed(2, 6).verify(&context, 5).unwrap_err();
        assert_eq!(
            duplicate,
            ActionValidationError::InvalidNonce {
                expected: 5,
                received: 4
            }
        );
        assert_eq!(
            skipped,
            ActionValidationError::InvalidNonce {
                expected: 5,
                received: 6
            }
        );
        assert_eq!(duplicate.code(), "ACTION_NONCE_INVALID");
        assert_eq!(duplicate.to_string(), "expected nonce 5, received 4");
    }

    #[test]
    fn expiry_is_height_based_and_inclusive() {
        let action = signed(3, 0);
        assert!(
            action
                .verify(&ActionVerificationContext::current(chain(1), 10), 0)
                .is_ok()
        );
        let error = action
            .verify(&ActionVerificationContext::current(chain(1), 11), 0)
            .unwrap_err();
        assert_eq!(error.code(), "ACTION_EXPIRED");
    }

    #[test]
    fn chain_version_actor_nonce_expiry_and_payload_are_signature_bound() {
        let context = ActionVerificationContext::current(chain(1), 1);
        let original = signed(4, 0);

        let mut changes = Vec::new();
        let mut actor = original.clone();
        actor.actor = ActorId::from(key(99).public_key());
        changes.push(actor);
        let mut nonce = original.clone();
        nonce.nonce = 1;
        changes.push(nonce);
        let mut expiry = original.clone();
        expiry.valid_until_height = 11;
        changes.push(expiry);
        let mut payload = original.clone();
        payload.payload = TestAction::Set(8);
        changes.push(payload);

        for changed in changes {
            let expected = changed.nonce;
            assert_eq!(
                changed.verify(&context, expected),
                Err(ActionValidationError::InvalidSignature)
            );
        }

        let mut chain_bound = original.clone();
        chain_bound.chain_id = chain(2);
        assert_eq!(
            chain_bound.verify(&ActionVerificationContext::current(chain(2), 1), 0),
            Err(ActionValidationError::InvalidSignature)
        );

        let mut version_bound = original;
        version_bound.version = ProtocolVersion::new(2);
        assert_eq!(
            version_bound.verify(
                &ActionVerificationContext::new(chain(1), ProtocolVersion::new(2), 1),
                0
            ),
            Err(ActionValidationError::UnsupportedProtocolVersion { received: 2 })
        );
    }

    #[test]
    fn cross_chain_and_cross_version_replay_are_rejected_before_execution() {
        let action = signed(5, 0);
        assert_eq!(
            action.verify(&ActionVerificationContext::current(chain(2), 1), 0),
            Err(ActionValidationError::ChainIdMismatch)
        );
        assert_eq!(
            action.verify(
                &ActionVerificationContext::new(chain(1), ProtocolVersion::new(2), 1),
                0
            ),
            Err(ActionValidationError::ProtocolVersionMismatch {
                expected: 2,
                received: 1
            })
        );
    }

    #[test]
    fn a_signature_from_another_key_is_rejected() {
        let mut action = signed(6, 0);
        action.signature = signed(7, 0).signature;
        let error = action
            .verify(&ActionVerificationContext::current(chain(1), 1), 0)
            .unwrap_err();
        assert_eq!(error.code(), "ACTION_SIGNATURE_INVALID");
    }

    #[test]
    fn codec_rejects_malformed_truncated_trailing_and_oversized_actions() {
        let action = signed(8, 0);
        let encoded = action.encode();
        assert_eq!(
            decode_signed_action::<TestAction>(&encoded, &()).unwrap(),
            action
        );

        for length in 0..encoded.len() {
            assert_eq!(
                decode_signed_action::<TestAction>(&encoded[..length], &()),
                Err(ActionValidationError::MalformedEncoding)
            );
        }

        let mut malformed_payload = encoded.to_vec();
        let payload_offset = SIGNED_ACTION_FIXED_BYTES - 64;
        malformed_payload[payload_offset] = 2;
        assert_eq!(
            decode_signed_action::<TestAction>(&malformed_payload, &()),
            Err(ActionValidationError::MalformedEncoding)
        );

        let mut trailing = encoded.to_vec();
        trailing.push(0xff);
        assert_eq!(
            decode_signed_action::<TestAction>(&trailing, &()),
            Err(ActionValidationError::MalformedEncoding)
        );

        assert_eq!(
            decode_signed_action::<TestAction>(&vec![0; MAX_ACTION_BYTES + 1], &()),
            Err(ActionValidationError::ActionTooLarge {
                maximum: MAX_ACTION_BYTES,
                actual: MAX_ACTION_BYTES + 1
            })
        );
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct LargePayload(usize);

    impl Write for LargePayload {
        fn write(&self, buf: &mut impl BufMut) {
            buf.put_bytes(0, self.0);
        }
    }

    impl EncodeSize for LargePayload {
        fn encode_size(&self) -> usize {
            self.0
        }
    }

    #[test]
    fn signing_rejects_a_payload_that_makes_the_envelope_oversized() {
        let payload_size = MAX_ACTION_BYTES - SIGNED_ACTION_FIXED_BYTES + 1;
        let error = SignedAction::sign(
            &key(9),
            ProtocolVersion::V1,
            chain(1),
            0,
            1,
            LargePayload(payload_size),
        )
        .unwrap_err();
        assert_eq!(
            error,
            ActionValidationError::ActionTooLarge {
                maximum: MAX_ACTION_BYTES,
                actual: MAX_ACTION_BYTES + 1
            }
        );
    }

    #[test]
    fn action_ids_are_deterministic_and_cover_the_complete_signed_envelope() {
        let baseline = signed(10, 0);
        assert_eq!(baseline.action_id(), signed(10, 0).action_id());
        assert_eq!(
            baseline.action_id().as_bytes(),
            [
                0xd1, 0xa6, 0xa4, 0xc8, 0x98, 0xba, 0xbd, 0x7e, 0x13, 0xea, 0xa2, 0x19, 0xbc, 0x9b,
                0xec, 0xec, 0xe5, 0xbd, 0xfb, 0x77, 0xc0, 0x58, 0x2b, 0xb4, 0xb2, 0xc6, 0x4b, 0x48,
                0x47, 0xde, 0x4c, 0x59,
            ]
        );

        let mut changed_signature = baseline.clone();
        changed_signature.signature = signed(11, 0).signature;
        assert_ne!(baseline.action_id(), changed_signature.action_id());

        let mut changed_payload = baseline.clone();
        changed_payload.payload = TestAction::Clear;
        assert_ne!(baseline.action_id(), changed_payload.action_id());
    }

    #[test]
    fn malformed_nonce_state_and_nonce_exhaustion_do_not_mutate_state() {
        let context = ActionVerificationContext::current(chain(1), 1);
        let action = signed(12, 0);
        let mut state = crate::state::InMemoryStateBatch::new();
        state.put(
            StateKey::account(&action.actor),
            vec![0; 7].into_boxed_slice(),
        );
        assert_eq!(
            action.verify_and_advance_nonce(&mut state, &context),
            Err(ActionValidationError::MalformedNonceState { actual: 7 })
        );

        state.put(
            StateKey::account(&action.actor),
            Box::new(u64::MAX.to_be_bytes()),
        );
        let max_action = SignedAction::sign(
            &key(12),
            ProtocolVersion::V1,
            chain(1),
            u64::MAX,
            10,
            TestAction::Clear,
        )
        .unwrap();
        assert_eq!(
            max_action.verify_and_advance_nonce(&mut state, &context),
            Err(ActionValidationError::NonceExhausted)
        );
        assert_eq!(
            state.get(&StateKey::account(&action.actor)).as_deref(),
            Some(u64::MAX.to_be_bytes().as_slice())
        );
    }
}
