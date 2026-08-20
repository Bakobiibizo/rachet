//! Canonical, consensus-independent validation ledger state keys.
//!
//! State keys are binary tuples. The first byte is an explicit namespace tag;
//! every following identifier uses its fixed-width canonical bytes. Keeping key
//! construction here prevents protocol code from assembling ad hoc string keys.

mod batch;
mod commitments;
mod evidence;
mod jobs;
mod resolutions;

pub use batch::{
    InMemoryStateBatch, StateBatch, StateBatchError, StateEntry, StateValue, reference_state_root,
};
pub use commitments::{CommitmentRecord, CommitmentStatus};
pub use evidence::{AttestationRecord, EvidenceRecord};
pub use jobs::{ClaimRecord, JobRecord, JobStatus};
pub use resolutions::{ChallengeRecord, ChallengeStatus, ClaimResolution, ClaimStatus};

use crate::primitives::{
    ActorId, AttestationId, ChallengeId, ClaimId, CommitmentId, EvidenceId, JobId,
};
use core::fmt;

/// The first byte of every canonical state key.
///
/// Discriminants are protocol bytes, not declaration-order defaults. Their
/// numeric order is the required lexicographic namespace order from section 17.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum StateNamespace {
    /// Actor account state.
    Account = 0x00,
    /// Canonical jobs by job identifier.
    Job = 0x10,
    /// Canonical claims by claim identifier.
    Claim = 0x11,
    /// Registered evidence by evidence identifier.
    Evidence = 0x12,
    /// Attestations by attestation identifier.
    Attestation = 0x13,
    /// Commitments by commitment identifier.
    Commitment = 0x14,
    /// Challenges by challenge identifier.
    Challenge = 0x15,
    /// Jobs indexed by customer and then job identifier.
    JobsByCustomer = 0x20,
    /// Attestations indexed by operator and then attestation identifier.
    AttestationsByOperator = 0x21,
    /// Claims indexed by job and then claim identifier.
    ClaimsByJob = 0x22,
    /// Mechanism-private state.
    Mechanism = 0x30,
    /// Genesis-committed protocol configuration.
    ProtocolConfig = 0x40,
    /// Current protocol epoch.
    ProtocolEpoch = 0x41,
}

impl StateNamespace {
    /// Returns the exact binary namespace tag.
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// A stable numeric namespace allocated to one compiled mechanism.
///
/// Big-endian encoding preserves numeric mechanism namespace order in the
/// database. The mechanism registry is responsible for assigning and isolating
/// these values; this core type only provides their canonical key encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct MechanismNamespace(u16);

impl MechanismNamespace {
    /// Constructs a mechanism namespace from its genesis-fixed number.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the genesis-fixed namespace number.
    pub const fn get(self) -> u16 {
        self.0
    }

    const fn to_key_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl From<u16> for MechanismNamespace {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<MechanismNamespace> for u16 {
    fn from(namespace: MechanismNamespace) -> Self {
        namespace.get()
    }
}

/// An encoded canonical state key.
///
/// There is deliberately no constructor from arbitrary bytes. Call one of the
/// typed namespace accessors so identifiers cannot be placed in the wrong key
/// family and protocol code cannot invent another layout.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct StateKey(Box<[u8]>);

impl StateKey {
    /// Returns the account key for an actor.
    pub fn account(actor: &ActorId) -> Self {
        Self::fixed(StateNamespace::Account, [actor.as_ref()])
    }

    /// Returns the primary key for a job.
    pub fn job(job_id: &JobId) -> Self {
        Self::fixed(StateNamespace::Job, [job_id.as_ref()])
    }

    /// Returns the primary key for a claim.
    pub fn claim(claim_id: &ClaimId) -> Self {
        Self::fixed(StateNamespace::Claim, [claim_id.as_ref()])
    }

    /// Returns the primary key for registered evidence.
    pub fn evidence(evidence_id: &EvidenceId) -> Self {
        Self::fixed(StateNamespace::Evidence, [evidence_id.as_ref()])
    }

    /// Returns the primary key for an attestation.
    pub fn attestation(attestation_id: &AttestationId) -> Self {
        Self::fixed(StateNamespace::Attestation, [attestation_id.as_ref()])
    }

    /// Returns the primary key for a commitment.
    pub fn commitment(commitment_id: &CommitmentId) -> Self {
        Self::fixed(StateNamespace::Commitment, [commitment_id.as_ref()])
    }

    /// Returns the primary key for a challenge.
    pub fn challenge(challenge_id: &ChallengeId) -> Self {
        Self::fixed(StateNamespace::Challenge, [challenge_id.as_ref()])
    }

    /// Returns a customer/job composite index key.
    pub fn job_by_customer(actor: &ActorId, job_id: &JobId) -> Self {
        Self::fixed(
            StateNamespace::JobsByCustomer,
            [actor.as_ref(), job_id.as_ref()],
        )
    }

    /// Returns an operator/attestation composite index key.
    pub fn attestation_by_operator(actor: &ActorId, attestation_id: &AttestationId) -> Self {
        Self::fixed(
            StateNamespace::AttestationsByOperator,
            [actor.as_ref(), attestation_id.as_ref()],
        )
    }

    /// Returns a job/claim composite index key.
    pub fn claim_by_job(job_id: &JobId, claim_id: &ClaimId) -> Self {
        Self::fixed(
            StateNamespace::ClaimsByJob,
            [job_id.as_ref(), claim_id.as_ref()],
        )
    }

    /// Returns a key in a mechanism's isolated state namespace.
    ///
    /// `module_key` is the mechanism's own canonical binary key. The fixed-width
    /// mechanism namespace makes the boundary unambiguous for every byte value,
    /// including an empty local key.
    pub fn mechanism(namespace: MechanismNamespace, module_key: &[u8]) -> Self {
        let namespace = namespace.to_key_bytes();
        Self::fixed(StateNamespace::Mechanism, [&namespace, module_key])
    }

    /// Returns the singleton protocol configuration key.
    pub fn protocol_config() -> Self {
        Self::fixed(StateNamespace::ProtocolConfig, [])
    }

    /// Returns the singleton current-epoch key.
    pub fn protocol_epoch() -> Self {
        Self::fixed(StateNamespace::ProtocolEpoch, [])
    }

    /// Restores a key from bytes previously emitted by [`Self::as_bytes`].
    ///
    /// This trust-boundary constructor accepts only the fixed section 17 key
    /// shapes (or a mechanism key containing its two-byte namespace). It exists
    /// for authenticated storage and retained-state replay; protocol code should
    /// continue to use the typed constructors above.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StateKeyDecodeError> {
        let Some(tag) = bytes.first().copied() else {
            return Err(StateKeyDecodeError::Empty);
        };
        let valid_length = match tag {
            0x00 | 0x10..=0x15 => bytes.len() == 33,
            0x20..=0x22 => bytes.len() == 65,
            0x30 => bytes.len() >= 3,
            0x40 | 0x41 => bytes.len() == 1,
            _ => return Err(StateKeyDecodeError::UnknownNamespace(tag)),
        };
        if !valid_length {
            return Err(StateKeyDecodeError::InvalidLength {
                namespace: tag,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.into()))
    }

    /// Returns the key's namespace.
    pub fn namespace(&self) -> StateNamespace {
        match self.0[0] {
            0x00 => StateNamespace::Account,
            0x10 => StateNamespace::Job,
            0x11 => StateNamespace::Claim,
            0x12 => StateNamespace::Evidence,
            0x13 => StateNamespace::Attestation,
            0x14 => StateNamespace::Commitment,
            0x15 => StateNamespace::Challenge,
            0x20 => StateNamespace::JobsByCustomer,
            0x21 => StateNamespace::AttestationsByOperator,
            0x22 => StateNamespace::ClaimsByJob,
            0x30 => StateNamespace::Mechanism,
            0x40 => StateNamespace::ProtocolConfig,
            0x41 => StateNamespace::ProtocolEpoch,
            _ => unreachable!("StateKey constructors only emit known namespace tags"),
        }
    }

    /// Returns the exact bytes supplied to the state backend.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the key and returns its exact bytes.
    pub fn into_bytes(self) -> Box<[u8]> {
        self.0
    }

    fn fixed<const PARTS: usize>(namespace: StateNamespace, parts: [&[u8]; PARTS]) -> Self {
        let payload_len = parts
            .iter()
            .try_fold(0_usize, |total, part| total.checked_add(part.len()))
            .expect("a state key cannot exceed addressable memory");
        let mut bytes = Vec::with_capacity(
            payload_len
                .checked_add(1)
                .expect("a state key cannot exceed addressable memory"),
        );
        bytes.push(namespace.tag());
        for part in parts {
            bytes.extend_from_slice(part);
        }
        Self(bytes.into_boxed_slice())
    }
}

/// A retained state key was not one exact section 17 binary shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateKeyDecodeError {
    Empty,
    UnknownNamespace(u8),
    InvalidLength { namespace: u8, actual: usize },
}

impl fmt::Display for StateKeyDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("state key is empty"),
            Self::UnknownNamespace(namespace) => {
                write!(formatter, "unknown state-key namespace 0x{namespace:02x}")
            }
            Self::InvalidLength { namespace, actual } => write!(
                formatter,
                "state-key namespace 0x{namespace:02x} has invalid length {actual}"
            ),
        }
    }
}

impl std::error::Error for StateKeyDecodeError {}

impl AsRef<[u8]> for StateKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Sha256Digest;
    use commonware_cryptography::{Signer as _, ed25519};

    fn actor(seed: u64) -> ActorId {
        ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from([byte; 32])
    }

    fn expected(namespace: StateNamespace, parts: &[&[u8]]) -> Vec<u8> {
        let mut bytes = vec![namespace.tag()];
        for part in parts {
            bytes.extend_from_slice(part);
        }
        bytes
    }

    #[test]
    fn retained_keys_restore_only_exact_section_17_shapes() {
        for key in [
            StateKey::account(&actor(1)),
            StateKey::job(&JobId::from_digest(digest(2))),
            StateKey::job_by_customer(&actor(3), &JobId::from_digest(digest(4))),
            StateKey::mechanism(MechanismNamespace::new(5), b"module"),
            StateKey::protocol_config(),
        ] {
            assert_eq!(StateKey::from_canonical_bytes(key.as_bytes()).unwrap(), key);
        }
        assert_eq!(
            StateKey::from_canonical_bytes(&[]),
            Err(StateKeyDecodeError::Empty)
        );
        assert_eq!(
            StateKey::from_canonical_bytes(&[0xff]),
            Err(StateKeyDecodeError::UnknownNamespace(0xff))
        );
        assert!(matches!(
            StateKey::from_canonical_bytes(&[StateNamespace::Account.tag()]),
            Err(StateKeyDecodeError::InvalidLength { .. })
        ));
        assert!(matches!(
            StateKey::from_canonical_bytes(&[StateNamespace::Mechanism.tag(), 0]),
            Err(StateKeyDecodeError::InvalidLength { .. })
        ));
    }

    #[test]
    fn every_section_17_key_has_stable_bytes() {
        let actor = actor(7);
        let job = JobId::from_digest(digest(0x10));
        let claim = ClaimId::from_digest(digest(0x11));
        let evidence = EvidenceId::from_digest(digest(0x12));
        let attestation = AttestationId::from_digest(digest(0x13));
        let commitment = CommitmentId::from_digest(digest(0x14));
        let challenge = ChallengeId::from_digest(digest(0x15));

        assert_eq!(
            StateKey::account(&actor).as_bytes(),
            expected(StateNamespace::Account, &[actor.as_ref()])
        );
        assert_eq!(
            StateKey::job(&job).as_bytes(),
            [vec![0x10], vec![0x10; 32]].concat()
        );
        assert_eq!(
            StateKey::claim(&claim).as_bytes(),
            [vec![0x11], vec![0x11; 32]].concat()
        );
        assert_eq!(
            StateKey::evidence(&evidence).as_bytes(),
            [vec![0x12], vec![0x12; 32]].concat()
        );
        assert_eq!(
            StateKey::attestation(&attestation).as_bytes(),
            [vec![0x13], vec![0x13; 32]].concat()
        );
        assert_eq!(
            StateKey::commitment(&commitment).as_bytes(),
            [vec![0x14], vec![0x14; 32]].concat()
        );
        assert_eq!(
            StateKey::challenge(&challenge).as_bytes(),
            [vec![0x15], vec![0x15; 32]].concat()
        );
        assert_eq!(
            StateKey::job_by_customer(&actor, &job).as_bytes(),
            expected(
                StateNamespace::JobsByCustomer,
                &[actor.as_ref(), &[0x10; 32]],
            )
        );
        assert_eq!(
            StateKey::attestation_by_operator(&actor, &attestation).as_bytes(),
            expected(
                StateNamespace::AttestationsByOperator,
                &[actor.as_ref(), &[0x13; 32]],
            )
        );
        assert_eq!(
            StateKey::claim_by_job(&job, &claim).as_bytes(),
            [vec![0x22], vec![0x10; 32], vec![0x11; 32]].concat()
        );
        assert_eq!(
            StateKey::mechanism(MechanismNamespace::new(0x1234), &[0x00, 0xff]).as_bytes(),
            [0x30, 0x12, 0x34, 0x00, 0xff]
        );
        assert_eq!(StateKey::protocol_config().as_bytes(), [0x40]);
        assert_eq!(StateKey::protocol_epoch().as_bytes(), [0x41]);
    }

    #[test]
    fn key_order_is_lexicographic_by_namespace_then_typed_tuple() {
        let actor_low = actor(1);
        let actor_high = actor(2);
        let (actor_low, actor_high) = if actor_low < actor_high {
            (actor_low, actor_high)
        } else {
            (actor_high, actor_low)
        };
        let job_low = JobId::from_digest(digest(0x01));
        let job_high = JobId::from_digest(digest(0x02));

        let keys = [
            StateKey::account(&actor_low),
            StateKey::job(&job_low),
            StateKey::claim(&ClaimId::from_digest(digest(0x01))),
            StateKey::evidence(&EvidenceId::from_digest(digest(0x01))),
            StateKey::attestation(&AttestationId::from_digest(digest(0x01))),
            StateKey::commitment(&CommitmentId::from_digest(digest(0x01))),
            StateKey::challenge(&ChallengeId::from_digest(digest(0x01))),
            StateKey::job_by_customer(&actor_low, &job_low),
            StateKey::attestation_by_operator(
                &actor_low,
                &AttestationId::from_digest(digest(0x01)),
            ),
            StateKey::claim_by_job(&job_low, &ClaimId::from_digest(digest(0x01))),
            StateKey::mechanism(MechanismNamespace::new(1), b"key"),
            StateKey::protocol_config(),
            StateKey::protocol_epoch(),
        ];
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));

        assert!(
            StateKey::job_by_customer(&actor_low, &job_high)
                < StateKey::job_by_customer(&actor_high, &job_low)
        );
        assert!(
            StateKey::job_by_customer(&actor_low, &job_low)
                < StateKey::job_by_customer(&actor_low, &job_high)
        );
        assert!(
            StateKey::mechanism(MechanismNamespace::new(1), &[0xff])
                < StateKey::mechanism(MechanismNamespace::new(2), &[0x00])
        );
    }

    #[test]
    fn typed_accessors_report_their_exact_namespace() {
        let actor = actor(3);
        let job = JobId::from_digest(digest(1));
        let claim = ClaimId::from_digest(digest(2));
        let cases = [
            (StateKey::account(&actor), StateNamespace::Account),
            (StateKey::job(&job), StateNamespace::Job),
            (StateKey::claim(&claim), StateNamespace::Claim),
            (
                StateKey::evidence(&EvidenceId::from_digest(digest(3))),
                StateNamespace::Evidence,
            ),
            (
                StateKey::attestation(&AttestationId::from_digest(digest(4))),
                StateNamespace::Attestation,
            ),
            (
                StateKey::commitment(&CommitmentId::from_digest(digest(5))),
                StateNamespace::Commitment,
            ),
            (
                StateKey::challenge(&ChallengeId::from_digest(digest(6))),
                StateNamespace::Challenge,
            ),
            (
                StateKey::job_by_customer(&actor, &job),
                StateNamespace::JobsByCustomer,
            ),
            (
                StateKey::attestation_by_operator(&actor, &AttestationId::from_digest(digest(7))),
                StateNamespace::AttestationsByOperator,
            ),
            (
                StateKey::claim_by_job(&job, &claim),
                StateNamespace::ClaimsByJob,
            ),
            (
                StateKey::mechanism(MechanismNamespace::new(0), b""),
                StateNamespace::Mechanism,
            ),
            (StateKey::protocol_config(), StateNamespace::ProtocolConfig),
            (StateKey::protocol_epoch(), StateNamespace::ProtocolEpoch),
        ];

        for (key, namespace) in cases {
            assert_eq!(key.namespace(), namespace);
            assert_eq!(key.as_bytes()[0], namespace.tag());
        }
    }
}
