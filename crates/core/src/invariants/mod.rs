//! Protocol state and transition invariants executed by the authoritative block path.

use crate::{
    actions::{Action, ResolutionPolicy, SignedAction, reveal_digest},
    primitives::{ActorId, ClaimId, EvidenceId, JobId},
    state::{
        AttestationRecord, ChallengeRecord, ChallengeStatus, ClaimRecord, ClaimStatus,
        CommitmentRecord, CommitmentStatus, EvidenceRecord, JobRecord, JobStatus, StateBatch,
        StateEntry, StateKey, StateNamespace,
    },
};
use commonware_codec::{Decode, Read, Write as _};
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

/// Checks the complete canonical state graph required at every execution boundary.
///
/// The check is deterministic: it consumes only ordered candidate state, decodes
/// every canonical record, recomputes every content ID, verifies all references
/// and indexes, and derives role separation from canonical records.
pub fn check_core_invariants(state: &dyn StateBatch) -> Result<(), CoreInvariantError> {
    let entries = state.entries();
    for pair in entries.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Err(CoreInvariantError::StateIterationNotStrictlyOrdered);
        }
    }

    let mut jobs = BTreeMap::new();
    let mut claims = BTreeMap::new();
    let mut evidence = BTreeMap::new();
    let mut attestations = BTreeMap::new();
    let mut challenges = BTreeMap::new();
    let mut actual_indexes: BTreeMap<StateNamespace, BTreeSet<StateKey>> = BTreeMap::new();

    for (key, value) in &entries {
        let namespace = key.namespace();
        match namespace {
            StateNamespace::Account => {
                if key.as_bytes().len() != 33 {
                    return Err(CoreInvariantError::MalformedStateKey { namespace });
                }
                if value.len() != 8 {
                    return Err(CoreInvariantError::MalformedActorNonce {
                        actual: value.len(),
                    });
                }
            }
            StateNamespace::Job => {
                let record: JobRecord = decode(value, namespace)?;
                let id = record.job_id();
                ensure_key(key, StateKey::job(&id), namespace)?;
                jobs.insert(id, record);
            }
            StateNamespace::Claim => {
                let record: ClaimRecord = decode(value, namespace)?;
                let id = claim_id(&record);
                ensure_key(key, StateKey::claim(&id), namespace)?;
                claims.insert(id, record);
            }
            StateNamespace::Evidence => {
                let record: EvidenceRecord = decode(value, namespace)?;
                let id = record.evidence_id();
                ensure_key(key, StateKey::evidence(&id), namespace)?;
                evidence.insert(id, record);
            }
            StateNamespace::Attestation => {
                let record: AttestationRecord = decode(value, namespace)?;
                let id = record.attestation_id();
                ensure_key(key, StateKey::attestation(&id), namespace)?;
                attestations.insert(id, record);
            }
            StateNamespace::Commitment => {
                let record: CommitmentRecord = decode(value, namespace)?;
                let id = record.commitment_id();
                ensure_key(key, StateKey::commitment(&id), namespace)?;
                if record.reveal_before_height < record.reveal_after_height
                    || matches!(
                        &record.status,
                        CommitmentStatus::Revealed { payload, salt }
                            if reveal_digest(payload, salt) != record.digest
                    )
                {
                    return Err(CoreInvariantError::InvalidLifecycleState { namespace });
                }
            }
            StateNamespace::Challenge => {
                let record: ChallengeRecord = decode(value, namespace)?;
                let id = record.challenge_id();
                ensure_key(key, StateKey::challenge(&id), namespace)?;
                challenges.insert(id, record);
            }
            StateNamespace::JobsByCustomer
            | StateNamespace::AttestationsByOperator
            | StateNamespace::ClaimsByJob => {
                if !value.is_empty() {
                    return Err(CoreInvariantError::MalformedIndex { namespace });
                }
                actual_indexes
                    .entry(namespace)
                    .or_default()
                    .insert(key.clone());
            }
            StateNamespace::ProtocolEpoch => {
                if key.as_bytes().len() != 1 || value.len() != 8 {
                    return Err(CoreInvariantError::MalformedProtocolState { namespace });
                }
            }
            StateNamespace::ProtocolConfig => {
                if key.as_bytes().len() != 1 {
                    return Err(CoreInvariantError::MalformedProtocolState { namespace });
                }
            }
            StateNamespace::Mechanism => {}
        }
    }

    let mut expected_indexes: BTreeMap<StateNamespace, BTreeSet<StateKey>> = BTreeMap::new();
    let mut customers = BTreeSet::new();
    let mut operators = BTreeSet::new();
    let mut authorities = BTreeSet::new();

    for (job_id, job) in &jobs {
        if job.claim_ids.is_empty() || has_duplicates(job.claim_ids.as_slice()) {
            return Err(CoreInvariantError::InvalidLifecycleState {
                namespace: StateNamespace::Job,
            });
        }
        let ResolutionPolicy::ExperimentAuthority { authority } = &job.resolution_policy else {
            return Err(CoreInvariantError::InvalidResolutionPolicy);
        };
        customers.insert(job.customer.clone());
        authorities.insert(authority.clone());
        expected_indexes
            .entry(StateNamespace::JobsByCustomer)
            .or_default()
            .insert(StateKey::job_by_customer(&job.customer, job_id));

        let all_resolved = job.claim_ids.iter().all(|claim_id| {
            claims
                .get(claim_id)
                .is_some_and(|claim| matches!(claim.status, ClaimStatus::Resolved(_)))
        });
        if (job.status == JobStatus::Resolved && !all_resolved)
            || (job.status == JobStatus::Open && all_resolved)
        {
            return Err(CoreInvariantError::InvalidLifecycleState {
                namespace: StateNamespace::Job,
            });
        }
        for claim_id in &job.claim_ids {
            let claim = claims
                .get(claim_id)
                .ok_or(CoreInvariantError::MissingReference {
                    namespace: StateNamespace::Job,
                })?;
            if claim.job_id != *job_id {
                return Err(CoreInvariantError::ReferenceMismatch {
                    namespace: StateNamespace::Claim,
                });
            }
        }
    }

    for (claim_id, claim) in &claims {
        let job = jobs
            .get(&claim.job_id)
            .ok_or(CoreInvariantError::MissingReference {
                namespace: StateNamespace::Claim,
            })?;
        if !job.claim_ids.iter().any(|id| id == claim_id) {
            return Err(CoreInvariantError::ReferenceMismatch {
                namespace: StateNamespace::Claim,
            });
        }
        expected_indexes
            .entry(StateNamespace::ClaimsByJob)
            .or_default()
            .insert(StateKey::claim_by_job(&claim.job_id, claim_id));
        if let ClaimStatus::Resolved(resolution) = &claim.status {
            check_evidence_references(
                &evidence,
                claim.job_id,
                Some(*claim_id),
                resolution.evidence_ids.as_slice(),
                StateNamespace::Claim,
            )?;
        }
    }

    for record in evidence.values() {
        if !jobs.contains_key(&record.job_id) {
            return Err(CoreInvariantError::MissingReference {
                namespace: StateNamespace::Evidence,
            });
        }
        if let Some(claim_id) = record.claim_id {
            let claim = claims
                .get(&claim_id)
                .ok_or(CoreInvariantError::MissingReference {
                    namespace: StateNamespace::Evidence,
                })?;
            if claim.job_id != record.job_id {
                return Err(CoreInvariantError::ReferenceMismatch {
                    namespace: StateNamespace::Evidence,
                });
            }
        }
    }

    for (attestation_id, record) in &attestations {
        let claim = claims
            .get(&record.claim_id)
            .ok_or(CoreInvariantError::MissingReference {
                namespace: StateNamespace::Attestation,
            })?;
        if claim.job_id != record.job_id || record.confidence_basis_points > 10_000 {
            return Err(CoreInvariantError::ReferenceMismatch {
                namespace: StateNamespace::Attestation,
            });
        }
        check_evidence_references(
            &evidence,
            record.job_id,
            Some(record.claim_id),
            record.evidence_ids.as_slice(),
            StateNamespace::Attestation,
        )?;
        operators.insert(record.operator.clone());
        expected_indexes
            .entry(StateNamespace::AttestationsByOperator)
            .or_default()
            .insert(StateKey::attestation_by_operator(
                &record.operator,
                attestation_id,
            ));
    }

    for record in challenges.values() {
        match record.target {
            crate::actions::ChallengeTarget::Claim(claim_id) => {
                let claim = claims
                    .get(&claim_id)
                    .ok_or(CoreInvariantError::MissingReference {
                        namespace: StateNamespace::Challenge,
                    })?;
                if claim.job_id != record.job_id || claim_id != record.claim_id {
                    return Err(CoreInvariantError::ReferenceMismatch {
                        namespace: StateNamespace::Challenge,
                    });
                }
            }
            crate::actions::ChallengeTarget::Attestation(attestation_id) => {
                let attestation = attestations.get(&attestation_id).ok_or(
                    CoreInvariantError::MissingReference {
                        namespace: StateNamespace::Challenge,
                    },
                )?;
                if attestation.job_id != record.job_id || attestation.claim_id != record.claim_id {
                    return Err(CoreInvariantError::ReferenceMismatch {
                        namespace: StateNamespace::Challenge,
                    });
                }
            }
        }
        check_evidence_references(
            &evidence,
            record.job_id,
            Some(record.claim_id),
            record.evidence_ids.as_slice(),
            StateNamespace::Challenge,
        )?;
        if let ChallengeStatus::Resolved { evidence_ids, .. } = &record.status {
            check_evidence_references(
                &evidence,
                record.job_id,
                Some(record.claim_id),
                evidence_ids.as_slice(),
                StateNamespace::Challenge,
            )?;
        }
    }

    for namespace in [
        StateNamespace::JobsByCustomer,
        StateNamespace::AttestationsByOperator,
        StateNamespace::ClaimsByJob,
    ] {
        if actual_indexes.get(&namespace).cloned().unwrap_or_default()
            != expected_indexes
                .get(&namespace)
                .cloned()
                .unwrap_or_default()
        {
            return Err(CoreInvariantError::IndexMismatch { namespace });
        }
    }

    if authorities
        .iter()
        .any(|actor| customers.contains(actor) || operators.contains(actor))
    {
        return Err(CoreInvariantError::RoleSeparationViolation);
    }

    Ok(())
}

/// Checks properties that require both the parent and final candidate state.
///
/// Canonical objects and indexes are append-only. Lifecycle fields may move,
/// but identity-bearing content may not. Actor nonces must advance by exactly
/// the number of accepted actions from that actor, and the stored application
/// epoch must equal the deterministic transition context.
pub fn check_transition_invariants(
    parent: &[StateEntry],
    candidate: &dyn StateBatch,
    actions: &[SignedAction<Action>],
    expected_epoch: u64,
) -> Result<(), CoreInvariantError> {
    let current: BTreeMap<_, _> = candidate.entries().into_iter().collect();
    let mut advanced = BTreeMap::<ActorId, u64>::new();
    for action in actions {
        let count = advanced.entry(action.actor.clone()).or_default();
        *count = count
            .checked_add(1)
            .ok_or(CoreInvariantError::NonceTransitionMismatch)?;
    }
    let advanced_keys: BTreeSet<_> = advanced.keys().map(StateKey::account).collect();

    for (key, old_value) in parent {
        let namespace = key.namespace();
        let Some(new_value) = current.get(key) else {
            if namespace != StateNamespace::Mechanism {
                return Err(CoreInvariantError::CanonicalStateDeleted { namespace });
            }
            continue;
        };
        match namespace {
            StateNamespace::Account => {
                if !advanced_keys.contains(key) && old_value != new_value {
                    return Err(CoreInvariantError::NonceTransitionMismatch);
                }
            }
            StateNamespace::Job => {
                let old: JobRecord = decode(old_value, namespace)?;
                let new: JobRecord = decode(new_value, namespace)?;
                if old.customer != new.customer
                    || old.artifact != new.artifact
                    || old.claim_ids != new.claim_ids
                    || old.resolution_policy != new.resolution_policy
                    || old.lifecycle != new.lifecycle
                    || old.supersedes != new.supersedes
                    || old.metadata != new.metadata
                {
                    return Err(CoreInvariantError::ImmutableStateModified { namespace });
                }
            }
            StateNamespace::Claim => {
                let old: ClaimRecord = decode(old_value, namespace)?;
                let new: ClaimRecord = decode(new_value, namespace)?;
                if old.job_id != new.job_id || old.definition != new.definition {
                    return Err(CoreInvariantError::ImmutableStateModified { namespace });
                }
            }
            StateNamespace::Evidence
            | StateNamespace::Attestation
            | StateNamespace::JobsByCustomer
            | StateNamespace::AttestationsByOperator
            | StateNamespace::ClaimsByJob
            | StateNamespace::ProtocolConfig => {
                if old_value != new_value {
                    return Err(CoreInvariantError::ImmutableStateModified { namespace });
                }
            }
            StateNamespace::Commitment => {
                let old: CommitmentRecord = decode(old_value, namespace)?;
                let new: CommitmentRecord = decode(new_value, namespace)?;
                if old.creator != new.creator
                    || old.subject != new.subject
                    || old.digest != new.digest
                    || old.reveal_after_height != new.reveal_after_height
                    || old.reveal_before_height != new.reveal_before_height
                {
                    return Err(CoreInvariantError::ImmutableStateModified { namespace });
                }
            }
            StateNamespace::Challenge => {
                let old: ChallengeRecord = decode(old_value, namespace)?;
                let new: ChallengeRecord = decode(new_value, namespace)?;
                if old.challenger != new.challenger
                    || old.job_id != new.job_id
                    || old.claim_id != new.claim_id
                    || old.target != new.target
                    || old.counterclaim != new.counterclaim
                    || old.evidence_ids != new.evidence_ids
                {
                    return Err(CoreInvariantError::ImmutableStateModified { namespace });
                }
            }
            StateNamespace::ProtocolEpoch | StateNamespace::Mechanism => {}
        }
    }

    for (actor, count) in advanced {
        let key = StateKey::account(&actor);
        let initial = parent
            .iter()
            .find(|(candidate, _)| candidate == &key)
            .map(|(_, value)| nonce(value))
            .transpose()?
            .unwrap_or(0);
        let expected = initial
            .checked_add(count)
            .ok_or(CoreInvariantError::NonceTransitionMismatch)?;
        let actual = current
            .get(&key)
            .ok_or(CoreInvariantError::NonceTransitionMismatch)
            .and_then(|value| nonce(value))?;
        if actual != expected {
            return Err(CoreInvariantError::NonceTransitionMismatch);
        }
    }

    let epoch = current
        .get(&StateKey::protocol_epoch())
        .ok_or(CoreInvariantError::MalformedProtocolState {
            namespace: StateNamespace::ProtocolEpoch,
        })
        .and_then(|value| nonce(value))?;
    if epoch != expected_epoch {
        return Err(CoreInvariantError::EpochTransitionMismatch {
            expected: expected_epoch,
            actual: epoch,
        });
    }
    Ok(())
}

fn decode<T: Read<Cfg = ()>>(
    value: &[u8],
    namespace: StateNamespace,
) -> Result<T, CoreInvariantError> {
    T::decode_cfg(value, &()).map_err(|_| CoreInvariantError::MalformedStateValue { namespace })
}

fn ensure_key(
    actual: &StateKey,
    expected: StateKey,
    namespace: StateNamespace,
) -> Result<(), CoreInvariantError> {
    if *actual == expected {
        Ok(())
    } else {
        Err(CoreInvariantError::ObjectIdentityMismatch { namespace })
    }
}

fn claim_id(record: &ClaimRecord) -> ClaimId {
    let mut identity = Vec::with_capacity(32 + record.definition.statement.len());
    record.job_id.write(&mut identity);
    record.definition.write(&mut identity);
    ClaimId::derive(&identity)
}

fn check_evidence_references(
    records: &BTreeMap<EvidenceId, EvidenceRecord>,
    job_id: JobId,
    claim_id: Option<ClaimId>,
    ids: &[EvidenceId],
    namespace: StateNamespace,
) -> Result<(), CoreInvariantError> {
    if has_duplicates(ids) {
        return Err(CoreInvariantError::ReferenceMismatch { namespace });
    }
    for id in ids {
        let record = records
            .get(id)
            .ok_or(CoreInvariantError::MissingReference { namespace })?;
        if record.job_id != job_id
            || record
                .claim_id
                .is_some_and(|target| Some(target) != claim_id)
        {
            return Err(CoreInvariantError::ReferenceMismatch { namespace });
        }
    }
    Ok(())
}

fn has_duplicates<T: Ord + Copy>(values: &[T]) -> bool {
    let mut unique = BTreeSet::new();
    values.iter().any(|value| !unique.insert(*value))
}

fn nonce(value: &[u8]) -> Result<u64, CoreInvariantError> {
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| CoreInvariantError::MalformedActorNonce {
            actual: value.len(),
        })?;
    Ok(u64::from_be_bytes(bytes))
}

/// A deterministic failure of an execution-boundary core invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreInvariantError {
    StateIterationNotStrictlyOrdered,
    MalformedStateKey { namespace: StateNamespace },
    MalformedActorNonce { actual: usize },
    MalformedStateValue { namespace: StateNamespace },
    MalformedIndex { namespace: StateNamespace },
    MalformedProtocolState { namespace: StateNamespace },
    ObjectIdentityMismatch { namespace: StateNamespace },
    MissingReference { namespace: StateNamespace },
    ReferenceMismatch { namespace: StateNamespace },
    IndexMismatch { namespace: StateNamespace },
    InvalidLifecycleState { namespace: StateNamespace },
    InvalidResolutionPolicy,
    RoleSeparationViolation,
    CanonicalStateDeleted { namespace: StateNamespace },
    ImmutableStateModified { namespace: StateNamespace },
    NonceTransitionMismatch,
    EpochTransitionMismatch { expected: u64, actual: u64 },
}

impl CoreInvariantError {
    /// Returns the stable machine-readable protocol error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::StateIterationNotStrictlyOrdered => "CORE_STATE_ORDER_INVALID",
            Self::MalformedStateKey { .. } => "CORE_STATE_KEY_MALFORMED",
            Self::MalformedActorNonce { .. } => "CORE_NONCE_STATE_MALFORMED",
            Self::MalformedStateValue { .. } => "CORE_STATE_VALUE_MALFORMED",
            Self::MalformedIndex { .. } => "CORE_INDEX_MALFORMED",
            Self::MalformedProtocolState { .. } => "CORE_PROTOCOL_STATE_MALFORMED",
            Self::ObjectIdentityMismatch { .. } => "CORE_OBJECT_IDENTITY_INVALID",
            Self::MissingReference { .. } => "CORE_REFERENCE_MISSING",
            Self::ReferenceMismatch { .. } => "CORE_REFERENCE_INVALID",
            Self::IndexMismatch { .. } => "CORE_INDEX_INVALID",
            Self::InvalidLifecycleState { .. } => "CORE_LIFECYCLE_INVALID",
            Self::InvalidResolutionPolicy => "CORE_RESOLUTION_POLICY_INVALID",
            Self::RoleSeparationViolation => "CORE_ROLE_SEPARATION_INVALID",
            Self::CanonicalStateDeleted { .. } => "CORE_CANONICAL_STATE_DELETED",
            Self::ImmutableStateModified { .. } => "CORE_IMMUTABLE_STATE_MODIFIED",
            Self::NonceTransitionMismatch => "CORE_NONCE_TRANSITION_INVALID",
            Self::EpochTransitionMismatch { .. } => "CORE_EPOCH_TRANSITION_INVALID",
        }
    }
}

impl fmt::Display for CoreInvariantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CoreInvariantError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{ClaimDefinition, CommitmentSubject, CreateJob},
        artifacts::{ContentRef, GitArtifact, GitHash},
        bounded::{BoundedBytes, BoundedVec},
        primitives::{ChainId, ProtocolVersion, Sha256Digest},
        state::{InMemoryStateBatch, StateBatch},
        transition::create_job,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{Signer as _, ed25519};

    fn actor(seed: u64) -> ActorId {
        ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
    }

    fn bounded<const MAX: usize>(bytes: &[u8]) -> BoundedBytes<MAX> {
        BoundedBytes::try_from(bytes).unwrap()
    }

    fn create(authority: ActorId) -> CreateJob {
        CreateJob {
            artifact: GitArtifact::new(
                bounded(b"https://git.invalid/invariants"),
                GitHash::sha1([1; 20]),
                GitHash::sha256([2; 32]),
                ContentRef::new(
                    Sha256Digest::from([3; 32]),
                    bounded(b"cas://spec"),
                    bounded(b"text/plain"),
                ),
            ),
            claims: BoundedVec::new(vec![ClaimDefinition::new(bounded(b"claim"))]).unwrap(),
            resolution_policy: ResolutionPolicy::ExperimentAuthority { authority },
            validation_opens_at: 10,
            validation_closes_at: 20,
            reveal_closes_at: None,
            challenge_closes_at: Some(30),
            supersedes: None,
            metadata: bounded(b"fixture"),
        }
    }

    fn valid_state() -> (InMemoryStateBatch, JobId) {
        let mut state = InMemoryStateBatch::new();
        let created = create_job(&mut state, &actor(1), 10, &create(actor(2))).unwrap();
        state.put(
            StateKey::protocol_epoch(),
            0_u64.to_be_bytes().as_slice().into(),
        );
        (state, created.job_id)
    }

    #[test]
    fn canonical_graph_and_nonce_shapes_are_checked() {
        let (mut state, _) = valid_state();
        state.put(
            StateKey::account(&actor(3)),
            1_u64.to_be_bytes().as_slice().into(),
        );
        assert_eq!(check_core_invariants(&state), Ok(()));

        state.put(StateKey::account(&actor(3)), vec![0; 7].into_boxed_slice());
        assert_eq!(
            check_core_invariants(&state),
            Err(CoreInvariantError::MalformedActorNonce { actual: 7 })
        );
    }

    #[test]
    fn identity_reference_index_and_role_mutations_fail() {
        let (state, job_id) = valid_state();
        let job_bytes = state.get(&StateKey::job(&job_id)).unwrap();

        let mut wrong_id = state.clone();
        wrong_id.delete(&StateKey::job(&job_id));
        wrong_id.put(StateKey::job(&JobId::derive(b"wrong")), job_bytes.clone());
        assert!(matches!(
            check_core_invariants(&wrong_id),
            Err(CoreInvariantError::ObjectIdentityMismatch { .. })
        ));

        let mut missing_index = state.clone();
        missing_index.delete(&StateKey::job_by_customer(&actor(1), &job_id));
        assert!(matches!(
            check_core_invariants(&missing_index),
            Err(CoreInvariantError::IndexMismatch { .. })
        ));

        let mut role_conflict = state;
        let mut job = JobRecord::decode_cfg(job_bytes.as_ref(), &()).unwrap();
        job.resolution_policy = ResolutionPolicy::ExperimentAuthority {
            authority: job.customer.clone(),
        };
        role_conflict.put(StateKey::job(&job_id), job.encode().as_ref().into());
        assert_eq!(
            check_core_invariants(&role_conflict),
            Err(CoreInvariantError::RoleSeparationViolation)
        );
    }

    #[test]
    fn transition_check_locks_immutable_content_nonces_and_epoch() {
        let (parent, job_id) = valid_state();
        let parent_entries = parent.entries();
        let private = ed25519::PrivateKey::from_seed(3);
        let action = SignedAction::sign(
            &private,
            ProtocolVersion::V1,
            ChainId::new([7; 32]),
            0,
            10,
            Action::CreateCommitment(crate::actions::CreateCommitment {
                subject: CommitmentSubject::Job(job_id),
                digest: Sha256Digest::from([9; 32]),
                reveal_after_height: 11,
                reveal_before_height: 12,
            }),
        )
        .unwrap();
        let mut candidate = parent.clone();
        candidate.put(
            StateKey::account(&action.actor),
            1_u64.to_be_bytes().as_slice().into(),
        );
        assert_eq!(
            check_transition_invariants(&parent_entries, &candidate, &[action], 0),
            Ok(())
        );

        let mut rewritten = candidate;
        let mut job = JobRecord::decode_cfg(
            rewritten.get(&StateKey::job(&job_id)).unwrap().as_ref(),
            &(),
        )
        .unwrap();
        job.metadata = bounded(b"rewritten");
        rewritten.put(StateKey::job(&job_id), job.encode().as_ref().into());
        assert!(matches!(
            check_transition_invariants(&parent_entries, &rewritten, &[], 0),
            Err(CoreInvariantError::ImmutableStateModified {
                namespace: StateNamespace::Job
            })
        ));
    }
}
