//! Pure job creation, role eligibility, and closure transitions.

use crate::{
    actions::{CloseJob, CreateJob, ResolutionPolicy},
    bounded::BoundedVec,
    limits::MAX_CLAIMS_PER_JOB,
    primitives::{ActorId, ClaimId, JobId},
    state::{ClaimRecord, ClaimStatus, JobRecord, JobStatus, StateBatch, StateKey, StateNamespace},
};
use commonware_codec::{Decode, Encode, Write as _};
use core::fmt;
use std::collections::BTreeSet;

/// Roles inferred from canonical job and attestation indexes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ActorRoles {
    pub customer: bool,
    pub validation_operator: bool,
    pub resolution_authority: bool,
}

/// IDs created by one successful [`CreateJob`] transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedJob {
    pub job_id: JobId,
    pub claim_ids: BoundedVec<ClaimId, MAX_CLAIMS_PER_JOB>,
}

/// Applies a canonical job creation atomically after validating every input.
pub fn create_job(
    state: &mut dyn StateBatch,
    actor: &ActorId,
    height: u64,
    action: &CreateJob,
) -> Result<CreatedJob, JobTransitionError> {
    validate_lifecycle(height, action)?;
    if action.claims.is_empty() {
        return Err(JobTransitionError::NoClaims);
    }

    let job_id = action.job_id();
    if action.supersedes == Some(job_id) {
        return Err(JobTransitionError::SelfSupersession);
    }
    if state.get(&StateKey::job(&job_id)).is_some() {
        return Err(JobTransitionError::JobAlreadyExists);
    }

    ensure_customer_role(state, actor)?;
    let ResolutionPolicy::ExperimentAuthority { authority } = &action.resolution_policy else {
        return Err(JobTransitionError::ResolutionPolicyNotImplemented);
    };
    ensure_resolution_authority_role(state, authority)?;
    if authority == actor {
        return Err(JobTransitionError::RoleConflict);
    }

    if let Some(predecessor_id) = action.supersedes {
        let predecessor = load_job(state, predecessor_id)?;
        if predecessor.customer != *actor {
            return Err(JobTransitionError::SupersessionCustomerMismatch);
        }
    }

    let mut claim_ids = Vec::with_capacity(action.claims.len());
    let mut unique_claims = BTreeSet::new();
    for definition in &action.claims {
        let mut identity = Vec::with_capacity(32 + definition.statement.len());
        job_id.write(&mut identity);
        definition.write(&mut identity);
        let claim_id = ClaimId::derive(&identity);
        if !unique_claims.insert(claim_id) {
            return Err(JobTransitionError::DuplicateClaim);
        }
        if state.get(&StateKey::claim(&claim_id)).is_some() {
            return Err(JobTransitionError::ClaimAlreadyExists);
        }
        claim_ids.push(claim_id);
    }
    let claim_ids = BoundedVec::new(claim_ids)
        .expect("claim IDs preserve the already bounded definition count");

    let record = JobRecord {
        customer: actor.clone(),
        artifact: action.artifact.clone(),
        claim_ids: claim_ids.clone(),
        resolution_policy: action.resolution_policy.clone(),
        lifecycle: action.lifecycle(),
        supersedes: action.supersedes,
        metadata: action.metadata.clone(),
        status: JobStatus::Open,
    };
    state.put(StateKey::job(&job_id), encoded(&record));
    state.put(
        StateKey::job_by_customer(actor, &job_id),
        Vec::new().into_boxed_slice(),
    );
    for (claim_id, definition) in claim_ids.iter().zip(action.claims.iter()) {
        let claim = ClaimRecord {
            job_id,
            definition: definition.clone(),
            status: ClaimStatus::Open,
        };
        state.put(StateKey::claim(claim_id), encoded(&claim));
        state.put(
            StateKey::claim_by_job(&job_id, claim_id),
            Vec::new().into_boxed_slice(),
        );
    }

    Ok(CreatedJob { job_id, claim_ids })
}

/// Applies customer-authorized closure after all inclusive windows have elapsed.
pub fn close_job(
    state: &mut dyn StateBatch,
    actor: &ActorId,
    height: u64,
    action: &CloseJob,
) -> Result<JobId, JobTransitionError> {
    let mut record = load_job(state, action.job_id)?;
    if record.customer != *actor {
        return Err(JobTransitionError::NotJobCustomer);
    }
    if record.status == JobStatus::Closed {
        return Err(JobTransitionError::JobAlreadyClosed);
    }
    let final_closes_at = record.lifecycle.final_closes_at();
    if height <= final_closes_at {
        return Err(JobTransitionError::LifecycleStillOpen {
            final_closes_at,
            current_height: height,
        });
    }

    record.status = JobStatus::Closed;
    state.put(StateKey::job(&action.job_id), encoded(&record));
    Ok(action.job_id)
}

/// Loads and validates one canonical job record.
pub fn load_job(state: &dyn StateBatch, job_id: JobId) -> Result<JobRecord, JobTransitionError> {
    let value = state
        .get(&StateKey::job(&job_id))
        .ok_or(JobTransitionError::JobNotFound)?;
    let record = JobRecord::decode_cfg(value.as_ref(), &())
        .map_err(|_| JobTransitionError::MalformedJobState)?;
    if record.job_id() != job_id {
        return Err(JobTransitionError::JobIdentityMismatch);
    }
    Ok(record)
}

/// Loads and identity-checks one canonical claim record.
pub fn load_claim(
    state: &dyn StateBatch,
    job_id: JobId,
    claim_id: ClaimId,
) -> Result<ClaimRecord, JobTransitionError> {
    let value = state
        .get(&StateKey::claim(&claim_id))
        .ok_or(JobTransitionError::ClaimNotFound)?;
    let record = ClaimRecord::decode_cfg(value.as_ref(), &())
        .map_err(|_| JobTransitionError::MalformedClaimState)?;

    let mut identity = Vec::with_capacity(32 + record.definition.statement.len());
    record.job_id.write(&mut identity);
    record.definition.write(&mut identity);
    if ClaimId::derive(&identity) != claim_id {
        return Err(JobTransitionError::ClaimIdentityMismatch);
    }
    if record.job_id != job_id {
        return Err(JobTransitionError::ClaimJobMismatch);
    }
    Ok(record)
}

/// Infers protocol roles without introducing a second mutable role registry.
pub fn actor_roles(
    state: &dyn StateBatch,
    actor: &ActorId,
) -> Result<ActorRoles, JobTransitionError> {
    let customer_prefix = index_prefix(StateNamespace::JobsByCustomer, actor);
    let operator_prefix = index_prefix(StateNamespace::AttestationsByOperator, actor);
    let mut roles = ActorRoles::default();

    for (key, value) in state.entries() {
        match key.namespace() {
            StateNamespace::JobsByCustomer => {
                roles.customer |= key.as_bytes().starts_with(&customer_prefix);
            }
            StateNamespace::AttestationsByOperator => {
                roles.validation_operator |= key.as_bytes().starts_with(&operator_prefix);
            }
            StateNamespace::Job => {
                let job = JobRecord::decode_cfg(value.as_ref(), &())
                    .map_err(|_| JobTransitionError::MalformedJobState)?;
                roles.resolution_authority |=
                    job.resolution_policy.experiment_authority() == Some(actor);
            }
            _ => {}
        }
    }
    Ok(roles)
}

/// Rejects an actor-authority attempting to become a customer.
pub fn ensure_customer_role(
    state: &dyn StateBatch,
    actor: &ActorId,
) -> Result<(), JobTransitionError> {
    if actor_roles(state, actor)?.resolution_authority {
        return Err(JobTransitionError::RoleConflict);
    }
    Ok(())
}

/// Rejects a resolution authority from validation-operator participation.
///
/// Attestation transitions must call this before writing the operator index;
/// doing so also prevents any mechanism from treating an authority attestation
/// as reputation-bearing validation work.
pub fn ensure_validation_operator_role(
    state: &dyn StateBatch,
    actor: &ActorId,
) -> Result<(), JobTransitionError> {
    if actor_roles(state, actor)?.resolution_authority {
        return Err(JobTransitionError::RoleConflict);
    }
    Ok(())
}

/// Rejects a customer or validation operator from authority configuration.
pub fn ensure_resolution_authority_role(
    state: &dyn StateBatch,
    actor: &ActorId,
) -> Result<(), JobTransitionError> {
    let roles = actor_roles(state, actor)?;
    if roles.customer || roles.validation_operator {
        return Err(JobTransitionError::RoleConflict);
    }
    Ok(())
}

fn validate_lifecycle(height: u64, action: &CreateJob) -> Result<(), JobTransitionError> {
    if action.validation_opens_at < height {
        return Err(JobTransitionError::ValidationAlreadyOpened);
    }
    if action.validation_closes_at < action.validation_opens_at {
        return Err(JobTransitionError::ValidationClosesBeforeOpen);
    }
    if action
        .reveal_closes_at
        .is_some_and(|reveal| reveal < action.validation_closes_at)
    {
        return Err(JobTransitionError::RevealClosesBeforeValidation);
    }
    let challenge_not_before = action
        .reveal_closes_at
        .unwrap_or(action.validation_closes_at);
    if action
        .challenge_closes_at
        .is_some_and(|challenge| challenge < challenge_not_before)
    {
        return Err(JobTransitionError::ChallengeClosesBeforePriorPhase);
    }
    Ok(())
}

fn encoded<T: Encode>(value: &T) -> Box<[u8]> {
    value.encode().to_vec().into_boxed_slice()
}

fn index_prefix(namespace: StateNamespace, actor: &ActorId) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(1 + actor.as_bytes().len());
    prefix.push(namespace.tag());
    prefix.extend_from_slice(actor.as_bytes());
    prefix
}

/// Stable failures from job lifecycle transitions and role checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobTransitionError {
    NoClaims,
    ValidationAlreadyOpened,
    ValidationClosesBeforeOpen,
    RevealClosesBeforeValidation,
    ChallengeClosesBeforePriorPhase,
    JobAlreadyExists,
    JobNotFound,
    JobIdentityMismatch,
    MalformedJobState,
    ClaimAlreadyExists,
    ClaimNotFound,
    ClaimIdentityMismatch,
    MalformedClaimState,
    ClaimJobMismatch,
    DuplicateClaim,
    SelfSupersession,
    SupersessionCustomerMismatch,
    RoleConflict,
    ResolutionPolicyNotImplemented,
    NotJobCustomer,
    JobAlreadyClosed,
    LifecycleStillOpen {
        final_closes_at: u64,
        current_height: u64,
    },
}

impl JobTransitionError {
    /// Returns a stable machine-readable protocol error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoClaims => "JOB_CLAIMS_EMPTY",
            Self::ValidationAlreadyOpened => "JOB_VALIDATION_ALREADY_OPENED",
            Self::ValidationClosesBeforeOpen => "JOB_VALIDATION_WINDOW_INVALID",
            Self::RevealClosesBeforeValidation => "JOB_REVEAL_WINDOW_INVALID",
            Self::ChallengeClosesBeforePriorPhase => "JOB_CHALLENGE_WINDOW_INVALID",
            Self::JobAlreadyExists => "JOB_ALREADY_EXISTS",
            Self::JobNotFound => "JOB_NOT_FOUND",
            Self::JobIdentityMismatch => "JOB_IDENTITY_INVALID",
            Self::MalformedJobState => "JOB_STATE_MALFORMED",
            Self::ClaimAlreadyExists => "CLAIM_ALREADY_EXISTS",
            Self::ClaimNotFound => "CLAIM_NOT_FOUND",
            Self::ClaimIdentityMismatch => "CLAIM_IDENTITY_INVALID",
            Self::MalformedClaimState => "CLAIM_STATE_MALFORMED",
            Self::ClaimJobMismatch => "CLAIM_JOB_MISMATCH",
            Self::DuplicateClaim => "JOB_CLAIM_DUPLICATE",
            Self::SelfSupersession => "JOB_SELF_SUPERSESSION",
            Self::SupersessionCustomerMismatch => "JOB_SUPERSESSION_CUSTOMER_INVALID",
            Self::RoleConflict => "ACTOR_ROLE_CONFLICT",
            Self::ResolutionPolicyNotImplemented => "RESOLUTION_POLICY_NOT_IMPLEMENTED",
            Self::NotJobCustomer => "JOB_CUSTOMER_UNAUTHORIZED",
            Self::JobAlreadyClosed => "JOB_ALREADY_CLOSED",
            Self::LifecycleStillOpen { .. } => "JOB_LIFECYCLE_OPEN",
        }
    }
}

impl fmt::Display for JobTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for JobTransitionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::ClaimDefinition,
        artifacts::{ContentRef, GitArtifact, GitHash},
        bounded::{BoundedBytes, BoundedVec},
        primitives::Sha256Digest,
        state::InMemoryStateBatch,
    };
    use commonware_cryptography::{Signer as _, ed25519};

    fn actor(seed: u64) -> ActorId {
        ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
    }

    fn bounded<const MAX: usize>(value: &[u8]) -> BoundedBytes<MAX> {
        BoundedBytes::try_from(value).unwrap()
    }

    fn artifact(candidate: u8, specification: u8) -> GitArtifact {
        GitArtifact::new(
            bounded(b"https://git.invalid/repository"),
            GitHash::sha1([1; 20]),
            GitHash::sha256([candidate; 32]),
            ContentRef::new(
                Sha256Digest::from([specification; 32]),
                bounded(b"cas://spec"),
                bounded(b"text/markdown"),
            ),
        )
    }

    fn claim(statement: &[u8]) -> ClaimDefinition {
        ClaimDefinition::new(bounded(statement))
    }

    fn create(candidate: u8, authority: ActorId) -> CreateJob {
        CreateJob {
            artifact: artifact(candidate, 9),
            claims: BoundedVec::new(vec![claim(b"tests pass"), claim(b"no regression")]).unwrap(),
            resolution_policy: ResolutionPolicy::ExperimentAuthority { authority },
            validation_opens_at: 10,
            validation_closes_at: 20,
            reveal_closes_at: Some(25),
            challenge_closes_at: Some(30),
            supersedes: None,
            metadata: bounded(b"fixture"),
        }
    }

    #[test]
    fn create_stores_immutable_job_claims_policy_windows_and_indexes() {
        let customer = actor(1);
        let authority = actor(2);
        let action = create(3, authority.clone());
        let mut state = InMemoryStateBatch::new();

        let created = create_job(&mut state, &customer, 10, &action).unwrap();
        assert_eq!(created.job_id, action.artifact.job_id());
        assert_eq!(created.claim_ids.len(), 2);

        let stored = load_job(&state, created.job_id).unwrap();
        assert_eq!(stored.customer, customer);
        assert_eq!(stored.artifact, action.artifact);
        assert_eq!(stored.claim_ids, created.claim_ids);
        assert_eq!(stored.resolution_policy, action.resolution_policy);
        assert_eq!(stored.lifecycle, action.lifecycle());
        assert_eq!(stored.status, JobStatus::Open);
        assert!(
            state
                .get(&StateKey::job_by_customer(&customer, &created.job_id))
                .is_some()
        );

        for (claim_id, definition) in created.claim_ids.iter().zip(action.claims.iter()) {
            let bytes = state.get(&StateKey::claim(claim_id)).unwrap();
            let stored_claim = ClaimRecord::decode_cfg(bytes.as_ref(), &()).unwrap();
            assert_eq!(stored_claim.job_id, created.job_id);
            assert_eq!(&stored_claim.definition, definition);
            assert!(
                state
                    .get(&StateKey::claim_by_job(&created.job_id, claim_id))
                    .is_some()
            );
        }
        assert!(
            actor_roles(&state, &authority)
                .unwrap()
                .resolution_authority
        );
    }

    #[test]
    fn lifecycle_creation_boundaries_are_inclusive_and_invalid_orders_are_rejected() {
        let customer = actor(3);
        let authority = actor(4);

        let mut boundary = create(10, authority.clone());
        boundary.validation_opens_at = 7;
        boundary.validation_closes_at = 7;
        boundary.reveal_closes_at = Some(7);
        boundary.challenge_closes_at = Some(7);
        assert!(create_job(&mut InMemoryStateBatch::new(), &customer, 7, &boundary).is_ok());

        let cases = [
            (
                {
                    let mut action = create(11, authority.clone());
                    action.validation_opens_at = 6;
                    action
                },
                JobTransitionError::ValidationAlreadyOpened,
            ),
            (
                {
                    let mut action = create(12, authority.clone());
                    action.validation_opens_at = 11;
                    action.validation_closes_at = 10;
                    action
                },
                JobTransitionError::ValidationClosesBeforeOpen,
            ),
            (
                {
                    let mut action = create(13, authority.clone());
                    action.reveal_closes_at = Some(19);
                    action
                },
                JobTransitionError::RevealClosesBeforeValidation,
            ),
            (
                {
                    let mut action = create(14, authority.clone());
                    action.reveal_closes_at = None;
                    action.challenge_closes_at = Some(19);
                    action
                },
                JobTransitionError::ChallengeClosesBeforePriorPhase,
            ),
            (
                {
                    let mut action = create(15, authority);
                    action.challenge_closes_at = Some(24);
                    action
                },
                JobTransitionError::ChallengeClosesBeforePriorPhase,
            ),
        ];

        for (action, expected) in cases {
            let mut state = InMemoryStateBatch::new();
            let root = state.root();
            assert_eq!(create_job(&mut state, &customer, 7, &action), Err(expected));
            assert_eq!(state.root(), root);
        }
    }

    #[test]
    fn close_requires_customer_and_height_after_each_final_inclusive_boundary() {
        let customer = actor(5);
        let authority = actor(6);
        for (candidate, reveal, challenge, final_height) in [
            (20, None, None, 20),
            (21, Some(25), None, 25),
            (22, Some(25), Some(30), 30),
        ] {
            let mut action = create(candidate, authority.clone());
            action.reveal_closes_at = reveal;
            action.challenge_closes_at = challenge;
            let mut state = InMemoryStateBatch::new();
            let created = create_job(&mut state, &customer, 10, &action).unwrap();

            assert_eq!(
                close_job(
                    &mut state,
                    &customer,
                    final_height,
                    &CloseJob::new(created.job_id)
                ),
                Err(JobTransitionError::LifecycleStillOpen {
                    final_closes_at: final_height,
                    current_height: final_height,
                })
            );
            assert_eq!(
                load_job(&state, created.job_id).unwrap().status,
                JobStatus::Open
            );
            assert_eq!(
                close_job(
                    &mut state,
                    &customer,
                    final_height + 1,
                    &CloseJob::new(created.job_id)
                ),
                Ok(created.job_id)
            );
            assert_eq!(
                load_job(&state, created.job_id).unwrap().status,
                JobStatus::Closed
            );
            assert_eq!(
                close_job(
                    &mut state,
                    &customer,
                    final_height + 2,
                    &CloseJob::new(created.job_id)
                ),
                Err(JobTransitionError::JobAlreadyClosed)
            );
        }
    }

    #[test]
    fn missing_and_non_customer_closure_are_rejected_without_mutation() {
        let customer = actor(7);
        let mut state = InMemoryStateBatch::new();
        let missing = JobId::derive(b"missing");
        assert_eq!(
            close_job(&mut state, &customer, 99, &CloseJob::new(missing)),
            Err(JobTransitionError::JobNotFound)
        );

        let created = create_job(&mut state, &customer, 10, &create(30, actor(8))).unwrap();
        let before = state.root();
        assert_eq!(
            close_job(&mut state, &actor(9), 31, &CloseJob::new(created.job_id)),
            Err(JobTransitionError::NotJobCustomer)
        );
        assert_eq!(state.root(), before);
    }

    #[test]
    fn revisions_require_owned_existing_predecessors_and_new_artifact_identity() {
        let customer = actor(10);
        let authority = actor(11);
        let mut state = InMemoryStateBatch::new();
        let original =
            create_job(&mut state, &customer, 10, &create(40, authority.clone())).unwrap();

        let mut self_supersession = create(40, authority.clone());
        self_supersession.supersedes = Some(original.job_id);
        assert_eq!(
            create_job(&mut state, &customer, 10, &self_supersession),
            Err(JobTransitionError::SelfSupersession)
        );

        let mut revision = create(41, authority.clone());
        revision.supersedes = Some(original.job_id);
        let revised = create_job(&mut state, &customer, 10, &revision).unwrap();
        assert_ne!(revised.job_id, original.job_id);
        assert_eq!(
            load_job(&state, revised.job_id).unwrap().supersedes,
            Some(original.job_id)
        );
        assert_eq!(load_job(&state, original.job_id).unwrap().supersedes, None);

        let mut unknown = create(42, authority.clone());
        unknown.supersedes = Some(JobId::derive(b"unknown"));
        assert_eq!(
            create_job(&mut state, &customer, 10, &unknown),
            Err(JobTransitionError::JobNotFound)
        );

        let mut foreign = create(43, authority);
        foreign.supersedes = Some(original.job_id);
        assert_eq!(
            create_job(&mut state, &actor(12), 10, &foreign),
            Err(JobTransitionError::SupersessionCustomerMismatch)
        );
    }

    #[test]
    fn same_artifact_cannot_overwrite_job_or_claim_content() {
        let customer = actor(13);
        let mut state = InMemoryStateBatch::new();
        let original = create(50, actor(14));
        let created = create_job(&mut state, &customer, 10, &original).unwrap();
        let before = state.root();

        let mut attempted_rewrite = original;
        attempted_rewrite.claims = BoundedVec::new(vec![claim(b"rewritten")]).unwrap();
        assert_eq!(
            create_job(&mut state, &customer, 10, &attempted_rewrite),
            Err(JobTransitionError::JobAlreadyExists)
        );
        assert_eq!(state.root(), before);
        assert_eq!(
            load_job(&state, created.job_id).unwrap().claim_ids,
            created.claim_ids
        );
    }

    #[test]
    fn empty_and_duplicate_claim_sets_are_rejected_atomically() {
        let customer = actor(15);
        let authority = actor(16);
        let mut empty = create(60, authority.clone());
        empty.claims = BoundedVec::default();
        assert_eq!(
            create_job(&mut InMemoryStateBatch::new(), &customer, 10, &empty),
            Err(JobTransitionError::NoClaims)
        );

        let duplicate_claim = claim(b"same");
        let mut duplicate = create(61, authority);
        duplicate.claims = BoundedVec::new(vec![duplicate_claim.clone(), duplicate_claim]).unwrap();
        let mut state = InMemoryStateBatch::new();
        let root = state.root();
        assert_eq!(
            create_job(&mut state, &customer, 10, &duplicate),
            Err(JobTransitionError::DuplicateClaim)
        );
        assert_eq!(state.root(), root);
    }

    #[test]
    fn resolution_authorities_are_disjoint_from_customer_and_validation_roles() {
        let customer = actor(17);
        let authority = actor(18);
        let mut state = InMemoryStateBatch::new();
        create_job(&mut state, &customer, 10, &create(70, authority.clone())).unwrap();

        assert_eq!(
            ensure_validation_operator_role(&state, &authority),
            Err(JobTransitionError::RoleConflict)
        );
        assert_eq!(
            create_job(&mut state, &authority, 10, &create(71, actor(19))),
            Err(JobTransitionError::RoleConflict)
        );

        let own_authority = create(72, customer.clone());
        assert_eq!(
            create_job(&mut state, &customer, 10, &own_authority),
            Err(JobTransitionError::RoleConflict)
        );

        let customer_as_authority = create(73, customer.clone());
        assert_eq!(
            create_job(&mut state, &actor(20), 10, &customer_as_authority),
            Err(JobTransitionError::RoleConflict)
        );

        let prior_operator = actor(21);
        state.put(
            StateKey::attestation_by_operator(
                &prior_operator,
                &crate::primitives::AttestationId::derive(b"attestation"),
            ),
            Vec::new().into_boxed_slice(),
        );
        assert_eq!(
            create_job(&mut state, &actor(22), 10, &create(74, prior_operator)),
            Err(JobTransitionError::RoleConflict)
        );
    }

    #[test]
    fn deferred_deterministic_verifier_policy_is_rejected_without_state() {
        let customer = actor(23);
        let mut action = create(80, actor(24));
        action.resolution_policy = ResolutionPolicy::DeterministicVerifier {
            verifier_id: Sha256Digest::from([8; 32]),
            verifier_spec: ContentRef::new(
                Sha256Digest::from([9; 32]),
                bounded(b"cas://verifier"),
                bounded(b"application/wasm"),
            ),
        };
        let mut state = InMemoryStateBatch::new();
        let root = state.root();
        assert_eq!(
            create_job(&mut state, &customer, 10, &action),
            Err(JobTransitionError::ResolutionPolicyNotImplemented)
        );
        assert_eq!(state.root(), root);
    }
}
