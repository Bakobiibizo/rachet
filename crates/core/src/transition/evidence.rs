//! Pure evidence registration and validation-attestation transitions.

use super::jobs::{JobTransitionError, ensure_validation_operator_role};
use crate::{
    actions::{RegisterEvidence, SubmitAttestation},
    limits::MAX_ATTESTATIONS_PER_CLAIM,
    numeric::BasisPoints,
    primitives::{ActorId, AttestationId, ClaimId, EvidenceId, JobId},
    state::{
        AttestationRecord, ClaimRecord, EvidenceRecord, JobRecord, JobStatus, StateBatch, StateKey,
        StateNamespace,
    },
};
use commonware_codec::{Decode, Encode, Write as _};
use core::fmt;
use std::collections::BTreeSet;

/// Registers immutable evidence metadata while retaining only off-chain references.
pub fn register_evidence(
    state: &mut dyn StateBatch,
    actor: &ActorId,
    height: u64,
    action: &RegisterEvidence,
) -> Result<EvidenceId, EvidenceAttestationError> {
    let job = load_target_job(state, action.job_id)?;
    if job.status == JobStatus::Closed {
        return Err(EvidenceAttestationError::JobClosed);
    }
    let final_closes_at = job.lifecycle.final_closes_at();
    if height > final_closes_at {
        return Err(EvidenceAttestationError::EvidenceWindowClosed {
            final_closes_at,
            current_height: height,
        });
    }
    if let Some(claim_id) = action.claim_id {
        load_target_claim(state, action.job_id, claim_id)?;
    }

    let evidence_id = action.evidence_id();
    if state.get(&StateKey::evidence(&evidence_id)).is_some() {
        return Err(EvidenceAttestationError::EvidenceAlreadyExists);
    }

    let record = EvidenceRecord::from_action(actor.clone(), action);
    state.put(StateKey::evidence(&evidence_id), encoded(&record));
    Ok(evidence_id)
}

/// Submits one immutable attestation during the job's inclusive validation window.
pub fn submit_attestation(
    state: &mut dyn StateBatch,
    actor: &ActorId,
    height: u64,
    action: &SubmitAttestation,
) -> Result<AttestationId, EvidenceAttestationError> {
    let job = load_target_job(state, action.job_id)?;
    if job.status == JobStatus::Closed {
        return Err(EvidenceAttestationError::JobClosed);
    }
    if !job.lifecycle.validation_is_open(height) {
        return Err(EvidenceAttestationError::ValidationNotOpen {
            validation_opens_at: job.lifecycle.validation_opens_at,
            validation_closes_at: job.lifecycle.validation_closes_at,
            current_height: height,
        });
    }
    load_target_claim(state, action.job_id, action.claim_id)?;

    if BasisPoints::new(action.confidence_basis_points).is_err() {
        return Err(EvidenceAttestationError::ConfidenceOutOfRange {
            value: action.confidence_basis_points,
        });
    }
    ensure_validation_operator_role(state, actor).map_err(map_role_error)?;

    let mut unique_evidence = BTreeSet::new();
    for evidence_id in &action.evidence_ids {
        if !unique_evidence.insert(*evidence_id) {
            return Err(EvidenceAttestationError::DuplicateEvidenceReference);
        }
        let evidence = load_evidence(state, *evidence_id)?;
        if evidence.job_id != action.job_id {
            return Err(EvidenceAttestationError::EvidenceJobMismatch);
        }
        if evidence
            .claim_id
            .is_some_and(|claim_id| claim_id != action.claim_id)
        {
            return Err(EvidenceAttestationError::EvidenceClaimMismatch);
        }
    }

    let record = AttestationRecord::from_action(actor.clone(), action);
    let attestation_id = record.attestation_id();
    if state.get(&StateKey::attestation(&attestation_id)).is_some() {
        return Err(EvidenceAttestationError::AttestationAlreadyExists);
    }
    if attestation_count(state, action.job_id, action.claim_id)? >= MAX_ATTESTATIONS_PER_CLAIM {
        return Err(EvidenceAttestationError::AttestationLimitReached {
            maximum: MAX_ATTESTATIONS_PER_CLAIM,
        });
    }

    state.put(StateKey::attestation(&attestation_id), encoded(&record));
    state.put(
        StateKey::attestation_by_operator(actor, &attestation_id),
        Vec::new().into_boxed_slice(),
    );
    Ok(attestation_id)
}

/// Loads and identity-checks a registered evidence record.
pub fn load_evidence(
    state: &dyn StateBatch,
    evidence_id: EvidenceId,
) -> Result<EvidenceRecord, EvidenceAttestationError> {
    let value = state
        .get(&StateKey::evidence(&evidence_id))
        .ok_or(EvidenceAttestationError::EvidenceNotFound)?;
    let record = EvidenceRecord::decode_cfg(value.as_ref(), &())
        .map_err(|_| EvidenceAttestationError::EvidenceStateMalformed)?;
    if record.evidence_id() != evidence_id {
        return Err(EvidenceAttestationError::EvidenceIdentityMismatch);
    }
    Ok(record)
}

/// Loads and identity-checks a canonical attestation record.
pub fn load_attestation(
    state: &dyn StateBatch,
    attestation_id: AttestationId,
) -> Result<AttestationRecord, EvidenceAttestationError> {
    let value = state
        .get(&StateKey::attestation(&attestation_id))
        .ok_or(EvidenceAttestationError::AttestationNotFound)?;
    let record = AttestationRecord::decode_cfg(value.as_ref(), &())
        .map_err(|_| EvidenceAttestationError::AttestationStateMalformed)?;
    if record.attestation_id() != attestation_id {
        return Err(EvidenceAttestationError::AttestationIdentityMismatch);
    }
    Ok(record)
}

fn load_target_job(
    state: &dyn StateBatch,
    job_id: JobId,
) -> Result<JobRecord, EvidenceAttestationError> {
    let value = state
        .get(&StateKey::job(&job_id))
        .ok_or(EvidenceAttestationError::JobNotFound)?;
    let record = JobRecord::decode_cfg(value.as_ref(), &())
        .map_err(|_| EvidenceAttestationError::JobStateMalformed)?;
    if record.job_id() != job_id {
        return Err(EvidenceAttestationError::JobIdentityMismatch);
    }
    Ok(record)
}

fn load_target_claim(
    state: &dyn StateBatch,
    job_id: JobId,
    claim_id: ClaimId,
) -> Result<ClaimRecord, EvidenceAttestationError> {
    let value = state
        .get(&StateKey::claim(&claim_id))
        .ok_or(EvidenceAttestationError::ClaimNotFound)?;
    let record = ClaimRecord::decode_cfg(value.as_ref(), &())
        .map_err(|_| EvidenceAttestationError::ClaimStateMalformed)?;

    let mut identity = Vec::with_capacity(32 + record.definition.statement.len());
    record.job_id.write(&mut identity);
    record.definition.write(&mut identity);
    if ClaimId::derive(&identity) != claim_id {
        return Err(EvidenceAttestationError::ClaimIdentityMismatch);
    }
    if record.job_id != job_id {
        return Err(EvidenceAttestationError::ClaimJobMismatch);
    }
    Ok(record)
}

fn attestation_count(
    state: &dyn StateBatch,
    job_id: JobId,
    claim_id: ClaimId,
) -> Result<usize, EvidenceAttestationError> {
    let mut count = 0_usize;
    for (key, value) in state.entries() {
        if key.namespace() != StateNamespace::Attestation {
            continue;
        }
        let record = AttestationRecord::decode_cfg(value.as_ref(), &())
            .map_err(|_| EvidenceAttestationError::AttestationStateMalformed)?;
        if StateKey::attestation(&record.attestation_id()) != key {
            return Err(EvidenceAttestationError::AttestationIdentityMismatch);
        }
        if record.job_id == job_id && record.claim_id == claim_id {
            count = count
                .checked_add(1)
                .expect("attestation state count cannot exceed addressable memory");
        }
    }
    Ok(count)
}

fn map_role_error(error: JobTransitionError) -> EvidenceAttestationError {
    match error {
        JobTransitionError::RoleConflict => EvidenceAttestationError::InvalidValidationOperator,
        JobTransitionError::MalformedJobState => EvidenceAttestationError::JobStateMalformed,
        _ => EvidenceAttestationError::JobStateMalformed,
    }
}

fn encoded<T: Encode>(value: &T) -> Box<[u8]> {
    value.encode().to_vec().into_boxed_slice()
}

/// Stable failures from evidence and attestation transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceAttestationError {
    JobNotFound,
    JobStateMalformed,
    JobIdentityMismatch,
    JobClosed,
    ClaimNotFound,
    ClaimStateMalformed,
    ClaimIdentityMismatch,
    ClaimJobMismatch,
    EvidenceWindowClosed {
        final_closes_at: u64,
        current_height: u64,
    },
    EvidenceAlreadyExists,
    EvidenceNotFound,
    EvidenceStateMalformed,
    EvidenceIdentityMismatch,
    EvidenceJobMismatch,
    EvidenceClaimMismatch,
    DuplicateEvidenceReference,
    ValidationNotOpen {
        validation_opens_at: u64,
        validation_closes_at: u64,
        current_height: u64,
    },
    ConfidenceOutOfRange {
        value: u16,
    },
    InvalidValidationOperator,
    AttestationAlreadyExists,
    AttestationNotFound,
    AttestationStateMalformed,
    AttestationIdentityMismatch,
    AttestationLimitReached {
        maximum: usize,
    },
}

impl EvidenceAttestationError {
    /// Returns a stable machine-readable protocol error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::JobNotFound => "JOB_NOT_FOUND",
            Self::JobStateMalformed => "JOB_STATE_MALFORMED",
            Self::JobIdentityMismatch => "JOB_IDENTITY_INVALID",
            Self::JobClosed => "JOB_ALREADY_CLOSED",
            Self::ClaimNotFound => "CLAIM_NOT_FOUND",
            Self::ClaimStateMalformed => "CLAIM_STATE_MALFORMED",
            Self::ClaimIdentityMismatch => "CLAIM_IDENTITY_INVALID",
            Self::ClaimJobMismatch => "CLAIM_JOB_MISMATCH",
            Self::EvidenceWindowClosed { .. } => "EVIDENCE_WINDOW_CLOSED",
            Self::EvidenceAlreadyExists => "EVIDENCE_ALREADY_EXISTS",
            Self::EvidenceNotFound => "EVIDENCE_NOT_FOUND",
            Self::EvidenceStateMalformed => "EVIDENCE_STATE_MALFORMED",
            Self::EvidenceIdentityMismatch => "EVIDENCE_IDENTITY_INVALID",
            Self::EvidenceJobMismatch => "EVIDENCE_JOB_MISMATCH",
            Self::EvidenceClaimMismatch => "EVIDENCE_CLAIM_MISMATCH",
            Self::DuplicateEvidenceReference => "ATTESTATION_EVIDENCE_DUPLICATE",
            Self::ValidationNotOpen { .. } => "JOB_VALIDATION_NOT_OPEN",
            Self::ConfidenceOutOfRange { .. } => "ATTESTATION_CONFIDENCE_INVALID",
            Self::InvalidValidationOperator => "VALIDATION_OPERATOR_INVALID",
            Self::AttestationAlreadyExists => "ATTESTATION_ALREADY_EXISTS",
            Self::AttestationNotFound => "ATTESTATION_NOT_FOUND",
            Self::AttestationStateMalformed => "ATTESTATION_STATE_MALFORMED",
            Self::AttestationIdentityMismatch => "ATTESTATION_IDENTITY_INVALID",
            Self::AttestationLimitReached { .. } => "CLAIM_ATTESTATION_LIMIT_REACHED",
        }
    }
}

impl fmt::Display for EvidenceAttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for EvidenceAttestationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{
            ClaimDefinition, CloseJob, CreateJob, ResolutionPolicy, SubmitAttestation, Verdict,
        },
        artifacts::{ContentRef, GitArtifact, GitHash},
        bounded::{BoundedBytes, BoundedVec},
        limits::MAX_EVIDENCE_IDS_PER_ACTION,
        state::InMemoryStateBatch,
        transition::{close_job, create_job},
    };
    use commonware_cryptography::{Signer as _, ed25519};

    fn actor(seed: u64) -> ActorId {
        ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
    }

    fn bounded<const MAX: usize>(value: &[u8]) -> BoundedBytes<MAX> {
        BoundedBytes::try_from(value).unwrap()
    }

    fn create(candidate: u8, authority: ActorId) -> CreateJob {
        CreateJob {
            artifact: GitArtifact::new(
                bounded(b"https://git.invalid/evidence"),
                GitHash::sha1([1; 20]),
                GitHash::sha256([candidate; 32]),
                ContentRef::new(
                    crate::primitives::Sha256Digest::from([9; 32]),
                    bounded(b"cas://spec"),
                    bounded(b"text/markdown"),
                ),
            ),
            claims: BoundedVec::new(vec![
                ClaimDefinition::new(bounded(b"tests pass")),
                ClaimDefinition::new(bounded(b"no regression")),
            ])
            .unwrap(),
            resolution_policy: ResolutionPolicy::ExperimentAuthority { authority },
            validation_opens_at: 10,
            validation_closes_at: 20,
            reveal_closes_at: Some(25),
            challenge_closes_at: Some(30),
            supersedes: None,
            metadata: bounded(b"fixture"),
        }
    }

    fn registration(job_id: JobId, claim_id: Option<ClaimId>, digest: u8) -> RegisterEvidence {
        RegisterEvidence {
            job_id,
            claim_id,
            evidence: ContentRef::new(
                crate::primitives::Sha256Digest::from([digest; 32]),
                bounded(b"cas://evidence"),
                bounded(b"application/json"),
            ),
            manifest_digest: crate::primitives::Sha256Digest::from([digest.wrapping_add(1); 32]),
        }
    }

    fn attestation(
        job_id: JobId,
        claim_id: ClaimId,
        evidence_ids: Vec<EvidenceId>,
    ) -> SubmitAttestation {
        SubmitAttestation {
            job_id,
            claim_id,
            verdict: Verdict::Pass,
            confidence_basis_points: 8_500,
            evidence_ids: BoundedVec::new(evidence_ids).unwrap(),
        }
    }

    fn fixture(candidate: u8) -> (InMemoryStateBatch, ActorId, ActorId, JobId, Vec<ClaimId>) {
        let customer = actor(u64::from(candidate) + 100);
        let authority = actor(u64::from(candidate) + 200);
        let mut state = InMemoryStateBatch::new();
        let created = create_job(
            &mut state,
            &customer,
            10,
            &create(candidate, authority.clone()),
        )
        .unwrap();
        (
            state,
            customer,
            authority,
            created.job_id,
            created.claim_ids.into_inner(),
        )
    }

    #[test]
    fn registration_preserves_off_chain_identity_target_metadata_and_unique_producer() {
        let (mut state, _, _, job_id, claims) = fixture(1);
        let producer = actor(1);
        let action = registration(job_id, Some(claims[0]), 0x41);
        let evidence_id = register_evidence(&mut state, &producer, 10, &action).unwrap();

        assert_eq!(
            evidence_id,
            EvidenceId::derive(action.evidence.digest.as_ref())
        );
        let stored = load_evidence(&state, evidence_id).unwrap();
        assert_eq!(
            stored,
            EvidenceRecord::from_action(producer.clone(), &action)
        );

        let mut alias = action.clone();
        alias.claim_id = None;
        alias.evidence.locator_hint = bounded(b"private://alternate");
        alias.evidence.media_type = bounded(b"application/octet-stream");
        alias.manifest_digest = crate::primitives::Sha256Digest::from([0x99; 32]);
        assert_eq!(alias.evidence_id(), evidence_id);
        let before = state.root();
        assert_eq!(
            register_evidence(&mut state, &actor(2), 11, &alias),
            Err(EvidenceAttestationError::EvidenceAlreadyExists)
        );
        assert_eq!(state.root(), before);
        assert_eq!(
            load_evidence(&state, evidence_id).unwrap().producer,
            producer
        );
    }

    #[test]
    fn registrations_reject_missing_or_foreign_targets_and_expired_lifecycles() {
        let (mut state, customer, _, job_id, claims) = fixture(2);
        assert_eq!(
            register_evidence(
                &mut state,
                &actor(3),
                10,
                &registration(JobId::derive(b"missing"), None, 1),
            ),
            Err(EvidenceAttestationError::JobNotFound)
        );
        assert_eq!(
            register_evidence(
                &mut state,
                &actor(3),
                10,
                &registration(job_id, Some(ClaimId::derive(b"missing")), 2),
            ),
            Err(EvidenceAttestationError::ClaimNotFound)
        );

        let second = create_job(&mut state, &customer, 10, &create(3, actor(202))).unwrap();
        assert_eq!(
            register_evidence(
                &mut state,
                &actor(3),
                10,
                &registration(job_id, Some(second.claim_ids.as_slice()[0]), 3),
            ),
            Err(EvidenceAttestationError::ClaimJobMismatch)
        );
        assert!(
            register_evidence(
                &mut state,
                &actor(3),
                30,
                &registration(job_id, Some(claims[0]), 4),
            )
            .is_ok()
        );
        assert_eq!(
            register_evidence(
                &mut state,
                &actor(3),
                31,
                &registration(job_id, Some(claims[0]), 5),
            ),
            Err(EvidenceAttestationError::EvidenceWindowClosed {
                final_closes_at: 30,
                current_height: 31,
            })
        );

        close_job(&mut state, &customer, 31, &CloseJob::new(job_id)).unwrap();
        assert_eq!(
            register_evidence(&mut state, &actor(3), 31, &registration(job_id, None, 6),),
            Err(EvidenceAttestationError::JobClosed)
        );
    }

    #[test]
    fn valid_attestation_preserves_operator_verdict_confidence_evidence_and_index() {
        let (mut state, _, _, job_id, claims) = fixture(4);
        let operator = actor(4);
        let evidence_id = register_evidence(
            &mut state,
            &actor(5),
            10,
            &registration(job_id, Some(claims[0]), 7),
        )
        .unwrap();
        let mut action = attestation(job_id, claims[0], vec![evidence_id]);
        action.verdict = Verdict::Indeterminate;
        action.confidence_basis_points = 10_000;

        let attestation_id = submit_attestation(&mut state, &operator, 10, &action).unwrap();
        assert_eq!(attestation_id, action.attestation_id(&operator));
        let stored = load_attestation(&state, attestation_id).unwrap();
        assert_eq!(
            stored,
            AttestationRecord::from_action(operator.clone(), &action)
        );
        assert!(
            state
                .get(&StateKey::attestation_by_operator(
                    &operator,
                    &attestation_id
                ))
                .is_some()
        );
        assert_eq!(stored.verdict, Verdict::Indeterminate);
        assert_eq!(stored.confidence_basis_points, 10_000);
        assert_eq!(stored.evidence_ids.as_slice(), [evidence_id]);
    }

    #[test]
    fn validation_window_is_inclusive_and_exact_duplicate_is_rejected_atomically() {
        for (candidate, height) in [(5, 10), (6, 20)] {
            let (mut state, _, _, job_id, claims) = fixture(candidate);
            assert!(
                submit_attestation(
                    &mut state,
                    &actor(u64::from(candidate)),
                    height,
                    &attestation(job_id, claims[0], Vec::new()),
                )
                .is_ok()
            );
        }
        for (candidate, height) in [(7, 9), (8, 21)] {
            let (mut state, _, _, job_id, claims) = fixture(candidate);
            assert_eq!(
                submit_attestation(
                    &mut state,
                    &actor(u64::from(candidate)),
                    height,
                    &attestation(job_id, claims[0], Vec::new()),
                ),
                Err(EvidenceAttestationError::ValidationNotOpen {
                    validation_opens_at: 10,
                    validation_closes_at: 20,
                    current_height: height,
                })
            );
        }

        let (mut state, _, _, job_id, claims) = fixture(9);
        let action = attestation(job_id, claims[0], Vec::new());
        let operator = actor(9);
        submit_attestation(&mut state, &operator, 10, &action).unwrap();
        let before = state.root();
        assert_eq!(
            submit_attestation(&mut state, &operator, 10, &action),
            Err(EvidenceAttestationError::AttestationAlreadyExists)
        );
        assert_eq!(state.root(), before);
    }

    #[test]
    fn attestations_reject_missing_mismatched_and_duplicate_evidence_references() {
        let (mut state, customer, _, job_id, claims) = fixture(10);
        let operator = actor(10);
        assert_eq!(
            submit_attestation(
                &mut state,
                &operator,
                10,
                &attestation(JobId::derive(b"missing"), claims[0], Vec::new()),
            ),
            Err(EvidenceAttestationError::JobNotFound)
        );
        assert_eq!(
            submit_attestation(
                &mut state,
                &operator,
                10,
                &attestation(job_id, ClaimId::derive(b"missing"), Vec::new()),
            ),
            Err(EvidenceAttestationError::ClaimNotFound)
        );
        let second = create_job(&mut state, &customer, 10, &create(11, actor(210))).unwrap();
        assert_eq!(
            submit_attestation(
                &mut state,
                &operator,
                10,
                &attestation(job_id, second.claim_ids.as_slice()[0], Vec::new()),
            ),
            Err(EvidenceAttestationError::ClaimJobMismatch)
        );
        assert_eq!(
            submit_attestation(
                &mut state,
                &operator,
                10,
                &attestation(job_id, claims[0], vec![EvidenceId::derive(b"missing")]),
            ),
            Err(EvidenceAttestationError::EvidenceNotFound)
        );

        let claim_evidence = register_evidence(
            &mut state,
            &actor(11),
            10,
            &registration(job_id, Some(claims[0]), 11),
        )
        .unwrap();
        assert_eq!(
            submit_attestation(
                &mut state,
                &operator,
                10,
                &attestation(job_id, claims[1], vec![claim_evidence]),
            ),
            Err(EvidenceAttestationError::EvidenceClaimMismatch)
        );
        assert_eq!(
            submit_attestation(
                &mut state,
                &operator,
                10,
                &attestation(job_id, claims[0], vec![claim_evidence, claim_evidence]),
            ),
            Err(EvidenceAttestationError::DuplicateEvidenceReference)
        );

        assert_eq!(
            submit_attestation(
                &mut state,
                &operator,
                10,
                &attestation(
                    second.job_id,
                    second.claim_ids.as_slice()[0],
                    vec![claim_evidence],
                ),
            ),
            Err(EvidenceAttestationError::EvidenceJobMismatch)
        );
    }

    #[test]
    fn confidence_bounds_and_resolution_authority_role_are_enforced_without_mutation() {
        let (mut state, _, authority, job_id, claims) = fixture(12);
        let mut invalid_confidence = attestation(job_id, claims[0], Vec::new());
        invalid_confidence.confidence_basis_points = 10_001;
        let before = state.root();
        assert_eq!(
            submit_attestation(&mut state, &actor(12), 10, &invalid_confidence),
            Err(EvidenceAttestationError::ConfidenceOutOfRange { value: 10_001 })
        );
        assert_eq!(state.root(), before);

        assert_eq!(
            submit_attestation(
                &mut state,
                &authority,
                10,
                &attestation(job_id, claims[0], Vec::new()),
            ),
            Err(EvidenceAttestationError::InvalidValidationOperator)
        );
        assert_eq!(state.root(), before);
    }

    #[test]
    fn evidence_reference_and_per_claim_attestation_limits_are_exact() {
        let (mut state, _, _, job_id, claims) = fixture(13);
        let mut evidence_ids = Vec::new();
        for digest in 0_u8..64 {
            evidence_ids.push(
                register_evidence(
                    &mut state,
                    &actor(13),
                    10,
                    &registration(job_id, None, digest),
                )
                .unwrap(),
            );
        }
        assert_eq!(evidence_ids.len(), MAX_EVIDENCE_IDS_PER_ACTION);
        assert!(
            submit_attestation(
                &mut state,
                &actor(14),
                10,
                &attestation(job_id, claims[0], evidence_ids),
            )
            .is_ok()
        );

        let (mut capped, _, _, job_id, claims) = fixture(14);
        let operator = actor(15);
        for confidence in 0_u16..u16::try_from(MAX_ATTESTATIONS_PER_CLAIM).unwrap() {
            let mut action = attestation(job_id, claims[0], Vec::new());
            action.confidence_basis_points = confidence;
            let record = AttestationRecord::from_action(operator.clone(), &action);
            capped.put(
                StateKey::attestation(&record.attestation_id()),
                encoded(&record),
            );
        }
        let mut overflow = attestation(job_id, claims[0], Vec::new());
        overflow.confidence_basis_points = u16::try_from(MAX_ATTESTATIONS_PER_CLAIM).unwrap();
        assert_eq!(
            submit_attestation(&mut capped, &operator, 10, &overflow),
            Err(EvidenceAttestationError::AttestationLimitReached {
                maximum: MAX_ATTESTATIONS_PER_CLAIM,
            })
        );
    }

    #[test]
    fn ids_are_deterministic_domain_separated_and_identity_checked_on_load() {
        let (mut state, _, _, job_id, claims) = fixture(15);
        let action = registration(job_id, Some(claims[0]), 20);
        assert_eq!(action.evidence_id(), action.evidence_id());
        let operator = actor(16);
        let statement = attestation(job_id, claims[0], Vec::new());
        assert_eq!(
            statement.attestation_id(&operator),
            statement.attestation_id(&operator)
        );
        assert_ne!(
            statement.attestation_id(&operator),
            statement.attestation_id(&actor(17))
        );
        assert_ne!(
            statement.attestation_id(&operator).as_bytes(),
            action.evidence_id().as_bytes()
        );

        let evidence_id = register_evidence(&mut state, &operator, 10, &action).unwrap();
        let mut wrong = EvidenceRecord::from_action(operator, &action);
        wrong.evidence.digest = crate::primitives::Sha256Digest::from([21; 32]);
        state.put(StateKey::evidence(&evidence_id), encoded(&wrong));
        assert_eq!(
            load_evidence(&state, evidence_id),
            Err(EvidenceAttestationError::EvidenceIdentityMismatch)
        );
    }
}
