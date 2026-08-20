//! Pure challenge, authority-resolution, reopening, and job-resolution transitions.

use super::{
    evidence::{EvidenceAttestationError, load_attestation, load_evidence},
    jobs::{JobTransitionError, load_claim, load_job},
};
use crate::{
    actions::{ChallengeTarget, CreateChallenge, ResolutionPolicy, ResolveChallenge, ResolveClaim},
    limits::MAX_OPEN_CHALLENGES_PER_CLAIM,
    primitives::{ActorId, ChallengeId, ClaimId, EvidenceId, JobId},
    state::{
        ChallengeRecord, ChallengeStatus, ClaimResolution, ClaimStatus, JobRecord, JobStatus,
        StateBatch, StateKey, StateNamespace,
    },
};
use commonware_codec::{Decode, Encode};
use core::fmt;
use std::collections::BTreeSet;

/// Additional lifecycle effects of a successful claim resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimResolutionOutcome {
    pub claim_id: ClaimId,
    pub job_resolved: bool,
}

/// Additional lifecycle effects of a successful challenge resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeResolutionOutcome {
    pub challenge_id: ChallengeId,
    pub reopened_claim: Option<ClaimId>,
    pub job_reopened: bool,
}

/// Records a counterclaim against an attestation or current claim resolution.
pub fn create_challenge(
    state: &mut dyn StateBatch,
    actor: &ActorId,
    height: u64,
    action: &CreateChallenge,
) -> Result<ChallengeId, ChallengeResolutionError> {
    let (job_id, claim_id, claim_is_resolved) = resolve_target(state, action.target)?;
    if matches!(action.target, ChallengeTarget::Claim(_)) && !claim_is_resolved {
        return Err(ChallengeResolutionError::ClaimNotResolved);
    }
    let job = load_resolution_job(state, job_id)?;
    ensure_job_open(&job)?;
    ensure_challenge_window(&job, height)?;
    validate_evidence(state, job_id, claim_id, action.evidence_ids.as_slice())?;

    let challenge_id = action.challenge_id(actor);
    if state.get(&StateKey::challenge(&challenge_id)).is_some() {
        return Err(ChallengeResolutionError::ChallengeAlreadyExists);
    }
    let open = open_challenge_count(state, claim_id)?;
    if open >= MAX_OPEN_CHALLENGES_PER_CLAIM {
        return Err(ChallengeResolutionError::OpenChallengeLimitReached {
            maximum: MAX_OPEN_CHALLENGES_PER_CLAIM,
        });
    }

    let record = ChallengeRecord::from_action(actor.clone(), job_id, claim_id, action);
    state.put(StateKey::challenge(&challenge_id), encoded(&record));
    Ok(challenge_id)
}

/// Stores one authorized claim verdict and resolves the job when all claims are resolved.
pub fn resolve_claim(
    state: &mut dyn StateBatch,
    actor: &ActorId,
    height: u64,
    action: &ResolveClaim,
) -> Result<ClaimResolutionOutcome, ChallengeResolutionError> {
    let mut job = load_resolution_job(state, action.job_id)?;
    ensure_job_open(&job)?;
    ensure_resolution_window(&job, height)?;
    ensure_authority(&job, actor)?;

    let mut claim = load_resolution_claim(state, action.job_id, action.claim_id)?;
    if matches!(claim.status, ClaimStatus::Resolved(_)) {
        return Err(ChallengeResolutionError::ClaimAlreadyResolved);
    }
    if open_claim_resolution_challenge_count(state, action.claim_id)? != 0 {
        return Err(ChallengeResolutionError::ClaimHasOpenChallenges);
    }
    validate_evidence(
        state,
        action.job_id,
        action.claim_id,
        action.evidence_ids.as_slice(),
    )?;

    claim.status = ClaimStatus::Resolved(ClaimResolution {
        verdict: action.verdict,
        evidence_ids: action.evidence_ids.clone(),
        resolution_reference: action.resolution_reference.clone(),
    });

    let mut all_resolved = true;
    for claim_id in &job.claim_ids {
        if *claim_id == action.claim_id {
            continue;
        }
        let other = load_resolution_claim(state, action.job_id, *claim_id)?;
        all_resolved &= matches!(other.status, ClaimStatus::Resolved(_));
    }
    if all_resolved {
        job.status = JobStatus::Resolved;
    }

    state.put(StateKey::claim(&action.claim_id), encoded(&claim));
    if all_resolved {
        state.put(StateKey::job(&action.job_id), encoded(&job));
    }
    Ok(ClaimResolutionOutcome {
        claim_id: action.claim_id,
        job_resolved: all_resolved,
    })
}

/// Stores one authorized challenge outcome and reopens an upheld claim target.
pub fn resolve_challenge(
    state: &mut dyn StateBatch,
    actor: &ActorId,
    height: u64,
    action: &ResolveChallenge,
) -> Result<ChallengeResolutionOutcome, ChallengeResolutionError> {
    let mut challenge = load_challenge(state, action.challenge_id)?;
    if !matches!(challenge.status, ChallengeStatus::Open) {
        return Err(ChallengeResolutionError::ChallengeAlreadyResolved);
    }

    let mut job = load_resolution_job(state, challenge.job_id)?;
    ensure_job_open(&job)?;
    ensure_challenge_window(&job, height)?;
    ensure_authority(&job, actor)?;
    validate_target_projection(state, &challenge)?;
    validate_evidence(
        state,
        challenge.job_id,
        challenge.claim_id,
        action.evidence_ids.as_slice(),
    )?;

    let mut reopened_claim = None;
    let mut job_reopened = false;
    let mut reopened_record = None;
    if action.upheld
        && let ChallengeTarget::Claim(claim_id) = challenge.target
    {
        let mut claim = load_resolution_claim(state, challenge.job_id, claim_id)?;
        if !matches!(claim.status, ClaimStatus::Resolved(_)) {
            return Err(ChallengeResolutionError::ClaimNotResolved);
        }
        claim.status = ClaimStatus::Open;
        reopened_claim = Some(claim_id);
        reopened_record = Some((claim_id, claim));
        if job.status == JobStatus::Resolved {
            job.status = JobStatus::Open;
            job_reopened = true;
        }
    }

    challenge.status = ChallengeStatus::Resolved {
        upheld: action.upheld,
        evidence_ids: action.evidence_ids.clone(),
        resolution_reference: action.resolution_reference.clone(),
    };
    state.put(
        StateKey::challenge(&action.challenge_id),
        encoded(&challenge),
    );
    if let Some((claim_id, claim)) = reopened_record {
        state.put(StateKey::claim(&claim_id), encoded(&claim));
    }
    if job_reopened {
        state.put(StateKey::job(&challenge.job_id), encoded(&job));
    }

    Ok(ChallengeResolutionOutcome {
        challenge_id: action.challenge_id,
        reopened_claim,
        job_reopened,
    })
}

/// Loads and identity-checks one canonical challenge record.
pub fn load_challenge(
    state: &dyn StateBatch,
    challenge_id: ChallengeId,
) -> Result<ChallengeRecord, ChallengeResolutionError> {
    let value = state
        .get(&StateKey::challenge(&challenge_id))
        .ok_or(ChallengeResolutionError::ChallengeNotFound)?;
    let record = ChallengeRecord::decode_cfg(value.as_ref(), &())
        .map_err(|_| ChallengeResolutionError::ChallengeStateMalformed)?;
    if record.challenge_id() != challenge_id {
        return Err(ChallengeResolutionError::ChallengeIdentityMismatch);
    }
    Ok(record)
}

fn resolve_target(
    state: &dyn StateBatch,
    target: ChallengeTarget,
) -> Result<(JobId, ClaimId, bool), ChallengeResolutionError> {
    match target {
        ChallengeTarget::Claim(claim_id) => {
            let value = state
                .get(&StateKey::claim(&claim_id))
                .ok_or(ChallengeResolutionError::ClaimNotFound)?;
            let claim = crate::state::ClaimRecord::decode_cfg(value.as_ref(), &())
                .map_err(|_| ChallengeResolutionError::ClaimStateMalformed)?;
            let checked = load_resolution_claim(state, claim.job_id, claim_id)?;
            let resolved = matches!(checked.status, ClaimStatus::Resolved(_));
            Ok((checked.job_id, claim_id, resolved))
        }
        ChallengeTarget::Attestation(attestation_id) => {
            let attestation =
                load_attestation(state, attestation_id).map_err(map_evidence_error)?;
            Ok((attestation.job_id, attestation.claim_id, false))
        }
    }
}

fn validate_target_projection(
    state: &dyn StateBatch,
    challenge: &ChallengeRecord,
) -> Result<(), ChallengeResolutionError> {
    let (job_id, claim_id, _) = resolve_target(state, challenge.target)?;
    if job_id != challenge.job_id || claim_id != challenge.claim_id {
        return Err(ChallengeResolutionError::ChallengeTargetMismatch);
    }
    Ok(())
}

fn load_resolution_job(
    state: &dyn StateBatch,
    job_id: JobId,
) -> Result<JobRecord, ChallengeResolutionError> {
    load_job(state, job_id).map_err(|error| match error {
        JobTransitionError::JobNotFound => ChallengeResolutionError::JobNotFound,
        JobTransitionError::JobIdentityMismatch => ChallengeResolutionError::JobIdentityMismatch,
        _ => ChallengeResolutionError::JobStateMalformed,
    })
}

fn load_resolution_claim(
    state: &dyn StateBatch,
    job_id: JobId,
    claim_id: ClaimId,
) -> Result<crate::state::ClaimRecord, ChallengeResolutionError> {
    load_claim(state, job_id, claim_id).map_err(|error| match error {
        JobTransitionError::ClaimNotFound => ChallengeResolutionError::ClaimNotFound,
        JobTransitionError::ClaimIdentityMismatch => {
            ChallengeResolutionError::ClaimIdentityMismatch
        }
        JobTransitionError::ClaimJobMismatch => ChallengeResolutionError::ClaimJobMismatch,
        _ => ChallengeResolutionError::ClaimStateMalformed,
    })
}

fn ensure_job_open(job: &JobRecord) -> Result<(), ChallengeResolutionError> {
    if job.status == JobStatus::Closed {
        return Err(ChallengeResolutionError::JobClosed);
    }
    Ok(())
}

fn ensure_authority(job: &JobRecord, actor: &ActorId) -> Result<(), ChallengeResolutionError> {
    match &job.resolution_policy {
        ResolutionPolicy::ExperimentAuthority { authority } if authority == actor => Ok(()),
        ResolutionPolicy::ExperimentAuthority { .. } => {
            Err(ChallengeResolutionError::ResolutionUnauthorized)
        }
        ResolutionPolicy::DeterministicVerifier { .. } => {
            Err(ChallengeResolutionError::ResolutionPolicyNotImplemented)
        }
    }
}

fn prior_phase_closes_at(job: &JobRecord) -> u64 {
    job.lifecycle
        .reveal_closes_at
        .unwrap_or(job.lifecycle.validation_closes_at)
}

fn ensure_resolution_window(job: &JobRecord, height: u64) -> Result<(), ChallengeResolutionError> {
    let opens_after = prior_phase_closes_at(job);
    if height <= opens_after {
        return Err(ChallengeResolutionError::ResolutionTooEarly {
            opens_after,
            current_height: height,
        });
    }
    if let Some(closes_at) = job.lifecycle.challenge_closes_at
        && height > closes_at
    {
        return Err(ChallengeResolutionError::ResolutionTooLate {
            closes_at,
            current_height: height,
        });
    }
    Ok(())
}

fn ensure_challenge_window(job: &JobRecord, height: u64) -> Result<(), ChallengeResolutionError> {
    let closes_at = job
        .lifecycle
        .challenge_closes_at
        .ok_or(ChallengeResolutionError::ChallengeWindowNotConfigured)?;
    let opens_after = prior_phase_closes_at(job);
    if height <= opens_after {
        return Err(ChallengeResolutionError::ChallengeTooEarly {
            opens_after,
            current_height: height,
        });
    }
    if height > closes_at {
        return Err(ChallengeResolutionError::ChallengeTooLate {
            closes_at,
            current_height: height,
        });
    }
    Ok(())
}

fn validate_evidence(
    state: &dyn StateBatch,
    job_id: JobId,
    claim_id: ClaimId,
    evidence_ids: &[EvidenceId],
) -> Result<(), ChallengeResolutionError> {
    let mut unique = BTreeSet::new();
    for evidence_id in evidence_ids {
        if !unique.insert(*evidence_id) {
            return Err(ChallengeResolutionError::DuplicateEvidenceReference);
        }
        let evidence = load_evidence(state, *evidence_id).map_err(map_evidence_error)?;
        if evidence.job_id != job_id {
            return Err(ChallengeResolutionError::EvidenceJobMismatch);
        }
        if evidence.claim_id.is_some_and(|target| target != claim_id) {
            return Err(ChallengeResolutionError::EvidenceClaimMismatch);
        }
    }
    Ok(())
}

fn map_evidence_error(error: EvidenceAttestationError) -> ChallengeResolutionError {
    match error {
        EvidenceAttestationError::EvidenceNotFound => ChallengeResolutionError::EvidenceNotFound,
        EvidenceAttestationError::EvidenceIdentityMismatch => {
            ChallengeResolutionError::EvidenceIdentityMismatch
        }
        EvidenceAttestationError::AttestationNotFound => {
            ChallengeResolutionError::AttestationNotFound
        }
        EvidenceAttestationError::AttestationIdentityMismatch => {
            ChallengeResolutionError::AttestationIdentityMismatch
        }
        EvidenceAttestationError::AttestationStateMalformed => {
            ChallengeResolutionError::AttestationStateMalformed
        }
        _ => ChallengeResolutionError::EvidenceStateMalformed,
    }
}

fn open_challenge_count(
    state: &dyn StateBatch,
    claim_id: ClaimId,
) -> Result<usize, ChallengeResolutionError> {
    challenge_count(state, claim_id, false)
}

fn open_claim_resolution_challenge_count(
    state: &dyn StateBatch,
    claim_id: ClaimId,
) -> Result<usize, ChallengeResolutionError> {
    challenge_count(state, claim_id, true)
}

fn challenge_count(
    state: &dyn StateBatch,
    claim_id: ClaimId,
    claim_targets_only: bool,
) -> Result<usize, ChallengeResolutionError> {
    let mut count = 0_usize;
    for (key, value) in state.entries() {
        if key.namespace() != StateNamespace::Challenge {
            continue;
        }
        let record = ChallengeRecord::decode_cfg(value.as_ref(), &())
            .map_err(|_| ChallengeResolutionError::ChallengeStateMalformed)?;
        if StateKey::challenge(&record.challenge_id()) != key {
            return Err(ChallengeResolutionError::ChallengeIdentityMismatch);
        }
        validate_target_projection(state, &record)?;
        let matching_target = !claim_targets_only
            || matches!(record.target, ChallengeTarget::Claim(target) if target == claim_id);
        if record.claim_id == claim_id
            && matching_target
            && matches!(record.status, ChallengeStatus::Open)
        {
            count = count
                .checked_add(1)
                .expect("challenge count cannot exceed addressable memory");
        }
    }
    Ok(count)
}

fn encoded<T: Encode>(value: &T) -> Box<[u8]> {
    value.encode().to_vec().into_boxed_slice()
}

/// Stable failures from challenge and resolution lifecycle transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeResolutionError {
    JobNotFound,
    JobStateMalformed,
    JobIdentityMismatch,
    JobClosed,
    ClaimNotFound,
    ClaimStateMalformed,
    ClaimIdentityMismatch,
    ClaimJobMismatch,
    ClaimNotResolved,
    ClaimAlreadyResolved,
    ClaimHasOpenChallenges,
    AttestationNotFound,
    AttestationStateMalformed,
    AttestationIdentityMismatch,
    ChallengeNotFound,
    ChallengeStateMalformed,
    ChallengeIdentityMismatch,
    ChallengeTargetMismatch,
    ChallengeAlreadyExists,
    ChallengeAlreadyResolved,
    ChallengeWindowNotConfigured,
    ChallengeTooEarly {
        opens_after: u64,
        current_height: u64,
    },
    ChallengeTooLate {
        closes_at: u64,
        current_height: u64,
    },
    ResolutionTooEarly {
        opens_after: u64,
        current_height: u64,
    },
    ResolutionTooLate {
        closes_at: u64,
        current_height: u64,
    },
    ResolutionUnauthorized,
    ResolutionPolicyNotImplemented,
    EvidenceNotFound,
    EvidenceStateMalformed,
    EvidenceIdentityMismatch,
    EvidenceJobMismatch,
    EvidenceClaimMismatch,
    DuplicateEvidenceReference,
    OpenChallengeLimitReached {
        maximum: usize,
    },
}

impl ChallengeResolutionError {
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
            Self::ClaimNotResolved => "CLAIM_NOT_RESOLVED",
            Self::ClaimAlreadyResolved => "CLAIM_ALREADY_RESOLVED",
            Self::ClaimHasOpenChallenges => "CLAIM_CHALLENGES_OPEN",
            Self::AttestationNotFound => "ATTESTATION_NOT_FOUND",
            Self::AttestationStateMalformed => "ATTESTATION_STATE_MALFORMED",
            Self::AttestationIdentityMismatch => "ATTESTATION_IDENTITY_INVALID",
            Self::ChallengeNotFound => "CHALLENGE_NOT_FOUND",
            Self::ChallengeStateMalformed => "CHALLENGE_STATE_MALFORMED",
            Self::ChallengeIdentityMismatch => "CHALLENGE_IDENTITY_INVALID",
            Self::ChallengeTargetMismatch => "CHALLENGE_TARGET_MISMATCH",
            Self::ChallengeAlreadyExists => "CHALLENGE_ALREADY_EXISTS",
            Self::ChallengeAlreadyResolved => "CHALLENGE_ALREADY_RESOLVED",
            Self::ChallengeWindowNotConfigured => "JOB_CHALLENGE_WINDOW_NOT_CONFIGURED",
            Self::ChallengeTooEarly { .. } => "CHALLENGE_TOO_EARLY",
            Self::ChallengeTooLate { .. } => "CHALLENGE_TOO_LATE",
            Self::ResolutionTooEarly { .. } => "RESOLUTION_TOO_EARLY",
            Self::ResolutionTooLate { .. } => "RESOLUTION_TOO_LATE",
            Self::ResolutionUnauthorized => "RESOLUTION_UNAUTHORIZED",
            Self::ResolutionPolicyNotImplemented => "RESOLUTION_POLICY_NOT_IMPLEMENTED",
            Self::EvidenceNotFound => "EVIDENCE_NOT_FOUND",
            Self::EvidenceStateMalformed => "EVIDENCE_STATE_MALFORMED",
            Self::EvidenceIdentityMismatch => "EVIDENCE_IDENTITY_INVALID",
            Self::EvidenceJobMismatch => "EVIDENCE_JOB_MISMATCH",
            Self::EvidenceClaimMismatch => "EVIDENCE_CLAIM_MISMATCH",
            Self::DuplicateEvidenceReference => "RESOLUTION_EVIDENCE_DUPLICATE",
            Self::OpenChallengeLimitReached { .. } => "CLAIM_OPEN_CHALLENGE_LIMIT_REACHED",
        }
    }
}

impl fmt::Display for ChallengeResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ChallengeResolutionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{
            ClaimDefinition, CreateJob, RegisterEvidence, ResolutionVerdict, SubmitAttestation,
            Verdict,
        },
        artifacts::{ContentRef, GitArtifact, GitHash},
        bounded::{BoundedBytes, BoundedVec},
        limits::MAX_COUNTERCLAIM_BYTES,
        primitives::{AttestationId, Sha256Digest},
        state::{InMemoryStateBatch, StateBatch},
        transition::{create_job, register_evidence, submit_attestation},
    };
    use commonware_cryptography::{Signer as _, ed25519};

    fn actor(seed: u64) -> ActorId {
        ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
    }

    fn bounded<const MAX: usize>(value: &[u8]) -> BoundedBytes<MAX> {
        BoundedBytes::try_from(value).unwrap()
    }

    fn content(byte: u8) -> ContentRef {
        ContentRef::new(
            Sha256Digest::from([byte; 32]),
            bounded(b"cas://resolution"),
            bounded(b"application/json"),
        )
    }

    fn create(candidate: u8, authority: ActorId) -> CreateJob {
        CreateJob {
            artifact: GitArtifact::new(
                bounded(b"https://git.invalid/resolution"),
                GitHash::sha1([1; 20]),
                GitHash::sha256([candidate; 32]),
                content(2),
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

    fn fixture(candidate: u8) -> (InMemoryStateBatch, ActorId, JobId, Vec<ClaimId>) {
        let customer = actor(1_000 + u64::from(candidate));
        let authority = actor(2_000 + u64::from(candidate));
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
            authority,
            created.job_id,
            created.claim_ids.into_inner(),
        )
    }

    fn resolve_action(job_id: JobId, claim_id: ClaimId) -> ResolveClaim {
        ResolveClaim {
            job_id,
            claim_id,
            verdict: ResolutionVerdict::Pass,
            evidence_ids: BoundedVec::default(),
            resolution_reference: content(10),
        }
    }

    fn challenge(target: ChallengeTarget, evidence_ids: Vec<EvidenceId>) -> CreateChallenge {
        CreateChallenge {
            target,
            counterclaim: bounded::<MAX_COUNTERCLAIM_BYTES>(b"counterexample"),
            evidence_ids: BoundedVec::new(evidence_ids).unwrap(),
        }
    }

    fn challenge_resolution(challenge_id: ChallengeId, upheld: bool) -> ResolveChallenge {
        ResolveChallenge {
            challenge_id,
            upheld,
            evidence_ids: BoundedVec::default(),
            resolution_reference: content(11),
        }
    }

    fn register(
        state: &mut InMemoryStateBatch,
        job_id: JobId,
        claim_id: Option<ClaimId>,
        byte: u8,
    ) -> EvidenceId {
        register_evidence(
            state,
            &actor(3_000 + u64::from(byte)),
            10,
            &RegisterEvidence {
                job_id,
                claim_id,
                evidence: content(byte),
                manifest_digest: Sha256Digest::from([byte.wrapping_add(1); 32]),
            },
        )
        .unwrap()
    }

    #[test]
    fn authorized_claim_resolutions_store_truth_and_resolve_the_job_exactly_once() {
        let (mut state, authority, job_id, claims) = fixture(1);
        let evidence_id = register(&mut state, job_id, Some(claims[0]), 40);
        let mut first = resolve_action(job_id, claims[0]);
        first.verdict = ResolutionVerdict::Fail;
        first.evidence_ids = BoundedVec::new(vec![evidence_id]).unwrap();

        let before = state.root();
        assert_eq!(
            resolve_claim(&mut state, &actor(9), 26, &first),
            Err(ChallengeResolutionError::ResolutionUnauthorized)
        );
        assert_eq!(state.root(), before);

        assert_eq!(
            resolve_claim(&mut state, &authority, 26, &first).unwrap(),
            ClaimResolutionOutcome {
                claim_id: claims[0],
                job_resolved: false,
            }
        );
        let stored = load_claim(&state, job_id, claims[0]).unwrap();
        let ClaimStatus::Resolved(resolution) = stored.status else {
            panic!("claim must be resolved")
        };
        assert_eq!(resolution.verdict, ResolutionVerdict::Fail);
        assert_eq!(resolution.evidence_ids.as_slice(), [evidence_id]);
        assert_eq!(load_job(&state, job_id).unwrap().status, JobStatus::Open);

        let mut second = resolve_action(job_id, claims[1]);
        second.verdict = ResolutionVerdict::Unresolved;
        assert!(
            resolve_claim(&mut state, &authority, 30, &second)
                .unwrap()
                .job_resolved
        );
        assert_eq!(
            load_job(&state, job_id).unwrap().status,
            JobStatus::Resolved
        );
        assert!(matches!(
            load_claim(&state, job_id, claims[1]).unwrap().status,
            ClaimStatus::Resolved(ClaimResolution {
                verdict: ResolutionVerdict::Unresolved,
                ..
            })
        ));

        let root = state.root();
        assert_eq!(
            resolve_claim(&mut state, &authority, 30, &second),
            Err(ChallengeResolutionError::ClaimAlreadyResolved)
        );
        assert_eq!(state.root(), root);
    }

    #[test]
    fn upheld_claim_challenge_reopens_claim_and_resolved_job() {
        let (mut state, authority, job_id, claims) = fixture(2);
        for claim_id in &claims {
            resolve_claim(
                &mut state,
                &authority,
                26,
                &resolve_action(job_id, *claim_id),
            )
            .unwrap();
        }
        let challenger = actor(50);
        let create = challenge(ChallengeTarget::Claim(claims[0]), Vec::new());
        let challenge_id = create_challenge(&mut state, &challenger, 27, &create).unwrap();
        assert_eq!(challenge_id, create.challenge_id(&challenger));
        assert!(matches!(
            load_challenge(&state, challenge_id).unwrap().status,
            ChallengeStatus::Open
        ));

        let action = challenge_resolution(challenge_id, true);
        let root = state.root();
        assert_eq!(
            resolve_challenge(&mut state, &actor(51), 28, &action),
            Err(ChallengeResolutionError::ResolutionUnauthorized)
        );
        assert_eq!(state.root(), root);

        assert_eq!(
            resolve_challenge(&mut state, &authority, 28, &action).unwrap(),
            ChallengeResolutionOutcome {
                challenge_id,
                reopened_claim: Some(claims[0]),
                job_reopened: true,
            }
        );
        assert_eq!(
            load_claim(&state, job_id, claims[0]).unwrap().status,
            ClaimStatus::Open
        );
        assert_eq!(load_job(&state, job_id).unwrap().status, JobStatus::Open);
        assert!(matches!(
            load_challenge(&state, challenge_id).unwrap().status,
            ChallengeStatus::Resolved { upheld: true, .. }
        ));
        assert_eq!(
            resolve_challenge(&mut state, &authority, 29, &action),
            Err(ChallengeResolutionError::ChallengeAlreadyResolved)
        );
    }

    #[test]
    fn rejected_and_attestation_challenges_do_not_reopen_claims() {
        let (mut state, authority, job_id, claims) = fixture(3);
        let operator = actor(60);
        let attestation = SubmitAttestation {
            job_id,
            claim_id: claims[0],
            verdict: Verdict::Pass,
            confidence_basis_points: 9_000,
            evidence_ids: BoundedVec::default(),
        };
        let attestation_id = submit_attestation(&mut state, &operator, 10, &attestation).unwrap();
        let attestation_challenge =
            challenge(ChallengeTarget::Attestation(attestation_id), Vec::new());
        let first = create_challenge(&mut state, &actor(61), 26, &attestation_challenge).unwrap();
        let outcome = resolve_challenge(
            &mut state,
            &authority,
            27,
            &challenge_resolution(first, true),
        )
        .unwrap();
        assert_eq!(outcome.reopened_claim, None);

        resolve_claim(
            &mut state,
            &authority,
            27,
            &resolve_action(job_id, claims[0]),
        )
        .unwrap();
        let claim_challenge = challenge(ChallengeTarget::Claim(claims[0]), Vec::new());
        let second = create_challenge(&mut state, &actor(62), 28, &claim_challenge).unwrap();
        let outcome = resolve_challenge(
            &mut state,
            &authority,
            29,
            &challenge_resolution(second, false),
        )
        .unwrap();
        assert_eq!(outcome.reopened_claim, None);
        assert!(matches!(
            load_claim(&state, job_id, claims[0]).unwrap().status,
            ClaimStatus::Resolved(_)
        ));
    }

    #[test]
    fn lifecycle_boundaries_missing_windows_and_invalid_targets_are_rejected() {
        let (mut state, authority, job_id, claims) = fixture(4);
        let resolution = resolve_action(job_id, claims[0]);
        for height in [20, 25] {
            assert_eq!(
                resolve_claim(&mut state, &authority, height, &resolution),
                Err(ChallengeResolutionError::ResolutionTooEarly {
                    opens_after: 25,
                    current_height: height,
                })
            );
        }
        assert!(resolve_claim(&mut state, &authority, 26, &resolution).is_ok());
        let claim_challenge = challenge(ChallengeTarget::Claim(claims[0]), Vec::new());
        assert_eq!(
            create_challenge(&mut state, &actor(70), 25, &claim_challenge),
            Err(ChallengeResolutionError::ChallengeTooEarly {
                opens_after: 25,
                current_height: 25,
            })
        );
        let boundary_challenge =
            create_challenge(&mut state, &actor(70), 30, &claim_challenge).unwrap();
        assert_eq!(
            resolve_challenge(
                &mut state,
                &authority,
                31,
                &challenge_resolution(boundary_challenge, false),
            ),
            Err(ChallengeResolutionError::ChallengeTooLate {
                closes_at: 30,
                current_height: 31,
            })
        );
        assert_eq!(
            resolve_challenge(
                &mut state,
                &authority,
                30,
                &challenge_resolution(ChallengeId::derive(b"missing"), false),
            ),
            Err(ChallengeResolutionError::ChallengeNotFound)
        );
        assert_eq!(
            create_challenge(&mut state, &actor(71), 31, &claim_challenge),
            Err(ChallengeResolutionError::ChallengeTooLate {
                closes_at: 30,
                current_height: 31,
            })
        );
        assert_eq!(
            resolve_claim(
                &mut state,
                &authority,
                31,
                &resolve_action(job_id, claims[1]),
            ),
            Err(ChallengeResolutionError::ResolutionTooLate {
                closes_at: 30,
                current_height: 31,
            })
        );
        assert_eq!(
            create_challenge(
                &mut state,
                &actor(72),
                26,
                &challenge(ChallengeTarget::Claim(claims[1]), Vec::new()),
            ),
            Err(ChallengeResolutionError::ClaimNotResolved)
        );
        let foreign = create_job(&mut state, &actor(700), 10, &create(41, actor(701))).unwrap();
        assert_eq!(
            resolve_claim(
                &mut state,
                &authority,
                26,
                &resolve_action(job_id, foreign.claim_ids.as_slice()[0]),
            ),
            Err(ChallengeResolutionError::ClaimJobMismatch)
        );
        assert_eq!(
            create_challenge(
                &mut state,
                &actor(72),
                26,
                &challenge(
                    ChallengeTarget::Attestation(AttestationId::derive(b"missing")),
                    Vec::new(),
                ),
            ),
            Err(ChallengeResolutionError::AttestationNotFound)
        );

        let customer = actor(73);
        let mut no_window = create(40, actor(74));
        no_window.reveal_closes_at = None;
        no_window.challenge_closes_at = None;
        let no_window_job = create_job(&mut state, &customer, 10, &no_window).unwrap();
        let attestation = SubmitAttestation {
            job_id: no_window_job.job_id,
            claim_id: no_window_job.claim_ids.as_slice()[0],
            verdict: Verdict::Pass,
            confidence_basis_points: 1,
            evidence_ids: BoundedVec::default(),
        };
        let attestation_id = submit_attestation(&mut state, &actor(75), 10, &attestation).unwrap();
        assert_eq!(
            create_challenge(
                &mut state,
                &actor(76),
                21,
                &challenge(ChallengeTarget::Attestation(attestation_id), Vec::new()),
            ),
            Err(ChallengeResolutionError::ChallengeWindowNotConfigured)
        );
    }

    #[test]
    fn evidence_references_are_unique_registered_and_target_scoped() {
        let (mut state, authority, job_id, claims) = fixture(5);
        let first = register(&mut state, job_id, Some(claims[0]), 80);
        let second = register(&mut state, job_id, Some(claims[1]), 81);
        let missing = EvidenceId::derive(b"missing");

        for (ids, expected) in [
            (vec![missing], ChallengeResolutionError::EvidenceNotFound),
            (
                vec![first, first],
                ChallengeResolutionError::DuplicateEvidenceReference,
            ),
            (
                vec![second],
                ChallengeResolutionError::EvidenceClaimMismatch,
            ),
        ] {
            let mut action = resolve_action(job_id, claims[0]);
            action.evidence_ids = BoundedVec::new(ids).unwrap();
            assert_eq!(
                resolve_claim(&mut state, &authority, 26, &action),
                Err(expected)
            );
        }

        let (mut foreign, _, foreign_job, foreign_claims) = fixture(6);
        let foreign_evidence = register(&mut foreign, foreign_job, None, 82);
        let bytes = foreign.get(&StateKey::evidence(&foreign_evidence)).unwrap();
        state.put(StateKey::evidence(&foreign_evidence), bytes);
        let mut action = resolve_action(job_id, claims[0]);
        action.evidence_ids = BoundedVec::new(vec![foreign_evidence]).unwrap();
        assert_eq!(
            resolve_claim(&mut state, &authority, 26, &action),
            Err(ChallengeResolutionError::EvidenceJobMismatch)
        );
        assert_ne!(foreign_claims[0], claims[0]);
    }

    #[test]
    fn exact_open_challenge_limit_and_duplicate_identity_are_enforced() {
        let (mut state, authority, job_id, claims) = fixture(7);
        resolve_claim(
            &mut state,
            &authority,
            26,
            &resolve_action(job_id, claims[0]),
        )
        .unwrap();
        let target = ChallengeTarget::Claim(claims[0]);
        for seed in 0..MAX_OPEN_CHALLENGES_PER_CLAIM {
            let action = CreateChallenge {
                target,
                counterclaim: bounded::<MAX_COUNTERCLAIM_BYTES>(&seed.to_be_bytes()),
                evidence_ids: BoundedVec::default(),
            };
            create_challenge(
                &mut state,
                &actor(10_000 + u64::try_from(seed).unwrap()),
                26,
                &action,
            )
            .unwrap();
        }
        let overflow = challenge(target, Vec::new());
        assert_eq!(
            create_challenge(&mut state, &actor(20_000), 26, &overflow),
            Err(ChallengeResolutionError::OpenChallengeLimitReached {
                maximum: MAX_OPEN_CHALLENGES_PER_CLAIM,
            })
        );

        let (mut duplicate_state, authority, job_id, claims) = fixture(8);
        resolve_claim(
            &mut duplicate_state,
            &authority,
            26,
            &resolve_action(job_id, claims[0]),
        )
        .unwrap();
        let challenger = actor(90);
        let action = challenge(ChallengeTarget::Claim(claims[0]), Vec::new());
        create_challenge(&mut duplicate_state, &challenger, 26, &action).unwrap();
        let root = duplicate_state.root();
        assert_eq!(
            create_challenge(&mut duplicate_state, &challenger, 27, &action),
            Err(ChallengeResolutionError::ChallengeAlreadyExists)
        );
        assert_eq!(duplicate_state.root(), root);
    }

    #[test]
    fn stale_open_claim_challenges_block_reresolution_until_closed() {
        let (mut state, authority, job_id, claims) = fixture(9);
        resolve_claim(
            &mut state,
            &authority,
            26,
            &resolve_action(job_id, claims[0]),
        )
        .unwrap();
        let target = challenge(ChallengeTarget::Claim(claims[0]), Vec::new());
        let upheld = create_challenge(&mut state, &actor(100), 26, &target).unwrap();
        let stale = create_challenge(&mut state, &actor(101), 26, &target).unwrap();
        resolve_challenge(
            &mut state,
            &authority,
            27,
            &challenge_resolution(upheld, true),
        )
        .unwrap();
        assert_eq!(
            resolve_claim(
                &mut state,
                &authority,
                28,
                &resolve_action(job_id, claims[0]),
            ),
            Err(ChallengeResolutionError::ClaimHasOpenChallenges)
        );
        assert_eq!(
            resolve_challenge(
                &mut state,
                &authority,
                28,
                &challenge_resolution(stale, true),
            ),
            Err(ChallengeResolutionError::ClaimNotResolved)
        );
        resolve_challenge(
            &mut state,
            &authority,
            28,
            &challenge_resolution(stale, false),
        )
        .unwrap();
        assert!(
            resolve_claim(
                &mut state,
                &authority,
                29,
                &resolve_action(job_id, claims[0]),
            )
            .is_ok()
        );
    }
}
