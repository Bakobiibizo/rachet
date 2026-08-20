//! Canonical job lifecycle action payloads.

use crate::{
    artifacts::{ContentRef, GitArtifact},
    bounded::{BoundedBytes, BoundedVec},
    limits::{MAX_CLAIM_STATEMENT_BYTES, MAX_CLAIMS_PER_JOB, MAX_METADATA_BYTES},
    primitives::{ActorId, JobId, Sha256Digest},
};

/// The immutable statement operators evaluate for one job claim.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClaimDefinition {
    /// Canonical bounded claim statement.
    pub statement: BoundedBytes<MAX_CLAIM_STATEMENT_BYTES>,
}

impl ClaimDefinition {
    /// Constructs an immutable claim definition.
    pub const fn new(statement: BoundedBytes<MAX_CLAIM_STATEMENT_BYTES>) -> Self {
        Self { statement }
    }
}

/// The authority model against which claim resolutions are evaluated.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ResolutionPolicy {
    /// A signed resolution from the configured experimental authority.
    ExperimentAuthority {
        /// Network actor authorized to resolve this job.
        authority: ActorId,
    } = 0,
    /// A future deterministic verifier identified by immutable content.
    DeterministicVerifier {
        /// Identity of the verifier implementation.
        verifier_id: Sha256Digest,
        /// Digest-addressed verifier specification.
        verifier_spec: ContentRef,
    } = 1,
}

impl ResolutionPolicy {
    /// Returns the configured actor authority, when resolution is actor-signed.
    pub const fn experiment_authority(&self) -> Option<&ActorId> {
        match self {
            Self::ExperimentAuthority { authority } => Some(authority),
            Self::DeterministicVerifier { .. } => None,
        }
    }
}

/// Height-based windows controlling a job's validation lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobLifecycle {
    /// First height at which validation actions are accepted, inclusive.
    pub validation_opens_at: u64,
    /// Last height at which validation actions are accepted, inclusive.
    pub validation_closes_at: u64,
    /// Last commitment-reveal height, inclusive, when configured.
    pub reveal_closes_at: Option<u64>,
    /// Last challenge height, inclusive, when configured.
    pub challenge_closes_at: Option<u64>,
}

impl JobLifecycle {
    /// Constructs lifecycle windows without performing creation-height validation.
    pub const fn new(
        validation_opens_at: u64,
        validation_closes_at: u64,
        reveal_closes_at: Option<u64>,
        challenge_closes_at: Option<u64>,
    ) -> Self {
        Self {
            validation_opens_at,
            validation_closes_at,
            reveal_closes_at,
            challenge_closes_at,
        }
    }

    /// Returns the last inclusive height of every configured lifecycle phase.
    pub fn final_closes_at(self) -> u64 {
        self.challenge_closes_at
            .or(self.reveal_closes_at)
            .unwrap_or(self.validation_closes_at)
    }

    /// Returns whether validation is open at `height`.
    pub fn validation_is_open(self, height: u64) -> bool {
        (self.validation_opens_at..=self.validation_closes_at).contains(&height)
    }
}

/// Creates one immutable Git validation job and its immutable claims.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CreateJob {
    pub artifact: GitArtifact,
    pub claims: BoundedVec<ClaimDefinition, MAX_CLAIMS_PER_JOB>,
    pub resolution_policy: ResolutionPolicy,
    pub validation_opens_at: u64,
    pub validation_closes_at: u64,
    pub reveal_closes_at: Option<u64>,
    pub challenge_closes_at: Option<u64>,
    pub supersedes: Option<JobId>,
    pub metadata: BoundedBytes<MAX_METADATA_BYTES>,
}

impl CreateJob {
    /// Returns the lifecycle projection carried by this action.
    pub const fn lifecycle(&self) -> JobLifecycle {
        JobLifecycle::new(
            self.validation_opens_at,
            self.validation_closes_at,
            self.reveal_closes_at,
            self.challenge_closes_at,
        )
    }

    /// Returns the immutable software-change identity for this job revision.
    pub fn job_id(&self) -> JobId {
        self.artifact.job_id()
    }
}

/// Closes a job after all of its configured lifecycle windows have elapsed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CloseJob {
    pub job_id: JobId,
}

impl CloseJob {
    /// Constructs a close-job action.
    pub const fn new(job_id: JobId) -> Self {
        Self { job_id }
    }
}
