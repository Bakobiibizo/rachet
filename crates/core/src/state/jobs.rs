//! Canonical job and claim state records.

use crate::{
    actions::{ClaimDefinition, JobLifecycle, ResolutionPolicy},
    artifacts::GitArtifact,
    bounded::{BoundedBytes, BoundedVec},
    limits::{MAX_CLAIMS_PER_JOB, MAX_METADATA_BYTES},
    primitives::{ActorId, ClaimId, JobId},
    state::ClaimStatus,
};

/// Mutable lifecycle status of an otherwise immutable job record.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum JobStatus {
    /// At least one configured lifecycle phase has not been explicitly closed.
    Open = 0,
    /// Every claim currently has an authority resolution.
    Resolved = 1,
    /// The customer closed the job after every configured window elapsed.
    Closed = 2,
}

/// Canonical state retained for one validation job.
///
/// Closing a job may change only `status`; artifact, claims, policy, windows,
/// predecessor linkage, customer, and metadata remain immutable.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobRecord {
    pub customer: ActorId,
    pub artifact: GitArtifact,
    pub claim_ids: BoundedVec<ClaimId, MAX_CLAIMS_PER_JOB>,
    pub resolution_policy: ResolutionPolicy,
    pub lifecycle: JobLifecycle,
    pub supersedes: Option<JobId>,
    pub metadata: BoundedBytes<MAX_METADATA_BYTES>,
    pub status: JobStatus,
}

impl JobRecord {
    /// Returns the identifier implied by the immutable artifact.
    pub fn job_id(&self) -> JobId {
        self.artifact.job_id()
    }
}

/// Canonical state retained for one job claim.
///
/// The job and definition are immutable. Only `status` changes when an
/// authority resolves the claim or an upheld challenge reopens it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClaimRecord {
    pub job_id: JobId,
    pub definition: ClaimDefinition,
    pub status: ClaimStatus,
}
