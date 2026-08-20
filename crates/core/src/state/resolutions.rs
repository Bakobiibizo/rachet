//! Canonical challenge and resolution state records.

use crate::{
    actions::{ChallengeTarget, CreateChallenge, ResolutionVerdict},
    artifacts::ContentRef,
    bounded::{BoundedBytes, BoundedVec},
    limits::{MAX_COUNTERCLAIM_BYTES, MAX_EVIDENCE_IDS_PER_ACTION},
    primitives::{ActorId, ChallengeId, ClaimId, EvidenceId, JobId},
};
use commonware_codec::Write as _;

/// Authority result retained while a claim remains resolved.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClaimResolution {
    pub verdict: ResolutionVerdict,
    pub evidence_ids: BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>,
    pub resolution_reference: ContentRef,
}

/// Mutable lifecycle state of a claim.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ClaimStatus {
    /// No current authority resolution exists.
    Open = 0,
    /// The authority supplied a current ground-truth resolution.
    Resolved(ClaimResolution) = 1,
}

/// Mutable lifecycle state of a challenge.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ChallengeStatus {
    Open = 0,
    Resolved {
        upheld: bool,
        evidence_ids: BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>,
        resolution_reference: ContentRef,
    } = 1,
}

/// Canonical state retained for one counterclaim.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChallengeRecord {
    pub challenger: ActorId,
    /// Validated target projection retained for bounded counting and lookup.
    pub job_id: JobId,
    /// Validated target projection retained for bounded counting and lookup.
    pub claim_id: ClaimId,
    pub target: ChallengeTarget,
    pub counterclaim: BoundedBytes<MAX_COUNTERCLAIM_BYTES>,
    pub evidence_ids: BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>,
    pub status: ChallengeStatus,
}

impl ChallengeRecord {
    /// Constructs a pending record after the target projection is validated.
    pub fn from_action(
        challenger: ActorId,
        job_id: JobId,
        claim_id: ClaimId,
        action: &CreateChallenge,
    ) -> Self {
        Self {
            challenger,
            job_id,
            claim_id,
            target: action.target,
            counterclaim: action.counterclaim.clone(),
            evidence_ids: action.evidence_ids.clone(),
            status: ChallengeStatus::Open,
        }
    }

    /// Returns the identifier implied by challenger and original payload.
    pub fn challenge_id(&self) -> ChallengeId {
        let mut identity = Vec::new();
        self.challenger.write(&mut identity);
        self.target.write(&mut identity);
        self.counterclaim.write(&mut identity);
        self.evidence_ids.write(&mut identity);
        ChallengeId::derive(&identity)
    }
}
