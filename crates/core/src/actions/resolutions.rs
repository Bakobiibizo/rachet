//! Canonical challenge and authority-resolution action payloads.

use crate::{
    artifacts::ContentRef,
    bounded::{BoundedBytes, BoundedVec},
    limits::{MAX_COUNTERCLAIM_BYTES, MAX_EVIDENCE_IDS_PER_ACTION},
    primitives::{ActorId, AttestationId, ChallengeId, ClaimId, EvidenceId, JobId},
};
use commonware_codec::Write as _;

/// An immutable protocol object against which a counterclaim is made.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ChallengeTarget {
    /// The current authority resolution of a claim.
    Claim(ClaimId) = 0,
    /// One validation operator's immutable attestation.
    Attestation(AttestationId) = 1,
}

/// Records one bounded counterclaim during a job's challenge window.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CreateChallenge {
    pub target: ChallengeTarget,
    pub counterclaim: BoundedBytes<MAX_COUNTERCLAIM_BYTES>,
    pub evidence_ids: BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>,
}

impl CreateChallenge {
    /// Derives an identity that binds the challenger and complete payload.
    pub fn challenge_id(&self, challenger: &ActorId) -> ChallengeId {
        let mut identity = Vec::new();
        challenger.write(&mut identity);
        self.write(&mut identity);
        ChallengeId::derive(&identity)
    }
}

/// The experimental authority's ground-truth verdict for one claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ResolutionVerdict {
    Pass = 0,
    Fail = 1,
    Unresolved = 2,
}

/// Finalizes the current authority verdict for one claim.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResolveClaim {
    pub job_id: JobId,
    pub claim_id: ClaimId,
    pub verdict: ResolutionVerdict,
    pub evidence_ids: BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>,
    pub resolution_reference: ContentRef,
}

/// Finalizes one recorded challenge.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResolveChallenge {
    pub challenge_id: ChallengeId,
    pub upheld: bool,
    pub evidence_ids: BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>,
    pub resolution_reference: ContentRef,
}
