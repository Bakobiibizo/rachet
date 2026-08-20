//! Canonical off-chain evidence registration and attestation payloads.

use crate::{
    artifacts::ContentRef,
    bounded::BoundedVec,
    limits::MAX_EVIDENCE_IDS_PER_ACTION,
    primitives::{AttestationId, ClaimId, EvidenceId, JobId, Sha256Digest},
};
use commonware_codec::Write as _;

/// Registers one digest-addressed off-chain evidence body for a job.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegisterEvidence {
    pub job_id: JobId,
    pub claim_id: Option<ClaimId>,
    pub evidence: ContentRef,
    pub manifest_digest: Sha256Digest,
}

impl RegisterEvidence {
    /// Returns the identity of the off-chain evidence body.
    ///
    /// Locator and media-type hints, the manifest, target, and producer are
    /// registration metadata. Excluding them keeps one content digest bound to
    /// exactly one producer and prevents alternate hints from creating aliases.
    pub fn evidence_id(&self) -> EvidenceId {
        EvidenceId::derive(self.evidence.digest.as_ref())
    }
}

/// An operator's semantic verdict about one claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Verdict {
    Pass = 0,
    Fail = 1,
    Abstain = 2,
    Indeterminate = 3,
}

/// Submits one validation operator's attestation about a canonical claim.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SubmitAttestation {
    pub job_id: JobId,
    pub claim_id: ClaimId,
    pub verdict: Verdict,
    pub confidence_basis_points: u16,
    pub evidence_ids: BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>,
}

impl SubmitAttestation {
    /// Derives an attestation ID from the operator and complete payload.
    pub fn attestation_id(&self, operator: &crate::primitives::ActorId) -> AttestationId {
        let mut identity = Vec::new();
        operator.write(&mut identity);
        self.write(&mut identity);
        AttestationId::derive(&identity)
    }
}
