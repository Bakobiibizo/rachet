//! Canonical evidence registration and attestation state records.

use crate::{
    actions::{RegisterEvidence, SubmitAttestation, Verdict},
    artifacts::ContentRef,
    bounded::BoundedVec,
    limits::MAX_EVIDENCE_IDS_PER_ACTION,
    primitives::{ActorId, AttestationId, ClaimId, EvidenceId, JobId, Sha256Digest},
};
use commonware_codec::Write as _;

/// Immutable metadata retained for one digest-addressed off-chain evidence body.
///
/// The evidence body is deliberately absent from consensus state.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceRecord {
    pub producer: ActorId,
    pub job_id: JobId,
    pub claim_id: Option<ClaimId>,
    pub evidence: ContentRef,
    pub manifest_digest: Sha256Digest,
}

impl EvidenceRecord {
    /// Constructs a record from an accepted registration.
    pub fn from_action(producer: ActorId, action: &RegisterEvidence) -> Self {
        Self {
            producer,
            job_id: action.job_id,
            claim_id: action.claim_id,
            evidence: action.evidence.clone(),
            manifest_digest: action.manifest_digest,
        }
    }

    /// Returns the content identity implied by this record.
    pub fn evidence_id(&self) -> EvidenceId {
        EvidenceId::derive(self.evidence.digest.as_ref())
    }
}

/// Immutable state retained for one operator attestation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttestationRecord {
    pub operator: ActorId,
    pub job_id: JobId,
    pub claim_id: ClaimId,
    pub verdict: Verdict,
    pub confidence_basis_points: u16,
    pub evidence_ids: BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>,
}

impl AttestationRecord {
    /// Constructs a record from an accepted attestation.
    pub fn from_action(operator: ActorId, action: &SubmitAttestation) -> Self {
        Self {
            operator,
            job_id: action.job_id,
            claim_id: action.claim_id,
            verdict: action.verdict,
            confidence_basis_points: action.confidence_basis_points,
            evidence_ids: action.evidence_ids.clone(),
        }
    }

    /// Returns the identifier implied by the complete canonical record.
    pub fn attestation_id(&self) -> AttestationId {
        let mut identity = Vec::new();
        self.write(&mut identity);
        AttestationId::derive(&identity)
    }
}
