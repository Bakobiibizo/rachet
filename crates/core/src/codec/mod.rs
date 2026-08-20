//! Canonical protocol encoding.
//!
//! Every implementation in this module writes fields in declaration order,
//! uses fixed-width big-endian integers, and assigns one-byte enum tags
//! explicitly. Variable-length fields are protocol-bounded by their types.

use crate::{
    actions::{
        Action, ChallengeTarget, ClaimDefinition, CloseJob, CommitmentSubject, CreateChallenge,
        CreateCommitment, CreateJob, Ed25519Signature, JobLifecycle, RegisterEvidence,
        ResolutionPolicy, ResolutionVerdict, ResolveChallenge, ResolveClaim, RevealCommitment,
        SIGNED_ACTION_FIXED_BYTES, SignedAction, SubmitAttestation, Verdict,
    },
    artifacts::{ContentRef, GitArtifact, GitHash, JobArtifact},
    blocks::{Block, BlockHeader, BlockValidationError, ConsensusContext, ConsensusNodeId},
    events::{ActionReceipt, CanonicalEvent},
    limits::{MAX_ACTION_BYTES, MAX_ACTIONS_PER_BLOCK, MAX_BLOCK_BODY_BYTES},
    numeric::{BasisPoints, RoundingMode},
    primitives::{
        ActionId, ActorId, AttestationId, ChainId, ChallengeId, ClaimId, CodecVersion,
        CommitmentId, Ed25519PublicKey, EvidenceId, ExperimentId, HashDomain, JobId,
        MechanismSetId, ProtocolVersion, Sha256Digest,
    },
    state::{
        AttestationRecord, ChallengeRecord, ChallengeStatus, ClaimRecord, ClaimResolution,
        ClaimStatus, CommitmentRecord, CommitmentStatus, EvidenceRecord, JobRecord, JobStatus,
    },
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write};

macro_rules! version_codec {
    ($type:ty) => {
        impl Write for $type {
            fn write(&self, buf: &mut impl BufMut) {
                self.get().write(buf);
            }
        }

        impl FixedSize for $type {
            const SIZE: usize = <u16 as FixedSize>::SIZE;
        }

        impl Read for $type {
            type Cfg = ();

            fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
                Ok(Self::new(u16::read(buf)?))
            }
        }
    };
}

version_codec!(ProtocolVersion);
version_codec!(CodecVersion);

impl Write for ChainId {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl FixedSize for ChainId {
    const SIZE: usize = <[u8; 32] as FixedSize>::SIZE;
}

impl Read for ChainId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(<[u8; 32]>::read(buf)?))
    }
}

impl Write for ActorId {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl FixedSize for ActorId {
    const SIZE: usize = <Ed25519PublicKey as FixedSize>::SIZE;
}

impl Read for ActorId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::from(Ed25519PublicKey::read(buf)?))
    }
}

macro_rules! digest_identifier_codec {
    ($($type:ty),+ $(,)?) => {
        $(
            impl Write for $type {
                fn write(&self, buf: &mut impl BufMut) {
                    self.0.write(buf);
                }
            }

            impl FixedSize for $type {
                const SIZE: usize = <Sha256Digest as FixedSize>::SIZE;
            }

            impl Read for $type {
                type Cfg = ();

                fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
                    Ok(Self::from_digest(Sha256Digest::read(buf)?))
                }
            }
        )+
    };
}

digest_identifier_codec!(
    JobId,
    ClaimId,
    AttestationId,
    EvidenceId,
    ChallengeId,
    CommitmentId,
    ActionId,
    MechanismSetId,
    ExperimentId,
);

impl Write for HashDomain {
    fn write(&self, buf: &mut impl BufMut) {
        (*self as u8).write(buf);
    }
}

impl FixedSize for HashDomain {
    const SIZE: usize = <u8 as FixedSize>::SIZE;
}

impl Read for HashDomain {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Action),
            1 => Ok(Self::Job),
            2 => Ok(Self::Claim),
            3 => Ok(Self::Attestation),
            4 => Ok(Self::Evidence),
            5 => Ok(Self::Challenge),
            6 => Ok(Self::Commitment),
            7 => Ok(Self::Block),
            8 => Ok(Self::State),
            9 => Ok(Self::MechanismSet),
            10 => Ok(Self::Experiment),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for RoundingMode {
    fn write(&self, buf: &mut impl BufMut) {
        (*self as u8).write(buf);
    }
}

impl FixedSize for RoundingMode {
    const SIZE: usize = <u8 as FixedSize>::SIZE;
}

impl Read for RoundingMode {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::TowardZero),
            1 => Ok(Self::AwayFromZero),
            2 => Ok(Self::Floor),
            3 => Ok(Self::Ceiling),
            4 => Ok(Self::NearestTiesToEven),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for BasisPoints {
    fn write(&self, buf: &mut impl BufMut) {
        self.get().write(buf);
    }
}

impl FixedSize for BasisPoints {
    const SIZE: usize = <u16 as FixedSize>::SIZE;
}

impl Read for BasisPoints {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Self::new(u16::read(buf)?)
            .map_err(|error| CodecError::Wrapped("BasisPoints", Box::new(error)))
    }
}

impl Write for GitHash {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Sha1(bytes) => {
                0_u8.write(buf);
                bytes.write(buf);
            }
            Self::Sha256(bytes) => {
                1_u8.write(buf);
                bytes.write(buf);
            }
        }
    }
}

impl EncodeSize for GitHash {
    fn encode_size(&self) -> usize {
        1 + self.as_bytes().len()
    }
}

impl Read for GitHash {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::sha1(<[u8; 20]>::read(buf)?)),
            1 => Ok(Self::sha256(<[u8; 32]>::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for ContentRef {
    fn write(&self, buf: &mut impl BufMut) {
        self.digest.write(buf);
        self.locator_hint.write(buf);
        self.media_type.write(buf);
    }
}

impl EncodeSize for ContentRef {
    fn encode_size(&self) -> usize {
        self.digest.encode_size() + self.locator_hint.encode_size() + self.media_type.encode_size()
    }
}

impl Read for ContentRef {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(
            Sha256Digest::read(buf)?,
            Read::read_cfg(buf, &())?,
            Read::read_cfg(buf, &())?,
        ))
    }
}

impl Write for GitArtifact {
    fn write(&self, buf: &mut impl BufMut) {
        self.repository.write(buf);
        self.base_commit.write(buf);
        self.candidate_commit.write(buf);
        self.specification.write(buf);
    }
}

impl EncodeSize for GitArtifact {
    fn encode_size(&self) -> usize {
        self.repository.encode_size()
            + self.base_commit.encode_size()
            + self.candidate_commit.encode_size()
            + self.specification.encode_size()
    }
}

impl Read for GitArtifact {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(
            Read::read_cfg(buf, &())?,
            GitHash::read(buf)?,
            GitHash::read(buf)?,
            ContentRef::read(buf)?,
        ))
    }
}

impl Write for JobArtifact {
    fn write(&self, buf: &mut impl BufMut) {
        self.artifact.write(buf);
        self.supersedes.write(buf);
    }
}

impl EncodeSize for JobArtifact {
    fn encode_size(&self) -> usize {
        self.artifact.encode_size() + self.supersedes.encode_size()
    }
}

impl Read for JobArtifact {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(
            GitArtifact::read(buf)?,
            Option::<JobId>::read(buf)?,
        ))
    }
}

impl Write for CommitmentSubject {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Job(job_id) => {
                0_u8.write(buf);
                job_id.write(buf);
            }
            Self::Claim(claim_id) => {
                1_u8.write(buf);
                claim_id.write(buf);
            }
        }
    }
}

impl EncodeSize for CommitmentSubject {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Job(job_id) => job_id.encode_size(),
            Self::Claim(claim_id) => claim_id.encode_size(),
        }
    }
}

impl Read for CommitmentSubject {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Job(JobId::read(buf)?)),
            1 => Ok(Self::Claim(ClaimId::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for CreateCommitment {
    fn write(&self, buf: &mut impl BufMut) {
        self.subject.write(buf);
        self.digest.write(buf);
        self.reveal_after_height.write(buf);
        self.reveal_before_height.write(buf);
    }
}

impl EncodeSize for CreateCommitment {
    fn encode_size(&self) -> usize {
        self.subject.encode_size()
            + self.digest.encode_size()
            + self.reveal_after_height.encode_size()
            + self.reveal_before_height.encode_size()
    }
}

impl Read for CreateCommitment {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            subject: CommitmentSubject::read(buf)?,
            digest: Sha256Digest::read(buf)?,
            reveal_after_height: u64::read(buf)?,
            reveal_before_height: u64::read(buf)?,
        })
    }
}

impl Write for RevealCommitment {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment_id.write(buf);
        self.payload.write(buf);
        self.salt.write(buf);
    }
}

impl EncodeSize for RevealCommitment {
    fn encode_size(&self) -> usize {
        self.commitment_id.encode_size() + self.payload.encode_size() + self.salt.encode_size()
    }
}

impl Read for RevealCommitment {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            commitment_id: CommitmentId::read(buf)?,
            payload: Read::read_cfg(buf, &())?,
            salt: Read::read_cfg(buf, &())?,
        })
    }
}

impl Write for RegisterEvidence {
    fn write(&self, buf: &mut impl BufMut) {
        self.job_id.write(buf);
        self.claim_id.write(buf);
        self.evidence.write(buf);
        self.manifest_digest.write(buf);
    }
}

impl EncodeSize for RegisterEvidence {
    fn encode_size(&self) -> usize {
        self.job_id.encode_size()
            + self.claim_id.encode_size()
            + self.evidence.encode_size()
            + self.manifest_digest.encode_size()
    }
}

impl Read for RegisterEvidence {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            job_id: JobId::read(buf)?,
            claim_id: Option::<ClaimId>::read(buf)?,
            evidence: ContentRef::read(buf)?,
            manifest_digest: Sha256Digest::read(buf)?,
        })
    }
}

impl Write for Verdict {
    fn write(&self, buf: &mut impl BufMut) {
        (*self as u8).write(buf);
    }
}

impl FixedSize for Verdict {
    const SIZE: usize = <u8 as FixedSize>::SIZE;
}

impl Read for Verdict {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Pass),
            1 => Ok(Self::Fail),
            2 => Ok(Self::Abstain),
            3 => Ok(Self::Indeterminate),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for SubmitAttestation {
    fn write(&self, buf: &mut impl BufMut) {
        self.job_id.write(buf);
        self.claim_id.write(buf);
        self.verdict.write(buf);
        self.confidence_basis_points.write(buf);
        self.evidence_ids.write(buf);
    }
}

impl EncodeSize for SubmitAttestation {
    fn encode_size(&self) -> usize {
        self.job_id.encode_size()
            + self.claim_id.encode_size()
            + self.verdict.encode_size()
            + self.confidence_basis_points.encode_size()
            + self.evidence_ids.encode_size()
    }
}

impl Read for SubmitAttestation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            job_id: JobId::read(buf)?,
            claim_id: ClaimId::read(buf)?,
            verdict: Verdict::read(buf)?,
            confidence_basis_points: u16::read(buf)?,
            evidence_ids: Read::read_cfg(buf, &())?,
        })
    }
}

impl Write for ChallengeTarget {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Claim(claim_id) => {
                0_u8.write(buf);
                claim_id.write(buf);
            }
            Self::Attestation(attestation_id) => {
                1_u8.write(buf);
                attestation_id.write(buf);
            }
        }
    }
}

impl EncodeSize for ChallengeTarget {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Claim(claim_id) => claim_id.encode_size(),
            Self::Attestation(attestation_id) => attestation_id.encode_size(),
        }
    }
}

impl Read for ChallengeTarget {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Claim(ClaimId::read(buf)?)),
            1 => Ok(Self::Attestation(AttestationId::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for CreateChallenge {
    fn write(&self, buf: &mut impl BufMut) {
        self.target.write(buf);
        self.counterclaim.write(buf);
        self.evidence_ids.write(buf);
    }
}

impl EncodeSize for CreateChallenge {
    fn encode_size(&self) -> usize {
        self.target.encode_size()
            + self.counterclaim.encode_size()
            + self.evidence_ids.encode_size()
    }
}

impl Read for CreateChallenge {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            target: ChallengeTarget::read(buf)?,
            counterclaim: Read::read_cfg(buf, &())?,
            evidence_ids: Read::read_cfg(buf, &())?,
        })
    }
}

impl Write for ResolutionVerdict {
    fn write(&self, buf: &mut impl BufMut) {
        (*self as u8).write(buf);
    }
}

impl FixedSize for ResolutionVerdict {
    const SIZE: usize = <u8 as FixedSize>::SIZE;
}

impl Read for ResolutionVerdict {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Pass),
            1 => Ok(Self::Fail),
            2 => Ok(Self::Unresolved),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for ResolveClaim {
    fn write(&self, buf: &mut impl BufMut) {
        self.job_id.write(buf);
        self.claim_id.write(buf);
        self.verdict.write(buf);
        self.evidence_ids.write(buf);
        self.resolution_reference.write(buf);
    }
}

impl EncodeSize for ResolveClaim {
    fn encode_size(&self) -> usize {
        self.job_id.encode_size()
            + self.claim_id.encode_size()
            + self.verdict.encode_size()
            + self.evidence_ids.encode_size()
            + self.resolution_reference.encode_size()
    }
}

impl Read for ResolveClaim {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            job_id: JobId::read(buf)?,
            claim_id: ClaimId::read(buf)?,
            verdict: ResolutionVerdict::read(buf)?,
            evidence_ids: Read::read_cfg(buf, &())?,
            resolution_reference: ContentRef::read(buf)?,
        })
    }
}

impl Write for ResolveChallenge {
    fn write(&self, buf: &mut impl BufMut) {
        self.challenge_id.write(buf);
        self.upheld.write(buf);
        self.evidence_ids.write(buf);
        self.resolution_reference.write(buf);
    }
}

impl EncodeSize for ResolveChallenge {
    fn encode_size(&self) -> usize {
        self.challenge_id.encode_size()
            + self.upheld.encode_size()
            + self.evidence_ids.encode_size()
            + self.resolution_reference.encode_size()
    }
}

impl Read for ResolveChallenge {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            challenge_id: ChallengeId::read(buf)?,
            upheld: bool::read(buf)?,
            evidence_ids: Read::read_cfg(buf, &())?,
            resolution_reference: ContentRef::read(buf)?,
        })
    }
}

impl Write for ClaimDefinition {
    fn write(&self, buf: &mut impl BufMut) {
        self.statement.write(buf);
    }
}

impl EncodeSize for ClaimDefinition {
    fn encode_size(&self) -> usize {
        self.statement.encode_size()
    }
}

impl Read for ClaimDefinition {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(Read::read_cfg(buf, &())?))
    }
}

impl Write for ResolutionPolicy {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::ExperimentAuthority { authority } => {
                0_u8.write(buf);
                authority.write(buf);
            }
            Self::DeterministicVerifier {
                verifier_id,
                verifier_spec,
            } => {
                1_u8.write(buf);
                verifier_id.write(buf);
                verifier_spec.write(buf);
            }
        }
    }
}

impl EncodeSize for ResolutionPolicy {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::ExperimentAuthority { authority } => authority.encode_size(),
            Self::DeterministicVerifier {
                verifier_id,
                verifier_spec,
            } => verifier_id.encode_size() + verifier_spec.encode_size(),
        }
    }
}

impl Read for ResolutionPolicy {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::ExperimentAuthority {
                authority: ActorId::read(buf)?,
            }),
            1 => Ok(Self::DeterministicVerifier {
                verifier_id: Sha256Digest::read(buf)?,
                verifier_spec: ContentRef::read(buf)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for JobLifecycle {
    fn write(&self, buf: &mut impl BufMut) {
        self.validation_opens_at.write(buf);
        self.validation_closes_at.write(buf);
        self.reveal_closes_at.write(buf);
        self.challenge_closes_at.write(buf);
    }
}

impl EncodeSize for JobLifecycle {
    fn encode_size(&self) -> usize {
        self.validation_opens_at.encode_size()
            + self.validation_closes_at.encode_size()
            + self.reveal_closes_at.encode_size()
            + self.challenge_closes_at.encode_size()
    }
}

impl Read for JobLifecycle {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(
            u64::read(buf)?,
            u64::read(buf)?,
            Option::<u64>::read(buf)?,
            Option::<u64>::read(buf)?,
        ))
    }
}

impl Write for CreateJob {
    fn write(&self, buf: &mut impl BufMut) {
        self.artifact.write(buf);
        self.claims.write(buf);
        self.resolution_policy.write(buf);
        self.validation_opens_at.write(buf);
        self.validation_closes_at.write(buf);
        self.reveal_closes_at.write(buf);
        self.challenge_closes_at.write(buf);
        self.supersedes.write(buf);
        self.metadata.write(buf);
    }
}

impl EncodeSize for CreateJob {
    fn encode_size(&self) -> usize {
        self.artifact.encode_size()
            + self.claims.encode_size()
            + self.resolution_policy.encode_size()
            + self.validation_opens_at.encode_size()
            + self.validation_closes_at.encode_size()
            + self.reveal_closes_at.encode_size()
            + self.challenge_closes_at.encode_size()
            + self.supersedes.encode_size()
            + self.metadata.encode_size()
    }
}

impl Read for CreateJob {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            artifact: GitArtifact::read(buf)?,
            claims: Read::read_cfg(buf, &())?,
            resolution_policy: ResolutionPolicy::read(buf)?,
            validation_opens_at: u64::read(buf)?,
            validation_closes_at: u64::read(buf)?,
            reveal_closes_at: Option::<u64>::read(buf)?,
            challenge_closes_at: Option::<u64>::read(buf)?,
            supersedes: Option::<JobId>::read(buf)?,
            metadata: Read::read_cfg(buf, &())?,
        })
    }
}

impl Write for CloseJob {
    fn write(&self, buf: &mut impl BufMut) {
        self.job_id.write(buf);
    }
}

impl FixedSize for CloseJob {
    const SIZE: usize = <JobId as FixedSize>::SIZE;
}

impl Read for CloseJob {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(JobId::read(buf)?))
    }
}

impl Write for JobStatus {
    fn write(&self, buf: &mut impl BufMut) {
        (*self as u8).write(buf);
    }
}

impl FixedSize for JobStatus {
    const SIZE: usize = <u8 as FixedSize>::SIZE;
}

impl Read for JobStatus {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Open),
            1 => Ok(Self::Resolved),
            2 => Ok(Self::Closed),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for JobRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.customer.write(buf);
        self.artifact.write(buf);
        self.claim_ids.write(buf);
        self.resolution_policy.write(buf);
        self.lifecycle.write(buf);
        self.supersedes.write(buf);
        self.metadata.write(buf);
        self.status.write(buf);
    }
}

impl EncodeSize for JobRecord {
    fn encode_size(&self) -> usize {
        self.customer.encode_size()
            + self.artifact.encode_size()
            + self.claim_ids.encode_size()
            + self.resolution_policy.encode_size()
            + self.lifecycle.encode_size()
            + self.supersedes.encode_size()
            + self.metadata.encode_size()
            + self.status.encode_size()
    }
}

impl Read for JobRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            customer: ActorId::read(buf)?,
            artifact: GitArtifact::read(buf)?,
            claim_ids: Read::read_cfg(buf, &())?,
            resolution_policy: ResolutionPolicy::read(buf)?,
            lifecycle: JobLifecycle::read(buf)?,
            supersedes: Option::<JobId>::read(buf)?,
            metadata: Read::read_cfg(buf, &())?,
            status: JobStatus::read(buf)?,
        })
    }
}

impl Write for ClaimResolution {
    fn write(&self, buf: &mut impl BufMut) {
        self.verdict.write(buf);
        self.evidence_ids.write(buf);
        self.resolution_reference.write(buf);
    }
}

impl EncodeSize for ClaimResolution {
    fn encode_size(&self) -> usize {
        self.verdict.encode_size()
            + self.evidence_ids.encode_size()
            + self.resolution_reference.encode_size()
    }
}

impl Read for ClaimResolution {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            verdict: ResolutionVerdict::read(buf)?,
            evidence_ids: Read::read_cfg(buf, &())?,
            resolution_reference: ContentRef::read(buf)?,
        })
    }
}

impl Write for ClaimStatus {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Open => 0_u8.write(buf),
            Self::Resolved(resolution) => {
                1_u8.write(buf);
                resolution.write(buf);
            }
        }
    }
}

impl EncodeSize for ClaimStatus {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Open => 0,
            Self::Resolved(resolution) => resolution.encode_size(),
        }
    }
}

impl Read for ClaimStatus {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Open),
            1 => Ok(Self::Resolved(ClaimResolution::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for ClaimRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.job_id.write(buf);
        self.definition.write(buf);
        self.status.write(buf);
    }
}

impl EncodeSize for ClaimRecord {
    fn encode_size(&self) -> usize {
        self.job_id.encode_size() + self.definition.encode_size() + self.status.encode_size()
    }
}

impl Read for ClaimRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            job_id: JobId::read(buf)?,
            definition: ClaimDefinition::read(buf)?,
            status: ClaimStatus::read(buf)?,
        })
    }
}

impl Write for ChallengeStatus {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Open => 0_u8.write(buf),
            Self::Resolved {
                upheld,
                evidence_ids,
                resolution_reference,
            } => {
                1_u8.write(buf);
                upheld.write(buf);
                evidence_ids.write(buf);
                resolution_reference.write(buf);
            }
        }
    }
}

impl EncodeSize for ChallengeStatus {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Open => 0,
            Self::Resolved {
                upheld,
                evidence_ids,
                resolution_reference,
            } => {
                upheld.encode_size()
                    + evidence_ids.encode_size()
                    + resolution_reference.encode_size()
            }
        }
    }
}

impl Read for ChallengeStatus {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Open),
            1 => Ok(Self::Resolved {
                upheld: bool::read(buf)?,
                evidence_ids: Read::read_cfg(buf, &())?,
                resolution_reference: ContentRef::read(buf)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for ChallengeRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.challenger.write(buf);
        self.job_id.write(buf);
        self.claim_id.write(buf);
        self.target.write(buf);
        self.counterclaim.write(buf);
        self.evidence_ids.write(buf);
        self.status.write(buf);
    }
}

impl EncodeSize for ChallengeRecord {
    fn encode_size(&self) -> usize {
        self.challenger.encode_size()
            + self.job_id.encode_size()
            + self.claim_id.encode_size()
            + self.target.encode_size()
            + self.counterclaim.encode_size()
            + self.evidence_ids.encode_size()
            + self.status.encode_size()
    }
}

impl Read for ChallengeRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            challenger: ActorId::read(buf)?,
            job_id: JobId::read(buf)?,
            claim_id: ClaimId::read(buf)?,
            target: ChallengeTarget::read(buf)?,
            counterclaim: Read::read_cfg(buf, &())?,
            evidence_ids: Read::read_cfg(buf, &())?,
            status: ChallengeStatus::read(buf)?,
        })
    }
}

impl Write for CommitmentStatus {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Pending => 0_u8.write(buf),
            Self::Revealed { payload, salt } => {
                1_u8.write(buf);
                payload.write(buf);
                salt.write(buf);
            }
            Self::Expired => 2_u8.write(buf),
        }
    }
}

impl EncodeSize for CommitmentStatus {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Pending | Self::Expired => 0,
            Self::Revealed { payload, salt } => payload.encode_size() + salt.encode_size(),
        }
    }
}

impl Read for CommitmentStatus {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Revealed {
                payload: Read::read_cfg(buf, &())?,
                salt: Read::read_cfg(buf, &())?,
            }),
            2 => Ok(Self::Expired),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for CommitmentRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.creator.write(buf);
        self.subject.write(buf);
        self.digest.write(buf);
        self.reveal_after_height.write(buf);
        self.reveal_before_height.write(buf);
        self.status.write(buf);
    }
}

impl EncodeSize for CommitmentRecord {
    fn encode_size(&self) -> usize {
        self.creator.encode_size()
            + self.subject.encode_size()
            + self.digest.encode_size()
            + self.reveal_after_height.encode_size()
            + self.reveal_before_height.encode_size()
            + self.status.encode_size()
    }
}

impl Read for CommitmentRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            creator: ActorId::read(buf)?,
            subject: CommitmentSubject::read(buf)?,
            digest: Sha256Digest::read(buf)?,
            reveal_after_height: u64::read(buf)?,
            reveal_before_height: u64::read(buf)?,
            status: CommitmentStatus::read(buf)?,
        })
    }
}

impl Write for EvidenceRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.producer.write(buf);
        self.job_id.write(buf);
        self.claim_id.write(buf);
        self.evidence.write(buf);
        self.manifest_digest.write(buf);
    }
}

impl EncodeSize for EvidenceRecord {
    fn encode_size(&self) -> usize {
        self.producer.encode_size()
            + self.job_id.encode_size()
            + self.claim_id.encode_size()
            + self.evidence.encode_size()
            + self.manifest_digest.encode_size()
    }
}

impl Read for EvidenceRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            producer: ActorId::read(buf)?,
            job_id: JobId::read(buf)?,
            claim_id: Option::<ClaimId>::read(buf)?,
            evidence: ContentRef::read(buf)?,
            manifest_digest: Sha256Digest::read(buf)?,
        })
    }
}

impl Write for AttestationRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.operator.write(buf);
        self.job_id.write(buf);
        self.claim_id.write(buf);
        self.verdict.write(buf);
        self.confidence_basis_points.write(buf);
        self.evidence_ids.write(buf);
    }
}

impl EncodeSize for AttestationRecord {
    fn encode_size(&self) -> usize {
        self.operator.encode_size()
            + self.job_id.encode_size()
            + self.claim_id.encode_size()
            + self.verdict.encode_size()
            + self.confidence_basis_points.encode_size()
            + self.evidence_ids.encode_size()
    }
}

impl Read for AttestationRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            operator: ActorId::read(buf)?,
            job_id: JobId::read(buf)?,
            claim_id: ClaimId::read(buf)?,
            verdict: Verdict::read(buf)?,
            confidence_basis_points: u16::read(buf)?,
            evidence_ids: Read::read_cfg(buf, &())?,
        })
    }
}

impl Write for ConsensusNodeId {
    fn write(&self, buf: &mut impl BufMut) {
        self.public_key().write(buf);
    }
}

impl FixedSize for ConsensusNodeId {
    const SIZE: usize = <Ed25519PublicKey as FixedSize>::SIZE;
}

impl Read for ConsensusNodeId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::from(Ed25519PublicKey::read(buf)?))
    }
}

impl Write for ConsensusContext {
    fn write(&self, buf: &mut impl BufMut) {
        self.consensus_epoch.write(buf);
        self.view.write(buf);
        self.leader.write(buf);
        self.parent_view.write(buf);
        self.parent_block.write(buf);
    }
}

impl FixedSize for ConsensusContext {
    const SIZE: usize =
        <u64 as FixedSize>::SIZE * 3 + ConsensusNodeId::SIZE + <Sha256Digest as FixedSize>::SIZE;
}

impl Read for ConsensusContext {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            consensus_epoch: u64::read(buf)?,
            view: u64::read(buf)?,
            leader: ConsensusNodeId::read(buf)?,
            parent_view: u64::read(buf)?,
            parent_block: Sha256Digest::read(buf)?,
        })
    }
}

impl Write for BlockHeader {
    fn write(&self, buf: &mut impl BufMut) {
        self.protocol_version.write(buf);
        self.chain_id.write(buf);
        self.height.write(buf);
        self.epoch.write(buf);
        self.parent_block.write(buf);
        self.parent_state_root.write(buf);
        self.action_root.write(buf);
        self.receipt_root.write(buf);
        self.post_state_root.write(buf);
        self.mechanism_set_id.write(buf);
        self.timestamp_ms.write(buf);
    }
}

impl FixedSize for BlockHeader {
    const SIZE: usize = ProtocolVersion::SIZE
        + ChainId::SIZE
        + <u64 as FixedSize>::SIZE * 3
        + <Sha256Digest as FixedSize>::SIZE * 5
        + MechanismSetId::SIZE;
}

impl Read for BlockHeader {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            protocol_version: ProtocolVersion::read(buf)?,
            chain_id: ChainId::read(buf)?,
            height: u64::read(buf)?,
            epoch: u64::read(buf)?,
            parent_block: Sha256Digest::read(buf)?,
            parent_state_root: Sha256Digest::read(buf)?,
            action_root: Sha256Digest::read(buf)?,
            receipt_root: Sha256Digest::read(buf)?,
            post_state_root: Sha256Digest::read(buf)?,
            mechanism_set_id: MechanismSetId::read(buf)?,
            timestamp_ms: u64::read(buf)?,
        })
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.header.write(buf);
        self.actions.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size() + self.header.encode_size() + self.actions.encode_size()
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let context = ConsensusContext::read(buf)?;
        let header = BlockHeader::read(buf)?;

        // Decode the complete variable-length body through a limited view. This
        // prevents a packet containing many individually valid large actions from
        // allocating beyond the canonical body maximum before the post-decode
        // constructor can inspect its encoded size. `Take<&mut Buf>` advances the
        // caller's buffer while exposing at most the remaining body budget.
        let mut body = buf.take(MAX_BLOCK_BODY_BYTES);
        let actions =
            <crate::bounded::BoundedVec<SignedAction<Action>, MAX_ACTIONS_PER_BLOCK>>::read_cfg(
                &mut body,
                &(),
            )?;
        Block::from_bounded_actions(context, header, actions).map_err(|error| match error {
            BlockValidationError::BlockBodyTooLarge { actual, .. } => {
                CodecError::InvalidLength(actual)
            }
            BlockValidationError::ActionCount(error) => CodecError::InvalidLength(error.actual()),
            _ => CodecError::Wrapped("Block", Box::new(error)),
        })
    }
}

impl Write for Action {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::CreateJob(action) => {
                0_u8.write(buf);
                action.write(buf);
            }
            Self::RegisterEvidence(action) => {
                1_u8.write(buf);
                action.write(buf);
            }
            Self::SubmitAttestation(action) => {
                2_u8.write(buf);
                action.write(buf);
            }
            Self::CreateCommitment(action) => {
                3_u8.write(buf);
                action.write(buf);
            }
            Self::RevealCommitment(action) => {
                4_u8.write(buf);
                action.write(buf);
            }
            Self::CreateChallenge(action) => {
                5_u8.write(buf);
                action.write(buf);
            }
            Self::ResolveClaim(action) => {
                6_u8.write(buf);
                action.write(buf);
            }
            Self::ResolveChallenge(action) => {
                7_u8.write(buf);
                action.write(buf);
            }
            Self::CloseJob(action) => {
                8_u8.write(buf);
                action.write(buf);
            }
        }
    }
}

impl EncodeSize for Action {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::CreateJob(action) => action.encode_size(),
            Self::RegisterEvidence(action) => action.encode_size(),
            Self::SubmitAttestation(action) => action.encode_size(),
            Self::CreateCommitment(action) => action.encode_size(),
            Self::RevealCommitment(action) => action.encode_size(),
            Self::CreateChallenge(action) => action.encode_size(),
            Self::ResolveClaim(action) => action.encode_size(),
            Self::ResolveChallenge(action) => action.encode_size(),
            Self::CloseJob(action) => action.encode_size(),
        }
    }
}

impl Read for Action {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::CreateJob(Box::new(CreateJob::read(buf)?))),
            1 => Ok(Self::RegisterEvidence(RegisterEvidence::read(buf)?)),
            2 => Ok(Self::SubmitAttestation(SubmitAttestation::read(buf)?)),
            3 => Ok(Self::CreateCommitment(CreateCommitment::read(buf)?)),
            4 => Ok(Self::RevealCommitment(RevealCommitment::read(buf)?)),
            5 => Ok(Self::CreateChallenge(CreateChallenge::read(buf)?)),
            6 => Ok(Self::ResolveClaim(ResolveClaim::read(buf)?)),
            7 => Ok(Self::ResolveChallenge(ResolveChallenge::read(buf)?)),
            8 => Ok(Self::CloseJob(CloseJob::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for CanonicalEvent {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::JobCreated { job_id } => {
                0_u8.write(buf);
                job_id.write(buf);
            }
            Self::ClaimCreated { job_id, claim_id } => {
                1_u8.write(buf);
                job_id.write(buf);
                claim_id.write(buf);
            }
            Self::EvidenceRegistered { evidence_id } => {
                2_u8.write(buf);
                evidence_id.write(buf);
            }
            Self::AttestationSubmitted { attestation_id } => {
                3_u8.write(buf);
                attestation_id.write(buf);
            }
            Self::CommitmentCreated { commitment_id } => {
                4_u8.write(buf);
                commitment_id.write(buf);
            }
            Self::CommitmentRevealed { commitment_id } => {
                5_u8.write(buf);
                commitment_id.write(buf);
            }
            Self::CommitmentExpired { commitment_id } => {
                6_u8.write(buf);
                commitment_id.write(buf);
            }
            Self::ChallengeCreated { challenge_id } => {
                7_u8.write(buf);
                challenge_id.write(buf);
            }
            Self::ClaimResolved { claim_id, verdict } => {
                8_u8.write(buf);
                claim_id.write(buf);
                verdict.write(buf);
            }
            Self::ClaimReopened { claim_id } => {
                9_u8.write(buf);
                claim_id.write(buf);
            }
            Self::ChallengeResolved {
                challenge_id,
                upheld,
            } => {
                10_u8.write(buf);
                challenge_id.write(buf);
                upheld.write(buf);
            }
            Self::JobResolved { job_id } => {
                11_u8.write(buf);
                job_id.write(buf);
            }
            Self::JobClosed { job_id } => {
                12_u8.write(buf);
                job_id.write(buf);
            }
            Self::EpochChanged { previous, current } => {
                13_u8.write(buf);
                previous.write(buf);
                current.write(buf);
            }
        }
    }
}

impl EncodeSize for CanonicalEvent {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::JobCreated { job_id }
            | Self::JobResolved { job_id }
            | Self::JobClosed { job_id } => job_id.encode_size(),
            Self::ClaimCreated { job_id, claim_id } => {
                job_id.encode_size() + claim_id.encode_size()
            }
            Self::EvidenceRegistered { evidence_id } => evidence_id.encode_size(),
            Self::AttestationSubmitted { attestation_id } => attestation_id.encode_size(),
            Self::CommitmentCreated { commitment_id }
            | Self::CommitmentRevealed { commitment_id }
            | Self::CommitmentExpired { commitment_id } => commitment_id.encode_size(),
            Self::ChallengeCreated { challenge_id } => challenge_id.encode_size(),
            Self::ClaimResolved { claim_id, verdict } => {
                claim_id.encode_size() + verdict.encode_size()
            }
            Self::ClaimReopened { claim_id } => claim_id.encode_size(),
            Self::ChallengeResolved {
                challenge_id,
                upheld,
            } => challenge_id.encode_size() + upheld.encode_size(),
            Self::EpochChanged { previous, current } => {
                previous.encode_size() + current.encode_size()
            }
        }
    }
}

impl Read for CanonicalEvent {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::JobCreated {
                job_id: JobId::read(buf)?,
            }),
            1 => Ok(Self::ClaimCreated {
                job_id: JobId::read(buf)?,
                claim_id: ClaimId::read(buf)?,
            }),
            2 => Ok(Self::EvidenceRegistered {
                evidence_id: EvidenceId::read(buf)?,
            }),
            3 => Ok(Self::AttestationSubmitted {
                attestation_id: AttestationId::read(buf)?,
            }),
            4 => Ok(Self::CommitmentCreated {
                commitment_id: CommitmentId::read(buf)?,
            }),
            5 => Ok(Self::CommitmentRevealed {
                commitment_id: CommitmentId::read(buf)?,
            }),
            6 => Ok(Self::CommitmentExpired {
                commitment_id: CommitmentId::read(buf)?,
            }),
            7 => Ok(Self::ChallengeCreated {
                challenge_id: ChallengeId::read(buf)?,
            }),
            8 => Ok(Self::ClaimResolved {
                claim_id: ClaimId::read(buf)?,
                verdict: ResolutionVerdict::read(buf)?,
            }),
            9 => Ok(Self::ClaimReopened {
                claim_id: ClaimId::read(buf)?,
            }),
            10 => Ok(Self::ChallengeResolved {
                challenge_id: ChallengeId::read(buf)?,
                upheld: bool::read(buf)?,
            }),
            11 => Ok(Self::JobResolved {
                job_id: JobId::read(buf)?,
            }),
            12 => Ok(Self::JobClosed {
                job_id: JobId::read(buf)?,
            }),
            13 => Ok(Self::EpochChanged {
                previous: u64::read(buf)?,
                current: u64::read(buf)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for ActionReceipt {
    fn write(&self, buf: &mut impl BufMut) {
        self.action_id.write(buf);
        self.actor.write(buf);
        self.nonce.write(buf);
        self.events.write(buf);
    }
}

impl EncodeSize for ActionReceipt {
    fn encode_size(&self) -> usize {
        self.action_id.encode_size()
            + self.actor.encode_size()
            + self.nonce.encode_size()
            + self.events.encode_size()
    }
}

impl Read for ActionReceipt {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::from_bounded_events(
            ActionId::read(buf)?,
            ActorId::read(buf)?,
            u64::read(buf)?,
            Read::read_cfg(buf, &())?,
        ))
    }
}

impl<P: Write> Write for SignedAction<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.chain_id.write(buf);
        self.actor.write(buf);
        self.nonce.write(buf);
        self.valid_until_height.write(buf);
        self.payload.write(buf);
        self.signature.write(buf);
    }
}

impl<P: EncodeSize> EncodeSize for SignedAction<P> {
    fn encode_size(&self) -> usize {
        SIGNED_ACTION_FIXED_BYTES.saturating_add(self.payload.encode_size())
    }
}

impl<P: Read + EncodeSize> Read for SignedAction<P> {
    type Cfg = P::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let action = Self {
            version: ProtocolVersion::read(buf)?,
            chain_id: ChainId::read(buf)?,
            actor: ActorId::read(buf)?,
            nonce: u64::read(buf)?,
            valid_until_height: u64::read(buf)?,
            payload: P::read_cfg(buf, cfg)?,
            signature: Ed25519Signature::read(buf)?,
        };
        let encoded_size = action.encode_size();
        if encoded_size > MAX_ACTION_BYTES {
            return Err(CodecError::InvalidLength(encoded_size));
        }
        Ok(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bounded::{BoundedBytes, BoundedVec},
        limits::{
            MAX_COMMITMENT_PAYLOAD_BYTES, MAX_COMMITMENT_SALT_BYTES,
            MAX_CONTENT_LOCATOR_HINT_BYTES, MAX_EVIDENCE_IDS_PER_ACTION, MAX_MEDIA_TYPE_BYTES,
            MAX_REPOSITORY_LOCATOR_BYTES,
        },
    };
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519};
    use core::fmt::Debug;

    fn bounded<const MAX: usize>(bytes: &[u8]) -> BoundedBytes<MAX> {
        BoundedBytes::try_from(bytes).expect("test fixture is bounded")
    }

    fn sample_content() -> ContentRef {
        ContentRef::new(
            Sha256Digest::from([0x33; 32]),
            bounded(b"cas://spec"),
            bounded(b"application/toml"),
        )
    }

    fn sample_artifact() -> GitArtifact {
        GitArtifact::new(
            bounded(b"https://git.invalid/r.git"),
            GitHash::sha1([0x11; 20]),
            GitHash::sha256([0x22; 32]),
            sample_content(),
        )
    }

    fn sample_actor(seed: u64) -> ActorId {
        ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
    }

    fn sample_register_evidence() -> RegisterEvidence {
        RegisterEvidence {
            job_id: JobId::derive(b"job"),
            claim_id: Some(ClaimId::derive(b"claim")),
            evidence: sample_content(),
            manifest_digest: Sha256Digest::from([0x55; 32]),
        }
    }

    fn sample_create_job() -> CreateJob {
        CreateJob {
            artifact: sample_artifact(),
            claims: BoundedVec::new(vec![ClaimDefinition::new(bounded(b"tests pass"))]).unwrap(),
            resolution_policy: ResolutionPolicy::ExperimentAuthority {
                authority: sample_actor(15),
            },
            validation_opens_at: 10,
            validation_closes_at: 20,
            reveal_closes_at: Some(25),
            challenge_closes_at: Some(30),
            supersedes: Some(JobId::derive(b"predecessor")),
            metadata: bounded(b"metadata"),
        }
    }

    fn assert_codec<T>(value: T)
    where
        T: Encode + Read<Cfg = ()> + Eq + Debug,
    {
        let encoded = value.encode();
        assert_eq!(T::decode_cfg(encoded.clone(), &()).unwrap(), value);

        for length in 0..encoded.len() {
            assert!(
                T::decode_cfg(encoded.slice(..length), &()).is_err(),
                "{value:?} accepted truncation at byte {length}"
            );
        }

        let mut trailing = encoded.to_vec();
        trailing.push(0xff);
        assert!(matches!(
            T::decode_cfg(trailing.as_slice(), &()),
            Err(CodecError::ExtraData(1))
        ));
    }

    #[test]
    fn every_public_primitive_round_trips_and_rejects_truncation_and_trailing_data() {
        assert_codec(ProtocolVersion::V1);
        assert_codec(CodecVersion::new(7));
        assert_codec(ChainId::new([0x10; 32]));

        let actor = ActorId::from(ed25519::PrivateKey::from_seed(14).public_key());
        assert_codec(actor);

        assert_codec(JobId::from_digest(Sha256Digest::from([0x21; 32])));
        assert_codec(ClaimId::from_digest(Sha256Digest::from([0x22; 32])));
        assert_codec(AttestationId::from_digest(Sha256Digest::from([0x23; 32])));
        assert_codec(EvidenceId::from_digest(Sha256Digest::from([0x24; 32])));
        assert_codec(ChallengeId::from_digest(Sha256Digest::from([0x25; 32])));
        assert_codec(CommitmentId::from_digest(Sha256Digest::from([0x26; 32])));
        assert_codec(ActionId::from_digest(Sha256Digest::from([0x27; 32])));
        assert_codec(MechanismSetId::from_digest(Sha256Digest::from([0x28; 32])));
        assert_codec(ExperimentId::from_digest(Sha256Digest::from([0x29; 32])));

        for domain in [
            HashDomain::Action,
            HashDomain::Job,
            HashDomain::Claim,
            HashDomain::Attestation,
            HashDomain::Evidence,
            HashDomain::Challenge,
            HashDomain::Commitment,
            HashDomain::Block,
            HashDomain::State,
            HashDomain::MechanismSet,
            HashDomain::Experiment,
        ] {
            assert_codec(domain);
        }

        for mode in [
            RoundingMode::TowardZero,
            RoundingMode::AwayFromZero,
            RoundingMode::Floor,
            RoundingMode::Ceiling,
            RoundingMode::NearestTiesToEven,
        ] {
            assert_codec(mode);
        }
        assert_codec(BasisPoints::new(3_333).unwrap());
    }

    #[test]
    fn every_public_git_type_round_trips_and_rejects_truncation_and_trailing_data() {
        assert_codec(GitHash::sha1([0x51; 20]));
        assert_codec(GitHash::sha256([0x52; 32]));
        assert_codec(sample_content());
        assert_codec(sample_artifact());
        assert_codec(JobArtifact::new(sample_artifact(), None));
        assert_codec(JobArtifact::new(
            sample_artifact(),
            Some(JobId::from_digest(Sha256Digest::from([0x44; 32]))),
        ));
    }

    #[test]
    fn commitment_actions_and_state_round_trip_canonically() {
        let creator = sample_actor(18);
        let payload = bounded::<MAX_COMMITMENT_PAYLOAD_BYTES>(b"verdict");
        let salt = bounded::<MAX_COMMITMENT_SALT_BYTES>(b"salt");
        let create = CreateCommitment {
            subject: CommitmentSubject::Claim(ClaimId::derive(b"claim")),
            digest: crate::actions::reveal_digest(&payload, &salt),
            reveal_after_height: 20,
            reveal_before_height: 30,
        };
        let reveal = RevealCommitment {
            commitment_id: create.commitment_id(&creator),
            payload: payload.clone(),
            salt: salt.clone(),
        };

        assert_codec(CommitmentSubject::Job(JobId::derive(b"job")));
        assert_codec(create.clone());
        assert_codec(reveal);
        assert_codec(CommitmentStatus::Pending);
        assert_codec(CommitmentStatus::Revealed {
            payload: payload.clone(),
            salt: salt.clone(),
        });
        assert_codec(CommitmentStatus::Expired);
        assert_codec(CommitmentRecord {
            creator,
            subject: create.subject,
            digest: create.digest,
            reveal_after_height: create.reveal_after_height,
            reveal_before_height: create.reveal_before_height,
            status: CommitmentStatus::Revealed { payload, salt },
        });
    }

    #[test]
    fn job_evidence_attestation_actions_and_state_round_trip_canonically() {
        let create = sample_create_job();
        let job_id = create.job_id();
        let definition = create.claims.as_slice()[0].clone();
        let claim_id = ClaimId::derive(b"claim");

        let registration = sample_register_evidence();
        let evidence_id = registration.evidence_id();
        let operator = sample_actor(17);
        let attestation = SubmitAttestation {
            job_id,
            claim_id,
            verdict: Verdict::Indeterminate,
            confidence_basis_points: 7_500,
            evidence_ids: BoundedVec::new(vec![evidence_id]).unwrap(),
        };

        assert_codec(registration.clone());
        for verdict in [
            Verdict::Pass,
            Verdict::Fail,
            Verdict::Abstain,
            Verdict::Indeterminate,
        ] {
            assert_codec(verdict);
        }
        assert_codec(attestation.clone());
        assert_codec(EvidenceRecord::from_action(operator.clone(), &registration));
        assert_codec(AttestationRecord::from_action(operator, &attestation));
        assert_codec(definition.clone());
        assert_codec(create.resolution_policy.clone());
        assert_codec(ResolutionPolicy::DeterministicVerifier {
            verifier_id: Sha256Digest::from([0x77; 32]),
            verifier_spec: sample_content(),
        });
        assert_codec(create.lifecycle());
        assert_codec(create.clone());
        assert_codec(CloseJob::new(job_id));
        assert_codec(JobStatus::Open);
        assert_codec(JobStatus::Resolved);
        assert_codec(JobStatus::Closed);
        assert_codec(ClaimRecord {
            job_id,
            definition,
            status: ClaimStatus::Open,
        });
        assert_codec(JobRecord {
            customer: sample_actor(16),
            artifact: create.artifact.clone(),
            claim_ids: BoundedVec::new(vec![claim_id]).unwrap(),
            resolution_policy: create.resolution_policy.clone(),
            lifecycle: create.lifecycle(),
            supersedes: create.supersedes,
            metadata: create.metadata.clone(),
            status: JobStatus::Open,
        });
    }

    #[test]
    fn canonical_actions_events_and_receipts_round_trip_canonically() {
        let create_job = sample_create_job();
        let registration = sample_register_evidence();
        let actor = sample_actor(31);
        let commitment = CreateCommitment {
            subject: CommitmentSubject::Claim(ClaimId::derive(b"action-claim")),
            digest: Sha256Digest::from([0x61; 32]),
            reveal_after_height: 20,
            reveal_before_height: 30,
        };
        let reveal = RevealCommitment {
            commitment_id: commitment.commitment_id(&actor),
            payload: bounded(b"payload"),
            salt: bounded(b"salt"),
        };
        let challenge = CreateChallenge {
            target: ChallengeTarget::Claim(ClaimId::derive(b"action-claim")),
            counterclaim: bounded(b"counterclaim"),
            evidence_ids: BoundedVec::default(),
        };
        let resolve_claim = ResolveClaim {
            job_id: JobId::derive(b"action-job"),
            claim_id: ClaimId::derive(b"action-claim"),
            verdict: ResolutionVerdict::Fail,
            evidence_ids: BoundedVec::default(),
            resolution_reference: sample_content(),
        };
        let resolve_challenge = ResolveChallenge {
            challenge_id: challenge.challenge_id(&actor),
            upheld: true,
            evidence_ids: BoundedVec::default(),
            resolution_reference: sample_content(),
        };
        let attestation = SubmitAttestation {
            job_id: JobId::derive(b"action-job"),
            claim_id: ClaimId::derive(b"action-claim"),
            verdict: Verdict::Pass,
            confidence_basis_points: 9_000,
            evidence_ids: BoundedVec::default(),
        };

        for action in [
            Action::CreateJob(Box::new(create_job)),
            Action::RegisterEvidence(registration),
            Action::SubmitAttestation(attestation),
            Action::CreateCommitment(commitment),
            Action::RevealCommitment(reveal),
            Action::CreateChallenge(challenge),
            Action::ResolveClaim(resolve_claim),
            Action::ResolveChallenge(resolve_challenge),
            Action::CloseJob(CloseJob::new(JobId::derive(b"action-job"))),
        ] {
            assert_codec(action);
        }

        let job_id = JobId::derive(b"event-job");
        let claim_id = ClaimId::derive(b"event-claim");
        let evidence_id = EvidenceId::derive(b"event-evidence");
        let attestation_id = AttestationId::derive(b"event-attestation");
        let commitment_id = CommitmentId::derive(b"event-commitment");
        let challenge_id = ChallengeId::derive(b"event-challenge");
        let events = vec![
            CanonicalEvent::JobCreated { job_id },
            CanonicalEvent::ClaimCreated { job_id, claim_id },
            CanonicalEvent::EvidenceRegistered { evidence_id },
            CanonicalEvent::AttestationSubmitted { attestation_id },
            CanonicalEvent::CommitmentCreated { commitment_id },
            CanonicalEvent::CommitmentRevealed { commitment_id },
            CanonicalEvent::CommitmentExpired { commitment_id },
            CanonicalEvent::ChallengeCreated { challenge_id },
            CanonicalEvent::ClaimResolved {
                claim_id,
                verdict: ResolutionVerdict::Unresolved,
            },
            CanonicalEvent::ClaimReopened { claim_id },
            CanonicalEvent::ChallengeResolved {
                challenge_id,
                upheld: true,
            },
            CanonicalEvent::JobResolved { job_id },
            CanonicalEvent::JobClosed { job_id },
            CanonicalEvent::EpochChanged {
                previous: 11,
                current: 12,
            },
        ];
        for event in &events {
            assert_codec(*event);
        }

        let receipt = ActionReceipt::new(
            ActionId::from_digest(Sha256Digest::from([0xa1; 32])),
            actor,
            0x0102_0304_0506_0708,
            events,
        )
        .unwrap();
        assert_codec(receipt.clone());
        assert_eq!(receipt.events.len(), 14);

        let encoded = receipt.encode();
        let mut expected = vec![0xa1; 32];
        expected.extend_from_slice(receipt.actor.as_bytes());
        expected.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
        expected.push(14);
        for event in &receipt.events {
            event.write(&mut expected);
        }
        assert_eq!(encoded.as_ref(), expected);
        assert_eq!(ActionReceipt::decode_cfg(encoded, &()).unwrap(), receipt);
    }

    #[test]
    fn event_and_receipt_decoders_reject_invalid_tags_and_oversized_event_counts() {
        assert!(matches!(
            CanonicalEvent::decode_cfg([14_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(14))
        ));
        assert!(matches!(
            Action::decode_cfg([9_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(9))
        ));

        let mut oversized = vec![0_u8; 32 + 32 + 8];
        (crate::limits::MAX_EVENTS_PER_ACTION + 1).write(&mut oversized);
        assert!(matches!(
            ActionReceipt::decode_cfg(oversized.as_slice(), &()),
            Err(CodecError::InvalidLength(length))
                if length == crate::limits::MAX_EVENTS_PER_ACTION + 1
        ));
    }

    #[test]
    fn challenge_and_resolution_actions_and_state_round_trip_canonically() {
        let challenger = sample_actor(30);
        let job_id = JobId::derive(b"resolved-job");
        let claim_id = ClaimId::derive(b"resolved-claim");
        let evidence_id = EvidenceId::derive(b"resolution-evidence");
        let evidence_ids = BoundedVec::new(vec![evidence_id]).unwrap();
        let create = CreateChallenge {
            target: ChallengeTarget::Claim(claim_id),
            counterclaim: bounded(b"counterexample"),
            evidence_ids: evidence_ids.clone(),
        };
        let challenge_id = create.challenge_id(&challenger);
        let resolution = ClaimResolution {
            verdict: ResolutionVerdict::Fail,
            evidence_ids: evidence_ids.clone(),
            resolution_reference: sample_content(),
        };

        assert_codec(ChallengeTarget::Claim(claim_id));
        assert_codec(ChallengeTarget::Attestation(AttestationId::derive(
            b"attestation",
        )));
        assert_codec(create.clone());
        for verdict in [
            ResolutionVerdict::Pass,
            ResolutionVerdict::Fail,
            ResolutionVerdict::Unresolved,
        ] {
            assert_codec(verdict);
        }
        assert_codec(ResolveClaim {
            job_id,
            claim_id,
            verdict: ResolutionVerdict::Fail,
            evidence_ids: evidence_ids.clone(),
            resolution_reference: sample_content(),
        });
        assert_codec(ResolveChallenge {
            challenge_id,
            upheld: true,
            evidence_ids: evidence_ids.clone(),
            resolution_reference: sample_content(),
        });
        assert_codec(ClaimStatus::Open);
        assert_codec(ClaimStatus::Resolved(resolution.clone()));
        assert_codec(resolution);
        assert_codec(ChallengeStatus::Open);
        assert_codec(ChallengeStatus::Resolved {
            upheld: false,
            evidence_ids: evidence_ids.clone(),
            resolution_reference: sample_content(),
        });
        assert_codec(ChallengeRecord::from_action(
            challenger, job_id, claim_id, &create,
        ));
    }

    #[test]
    fn enum_discriminants_and_fixed_width_vectors_are_stable() {
        assert_eq!(ProtocolVersion::V1.encode().as_ref(), [0x00, 0x01]);
        assert_eq!(CodecVersion::new(0x1234).encode().as_ref(), [0x12, 0x34]);
        assert_eq!(ChainId::new([0x5a; 32]).encode().as_ref(), [0x5a; 32]);
        assert_eq!(
            JobId::from_digest(Sha256Digest::from([0x6b; 32]))
                .encode()
                .as_ref(),
            [0x6b; 32]
        );
        assert_eq!(BasisPoints::FULL.encode().as_ref(), [0x27, 0x10]);

        for (domain, tag) in [
            (HashDomain::Action, 0),
            (HashDomain::Job, 1),
            (HashDomain::Claim, 2),
            (HashDomain::Attestation, 3),
            (HashDomain::Evidence, 4),
            (HashDomain::Challenge, 5),
            (HashDomain::Commitment, 6),
            (HashDomain::Block, 7),
            (HashDomain::State, 8),
            (HashDomain::MechanismSet, 9),
            (HashDomain::Experiment, 10),
        ] {
            assert_eq!(domain.encode().as_ref(), [tag]);
        }

        for (mode, tag) in [
            (RoundingMode::TowardZero, 0),
            (RoundingMode::AwayFromZero, 1),
            (RoundingMode::Floor, 2),
            (RoundingMode::Ceiling, 3),
            (RoundingMode::NearestTiesToEven, 4),
        ] {
            assert_eq!(mode.encode().as_ref(), [tag]);
        }

        assert_eq!(
            GitHash::sha1([0x11; 20]).encode().as_ref(),
            [&[0_u8][..], &[0x11; 20]].concat()
        );
        assert_eq!(
            GitHash::sha256([0x22; 32]).encode().as_ref(),
            [&[1_u8][..], &[0x22; 32]].concat()
        );
    }

    #[test]
    fn composite_vector_and_sha256_conformance_hash_are_stable() {
        let encoded = JobArtifact::new(
            sample_artifact(),
            Some(JobId::from_digest(Sha256Digest::from([0x44; 32]))),
        )
        .encode();
        let expected = [
            &[25_u8][..],
            b"https://git.invalid/r.git",
            &[0_u8][..],
            &[0x11; 20],
            &[1_u8][..],
            &[0x22; 32],
            &[0x33; 32],
            &[10_u8][..],
            b"cas://spec",
            &[16_u8][..],
            b"application/toml",
            &[1_u8][..],
            &[0x44; 32],
        ]
        .concat();
        assert_eq!(encoded.as_ref(), expected);
        assert_eq!(
            Sha256::hash(&encoded),
            Sha256Digest::from([
                0x01, 0xc6, 0x6f, 0xc5, 0x36, 0x55, 0x23, 0x0a, 0xd1, 0x13, 0x19, 0x3f, 0xa6, 0xe4,
                0x52, 0xb0, 0x80, 0xf1, 0xdf, 0x58, 0xe2, 0xdd, 0x2b, 0x8c, 0x66, 0xd0, 0xce, 0xd0,
                0x1e, 0x4e, 0xd4, 0x7b,
            ])
        );
    }

    #[test]
    fn invalid_enum_and_semantic_values_are_rejected() {
        assert!(matches!(
            HashDomain::decode_cfg([11_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(11))
        ));
        assert!(matches!(
            RoundingMode::decode_cfg([5_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(5))
        ));
        assert!(matches!(
            GitHash::decode_cfg([2_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(2))
        ));
        assert!(matches!(
            ResolutionPolicy::decode_cfg([2_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(2))
        ));
        assert!(matches!(
            JobStatus::decode_cfg([3_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(3))
        ));
        assert!(matches!(
            Verdict::decode_cfg([4_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(4))
        ));
        assert!(matches!(
            ResolutionVerdict::decode_cfg([3_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(3))
        ));
        assert!(matches!(
            ChallengeTarget::decode_cfg([2_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(2))
        ));
        assert!(matches!(
            ClaimStatus::decode_cfg([2_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(2))
        ));
        assert!(matches!(
            ChallengeStatus::decode_cfg([2_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(2))
        ));
        assert!(matches!(
            CommitmentSubject::decode_cfg([2_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(2))
        ));
        assert!(matches!(
            CommitmentStatus::decode_cfg([3_u8].as_slice(), &()),
            Err(CodecError::InvalidEnum(3))
        ));
        assert!(matches!(
            BasisPoints::decode_cfg(10_001_u16.to_be_bytes().as_slice(), &()),
            Err(CodecError::Wrapped("BasisPoints", _))
        ));
        let mut malformed_option = JobArtifact::new(sample_artifact(), None).encode().to_vec();
        *malformed_option.last_mut().unwrap() = 2;
        assert!(matches!(
            JobArtifact::decode_cfg(malformed_option.as_slice(), &()),
            Err(CodecError::InvalidBool)
        ));
    }

    #[test]
    fn malformed_and_oversized_nested_lengths_are_rejected_before_payload_decode() {
        assert!(matches!(
            GitArtifact::decode_cfg([0x80, 0x80, 0x80, 0x80, 0x80].as_slice(), &()),
            Err(CodecError::InvalidVarint(_) | CodecError::InvalidUsize)
        ));

        let mut oversized_repository = Vec::new();
        (MAX_REPOSITORY_LOCATOR_BYTES + 1).write(&mut oversized_repository);
        assert!(matches!(
            GitArtifact::decode_cfg(oversized_repository.as_slice(), &()),
            Err(CodecError::InvalidLength(length))
                if length == MAX_REPOSITORY_LOCATOR_BYTES + 1
        ));

        let mut oversized_locator = vec![0x33; 32];
        (MAX_CONTENT_LOCATOR_HINT_BYTES + 1).write(&mut oversized_locator);
        assert!(matches!(
            ContentRef::decode_cfg(oversized_locator.as_slice(), &()),
            Err(CodecError::InvalidLength(length))
                if length == MAX_CONTENT_LOCATOR_HINT_BYTES + 1
        ));

        let mut oversized_media_type = vec![0x33; 32];
        0_usize.write(&mut oversized_media_type);
        (MAX_MEDIA_TYPE_BYTES + 1).write(&mut oversized_media_type);
        assert!(matches!(
            ContentRef::decode_cfg(oversized_media_type.as_slice(), &()),
            Err(CodecError::InvalidLength(length)) if length == MAX_MEDIA_TYPE_BYTES + 1
        ));

        let mut oversized_commitment_payload = Vec::new();
        CommitmentId::derive(b"commitment").write(&mut oversized_commitment_payload);
        (MAX_COMMITMENT_PAYLOAD_BYTES + 1).write(&mut oversized_commitment_payload);
        assert!(matches!(
            RevealCommitment::decode_cfg(oversized_commitment_payload.as_slice(), &()),
            Err(CodecError::InvalidLength(length)) if length == MAX_COMMITMENT_PAYLOAD_BYTES + 1
        ));

        let mut oversized_commitment_salt = Vec::new();
        CommitmentId::derive(b"commitment").write(&mut oversized_commitment_salt);
        0_usize.write(&mut oversized_commitment_salt);
        (MAX_COMMITMENT_SALT_BYTES + 1).write(&mut oversized_commitment_salt);
        assert!(matches!(
            RevealCommitment::decode_cfg(oversized_commitment_salt.as_slice(), &()),
            Err(CodecError::InvalidLength(length)) if length == MAX_COMMITMENT_SALT_BYTES + 1
        ));

        let mut oversized_evidence_ids = Vec::new();
        JobId::derive(b"job").write(&mut oversized_evidence_ids);
        ClaimId::derive(b"claim").write(&mut oversized_evidence_ids);
        Verdict::Pass.write(&mut oversized_evidence_ids);
        10_000_u16.write(&mut oversized_evidence_ids);
        (MAX_EVIDENCE_IDS_PER_ACTION + 1).write(&mut oversized_evidence_ids);
        assert!(matches!(
            SubmitAttestation::decode_cfg(oversized_evidence_ids.as_slice(), &()),
            Err(CodecError::InvalidLength(length)) if length == MAX_EVIDENCE_IDS_PER_ACTION + 1
        ));
    }
}
