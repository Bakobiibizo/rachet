//! Canonical commitment creation and reveal payloads.

use crate::{
    bounded::BoundedBytes,
    limits::{MAX_COMMITMENT_PAYLOAD_BYTES, MAX_COMMITMENT_SALT_BYTES},
    primitives::{ActorId, ClaimId, CommitmentId, HashDomain, JobId, Sha256Digest, hash_canonical},
};
use commonware_codec::Write as _;

/// The canonical object to which a generic commitment relates.
///
/// The subject supplies semantic context without making the core interpret the
/// committed payload. Claim identifiers already bind their containing job.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CommitmentSubject {
    /// A commitment concerning an entire validation job.
    Job(JobId) = 0,
    /// A commitment concerning one immutable claim.
    Claim(ClaimId) = 1,
}

/// Creates one immutable commitment with an inclusive reveal window.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CreateCommitment {
    pub subject: CommitmentSubject,
    pub digest: Sha256Digest,
    pub reveal_after_height: u64,
    pub reveal_before_height: u64,
}

impl CreateCommitment {
    /// Derives the commitment ID from its creator and complete creation payload.
    pub fn commitment_id(&self, creator: &ActorId) -> CommitmentId {
        let mut identity = Vec::new();
        creator.write(&mut identity);
        self.write(&mut identity);
        CommitmentId::derive(&identity)
    }
}

/// Reveals the bounded payload and salt of an existing commitment.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RevealCommitment {
    pub commitment_id: CommitmentId,
    pub payload: BoundedBytes<MAX_COMMITMENT_PAYLOAD_BYTES>,
    pub salt: BoundedBytes<MAX_COMMITMENT_SALT_BYTES>,
}

impl RevealCommitment {
    /// Returns the domain-separated digest committed to by this reveal.
    pub fn digest(&self) -> Sha256Digest {
        reveal_digest(&self.payload, &self.salt)
    }
}

/// Computes the canonical commitment digest for a payload and salt.
///
/// Both bounded byte strings retain their canonical length framing in the
/// preimage, so different payload/salt splits cannot reveal the same bytes.
pub fn reveal_digest(
    payload: &BoundedBytes<MAX_COMMITMENT_PAYLOAD_BYTES>,
    salt: &BoundedBytes<MAX_COMMITMENT_SALT_BYTES>,
) -> Sha256Digest {
    let mut preimage = Vec::new();
    payload.write(&mut preimage);
    salt.write(&mut preimage);
    hash_canonical(HashDomain::Commitment, &preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(value: &[u8]) -> BoundedBytes<MAX_COMMITMENT_PAYLOAD_BYTES> {
        BoundedBytes::try_from(value).unwrap()
    }

    fn salt(value: &[u8]) -> BoundedBytes<MAX_COMMITMENT_SALT_BYTES> {
        BoundedBytes::try_from(value).unwrap()
    }

    #[test]
    fn reveal_digest_has_a_stable_domain_separated_vector() {
        assert_eq!(
            reveal_digest(&payload(b"canonical verdict"), &salt(b"private salt")).as_ref(),
            [
                0x0a, 0x52, 0xcb, 0xd0, 0xe9, 0xe5, 0x44, 0xe5, 0x61, 0x4c, 0xda, 0xa7, 0x64, 0xc0,
                0x90, 0xeb, 0x46, 0xf3, 0x3c, 0xe6, 0x3c, 0xe8, 0x29, 0xe5, 0xb7, 0x25, 0x20, 0xe3,
                0x57, 0x24, 0xb0, 0x58,
            ]
        );
    }

    #[test]
    fn reveal_digest_frames_payload_and_salt_boundaries() {
        assert_ne!(
            reveal_digest(&payload(b"ab"), &salt(b"c")),
            reveal_digest(&payload(b"a"), &salt(b"bc"))
        );
    }
}
