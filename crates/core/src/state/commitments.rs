//! Canonical commitment state records.

use crate::{
    actions::{CommitmentSubject, CreateCommitment},
    bounded::BoundedBytes,
    limits::{MAX_COMMITMENT_PAYLOAD_BYTES, MAX_COMMITMENT_SALT_BYTES},
    primitives::{ActorId, CommitmentId, Sha256Digest},
};
use commonware_codec::Write as _;

/// Mutable lifecycle state of an immutable commitment.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CommitmentStatus {
    /// The reveal window has not elapsed and no reveal was accepted.
    Pending = 0,
    /// The creator supplied a hash-matching reveal during the window.
    Revealed {
        payload: BoundedBytes<MAX_COMMITMENT_PAYLOAD_BYTES>,
        salt: BoundedBytes<MAX_COMMITMENT_SALT_BYTES>,
    } = 1,
    /// The inclusive reveal deadline elapsed without a reveal.
    Expired = 2,
}

/// Canonical state retained for one generic commitment.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommitmentRecord {
    pub creator: ActorId,
    pub subject: CommitmentSubject,
    pub digest: Sha256Digest,
    pub reveal_after_height: u64,
    pub reveal_before_height: u64,
    pub status: CommitmentStatus,
}

impl CommitmentRecord {
    /// Constructs a pending record from an accepted creation action.
    pub fn from_action(creator: ActorId, action: &CreateCommitment) -> Self {
        Self {
            creator,
            subject: action.subject,
            digest: action.digest,
            reveal_after_height: action.reveal_after_height,
            reveal_before_height: action.reveal_before_height,
            status: CommitmentStatus::Pending,
        }
    }

    /// Returns the identifier implied by the immutable creation fields.
    pub fn commitment_id(&self) -> CommitmentId {
        let action = CreateCommitment {
            subject: self.subject,
            digest: self.digest,
            reveal_after_height: self.reveal_after_height,
            reveal_before_height: self.reveal_before_height,
        };
        let mut identity = Vec::new();
        self.creator.write(&mut identity);
        action.write(&mut identity);
        CommitmentId::derive(&identity)
    }
}
