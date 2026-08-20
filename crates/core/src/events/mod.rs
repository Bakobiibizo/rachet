//! Canonical transition events and per-action receipts.

use crate::{
    actions::ResolutionVerdict,
    bounded::{BoundedVec, LengthExceeded},
    limits::MAX_EVENTS_PER_ACTION,
    primitives::{
        ActionId, ActorId, AttestationId, ChallengeId, ClaimId, CommitmentId, EvidenceId, JobId,
    },
};

/// A deterministic, immutable output of a canonical state transition.
///
/// Discriminants are consensus bytes and follow specification section 14.
/// Event order inside a receipt is transition order; consumers must not sort
/// events by this discriminant or by object ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CanonicalEvent {
    JobCreated {
        job_id: JobId,
    } = 0,
    ClaimCreated {
        job_id: JobId,
        claim_id: ClaimId,
    } = 1,
    EvidenceRegistered {
        evidence_id: EvidenceId,
    } = 2,
    AttestationSubmitted {
        attestation_id: AttestationId,
    } = 3,
    CommitmentCreated {
        commitment_id: CommitmentId,
    } = 4,
    CommitmentRevealed {
        commitment_id: CommitmentId,
    } = 5,
    CommitmentExpired {
        commitment_id: CommitmentId,
    } = 6,
    ChallengeCreated {
        challenge_id: ChallengeId,
    } = 7,
    ClaimResolved {
        claim_id: ClaimId,
        verdict: ResolutionVerdict,
    } = 8,
    ClaimReopened {
        claim_id: ClaimId,
    } = 9,
    ChallengeResolved {
        challenge_id: ChallengeId,
        upheld: bool,
    } = 10,
    JobResolved {
        job_id: JobId,
    } = 11,
    JobClosed {
        job_id: JobId,
    } = 12,
    EpochChanged {
        previous: u64,
        current: u64,
    } = 13,
}

impl CanonicalEvent {
    /// Returns the affected commitment for commitment lifecycle events.
    pub const fn commitment_id(self) -> Option<CommitmentId> {
        match self {
            Self::CommitmentCreated { commitment_id }
            | Self::CommitmentRevealed { commitment_id }
            | Self::CommitmentExpired { commitment_id } => Some(commitment_id),
            _ => None,
        }
    }
}

/// The complete deterministic result of one accepted action.
///
/// Construction and decoding both enforce the genesis-committed v1 event
/// maximum. A failed action has no `ActionReceipt` value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActionReceipt {
    pub action_id: ActionId,
    pub actor: ActorId,
    pub nonce: u64,
    pub events: BoundedVec<CanonicalEvent, MAX_EVENTS_PER_ACTION>,
}

impl ActionReceipt {
    /// Constructs a receipt while enforcing the per-action event bound.
    pub fn new(
        action_id: ActionId,
        actor: ActorId,
        nonce: u64,
        events: Vec<CanonicalEvent>,
    ) -> Result<Self, LengthExceeded> {
        Ok(Self {
            action_id,
            actor,
            nonce,
            events: BoundedVec::new(events)?,
        })
    }

    /// Constructs a receipt from an already bounded event sequence.
    pub const fn from_bounded_events(
        action_id: ActionId,
        actor: ActorId,
        nonce: u64,
        events: BoundedVec<CanonicalEvent, MAX_EVENTS_PER_ACTION>,
    ) -> Self {
        Self {
            action_id,
            actor,
            nonce,
            events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};

    fn actor() -> ActorId {
        ActorId::from(ed25519::PrivateKey::from_seed(1).public_key())
    }

    #[test]
    fn receipt_construction_enforces_the_exact_event_boundary() {
        let event = CanonicalEvent::JobClosed {
            job_id: JobId::derive(b"job"),
        };
        let boundary = vec![event; MAX_EVENTS_PER_ACTION];
        assert_eq!(
            ActionReceipt::new(ActionId::derive(b"action"), actor(), 7, boundary)
                .unwrap()
                .events
                .len(),
            MAX_EVENTS_PER_ACTION
        );

        let error = ActionReceipt::new(
            ActionId::derive(b"oversized"),
            actor(),
            8,
            vec![event; MAX_EVENTS_PER_ACTION + 1],
        )
        .unwrap_err();
        assert_eq!(error.maximum(), MAX_EVENTS_PER_ACTION);
        assert_eq!(error.actual(), MAX_EVENTS_PER_ACTION + 1);
    }

    #[test]
    fn commitment_projection_is_defined_only_for_commitment_events() {
        let commitment_id = CommitmentId::derive(b"commitment");
        assert_eq!(
            CanonicalEvent::CommitmentExpired { commitment_id }.commitment_id(),
            Some(commitment_id)
        );
        assert_eq!(
            CanonicalEvent::JobClosed {
                job_id: JobId::derive(b"job")
            }
            .commitment_id(),
            None
        );
    }
}
