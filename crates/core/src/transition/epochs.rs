//! Transactional height-derived epoch and commitment-expiry events.

use super::{CommitmentTransitionError, expire_commitments};
use crate::{
    events::CanonicalEvent,
    state::{StateBatch, StateBatchError, StateKey},
};
use core::fmt;

/// Applies system transitions evaluated once at the start of a block height.
///
/// A changed epoch is emitted first because the new height context is active
/// before height-based expirations are evaluated. Expiration events then follow
/// in ascending commitment-ID order. The whole operation is transactional.
pub fn execute_height_events(
    state: &mut dyn StateBatch,
    height: u64,
    previous_epoch: u64,
    current_epoch: u64,
) -> Result<Vec<CanonicalEvent>, HeightEventError> {
    state.fork();
    let execution = execute_height_events_in_fork(state, height, previous_epoch, current_epoch);
    match execution {
        Ok(events) => {
            state.commit().map_err(HeightEventError::State)?;
            Ok(events)
        }
        Err(error) => {
            state.rollback().map_err(HeightEventError::State)?;
            Err(error)
        }
    }
}

fn execute_height_events_in_fork(
    state: &mut dyn StateBatch,
    height: u64,
    previous_epoch: u64,
    current_epoch: u64,
) -> Result<Vec<CanonicalEvent>, HeightEventError> {
    if current_epoch < previous_epoch {
        return Err(HeightEventError::EpochRegression {
            previous: previous_epoch,
            current: current_epoch,
        });
    }
    validate_stored_epoch(state, previous_epoch)?;

    let mut events = Vec::new();
    if current_epoch != previous_epoch {
        state.put(
            StateKey::protocol_epoch(),
            Box::new(current_epoch.to_be_bytes()),
        );
        events.push(CanonicalEvent::EpochChanged {
            previous: previous_epoch,
            current: current_epoch,
        });
    } else if state.get(&StateKey::protocol_epoch()).is_none() {
        state.put(
            StateKey::protocol_epoch(),
            Box::new(current_epoch.to_be_bytes()),
        );
    }

    events.extend(expire_commitments(state, height).map_err(HeightEventError::Commitment)?);
    Ok(events)
}

fn validate_stored_epoch(state: &dyn StateBatch, expected: u64) -> Result<(), HeightEventError> {
    let Some(value) = state.get(&StateKey::protocol_epoch()) else {
        if expected == 0 {
            return Ok(());
        }
        return Err(HeightEventError::StoredEpochMissing { expected });
    };
    let actual = value.len();
    let bytes: [u8; 8] = value
        .as_ref()
        .try_into()
        .map_err(|_| HeightEventError::StoredEpochMalformed { actual })?;
    let stored = u64::from_be_bytes(bytes);
    if stored != expected {
        return Err(HeightEventError::StoredEpochMismatch { expected, stored });
    }
    Ok(())
}

/// Stable failures from automatic height transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeightEventError {
    EpochRegression { previous: u64, current: u64 },
    StoredEpochMissing { expected: u64 },
    StoredEpochMalformed { actual: usize },
    StoredEpochMismatch { expected: u64, stored: u64 },
    Commitment(CommitmentTransitionError),
    State(StateBatchError),
}

impl HeightEventError {
    /// Returns the stable machine-readable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::EpochRegression { .. } => "EPOCH_REGRESSION",
            Self::StoredEpochMissing { .. } => "EPOCH_STATE_MISSING",
            Self::StoredEpochMalformed { .. } => "EPOCH_STATE_MALFORMED",
            Self::StoredEpochMismatch { .. } => "EPOCH_STATE_MISMATCH",
            Self::Commitment(error) => error.code(),
            Self::State(StateBatchError::NoOpenFork) => "STATE_TRANSACTION_INVALID",
        }
    }
}

impl fmt::Display for HeightEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for HeightEventError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{CommitmentSubject, CreateCommitment},
        primitives::{ActorId, ClaimId, CommitmentId, Sha256Digest},
        state::{InMemoryStateBatch, StateBatch},
        transition::{create_commitment, load_commitment},
    };
    use commonware_cryptography::{Signer as _, ed25519};

    fn actor() -> ActorId {
        ActorId::from(ed25519::PrivateKey::from_seed(30).public_key())
    }

    fn pending(state: &mut InMemoryStateBatch, byte: u8) -> CommitmentId {
        let action = CreateCommitment {
            subject: CommitmentSubject::Claim(ClaimId::from_digest(Sha256Digest::from([byte; 32]))),
            digest: Sha256Digest::from([byte; 32]),
            reveal_after_height: 10,
            reveal_before_height: 20,
        };
        let event = create_commitment(state, &actor(), 10, &action).unwrap();
        event.commitment_id().unwrap()
    }

    #[test]
    fn epoch_change_precedes_id_sorted_expirations_and_is_once_only() {
        let mut state = InMemoryStateBatch::new();
        let first = pending(&mut state, 1);
        let second = pending(&mut state, 2);
        let mut sorted = vec![first, second];
        sorted.sort_unstable();

        let events = execute_height_events(&mut state, 21, 0, 1).unwrap();
        let mut expected = vec![CanonicalEvent::EpochChanged {
            previous: 0,
            current: 1,
        }];
        expected.extend(
            sorted
                .iter()
                .copied()
                .map(|commitment_id| CanonicalEvent::CommitmentExpired { commitment_id }),
        );
        assert_eq!(events, expected);
        assert_eq!(
            state.get(&StateKey::protocol_epoch()).as_deref(),
            Some(1_u64.to_be_bytes().as_slice())
        );
        for commitment_id in sorted {
            assert!(matches!(
                load_commitment(&state, commitment_id).unwrap().status,
                crate::state::CommitmentStatus::Expired
            ));
        }
        assert!(
            execute_height_events(&mut state, 22, 1, 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn invalid_epoch_state_or_regression_rolls_back_all_height_effects() {
        let mut state = InMemoryStateBatch::new();
        let commitment_id = pending(&mut state, 3);
        let before = state.root();
        assert_eq!(
            execute_height_events(&mut state, 21, 1, 2),
            Err(HeightEventError::StoredEpochMissing { expected: 1 })
        );
        assert_eq!(state.root(), before);

        assert_eq!(
            execute_height_events(&mut state, 21, 2, 1),
            Err(HeightEventError::EpochRegression {
                previous: 2,
                current: 1
            })
        );
        assert_eq!(state.root(), before);
        assert!(matches!(
            load_commitment(&state, commitment_id).unwrap().status,
            crate::state::CommitmentStatus::Pending
        ));

        state.put(StateKey::protocol_epoch(), vec![0; 7].into_boxed_slice());
        let malformed = state.root();
        assert_eq!(
            execute_height_events(&mut state, 21, 0, 1),
            Err(HeightEventError::StoredEpochMalformed { actual: 7 })
        );
        assert_eq!(state.root(), malformed);
    }
}
