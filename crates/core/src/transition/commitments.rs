//! Pure commitment creation, reveal, and height-based expiry transitions.

use crate::{
    actions::{CreateCommitment, RevealCommitment},
    events::CanonicalEvent,
    primitives::{ActorId, CommitmentId},
    state::{CommitmentRecord, CommitmentStatus, StateBatch, StateKey, StateNamespace},
};
use commonware_codec::{Decode, Encode};
use core::fmt;

/// Creates a pending commitment and emits its canonical creation event.
pub fn create_commitment(
    state: &mut dyn StateBatch,
    actor: &ActorId,
    height: u64,
    action: &CreateCommitment,
) -> Result<CanonicalEvent, CommitmentTransitionError> {
    if action.reveal_before_height < action.reveal_after_height {
        return Err(CommitmentTransitionError::RevealWindowInvalid);
    }
    if action.reveal_after_height < height {
        return Err(CommitmentTransitionError::RevealAlreadyOpened {
            reveal_after_height: action.reveal_after_height,
            current_height: height,
        });
    }

    let commitment_id = action.commitment_id(actor);
    if state.get(&StateKey::commitment(&commitment_id)).is_some() {
        return Err(CommitmentTransitionError::CommitmentAlreadyExists);
    }

    let record = CommitmentRecord::from_action(actor.clone(), action);
    state.put(StateKey::commitment(&commitment_id), encoded(&record));
    Ok(CanonicalEvent::CommitmentCreated { commitment_id })
}

/// Accepts exactly one creator-authorized reveal during the inclusive window.
pub fn reveal_commitment(
    state: &mut dyn StateBatch,
    actor: &ActorId,
    height: u64,
    action: &RevealCommitment,
) -> Result<CanonicalEvent, CommitmentTransitionError> {
    let mut record = load_commitment(state, action.commitment_id)?;
    if record.creator != *actor {
        return Err(CommitmentTransitionError::NotCommitmentCreator);
    }
    match record.status {
        CommitmentStatus::Pending => {}
        CommitmentStatus::Revealed { .. } => {
            return Err(CommitmentTransitionError::CommitmentAlreadyRevealed);
        }
        CommitmentStatus::Expired => {
            return Err(CommitmentTransitionError::CommitmentAlreadyExpired);
        }
    }
    if height < record.reveal_after_height {
        return Err(CommitmentTransitionError::RevealTooEarly {
            reveal_after_height: record.reveal_after_height,
            current_height: height,
        });
    }
    if height > record.reveal_before_height {
        return Err(CommitmentTransitionError::RevealTooLate {
            reveal_before_height: record.reveal_before_height,
            current_height: height,
        });
    }
    if action.digest() != record.digest {
        return Err(CommitmentTransitionError::RevealDigestMismatch);
    }

    record.status = CommitmentStatus::Revealed {
        payload: action.payload.clone(),
        salt: action.salt.clone(),
    };
    state.put(
        StateKey::commitment(&action.commitment_id),
        encoded(&record),
    );
    Ok(CanonicalEvent::CommitmentRevealed {
        commitment_id: action.commitment_id,
    })
}

/// Expires every pending commitment whose inclusive deadline has elapsed.
///
/// Events and writes are ordered by commitment ID because state iteration is
/// lexicographic by typed binary key. The full namespace is validated before
/// any write, so malformed state cannot cause partial expiry.
pub fn expire_commitments(
    state: &mut dyn StateBatch,
    height: u64,
) -> Result<Vec<CanonicalEvent>, CommitmentTransitionError> {
    let mut expired = Vec::new();
    for (key, value) in state.entries() {
        if key.namespace() != StateNamespace::Commitment {
            continue;
        }
        let mut record = decode_record(value.as_ref())?;
        let commitment_id = record.commitment_id();
        if StateKey::commitment(&commitment_id) != key {
            return Err(CommitmentTransitionError::CommitmentIdentityMismatch);
        }
        if matches!(record.status, CommitmentStatus::Pending)
            && height > record.reveal_before_height
        {
            record.status = CommitmentStatus::Expired;
            expired.push((commitment_id, record));
        }
    }

    let mut events = Vec::with_capacity(expired.len());
    for (commitment_id, record) in expired {
        state.put(StateKey::commitment(&commitment_id), encoded(&record));
        events.push(CanonicalEvent::CommitmentExpired { commitment_id });
    }
    Ok(events)
}

/// Loads and identity-checks one canonical commitment record.
pub fn load_commitment(
    state: &dyn StateBatch,
    commitment_id: CommitmentId,
) -> Result<CommitmentRecord, CommitmentTransitionError> {
    let value = state
        .get(&StateKey::commitment(&commitment_id))
        .ok_or(CommitmentTransitionError::CommitmentNotFound)?;
    let record = decode_record(value.as_ref())?;
    if record.commitment_id() != commitment_id {
        return Err(CommitmentTransitionError::CommitmentIdentityMismatch);
    }
    Ok(record)
}

fn decode_record(bytes: &[u8]) -> Result<CommitmentRecord, CommitmentTransitionError> {
    let record = CommitmentRecord::decode_cfg(bytes, &())
        .map_err(|_| CommitmentTransitionError::CommitmentStateMalformed)?;
    if record.reveal_before_height < record.reveal_after_height {
        return Err(CommitmentTransitionError::CommitmentStateMalformed);
    }
    Ok(record)
}

fn encoded<T: Encode>(value: &T) -> Box<[u8]> {
    value.encode().to_vec().into_boxed_slice()
}

/// Stable failures produced by commitment transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitmentTransitionError {
    RevealWindowInvalid,
    RevealAlreadyOpened {
        reveal_after_height: u64,
        current_height: u64,
    },
    CommitmentAlreadyExists,
    CommitmentNotFound,
    CommitmentStateMalformed,
    CommitmentIdentityMismatch,
    NotCommitmentCreator,
    CommitmentAlreadyRevealed,
    CommitmentAlreadyExpired,
    RevealTooEarly {
        reveal_after_height: u64,
        current_height: u64,
    },
    RevealTooLate {
        reveal_before_height: u64,
        current_height: u64,
    },
    RevealDigestMismatch,
}

impl CommitmentTransitionError {
    /// Returns the stable machine-readable protocol error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::RevealWindowInvalid => "COMMITMENT_REVEAL_WINDOW_INVALID",
            Self::RevealAlreadyOpened { .. } => "COMMITMENT_REVEAL_ALREADY_OPENED",
            Self::CommitmentAlreadyExists => "COMMITMENT_ALREADY_EXISTS",
            Self::CommitmentNotFound => "COMMITMENT_NOT_FOUND",
            Self::CommitmentStateMalformed => "COMMITMENT_STATE_MALFORMED",
            Self::CommitmentIdentityMismatch => "COMMITMENT_IDENTITY_INVALID",
            Self::NotCommitmentCreator => "COMMITMENT_CREATOR_UNAUTHORIZED",
            Self::CommitmentAlreadyRevealed => "COMMITMENT_ALREADY_REVEALED",
            Self::CommitmentAlreadyExpired => "COMMITMENT_ALREADY_EXPIRED",
            Self::RevealTooEarly { .. } => "COMMITMENT_REVEAL_TOO_EARLY",
            Self::RevealTooLate { .. } => "COMMITMENT_REVEAL_TOO_LATE",
            Self::RevealDigestMismatch => "COMMITMENT_REVEAL_DIGEST_MISMATCH",
        }
    }
}

impl fmt::Display for CommitmentTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CommitmentTransitionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{CommitmentSubject, reveal_digest},
        bounded::BoundedBytes,
        limits::{MAX_COMMITMENT_PAYLOAD_BYTES, MAX_COMMITMENT_SALT_BYTES},
        primitives::{ActorId, ClaimId, JobId, Sha256Digest},
        state::InMemoryStateBatch,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{Signer as _, ed25519};

    fn actor(seed: u64) -> ActorId {
        ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
    }

    fn payload(value: &[u8]) -> BoundedBytes<MAX_COMMITMENT_PAYLOAD_BYTES> {
        BoundedBytes::try_from(value).unwrap()
    }

    fn salt(value: &[u8]) -> BoundedBytes<MAX_COMMITMENT_SALT_BYTES> {
        BoundedBytes::try_from(value).unwrap()
    }

    fn fixture(subject_byte: u8, after: u64, before: u64) -> (CreateCommitment, RevealCommitment) {
        let payload = payload(b"canonical verdict");
        let salt = salt(b"private salt");
        let create = CreateCommitment {
            subject: CommitmentSubject::Claim(ClaimId::from_digest(Sha256Digest::from(
                [subject_byte; 32],
            ))),
            digest: reveal_digest(&payload, &salt),
            reveal_after_height: after,
            reveal_before_height: before,
        };
        let reveal = RevealCommitment {
            commitment_id: CommitmentId::derive(b"replaced after creation"),
            payload,
            salt,
        };
        (create, reveal)
    }

    fn create_fixture(
        state: &mut InMemoryStateBatch,
        creator: &ActorId,
        subject_byte: u8,
        after: u64,
        before: u64,
    ) -> RevealCommitment {
        let (create, mut reveal) = fixture(subject_byte, after, before);
        let event = create_commitment(state, creator, 10, &create).unwrap();
        reveal.commitment_id = event.commitment_id().unwrap();
        reveal
    }

    #[test]
    fn correct_reveal_succeeds_once_and_preserves_payload_and_salt() {
        let creator = actor(1);
        let mut state = InMemoryStateBatch::new();
        let reveal = create_fixture(&mut state, &creator, 1, 12, 20);

        assert_eq!(
            reveal_commitment(&mut state, &creator, 12, &reveal),
            Ok(CanonicalEvent::CommitmentRevealed {
                commitment_id: reveal.commitment_id
            })
        );
        assert_eq!(
            load_commitment(&state, reveal.commitment_id)
                .unwrap()
                .status,
            CommitmentStatus::Revealed {
                payload: reveal.payload.clone(),
                salt: reveal.salt.clone(),
            }
        );

        let root = state.root();
        assert_eq!(
            reveal_commitment(&mut state, &creator, 13, &reveal),
            Err(CommitmentTransitionError::CommitmentAlreadyRevealed)
        );
        assert_eq!(state.root(), root);
    }

    #[test]
    fn reveal_window_is_inclusive_and_early_and_late_reveals_do_not_mutate() {
        for (subject, height) in [(2, 12), (3, 20)] {
            let creator = actor(u64::from(subject));
            let mut state = InMemoryStateBatch::new();
            let reveal = create_fixture(&mut state, &creator, subject, 12, 20);
            assert!(reveal_commitment(&mut state, &creator, height, &reveal).is_ok());
        }

        let creator = actor(4);
        let mut early = InMemoryStateBatch::new();
        let reveal = create_fixture(&mut early, &creator, 4, 12, 20);
        let root = early.root();
        assert_eq!(
            reveal_commitment(&mut early, &creator, 11, &reveal),
            Err(CommitmentTransitionError::RevealTooEarly {
                reveal_after_height: 12,
                current_height: 11,
            })
        );
        assert_eq!(early.root(), root);

        let mut late = InMemoryStateBatch::new();
        let reveal = create_fixture(&mut late, &creator, 5, 12, 20);
        let root = late.root();
        assert_eq!(
            reveal_commitment(&mut late, &creator, 21, &reveal),
            Err(CommitmentTransitionError::RevealTooLate {
                reveal_before_height: 20,
                current_height: 21,
            })
        );
        assert_eq!(late.root(), root);
    }

    #[test]
    fn hash_mismatch_wrong_creator_and_malformed_creation_are_rejected_atomically() {
        let creator = actor(5);
        let mut state = InMemoryStateBatch::new();
        let mut reveal = create_fixture(&mut state, &creator, 6, 12, 20);
        let root = state.root();

        reveal.payload = payload(b"changed verdict");
        assert_eq!(
            reveal_commitment(&mut state, &creator, 12, &reveal),
            Err(CommitmentTransitionError::RevealDigestMismatch)
        );
        assert_eq!(state.root(), root);
        assert_eq!(
            reveal_commitment(&mut state, &actor(6), 12, &reveal),
            Err(CommitmentTransitionError::NotCommitmentCreator)
        );
        assert_eq!(state.root(), root);

        let (mut malformed, _) = fixture(7, 12, 20);
        malformed.reveal_before_height = 11;
        assert_eq!(
            create_commitment(&mut state, &creator, 10, &malformed),
            Err(CommitmentTransitionError::RevealWindowInvalid)
        );
        malformed.reveal_before_height = 20;
        malformed.reveal_after_height = 9;
        assert_eq!(
            create_commitment(&mut state, &creator, 10, &malformed),
            Err(CommitmentTransitionError::RevealAlreadyOpened {
                reveal_after_height: 9,
                current_height: 10,
            })
        );
        assert_eq!(state.root(), root);
    }

    #[test]
    fn commitment_identity_binds_creator_subject_digest_and_window() {
        let creator = actor(7);
        let other = actor(8);
        let (base, _) = fixture(8, 12, 20);
        assert_eq!(base.commitment_id(&creator), base.commitment_id(&creator));
        assert_ne!(base.commitment_id(&creator), base.commitment_id(&other));

        let mut variants = Vec::new();
        let mut subject = base.clone();
        subject.subject = CommitmentSubject::Job(JobId::derive(b"job"));
        variants.push(subject);
        let mut digest = base.clone();
        digest.digest = Sha256Digest::from([9; 32]);
        variants.push(digest);
        let mut after = base.clone();
        after.reveal_after_height = 13;
        variants.push(after);
        let mut before = base.clone();
        before.reveal_before_height = 21;
        variants.push(before);
        for variant in variants {
            assert_ne!(
                base.commitment_id(&creator),
                variant.commitment_id(&creator)
            );
        }

        let mut state = InMemoryStateBatch::new();
        create_commitment(&mut state, &creator, 10, &base).unwrap();
        assert_eq!(
            create_commitment(&mut state, &creator, 10, &base),
            Err(CommitmentTransitionError::CommitmentAlreadyExists)
        );
    }

    #[test]
    fn expiry_is_once_only_after_deadline_and_sorted_by_commitment_id() {
        let creator = actor(9);
        let mut state = InMemoryStateBatch::new();
        let first = create_fixture(&mut state, &creator, 10, 12, 20);
        let second = create_fixture(&mut state, &creator, 11, 12, 20);
        let revealed = create_fixture(&mut state, &creator, 12, 12, 20);
        reveal_commitment(&mut state, &creator, 20, &revealed).unwrap();

        assert!(expire_commitments(&mut state, 20).unwrap().is_empty());
        let events = expire_commitments(&mut state, 21).unwrap();
        let expected_ids = {
            let mut ids = vec![first.commitment_id, second.commitment_id];
            ids.sort_unstable();
            ids
        };
        assert_eq!(
            events
                .iter()
                .copied()
                .filter_map(CanonicalEvent::commitment_id)
                .collect::<Vec<_>>(),
            expected_ids
        );
        for commitment_id in expected_ids {
            assert_eq!(
                load_commitment(&state, commitment_id).unwrap().status,
                CommitmentStatus::Expired
            );
        }
        assert!(expire_commitments(&mut state, 22).unwrap().is_empty());
        assert!(matches!(
            load_commitment(&state, revealed.commitment_id)
                .unwrap()
                .status,
            CommitmentStatus::Revealed { .. }
        ));
        assert_eq!(
            reveal_commitment(&mut state, &creator, 22, &first),
            Err(CommitmentTransitionError::CommitmentAlreadyExpired)
        );
    }

    #[test]
    fn expiry_validates_the_whole_namespace_before_writing() {
        let creator = actor(10);
        let mut state = InMemoryStateBatch::new();
        let valid = create_fixture(&mut state, &creator, 13, 12, 20);
        let (create, _) = fixture(14, 12, 20);
        let wrong_id = CommitmentId::derive(b"wrong state key");
        state.put(
            StateKey::commitment(&wrong_id),
            CommitmentRecord::from_action(creator, &create)
                .encode()
                .to_vec()
                .into_boxed_slice(),
        );
        let root = state.root();
        assert_eq!(
            expire_commitments(&mut state, 21),
            Err(CommitmentTransitionError::CommitmentIdentityMismatch)
        );
        assert_eq!(state.root(), root);
        assert_eq!(
            load_commitment(&state, valid.commitment_id).unwrap().status,
            CommitmentStatus::Pending
        );
    }
}
