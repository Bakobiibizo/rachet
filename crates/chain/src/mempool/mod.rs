//! Bounded, concurrency-safe pending-action management.
//!
//! Stateless envelope verification belongs to ingress and is repeated by consensus.
//! This component owns only pool policy: bounded storage, nonce-window admission,
//! height expiry, finalization removal, and reproducible candidate snapshots.

use crate::application::ProposalActionSource;
use rachet_core::{
    actions::{Action, SignedAction},
    primitives::{ActionId, ActorId},
};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Mutex, MutexGuard},
};

/// Node-local limits for pending canonical actions.
///
/// Zero action or byte limits are valid and produce a deliberately disabled pool.
/// A zero nonce gap admits only the actor's current expected nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingPoolLimits {
    /// Maximum number of actions across all actors.
    pub max_actions: usize,
    /// Maximum number of actions belonging to one actor.
    pub max_actions_per_actor: usize,
    /// Maximum sum of canonical signed-action lengths.
    pub max_total_bytes: usize,
    /// Largest admitted `action.nonce - expected_nonce`, inclusive.
    pub max_nonce_gap: u64,
}

impl PendingPoolLimits {
    /// Constructs explicit node-local pool limits.
    pub const fn new(
        max_actions: usize,
        max_actions_per_actor: usize,
        max_total_bytes: usize,
        max_nonce_gap: u64,
    ) -> Self {
        Self {
            max_actions,
            max_actions_per_actor,
            max_total_bytes,
            max_nonce_gap,
        }
    }
}

/// Successful admission result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertOutcome {
    /// A previously unseen actor/nonce slot was inserted.
    Inserted { action_id: ActionId },
    /// The exact canonical action was already present; the pool was unchanged.
    Duplicate { action_id: ActionId },
    /// The new action atomically replaced a different action for the same actor/nonce.
    Replaced {
        action_id: ActionId,
        replaced_action_id: ActionId,
    },
}

/// Stable pending-pool admission failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingPoolError {
    /// The action is no longer valid at the supplied current height.
    Expired {
        valid_until_height: u64,
        current_height: u64,
    },
    /// The action nonce is below current canonical actor state.
    StaleNonce { expected: u64, received: u64 },
    /// The action nonce is farther ahead than node policy permits.
    NonceGap {
        expected: u64,
        received: u64,
        maximum_gap: u64,
    },
    /// A new actor/nonce slot would exceed the global count bound.
    GlobalActionLimit { maximum: usize },
    /// A new actor/nonce slot would exceed the per-actor count bound.
    ActorActionLimit { maximum: usize },
    /// Insertion or replacement would exceed the canonical-byte bound.
    TotalByteLimit { maximum: usize, attempted: usize },
}

impl PendingPoolError {
    /// Returns a stable machine-readable policy error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Expired { .. } => "PENDING_ACTION_EXPIRED",
            Self::StaleNonce { .. } => "PENDING_NONCE_STALE",
            Self::NonceGap { .. } => "PENDING_NONCE_GAP",
            Self::GlobalActionLimit { .. } => "PENDING_GLOBAL_LIMIT",
            Self::ActorActionLimit { .. } => "PENDING_ACTOR_LIMIT",
            Self::TotalByteLimit { .. } => "PENDING_BYTE_LIMIT",
        }
    }
}

impl fmt::Display for PendingPoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired {
                valid_until_height,
                current_height,
            } => write!(
                formatter,
                "action expired at height {valid_until_height}, current height is {current_height}"
            ),
            Self::StaleNonce { expected, received } => {
                write!(
                    formatter,
                    "expected nonce at least {expected}, received {received}"
                )
            }
            Self::NonceGap {
                expected,
                received,
                maximum_gap,
            } => write!(
                formatter,
                "nonce {received} exceeds expected nonce {expected} plus maximum gap {maximum_gap}"
            ),
            Self::GlobalActionLimit { maximum } => {
                write!(formatter, "pending action limit {maximum} reached")
            }
            Self::ActorActionLimit { maximum } => {
                write!(
                    formatter,
                    "per-actor pending action limit {maximum} reached"
                )
            }
            Self::TotalByteLimit { maximum, attempted } => write!(
                formatter,
                "pending canonical bytes {attempted} exceed limit {maximum}"
            ),
        }
    }
}

impl std::error::Error for PendingPoolError {}

#[derive(Clone)]
struct PendingEntry {
    action: SignedAction<Action>,
    canonical_bytes: usize,
}

type OrderKey = (ActorId, u64, ActionId);
type SlotKey = (ActorId, u64);

#[derive(Default)]
struct PoolState {
    by_id: BTreeMap<ActionId, PendingEntry>,
    by_order: BTreeMap<OrderKey, ActionId>,
    by_slot: BTreeMap<SlotKey, ActionId>,
    actor_counts: BTreeMap<ActorId, usize>,
    total_bytes: usize,
}

impl PoolState {
    fn remove(&mut self, action_id: ActionId) -> bool {
        let Some(entry) = self.by_id.remove(&action_id) else {
            return false;
        };
        let actor = entry.action.actor;
        let nonce = entry.action.nonce;
        self.by_order.remove(&(actor.clone(), nonce, action_id));
        if self.by_slot.get(&(actor.clone(), nonce)) == Some(&action_id) {
            self.by_slot.remove(&(actor.clone(), nonce));
        }
        self.total_bytes = self
            .total_bytes
            .checked_sub(entry.canonical_bytes)
            .expect("pending byte index must equal stored entries");
        let remove_actor = {
            let count = self
                .actor_counts
                .get_mut(&actor)
                .expect("pending actor index must contain stored entries");
            *count = count
                .checked_sub(1)
                .expect("pending actor count must be positive");
            *count == 0
        };
        if remove_actor {
            self.actor_counts.remove(&actor);
        }
        true
    }
}

/// A bounded pending pool whose operations and snapshots are synchronized.
///
/// Every public mutation is linearized by one mutex. Poison recovery preserves
/// availability after a caller panic because all index updates occur while the
/// guard is held and this module contains no panic-capable user callbacks.
pub struct PendingActionPool {
    limits: PendingPoolLimits,
    state: Mutex<PoolState>,
}

impl PendingActionPool {
    /// Constructs an empty pool with explicit node-local limits.
    pub fn new(limits: PendingPoolLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(PoolState::default()),
        }
    }

    /// Returns this pool's immutable limits.
    pub const fn limits(&self) -> PendingPoolLimits {
        self.limits
    }

    /// Inserts one ingress-validated canonical action.
    ///
    /// `expected_nonce` is read from canonical actor state by the caller. Future
    /// nonces are admitted only through the configured inclusive gap. A distinct
    /// action for an occupied actor/nonce slot is an atomic replacement: if the
    /// replacement exceeds the byte bound, the old action remains present.
    /// Actions expired before `current_height` are pruned before admission.
    pub fn insert(
        &self,
        action: SignedAction<Action>,
        expected_nonce: u64,
        current_height: u64,
    ) -> Result<InsertOutcome, PendingPoolError> {
        let mut state = self.lock();
        expire_locked(&mut state, current_height);

        if action.valid_until_height < current_height {
            return Err(PendingPoolError::Expired {
                valid_until_height: action.valid_until_height,
                current_height,
            });
        }
        if action.nonce < expected_nonce {
            return Err(PendingPoolError::StaleNonce {
                expected: expected_nonce,
                received: action.nonce,
            });
        }
        let gap = action.nonce - expected_nonce;
        if gap > self.limits.max_nonce_gap {
            return Err(PendingPoolError::NonceGap {
                expected: expected_nonce,
                received: action.nonce,
                maximum_gap: self.limits.max_nonce_gap,
            });
        }

        let action_id = action.action_id();
        if state.by_id.contains_key(&action_id) {
            return Ok(InsertOutcome::Duplicate { action_id });
        }

        let slot = (action.actor.clone(), action.nonce);
        let replaced = state.by_slot.get(&slot).copied();
        if replaced.is_none() {
            if state.by_id.len() >= self.limits.max_actions {
                return Err(PendingPoolError::GlobalActionLimit {
                    maximum: self.limits.max_actions,
                });
            }
            let actor_count = state.actor_counts.get(&action.actor).copied().unwrap_or(0);
            if actor_count >= self.limits.max_actions_per_actor {
                return Err(PendingPoolError::ActorActionLimit {
                    maximum: self.limits.max_actions_per_actor,
                });
            }
        }

        let canonical_bytes = action.canonical_len();
        let retained_bytes = match replaced.and_then(|id| state.by_id.get(&id)) {
            Some(entry) => state
                .total_bytes
                .checked_sub(entry.canonical_bytes)
                .expect("pending byte index must equal stored entries"),
            None => state.total_bytes,
        };
        let attempted_bytes = retained_bytes.checked_add(canonical_bytes).ok_or(
            PendingPoolError::TotalByteLimit {
                maximum: self.limits.max_total_bytes,
                attempted: usize::MAX,
            },
        )?;
        if attempted_bytes > self.limits.max_total_bytes {
            return Err(PendingPoolError::TotalByteLimit {
                maximum: self.limits.max_total_bytes,
                attempted: attempted_bytes,
            });
        }

        if let Some(replaced_action_id) = replaced {
            state.remove(replaced_action_id);
        }
        state.total_bytes = state
            .total_bytes
            .checked_add(canonical_bytes)
            .expect("admission checked pending byte addition");
        *state.actor_counts.entry(action.actor.clone()).or_default() += 1;
        state.by_slot.insert(slot, action_id);
        state
            .by_order
            .insert((action.actor.clone(), action.nonce, action_id), action_id);
        state.by_id.insert(
            action_id,
            PendingEntry {
                action,
                canonical_bytes,
            },
        );

        Ok(match replaced {
            Some(replaced_action_id) => InsertOutcome::Replaced {
                action_id,
                replaced_action_id,
            },
            None => InsertOutcome::Inserted { action_id },
        })
    }

    /// Removes actions whose inclusive validity height has passed.
    pub fn expire(&self, current_height: u64) -> usize {
        expire_locked(&mut self.lock(), current_height)
    }

    /// Removes actions made stale by finalized actions.
    ///
    /// Removal includes a locally replaced action occupying the same actor/nonce
    /// and any older pending nonce for that actor, not only matching ActionIds.
    /// This prevents a finalized competing action from leaving stale candidates.
    pub fn remove_finalized(&self, finalized: &[SignedAction<Action>]) -> usize {
        let mut state = self.lock();
        let mut finalized_nonces: BTreeMap<ActorId, u64> = BTreeMap::new();
        for action in finalized {
            finalized_nonces
                .entry(action.actor.clone())
                .and_modify(|nonce| *nonce = (*nonce).max(action.nonce))
                .or_insert(action.nonce);
        }
        let removed: Vec<_> = state
            .by_id
            .iter()
            .filter_map(|(action_id, entry)| {
                finalized_nonces
                    .get(&entry.action.actor)
                    .is_some_and(|nonce| entry.action.nonce <= *nonce)
                    .then_some(*action_id)
            })
            .collect();
        for action_id in &removed {
            state.remove(*action_id);
        }
        removed.len()
    }

    /// Returns an owned snapshot in canonical `(actor_id, nonce, action_id)` order.
    pub fn candidates(&self) -> Vec<SignedAction<Action>> {
        let state = self.lock();
        state
            .by_order
            .values()
            .map(|action_id| {
                state
                    .by_id
                    .get(action_id)
                    .expect("pending order index must reference stored action")
                    .action
                    .clone()
            })
            .collect()
    }

    /// Returns the current global action count.
    pub fn len(&self) -> usize {
        self.lock().by_id.len()
    }

    /// Returns whether no actions are pending.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the current canonical-byte total.
    pub fn total_bytes(&self) -> usize {
        self.lock().total_bytes
    }

    /// Returns the number of actions pending for one actor.
    pub fn actor_len(&self, actor: &ActorId) -> usize {
        self.lock().actor_counts.get(actor).copied().unwrap_or(0)
    }

    /// Returns whether an ActionId is currently pending.
    pub fn contains(&self, action_id: &ActionId) -> bool {
        self.lock().by_id.contains_key(action_id)
    }

    /// Returns an owned pending action without exposing the pool lock.
    pub fn get(&self, action_id: &ActionId) -> Option<SignedAction<Action>> {
        self.lock()
            .by_id
            .get(action_id)
            .map(|entry| entry.action.clone())
    }

    fn lock(&self) -> MutexGuard<'_, PoolState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl ProposalActionSource for PendingActionPool {
    fn candidates(&self) -> Vec<SignedAction<Action>> {
        PendingActionPool::candidates(self)
    }
}

fn expire_locked(state: &mut PoolState, current_height: u64) -> usize {
    let expired: Vec<_> = state
        .by_id
        .iter()
        .filter_map(|(action_id, entry)| {
            (entry.action.valid_until_height < current_height).then_some(*action_id)
        })
        .collect();
    for action_id in &expired {
        state.remove(*action_id);
    }
    expired.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};
    use rachet_core::{
        actions::{ClaimDefinition, CloseJob, CreateJob, ResolutionPolicy},
        artifacts::{ContentRef, GitArtifact, GitHash},
        bounded::{BoundedBytes, BoundedVec},
        primitives::{ChainId, JobId, ProtocolVersion, Sha256Digest},
    };
    use std::sync::{Arc, Barrier};

    fn signed(seed: u64, nonce: u64, valid_until_height: u64) -> SignedAction<Action> {
        SignedAction::sign(
            &ed25519::PrivateKey::from_seed(seed),
            ProtocolVersion::V1,
            ChainId::new([9; 32]),
            nonce,
            valid_until_height,
            Action::CloseJob(CloseJob::new(JobId::derive(&seed.to_be_bytes()))),
        )
        .unwrap()
    }

    fn limits() -> PendingPoolLimits {
        PendingPoolLimits::new(16, 8, 64 * 1024, 4)
    }

    #[test]
    fn action_ids_are_deduplicated_under_concurrent_admission() {
        let pool = Arc::new(PendingActionPool::new(limits()));
        let action = signed(1, 0, 10);
        let barrier = Arc::new(Barrier::new(9));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let pool = Arc::clone(&pool);
            let action = action.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                pool.insert(action, 0, 1).unwrap()
            }));
        }
        barrier.wait();

        let outcomes: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, InsertOutcome::Inserted { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, InsertOutcome::Duplicate { .. }))
                .count(),
            7
        );
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.total_bytes(), action.canonical_len());
    }

    #[test]
    fn concurrent_admission_never_overshoots_count_actor_or_byte_bounds() {
        fn race(
            pool: Arc<PendingActionPool>,
            actions: Vec<SignedAction<Action>>,
        ) -> Vec<Result<InsertOutcome, PendingPoolError>> {
            let barrier = Arc::new(Barrier::new(actions.len() + 1));
            let workers: Vec<_> = actions
                .into_iter()
                .map(|action| {
                    let pool = Arc::clone(&pool);
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        pool.insert(action, 0, 1)
                    })
                })
                .collect();
            barrier.wait();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect()
        }

        let distinct: Vec<_> = (20..28).map(|seed| signed(seed, 0, 10)).collect();
        let action_bytes = distinct[0].canonical_len();

        let global = Arc::new(PendingActionPool::new(PendingPoolLimits::new(
            3,
            8,
            usize::MAX,
            0,
        )));
        let global_results = race(Arc::clone(&global), distinct.clone());
        assert_eq!(global.len(), 3);
        assert_eq!(
            global_results
                .iter()
                .filter(|result| matches!(result, Err(PendingPoolError::GlobalActionLimit { .. })))
                .count(),
            5
        );

        let actor = Arc::new(PendingActionPool::new(PendingPoolLimits::new(
            8,
            3,
            usize::MAX,
            7,
        )));
        let actor_results = race(
            Arc::clone(&actor),
            (0..8).map(|nonce| signed(30, nonce, 10)).collect(),
        );
        assert_eq!(actor.len(), 3);
        assert_eq!(actor.actor_len(&signed(30, 0, 10).actor), 3);
        assert_eq!(
            actor_results
                .iter()
                .filter(|result| matches!(result, Err(PendingPoolError::ActorActionLimit { .. })))
                .count(),
            5
        );

        let bytes = Arc::new(PendingActionPool::new(PendingPoolLimits::new(
            8,
            8,
            action_bytes * 3,
            0,
        )));
        let byte_results = race(Arc::clone(&bytes), distinct);
        assert_eq!(bytes.len(), 3);
        assert_eq!(bytes.total_bytes(), action_bytes * 3);
        assert_eq!(
            byte_results
                .iter()
                .filter(|result| matches!(result, Err(PendingPoolError::TotalByteLimit { .. })))
                .count(),
            5
        );
    }

    #[test]
    fn global_per_actor_byte_and_nonce_gap_bounds_are_inclusive_and_atomic() {
        let actor_first = signed(2, 0, 10);
        let actor_second = signed(2, 1, 10);
        let other_actor = signed(3, 0, 10);
        let pool = PendingActionPool::new(PendingPoolLimits::new(
            2,
            1,
            actor_first.canonical_len() + other_actor.canonical_len(),
            1,
        ));

        pool.insert(actor_first.clone(), 0, 1).unwrap();
        assert_eq!(
            pool.insert(actor_second, 0, 1),
            Err(PendingPoolError::ActorActionLimit { maximum: 1 })
        );
        pool.insert(other_actor.clone(), 0, 1).unwrap();
        assert_eq!(
            pool.insert(signed(4, 0, 10), 0, 1),
            Err(PendingPoolError::GlobalActionLimit { maximum: 2 })
        );
        assert_eq!(pool.len(), 2);
        assert_eq!(
            PendingActionPool::new(limits()).insert(signed(5, 5, 10), 0, 1),
            Err(PendingPoolError::NonceGap {
                expected: 0,
                received: 5,
                maximum_gap: 4,
            })
        );
        assert_eq!(
            PendingActionPool::new(limits()).insert(signed(5, 0, 10), 1, 1),
            Err(PendingPoolError::StaleNonce {
                expected: 1,
                received: 0,
            })
        );

        let byte_pool =
            PendingActionPool::new(PendingPoolLimits::new(2, 2, actor_first.canonical_len(), 1));
        byte_pool.insert(actor_first.clone(), 0, 1).unwrap();
        assert!(matches!(
            byte_pool.insert(other_actor, 0, 1),
            Err(PendingPoolError::TotalByteLimit { .. })
        ));
        assert_eq!(byte_pool.candidates(), vec![actor_first]);
    }

    #[test]
    fn expiry_is_inclusive_and_failed_admission_prunes_old_capacity() {
        let pool = PendingActionPool::new(PendingPoolLimits::new(1, 1, 64 * 1024, 0));
        let expiring = signed(6, 0, 5);
        pool.insert(expiring.clone(), 0, 5).unwrap();
        assert_eq!(pool.expire(5), 0);
        assert!(pool.contains(&expiring.action_id()));

        assert_eq!(
            pool.insert(signed(7, 0, 5), 0, 6),
            Err(PendingPoolError::Expired {
                valid_until_height: 5,
                current_height: 6,
            })
        );
        assert!(pool.is_empty());
        pool.insert(signed(7, 0, 6), 0, 6).unwrap();
        assert_eq!(pool.expire(7), 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn replacement_preserves_indices_and_rolls_back_when_too_large() {
        let original = signed(8, 0, 10);
        let replacement = signed(8, 0, 11);
        let pool =
            PendingActionPool::new(PendingPoolLimits::new(1, 1, original.canonical_len(), 0));
        pool.insert(original.clone(), 0, 1).unwrap();
        let outcome = pool.insert(replacement.clone(), 0, 1).unwrap();
        assert_eq!(
            outcome,
            InsertOutcome::Replaced {
                action_id: replacement.action_id(),
                replaced_action_id: original.action_id(),
            }
        );
        assert!(!pool.contains(&original.action_id()));
        assert!(pool.contains(&replacement.action_id()));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.actor_len(&replacement.actor), 1);

        let mut oversized = replacement.clone();
        oversized.payload = Action::CreateJob(Box::new(CreateJob {
            artifact: GitArtifact::new(
                BoundedBytes::try_from(vec![1; 64]).unwrap(),
                GitHash::sha1([2; 20]),
                GitHash::sha1([3; 20]),
                ContentRef::new(
                    Sha256Digest::from([4; 32]),
                    BoundedBytes::try_from(vec![5; 64]).unwrap(),
                    BoundedBytes::try_from(b"text/plain".as_slice()).unwrap(),
                ),
            ),
            claims: BoundedVec::new(vec![ClaimDefinition::new(
                BoundedBytes::try_from(vec![6; 64]).unwrap(),
            )])
            .unwrap(),
            resolution_policy: ResolutionPolicy::ExperimentAuthority {
                authority: replacement.actor.clone(),
            },
            validation_opens_at: 1,
            validation_closes_at: 2,
            reveal_closes_at: None,
            challenge_closes_at: None,
            supersedes: None,
            metadata: BoundedBytes::try_from(vec![7; 64]).unwrap(),
        }));
        assert!(oversized.canonical_len() > replacement.canonical_len());
        assert!(matches!(
            pool.insert(oversized, 0, 1),
            Err(PendingPoolError::TotalByteLimit { .. })
        ));
        assert_eq!(pool.candidates(), vec![replacement]);
    }

    #[test]
    fn finalization_removes_exact_competitors_and_older_actor_nonces() {
        let pool = PendingActionPool::new(limits());
        let old = signed(9, 0, 20);
        let local_competitor = signed(9, 1, 20);
        let finalized_competitor = signed(9, 1, 21);
        let future = signed(9, 2, 20);
        let other = signed(10, 0, 20);
        for action in [&old, &local_competitor, &future, &other] {
            pool.insert(action.clone(), 0, 1).unwrap();
        }

        assert_eq!(pool.remove_finalized(&[finalized_competitor]), 2);
        assert!(!pool.contains(&old.action_id()));
        assert!(!pool.contains(&local_competitor.action_id()));
        assert!(pool.contains(&future.action_id()));
        assert!(pool.contains(&other.action_id()));
        assert_eq!(pool.actor_len(&future.actor), 1);
        assert_eq!(
            pool.total_bytes(),
            future.canonical_len() + other.canonical_len()
        );
    }

    #[test]
    fn expiry_finalization_and_ordered_snapshots_are_linearizable() {
        let pool = Arc::new(PendingActionPool::new(limits()));
        let expired = signed(40, 0, 1);
        let future = signed(40, 1, 10);
        let finalized = signed(41, 0, 10);
        for action in [&expired, &future, &finalized] {
            pool.insert(action.clone(), 0, 1).unwrap();
        }

        let barrier = Arc::new(Barrier::new(7));
        let mut workers = Vec::new();
        {
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                pool.expire(2);
            }));
        }
        {
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                pool.remove_finalized(&[finalized]);
            }));
        }
        for _ in 0..4 {
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..32 {
                    let candidates = pool.candidates();
                    assert!(candidates.windows(2).all(|pair| {
                        (&pair[0].actor, pair[0].nonce, pair[0].action_id())
                            < (&pair[1].actor, pair[1].nonce, pair[1].action_id())
                    }));
                }
            }));
        }
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(pool.candidates(), vec![future]);
    }

    #[test]
    fn candidates_and_trait_snapshots_use_the_canonical_total_order() {
        let pool = PendingActionPool::new(limits());
        let actions = vec![signed(13, 1, 10), signed(12, 2, 10), signed(13, 0, 10)];
        for action in &actions {
            pool.insert(action.clone(), 0, 1).unwrap();
        }
        let mut expected = actions;
        expected.sort_unstable_by(|left, right| {
            (&left.actor, left.nonce, left.action_id()).cmp(&(
                &right.actor,
                right.nonce,
                right.action_id(),
            ))
        });

        assert_eq!(pool.candidates(), expected);
        let source: &dyn ProposalActionSource = &pool;
        assert_eq!(source.candidates(), expected);
    }
}
