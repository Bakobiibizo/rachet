//! Consensus-independent state batches and the in-memory reference backend.

use super::StateKey;
use crate::primitives::{HashDomain, Sha256Digest};
use commonware_cryptography::{Hasher as _, Sha256};
use std::{collections::BTreeMap, fmt};

/// An owned canonical state value.
pub type StateValue = Box<[u8]>;

/// One owned key/value entry returned by deterministic state iteration.
pub type StateEntry = (StateKey, StateValue);

/// A synchronous, consensus-independent transactional view of protocol state.
///
/// Iteration must return each visible key exactly once in ascending binary-key
/// order. `fork` opens a nested transaction: `commit` merges its writes into
/// the enclosing transaction, while `rollback` discards them. Implementations
/// must make all operations, including roots and errors, deterministic.
pub trait StateBatch {
    /// Returns an owned copy of the value visible at `key`.
    fn get(&self, key: &StateKey) -> Option<StateValue>;

    /// Sets `key` and returns its previously visible value, if any.
    fn put(&mut self, key: StateKey, value: StateValue) -> Option<StateValue>;

    /// Deletes `key` and returns its previously visible value, if any.
    fn delete(&mut self, key: &StateKey) -> Option<StateValue>;

    /// Returns all visible entries in ascending binary-key order.
    fn entries(&self) -> Vec<StateEntry>;

    /// Opens a nested transactional fork at the current visible state.
    fn fork(&mut self);

    /// Merges the innermost open fork into its parent.
    fn commit(&mut self) -> Result<(), StateBatchError>;

    /// Discards the innermost open fork.
    fn rollback(&mut self) -> Result<(), StateBatchError>;

    /// Returns the deterministic root representing the visible state.
    fn root(&self) -> Sha256Digest;
}

/// A transaction operation was invalid for the batch's current state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateBatchError {
    /// `commit` or `rollback` was called without an open fork.
    NoOpenFork,
}

impl fmt::Display for StateBatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoOpenFork => formatter.write_str("the state batch has no open fork"),
        }
    }
}

impl std::error::Error for StateBatchError {}

/// A deterministic transactional state backend for pure execution and tests.
///
/// The base map and every write overlay are ordered maps; no operation depends
/// on insertion order or randomized hashing. Forks are nested write overlays,
/// so rollback does not need to reconstruct earlier values.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryStateBatch {
    base: BTreeMap<StateKey, StateValue>,
    forks: Vec<BTreeMap<StateKey, Option<StateValue>>>,
}

impl InMemoryStateBatch {
    /// Creates an empty state batch with no open transactional forks.
    pub const fn new() -> Self {
        Self {
            base: BTreeMap::new(),
            forks: Vec::new(),
        }
    }

    /// Returns the number of open nested forks.
    pub fn fork_depth(&self) -> usize {
        self.forks.len()
    }

    fn visible_entries(&self) -> BTreeMap<StateKey, StateValue> {
        let mut visible = self.base.clone();
        for fork in &self.forks {
            apply_writes(&mut visible, fork.clone());
        }
        visible
    }

    fn record(&mut self, key: StateKey, value: Option<StateValue>) {
        if let Some(fork) = self.forks.last_mut() {
            fork.insert(key, value);
        } else if let Some(value) = value {
            self.base.insert(key, value);
        } else {
            self.base.remove(&key);
        }
    }
}

impl StateBatch for InMemoryStateBatch {
    fn get(&self, key: &StateKey) -> Option<StateValue> {
        for fork in self.forks.iter().rev() {
            if let Some(value) = fork.get(key) {
                return value.clone();
            }
        }
        self.base.get(key).cloned()
    }

    fn put(&mut self, key: StateKey, value: StateValue) -> Option<StateValue> {
        let previous = self.get(&key);
        self.record(key, Some(value));
        previous
    }

    fn delete(&mut self, key: &StateKey) -> Option<StateValue> {
        let previous = self.get(key);
        self.record(key.clone(), None);
        previous
    }

    fn entries(&self) -> Vec<StateEntry> {
        self.visible_entries().into_iter().collect()
    }

    fn fork(&mut self) {
        self.forks.push(BTreeMap::new());
    }

    fn commit(&mut self) -> Result<(), StateBatchError> {
        let writes = self.forks.pop().ok_or(StateBatchError::NoOpenFork)?;
        if let Some(parent) = self.forks.last_mut() {
            parent.extend(writes);
        } else {
            apply_writes(&mut self.base, writes);
        }
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), StateBatchError> {
        self.forks
            .pop()
            .map(|_| ())
            .ok_or(StateBatchError::NoOpenFork)
    }

    fn root(&self) -> Sha256Digest {
        reference_state_root(&self.entries())
    }
}

fn apply_writes(
    target: &mut BTreeMap<StateKey, StateValue>,
    writes: BTreeMap<StateKey, Option<StateValue>>,
) {
    for (key, value) in writes {
        if let Some(value) = value {
            target.insert(key, value);
        } else {
            target.remove(&key);
        }
    }
}

/// Hashes an ordered state snapshot using the in-memory v1 reference format.
///
/// Entries are sorted by binary key before hashing. The preimage after the
/// state hash domain is:
///
/// ```text
/// entry_count:u64be ||
/// repeated(key_length:u64be || key || value_length:u64be || value)
/// ```
///
/// Length framing makes every snapshot unambiguous. This is the deterministic
/// test-state reference hash; authenticated chain storage may supply its own
/// `StateBatch::root` while preserving the rest of the interface.
pub fn reference_state_root(entries: &[StateEntry]) -> Sha256Digest {
    let mut ordered: Vec<&StateEntry> = entries.iter().collect();
    ordered.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    for pair in ordered.windows(2) {
        assert_ne!(
            pair[0].0, pair[1].0,
            "a state snapshot cannot contain duplicate keys"
        );
    }

    let mut hasher = Sha256::new();
    hasher.update(HashDomain::State.as_bytes());
    hasher.update(&encoded_length(ordered.len()));
    for (key, value) in ordered {
        hasher.update(&encoded_length(key.as_bytes().len()));
        hasher.update(key.as_bytes());
        hasher.update(&encoded_length(value.len()));
        hasher.update(value);
    }
    hasher.finalize()
}

fn encoded_length(length: usize) -> [u8; 8] {
    u64::try_from(length)
        .expect("state lengths fit u64 on supported Linux targets")
        .to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(bytes: &[u8]) -> StateValue {
        bytes.into()
    }

    #[test]
    fn nested_forks_commit_and_roll_back_transactionally() {
        let config = StateKey::protocol_config();
        let epoch = StateKey::protocol_epoch();
        let mut batch = InMemoryStateBatch::new();
        assert_eq!(batch.put(config.clone(), value(b"base")), None);
        let base_root = batch.root();

        batch.fork();
        assert_eq!(
            batch.put(config.clone(), value(b"outer")),
            Some(value(b"base"))
        );
        batch.fork();
        batch.put(epoch.clone(), value(&7_u64.to_be_bytes()));
        batch.commit().unwrap();

        assert_eq!(batch.fork_depth(), 1);
        assert_eq!(batch.get(&config), Some(value(b"outer")));
        assert_eq!(batch.get(&epoch), Some(value(&7_u64.to_be_bytes())));
        assert_ne!(batch.root(), base_root);

        batch.rollback().unwrap();
        assert_eq!(batch.fork_depth(), 0);
        assert_eq!(batch.get(&config), Some(value(b"base")));
        assert_eq!(batch.get(&epoch), None);
        assert_eq!(batch.root(), base_root);

        batch.fork();
        batch.put(config.clone(), value(b"committed"));
        batch.delete(&config);
        batch.put(epoch.clone(), value(&8_u64.to_be_bytes()));
        batch.commit().unwrap();
        assert_eq!(batch.get(&config), None);
        assert_eq!(batch.get(&epoch), Some(value(&8_u64.to_be_bytes())));
        assert_ne!(batch.root(), base_root);
    }

    #[test]
    fn invalid_transaction_operations_do_not_mutate_state() {
        let mut batch = InMemoryStateBatch::new();
        let root = batch.root();
        assert_eq!(batch.commit(), Err(StateBatchError::NoOpenFork));
        assert_eq!(batch.rollback(), Err(StateBatchError::NoOpenFork));
        assert_eq!(batch.root(), root);
    }

    #[test]
    fn iteration_and_roots_do_not_depend_on_insertion_order() {
        let entries = [
            (StateKey::protocol_epoch(), value(b"epoch")),
            (StateKey::protocol_config(), value(b"config")),
            (
                StateKey::mechanism(super::super::MechanismNamespace::new(2), b"z"),
                value(b"mechanism"),
            ),
        ];
        let mut forward = InMemoryStateBatch::new();
        let mut reverse = InMemoryStateBatch::new();

        for (key, value) in entries.iter().cloned() {
            forward.put(key, value);
        }
        for (key, value) in entries.iter().rev().cloned() {
            reverse.put(key, value);
        }

        assert_eq!(forward.entries(), reverse.entries());
        assert!(
            forward
                .entries()
                .windows(2)
                .all(|pair| pair[0].0 < pair[1].0)
        );
        assert_eq!(forward.root(), reverse.root());
    }

    #[test]
    fn reference_root_has_a_stable_framed_vector() {
        let entries = vec![
            (StateKey::protocol_epoch(), value(&42_u64.to_be_bytes())),
            (StateKey::protocol_config(), value(b"v1")),
        ];
        let expected = [
            0xd9, 0xd3, 0x28, 0xf2, 0x5b, 0x12, 0xa9, 0x5f, 0xf0, 0xb6, 0x75, 0xb4, 0x6a, 0x0b,
            0x0b, 0xad, 0x09, 0x69, 0x73, 0xe5, 0x33, 0x11, 0xcf, 0x91, 0x26, 0xb1, 0x4e, 0x14,
            0xe7, 0x8c, 0x7b, 0xc4,
        ];

        assert_eq!(reference_state_root(&entries).as_ref(), expected);
        assert_eq!(
            reference_state_root(&entries),
            reference_state_root(&[entries[1].clone(), entries[0].clone()])
        );

        let ambiguous_without_lengths = [
            (
                StateKey::mechanism(super::super::MechanismNamespace::new(1), b"a"),
                value(b"bc"),
            ),
            (
                StateKey::mechanism(super::super::MechanismNamespace::new(1), b"ab"),
                value(b"c"),
            ),
        ];
        assert_ne!(
            reference_state_root(&ambiguous_without_lengths[..1]),
            reference_state_root(&ambiguous_without_lengths[1..])
        );
    }

    #[test]
    fn interface_is_usable_through_a_trait_object() {
        fn transact(batch: &mut dyn StateBatch) {
            batch.fork();
            batch.put(StateKey::protocol_epoch(), value(b"epoch"));
            batch.commit().unwrap();
        }

        let mut batch = InMemoryStateBatch::new();
        transact(&mut batch);
        assert_eq!(
            batch.get(&StateKey::protocol_epoch()),
            Some(value(b"epoch"))
        );
    }
}
