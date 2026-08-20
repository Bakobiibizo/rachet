//! Canonical protocol-state adapter for one ordered current QMDB.
//!
//! Pure execution remains synchronous: this adapter materializes the logical
//! parent snapshot, implements [`StateBatch`], and emits one sorted QMDB
//! changeset after execution commits its local forks. Commonware then
//! merkleizes that changeset and owns speculative branch/finalization state.

use commonware_codec::Codec;
use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::{Sequential, Strategy};
use commonware_storage::{
    merkle::{Graftable, mmr},
    qmdb::{
        any::{ordered, value::VariableEncoding},
        current::{self, batch::UnmerkleizedBatch},
    },
    translator::OneCap,
};
use rachet_core::{
    primitives::Sha256Digest,
    state::{
        InMemoryStateBatch, StateBatch, StateBatchError, StateEntry, StateKey, StateKeyDecodeError,
        StateValue,
    },
};
use std::{collections::BTreeMap, fmt};

/// Bitmap chunk size used by Rachet's single current-state QMDB.
pub const QMDB_BITMAP_CHUNK_BYTES: usize = 32;

/// The ordered, variable-key/value current QMDB used for canonical state.
///
/// `Vec<u8>` preserves section 17 keys byte-for-byte. The ordered variant also
/// supports deterministic full-state streaming and exclusion proofs.
pub type QmdbStateDatabase<E, T = OneCap, S = Sequential> = current::ordered::variable::Db<
    mmr::Family,
    E,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    T,
    QMDB_BITMAP_CHUNK_BYTES,
    S,
>;

/// The exact ordered variable-value operation stored by the state QMDB.
pub type QmdbStateOperation<F> = ordered::Operation<F, Vec<u8>, VariableEncoding<Vec<u8>>>;

/// A raw unmerkleized batch for the state QMDB schema.
pub type QmdbStateUnmerkleized<F, H, const N: usize, S> =
    UnmerkleizedBatch<F, H, ordered::Update<Vec<u8>, VariableEncoding<Vec<u8>>>, N, S>;

/// One sorted mutation destined for the current QMDB.
pub type QmdbStateUpdate = (Vec<u8>, Option<Vec<u8>>);

/// A synchronous logical-state view backed by a materialized QMDB parent.
///
/// The QMDB itself is not called from [`StateBatch`] methods because its reads
/// and merkleization are asynchronous. Construct this value at the application
/// boundary, run the consensus-independent transition, then call [`finish`]
/// and apply the returned mutations to the supplied Commonware batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QmdbStateBatch {
    parent: BTreeMap<StateKey, StateValue>,
    working: InMemoryStateBatch,
}

impl QmdbStateBatch {
    /// Creates an empty logical state batch.
    pub const fn new() -> Self {
        Self {
            parent: BTreeMap::new(),
            working: InMemoryStateBatch::new(),
        }
    }

    /// Materializes a batch from typed canonical entries.
    pub fn from_entries(
        entries: impl IntoIterator<Item = StateEntry>,
    ) -> Result<Self, QmdbStateError> {
        let mut parent = BTreeMap::new();
        let mut working = InMemoryStateBatch::new();
        for (key, value) in entries {
            if parent.insert(key.clone(), value.clone()).is_some() {
                return Err(QmdbStateError::DuplicateKey(key.into_bytes().into_vec()));
            }
            working.put(key, value);
        }
        Ok(Self { parent, working })
    }

    /// Decodes entries streamed from the ordered QMDB trust boundary.
    ///
    /// Every database key must be one exact section 17 shape. Values are kept
    /// byte-for-byte and are decoded by their typed protocol consumers.
    pub fn from_qmdb_entries(
        entries: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<Self, QmdbStateError> {
        let mut typed = Vec::new();
        for (key, value) in entries {
            let key = StateKey::from_canonical_bytes(&key).map_err(QmdbStateError::InvalidKey)?;
            typed.push((key, value.into_boxed_slice()));
        }
        Self::from_entries(typed)
    }

    /// Returns the number of local pure-execution transaction forks.
    pub fn fork_depth(&self) -> usize {
        self.working.fork_depth()
    }

    /// Seals pure execution and computes the sorted QMDB delta.
    ///
    /// Finishing with an open fork is rejected so speculative writes can never
    /// leak into the Commonware batch before the pure transaction commits.
    pub fn finish(self) -> Result<QmdbStateCommit, QmdbStateError> {
        if self.fork_depth() != 0 {
            return Err(QmdbStateError::OpenForks(self.fork_depth()));
        }

        let entries = self.working.entries();
        let current: BTreeMap<_, _> = entries.iter().cloned().collect();
        let mut updates = Vec::new();

        for (key, previous) in &self.parent {
            match current.get(key) {
                Some(value) if value == previous => {}
                Some(value) => updates.push((key.as_bytes().to_vec(), Some(value.to_vec()))),
                None => updates.push((key.as_bytes().to_vec(), None)),
            }
        }
        for (key, value) in &current {
            if !self.parent.contains_key(key) {
                updates.push((key.as_bytes().to_vec(), Some(value.to_vec())));
            }
        }
        updates.sort_unstable_by(|left, right| left.0.cmp(&right.0));

        Ok(QmdbStateCommit {
            logical_root: self.working.root(),
            entries,
            updates,
        })
    }
}

impl Default for QmdbStateBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl StateBatch for QmdbStateBatch {
    fn get(&self, key: &StateKey) -> Option<StateValue> {
        self.working.get(key)
    }

    fn put(&mut self, key: StateKey, value: StateValue) -> Option<StateValue> {
        self.working.put(key, value)
    }

    fn delete(&mut self, key: &StateKey) -> Option<StateValue> {
        self.working.delete(key)
    }

    fn entries(&self) -> Vec<StateEntry> {
        self.working.entries()
    }

    fn fork(&mut self) {
        self.working.fork();
    }

    fn commit(&mut self) -> Result<(), StateBatchError> {
        self.working.commit()
    }

    fn rollback(&mut self) -> Result<(), StateBatchError> {
        self.working.rollback()
    }

    fn root(&self) -> Sha256Digest {
        self.working.root()
    }
}

/// Pure-execution output ready to be written into one current-QMDB batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QmdbStateCommit {
    logical_root: Sha256Digest,
    entries: Vec<StateEntry>,
    updates: Vec<QmdbStateUpdate>,
}

impl QmdbStateCommit {
    /// Returns the reference logical root committed by pure execution.
    pub const fn logical_root(&self) -> Sha256Digest {
        self.logical_root
    }

    /// Returns the complete post-transition logical snapshot in key order.
    pub fn entries(&self) -> &[StateEntry] {
        &self.entries
    }

    /// Returns the minimal parent-to-child QMDB delta in key order.
    pub fn updates(&self) -> &[QmdbStateUpdate] {
        &self.updates
    }

    /// Writes the delta into a raw ordered current-QMDB batch.
    ///
    /// The returned batch must be merkleized by Commonware. Its authenticated
    /// QMDB root and [`logical_root`](Self::logical_root) are distinct roots:
    /// blocks use each at its specified boundary rather than substituting one
    /// hash construction for the other.
    pub fn write_to<F, H, const N: usize, S>(
        self,
        mut batch: QmdbStateUnmerkleized<F, H, N, S>,
    ) -> (QmdbStateUnmerkleized<F, H, N, S>, Sha256Digest)
    where
        F: Graftable,
        H: Hasher,
        S: Strategy,
        QmdbStateOperation<F>: Codec,
    {
        for (key, value) in self.updates {
            batch = batch.write(key, value);
        }
        (batch, self.logical_root)
    }
}

/// Invalid canonical-state materialization or transaction sealing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QmdbStateError {
    InvalidKey(StateKeyDecodeError),
    DuplicateKey(Vec<u8>),
    OpenForks(usize),
}

impl fmt::Display for QmdbStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(error) => write!(formatter, "invalid QMDB state key: {error}"),
            Self::DuplicateKey(key) => write!(
                formatter,
                "duplicate QMDB state key 0x{}",
                key.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
            Self::OpenForks(depth) => write!(
                formatter,
                "cannot seal QMDB state with {depth} open transaction fork(s)"
            ),
        }
    }
}

impl std::error::Error for QmdbStateError {}
