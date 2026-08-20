//! Durable finalized-report storage and idempotent marshal delivery.
//!
//! Marshal owns the immutable block and certificate archives. This module is
//! the application-side half of the same finalization boundary: it executes
//! each ordered finalized block against the previous finalized snapshot,
//! journals its canonical receipts and recovery snapshot, and acknowledges the
//! marshal update only after both journals are durable.

use crate::{
    application::{GenesisState, StatefulBlock, state::QmdbStateBatch},
    ingress::{ActionStateSnapshot, IngressState, IngressStateError},
};
use bytes::{Buf, BufMut};
use commonware_actor::{Feedback, mailbox};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write};
use commonware_consensus::{Reporter, marshal::Update};
use commonware_cryptography::{Digestible as _, sha256::Digest};
use commonware_runtime::{Handle, Spawner, Supervisor, buffer::paged::CacheRef};
use commonware_storage::{
    Context as StorageContext,
    journal::{
        Error as JournalError,
        contiguous::{Contiguous as _, variable},
    },
};
use commonware_utils::{Acknowledgement as _, NZUsize, SystemTimeExt as _};
use futures::{FutureExt as _, select};
use rachet_core::{
    blocks::{BlockValidationContext, action_root, receipt_root},
    events::ActionReceipt,
    limits::{MAX_ACTIONS_PER_BLOCK, MAX_BLOCK_BODY_BYTES},
    mechanisms::{MechanismId, MechanismVersion},
    primitives::{ActionId, ActorId, ChainId, ProtocolVersion, Sha256Digest},
    state::{StateBatch as _, StateEntry, StateKey, StateNamespace, reference_state_root},
    transition::{TransitionContext, execute_block},
};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    num::{NonZeroU64, NonZeroUsize},
    sync::{Arc, RwLock},
};

const REPORT_VERSION: u8 = 1;
const MAILBOX_SIZE: NonZeroUsize = NZUsize!(128);
const MAX_RECOVERY_ENTRIES: usize = 1_000_000;
const MAX_STATE_KEY_BYTES: usize = 1_024;
const MAX_STATE_VALUE_BYTES: usize = MAX_BLOCK_BODY_BYTES;

/// Storage settings for finalized receipt and recovery journals.
#[derive(Clone)]
pub struct FinalizationStorageConfig {
    prefix: String,
    items_per_section: NonZeroU64,
    page_cache: CacheRef,
    write_buffer: NonZeroUsize,
}

impl FinalizationStorageConfig {
    pub fn new(
        prefix: impl Into<String>,
        items_per_section: NonZeroU64,
        page_cache: CacheRef,
        write_buffer: NonZeroUsize,
    ) -> Result<Self, FinalizationPersistenceError> {
        let prefix = prefix.into();
        if prefix.is_empty() {
            return Err(FinalizationPersistenceError::EmptyPrefix);
        }
        Ok(Self {
            prefix,
            items_per_section,
            page_cache,
            write_buffer,
        })
    }

    fn receipt_config(&self) -> variable::Config<()> {
        variable::Config {
            partition: format!("{}-finalized-receipts", self.prefix),
            items_per_section: self.items_per_section,
            compression: None,
            codec_config: (),
            page_cache: self.page_cache.clone(),
            write_buffer: self.write_buffer,
        }
    }

    fn recovery_config(&self) -> variable::Config<()> {
        variable::Config {
            partition: format!("{}-finalized-recovery", self.prefix),
            items_per_section: self.items_per_section,
            compression: None,
            codec_config: (),
            page_cache: self.page_cache.clone(),
            write_buffer: self.write_buffer,
        }
    }
}

/// Canonical local report for one finalized block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedBlockReport {
    pub height: u64,
    pub epoch: u64,
    pub block_digest: Sha256Digest,
    pub parent_block: Sha256Digest,
    pub receipt_root: Sha256Digest,
    pub state_root: Sha256Digest,
    pub qmdb_state_root: Sha256Digest,
    pub receipts: Vec<ActionReceipt>,
}

impl Write for FinalizedBlockReport {
    fn write(&self, buf: &mut impl BufMut) {
        REPORT_VERSION.write(buf);
        self.height.write(buf);
        self.epoch.write(buf);
        self.block_digest.write(buf);
        self.parent_block.write(buf);
        self.receipt_root.write(buf);
        self.state_root.write(buf);
        self.qmdb_state_root.write(buf);
        self.receipts.write(buf);
    }
}

impl EncodeSize for FinalizedBlockReport {
    fn encode_size(&self) -> usize {
        REPORT_VERSION.encode_size()
            + self.height.encode_size()
            + self.epoch.encode_size()
            + self.block_digest.encode_size()
            + self.parent_block.encode_size()
            + self.receipt_root.encode_size()
            + self.state_root.encode_size()
            + self.qmdb_state_root.encode_size()
            + self.receipts.encode_size()
    }
}

impl Read for FinalizedBlockReport {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != REPORT_VERSION {
            return Err(CodecError::Invalid(
                "FinalizedBlockReport",
                "unsupported report version",
            ));
        }
        Ok(Self {
            height: u64::read(buf)?,
            epoch: u64::read(buf)?,
            block_digest: Sha256Digest::read(buf)?,
            parent_block: Sha256Digest::read(buf)?,
            receipt_root: Sha256Digest::read(buf)?,
            state_root: Sha256Digest::read(buf)?,
            qmdb_state_root: Sha256Digest::read(buf)?,
            receipts: Vec::<ActionReceipt>::read_cfg(
                buf,
                &(RangeCfg::new(..=MAX_ACTIONS_PER_BLOCK), ()),
            )?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveryRecord {
    height: u64,
    block_digest: Sha256Digest,
    state_root: Sha256Digest,
    qmdb_state_root: Sha256Digest,
    finalization_latency_ms: u64,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Write for RecoveryRecord {
    fn write(&self, buf: &mut impl BufMut) {
        REPORT_VERSION.write(buf);
        self.height.write(buf);
        self.block_digest.write(buf);
        self.state_root.write(buf);
        self.qmdb_state_root.write(buf);
        self.finalization_latency_ms.write(buf);
        (self.entries.len() as u64).write(buf);
        for (key, value) in &self.entries {
            key.write(buf);
            value.write(buf);
        }
    }
}

impl EncodeSize for RecoveryRecord {
    fn encode_size(&self) -> usize {
        REPORT_VERSION.encode_size()
            + self.height.encode_size()
            + self.block_digest.encode_size()
            + self.state_root.encode_size()
            + self.qmdb_state_root.encode_size()
            + self.finalization_latency_ms.encode_size()
            + (self.entries.len() as u64).encode_size()
            + self
                .entries
                .iter()
                .map(|(key, value)| key.encode_size() + value.encode_size())
                .sum::<usize>()
    }
}

impl Read for RecoveryRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != REPORT_VERSION {
            return Err(CodecError::Invalid(
                "RecoveryRecord",
                "unsupported report version",
            ));
        }
        let height = u64::read(buf)?;
        let block_digest = Sha256Digest::read(buf)?;
        let state_root = Sha256Digest::read(buf)?;
        let qmdb_state_root = Sha256Digest::read(buf)?;
        let finalization_latency_ms = u64::read(buf)?;
        let count =
            usize::try_from(u64::read(buf)?).map_err(|_| CodecError::InvalidLength(usize::MAX))?;
        if count > MAX_RECOVERY_ENTRIES {
            return Err(CodecError::InvalidLength(count));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let key = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(1..=MAX_STATE_KEY_BYTES), ()))?;
            let value = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(..=MAX_STATE_VALUE_BYTES), ()))?;
            StateKey::from_canonical_bytes(&key).map_err(|_| {
                CodecError::Invalid("RecoveryRecord", "invalid canonical state key")
            })?;
            entries.push((key, value));
        }
        Ok(Self {
            height,
            block_digest,
            state_root,
            qmdb_state_root,
            finalization_latency_ms,
            entries,
        })
    }
}

/// One indexed finalized block exposed to query and observability surfaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedBlockSummary {
    pub height: u64,
    pub epoch: u64,
    pub block_digest: Sha256Digest,
    pub parent_block: Sha256Digest,
    pub parent_state_root: Sha256Digest,
    pub action_root: Sha256Digest,
    pub receipt_root: Sha256Digest,
    pub state_root: Sha256Digest,
    pub qmdb_state_root: Sha256Digest,
    pub action_count: usize,
    pub receipt_count: usize,
}

/// Public retained-state projection for one genesis-selected mechanism.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedMechanismState {
    pub id: MechanismId,
    pub version: MechanismVersion,
    pub namespace: u16,
    pub config_digest: Sha256Digest,
    pub entries: Vec<StateEntry>,
}

/// Successful pure replay of the complete retained finalized archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayVerification {
    pub first_height: u64,
    pub finalized_height: u64,
    pub blocks_verified: u64,
    pub state_root: Sha256Digest,
}

/// First archive field that differs from deterministic pure execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayMismatch {
    pub height: u64,
    pub field: &'static str,
    pub expected: String,
    pub actual: String,
}

/// Current finalization metrics derived only from retained finalized records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizationSnapshot {
    pub finalized_height: u64,
    pub current_epoch: u64,
    pub finalized_state_root: Sha256Digest,
    pub finalized_qmdb_root: Sha256Digest,
    pub finalized_block: Sha256Digest,
    pub receipt_count: u64,
    pub observed_tip_height: u64,
    pub last_finalization_latency_ms: u64,
}

#[derive(Clone)]
struct IndexedReceipt {
    height: u64,
    receipt: ActionReceipt,
}

struct QueryState {
    summaries: BTreeMap<u64, FinalizedBlockSummary>,
    blocks: BTreeMap<u64, StatefulBlock>,
    receipts: BTreeMap<ActionId, IndexedReceipt>,
    entries: BTreeMap<StateKey, Box<[u8]>>,
    genesis: GenesisState,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    snapshot: FinalizationSnapshot,
}

/// Restart-rebuilt local query index over canonical finalized reports.
#[derive(Clone)]
pub struct FinalizedQueryIndex(Arc<RwLock<QueryState>>);

impl FinalizedQueryIndex {
    fn new(genesis_state: &GenesisState, genesis: &StatefulBlock, entries: &[StateEntry]) -> Self {
        let protocol = genesis.protocol();
        let summary = FinalizedBlockSummary {
            height: 0,
            epoch: 0,
            block_digest: genesis.digest(),
            parent_block: protocol.header.parent_block,
            parent_state_root: protocol.header.parent_state_root,
            action_root: protocol.header.action_root,
            receipt_root: protocol.header.receipt_root,
            state_root: protocol.header.post_state_root,
            qmdb_state_root: genesis.qmdb_state_root(),
            action_count: protocol.actions.len(),
            receipt_count: 0,
        };
        Self(Arc::new(RwLock::new(QueryState {
            summaries: [(0, summary)].into_iter().collect(),
            blocks: [(0, genesis.clone())].into_iter().collect(),
            receipts: BTreeMap::new(),
            entries: entries.iter().cloned().collect(),
            genesis: genesis_state.clone(),
            chain_id: genesis_state.chain_id(),
            protocol_version: genesis_state.protocol().protocol().version(),
            snapshot: FinalizationSnapshot {
                finalized_height: 0,
                current_epoch: 0,
                finalized_state_root: protocol.header.post_state_root,
                finalized_qmdb_root: genesis.qmdb_state_root(),
                finalized_block: genesis.digest(),
                receipt_count: 0,
                observed_tip_height: 0,
                last_finalization_latency_ms: 0,
            },
        })))
    }

    pub fn snapshot(&self) -> FinalizationSnapshot {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot
            .clone()
    }

    pub fn block(&self, height: u64) -> Option<FinalizedBlockSummary> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .summaries
            .get(&height)
            .cloned()
    }

    pub fn receipt(&self, action_id: &ActionId) -> Option<(u64, ActionReceipt)> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .receipts
            .get(action_id)
            .map(|indexed| (indexed.height, indexed.receipt.clone()))
    }

    /// Returns one retained canonical state value from the latest finalized snapshot.
    pub fn state_value(&self, key: &StateKey) -> Option<Box<[u8]>> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .get(key)
            .cloned()
    }

    /// Returns an owned, key-ordered projection of one canonical state namespace.
    pub fn state_namespace(&self, namespace: StateNamespace) -> Vec<StateEntry> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .iter()
            .filter(|(key, _)| key.namespace() == namespace)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    /// Returns one genesis-selected mechanism and its latest finalized private entries.
    pub fn mechanism_state(&self, id: MechanismId) -> Option<FinalizedMechanismState> {
        let state = self
            .0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let selected = state
            .genesis
            .protocol()
            .mechanism_set()
            .mechanisms()
            .iter()
            .find(|selected| selected.id == id)?;
        let namespace = id.get();
        let prefix = [
            StateNamespace::Mechanism.tag(),
            namespace.to_be_bytes()[0],
            namespace.to_be_bytes()[1],
        ];
        let entries = state
            .entries
            .iter()
            .filter(|(key, _)| key.as_bytes().starts_with(&prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Some(FinalizedMechanismState {
            id,
            version: selected.version,
            namespace,
            config_digest: selected.config.digest(),
            entries,
        })
    }

    /// Replays finalized archive blocks through the authoritative pure executor.
    pub fn verify_replay(&self) -> Result<ReplayVerification, ReplayMismatch> {
        let (genesis, summaries, blocks, finalized_height) = {
            let state = self
                .0
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                state.genesis.clone(),
                state.summaries.clone(),
                state.blocks.clone(),
                state.snapshot.finalized_height,
            )
        };
        let genesis_block = blocks
            .get(&0)
            .ok_or_else(|| mismatch(0, "archive_block", "present", "missing"))?;
        let genesis_summary = summaries
            .get(&0)
            .ok_or_else(|| mismatch(0, "finalized_report", "present", "missing"))?;
        compare_digest(
            0,
            "block_id",
            genesis_summary.block_digest,
            genesis_block.digest(),
        )?;
        compare_digest(
            0,
            "post_state_root",
            genesis_summary.state_root,
            genesis_block.protocol().header.post_state_root,
        )?;

        let mut state = QmdbStateBatch::from_entries(
            genesis_entries(&genesis)
                .map_err(|error| mismatch(0, "genesis_state", "valid", error.to_string()))?,
        )
        .map_err(|error| mismatch(0, "genesis_state", "valid", error.to_string()))?;
        let mechanisms =
            crate::application::compile_mechanism_set(genesis.protocol().mechanism_set())
                .map_err(|error| mismatch(0, "mechanism_set", "valid", error.to_string()))?;
        let mut parent_block = genesis_block.digest();
        let mut parent_state_root = genesis_block.protocol().header.post_state_root;

        for height in 1..=finalized_height {
            let archived = blocks
                .get(&height)
                .ok_or_else(|| mismatch(height, "archive_block", "present", "missing"))?;
            let report = summaries
                .get(&height)
                .ok_or_else(|| mismatch(height, "finalized_report", "present", "missing"))?;
            let protocol = archived.protocol();
            compare_u64(height, "height", height, protocol.header.height)?;
            compare_digest(
                height,
                "parent_block",
                parent_block,
                protocol.header.parent_block,
            )?;
            compare_digest(
                height,
                "parent_state_root",
                parent_state_root,
                protocol.header.parent_state_root,
            )?;
            compare_digest(
                height,
                "action_root",
                protocol.header.action_root,
                action_root(protocol.actions.as_slice()),
            )?;
            compare_digest(height, "block_id", report.block_digest, archived.digest())?;
            compare_digest(
                height,
                "qmdb_state_root",
                report.qmdb_state_root,
                archived.qmdb_state_root(),
            )?;

            let transition = TransitionContext {
                chain_id: protocol.header.chain_id,
                protocol_version: protocol.header.protocol_version,
                height,
                epoch: protocol.header.epoch,
                mechanism_set_id: protocol.header.mechanism_set_id,
            };
            let execution = execute_block(
                &mut state,
                &transition,
                protocol.actions.as_slice(),
                &mechanisms,
            )
            .map_err(|error| mismatch(height, "execution", "success", error.code()))?;
            compare_digest(
                height,
                "receipt_root",
                protocol.header.receipt_root,
                execution.receipt_root,
            )?;
            compare_digest(
                height,
                "post_state_root",
                protocol.header.post_state_root,
                execution.post_state_root,
            )?;
            compare_digest(
                height,
                "finalized_report_state_root",
                report.state_root,
                execution.post_state_root,
            )?;
            compare_u64(
                height,
                "receipt_count",
                report.receipt_count as u64,
                execution.receipts.len() as u64,
            )?;
            parent_block = archived.digest();
            parent_state_root = execution.post_state_root;
        }

        Ok(ReplayVerification {
            first_height: 0,
            finalized_height,
            blocks_verified: finalized_height.saturating_add(1),
            state_root: parent_state_root,
        })
    }

    /// Counts finalized receipts authored by one actor without exposing receipt bodies.
    pub fn actor_receipt_count(&self, actor: &ActorId) -> u64 {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .receipts
            .values()
            .filter(|indexed| &indexed.receipt.actor == actor)
            .count() as u64
    }

    fn apply(
        &self,
        report: &FinalizedBlockReport,
        latency_ms: u64,
        entries: &[StateEntry],
        block: Option<&StatefulBlock>,
    ) {
        let mut state = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for receipt in &report.receipts {
            state.receipts.insert(
                receipt.action_id,
                IndexedReceipt {
                    height: report.height,
                    receipt: receipt.clone(),
                },
            );
        }
        state.entries = entries.iter().cloned().collect();
        let archived = block.map(StatefulBlock::protocol);
        state.summaries.insert(
            report.height,
            FinalizedBlockSummary {
                height: report.height,
                epoch: report.epoch,
                block_digest: report.block_digest,
                parent_block: report.parent_block,
                parent_state_root: archived.map_or_else(
                    || Sha256Digest::from([0_u8; 32]),
                    |block| block.header.parent_state_root,
                ),
                action_root: archived.map_or_else(
                    || Sha256Digest::from([0_u8; 32]),
                    |block| block.header.action_root,
                ),
                receipt_root: report.receipt_root,
                state_root: report.state_root,
                qmdb_state_root: report.qmdb_state_root,
                action_count: archived.map_or(0, |block| block.actions.len()),
                receipt_count: report.receipts.len(),
            },
        );
        if let Some(block) = block {
            state.blocks.insert(report.height, block.clone());
        }
        state.snapshot.finalized_height = report.height;
        state.snapshot.current_epoch = report.epoch;
        state.snapshot.finalized_state_root = report.state_root;
        state.snapshot.finalized_qmdb_root = report.qmdb_state_root;
        state.snapshot.finalized_block = report.block_digest;
        state.snapshot.receipt_count = state
            .snapshot
            .receipt_count
            .saturating_add(report.receipts.len() as u64);
        state.snapshot.observed_tip_height = state.snapshot.observed_tip_height.max(report.height);
        state.snapshot.last_finalization_latency_ms = latency_ms;
    }

    fn observe_tip(&self, height: u64) {
        let mut state = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.snapshot.observed_tip_height = state.snapshot.observed_tip_height.max(height);
    }
}

fn mismatch(
    height: u64,
    field: &'static str,
    expected: impl Into<String>,
    actual: impl Into<String>,
) -> ReplayMismatch {
    ReplayMismatch {
        height,
        field,
        expected: expected.into(),
        actual: actual.into(),
    }
}

fn compare_digest(
    height: u64,
    field: &'static str,
    expected: Sha256Digest,
    actual: Sha256Digest,
) -> Result<(), ReplayMismatch> {
    if expected == actual {
        Ok(())
    } else {
        Err(mismatch(
            height,
            field,
            encode_hex(expected.as_ref()),
            encode_hex(actual.as_ref()),
        ))
    }
}

fn compare_u64(
    height: u64,
    field: &'static str,
    expected: u64,
    actual: u64,
) -> Result<(), ReplayMismatch> {
    if expected == actual {
        Ok(())
    } else {
        Err(mismatch(
            height,
            field,
            expected.to_string(),
            actual.to_string(),
        ))
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

impl IngressState for FinalizedQueryIndex {
    fn snapshot(&self, actor: &ActorId) -> Result<ActionStateSnapshot, IngressStateError> {
        let state = self
            .0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let height = state
            .snapshot
            .finalized_height
            .checked_add(1)
            .ok_or(IngressStateError::Unavailable)?;
        let expected_nonce = match state.entries.get(&StateKey::account(actor)) {
            None => 0,
            Some(value) => {
                let actual = value.len();
                let bytes: [u8; 8] = value
                    .as_ref()
                    .try_into()
                    .map_err(|_| IngressStateError::MalformedNonce { actual })?;
                u64::from_be_bytes(bytes)
            }
        };
        Ok(ActionStateSnapshot::new(
            rachet_core::actions::ActionVerificationContext::new(
                state.chain_id,
                state.protocol_version,
                height,
            ),
            expected_nonce,
        ))
    }
}

/// Outcome of processing an at-least-once finalized block delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistOutcome {
    Stored,
    Duplicate,
}

/// Pair of crash-reconciled journals and the finalized execution snapshot.
pub struct FinalizationStore<E: StorageContext> {
    receipts: variable::Journal<E, FinalizedBlockReport>,
    recovery: variable::Journal<E, RecoveryRecord>,
    genesis: GenesisState,
    entries: Vec<StateEntry>,
    index: FinalizedQueryIndex,
}

impl<E: StorageContext> FinalizationStore<E> {
    pub async fn init(
        context: E,
        config: FinalizationStorageConfig,
        genesis: GenesisState,
        genesis_block: &StatefulBlock,
    ) -> Result<Self, FinalizationPersistenceError> {
        Self::init_with_archive(context, config, genesis, genesis_block, Vec::new()).await
    }

    /// Rebuilds query and replay state from application journals plus marshal's immutable blocks.
    pub async fn init_with_archive(
        context: E,
        config: FinalizationStorageConfig,
        genesis: GenesisState,
        genesis_block: &StatefulBlock,
        archived_blocks: Vec<StatefulBlock>,
    ) -> Result<Self, FinalizationPersistenceError> {
        let archived_blocks: BTreeMap<u64, StatefulBlock> = archived_blocks
            .into_iter()
            .map(|block| (block.protocol().header.height, block))
            .collect();
        let mut receipts =
            variable::Journal::init(context.child("receipt_journal"), config.receipt_config())
                .await?;
        let mut recovery =
            variable::Journal::init(context.child("recovery_journal"), config.recovery_config())
                .await?;

        let receipt_bounds = receipts.bounds();
        let recovery_bounds = recovery.bounds();
        if receipt_bounds.start != 0 || recovery_bounds.start != 0 {
            return Err(FinalizationPersistenceError::PrunedJournal);
        }
        let common = receipt_bounds.end.min(recovery_bounds.end);
        if receipt_bounds.end != common {
            receipts.rewind(common).await?;
            receipts.sync().await?;
        }
        if recovery_bounds.end != common {
            recovery.rewind(common).await?;
            recovery.sync().await?;
        }

        let mut entries = genesis_entries(&genesis)?;
        let index = FinalizedQueryIndex::new(&genesis, genesis_block, &entries);
        let mut expected_parent = genesis_block.digest();
        for position in 0..common {
            let report = receipts.read(position).await?;
            let record = recovery.read(position).await?;
            let expected_height = position
                .checked_add(1)
                .ok_or(FinalizationPersistenceError::HeightOverflow)?;
            validate_pair(&report, &record, expected_height, expected_parent)?;
            entries = decode_entries(&record.entries)?;
            if reference_state_root(&entries) != record.state_root {
                return Err(FinalizationPersistenceError::RecoveryRootMismatch {
                    height: record.height,
                });
            }
            index.apply(
                &report,
                record.finalization_latency_ms,
                &entries,
                archived_blocks.get(&expected_height),
            );
            expected_parent = report.block_digest;
        }

        Ok(Self {
            receipts,
            recovery,
            genesis,
            entries,
            index,
        })
    }

    pub fn index(&self) -> FinalizedQueryIndex {
        self.index.clone()
    }

    pub async fn persist(
        &mut self,
        block: &StatefulBlock,
        observed_at_ms: u64,
    ) -> Result<PersistOutcome, FinalizationPersistenceError> {
        let protocol = block.protocol();
        let snapshot = self.index.snapshot();
        if protocol.header.height <= snapshot.finalized_height {
            let stored = self.index.block(protocol.header.height).ok_or(
                FinalizationPersistenceError::MissingDuplicateIndex(protocol.header.height),
            )?;
            if stored.block_digest != block.digest()
                || stored.qmdb_state_root != block.qmdb_state_root()
            {
                return Err(FinalizationPersistenceError::ConflictingDuplicate {
                    height: protocol.header.height,
                });
            }
            return Ok(PersistOutcome::Duplicate);
        }

        let expected_height = snapshot
            .finalized_height
            .checked_add(1)
            .ok_or(FinalizationPersistenceError::HeightOverflow)?;
        if protocol.header.height != expected_height {
            return Err(FinalizationPersistenceError::NonContiguousHeight {
                expected: expected_height,
                received: protocol.header.height,
            });
        }
        if protocol.header.parent_block != snapshot.finalized_block {
            return Err(FinalizationPersistenceError::ParentMismatch {
                height: protocol.header.height,
            });
        }
        if protocol.header.parent_state_root != snapshot.finalized_state_root {
            return Err(FinalizationPersistenceError::ParentStateRootMismatch {
                height: protocol.header.height,
            });
        }

        protocol.validate_structure(&BlockValidationContext {
            consensus_context: protocol.context.clone(),
            protocol_version: self.genesis.protocol().protocol().version(),
            chain_id: self.genesis.chain_id(),
            height: expected_height,
            parent_block: snapshot.finalized_block,
            parent_state_root: snapshot.finalized_state_root,
            mechanism_set_id: self.genesis.protocol().mechanism_set_id(),
            blocks_per_epoch: self.genesis.protocol().protocol().blocks_per_epoch(),
            limits: self.genesis.limits(),
        })?;

        let mut state = QmdbStateBatch::from_entries(self.entries.clone())?;
        let transition = TransitionContext {
            chain_id: protocol.header.chain_id,
            protocol_version: protocol.header.protocol_version,
            height: protocol.header.height,
            epoch: protocol.header.epoch,
            mechanism_set_id: protocol.header.mechanism_set_id,
        };
        let mechanisms =
            crate::application::compile_mechanism_set(self.genesis.protocol().mechanism_set())?;
        let execution = execute_block(
            &mut state,
            &transition,
            protocol.actions.as_slice(),
            &mechanisms,
        )?;
        protocol.validate_execution(&execution.receipts, execution.post_state_root)?;
        let commit = state.finish()?;
        if commit.logical_root() != protocol.header.post_state_root {
            return Err(FinalizationPersistenceError::RecoveryRootMismatch {
                height: protocol.header.height,
            });
        }
        let entries = commit.entries().to_vec();
        let report = FinalizedBlockReport {
            height: protocol.header.height,
            epoch: protocol.header.epoch,
            block_digest: block.digest(),
            parent_block: protocol.header.parent_block,
            receipt_root: execution.receipt_root,
            state_root: execution.post_state_root,
            qmdb_state_root: block.qmdb_state_root(),
            receipts: execution.receipts,
        };
        let recovery = RecoveryRecord {
            height: report.height,
            block_digest: report.block_digest,
            state_root: report.state_root,
            qmdb_state_root: report.qmdb_state_root,
            finalization_latency_ms: observed_at_ms.saturating_sub(protocol.header.timestamp_ms),
            entries: encode_entries(&entries),
        };

        let expected_position = report.height - 1;
        let receipt_position = self.receipts.append(&report).await?;
        if receipt_position != expected_position {
            return Err(FinalizationPersistenceError::JournalPositionMismatch);
        }
        self.receipts.sync().await?;
        let recovery_position = self.recovery.append(&recovery).await?;
        if recovery_position != expected_position {
            return Err(FinalizationPersistenceError::JournalPositionMismatch);
        }
        self.recovery.sync().await?;

        self.index.apply(
            &report,
            observed_at_ms.saturating_sub(protocol.header.timestamp_ms),
            &entries,
            Some(block),
        );
        self.entries = entries;
        Ok(PersistOutcome::Stored)
    }
}

fn genesis_entries(
    genesis: &GenesisState,
) -> Result<Vec<StateEntry>, FinalizationPersistenceError> {
    let mut state = QmdbStateBatch::new();
    state.put(
        StateKey::protocol_config(),
        commonware_codec::Encode::encode(genesis).as_ref().into(),
    );
    state.put(
        StateKey::protocol_epoch(),
        0_u64.to_be_bytes().as_slice().into(),
    );
    Ok(state.finish()?.entries().to_vec())
}

fn encode_entries(entries: &[StateEntry]) -> Vec<(Vec<u8>, Vec<u8>)> {
    entries
        .iter()
        .map(|(key, value)| (key.as_bytes().to_vec(), value.to_vec()))
        .collect()
}

fn decode_entries(
    entries: &[(Vec<u8>, Vec<u8>)],
) -> Result<Vec<StateEntry>, FinalizationPersistenceError> {
    let mut previous: Option<&[u8]> = None;
    let mut decoded = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        if previous.is_some_and(|previous| previous >= key.as_slice()) {
            return Err(FinalizationPersistenceError::NonCanonicalRecoveryEntries);
        }
        let typed = StateKey::from_canonical_bytes(key)
            .map_err(|_| FinalizationPersistenceError::NonCanonicalRecoveryEntries)?;
        decoded.push((typed, value.clone().into_boxed_slice()));
        previous = Some(key);
    }
    Ok(decoded)
}

fn validate_pair(
    report: &FinalizedBlockReport,
    recovery: &RecoveryRecord,
    expected_height: u64,
    expected_parent: Digest,
) -> Result<(), FinalizationPersistenceError> {
    if report.height != expected_height || recovery.height != expected_height {
        return Err(FinalizationPersistenceError::NonContiguousHeight {
            expected: expected_height,
            received: report.height,
        });
    }
    if report.parent_block != expected_parent {
        return Err(FinalizationPersistenceError::ParentMismatch {
            height: report.height,
        });
    }
    if report.block_digest != recovery.block_digest
        || report.state_root != recovery.state_root
        || report.qmdb_state_root != recovery.qmdb_state_root
    {
        return Err(FinalizationPersistenceError::JournalDivergence {
            height: report.height,
        });
    }
    if report.receipt_root != receipt_root(&report.receipts) {
        return Err(FinalizationPersistenceError::ReceiptRootMismatch {
            height: report.height,
        });
    }
    Ok(())
}

struct FinalizationCommand(Update<StatefulBlock>);

impl mailbox::Policy for FinalizationCommand {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// Cloneable reporter passed directly to standard marshal's application fanout.
#[derive(Clone)]
pub struct FinalizationReporter {
    sender: mailbox::Sender<FinalizationCommand>,
}

impl Reporter for FinalizationReporter {
    type Activity = Update<StatefulBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.sender.enqueue(FinalizationCommand(activity))
    }
}

/// Async persistence actor that owns both finalization journals.
pub struct FinalizationActor<E: StorageContext + Spawner + Supervisor> {
    context: E,
    receiver: mailbox::Receiver<FinalizationCommand>,
    store: FinalizationStore<E>,
}

impl<E> FinalizationActor<E>
where
    E: StorageContext + Spawner + Supervisor + Send + 'static,
{
    pub async fn init(
        context: E,
        config: FinalizationStorageConfig,
        genesis: GenesisState,
        genesis_block: &StatefulBlock,
    ) -> Result<(Self, FinalizationReporter, FinalizedQueryIndex), FinalizationPersistenceError>
    {
        Self::init_with_archive(context, config, genesis, genesis_block, Vec::new()).await
    }

    /// Initializes the reporter with blocks read from marshal's immutable archive.
    pub async fn init_with_archive(
        context: E,
        config: FinalizationStorageConfig,
        genesis: GenesisState,
        genesis_block: &StatefulBlock,
        archived_blocks: Vec<StatefulBlock>,
    ) -> Result<(Self, FinalizationReporter, FinalizedQueryIndex), FinalizationPersistenceError>
    {
        let store = FinalizationStore::init_with_archive(
            context.child("storage"),
            config,
            genesis,
            genesis_block,
            archived_blocks,
        )
        .await?;
        let index = store.index();
        let (sender, receiver) = mailbox::new(context.child("mailbox"), MAILBOX_SIZE);
        Ok((
            Self {
                context,
                receiver,
                store,
            },
            FinalizationReporter { sender },
            index,
        ))
    }

    pub fn start(mut self) -> Handle<()> {
        self.context.child("actor").spawn(move |_| async move {
            let mut stopped = self.context.stopped().fuse();
            loop {
                let receive = self.receiver.recv().fuse();
                futures::pin_mut!(receive);
                select! {
                    command = receive => {
                        let Some(FinalizationCommand(update)) = command else {
                            return;
                        };
                        match update {
                            Update::Tip(_, height, _) => self.store.index.observe_tip(height.get()),
                            Update::Block(block, acknowledgement) => {
                                let observed_at_ms = u64::try_from(
                                    self.context.current().epoch().as_millis()
                                ).unwrap_or(u64::MAX);
                                self.store.persist(&block, observed_at_ms).await
                                    .unwrap_or_else(|error| panic!("finalization persistence failed: {error}"));
                                acknowledgement.acknowledge();
                            }
                        }
                    },
                    _ = stopped => return,
                }
            }
        })
    }
}

/// Durable-finalization initialization or consistency failure.
#[derive(Debug)]
pub enum FinalizationPersistenceError {
    EmptyPrefix,
    PrunedJournal,
    HeightOverflow,
    Journal(JournalError),
    Genesis(crate::application::GenesisError),
    State(crate::application::state::QmdbStateError),
    Execution(rachet_core::transition::BlockExecutionError),
    Block(rachet_core::blocks::BlockValidationError),
    NonContiguousHeight { expected: u64, received: u64 },
    ParentMismatch { height: u64 },
    ParentStateRootMismatch { height: u64 },
    ConflictingDuplicate { height: u64 },
    MissingDuplicateIndex(u64),
    JournalDivergence { height: u64 },
    ReceiptRootMismatch { height: u64 },
    RecoveryRootMismatch { height: u64 },
    JournalPositionMismatch,
    NonCanonicalRecoveryEntries,
}

impl fmt::Display for FinalizationPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPrefix => formatter.write_str("finalization storage prefix is empty"),
            Self::PrunedJournal => formatter.write_str("finalization journals must retain history"),
            Self::HeightOverflow => formatter.write_str("finalized height overflow"),
            Self::Journal(error) => write!(formatter, "finalization journal: {error}"),
            Self::Genesis(error) => write!(formatter, "finalization genesis: {error}"),
            Self::State(error) => write!(formatter, "finalization state: {error}"),
            Self::Execution(error) => write!(formatter, "finalization execution: {error}"),
            Self::Block(error) => write!(formatter, "finalization block: {error}"),
            Self::NonContiguousHeight { expected, received } => write!(
                formatter,
                "non-contiguous finalized height: expected {expected}, received {received}"
            ),
            Self::ParentMismatch { height } => {
                write!(formatter, "finalized parent mismatch at height {height}")
            }
            Self::ParentStateRootMismatch { height } => {
                write!(
                    formatter,
                    "finalized parent state root mismatch at height {height}"
                )
            }
            Self::ConflictingDuplicate { height } => {
                write!(
                    formatter,
                    "conflicting duplicate finalization at height {height}"
                )
            }
            Self::MissingDuplicateIndex(height) => {
                write!(
                    formatter,
                    "missing finalized query index at height {height}"
                )
            }
            Self::JournalDivergence { height } => {
                write!(
                    formatter,
                    "finalization journals diverge at height {height}"
                )
            }
            Self::ReceiptRootMismatch { height } => {
                write!(formatter, "receipt root mismatch at height {height}")
            }
            Self::RecoveryRootMismatch { height } => {
                write!(formatter, "recovery root mismatch at height {height}")
            }
            Self::JournalPositionMismatch => {
                formatter.write_str("finalization journal position mismatch")
            }
            Self::NonCanonicalRecoveryEntries => {
                formatter.write_str("non-canonical finalized recovery entries")
            }
        }
    }
}

impl std::error::Error for FinalizationPersistenceError {}

impl From<JournalError> for FinalizationPersistenceError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<crate::application::GenesisError> for FinalizationPersistenceError {
    fn from(error: crate::application::GenesisError) -> Self {
        Self::Genesis(error)
    }
}

impl From<crate::application::state::QmdbStateError> for FinalizationPersistenceError {
    fn from(error: crate::application::state::QmdbStateError) -> Self {
        Self::State(error)
    }
}

impl From<rachet_core::transition::BlockExecutionError> for FinalizationPersistenceError {
    fn from(error: rachet_core::transition::BlockExecutionError) -> Self {
        Self::Execution(error)
    }
}

impl From<rachet_core::blocks::BlockValidationError> for FinalizationPersistenceError {
    fn from(error: rachet_core::blocks::BlockValidationError) -> Self {
        Self::Block(error)
    }
}
