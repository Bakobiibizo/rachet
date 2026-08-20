//! Exact action-trace replay from immutable laboratory artifacts.
//!
//! The retained initial-state envelope contains every deterministic runner
//! input and the canonical state snapshot. The action trace contains only
//! already-signed actions grouped by block. Replaying these inputs has no
//! policy, provider, network, or model callback.

use std::{error::Error, fmt, path::Path};

use commonware_codec::{Decode as _, Write as _};
use rachet_core::{
    actions::{Action, SignedAction, decode_signed_action},
    blocks::{Block, ConsensusNodeId},
    events::CanonicalEvent,
    limits::MAX_ACTIONS_PER_BLOCK,
    primitives::{ChainId, Sha256Digest},
    state::{InMemoryStateBatch, StateBatch, StateEntry, StateKey},
};
use rachet_mechanisms::m01_naive_reputation::{M01NaiveReputation, NaiveReputation};
use serde::{Deserialize, Serialize};

use crate::{
    experiment::RunId,
    run_artifacts::{
        RunArtifactBundle, RunArtifactError, RunArtifactStore, RunFailure, RunOutcome,
    },
    simulator::{
        DeterministicRunner, LaboratoryMechanism, RunnerConfig, RunnerError, RunnerSetupError,
        TraceRunOutput,
    },
};

const INITIAL_STATE_MAGIC: &[u8; 8] = b"RCHTIS01";
const ACTION_TRACE_MAGIC: &[u8; 8] = b"RCHTAC01";
const BLOCK_TRACE_MAGIC: &[u8; 8] = b"RCHTBL01";
const EVENT_TRACE_MAGIC: &[u8; 8] = b"RCHTEV01";

/// Replay-critical bytes generated while capturing a deterministic run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayCapture {
    pub initial_state: Vec<u8>,
    pub signed_actions: Vec<u8>,
    pub blocks: Vec<u8>,
    pub events: Vec<u8>,
    pub economic_state_jsonl: Vec<u8>,
    pub outcome: RunOutcome,
}

impl ReplayCapture {
    /// Encodes a completed scripted or closed-loop run from its canonical output.
    pub fn from_completed_run(
        config: &RunnerConfig,
        mechanism: LaboratoryMechanism,
        initial_state: &[StateEntry],
        output: &crate::simulator::RunOutput,
    ) -> Result<Self, TraceReplayError> {
        let action_blocks = output
            .blocks
            .iter()
            .map(|executed| executed.block.actions.iter().cloned().collect())
            .collect::<Vec<Vec<SignedAction<Action>>>>();
        Ok(Self {
            initial_state: encode_initial_state(config, mechanism, initial_state),
            signed_actions: encode_action_trace(&action_blocks),
            blocks: encode_blocks(output),
            events: encode_events(output),
            economic_state_jsonl: encode_economic_state(output)?,
            outcome: RunOutcome::Completed,
        })
    }

    /// Encodes one replayable capture from exact initial state and action-trace execution.
    ///
    /// Unlike [`Self::from_completed_run`], this retains an attempted block that
    /// ended in a terminal protocol error.
    pub fn from_execution(
        config: &RunnerConfig,
        mechanism: LaboratoryMechanism,
        initial_state: &[StateEntry],
        execution: &TraceRunOutput,
    ) -> Result<Self, TraceReplayError> {
        Ok(Self {
            initial_state: encode_initial_state(config, mechanism, initial_state),
            signed_actions: encode_action_trace(&execution.action_blocks),
            blocks: encode_blocks(&execution.output),
            events: encode_events(&execution.output),
            economic_state_jsonl: encode_economic_state(&execution.output)?,
            outcome: outcome_for_execution(execution)?,
        })
    }

    /// Replaces the five replay-critical fields in a complete section 37 bundle.
    pub fn apply_to(self, bundle: &mut RunArtifactBundle) -> RunOutcome {
        bundle.initial_state = self.initial_state;
        bundle.signed_actions = self.signed_actions;
        bundle.blocks = self.blocks;
        bundle.events = self.events;
        bundle.economic_state_jsonl = self.economic_state_jsonl;
        self.outcome
    }
}

/// The exact output surface on which replay first diverged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplaySurface {
    Blocks,
    Events,
    Roots,
    M01Scores,
    TerminalError,
}

impl fmt::Display for ReplaySurface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Blocks => "blocks",
            Self::Events => "events",
            Self::Roots => "roots",
            Self::M01Scores => "M01 scores",
            Self::TerminalError => "terminal error",
        })
    }
}

/// First byte-level difference between a retained and replayed output surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayMismatch {
    pub surface: ReplaySurface,
    pub byte_offset: usize,
    pub expected: Option<u8>,
    pub actual: Option<u8>,
}

/// Evidence returned only after every required output matched exactly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReplayReport {
    pub blocks_replayed: usize,
    pub terminal_error: Option<RunFailure>,
    /// Fixed at zero because trace replay exposes no model invocation boundary.
    pub model_calls: u64,
}

/// Replays a verified immutable run directory.
pub fn replay_run(
    experiment_root: impl AsRef<Path>,
    run_id: RunId,
) -> Result<ReplayReport, TraceReplayError> {
    let loaded =
        RunArtifactStore::load(experiment_root, run_id).map_err(TraceReplayError::Artifact)?;
    replay_bundle(&loaded.bundle, &loaded.manifest.outcome)
}

/// Replays an in-memory artifact bundle and compares the five required surfaces.
///
/// This entry point is useful before immutable capture. Persistent callers
/// should use [`replay_run`] so input hashes and inventory are checked first.
pub fn replay_bundle(
    bundle: &RunArtifactBundle,
    expected_outcome: &RunOutcome,
) -> Result<ReplayReport, TraceReplayError> {
    let retained = decode_initial_state(&bundle.initial_state)?;
    let action_blocks = decode_action_trace(&bundle.signed_actions)?;

    // Reject malformed or non-canonical expected traces before executing them.
    decode_block_trace(&bundle.blocks)?;
    decode_event_trace(&bundle.events)?;
    let expected_economic = decode_economic_state(&bundle.economic_state_jsonl)?;

    let execution = DeterministicRunner::new(retained.config, retained.mechanism)
        .map_err(TraceReplayError::Setup)?
        .with_initial_state(retained.state)
        .replay_actions(action_blocks)
        .map_err(TraceReplayError::Execution)?;

    compare_bytes(
        ReplaySurface::Blocks,
        &bundle.blocks,
        &encode_blocks(&execution.output),
    )?;
    compare_bytes(
        ReplaySurface::Events,
        &bundle.events,
        &encode_events(&execution.output),
    )?;

    let actual_economic = economic_records(&execution.output)?;
    compare_bytes(
        ReplaySurface::Roots,
        &encode_roots(&expected_economic)?,
        &encode_roots(&actual_economic)?,
    )?;
    compare_bytes(
        ReplaySurface::M01Scores,
        &encode_scores(&expected_economic)?,
        &encode_scores(&actual_economic)?,
    )?;

    let actual_outcome = outcome_for_execution(&execution)?;
    compare_bytes(
        ReplaySurface::TerminalError,
        &serde_json::to_vec(expected_outcome).map_err(TraceReplayError::JsonEncode)?,
        &serde_json::to_vec(&actual_outcome).map_err(TraceReplayError::JsonEncode)?,
    )?;

    let terminal_error = match actual_outcome {
        RunOutcome::Completed => None,
        RunOutcome::Failed { failure } => Some(failure),
    };
    Ok(ReplayReport {
        blocks_replayed: execution.output.blocks.len(),
        terminal_error,
        model_calls: 0,
    })
}

/// Resumes a retained deterministic checkpoint by appending one explicit block
/// of already-signed actions. No policy or external host handle is available
/// on this path.
pub(crate) fn replay_with_appended_block(
    initial_state: &[u8],
    action_trace: &[u8],
    actions: Vec<SignedAction<Action>>,
) -> Result<TraceRunOutput, TraceReplayError> {
    let mut checkpoint = decode_checkpoint(initial_state, action_trace)?;
    checkpoint.actions.push(actions);
    DeterministicRunner::new(checkpoint.config, checkpoint.mechanism)
        .map_err(TraceReplayError::Setup)?
        .with_initial_state(entries_to_state(&checkpoint.state))
        .replay_actions(checkpoint.actions)
        .map_err(TraceReplayError::Execution)
}

pub(crate) struct DecodedCheckpoint {
    pub config: RunnerConfig,
    pub mechanism: LaboratoryMechanism,
    pub state: Vec<StateEntry>,
    pub actions: Vec<Vec<SignedAction<Action>>>,
}

pub(crate) fn decode_checkpoint(
    initial_state: &[u8],
    action_trace: &[u8],
) -> Result<DecodedCheckpoint, TraceReplayError> {
    let retained = decode_initial_state(initial_state)?;
    let actions = decode_action_trace(action_trace)?;
    Ok(DecodedCheckpoint {
        config: retained.config,
        mechanism: retained.mechanism,
        state: retained.state.entries(),
        actions,
    })
}

fn entries_to_state(entries: &[StateEntry]) -> InMemoryStateBatch {
    let mut state = InMemoryStateBatch::new();
    for (key, value) in entries {
        state.put(key.clone(), value.clone());
    }
    state
}

struct RetainedInitialState {
    config: RunnerConfig,
    mechanism: LaboratoryMechanism,
    state: InMemoryStateBatch,
}

fn encode_initial_state(
    config: &RunnerConfig,
    mechanism: LaboratoryMechanism,
    entries: &[StateEntry],
) -> Vec<u8> {
    let mut ordered: Vec<_> = entries.iter().collect();
    ordered.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    let mut bytes = Vec::new();
    bytes.extend_from_slice(INITIAL_STATE_MAGIC);
    bytes.extend_from_slice(&config.seed.to_be_bytes());
    config.chain_id.write(&mut bytes);
    bytes.extend_from_slice(&config.blocks_per_epoch.to_be_bytes());
    config.consensus_node.write(&mut bytes);
    config.genesis_parent_block.write(&mut bytes);
    bytes.extend_from_slice(&config.genesis_timestamp_ms.to_be_bytes());
    bytes.extend_from_slice(&config.block_interval_ms.to_be_bytes());
    bytes.push(match mechanism {
        LaboratoryMechanism::M00RecordOnly => 0,
        LaboratoryMechanism::M01NaiveReputation => 1,
    });
    push_len(&mut bytes, ordered.len());
    for (key, value) in ordered {
        push_bytes(&mut bytes, key.as_bytes());
        push_bytes(&mut bytes, value);
    }
    bytes
}

fn decode_initial_state(bytes: &[u8]) -> Result<RetainedInitialState, TraceReplayError> {
    let mut reader = ByteReader::new("initial-state.bin", bytes);
    reader.expect_magic(INITIAL_STATE_MAGIC)?;
    let seed = reader.read_u64()?;
    let chain_id = decode_exact::<ChainId>(&mut reader, 32, "chain ID")?;
    let blocks_per_epoch = reader.read_u64()?;
    let consensus_node = decode_exact::<ConsensusNodeId>(&mut reader, 32, "consensus node")?;
    let genesis_parent_block = decode_exact::<Sha256Digest>(&mut reader, 32, "parent block")?;
    let genesis_timestamp_ms = reader.read_u64()?;
    let block_interval_ms = reader.read_u64()?;
    let mechanism = match reader.read_u8()? {
        0 => LaboratoryMechanism::M00RecordOnly,
        1 => LaboratoryMechanism::M01NaiveReputation,
        tag => return Err(reader.invalid(format!("unknown mechanism tag {tag}"))),
    };
    let count = reader.read_count()?;
    let mut state = InMemoryStateBatch::new();
    let mut previous_key: Option<Vec<u8>> = None;
    for _ in 0..count {
        let key_bytes = reader.read_framed()?;
        if previous_key
            .as_deref()
            .is_some_and(|previous| previous >= key_bytes)
        {
            return Err(reader.invalid("state keys are not in unique ascending order"));
        }
        let key = StateKey::from_canonical_bytes(key_bytes)
            .map_err(|error| reader.invalid(error.to_string()))?;
        previous_key = Some(key_bytes.to_vec());
        let value = reader.read_framed()?.to_vec().into_boxed_slice();
        state.put(key, value);
    }
    reader.finish()?;
    Ok(RetainedInitialState {
        config: RunnerConfig {
            seed,
            chain_id,
            blocks_per_epoch,
            consensus_node,
            genesis_parent_block,
            genesis_timestamp_ms,
            block_interval_ms,
        },
        mechanism,
        state,
    })
}

fn encode_action_trace(blocks: &[Vec<SignedAction<Action>>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ACTION_TRACE_MAGIC);
    push_len(&mut bytes, blocks.len());
    for block in blocks {
        push_len(&mut bytes, block.len());
        for action in block {
            let mut encoded = Vec::new();
            action.write(&mut encoded);
            push_bytes(&mut bytes, &encoded);
        }
    }
    bytes
}

fn decode_action_trace(bytes: &[u8]) -> Result<Vec<Vec<SignedAction<Action>>>, TraceReplayError> {
    let mut reader = ByteReader::new("actions.bin", bytes);
    reader.expect_magic(ACTION_TRACE_MAGIC)?;
    let block_count = reader.read_count()?;
    let mut blocks = Vec::with_capacity(block_count);
    for _ in 0..block_count {
        let action_count = reader.read_count()?;
        if action_count > MAX_ACTIONS_PER_BLOCK {
            return Err(reader.invalid(format!(
                "block contains {action_count} actions; maximum is {MAX_ACTIONS_PER_BLOCK}"
            )));
        }
        let mut actions = Vec::with_capacity(action_count);
        for _ in 0..action_count {
            let encoded = reader.read_framed()?;
            actions.push(
                decode_signed_action(encoded, &())
                    .map_err(|error| reader.invalid(error.to_string()))?,
            );
        }
        blocks.push(actions);
    }
    reader.finish()?;
    Ok(blocks)
}

fn encode_blocks(output: &crate::simulator::RunOutput) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(BLOCK_TRACE_MAGIC);
    push_len(&mut bytes, output.blocks.len());
    for executed in &output.blocks {
        let mut encoded = Vec::new();
        executed.block.write(&mut encoded);
        push_bytes(&mut bytes, &encoded);
    }
    bytes
}

fn decode_block_trace(bytes: &[u8]) -> Result<Vec<Block>, TraceReplayError> {
    let mut reader = ByteReader::new("blocks.bin", bytes);
    reader.expect_magic(BLOCK_TRACE_MAGIC)?;
    let count = reader.read_count()?;
    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        let encoded = reader.read_framed()?;
        blocks.push(
            Block::decode_cfg(encoded, &())
                .map_err(|error| reader.invalid(format!("malformed canonical block: {error}")))?,
        );
    }
    reader.finish()?;
    Ok(blocks)
}

fn encode_events(output: &crate::simulator::RunOutput) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(EVENT_TRACE_MAGIC);
    push_len(&mut bytes, output.blocks.len());
    for executed in &output.blocks {
        push_len(&mut bytes, executed.events.len());
        for event in &executed.events {
            let mut encoded = Vec::new();
            event.write(&mut encoded);
            push_bytes(&mut bytes, &encoded);
        }
    }
    bytes
}

fn decode_event_trace(bytes: &[u8]) -> Result<Vec<Vec<CanonicalEvent>>, TraceReplayError> {
    let mut reader = ByteReader::new("events.bin", bytes);
    reader.expect_magic(EVENT_TRACE_MAGIC)?;
    let block_count = reader.read_count()?;
    let mut blocks = Vec::with_capacity(block_count);
    for _ in 0..block_count {
        let event_count = reader.read_count()?;
        let mut events = Vec::with_capacity(event_count);
        for _ in 0..event_count {
            let encoded = reader.read_framed()?;
            events.push(
                CanonicalEvent::decode_cfg(encoded, &()).map_err(|error| {
                    reader.invalid(format!("malformed canonical event: {error}"))
                })?,
            );
        }
        blocks.push(events);
    }
    reader.finish()?;
    Ok(blocks)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EconomicStateRecord {
    height: u64,
    post_state_root: String,
    m01_scores: Vec<M01ScoreRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct M01ScoreRecord {
    state_key: String,
    reputation: String,
}

fn economic_records(
    output: &crate::simulator::RunOutput,
) -> Result<Vec<EconomicStateRecord>, TraceReplayError> {
    output
        .blocks
        .iter()
        .map(|executed| {
            let mut m01_scores = Vec::new();
            for (key, value) in &executed.post_state {
                if M01NaiveReputation::is_reputation_state_key(key) {
                    NaiveReputation::decode(value).map_err(|error| {
                        TraceReplayError::InvalidFormat {
                            artifact: "economic-state.jsonl",
                            offset: 0,
                            reason: error.to_string(),
                        }
                    })?;
                    m01_scores.push(M01ScoreRecord {
                        state_key: encode_hex(key.as_bytes()),
                        reputation: encode_hex(value),
                    });
                }
            }
            Ok(EconomicStateRecord {
                height: executed.block.header.height,
                post_state_root: encode_hex(executed.block.header.post_state_root.as_ref()),
                m01_scores,
            })
        })
        .collect()
}

fn encode_economic_state(
    output: &crate::simulator::RunOutput,
) -> Result<Vec<u8>, TraceReplayError> {
    let mut bytes = Vec::new();
    for record in economic_records(output)? {
        serde_json::to_writer(&mut bytes, &record).map_err(TraceReplayError::JsonEncode)?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn decode_economic_state(bytes: &[u8]) -> Result<Vec<EconomicStateRecord>, TraceReplayError> {
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(TraceReplayError::InvalidFormat {
            artifact: "economic-state.jsonl",
            offset: bytes.len(),
            reason: "non-empty JSONL does not end with a newline".to_owned(),
        });
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for (index, line) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        let record: EconomicStateRecord =
            serde_json::from_slice(line).map_err(|error| TraceReplayError::InvalidFormat {
                artifact: "economic-state.jsonl",
                offset: index,
                reason: error.to_string(),
            })?;
        let expected_height =
            u64::try_from(index).map_err(|_| TraceReplayError::InvalidFormat {
                artifact: "economic-state.jsonl",
                offset: index,
                reason: "record index does not fit u64".to_owned(),
            })?;
        if record.height != expected_height {
            return Err(TraceReplayError::InvalidFormat {
                artifact: "economic-state.jsonl",
                offset: index,
                reason: format!("expected height {expected_height}, found {}", record.height),
            });
        }
        decode_fixed_hex(&record.post_state_root, 32, "post-state root")?;
        let mut previous_key: Option<Vec<u8>> = None;
        for score in &record.m01_scores {
            let key_bytes = decode_hex(&score.state_key, "M01 state key")?;
            let key = StateKey::from_canonical_bytes(&key_bytes).map_err(|error| {
                TraceReplayError::InvalidFormat {
                    artifact: "economic-state.jsonl",
                    offset: index,
                    reason: error.to_string(),
                }
            })?;
            if !M01NaiveReputation::is_reputation_state_key(&key) {
                return Err(TraceReplayError::InvalidFormat {
                    artifact: "economic-state.jsonl",
                    offset: index,
                    reason: "score entry is not an M01 v1 reputation key".to_owned(),
                });
            }
            if previous_key
                .as_deref()
                .is_some_and(|previous| previous >= key_bytes.as_slice())
            {
                return Err(TraceReplayError::InvalidFormat {
                    artifact: "economic-state.jsonl",
                    offset: index,
                    reason: "M01 score keys are not in unique ascending order".to_owned(),
                });
            }
            previous_key = Some(key_bytes);
            let reputation = decode_hex(&score.reputation, "M01 reputation")?;
            NaiveReputation::decode(&reputation).map_err(|error| {
                TraceReplayError::InvalidFormat {
                    artifact: "economic-state.jsonl",
                    offset: index,
                    reason: error.to_string(),
                }
            })?;
        }
        records.push(record);
    }
    Ok(records)
}

fn encode_roots(records: &[EconomicStateRecord]) -> Result<Vec<u8>, TraceReplayError> {
    let mut bytes = Vec::new();
    push_len(&mut bytes, records.len());
    for record in records {
        bytes.extend_from_slice(&decode_fixed_hex(
            &record.post_state_root,
            32,
            "post-state root",
        )?);
    }
    Ok(bytes)
}

fn encode_scores(records: &[EconomicStateRecord]) -> Result<Vec<u8>, TraceReplayError> {
    let mut bytes = Vec::new();
    push_len(&mut bytes, records.len());
    for record in records {
        bytes.extend_from_slice(&record.height.to_be_bytes());
        push_len(&mut bytes, record.m01_scores.len());
        for score in &record.m01_scores {
            push_bytes(&mut bytes, &decode_hex(&score.state_key, "M01 state key")?);
            push_bytes(
                &mut bytes,
                &decode_hex(&score.reputation, "M01 reputation")?,
            );
        }
    }
    Ok(bytes)
}

fn outcome_for_execution(execution: &TraceRunOutput) -> Result<RunOutcome, TraceReplayError> {
    match &execution.terminal_error {
        None => Ok(RunOutcome::Completed),
        Some(error) => Ok(RunOutcome::Failed {
            failure: RunFailure::new(error.code.clone(), error.message.clone())
                .map_err(TraceReplayError::Artifact)?,
        }),
    }
}

fn compare_bytes(
    surface: ReplaySurface,
    expected: &[u8],
    actual: &[u8],
) -> Result<(), TraceReplayError> {
    if expected == actual {
        return Ok(());
    }
    let byte_offset = expected
        .iter()
        .zip(actual)
        .position(|(expected, actual)| expected != actual)
        .unwrap_or_else(|| expected.len().min(actual.len()));
    Err(TraceReplayError::Mismatch(ReplayMismatch {
        surface,
        byte_offset,
        expected: expected.get(byte_offset).copied(),
        actual: actual.get(byte_offset).copied(),
    }))
}

fn decode_exact<T: commonware_codec::Read<Cfg = ()>>(
    reader: &mut ByteReader<'_>,
    length: usize,
    label: &str,
) -> Result<T, TraceReplayError> {
    let encoded = reader.take(length)?;
    T::decode_cfg(encoded, &())
        .map_err(|error| reader.invalid(format!("malformed {label}: {error}")))
}

fn push_len(bytes: &mut Vec<u8>, length: usize) {
    bytes.extend_from_slice(
        &u64::try_from(length)
            .expect("supported Linux collection lengths fit u64")
            .to_be_bytes(),
    );
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    push_len(bytes, value.len());
    bytes.extend_from_slice(value);
}

struct ByteReader<'a> {
    artifact: &'static str,
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    const fn new(artifact: &'static str, bytes: &'a [u8]) -> Self {
        Self {
            artifact,
            bytes,
            offset: 0,
        }
    }

    fn expect_magic(&mut self, expected: &[u8]) -> Result<(), TraceReplayError> {
        if self.take(expected.len())? != expected {
            return Err(self.invalid("unsupported replay artifact header"));
        }
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, TraceReplayError> {
        Ok(self.take(1)?[0])
    }

    fn read_u64(&mut self) -> Result<u64, TraceReplayError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("exact length requested"),
        ))
    }

    fn read_count(&mut self) -> Result<usize, TraceReplayError> {
        let count = usize::try_from(self.read_u64()?)
            .map_err(|_| self.invalid("count does not fit this platform"))?;
        if count > self.bytes.len().saturating_sub(self.offset) / 8 {
            return Err(self.invalid("count exceeds remaining framed input"));
        }
        Ok(count)
    }

    fn read_framed(&mut self) -> Result<&'a [u8], TraceReplayError> {
        let length = usize::try_from(self.read_u64()?)
            .map_err(|_| self.invalid("length does not fit this platform"))?;
        self.take(length)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TraceReplayError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| self.invalid("offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| self.invalid("truncated input"))?;
        self.offset = end;
        Ok(value)
    }

    fn finish(&self) -> Result<(), TraceReplayError> {
        if self.offset != self.bytes.len() {
            return Err(self.invalid("trailing bytes"));
        }
        Ok(())
    }

    fn invalid(&self, reason: impl Into<String>) -> TraceReplayError {
        TraceReplayError::InvalidFormat {
            artifact: self.artifact,
            offset: self.offset,
            reason: reason.into(),
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_fixed_hex(
    value: &str,
    expected_length: usize,
    label: &str,
) -> Result<Vec<u8>, TraceReplayError> {
    let bytes = decode_hex(value, label)?;
    if bytes.len() != expected_length {
        return Err(TraceReplayError::InvalidFormat {
            artifact: "economic-state.jsonl",
            offset: 0,
            reason: format!(
                "{label} has {} bytes; expected {expected_length}",
                bytes.len()
            ),
        });
    }
    Ok(bytes)
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, TraceReplayError> {
    if !value.len().is_multiple_of(2) {
        return Err(TraceReplayError::InvalidFormat {
            artifact: "economic-state.jsonl",
            offset: 0,
            reason: format!("{label} has odd-length hexadecimal text"),
        });
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            match (high, low) {
                (Some(high), Some(low)) => Ok((high << 4) | low),
                _ => Err(TraceReplayError::InvalidFormat {
                    artifact: "economic-state.jsonl",
                    offset: 0,
                    reason: format!("{label} is not lowercase hexadecimal"),
                }),
            }
        })
        .collect()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Invalid retained input, execution, or exact-output divergence.
#[derive(Debug)]
pub enum TraceReplayError {
    Artifact(RunArtifactError),
    Setup(RunnerSetupError),
    Execution(RunnerError),
    InvalidFormat {
        artifact: &'static str,
        offset: usize,
        reason: String,
    },
    JsonEncode(serde_json::Error),
    Mismatch(ReplayMismatch),
}

impl fmt::Display for TraceReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Artifact(error) => {
                write!(formatter, "retained artifact verification failed: {error}")
            }
            Self::Setup(error) => write!(
                formatter,
                "retained runner configuration is invalid: {error}"
            ),
            Self::Execution(error) => write!(formatter, "trace replay actor failed: {error}"),
            Self::InvalidFormat {
                artifact,
                offset,
                reason,
            } => write!(
                formatter,
                "invalid {artifact} at byte/record {offset}: {reason}"
            ),
            Self::JsonEncode(error) => {
                write!(formatter, "cannot encode replay comparison: {error}")
            }
            Self::Mismatch(mismatch) => write!(
                formatter,
                "first {} mismatch at byte {}: expected {:?}, actual {:?}",
                mismatch.surface, mismatch.byte_offset, mismatch.expected, mismatch.actual
            ),
        }
    }
}

impl Error for TraceReplayError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Artifact(error) => Some(error),
            Self::Setup(error) => Some(error),
            Self::Execution(error) => Some(error),
            Self::JsonEncode(error) => Some(error),
            Self::InvalidFormat { .. } | Self::Mismatch(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use commonware_cryptography::{Signer as _, ed25519};
    use rachet_core::{
        actions::{Action, CloseJob, SignedAction},
        primitives::{ActorId, JobId, ProtocolVersion},
    };

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn config() -> RunnerConfig {
        RunnerConfig {
            seed: 41,
            chain_id: ChainId::new([0x41; 32]),
            blocks_per_epoch: 2,
            consensus_node: ConsensusNodeId::from(ed25519::PrivateKey::from_seed(410).public_key()),
            genesis_parent_block: Sha256Digest::from([0x11; 32]),
            genesis_timestamp_ms: 1_000,
            block_interval_ms: 250,
        }
    }

    fn initial_m01_state() -> InMemoryStateBatch {
        let operator = ActorId::from(ed25519::PrivateKey::from_seed(411).public_key());
        let mut state = InMemoryStateBatch::new();
        state.put(
            M01NaiveReputation::reputation_state_key(&operator),
            NaiveReputation {
                score: 2,
                correct: 2,
                incorrect: 0,
                abstained: 1,
                unresolved: 1,
            }
            .encode(),
        );
        state
    }

    fn base_bundle() -> RunArtifactBundle {
        RunArtifactBundle {
            initial_state: Vec::new(),
            observations_jsonl: Vec::new(),
            decisions_jsonl: Vec::new(),
            signed_actions: Vec::new(),
            blocks: Vec::new(),
            events: Vec::new(),
            economic_state_jsonl: Vec::new(),
            resources_json: b"{}".to_vec(),
            metrics_json: b"{}".to_vec(),
            discovered_strategies_markdown: b"# Strategies\n".to_vec(),
        }
    }

    fn completed_fixture() -> (RunArtifactBundle, RunOutcome) {
        let config = config();
        let state = initial_m01_state();
        let initial_entries = state.entries();
        let execution =
            DeterministicRunner::new(config.clone(), LaboratoryMechanism::M01NaiveReputation)
                .unwrap()
                .with_initial_state(state)
                .replay_actions(vec![Vec::new(), Vec::new()])
                .unwrap();
        let capture = ReplayCapture::from_completed_run(
            &config,
            LaboratoryMechanism::M01NaiveReputation,
            &initial_entries,
            &execution.output,
        )
        .unwrap();
        let mut bundle = base_bundle();
        let outcome = capture.apply_to(&mut bundle);
        (bundle, outcome)
    }

    fn mismatch(error: TraceReplayError) -> ReplayMismatch {
        match error {
            TraceReplayError::Mismatch(mismatch) => mismatch,
            other => panic!("expected exact mismatch, found {other}"),
        }
    }

    #[test]
    fn captured_m01_trace_replays_every_surface_without_model_calls() {
        let (bundle, outcome) = completed_fixture();
        let report = replay_bundle(&bundle, &outcome).unwrap();
        assert_eq!(report.blocks_replayed, 2);
        assert_eq!(report.terminal_error, None);
        assert_eq!(report.model_calls, 0);
    }

    #[test]
    fn reports_first_exact_block_event_root_and_score_mismatch() {
        let (bundle, outcome) = completed_fixture();

        let mut alternate_config = config();
        alternate_config.genesis_timestamp_ms += 1;
        let alternate_state = initial_m01_state();
        let alternate_entries = alternate_state.entries();
        let alternate_execution = DeterministicRunner::new(
            alternate_config.clone(),
            LaboratoryMechanism::M01NaiveReputation,
        )
        .unwrap()
        .with_initial_state(alternate_state)
        .replay_actions(vec![Vec::new(), Vec::new()])
        .unwrap();
        let alternate_capture = ReplayCapture::from_execution(
            &alternate_config,
            LaboratoryMechanism::M01NaiveReputation,
            &alternate_entries,
            &alternate_execution,
        )
        .unwrap();
        let mut block_divergence = bundle.clone();
        block_divergence.blocks = alternate_capture.blocks;
        let block = mismatch(replay_bundle(&block_divergence, &outcome).unwrap_err());
        assert_eq!(block.surface, ReplaySurface::Blocks);
        assert_ne!(block.expected, block.actual);

        let mut event_divergence = bundle.clone();
        let event = CanonicalEvent::JobClosed {
            job_id: JobId::derive(b"unexpected-event"),
        };
        let mut encoded_event = Vec::new();
        event.write(&mut encoded_event);
        let mut unexpected_events = Vec::new();
        unexpected_events.extend_from_slice(EVENT_TRACE_MAGIC);
        push_len(&mut unexpected_events, 2);
        push_len(&mut unexpected_events, 1);
        push_bytes(&mut unexpected_events, &encoded_event);
        push_len(&mut unexpected_events, 0);
        event_divergence.events = unexpected_events;
        let event = mismatch(replay_bundle(&event_divergence, &outcome).unwrap_err());
        assert_eq!(event.surface, ReplaySurface::Events);
        assert_ne!(event.expected, event.actual);

        let records = decode_economic_state(&bundle.economic_state_jsonl).unwrap();
        let mut root_records = records.clone();
        root_records[0].post_state_root = "00".repeat(32);
        let mut root_divergence = bundle.clone();
        root_divergence.economic_state_jsonl = encode_records(&root_records);
        let root = mismatch(replay_bundle(&root_divergence, &outcome).unwrap_err());
        assert_eq!(root.surface, ReplaySurface::Roots);
        assert_ne!(root.expected, root.actual);

        let mut score_records = records;
        score_records[0].m01_scores[0].reputation = "00".repeat(40);
        let mut score_divergence = bundle;
        score_divergence.economic_state_jsonl = encode_records(&score_records);
        let score = mismatch(replay_bundle(&score_divergence, &outcome).unwrap_err());
        assert_eq!(score.surface, ReplaySurface::M01Scores);
        assert_ne!(score.expected, score.actual);
    }

    #[test]
    fn terminal_protocol_errors_replay_byte_for_byte() {
        let config = config();
        let key = ed25519::PrivateKey::from_seed(412);
        let invalid_nonce = SignedAction::sign(
            &key,
            ProtocolVersion::V1,
            config.chain_id,
            1,
            10,
            Action::CloseJob(CloseJob::new(JobId::derive(b"missing"))),
        )
        .unwrap();
        let execution =
            DeterministicRunner::new(config.clone(), LaboratoryMechanism::M00RecordOnly)
                .unwrap()
                .replay_actions(vec![vec![invalid_nonce]])
                .unwrap();
        assert_eq!(
            execution.terminal_error.as_ref().unwrap().code,
            "ACTION_NONCE_INVALID"
        );
        let capture = ReplayCapture::from_execution(
            &config,
            LaboratoryMechanism::M00RecordOnly,
            &[],
            &execution,
        )
        .unwrap();
        let mut bundle = base_bundle();
        let outcome = capture.apply_to(&mut bundle);
        let report = replay_bundle(&bundle, &outcome).unwrap();
        assert_eq!(
            report.terminal_error.as_ref().unwrap().code,
            "ACTION_NONCE_INVALID"
        );

        let wrong_outcome = RunOutcome::Failed {
            failure: RunFailure::new("DIFFERENT", "different terminal error").unwrap(),
        };
        let terminal = mismatch(replay_bundle(&bundle, &wrong_outcome).unwrap_err());
        assert_eq!(terminal.surface, ReplaySurface::TerminalError);
        assert_ne!(terminal.expected, terminal.actual);
    }

    #[test]
    fn persistent_replay_rejects_tampered_input_before_execution() {
        let temp = TempDirectory::new();
        let run_id: RunId = "41".repeat(32).parse().unwrap();
        let experiment = temp.path().join("experiment");
        fs::create_dir_all(experiment.join("seeds")).unwrap();
        let run_root = experiment.join("runs").join(run_id.to_string());
        fs::create_dir_all(&run_root).unwrap();
        let (bundle, outcome) = completed_fixture();
        RunArtifactStore::capture(&experiment, run_id, outcome, &bundle).unwrap();
        let report = replay_run(&experiment, run_id).unwrap();
        assert_eq!(report.blocks_replayed, 2);
        assert_eq!(report.model_calls, 0);

        let actions = run_root.join("actions.bin");
        let mut tampered = fs::read(&actions).unwrap();
        tampered[0] ^= 1;
        fs::write(actions, tampered).unwrap();

        assert!(matches!(
            replay_run(&experiment, run_id),
            Err(TraceReplayError::Artifact(
                RunArtifactError::ArtifactHash { .. }
            ))
        ));
    }

    fn encode_records(records: &[EconomicStateRecord]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for record in records {
            serde_json::to_writer(&mut bytes, record).unwrap();
            bytes.push(b'\n');
        }
        bytes
    }

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rachet-trace-replay-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
