//! Durable host-side pause/resume boundary for closed-loop laboratory runs.
//!
//! Deterministic execution stops before an external operator is called. The
//! checkpoint and exact observation are synced first, the host invocation is
//! captured as explicit signed actions, and a fresh deterministic actor resumes
//! only from those retained bytes. An in-progress host call discovered after a
//! process restart becomes a durable failure instead of being called again.

use std::{
    collections::BTreeSet,
    error::Error,
    fmt, fs, io,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use commonware_codec::Write as _;
use rachet_core::{
    actions::{Action, SignedAction, decode_signed_action},
    blocks::epoch_for_height,
    limits::MAX_ACTIONS_PER_BLOCK,
    primitives::ChainId,
    state::{InMemoryStateBatch, StateBatch as _, StateEntry},
};
use rachet_operator::{
    agentctl::{AgentctlBoundary, AgentctlOutcome},
    decision::{DecisionContext, ParsedDecision},
    host::ProvisionedOperator,
    observation::{ObservationProvenance, ObservationSnapshot},
    provenance::ProvenanceStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    replay::{ReplayCapture, TraceReplayError, decode_checkpoint, replay_with_appended_block},
    simulator::{
        DeterministicRunner, LaboratoryMechanism, RunnerConfig, RunnerError, RunnerSetupError,
        TraceRunOutput,
    },
};

const BOUNDARY_SCHEMA_VERSION: &str = "lab-decision-boundary.v1";
const STATE_FILE: &str = "boundary-state.json";
const INITIAL_STATE_FILE: &str = "initial-state.bin";
const PREFIX_ACTIONS_FILE: &str = "prefix-actions.bin";
const OBSERVATION_FILE: &str = "observation.json";
const OBSERVATION_PROVENANCE_FILE: &str = "observation-provenance.json";
const RAW_OUTPUT_FILE: &str = "raw-output.bin";
const DECISION_FILE: &str = "decision.json";
const DECISION_ACTIONS_FILE: &str = "decision-actions.bin";
const RESUME_FILE: &str = "resume.json";
const ACTION_MAGIC: &[u8; 8] = b"RCHTBD01";
const O_NOFOLLOW: i32 = 0o400_000;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Durable phase of one external decision boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryPhase {
    Paused,
    Invoking,
    Ready,
    Resumed,
    Failed,
}

/// Stable terminal boundary failure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryFailure {
    pub code: String,
    pub message: String,
}

/// Public status reconstructed only from verified durable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryStatus {
    pub phase: BoundaryPhase,
    pub failure: Option<BoundaryFailure>,
}

/// Durable coordinator. It owns no model capability while deterministic code is
/// running; the capability is passed only to [`Self::invoke_external`].
pub struct PauseResumeBoundary {
    root: PathBuf,
    state: PersistedState,
    observation: ObservationSnapshot,
}

impl PauseResumeBoundary {
    /// Restores canonical replay inputs and pauses at their exact deterministic
    /// tip. This is the host CLI boundary: it accepts no model capability and
    /// verifies the supplied observation against the reconstructed state.
    pub fn pause_captured(
        root: impl AsRef<Path>,
        initial_state: &[u8],
        prefix_actions: &[u8],
        observation: ObservationSnapshot,
    ) -> Result<Self, BoundaryError> {
        let checkpoint =
            decode_checkpoint(initial_state, prefix_actions).map_err(BoundaryError::Replay)?;
        Self::pause(
            root,
            checkpoint.config,
            checkpoint.mechanism,
            checkpoint.state,
            checkpoint.actions,
            observation,
        )
    }

    /// Runs the deterministic prefix to completion and then durably records the
    /// exact checkpoint and observation before exposing a paused boundary.
    pub fn pause(
        root: impl AsRef<Path>,
        config: RunnerConfig,
        mechanism: LaboratoryMechanism,
        initial_state: Vec<StateEntry>,
        prefix_action_blocks: Vec<Vec<SignedAction<Action>>>,
        observation: ObservationSnapshot,
    ) -> Result<Self, BoundaryError> {
        let mut state_batch = InMemoryStateBatch::new();
        let mut keys = BTreeSet::new();
        for (key, value) in &initial_state {
            if !keys.insert(key.clone()) {
                return Err(BoundaryError::InvalidCheckpoint(
                    "initial state contains a duplicate key".to_owned(),
                ));
            }
            state_batch.put(key.clone(), value.clone());
        }

        let execution = DeterministicRunner::new(config.clone(), mechanism)
            .map_err(BoundaryError::Setup)?
            .with_initial_state(state_batch)
            .replay_actions(prefix_action_blocks)
            .map_err(BoundaryError::Runner)?;
        if let Some(failure) = execution.terminal_error {
            return Err(BoundaryError::PrefixFailed(BoundaryFailure {
                code: failure.code,
                message: failure.message,
            }));
        }
        let decision_height = u64::try_from(execution.output.blocks.len()).map_err(|_| {
            BoundaryError::InvalidCheckpoint("prefix block count does not fit u64".to_owned())
        })?;
        let decision_epoch = epoch_for_height(decision_height, config.blocks_per_epoch)
            .map_err(|error| BoundaryError::InvalidCheckpoint(error.to_string()))?;
        let finalized_root = if let Some(last) = execution.output.blocks.last() {
            hash_value_hex(last.block.header.post_state_root.as_ref())
        } else {
            let mut final_state = InMemoryStateBatch::new();
            for (key, value) in &execution.output.final_state {
                final_state.put(key.clone(), value.clone());
            }
            hash_value_hex(final_state.root().as_ref())
        };
        if observation.observation().height() != decision_height
            || observation.observation().epoch() != decision_epoch
            || observation
                .provenance()
                .finalized_state_root_sha256
                .as_str()
                != finalized_root
        {
            return Err(BoundaryError::InvalidCheckpoint(
                "observation height, epoch, or finalized state root does not match the deterministic pause point".to_owned(),
            ));
        }
        let checkpoint =
            ReplayCapture::from_execution(&config, mechanism, &initial_state, &execution)
                .map_err(BoundaryError::Replay)?;

        let root = root.as_ref().to_path_buf();
        create_boundary_directory(&root)?;
        let result = (|| {
            let observation_provenance = json_bytes(observation.provenance())?;
            let artifacts = BaseArtifacts {
                initial_state: write_artifact(
                    &root,
                    INITIAL_STATE_FILE,
                    &checkpoint.initial_state,
                )?,
                prefix_actions: write_artifact(
                    &root,
                    PREFIX_ACTIONS_FILE,
                    &checkpoint.signed_actions,
                )?,
                observation: write_artifact(&root, OBSERVATION_FILE, observation.canonical_json())?,
                observation_provenance: write_artifact(
                    &root,
                    OBSERVATION_PROVENANCE_FILE,
                    &observation_provenance,
                )?,
            };
            let state = PersistedState {
                schema_version: BOUNDARY_SCHEMA_VERSION.to_owned(),
                base: artifacts,
                decision: None,
                phase: PersistedPhase::Paused,
            };
            write_state(&root, &state)?;
            Ok(Self {
                root: root.clone(),
                state,
                observation,
            })
        })();
        if result.is_err() {
            // A directory without the state completion marker is not resumable.
            let _ = fs::remove_dir_all(&root);
        }
        result
    }

    /// Opens and verifies a durable boundary after process restart. A host call
    /// that was in flight is terminally failed: it is never silently repeated.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, BoundaryError> {
        let root = canonical_directory(root.as_ref())?;
        let mut state = read_state(&root)?;
        verify_base(&root, &state.base)?;
        let observation_bytes = read_artifact(&root, &state.base.observation)?;
        let provenance_bytes = read_artifact(&root, &state.base.observation_provenance)?;
        let provenance: ObservationProvenance =
            serde_json::from_slice(&provenance_bytes).map_err(BoundaryError::JsonDecode)?;
        let observation = ObservationSnapshot::from_captured(observation_bytes, provenance)
            .map_err(|error| BoundaryError::Observation(error.to_string()))?;
        if let Some(decision) = &state.decision {
            verify_decision(&root, decision)?;
        }
        if matches!(state.phase, PersistedPhase::Invoking) {
            state.phase = PersistedPhase::Failed {
                failure: BoundaryFailure {
                    code: "LAB_EXTERNAL_INVOCATION_INTERRUPTED".to_owned(),
                    message: "process restarted while the external operator host was in flight; invocation will not be repeated".to_owned(),
                },
            };
            write_state(&root, &state)?;
        }
        Ok(Self {
            root,
            state,
            observation,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn status(&self) -> BoundaryStatus {
        match &self.state.phase {
            PersistedPhase::Paused => BoundaryStatus {
                phase: BoundaryPhase::Paused,
                failure: None,
            },
            PersistedPhase::Invoking => BoundaryStatus {
                phase: BoundaryPhase::Invoking,
                failure: None,
            },
            PersistedPhase::Ready => BoundaryStatus {
                phase: BoundaryPhase::Ready,
                failure: None,
            },
            PersistedPhase::Resumed { .. } => BoundaryStatus {
                phase: BoundaryPhase::Resumed,
                failure: None,
            },
            PersistedPhase::Failed { failure } => BoundaryStatus {
                phase: BoundaryPhase::Failed,
                failure: Some(failure.clone()),
            },
        }
    }

    #[must_use]
    pub const fn observation(&self) -> &ObservationSnapshot {
        &self.observation
    }

    /// Returns the chain committed by the retained deterministic checkpoint.
    pub fn chain_id(&self) -> Result<ChainId, BoundaryError> {
        let initial_state = read_artifact(&self.root, &self.state.base.initial_state)?;
        let prefix_actions = read_artifact(&self.root, &self.state.base.prefix_actions)?;
        decode_checkpoint(&initial_state, &prefix_actions)
            .map(|checkpoint| checkpoint.config.chain_id)
            .map_err(BoundaryError::Replay)
    }

    /// Marks intent durably, invokes the external host exactly once, and
    /// captures raw output, strict parsed decision, provenance pointer, and
    /// canonical signed actions before making the boundary ready to resume.
    pub fn invoke_external(
        &mut self,
        boundary: &AgentctlBoundary,
        operator: &mut ProvisionedOperator,
        system_prompt: &[u8],
        context: DecisionContext<'_>,
    ) -> Result<BoundaryStatus, BoundaryError> {
        self.require_phase(BoundaryPhase::Paused)?;
        self.state.phase = PersistedPhase::Invoking;
        write_state(&self.root, &self.state)?;

        let record = boundary.invoke_and_sign(operator, system_prompt, &self.observation, context);
        let (parsed_decision, signed_actions, mut failure) = match &record.outcome {
            AgentctlOutcome::Decision(decision) => (
                decision.parsed_decision.clone(),
                decision.signed_actions.clone(),
                decision.failure.as_ref().map(|failure| BoundaryFailure {
                    code: failure.code.to_owned(),
                    message: failure.message.clone(),
                }),
            ),
            AgentctlOutcome::Failure(host_failure) => (
                None,
                Vec::new(),
                Some(BoundaryFailure {
                    code: host_failure.code.to_owned(),
                    message: host_failure.message.clone(),
                }),
            ),
        };

        let (provenance_manifest, provenance_sha256) = match &record.provenance {
            ProvenanceStatus::Committed(reference) => (
                Some(reference.manifest_path.display().to_string()),
                Some(reference.manifest_sha256.clone()),
            ),
            ProvenanceStatus::Failed(provenance_failure) => {
                failure = Some(BoundaryFailure {
                    code: provenance_failure.code.to_owned(),
                    message: provenance_failure.message.clone(),
                });
                (None, None)
            }
            ProvenanceStatus::Pending => {
                failure = Some(BoundaryFailure {
                    code: "OPERATOR_PROVENANCE_INCOMPLETE".to_owned(),
                    message: "operator invocation did not commit terminal provenance".to_owned(),
                });
                (None, None)
            }
        };

        let raw_output = record.raw_output();
        let encoded_actions = encode_actions(&signed_actions);
        let capture = DecisionCapture {
            schema_version: "operator-boundary-capture.v1".to_owned(),
            raw_output_sha256: hash_hex(raw_output),
            parsed_decision,
            signed_action_count: signed_actions.len(),
            failure: failure.clone(),
            provenance_manifest,
            provenance_manifest_sha256: provenance_sha256,
        };
        let capture_bytes = json_bytes(&capture)?;
        let decision = DecisionArtifacts {
            raw_output: write_artifact(&self.root, RAW_OUTPUT_FILE, raw_output)?,
            capture: write_artifact(&self.root, DECISION_FILE, &capture_bytes)?,
            signed_actions: write_artifact(&self.root, DECISION_ACTIONS_FILE, &encoded_actions)?,
        };
        self.state.decision = Some(decision);
        self.state.phase = failure.map_or(PersistedPhase::Ready, |failure| {
            PersistedPhase::Failed { failure }
        });
        write_state(&self.root, &self.state)?;
        Ok(self.status())
    }

    /// Starts a fresh deterministic actor from the retained checkpoint and one
    /// decoded block of captured signed actions. Raw output, timing, provider
    /// metadata, and callbacks are intentionally absent from this path.
    pub fn resume(&mut self) -> Result<TraceRunOutput, BoundaryError> {
        self.require_phase(BoundaryPhase::Ready)?;
        let decision =
            self.state.decision.as_ref().ok_or_else(|| {
                BoundaryError::InvalidState("ready state has no decision".to_owned())
            })?;
        verify_decision(&self.root, decision)?;
        let initial_state = read_artifact(&self.root, &self.state.base.initial_state)?;
        let prefix_actions = read_artifact(&self.root, &self.state.base.prefix_actions)?;
        let decision_actions =
            decode_actions(&read_artifact(&self.root, &decision.signed_actions)?)?;

        let execution =
            replay_with_appended_block(&initial_state, &prefix_actions, decision_actions)
                .map_err(BoundaryError::Replay)?;
        if let Some(terminal) = &execution.terminal_error {
            let failure = BoundaryFailure {
                code: terminal.code.clone(),
                message: terminal.message.clone(),
            };
            self.state.phase = PersistedPhase::Failed {
                failure: failure.clone(),
            };
            write_state(&self.root, &self.state)?;
            return Err(BoundaryError::ResumeFailed(failure));
        }

        let report = ResumeCapture {
            blocks_executed: execution.output.blocks.len(),
            canonical_output_sha256: hash_hex(&execution.output.canonical_bytes()),
        };
        let report_bytes = json_bytes(&report)?;
        write_artifact_idempotent(&self.root, RESUME_FILE, &report_bytes)?;
        self.state.phase = PersistedPhase::Resumed {
            blocks_executed: report.blocks_executed,
            canonical_output_sha256: report.canonical_output_sha256,
        };
        write_state(&self.root, &self.state)?;
        Ok(execution)
    }

    fn require_phase(&self, expected: BoundaryPhase) -> Result<(), BoundaryError> {
        let actual = self.status().phase;
        if actual != expected {
            return Err(BoundaryError::InvalidPhase { expected, actual });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactCommitment {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BaseArtifacts {
    initial_state: ArtifactCommitment,
    prefix_actions: ArtifactCommitment,
    observation: ArtifactCommitment,
    observation_provenance: ArtifactCommitment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DecisionArtifacts {
    raw_output: ArtifactCommitment,
    capture: ArtifactCommitment,
    signed_actions: ArtifactCommitment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedState {
    schema_version: String,
    base: BaseArtifacts,
    decision: Option<DecisionArtifacts>,
    phase: PersistedPhase,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum PersistedPhase {
    Paused,
    Invoking,
    Ready,
    Resumed {
        blocks_executed: usize,
        canonical_output_sha256: String,
    },
    Failed {
        failure: BoundaryFailure,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DecisionCapture {
    schema_version: String,
    raw_output_sha256: String,
    parsed_decision: Option<ParsedDecision>,
    signed_action_count: usize,
    failure: Option<BoundaryFailure>,
    provenance_manifest: Option<String>,
    provenance_manifest_sha256: Option<String>,
}

#[derive(Serialize)]
struct ResumeCapture {
    blocks_executed: usize,
    canonical_output_sha256: String,
}

fn verify_base(root: &Path, artifacts: &BaseArtifacts) -> Result<(), BoundaryError> {
    for artifact in [
        &artifacts.initial_state,
        &artifacts.prefix_actions,
        &artifacts.observation,
        &artifacts.observation_provenance,
    ] {
        read_artifact(root, artifact)?;
    }
    Ok(())
}

fn verify_decision(root: &Path, artifacts: &DecisionArtifacts) -> Result<(), BoundaryError> {
    let raw = read_artifact(root, &artifacts.raw_output)?;
    let capture_bytes = read_artifact(root, &artifacts.capture)?;
    let actions = read_artifact(root, &artifacts.signed_actions)?;
    let capture: DecisionCapture =
        serde_json::from_slice(&capture_bytes).map_err(BoundaryError::JsonDecode)?;
    if capture.schema_version != "operator-boundary-capture.v1"
        || capture.raw_output_sha256 != hash_hex(&raw)
        || capture.signed_action_count != decode_actions(&actions)?.len()
    {
        return Err(BoundaryError::InvalidState(
            "decision capture does not match retained raw output and actions".to_owned(),
        ));
    }
    Ok(())
}

fn create_boundary_directory(path: &Path) -> Result<(), BoundaryError> {
    let parent = path.parent().ok_or_else(|| {
        BoundaryError::InvalidState("boundary root has no parent directory".to_owned())
    })?;
    fs::create_dir_all(parent)
        .map_err(|source| io_error("create boundary parent", parent, source))?;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|source| io_error("create boundary directory", path, source))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("restrict boundary directory", path, source))
}

fn canonical_directory(path: &Path) -> Result<PathBuf, BoundaryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect boundary directory", path, source))?;
    if !metadata.file_type().is_dir() {
        return Err(BoundaryError::InvalidState(
            "boundary root is not a real directory".to_owned(),
        ));
    }
    fs::canonicalize(path)
        .map_err(|source| io_error("canonicalize boundary directory", path, source))
}

fn write_artifact(
    root: &Path,
    name: &'static str,
    bytes: &[u8],
) -> Result<ArtifactCommitment, BoundaryError> {
    let path = root.join(name);
    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW);
    let mut file = options
        .open(&path)
        .map_err(|source| io_error("create boundary artifact", &path, source))?;
    use std::io::Write as _;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("write boundary artifact", &path, source))?;
    Ok(ArtifactCommitment {
        path: name.to_owned(),
        bytes: bytes.len() as u64,
        sha256: hash_hex(bytes),
    })
}

fn write_artifact_idempotent(
    root: &Path,
    name: &'static str,
    bytes: &[u8],
) -> Result<(), BoundaryError> {
    match write_artifact(root, name, bytes) {
        Ok(_) => Ok(()),
        Err(BoundaryError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
            let retained = fs::read(root.join(name)).map_err(|source| {
                io_error("read existing boundary artifact", &root.join(name), source)
            })?;
            if retained == bytes {
                Ok(())
            } else {
                Err(BoundaryError::InvalidState(format!(
                    "existing {name} differs from deterministic retry"
                )))
            }
        }
        Err(error) => Err(error),
    }
}

fn read_artifact(root: &Path, commitment: &ArtifactCommitment) -> Result<Vec<u8>, BoundaryError> {
    if commitment.path.is_empty()
        || commitment.path.contains('/')
        || commitment.path == STATE_FILE
        || commitment.path.starts_with('.')
    {
        return Err(BoundaryError::InvalidState(
            "artifact commitment contains an unsafe path".to_owned(),
        ));
    }
    let path = root.join(&commitment.path);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|source| io_error("inspect boundary artifact", &path, source))?;
    if !metadata.file_type().is_file() {
        return Err(BoundaryError::InvalidState(format!(
            "{} is not a regular boundary artifact",
            commitment.path
        )));
    }
    let bytes =
        fs::read(&path).map_err(|source| io_error("read boundary artifact", &path, source))?;
    if commitment.bytes != bytes.len() as u64 || commitment.sha256 != hash_hex(&bytes) {
        return Err(BoundaryError::ArtifactMismatch(commitment.path.clone()));
    }
    Ok(bytes)
}

fn write_state(root: &Path, state: &PersistedState) -> Result<(), BoundaryError> {
    let mut bytes = serde_json::to_vec_pretty(state).map_err(BoundaryError::JsonEncode)?;
    bytes.push(b'\n');
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(
        ".boundary-state-{}-{sequence}.tmp",
        std::process::id()
    ));
    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW);
    let mut file = options
        .open(&temporary)
        .map_err(|source| io_error("create boundary state temporary", &temporary, source))?;
    use std::io::Write as _;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("write boundary state temporary", &temporary, source))?;
    let destination = root.join(STATE_FILE);
    fs::rename(&temporary, &destination)
        .map_err(|source| io_error("commit boundary state", &destination, source))?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error("restrict boundary state", &destination, source))?;
    fs::File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync boundary directory", root, source))
}

fn read_state(root: &Path) -> Result<PersistedState, BoundaryError> {
    let path = root.join(STATE_FILE);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|source| io_error("inspect boundary state", &path, source))?;
    if !metadata.file_type().is_file() {
        return Err(BoundaryError::InvalidState(
            "boundary state is not a regular file".to_owned(),
        ));
    }
    let bytes = fs::read(&path).map_err(|source| io_error("read boundary state", &path, source))?;
    let state: PersistedState =
        serde_json::from_slice(&bytes).map_err(BoundaryError::JsonDecode)?;
    if state.schema_version != BOUNDARY_SCHEMA_VERSION {
        return Err(BoundaryError::InvalidState(
            "unsupported decision-boundary schema".to_owned(),
        ));
    }
    match (&state.phase, &state.decision) {
        (PersistedPhase::Paused | PersistedPhase::Invoking, None) => {}
        (PersistedPhase::Ready | PersistedPhase::Resumed { .. }, Some(_)) => {}
        (PersistedPhase::Failed { .. }, _) => {}
        _ => {
            return Err(BoundaryError::InvalidState(
                "boundary phase and decision artifacts are inconsistent".to_owned(),
            ));
        }
    }
    Ok(state)
}

fn encode_actions(actions: &[SignedAction<Action>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ACTION_MAGIC);
    bytes.extend_from_slice(&(actions.len() as u64).to_be_bytes());
    for action in actions {
        let mut canonical = Vec::new();
        action.write(&mut canonical);
        bytes.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&canonical);
    }
    bytes
}

fn decode_actions(bytes: &[u8]) -> Result<Vec<SignedAction<Action>>, BoundaryError> {
    let mut reader = ActionReader { bytes, offset: 0 };
    if reader.take(ACTION_MAGIC.len())? != ACTION_MAGIC {
        return Err(BoundaryError::InvalidActions(
            "unsupported action capture header".to_owned(),
        ));
    }
    let count = reader.read_length()?;
    if count > MAX_ACTIONS_PER_BLOCK {
        return Err(BoundaryError::InvalidActions(format!(
            "decision contains {count} actions; maximum is {MAX_ACTIONS_PER_BLOCK}"
        )));
    }
    let mut actions = Vec::with_capacity(count);
    for _ in 0..count {
        let canonical = reader.read_framed()?;
        actions.push(
            decode_signed_action(canonical, &())
                .map_err(|error| BoundaryError::InvalidActions(error.to_string()))?,
        );
    }
    if reader.offset != bytes.len() {
        return Err(BoundaryError::InvalidActions(
            "action capture has trailing bytes".to_owned(),
        ));
    }
    Ok(actions)
}

struct ActionReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ActionReader<'a> {
    fn read_length(&mut self) -> Result<usize, BoundaryError> {
        usize::try_from(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .expect("exact action length requested"),
        ))
        .map_err(|_| BoundaryError::InvalidActions("length does not fit platform".to_owned()))
    }

    fn read_framed(&mut self) -> Result<&'a [u8], BoundaryError> {
        let length = self.read_length()?;
        self.take(length)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BoundaryError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| BoundaryError::InvalidActions("action offset overflow".to_owned()))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| BoundaryError::InvalidActions("truncated action capture".to_owned()))?;
        self.offset = end;
        Ok(value)
    }
}

fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>, BoundaryError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(BoundaryError::JsonEncode)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn hash_hex(bytes: &[u8]) -> String {
    hash_value_hex(Sha256::digest(bytes).as_slice())
}

fn hash_value_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> BoundaryError {
    BoundaryError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

/// Durable-boundary construction, host, capture, or deterministic resume error.
#[derive(Debug)]
pub enum BoundaryError {
    InvalidCheckpoint(String),
    PrefixFailed(BoundaryFailure),
    InvalidState(String),
    InvalidPhase {
        expected: BoundaryPhase,
        actual: BoundaryPhase,
    },
    ArtifactMismatch(String),
    InvalidActions(String),
    Observation(String),
    ResumeFailed(BoundaryFailure),
    Setup(RunnerSetupError),
    Runner(RunnerError),
    Replay(TraceReplayError),
    JsonEncode(serde_json::Error),
    JsonDecode(serde_json::Error),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl BoundaryError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidCheckpoint(_) => "LAB_BOUNDARY_CHECKPOINT_INVALID",
            Self::PrefixFailed(_) => "LAB_BOUNDARY_PREFIX_FAILED",
            Self::InvalidState(_) => "LAB_BOUNDARY_STATE_INVALID",
            Self::InvalidPhase { .. } => "LAB_BOUNDARY_PHASE_INVALID",
            Self::ArtifactMismatch(_) => "LAB_BOUNDARY_ARTIFACT_MISMATCH",
            Self::InvalidActions(_) => "LAB_BOUNDARY_ACTIONS_INVALID",
            Self::Observation(_) => "LAB_BOUNDARY_OBSERVATION_INVALID",
            Self::ResumeFailed(_) => "LAB_BOUNDARY_RESUME_FAILED",
            Self::Setup(_) => "LAB_BOUNDARY_SETUP_FAILED",
            Self::Runner(_) => "LAB_BOUNDARY_RUNNER_FAILED",
            Self::Replay(_) => "LAB_BOUNDARY_REPLAY_FAILED",
            Self::JsonEncode(_) | Self::JsonDecode(_) => "LAB_BOUNDARY_JSON_FAILED",
            Self::Io { .. } => "LAB_BOUNDARY_IO_FAILED",
        }
    }
}

impl fmt::Display for BoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCheckpoint(reason) => {
                write!(formatter, "invalid boundary checkpoint: {reason}")
            }
            Self::PrefixFailed(failure) => write!(
                formatter,
                "deterministic prefix failed ({}): {}",
                failure.code, failure.message
            ),
            Self::InvalidState(reason) => {
                write!(formatter, "invalid durable boundary state: {reason}")
            }
            Self::InvalidPhase { expected, actual } => write!(
                formatter,
                "boundary phase is {actual:?}; expected {expected:?}"
            ),
            Self::ArtifactMismatch(path) => write!(
                formatter,
                "boundary artifact {path} failed length or hash verification"
            ),
            Self::InvalidActions(reason) => {
                write!(formatter, "invalid captured decision actions: {reason}")
            }
            Self::Observation(reason) => {
                write!(formatter, "invalid captured observation: {reason}")
            }
            Self::ResumeFailed(failure) => write!(
                formatter,
                "deterministic resume failed ({}): {}",
                failure.code, failure.message
            ),
            Self::Setup(error) => write!(
                formatter,
                "cannot construct deterministic boundary runner: {error}"
            ),
            Self::Runner(error) => {
                write!(formatter, "deterministic boundary runner failed: {error}")
            }
            Self::Replay(error) => write!(
                formatter,
                "cannot replay durable boundary checkpoint: {error}"
            ),
            Self::JsonEncode(error) => {
                write!(formatter, "cannot encode durable boundary JSON: {error}")
            }
            Self::JsonDecode(error) => {
                write!(formatter, "cannot decode durable boundary JSON: {error}")
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "cannot {operation} {}: {source}", path.display()),
        }
    }
}

impl Error for BoundaryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Setup(error) => Some(error),
            Self::Runner(error) => Some(error),
            Self::Replay(error) => Some(error),
            Self::JsonEncode(error) | Self::JsonDecode(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
