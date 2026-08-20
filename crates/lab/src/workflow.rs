//! High-level, deterministic operations used by the `rcht-lab` command line.
//!
//! These functions are deliberately thin compositions of the fixture loader,
//! deterministic runner, immutable artifact store, replay engine, and metric
//! verifiers. They do not provide an alternate simulation or audit path.

use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use commonware_cryptography::{Signer as _, ed25519};
use rachet_core::{
    blocks::ConsensusNodeId,
    primitives::{ChainId, Sha256Digest},
};
use serde::{Deserialize, Serialize};

use crate::{
    experiment::RunId,
    fixtures::{FixtureSetKind, IntegrityHash, PublicFixtureLoader},
    metrics::{LaboratoryMetricInput, LaboratoryMetricReport, ResourceAccounting},
    replay::{ReplayCapture, ReplayReport, replay_bundle, replay_run},
    run_artifacts::{RunArtifactBundle, RunArtifactStore, RunOutcome},
    simulator::{
        DeterministicRunner, LaboratoryMechanism, RunnerConfig, ScriptedBlock, ScriptedRun,
    },
};

/// Result of exercising a calibration or formal fixture partition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureExerciseReport {
    pub fixture_set: &'static str,
    pub fixtures_verified: usize,
    pub claims_verified: usize,
    pub blocks_executed: usize,
    pub runtime_audit_present: bool,
}

/// Result of capturing one immutable deterministic run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CaptureReport {
    pub run_id: String,
    pub mechanism: &'static str,
    pub blocks_executed: usize,
    pub artifacts_captured: usize,
    pub outcome: RunOutcome,
}

/// Result of a complete retained-run audit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditReport {
    pub run_id: String,
    pub artifacts_verified: usize,
    pub seeds_verified: usize,
    pub blocks_replayed: usize,
    pub model_calls_during_replay: u64,
    pub resources_reconciled: bool,
    pub metrics_diagnostic_only: bool,
}

/// One artifact-level difference between two verified runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactDifference {
    pub path: String,
    pub left_sha256: IntegrityHash,
    pub right_sha256: IntegrityHash,
}

/// Deterministic comparison of two immutable runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ComparisonReport {
    pub left_run_id: String,
    pub right_run_id: String,
    pub same_outcome: bool,
    pub identical_artifacts: bool,
    pub differences: Vec<ArtifactDifference>,
}

/// Inputs that identify a retained run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunReference {
    pub experiment_root: PathBuf,
    pub run_id: RunId,
}

/// Inputs for immutable exploit promotion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExploitPromotion {
    pub source: RunReference,
    pub exploits_root: PathBuf,
    pub exploit_id: String,
    pub name: String,
    pub operator_manifest: Option<PathBuf>,
    pub root_cause: Option<PathBuf>,
}

/// Result of exploit promotion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExploitPromotionReport {
    pub exploit_id: String,
    pub exploit_root: PathBuf,
    pub discovery_run: String,
    pub status: &'static str,
}

/// Result of independently replaying a promoted exploit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExploitReplayReport {
    pub exploit_id: String,
    pub blocks_replayed: usize,
    pub model_calls: u64,
    pub reproduced: bool,
}

/// Exercises the real deterministic runner, optionally after fully verifying a
/// calibration or formal fixture partition and its repository capabilities.
/// Smoke callers must use [`crate::smoke::orchestrate_smoke`], which cannot run
/// without public/private fixtures, declared operators, resolutions, and capture.
pub fn exercise_fixture_set(
    expected: FixtureSetKind,
    public_root: Option<&Path>,
    repository_root: Option<&Path>,
    seed: u64,
    blocks: usize,
) -> Result<FixtureExerciseReport, WorkflowError> {
    if expected == FixtureSetKind::Smoke {
        return Err(WorkflowError::InvalidInput(
            "smoke requires fixture-backed orchestrate_smoke inputs".to_owned(),
        ));
    }
    if blocks == 0 {
        return Err(WorkflowError::InvalidInput(
            "block count must be greater than zero".to_owned(),
        ));
    }
    let (fixtures_verified, claims_verified) = match (public_root, repository_root) {
        (Some(public), Some(repositories)) => {
            let loaded = PublicFixtureLoader::new(public, repositories)
                .map_err(|error| WorkflowError::Fixture(error.to_string()))?
                .load()
                .map_err(|error| WorkflowError::Fixture(error.to_string()))?;
            if loaded.set() != expected {
                return Err(WorkflowError::FixtureSet {
                    expected: fixture_set_name(expected),
                    actual: fixture_set_name(loaded.set()),
                });
            }
            let claims = loaded
                .fixtures()
                .iter()
                .map(|fixture| fixture.definition().claims.len())
                .try_fold(0_usize, |total, count| total.checked_add(count))
                .ok_or_else(|| {
                    WorkflowError::InvalidInput("fixture claim count overflow".to_owned())
                })?;
            (loaded.fixtures().len(), claims)
        }
        (None, None) => (0, 0),
        _ => {
            return Err(WorkflowError::InvalidInput(
                "public fixture and repository roots must be supplied together".to_owned(),
            ));
        }
    };

    let mechanism = match expected {
        FixtureSetKind::Smoke => LaboratoryMechanism::M00RecordOnly,
        FixtureSetKind::Calibration | FixtureSetKind::Formal => {
            LaboratoryMechanism::M01NaiveReputation
        }
    };
    let output = DeterministicRunner::new(runner_config(seed), mechanism)
        .map_err(|error| WorkflowError::Runner(error.to_string()))?
        .run(ScriptedRun {
            operators: Vec::new(),
            blocks: (0..blocks).map(|_| ScriptedBlock::empty()).collect(),
        })
        .map_err(|error| WorkflowError::Runner(error.to_string()))?;

    Ok(FixtureExerciseReport {
        fixture_set: fixture_set_name(expected),
        fixtures_verified,
        claims_verified,
        blocks_executed: output.blocks.len(),
        runtime_audit_present: !output.runtime_audit.is_empty(),
    })
}

/// Executes real M00/M01 transitions and commits their exact replay artifacts.
pub fn capture_run(
    reference: &RunReference,
    mechanism: LaboratoryMechanism,
    seed: u64,
    blocks: usize,
) -> Result<CaptureReport, WorkflowError> {
    if blocks == 0 {
        return Err(WorkflowError::InvalidInput(
            "block count must be greater than zero".to_owned(),
        ));
    }
    let config = runner_config(seed);
    let output = DeterministicRunner::new(config.clone(), mechanism)
        .map_err(|error| WorkflowError::Runner(error.to_string()))?
        .run(ScriptedRun {
            operators: Vec::new(),
            blocks: (0..blocks).map(|_| ScriptedBlock::empty()).collect(),
        })
        .map_err(|error| WorkflowError::Runner(error.to_string()))?;
    let capture = ReplayCapture::from_completed_run(&config, mechanism, &[], &output)
        .map_err(|error| WorkflowError::Replay(error.to_string()))?;

    let resources = ResourceAccounting::from_records(Vec::new())
        .map_err(|error| WorkflowError::Audit(error.to_string()))?;
    let metrics = LaboratoryMetricReport::derive(&LaboratoryMetricInput::default(), &resources)
        .map_err(|error| WorkflowError::Audit(error.to_string()))?;
    let mut bundle = RunArtifactBundle {
        initial_state: Vec::new(),
        observations_jsonl: Vec::new(),
        decisions_jsonl: Vec::new(),
        signed_actions: Vec::new(),
        blocks: Vec::new(),
        events: Vec::new(),
        economic_state_jsonl: Vec::new(),
        resources_json: resources
            .to_json_bytes()
            .map_err(|error| WorkflowError::Json(error.to_string()))?,
        metrics_json: metrics
            .to_json_bytes()
            .map_err(|error| WorkflowError::Json(error.to_string()))?,
        discovered_strategies_markdown: b"# Discovered strategies\n\nNone recorded.\n".to_vec(),
    };
    let outcome = capture.apply_to(&mut bundle);
    let manifest = RunArtifactStore::capture(
        &reference.experiment_root,
        reference.run_id,
        outcome.clone(),
        &bundle,
    )
    .map_err(|error| WorkflowError::Artifact(error.to_string()))?;

    Ok(CaptureReport {
        run_id: reference.run_id.to_string(),
        mechanism: mechanism_name(mechanism),
        blocks_executed: output.blocks.len(),
        artifacts_captured: manifest.artifacts.len(),
        outcome,
    })
}

/// Replays one verified run without any model boundary.
pub fn replay(reference: &RunReference) -> Result<ReplayReport, WorkflowError> {
    replay_run(&reference.experiment_root, reference.run_id)
        .map_err(|error| WorkflowError::Replay(error.to_string()))
}

/// Verifies manifests, replay surfaces, resource reconciliation, and metric markers.
pub fn audit(reference: &RunReference) -> Result<AuditReport, WorkflowError> {
    let loaded = RunArtifactStore::load(&reference.experiment_root, reference.run_id)
        .map_err(|error| WorkflowError::Artifact(error.to_string()))?;
    let replay = replay_bundle(&loaded.bundle, &loaded.manifest.outcome)
        .map_err(|error| WorkflowError::Replay(error.to_string()))?;
    let resources: ResourceAccounting = serde_json::from_slice(&loaded.bundle.resources_json)
        .map_err(|error| WorkflowError::Audit(format!("invalid resources.json: {error}")))?;
    resources
        .verify()
        .map_err(|error| WorkflowError::Audit(error.to_string()))?;
    let metrics: LaboratoryMetricReport = serde_json::from_slice(&loaded.bundle.metrics_json)
        .map_err(|error| WorkflowError::Audit(format!("invalid metrics.json: {error}")))?;
    metrics
        .verify_diagnostic_marker()
        .map_err(|error| WorkflowError::Audit(error.to_string()))?;
    if metrics.resource_use != resources.totals {
        return Err(WorkflowError::Audit(
            "metrics resource totals do not match resources.json".to_owned(),
        ));
    }
    Ok(AuditReport {
        run_id: reference.run_id.to_string(),
        artifacts_verified: loaded.manifest.artifacts.len(),
        seeds_verified: loaded.manifest.seeds.len(),
        blocks_replayed: replay.blocks_replayed,
        model_calls_during_replay: replay.model_calls,
        resources_reconciled: true,
        metrics_diagnostic_only: true,
    })
}

/// Compares hashes from two independently verified immutable manifests.
pub fn compare(
    left: &RunReference,
    right: &RunReference,
) -> Result<ComparisonReport, WorkflowError> {
    let left_loaded = RunArtifactStore::load(&left.experiment_root, left.run_id)
        .map_err(|error| WorkflowError::Artifact(error.to_string()))?;
    let right_loaded = RunArtifactStore::load(&right.experiment_root, right.run_id)
        .map_err(|error| WorkflowError::Artifact(error.to_string()))?;
    let mut differences = Vec::new();
    for (left_entry, right_entry) in left_loaded
        .manifest
        .artifacts
        .iter()
        .zip(&right_loaded.manifest.artifacts)
    {
        if left_entry.path != right_entry.path {
            return Err(WorkflowError::Audit(
                "verified artifact inventories are not aligned".to_owned(),
            ));
        }
        if left_entry.sha256 != right_entry.sha256 {
            differences.push(ArtifactDifference {
                path: left_entry.path.clone(),
                left_sha256: left_entry.sha256,
                right_sha256: right_entry.sha256,
            });
        }
    }
    Ok(ComparisonReport {
        left_run_id: left.run_id.to_string(),
        right_run_id: right.run_id.to_string(),
        same_outcome: left_loaded.manifest.outcome == right_loaded.manifest.outcome,
        identical_artifacts: differences.is_empty(),
        differences,
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExploitDiscovery {
    schema_version: u32,
    exploit_id: String,
    name: String,
    discovery_run: String,
    discovering_operator: String,
    mechanism_versions: Vec<String>,
    required_preconditions: Vec<String>,
    strategy: String,
    useful_validation_performed: String,
    reputation_or_reward_obtained: String,
    resource_cost: String,
    root_cause: String,
    affected_claims: Vec<String>,
    status: String,
    replacement_mechanism_hypothesis: Option<String>,
    replay_inputs_sha256: ReplayInputHashes,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayInputHashes {
    initial_state: IntegrityHash,
    action_trace: IntegrityHash,
    expected_outcome: IntegrityHash,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotedExpectedOutcome {
    outcome: RunOutcome,
    blocks_hex: String,
    events_hex: String,
    economic_state_jsonl_hex: String,
}

/// Promotes a verified and successfully replayed run into an immutable exploit fixture.
pub fn promote_exploit(
    request: &ExploitPromotion,
) -> Result<ExploitPromotionReport, WorkflowError> {
    validate_portable_identifier("exploit ID", &request.exploit_id)?;
    validate_text("exploit name", &request.name)?;
    let loaded = RunArtifactStore::load(&request.source.experiment_root, request.source.run_id)
        .map_err(|error| WorkflowError::Artifact(error.to_string()))?;
    replay_bundle(&loaded.bundle, &loaded.manifest.outcome)
        .map_err(|error| WorkflowError::Replay(error.to_string()))?;

    let exploit_root = request.exploits_root.join(&request.exploit_id);
    fs::create_dir_all(&request.exploits_root)
        .map_err(|error| io_error("create exploits root", &request.exploits_root, error))?;
    fs::create_dir(&exploit_root).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            WorkflowError::ExploitExists(exploit_root.clone())
        } else {
            io_error("create exploit directory", &exploit_root, error)
        }
    })?;

    let result = (|| {
        let expected = PromotedExpectedOutcome {
            outcome: loaded.manifest.outcome.clone(),
            blocks_hex: encode_hex(&loaded.bundle.blocks),
            events_hex: encode_hex(&loaded.bundle.events),
            economic_state_jsonl_hex: encode_hex(&loaded.bundle.economic_state_jsonl),
        };
        let expected_bytes = json_bytes(&expected)?;
        let mechanism_bytes =
            read_required(&request.source.experiment_root.join("mechanism-set.toml"))?;
        let operator_bytes = match &request.operator_manifest {
            Some(path) => read_required(path)?,
            None => read_first_regular(&request.source.experiment_root.join("operators"))?,
        };
        let root_cause = match &request.root_cause {
            Some(path) => read_required(path)?,
            None => b"# Root cause\n\nPending causal analysis.\n".to_vec(),
        };
        let discovery = ExploitDiscovery {
            schema_version: 1,
            exploit_id: request.exploit_id.clone(),
            name: request.name.clone(),
            discovery_run: request.source.run_id.to_string(),
            discovering_operator: "retained-operator-manifest".to_owned(),
            mechanism_versions: vec!["retained-mechanism-set".to_owned()],
            required_preconditions: vec!["retained initial state".to_owned()],
            strategy: "retained action trace".to_owned(),
            useful_validation_performed: "see retained observation trace".to_owned(),
            reputation_or_reward_obtained: "see retained expected outcome".to_owned(),
            resource_cost: "see discovery run resources.json".to_owned(),
            root_cause: "see root-cause.md".to_owned(),
            affected_claims: Vec::new(),
            status: "reproduced".to_owned(),
            replacement_mechanism_hypothesis: None,
            replay_inputs_sha256: ReplayInputHashes {
                initial_state: IntegrityHash::digest(&loaded.bundle.initial_state),
                action_trace: IntegrityHash::digest(&loaded.bundle.signed_actions),
                expected_outcome: IntegrityHash::digest(&expected_bytes),
            },
        };

        write_new(
            &exploit_root.join("README.md"),
            format!(
                "# {} — {}\n\nPromoted from run `{}`.\n",
                request.exploit_id, request.name, request.source.run_id
            )
            .as_bytes(),
        )?;
        write_new(
            &exploit_root.join("discovery.json"),
            &json_bytes(&discovery)?,
        )?;
        write_new(&exploit_root.join("mechanism-set.toml"), &mechanism_bytes)?;
        write_new(
            &exploit_root.join("initial-state.bin"),
            &loaded.bundle.initial_state,
        )?;
        write_new(
            &exploit_root.join("operator-manifest.toml"),
            &operator_bytes,
        )?;
        write_new(
            &exploit_root.join("observation-trace.jsonl"),
            &loaded.bundle.observations_jsonl,
        )?;
        write_new(
            &exploit_root.join("action-trace.bin"),
            &loaded.bundle.signed_actions,
        )?;
        write_new(&exploit_root.join("expected-outcome.json"), &expected_bytes)?;
        write_new(&exploit_root.join("root-cause.md"), &root_cause)?;
        write_new(
            &exploit_root.join("reproducer.toml"),
            format!(
                "schema_version = 1\nexploit_id = {:?}\n",
                request.exploit_id
            )
            .as_bytes(),
        )?;
        write_new(
            &exploit_root.join("status.toml"),
            b"schema_version = 1\nstatus = \"reproduced\"\n",
        )
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&exploit_root);
        return Err(error);
    }

    Ok(ExploitPromotionReport {
        exploit_id: request.exploit_id.clone(),
        exploit_root,
        discovery_run: request.source.run_id.to_string(),
        status: "reproduced",
    })
}

/// Verifies promoted replay-input hashes and executes exact action-trace replay.
pub fn replay_exploit(exploit_root: &Path) -> Result<ExploitReplayReport, WorkflowError> {
    let discovery_bytes = read_required(&exploit_root.join("discovery.json"))?;
    let discovery: ExploitDiscovery = serde_json::from_slice(&discovery_bytes)
        .map_err(|error| WorkflowError::Exploit(format!("invalid discovery.json: {error}")))?;
    let initial_state = read_required(&exploit_root.join("initial-state.bin"))?;
    let actions = read_required(&exploit_root.join("action-trace.bin"))?;
    let expected_bytes = read_required(&exploit_root.join("expected-outcome.json"))?;
    verify_hash(
        "initial-state.bin",
        discovery.replay_inputs_sha256.initial_state,
        &initial_state,
    )?;
    verify_hash(
        "action-trace.bin",
        discovery.replay_inputs_sha256.action_trace,
        &actions,
    )?;
    verify_hash(
        "expected-outcome.json",
        discovery.replay_inputs_sha256.expected_outcome,
        &expected_bytes,
    )?;
    let expected: PromotedExpectedOutcome =
        serde_json::from_slice(&expected_bytes).map_err(|error| {
            WorkflowError::Exploit(format!("invalid expected-outcome.json: {error}"))
        })?;
    let bundle = RunArtifactBundle {
        initial_state,
        observations_jsonl: Vec::new(),
        decisions_jsonl: Vec::new(),
        signed_actions: actions,
        blocks: decode_hex(&expected.blocks_hex)?,
        events: decode_hex(&expected.events_hex)?,
        economic_state_jsonl: decode_hex(&expected.economic_state_jsonl_hex)?,
        resources_json: b"{}".to_vec(),
        metrics_json: b"{}".to_vec(),
        discovered_strategies_markdown: Vec::new(),
    };
    let replay = replay_bundle(&bundle, &expected.outcome)
        .map_err(|error| WorkflowError::Replay(error.to_string()))?;
    Ok(ExploitReplayReport {
        exploit_id: discovery.exploit_id,
        blocks_replayed: replay.blocks_replayed,
        model_calls: replay.model_calls,
        reproduced: true,
    })
}

pub(crate) fn runner_config(seed: u64) -> RunnerConfig {
    RunnerConfig {
        seed,
        chain_id: ChainId::new([0x52; 32]),
        blocks_per_epoch: 10,
        consensus_node: ConsensusNodeId::from(ed25519::PrivateKey::from_seed(seed).public_key()),
        genesis_parent_block: Sha256Digest::from([0_u8; 32]),
        genesis_timestamp_ms: 1_700_000_000_000,
        block_interval_ms: 1_000,
    }
}

const fn fixture_set_name(set: FixtureSetKind) -> &'static str {
    match set {
        FixtureSetKind::Smoke => "smoke",
        FixtureSetKind::Calibration => "calibration",
        FixtureSetKind::Formal => "formal",
    }
}

const fn mechanism_name(mechanism: LaboratoryMechanism) -> &'static str {
    match mechanism {
        LaboratoryMechanism::M00RecordOnly => "m00_record_only",
        LaboratoryMechanism::M01NaiveReputation => "m01_naive_reputation",
    }
}

fn validate_portable_identifier(label: &str, value: &str) -> Result<(), WorkflowError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(WorkflowError::InvalidInput(format!(
            "{label} must be 1..=128 ASCII letters, digits, '-' or '_'"
        )));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str) -> Result<(), WorkflowError> {
    if value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
        return Err(WorkflowError::InvalidInput(format!(
            "{label} must be 1..=4096 bytes without control characters"
        )));
    }
    Ok(())
}

fn read_required(path: &Path) -> Result<Vec<u8>, WorkflowError> {
    fs::read(path).map_err(|error| io_error("read required file", path, error))
}

fn read_first_regular(root: &Path) -> Result<Vec<u8>, WorkflowError> {
    let mut paths = fs::read_dir(root)
        .map_err(|error| io_error("list operator manifests", root, error))?
        .map(|entry| {
            entry
                .map(|value| value.path())
                .map_err(|error| io_error("read operator manifest entry", root, error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_error("inspect operator manifest", &path, error))?;
        if metadata.file_type().is_file() {
            return read_required(&path);
        }
    }
    Err(WorkflowError::Exploit(
        "experiment contains no regular operator manifest".to_owned(),
    ))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), WorkflowError> {
    use std::io::Write as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error("create immutable exploit artifact", path, error))?;
    file.write_all(bytes)
        .map_err(|error| io_error("write immutable exploit artifact", path, error))
}

fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, WorkflowError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| WorkflowError::Json(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn verify_hash(label: &str, expected: IntegrityHash, bytes: &[u8]) -> Result<(), WorkflowError> {
    let actual = IntegrityHash::digest(bytes);
    if actual != expected {
        return Err(WorkflowError::Exploit(format!(
            "{label} hashes to {actual}; discovery commits to {expected}"
        )));
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, WorkflowError> {
    if !value.len().is_multiple_of(2) {
        return Err(WorkflowError::Exploit(
            "expected outcome contains odd-length hexadecimal text".to_owned(),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            match (high, low) {
                (Some(high), Some(low)) => Ok((high << 4) | low),
                _ => Err(WorkflowError::Exploit(
                    "expected outcome contains non-lowercase hexadecimal text".to_owned(),
                )),
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

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> WorkflowError {
    WorkflowError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

/// Stable categories for high-level laboratory operation failures.
#[derive(Debug)]
pub enum WorkflowError {
    InvalidInput(String),
    Fixture(String),
    FixtureSet {
        expected: &'static str,
        actual: &'static str,
    },
    Runner(String),
    Artifact(String),
    Replay(String),
    Audit(String),
    Exploit(String),
    ExploitExists(PathBuf),
    Json(String),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl WorkflowError {
    /// Stable machine-readable code used by the CLI error envelope.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "LAB_INPUT_INVALID",
            Self::Fixture(_) | Self::FixtureSet { .. } => "LAB_FIXTURE_INVALID",
            Self::Runner(_) => "LAB_RUN_FAILED",
            Self::Artifact(_) => "LAB_ARTIFACT_INVALID",
            Self::Replay(_) => "LAB_REPLAY_FAILED",
            Self::Audit(_) => "LAB_AUDIT_FAILED",
            Self::Exploit(_) => "LAB_EXPLOIT_INVALID",
            Self::ExploitExists(_) => "LAB_EXPLOIT_EXISTS",
            Self::Json(_) => "LAB_JSON_FAILED",
            Self::Io { .. } => "LAB_IO_FAILED",
        }
    }
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(reason) => write!(formatter, "invalid laboratory input: {reason}"),
            Self::Fixture(reason) => write!(formatter, "fixture verification failed: {reason}"),
            Self::FixtureSet { expected, actual } => {
                write!(formatter, "expected {expected} fixture set, found {actual}")
            }
            Self::Runner(reason) => write!(formatter, "deterministic runner failed: {reason}"),
            Self::Artifact(reason) => write!(formatter, "artifact verification failed: {reason}"),
            Self::Replay(reason) => write!(formatter, "exact replay failed: {reason}"),
            Self::Audit(reason) => write!(formatter, "audit failed: {reason}"),
            Self::Exploit(reason) => write!(formatter, "exploit artifact is invalid: {reason}"),
            Self::ExploitExists(path) => write!(
                formatter,
                "exploit directory already exists and will not be overwritten: {}",
                path.display()
            ),
            Self::Json(reason) => write!(formatter, "JSON encoding failed: {reason}"),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "cannot {operation} {}: {source}", path.display()),
        }
    }
}

impl Error for WorkflowError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
