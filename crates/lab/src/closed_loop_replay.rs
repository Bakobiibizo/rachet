//! Capture and model-free replay for closed-loop operator runs.
//!
//! External operator invocations are converted into owned audit records before
//! deterministic execution starts. The execution and replay paths receive only
//! the exact initial state and already-signed actions. Observations, prompts,
//! raw outputs, parsed decisions, provider metadata, and provenance commitments
//! remain immutable evidence, but are never interpreted to recreate an action.

use std::{collections::BTreeSet, error::Error, fmt};

use commonware_codec::Write as _;
use rachet_core::{
    actions::{Action, SignedAction},
    state::StateEntry,
};
use rachet_operator::{
    agentctl::{AgentctlInvocationRecord, AgentctlOutcome},
    decision::ParsedDecision,
    observation::{ObservationProvenance, ObservationSnapshot},
    provenance::{OperatorProvenanceStore, ProvenanceStatus},
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    experiment::RunId,
    fixtures::IntegrityHash,
    metrics::{LaboratoryMetricInput, LaboratoryMetricReport, ResourceAccounting, ResourceRecord},
    replay::{ReplayCapture, TraceReplayError},
    run_artifacts::{RunArtifactBundle, RunArtifactError, RunArtifactStore, RunOutcome},
    simulator::{
        DeterministicRunner, LaboratoryMechanism, RunnerConfig, RunnerError, RunnerSetupError,
    },
};

const OBSERVATION_AUDIT_SCHEMA: &str = "closed-loop-observation.v1";
const DECISION_AUDIT_SCHEMA: &str = "closed-loop-decision.v1";

/// One successful external decision converted into owned replay and audit input.
///
/// Construction verifies the immutable operator provenance while it is still
/// available. No executable, provider handle, operator key, or callback is
/// retained by this value.
#[derive(Clone, Debug)]
pub struct CapturedOperatorDecision {
    operator_id: String,
    model: String,
    provider: String,
    observation: Vec<u8>,
    observation_provenance: ObservationProvenance,
    system_prompt: Vec<u8>,
    prompt: Vec<u8>,
    raw_output: Vec<u8>,
    parsed_decision: ParsedDecision,
    signed_actions: Vec<SignedAction<Action>>,
    provenance_manifest_sha256: String,
    resource: ResourceRecord,
}

impl CapturedOperatorDecision {
    /// Freezes one successful `agentctl` result into model-free run input.
    pub fn from_agentctl(
        operator_id: impl Into<String>,
        system_prompt: &[u8],
        observation: &ObservationSnapshot,
        invocation: &AgentctlInvocationRecord,
    ) -> Result<Self, ClosedLoopCaptureError> {
        let operator_id = operator_id.into();
        validate_operator_id(&operator_id)?;
        if invocation.system_prompt_sha256 != hash_hex(system_prompt)
            || invocation.observation_sha256 != observation.provenance().observation_sha256.as_str()
            || invocation.prompt_sha256 != hash_hex(&invocation.prompt)
        {
            return Err(ClosedLoopCaptureError::InvalidEvidence(
                "invocation hashes do not match the supplied prompt and observation".to_owned(),
            ));
        }

        let decision = match &invocation.outcome {
            AgentctlOutcome::Decision(decision) if decision.failure.is_none() => decision,
            AgentctlOutcome::Decision(decision) => {
                let failure = decision.failure.as_ref().expect("matched failed decision");
                return Err(ClosedLoopCaptureError::OperatorFailure {
                    code: failure.code.to_owned(),
                    message: failure.message.clone(),
                });
            }
            AgentctlOutcome::Failure(failure) => {
                return Err(ClosedLoopCaptureError::OperatorFailure {
                    code: failure.code.to_owned(),
                    message: failure.message.clone(),
                });
            }
        };
        let parsed_decision = decision.parsed_decision.clone().ok_or_else(|| {
            ClosedLoopCaptureError::InvalidEvidence(
                "successful invocation has no parsed decision".to_owned(),
            )
        })?;
        if decision.raw_output_sha256() != hash_hex(invocation.raw_output()) {
            return Err(ClosedLoopCaptureError::InvalidEvidence(
                "raw output does not match its decision hash".to_owned(),
            ));
        }

        let reference = match &invocation.provenance {
            ProvenanceStatus::Committed(reference) => reference,
            ProvenanceStatus::Failed(failure) => {
                return Err(ClosedLoopCaptureError::Provenance {
                    code: failure.code.to_owned(),
                    message: failure.message.clone(),
                });
            }
            ProvenanceStatus::Pending => {
                return Err(ClosedLoopCaptureError::InvalidEvidence(
                    "operator provenance is still pending".to_owned(),
                ));
            }
        };
        let manifest = OperatorProvenanceStore::verify(reference).map_err(|failure| {
            ClosedLoopCaptureError::Provenance {
                code: failure.code.to_owned(),
                message: failure.message,
            }
        })?;
        if manifest.operator.operator_id != operator_id
            || manifest.hashes.system_prompt_sha256 != invocation.system_prompt_sha256
            || manifest.hashes.observation_sha256 != invocation.observation_sha256
            || manifest.hashes.prompt_sha256 != invocation.prompt_sha256
            || manifest.hashes.raw_output_sha256 != decision.raw_output_sha256()
            || manifest.submitted_actions.len() != decision.signed_actions.len()
        {
            return Err(ClosedLoopCaptureError::InvalidEvidence(
                "verified provenance does not describe this invocation".to_owned(),
            ));
        }
        for (submitted, action) in manifest
            .submitted_actions
            .iter()
            .zip(&decision.signed_actions)
        {
            let mut canonical = Vec::new();
            action.write(&mut canonical);
            if submitted.action_id != encode_hex(action.action_id().as_bytes())
                || submitted.canonical_action.bytes != canonical.len() as u64
                || submitted.canonical_action.sha256 != format!("sha256:{}", hash_hex(&canonical))
            {
                return Err(ClosedLoopCaptureError::InvalidEvidence(
                    "signed actions differ from verified operator provenance".to_owned(),
                ));
            }
        }

        let duration_ms = u64::try_from(invocation.duration_ms).map_err(|_| {
            ClosedLoopCaptureError::InvalidEvidence(
                "operator duration does not fit the run resource format".to_owned(),
            )
        })?;
        let allowance_ms = observation
            .observation()
            .remaining_budget()
            .validation_seconds
            .checked_mul(1_000)
            .ok_or_else(|| {
                ClosedLoopCaptureError::InvalidEvidence(
                    "advertised validation allowance overflows milliseconds".to_owned(),
                )
            })?;
        let report = parsed_decision.resource_report;

        Ok(Self {
            operator_id: operator_id.clone(),
            model: manifest.operator.model,
            provider: manifest.operator.provider,
            observation: observation.canonical_json().to_vec(),
            observation_provenance: observation.provenance().clone(),
            system_prompt: system_prompt.to_vec(),
            prompt: invocation.prompt.clone(),
            raw_output: invocation.raw_output().to_vec(),
            parsed_decision,
            signed_actions: decision.signed_actions.clone(),
            provenance_manifest_sha256: reference.manifest_sha256.clone(),
            resource: ResourceRecord {
                operator: operator_id,
                epoch: observation.observation().epoch(),
                model_calls: report.model_calls,
                input_tokens: None,
                output_tokens: None,
                tool_calls: report.tool_calls,
                command_duration_ms: duration_ms,
                cpu_time_ms: None,
                validation_wall_clock_allowance_ms: allowance_ms,
                git_objects_read: 0,
                files_inspected: 0,
                tests_executed: 0,
                jobs_inspected: 0,
                jobs_accepted: 0,
                claims_evaluated: 0,
                evidence_bytes: 0,
                compute_units: None,
            },
        })
    }

    #[must_use]
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }

    #[must_use]
    pub fn signed_actions(&self) -> &[SignedAction<Action>] {
        &self.signed_actions
    }
}

/// Exact signed inputs for one block of a captured closed-loop run.
#[derive(Clone, Debug, Default)]
pub struct CapturedClosedLoopBlock {
    /// Signed customer, evaluator, or other non-model actions ordered before
    /// the operator decisions in this block.
    pub leading_actions: Vec<SignedAction<Action>>,
    /// External decisions in deterministic block order.
    pub operator_decisions: Vec<CapturedOperatorDecision>,
}

/// Successful immutable capture report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClosedLoopCaptureReport {
    pub run_id: String,
    pub operators: usize,
    pub decisions: usize,
    pub signed_actions: usize,
    pub blocks_executed: usize,
    pub audit_observations_sha256: IntegrityHash,
    pub audit_decisions_sha256: IntegrityHash,
    pub outcome: RunOutcome,
}

/// Executes captured signed actions and commits a complete replayable run.
///
/// This function has intentionally no operator host, model, shell, network, or
/// callback argument. Audit evidence is serialized beside the action trace and
/// cannot influence deterministic execution.
#[allow(clippy::too_many_arguments)]
pub fn capture_closed_loop_run(
    experiment_root: impl AsRef<std::path::Path>,
    run_id: RunId,
    config: RunnerConfig,
    mechanism: LaboratoryMechanism,
    initial_state: Vec<StateEntry>,
    blocks: Vec<CapturedClosedLoopBlock>,
) -> Result<ClosedLoopCaptureReport, ClosedLoopCaptureError> {
    if blocks.is_empty() {
        return Err(ClosedLoopCaptureError::InvalidEvidence(
            "closed-loop capture must contain at least one block".to_owned(),
        ));
    }

    let mut operators = BTreeSet::new();
    let mut decisions = 0_usize;
    let mut signed_action_count = 0_usize;
    let mut action_blocks = Vec::with_capacity(blocks.len());
    let mut observations_jsonl = Vec::new();
    let mut decisions_jsonl = Vec::new();
    let mut resources = Vec::new();

    for (block_index, block) in blocks.iter().enumerate() {
        let mut actions = block.leading_actions.clone();
        signed_action_count = signed_action_count
            .checked_add(actions.len())
            .ok_or(ClosedLoopCaptureError::CountOverflow)?;
        for (decision_index, decision) in block.operator_decisions.iter().enumerate() {
            operators.insert(decision.operator_id.clone());
            decisions = decisions
                .checked_add(1)
                .ok_or(ClosedLoopCaptureError::CountOverflow)?;
            signed_action_count = signed_action_count
                .checked_add(decision.signed_actions.len())
                .ok_or(ClosedLoopCaptureError::CountOverflow)?;
            actions.extend(decision.signed_actions.iter().cloned());
            resources.push(decision.resource.clone());

            append_jsonl(
                &mut observations_jsonl,
                &ObservationAuditRecord {
                    schema_version: OBSERVATION_AUDIT_SCHEMA,
                    block_index,
                    decision_index,
                    operator_id: &decision.operator_id,
                    canonical_observation_hex: encode_hex(&decision.observation),
                    observation_provenance: &decision.observation_provenance,
                },
            )?;
            append_jsonl(
                &mut decisions_jsonl,
                &DecisionAuditRecord {
                    schema_version: DECISION_AUDIT_SCHEMA,
                    block_index,
                    decision_index,
                    operator_id: &decision.operator_id,
                    model: &decision.model,
                    provider: &decision.provider,
                    system_prompt_hex: encode_hex(&decision.system_prompt),
                    prompt_hex: encode_hex(&decision.prompt),
                    raw_output_hex: encode_hex(&decision.raw_output),
                    parsed_decision: &decision.parsed_decision,
                    signed_action_count: decision.signed_actions.len(),
                    provenance_manifest_sha256: &decision.provenance_manifest_sha256,
                },
            )?;
        }
        action_blocks.push(actions);
    }

    let mut initial_batch = rachet_core::state::InMemoryStateBatch::new();
    let mut initial_keys = BTreeSet::new();
    for (key, value) in &initial_state {
        if !initial_keys.insert(key.clone()) {
            return Err(ClosedLoopCaptureError::InvalidEvidence(
                "initial state contains a duplicate key".to_owned(),
            ));
        }
        use rachet_core::state::StateBatch as _;
        initial_batch.put(key.clone(), value.clone());
    }
    let execution = DeterministicRunner::new(config.clone(), mechanism)
        .map_err(ClosedLoopCaptureError::Setup)?
        .with_initial_state(initial_batch)
        .replay_actions(action_blocks)
        .map_err(ClosedLoopCaptureError::Runner)?;
    let capture = ReplayCapture::from_execution(&config, mechanism, &initial_state, &execution)
        .map_err(ClosedLoopCaptureError::Replay)?;

    let accounting = ResourceAccounting::from_records(resources)
        .map_err(|error| ClosedLoopCaptureError::Audit(error.to_string()))?;
    let metrics = LaboratoryMetricReport::derive(&LaboratoryMetricInput::default(), &accounting)
        .map_err(|error| ClosedLoopCaptureError::Audit(error.to_string()))?;
    let mut bundle = RunArtifactBundle {
        initial_state: Vec::new(),
        observations_jsonl,
        decisions_jsonl,
        signed_actions: Vec::new(),
        blocks: Vec::new(),
        events: Vec::new(),
        economic_state_jsonl: Vec::new(),
        resources_json: accounting
            .to_json_bytes()
            .map_err(ClosedLoopCaptureError::Json)?,
        metrics_json: metrics
            .to_json_bytes()
            .map_err(ClosedLoopCaptureError::Json)?,
        discovered_strategies_markdown: b"# Discovered strategies\n\nNone recorded.\n".to_vec(),
    };
    let outcome = capture.apply_to(&mut bundle);
    let observation_hash = IntegrityHash::digest(&bundle.observations_jsonl);
    let decision_hash = IntegrityHash::digest(&bundle.decisions_jsonl);
    RunArtifactStore::capture(experiment_root, run_id, outcome.clone(), &bundle)
        .map_err(ClosedLoopCaptureError::Artifact)?;

    Ok(ClosedLoopCaptureReport {
        run_id: run_id.to_string(),
        operators: operators.len(),
        decisions,
        signed_actions: signed_action_count,
        blocks_executed: execution.output.blocks.len(),
        audit_observations_sha256: observation_hash,
        audit_decisions_sha256: decision_hash,
        outcome,
    })
}

#[derive(Serialize)]
struct ObservationAuditRecord<'a> {
    schema_version: &'static str,
    block_index: usize,
    decision_index: usize,
    operator_id: &'a str,
    canonical_observation_hex: String,
    observation_provenance: &'a ObservationProvenance,
}

#[derive(Serialize)]
struct DecisionAuditRecord<'a> {
    schema_version: &'static str,
    block_index: usize,
    decision_index: usize,
    operator_id: &'a str,
    model: &'a str,
    provider: &'a str,
    system_prompt_hex: String,
    prompt_hex: String,
    raw_output_hex: String,
    parsed_decision: &'a ParsedDecision,
    signed_action_count: usize,
    provenance_manifest_sha256: &'a str,
}

fn append_jsonl<T: Serialize>(
    output: &mut Vec<u8>,
    value: &T,
) -> Result<(), ClosedLoopCaptureError> {
    serde_json::to_writer(&mut *output, value).map_err(ClosedLoopCaptureError::Json)?;
    output.push(b'\n');
    Ok(())
}

fn validate_operator_id(value: &str) -> Result<(), ClosedLoopCaptureError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(ClosedLoopCaptureError::InvalidEvidence(
            "operator ID must be 1..=512 bytes without control characters".to_owned(),
        ));
    }
    Ok(())
}

fn hash_hex(bytes: &[u8]) -> String {
    encode_hex(Sha256::digest(bytes).as_slice())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

/// Invalid external evidence, deterministic execution, or immutable capture.
#[derive(Debug)]
pub enum ClosedLoopCaptureError {
    InvalidEvidence(String),
    OperatorFailure { code: String, message: String },
    Provenance { code: String, message: String },
    CountOverflow,
    Setup(RunnerSetupError),
    Runner(RunnerError),
    Replay(TraceReplayError),
    Artifact(RunArtifactError),
    Audit(String),
    Json(serde_json::Error),
}

impl fmt::Display for ClosedLoopCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvidence(reason) => {
                write!(formatter, "invalid closed-loop evidence: {reason}")
            }
            Self::OperatorFailure { code, message } => {
                write!(formatter, "operator decision failed ({code}): {message}")
            }
            Self::Provenance { code, message } => {
                write!(formatter, "operator provenance failed ({code}): {message}")
            }
            Self::CountOverflow => formatter.write_str("closed-loop capture count overflowed"),
            Self::Setup(error) => write!(formatter, "cannot construct replay runner: {error}"),
            Self::Runner(error) => write!(formatter, "captured action execution failed: {error}"),
            Self::Replay(error) => write!(formatter, "cannot encode replay capture: {error}"),
            Self::Artifact(error) => write!(formatter, "cannot commit run artifacts: {error}"),
            Self::Audit(reason) => write!(formatter, "cannot derive run audit artifacts: {reason}"),
            Self::Json(error) => write!(formatter, "cannot encode closed-loop evidence: {error}"),
        }
    }
}

impl Error for ClosedLoopCaptureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Setup(error) => Some(error),
            Self::Runner(error) => Some(error),
            Self::Replay(error) => Some(error),
            Self::Artifact(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::InvalidEvidence(_)
            | Self::OperatorFailure { .. }
            | Self::Provenance { .. }
            | Self::CountOverflow
            | Self::Audit(_) => None,
        }
    }
}
