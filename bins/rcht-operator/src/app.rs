use rachet_core::primitives::{ChainId, ClaimId, EvidenceId, JobId, Sha256Digest};
use rachet_lab::decision_boundary::{
    BoundaryError, BoundaryFailure, BoundaryPhase, BoundaryStatus, PauseResumeBoundary,
};
use rachet_operator::{
    agentctl::{AgentctlBoundary, AgentctlError},
    decision::{AvailableClaim, AvailableEvidence, AvailableJob, DecisionContext},
    host::{HostError, OperatorHost, ProtectedPaths, ProvisionedOperator},
    manifest::PopulationManifest,
    observation::{ObservationProvenance, ObservationSnapshot},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const CONTEXT_SCHEMA_VERSION: &str = "rcht-operator-decision-context.v1";
const MAX_CLI_FILE_BYTES: u64 = 64 * 1024 * 1024;
const USAGE: &str = "rcht-operator [--json] <command> [options]\n\n\
commands:\n\
  init --root DIR --repository DIR --revision REV --manifest FILE\n\
       [--consensus-key PATH ...] [--hidden-evaluator PATH ...]\n\
  pause --root DIR --initial-state FILE --actions FILE\n\
        --observation FILE --observation-provenance FILE [--boundary DIR]\n\
  execute --root DIR --agentctl FILE --system-prompt FILE --context FILE\n\
          [--boundary DIR]\n\
  resume --boundary DIR\n\
  status --boundary DIR\n\n\
Each init manifest must contain exactly one identity and no communication\n\
channels. Sensitive keys, prompts, raw output, protected paths, and private\n\
provenance locations are never printed.\n";

pub struct Invocation {
    pub json: bool,
    pub outcome: Result<Success, CliError>,
}

#[derive(Debug)]
pub struct Success {
    command: &'static str,
    result: Value,
}

#[derive(Debug)]
pub struct CliError {
    pub code: String,
    pub message: String,
    pub details: Value,
    pub exit_code: u8,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: "CLI_USAGE_INVALID".to_owned(),
            message: message.into(),
            details: json!({"usage": USAGE}),
            exit_code: 2,
        }
    }

    fn input(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            details: json!({}),
            exit_code: 2,
        }
    }

    fn host(error: HostError) -> Self {
        let code = error.code();
        Self {
            code: code.to_owned(),
            message: format!("operator host operation failed ({code})"),
            details: json!({}),
            exit_code: 1,
        }
    }

    fn boundary(error: BoundaryError) -> Self {
        Self {
            code: error.code().to_owned(),
            message: error.to_string(),
            details: json!({}),
            exit_code: 1,
        }
    }

    fn agentctl(error: AgentctlError) -> Self {
        Self {
            code: "AGENTCTL_EXECUTABLE_INVALID".to_owned(),
            message: error.to_string(),
            details: json!({}),
            exit_code: 1,
        }
    }

    fn io(operation: &'static str, error: std::io::Error) -> Self {
        Self {
            code: "OPERATOR_CLI_IO_FAILED".to_owned(),
            message: format!("cannot {operation}: {error}"),
            details: json!({}),
            exit_code: 1,
        }
    }

    fn json(subject: &'static str, error: serde_json::Error) -> Self {
        Self::input(
            "OPERATOR_CLI_JSON_INVALID",
            format!("invalid {subject} JSON: {error}"),
        )
    }

    fn durable_failure(failure: BoundaryFailure) -> Self {
        Self {
            message: public_failure_message(&failure.code),
            code: failure.code,
            details: json!({"phase": "failed"}),
            exit_code: 1,
        }
    }
}

pub fn invoke(raw_args: Vec<String>) -> Invocation {
    let json = raw_args.iter().any(|argument| argument == "--json");
    let args = raw_args
        .into_iter()
        .filter(|argument| argument != "--json")
        .collect();
    Invocation {
        json,
        outcome: dispatch(args),
    }
}

pub fn render(invocation: &Invocation) -> String {
    match &invocation.outcome {
        Ok(success) if invocation.json => serde_json::to_string(&json!({
            "ok": true,
            "command": success.command,
            "result": success.result,
        }))
        .expect("operator CLI success is serializable"),
        Ok(success) => format!(
            "{}: ok\n{}",
            success.command,
            serde_json::to_string_pretty(&success.result)
                .expect("operator CLI result is serializable")
        ),
        Err(error) if invocation.json => serde_json::to_string(&json!({
            "error": {
                "code": error.code,
                "message": error.message,
                "details": error.details,
            }
        }))
        .expect("operator CLI error is serializable"),
        Err(error) => format!("{}: {}", error.code, error.message),
    }
}

fn dispatch(mut args: Vec<String>) -> Result<Success, CliError> {
    if args.is_empty() {
        return Err(CliError::usage("a command is required"));
    }
    if matches!(args[0].as_str(), "help" | "-h" | "--help") {
        return Ok(Success {
            command: "help",
            result: json!({"usage": USAGE}),
        });
    }
    let command = args.remove(0);
    match command.as_str() {
        "init" => init_command(args),
        "pause" => pause_command(args),
        "execute" => execute_command(args),
        "resume" => resume_command(args),
        "status" => status_command(args),
        _ => Err(CliError::usage(format!("unknown command {command:?}"))),
    }
}

fn init_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let root = options.required_path("root")?;
    let repository = options.required_path("repository")?;
    let revision = options.required("revision")?;
    let manifest_path = options.required_path("manifest")?;
    let consensus_keys = options.repeated_paths("consensus-key");
    let hidden_evaluator = options.repeated_paths("hidden-evaluator");
    options.finish()?;

    let manifest: PopulationManifest = read_json(&manifest_path, "operator manifest")?;
    if manifest.operators.len() != 1 || !manifest.communication_channels.is_empty() {
        return Err(CliError::input(
            "OPERATOR_SINGLE_IDENTITY_REQUIRED",
            "rcht-operator requires exactly one identity and no shared communication channels",
        ));
    }
    let protected =
        ProtectedPaths::new(consensus_keys, hidden_evaluator).map_err(CliError::host)?;
    let population = OperatorHost::create(&root, repository, revision, protected)
        .and_then(|host| host.provision(manifest))
        .map_err(CliError::host)?;
    let operator = population
        .operators()
        .values()
        .next()
        .expect("single-identity manifest was provisioned");
    Ok(Success {
        command: "init",
        result: json!({
            "schema_version": "rcht-operator-status.v1",
            "operator_id": operator.operator_id(),
            "actor_id": operator.actor_id(),
            "role": operator.role(),
            "state": "initialized",
        }),
    })
}

fn pause_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let root = options.required_path("root")?;
    let initial_state_path = options.required_path("initial-state")?;
    let actions_path = options.required_path("actions")?;
    let observation_path = options.required_path("observation")?;
    let provenance_path = options.required_path("observation-provenance")?;
    let boundary_root = options
        .optional_path("boundary")?
        .unwrap_or_else(|| root.join("boundary"));
    options.finish()?;

    let operator = open_single_operator(&root)?;
    let observation_bytes = read_bounded(&observation_path, "read observation")?;
    let provenance: ObservationProvenance = read_json(&provenance_path, "observation provenance")?;
    let observation = ObservationSnapshot::from_captured(observation_bytes, provenance)
        .map_err(|error| CliError::input(error.code(), error.to_string()))?;
    if observation.observation().actor_id() != operator.actor_id()
        || observation.observation().remaining_budget() != operator.budget().remaining()
    {
        return Err(CliError::input(
            "OPERATOR_OBSERVATION_IDENTITY_MISMATCH",
            "observation identity or budget does not match the isolated operator",
        ));
    }
    let initial_state = read_bounded(&initial_state_path, "read initial state")?;
    let actions = read_bounded(&actions_path, "read action trace")?;
    let boundary =
        PauseResumeBoundary::pause_captured(&boundary_root, &initial_state, &actions, observation)
            .map_err(CliError::boundary)?;
    Ok(status_success("pause", boundary.status()))
}

fn execute_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let root = options.required_path("root")?;
    let boundary_root = options
        .optional_path("boundary")?
        .unwrap_or_else(|| root.join("boundary"));
    let executable = options.required_path("agentctl")?;
    let system_prompt_path = options.required_path("system-prompt")?;
    let context_path = options.required_path("context")?;
    options.finish()?;

    let mut operator = open_single_operator(&root)?;
    let mut boundary = PauseResumeBoundary::open(&boundary_root).map_err(CliError::boundary)?;
    let wire: WireDecisionContext = read_json(&context_path, "decision context")?;
    let owned = OwnedDecisionContext::parse(wire)?;
    if boundary.chain_id().map_err(CliError::boundary)? != owned.chain_id
        || owned.valid_until_height < boundary.observation().observation().height()
    {
        return Err(CliError::input(
            "OPERATOR_CONTEXT_CHECKPOINT_MISMATCH",
            "decision context chain or expiry does not match the deterministic checkpoint",
        ));
    }
    ensure_observation_context(boundary.observation(), &owned)?;
    let system_prompt = read_bounded(&system_prompt_path, "read system prompt")?;
    let agentctl = AgentctlBoundary::new(executable).map_err(CliError::agentctl)?;
    let status = boundary
        .invoke_external(&agentctl, &mut operator, &system_prompt, owned.context())
        .map_err(CliError::boundary)?;
    if let Some(failure) = status.failure {
        return Err(CliError::durable_failure(failure));
    }
    Ok(status_success("execute", status))
}

fn resume_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let boundary_root = options.required_path("boundary")?;
    options.finish()?;
    let mut boundary = PauseResumeBoundary::open(boundary_root).map_err(CliError::boundary)?;
    let execution = boundary.resume().map_err(CliError::boundary)?;
    let canonical = execution.output.canonical_bytes();
    Ok(Success {
        command: "resume",
        result: json!({
            "schema_version": "rcht-operator-status.v1",
            "phase": "resumed",
            "blocks_executed": execution.output.blocks.len(),
            "canonical_output_sha256": encode_hex(Sha256::digest(canonical).as_slice()),
            "model_calls_during_resume": 0,
        }),
    })
}

fn status_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let boundary_root = options.required_path("boundary")?;
    options.finish()?;
    let boundary = PauseResumeBoundary::open(boundary_root).map_err(CliError::boundary)?;
    Ok(status_success("status", boundary.status()))
}

fn status_success(command: &'static str, status: BoundaryStatus) -> Success {
    let failure = status.failure.map(|failure| {
        let message = public_failure_message(&failure.code);
        json!({"code": failure.code, "message": message})
    });
    Success {
        command,
        result: json!({
            "schema_version": "rcht-operator-status.v1",
            "phase": phase_name(status.phase),
            "failure": failure,
        }),
    }
}

fn public_failure_message(code: &str) -> String {
    format!("operator decision failed ({code}); inspect host-private provenance")
}

const fn phase_name(phase: BoundaryPhase) -> &'static str {
    match phase {
        BoundaryPhase::Paused => "paused",
        BoundaryPhase::Invoking => "invoking",
        BoundaryPhase::Ready => "ready",
        BoundaryPhase::Resumed => "resumed",
        BoundaryPhase::Failed => "failed",
    }
}

fn open_single_operator(root: &Path) -> Result<ProvisionedOperator, CliError> {
    let operators_root = root.join("operators");
    let entries = fs::read_dir(&operators_root)
        .map_err(|error| CliError::io("list isolated operators", error))?;
    let mut configs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| CliError::io("read isolated operator entry", error))?;
        let metadata = entry
            .file_type()
            .map_err(|error| CliError::io("inspect isolated operator entry", error))?;
        if metadata.is_dir() && !metadata.is_symlink() {
            configs.push(entry.path().join("home/.config/rachet/agent.json"));
        }
    }
    if configs.len() != 1 {
        return Err(CliError::input(
            "OPERATOR_SINGLE_IDENTITY_REQUIRED",
            "operator root must contain exactly one isolated identity",
        ));
    }
    ProvisionedOperator::open(&configs[0]).map_err(CliError::host)
}

fn ensure_observation_context(
    observation: &ObservationSnapshot,
    context: &OwnedDecisionContext,
) -> Result<(), CliError> {
    let advertised = observation
        .observation()
        .available_jobs()
        .iter()
        .collect::<BTreeSet<_>>();
    let available = context
        .jobs
        .iter()
        .map(|job| &job.reference)
        .collect::<BTreeSet<_>>();
    if advertised.len() != observation.observation().available_jobs().len()
        || available.len() != context.jobs.len()
        || advertised != available
    {
        return Err(CliError::input(
            "OPERATOR_CONTEXT_OBSERVATION_MISMATCH",
            "decision context jobs do not exactly match the advertised observation",
        ));
    }
    let evidence = context
        .evidence
        .iter()
        .map(|item| item.reference.as_str())
        .collect::<BTreeSet<_>>();
    if evidence.len() != context.evidence.len() {
        return Err(CliError::input(
            "OPERATOR_CONTEXT_INVALID",
            "decision context contains duplicate evidence references",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDecisionContext {
    schema_version: String,
    chain_id: String,
    next_nonce: u64,
    valid_until_height: u64,
    #[serde(default)]
    available_jobs: Vec<WireAvailableJob>,
    #[serde(default)]
    available_evidence: Vec<WireAvailableEvidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAvailableJob {
    reference: String,
    job_id: String,
    claims: Vec<WireAvailableClaim>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAvailableClaim {
    reference: String,
    claim_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAvailableEvidence {
    reference: String,
    evidence_id: String,
    job_id: String,
    claim_id: Option<String>,
}

struct OwnedDecisionContext {
    chain_id: ChainId,
    next_nonce: u64,
    valid_until_height: u64,
    jobs: Vec<AvailableJob>,
    evidence: Vec<AvailableEvidence>,
}

impl OwnedDecisionContext {
    fn parse(wire: WireDecisionContext) -> Result<Self, CliError> {
        if wire.schema_version != CONTEXT_SCHEMA_VERSION {
            return Err(CliError::input(
                "OPERATOR_CONTEXT_INVALID",
                "unsupported decision context schema version",
            ));
        }
        let chain_id = ChainId::new(parse_32(&wire.chain_id, "chain_id")?);
        let jobs = wire
            .available_jobs
            .into_iter()
            .map(|job| {
                let claims = job
                    .claims
                    .into_iter()
                    .map(|claim| {
                        Ok(AvailableClaim {
                            reference: claim.reference,
                            claim_id: ClaimId::from_digest(Sha256Digest::from(parse_32(
                                &claim.claim_id,
                                "claim_id",
                            )?)),
                        })
                    })
                    .collect::<Result<Vec<_>, CliError>>()?;
                Ok(AvailableJob {
                    reference: job.reference,
                    job_id: JobId::from_digest(Sha256Digest::from(parse_32(
                        &job.job_id,
                        "job_id",
                    )?)),
                    claims,
                })
            })
            .collect::<Result<Vec<_>, CliError>>()?;
        let evidence = wire
            .available_evidence
            .into_iter()
            .map(|item| {
                Ok(AvailableEvidence {
                    reference: item.reference,
                    evidence_id: EvidenceId::from_digest(Sha256Digest::from(parse_32(
                        &item.evidence_id,
                        "evidence_id",
                    )?)),
                    job_id: JobId::from_digest(Sha256Digest::from(parse_32(
                        &item.job_id,
                        "evidence job_id",
                    )?)),
                    claim_id: item
                        .claim_id
                        .map(|claim| {
                            parse_32(&claim, "evidence claim_id")
                                .map(Sha256Digest::from)
                                .map(ClaimId::from_digest)
                        })
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, CliError>>()?;
        Ok(Self {
            chain_id,
            next_nonce: wire.next_nonce,
            valid_until_height: wire.valid_until_height,
            jobs,
            evidence,
        })
    }

    fn context(&self) -> DecisionContext<'_> {
        DecisionContext {
            chain_id: self.chain_id,
            next_nonce: self.next_nonce,
            valid_until_height: self.valid_until_height,
            available_jobs: &self.jobs,
            available_evidence: &self.evidence,
        }
    }
}

fn parse_32(value: &str, field: &'static str) -> Result<[u8; 32], CliError> {
    let bytes = decode_hex(value).map_err(|message| {
        CliError::input(
            "OPERATOR_CONTEXT_INVALID",
            format!("invalid {field}: {message}"),
        )
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        CliError::input(
            "OPERATOR_CONTEXT_INVALID",
            format!("{field} must contain 32 bytes, received {}", bytes.len()),
        )
    })
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hexadecimal text has odd length".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("value is not hexadecimal".to_owned()),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    subject: &'static str,
) -> Result<T, CliError> {
    let bytes = read_bounded(path, "read JSON input")?;
    serde_json::from_slice(&bytes).map_err(|error| CliError::json(subject, error))
}

fn read_bounded(path: &Path, operation: &'static str) -> Result<Vec<u8>, CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| CliError::io(operation, error))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CLI_FILE_BYTES {
        return Err(CliError::input(
            "OPERATOR_CLI_INPUT_INVALID",
            format!("input must be a regular file no larger than {MAX_CLI_FILE_BYTES} bytes"),
        ));
    }
    fs::read(path).map_err(|error| CliError::io(operation, error))
}

struct Options {
    values: BTreeMap<String, Vec<String>>,
}

impl Options {
    fn parse(args: Vec<String>) -> Result<Self, CliError> {
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut arguments = args.into_iter();
        while let Some(flag) = arguments.next() {
            let key = flag
                .strip_prefix("--")
                .filter(|key| !key.is_empty())
                .ok_or_else(|| CliError::usage(format!("unexpected argument {flag:?}")))?;
            let value = arguments
                .next()
                .ok_or_else(|| CliError::usage(format!("--{key} requires a value")))?;
            if value.starts_with("--") {
                return Err(CliError::usage(format!("--{key} requires a value")));
            }
            values.entry(key.to_owned()).or_default().push(value);
        }
        Ok(Self { values })
    }

    fn required(&mut self, key: &'static str) -> Result<String, CliError> {
        match self.values.remove(key) {
            Some(values) if values.len() == 1 => Ok(values.into_iter().next().expect("one value")),
            Some(_) => Err(CliError::usage(format!(
                "--{key} may be supplied only once"
            ))),
            None => Err(CliError::usage(format!("--{key} is required"))),
        }
    }

    fn required_path(&mut self, key: &'static str) -> Result<PathBuf, CliError> {
        self.required(key).map(PathBuf::from)
    }

    fn optional_path(&mut self, key: &'static str) -> Result<Option<PathBuf>, CliError> {
        match self.values.remove(key) {
            Some(values) if values.len() == 1 => Ok(values.into_iter().next().map(PathBuf::from)),
            Some(_) => Err(CliError::usage(format!(
                "--{key} may be supplied only once"
            ))),
            None => Ok(None),
        }
    }

    fn repeated_paths(&mut self, key: &'static str) -> Vec<PathBuf> {
        self.values
            .remove(key)
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect()
    }

    fn finish(self) -> Result<(), CliError> {
        if let Some(key) = self.values.keys().next() {
            return Err(CliError::usage(format!("unknown option --{key}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};
    use rachet_core::{
        blocks::ConsensusNodeId,
        state::{InMemoryStateBatch, StateBatch as _},
    };
    use rachet_lab::{
        replay::ReplayCapture,
        simulator::{DeterministicRunner, LaboratoryMechanism, RunnerConfig},
    };
    use rachet_operator::{
        budget::ResourceBudget,
        manifest::{
            AgentConfiguration, IdentityConstraints, IndependenceDeclaration,
            InformationPolicy as ManifestInformationPolicy, LearningPolicy, OperatorKind,
            OperatorSpec, POPULATION_SCHEMA_VERSION, PRODUCTIVE_OBJECTIVE,
        },
        observation::{
            FinalizedPublicState, InformationPolicy, MechanismEconomicState, ObservationBuildInput,
            OperatorDeclaration, PrivateOperatorHistory, build,
        },
    };
    use std::{
        os::unix::fs::PermissionsExt as _,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    const PROMPT: &[u8] = b"Act as one bounded validation operator.";

    #[test]
    fn lifecycle_is_json_safe_and_resumes_without_model_access() {
        let temp = TempDirectory::new();
        let repository = repository(temp.path());
        let root = temp.path().join("operator");
        let manifest_path = temp.path().join("manifest.json");
        fs::write(&manifest_path, serde_json::to_vec(&manifest()).unwrap()).unwrap();
        let hidden = temp.path().join("hidden-truth");
        fs::create_dir(&hidden).unwrap();
        fs::write(hidden.join("truth.json"), b"secret").unwrap();

        let initialized = call(&[
            "init",
            "--root",
            text(&root),
            "--repository",
            text(&repository),
            "--revision",
            "HEAD",
            "--manifest",
            text(&manifest_path),
            "--hidden-evaluator",
            text(&hidden),
        ]);
        let actor = initialized["result"]["actor_id"].as_str().unwrap();
        assert!(!initialized.to_string().contains("actor.key"));
        assert!(!initialized.to_string().contains(text(&hidden)));

        let config = runner_config();
        let execution =
            DeterministicRunner::new(config.clone(), LaboratoryMechanism::M00RecordOnly)
                .unwrap()
                .replay_actions(Vec::new())
                .unwrap();
        let capture = ReplayCapture::from_execution(
            &config,
            LaboratoryMechanism::M00RecordOnly,
            &[],
            &execution,
        )
        .unwrap();
        let initial = temp.path().join("initial-state.bin");
        let actions = temp.path().join("actions.bin");
        fs::write(&initial, capture.initial_state).unwrap();
        fs::write(&actions, capture.signed_actions).unwrap();

        let state = InMemoryStateBatch::new();
        let observation = observation(actor, state.root().as_ref().try_into().unwrap());
        let observation_path = temp.path().join("observation.json");
        let observation_provenance = temp.path().join("observation-provenance.json");
        fs::write(&observation_path, observation.canonical_json()).unwrap();
        fs::write(
            &observation_provenance,
            serde_json::to_vec(observation.provenance()).unwrap(),
        )
        .unwrap();
        let boundary = root.join("boundary");
        assert_eq!(
            call(&[
                "pause",
                "--root",
                text(&root),
                "--initial-state",
                text(&initial),
                "--actions",
                text(&actions),
                "--observation",
                text(&observation_path),
                "--observation-provenance",
                text(&observation_provenance),
            ])["result"]["phase"],
            "paused"
        );

        let executable = script(temp.path());
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, PROMPT).unwrap();
        let context = temp.path().join("context.json");
        fs::write(
            &context,
            serde_json::to_vec(&json!({
                "schema_version": CONTEXT_SCHEMA_VERSION,
                "chain_id": encode_hex(config.chain_id.as_bytes()),
                "next_nonce": 0,
                "valid_until_height": 10,
                "available_jobs": [],
                "available_evidence": [],
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            call(&[
                "execute",
                "--root",
                text(&root),
                "--agentctl",
                text(&executable),
                "--system-prompt",
                text(&prompt),
                "--context",
                text(&context),
            ])["result"]["phase"],
            "ready"
        );
        fs::remove_file(&executable).unwrap();
        let resumed = call(&["resume", "--boundary", text(&boundary)]);
        assert_eq!(resumed["result"]["phase"], "resumed");
        assert_eq!(resumed["result"]["model_calls_during_resume"], 0);
        assert_eq!(
            call(&["status", "--boundary", text(&boundary)])["result"]["phase"],
            "resumed"
        );
    }

    #[test]
    fn json_failures_have_stable_shape() {
        let invocation = invoke(vec!["--json".to_owned(), "unknown".to_owned()]);
        let value: Value = serde_json::from_str(&render(&invocation)).unwrap();
        assert_eq!(value["error"]["code"], "CLI_USAGE_INVALID");
        assert!(value["error"]["message"].is_string());
        assert!(value["error"]["details"].is_object());
    }

    fn call(args: &[&str]) -> Value {
        let mut args = args
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        args.push("--json".to_owned());
        let invocation = invoke(args);
        assert!(invocation.outcome.is_ok(), "{}", render(&invocation));
        serde_json::from_str(&render(&invocation)).unwrap()
    }

    fn manifest() -> PopulationManifest {
        PopulationManifest {
            schema_version: POPULATION_SCHEMA_VERSION.to_owned(),
            operators: vec![OperatorSpec {
                operator_id: "alpha".to_owned(),
                role: "validation_operator".to_owned(),
                objective: PRODUCTIVE_OBJECTIVE.to_owned(),
                operator_kind: OperatorKind::Productive,
                agent: AgentConfiguration {
                    provider: "fixture".to_owned(),
                    model: "fixture-model".to_owned(),
                    model_family: "fixture-family".to_owned(),
                    random_seed: "fixture-seed".to_owned(),
                    tool_harness: "agentctl".to_owned(),
                    system_prompt_sha256: encode_hex(Sha256::digest(PROMPT).as_slice()),
                },
                information: ManifestInformationPolicy::standard_validation("inspection"),
                learning: LearningPolicy::adaptive_validation(),
                communication_channels: Vec::new(),
                customer_relationship: "none".to_owned(),
                resource_budget: ResourceBudget {
                    model_calls: 2,
                    tool_calls: 2,
                    validation_seconds: 4,
                },
                identity_constraints: IdentityConstraints::validation_operator(),
                independence: IndependenceDeclaration::all_independent(),
            }],
            communication_channels: Vec::new(),
        }
    }

    fn runner_config() -> RunnerConfig {
        RunnerConfig {
            seed: 76,
            chain_id: ChainId::new([0x76; 32]),
            blocks_per_epoch: 10,
            consensus_node: ConsensusNodeId::from(ed25519::PrivateKey::from_seed(76).public_key()),
            genesis_parent_block: Sha256Digest::from([0; 32]),
            genesis_timestamp_ms: 1_700_000_000_000,
            block_interval_ms: 1_000,
        }
    }

    fn observation(actor: &str, root: [u8; 32]) -> ObservationSnapshot {
        let mechanisms = vec!["M00@1.0.0".to_owned()];
        let jobs = Vec::new();
        let policy = InformationPolicy::section_31("section-31");
        build(ObservationBuildInput {
            finalized_public_state: FinalizedPublicState {
                experiment_id: "operator-cli-test",
                epoch: 0,
                height: 0,
                finalized_state_root_sha256: root,
                public_history: b"public",
            },
            operator: OperatorDeclaration {
                actor_id: actor,
                role: "validation_operator",
                objective: PRODUCTIVE_OBJECTIVE,
            },
            mechanism_economic_state: MechanismEconomicState {
                mechanism_set: &mechanisms,
                reputation: 0,
            },
            remaining_budget: ResourceBudget {
                model_calls: 2,
                tool_calls: 2,
                validation_seconds: 4,
            }
            .as_usage(),
            available_jobs: &jobs,
            private_operator_history: PrivateOperatorHistory {
                actor_id: actor,
                bytes: b"private",
            },
            information_policy: &policy,
        })
        .unwrap()
    }

    fn repository(root: &Path) -> PathBuf {
        let repository = root.join("repository");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--quiet"]);
        git(&repository, &["config", "user.name", "Rachet Test"]);
        git(
            &repository,
            &["config", "user.email", "rachet@example.invalid"],
        );
        fs::write(repository.join("README.md"), b"public\n").unwrap();
        git(&repository, &["add", "README.md"]);
        git(&repository, &["commit", "--quiet", "-m", "fixture"]);
        repository
    }

    fn git(repository: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn script(root: &Path) -> PathBuf {
        let path = root.join("agentctl");
        fs::write(
            &path,
            r#"#!/bin/sh
set -eu
dir="$HOME/.agentctl/jobs/fixture"
mkdir -p "$dir"
printf 'stdout:\n%s\n' '{"schema_version":"operator-decision.v1","decision":"wait","resource_report":{"model_calls":1,"tool_calls":0}}' > "$dir/output.log"
printf '[{"iteration":1,"iterations":1,"summary":{"command":"fixture","exit_code":0,"duration_ms":1,"preview_lines":[],"raw_log_path":"%s"}}]\n' "$dir/output.log"
"#,
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn text(path: &Path) -> &str {
        path.to_str().unwrap()
    }

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rachet-operator-cli-{}-{sequence}",
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
