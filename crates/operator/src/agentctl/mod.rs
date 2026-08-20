//! External `agentctl` process boundary for autonomous operators.
//!
//! This module is deliberately blocking and host-side. It converts a finalized
//! observation into a bounded prompt, runs exactly one external agent process,
//! retains raw process evidence, and only then converts the returned decision
//! into signed actions. Commonware deterministic actors never receive a
//! callback or handle to this boundary.

use crate::{
    budget::{BudgetError, BudgetTracker, ResourceUsage},
    decision::{DecisionContext, DecisionRecord, parse_and_sign_metered},
    host::ProvisionedOperator,
    manifest::OperatorRuntimeConfig,
    observation::{MAX_OBSERVATION_BYTES, ObservationSnapshot},
    provenance::{OperatorProvenanceStore, ProvenanceStatus},
};
use rachet_client::identity::ActorIdentity;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

pub const MAX_SYSTEM_PROMPT_BYTES: usize = 64 * 1024;
pub const MAX_AGENTCTL_REPORT_BYTES: usize = 1024 * 1024;
pub const MAX_AGENTCTL_RAW_LOG_BYTES: usize = 32 * 1024 * 1024 + 1024;

const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_GRACE: Duration = Duration::from_secs(2);
const O_NOFOLLOW: i32 = 0o400_000;
static INVOCATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Trusted, non-deterministic host capability for one installed `agentctl`
/// executable. This value is never accepted by deterministic runner APIs.
#[derive(Debug)]
pub struct AgentctlBoundary {
    executable: PathBuf,
}

impl AgentctlBoundary {
    /// Pins the exact executable used by subsequent records. PATH lookup is not
    /// performed at invocation time.
    pub fn new(executable: impl AsRef<Path>) -> Result<Self, AgentctlError> {
        let executable = canonical_regular_file(executable.as_ref(), "agentctl executable")?;
        Ok(Self { executable })
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Invokes one configured provider through `agentctl`, outside all
    /// deterministic actors, and signs a successful strict decision.
    ///
    /// The provider profile comes from the operator's isolated runtime config.
    /// The child receives a cleared environment containing only its isolated
    /// home/worktree/config, bounded budget values, PATH, and locale. One model
    /// call and measured wall time are charged even when model output is
    /// malformed; a parsed resource report may increase model/tool charges.
    pub fn invoke_and_sign(
        &self,
        operator: &mut ProvisionedOperator,
        system_prompt: &[u8],
        observation: &ObservationSnapshot,
        decision_context: DecisionContext<'_>,
    ) -> AgentctlInvocationRecord {
        let pending = OperatorProvenanceStore::begin(operator);
        let mut record = self.invoke_inner(operator, system_prompt, observation, decision_context);
        record.provenance = match pending {
            Ok(pending) => OperatorProvenanceStore::commit(
                pending,
                operator,
                system_prompt,
                observation,
                decision_context,
                &record,
            )
            .map_or_else(ProvenanceStatus::Failed, ProvenanceStatus::Committed),
            Err(failure) => ProvenanceStatus::Failed(failure),
        };
        record
    }

    fn invoke_inner(
        &self,
        operator: &mut ProvisionedOperator,
        system_prompt: &[u8],
        observation: &ObservationSnapshot,
        decision_context: DecisionContext<'_>,
    ) -> AgentctlInvocationRecord {
        let started = Instant::now();
        let mut record = AgentctlInvocationRecord::new(
            self.executable.clone(),
            hash_hex(system_prompt),
            observation
                .provenance()
                .observation_sha256
                .as_str()
                .to_owned(),
        );

        let prepared = match prepare(operator, system_prompt, observation) {
            Ok(prepared) => prepared,
            Err(failure) => {
                record.finish(started, AgentctlOutcome::Failure(failure));
                return record;
            }
        };
        record.prompt_sha256 = hash_hex(&prepared.prompt);
        record.prompt = prepared.prompt.clone();
        record.command = command_arguments(&prepared);

        let prior_logs = list_raw_logs(operator.home()).unwrap_or_default();
        let mut command = Command::new(&self.executable);
        command
            .args(&record.command)
            .current_dir(operator.worktree())
            .env_clear()
            .env("HOME", operator.home())
            .env("AGENTCTL_HOME", operator.home())
            .env("XDG_CONFIG_HOME", operator.home().join(".config"))
            .env("XDG_CACHE_HOME", operator.home().join(".cache"))
            .env("XDG_STATE_HOME", operator.home().join(".local/state"))
            .env("TMPDIR", &prepared.config.scratch)
            .env("RACHET_OPERATOR_CONFIG", operator.config_path())
            .env("RACHET_OPERATOR_ID", operator.operator_id())
            .env("RACHET_AGENT_PROVIDER", &prepared.config.agent.provider)
            .env("RACHET_AGENT_MODEL", &prepared.config.agent.model)
            .env(
                "RACHET_REMAINING_MODEL_CALLS",
                prepared.remaining.model_calls.to_string(),
            )
            .env(
                "RACHET_REMAINING_TOOL_CALLS",
                prepared.remaining.tool_calls.to_string(),
            )
            .env(
                "RACHET_REMAINING_VALIDATION_SECONDS",
                prepared.remaining.validation_seconds.to_string(),
            )
            .env("PATH", inherited_path())
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = fs::remove_file(&prepared.prompt_path);
                record.finish(
                    started,
                    AgentctlOutcome::Failure(AgentctlFailure::spawn(error)),
                );
                return record;
            }
        };
        let stdout_reader = capture_reader(child.stdout.take(), MAX_AGENTCTL_REPORT_BYTES);
        let stderr_reader = capture_reader(child.stderr.take(), MAX_AGENTCTL_REPORT_BYTES);
        let terminal = wait_bounded(
            &mut child,
            Duration::from_secs(prepared.remaining.validation_seconds),
        );
        record.stdout = stdout_reader.join().unwrap_or_default();
        record.stderr = stderr_reader.join().unwrap_or_default();
        record.exit_code = terminal.status.and_then(|status| status.code());
        record.timed_out = terminal.timed_out;
        let _ = fs::remove_file(&prepared.prompt_path);

        let discovered_log = discover_raw_log(operator.home(), &prior_logs);
        if terminal.timed_out {
            record.raw_log =
                discovered_log.and_then(|path| read_raw_log(operator.home(), &path).ok());
            let failure = charge_failed_process(
                operator.budget_mut(),
                started.elapsed(),
                AgentctlFailure::timeout(prepared.remaining.validation_seconds),
            );
            record.finish(started, AgentctlOutcome::Failure(failure));
            return record;
        }

        let status = match terminal.status {
            Some(status) => status,
            None => {
                let failure = charge_failed_process(
                    operator.budget_mut(),
                    started.elapsed(),
                    AgentctlFailure::wait("agentctl status unavailable"),
                );
                record.finish(started, AgentctlOutcome::Failure(failure));
                return record;
            }
        };
        if !status.success() {
            record.raw_log =
                discovered_log.and_then(|path| read_raw_log(operator.home(), &path).ok());
            let failure = charge_failed_process(
                operator.budget_mut(),
                started.elapsed(),
                AgentctlFailure::crash(status),
            );
            record.finish(started, AgentctlOutcome::Failure(failure));
            return record;
        }

        let report = match parse_report(&record.stdout.bytes) {
            Ok(report) => report,
            Err(failure) => {
                record.raw_log =
                    discovered_log.and_then(|path| read_raw_log(operator.home(), &path).ok());
                let failure =
                    charge_failed_process(operator.budget_mut(), started.elapsed(), failure);
                record.finish(started, AgentctlOutcome::Failure(failure));
                return record;
            }
        };
        record.agent_command = Some(report.command);
        let raw_log_path = PathBuf::from(report.raw_log_path);
        let raw_log = match read_raw_log(operator.home(), &raw_log_path) {
            Ok(raw_log) => raw_log,
            Err(failure) => {
                let failure =
                    charge_failed_process(operator.budget_mut(), started.elapsed(), failure);
                record.finish(started, AgentctlOutcome::Failure(failure));
                return record;
            }
        };
        let raw_decision = extract_model_stdout(&raw_log.bytes).to_vec();
        record.raw_log = Some(raw_log);

        let identity = match ActorIdentity::load(&prepared.config.actor_key) {
            Ok(identity) if encode_hex(identity.actor_id().as_bytes()) == operator.actor_id() => {
                identity
            }
            Ok(_) => {
                let failure = charge_failed_process(
                    operator.budget_mut(),
                    started.elapsed(),
                    AgentctlFailure::identity(
                        "isolated signing key does not match the provisioned actor".to_owned(),
                    ),
                );
                record.finish(started, AgentctlOutcome::Failure(failure));
                return record;
            }
            Err(error) => {
                let failure = charge_failed_process(
                    operator.budget_mut(),
                    started.elapsed(),
                    AgentctlFailure::identity(error.to_string()),
                );
                record.finish(started, AgentctlOutcome::Failure(failure));
                return record;
            }
        };
        let decision = parse_and_sign_metered(
            raw_decision,
            decision_context,
            &identity,
            operator.budget_mut(),
            elapsed_seconds(started.elapsed()),
        );
        record.finish(started, AgentctlOutcome::Decision(decision));
        record
    }
}

struct PreparedInvocation {
    config: OperatorRuntimeConfig,
    remaining: ResourceUsage,
    prompt: Vec<u8>,
    prompt_path: PathBuf,
}

fn prepare(
    operator: &ProvisionedOperator,
    system_prompt: &[u8],
    observation: &ObservationSnapshot,
) -> Result<PreparedInvocation, AgentctlFailure> {
    if system_prompt.is_empty() || system_prompt.len() > MAX_SYSTEM_PROMPT_BYTES {
        return Err(AgentctlFailure::preflight(
            "AGENTCTL_PROMPT_INVALID",
            format!("system prompt must contain 1-{MAX_SYSTEM_PROMPT_BYTES} bytes"),
        ));
    }
    if observation.canonical_json().len() > MAX_OBSERVATION_BYTES {
        return Err(AgentctlFailure::preflight(
            "AGENTCTL_OBSERVATION_TOO_LARGE",
            "observation exceeds its host bound".to_owned(),
        ));
    }
    if observation.observation().actor_id() != operator.actor_id() {
        return Err(AgentctlFailure::preflight(
            "AGENTCTL_OBSERVATION_ACTOR_MISMATCH",
            "observation belongs to another operator".to_owned(),
        ));
    }

    let config_bytes = fs::read(operator.config_path()).map_err(|error| {
        AgentctlFailure::preflight(
            "AGENTCTL_CONFIG_UNAVAILABLE",
            format!("cannot read isolated runtime config: {error}"),
        )
    })?;
    let config: OperatorRuntimeConfig = serde_json::from_slice(&config_bytes).map_err(|error| {
        AgentctlFailure::preflight(
            "AGENTCTL_CONFIG_MALFORMED",
            format!("cannot parse isolated runtime config: {error}"),
        )
    })?;
    if config.operator_id != operator.operator_id()
        || config.actor_id != operator.actor_id()
        || config.home != operator.home()
        || config.worktree != operator.worktree()
        || config.actor_key != operator.home().join("identity/actor.key")
        || config.memory != operator.home().join("memory")
        || config.scratch != operator.home().join("scratch")
    {
        return Err(AgentctlFailure::preflight(
            "AGENTCTL_CONFIG_IDENTITY_MISMATCH",
            "runtime config does not match the provisioned operator".to_owned(),
        ));
    }
    if config.agent.tool_harness != "agentctl" {
        return Err(AgentctlFailure::preflight(
            "AGENTCTL_HARNESS_MISMATCH",
            "operator tool_harness must be agentctl".to_owned(),
        ));
    }
    if config.agent.provider.trim().is_empty()
        || config
            .agent
            .provider
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == 0)
    {
        return Err(AgentctlFailure::preflight(
            "AGENTCTL_PROVIDER_INVALID",
            "agent provider is not a valid profile name".to_owned(),
        ));
    }
    if hash_hex(system_prompt) != config.agent.system_prompt_sha256.to_ascii_lowercase() {
        return Err(AgentctlFailure::preflight(
            "AGENTCTL_SYSTEM_PROMPT_HASH_MISMATCH",
            "system prompt does not match isolated operator configuration".to_owned(),
        ));
    }
    if operator.worktree().join("agentctl.toml").exists() {
        return Err(AgentctlFailure::preflight(
            "AGENTCTL_WORKTREE_CONFIG_FORBIDDEN",
            "worktree agentctl.toml would override the isolated home configuration".to_owned(),
        ));
    }

    let remaining = operator.budget().remaining();
    let advertised = observation.observation().remaining_budget();
    if remaining != advertised {
        return Err(AgentctlFailure::preflight(
            "AGENTCTL_OBSERVATION_BUDGET_STALE",
            "observation does not advertise the host's exact remaining budget".to_owned(),
        ));
    }
    if remaining.model_calls == 0 || remaining.validation_seconds == 0 {
        return Err(AgentctlFailure::budget(
            "no model calls or validation time remain",
        ));
    }

    let mut prompt =
        Vec::with_capacity(system_prompt.len() + observation.canonical_json().len() + 128);
    prompt.extend_from_slice(system_prompt);
    prompt.extend_from_slice(
        b"\n\nReturn exactly one strict operator-decision.v1 JSON object for this bounded observation.\n",
    );
    prompt.extend_from_slice(observation.canonical_json());
    let prompt_path = write_prompt(&config.scratch, &prompt)?;

    Ok(PreparedInvocation {
        config,
        remaining,
        prompt,
        prompt_path,
    })
}

fn command_arguments(prepared: &PreparedInvocation) -> Vec<String> {
    vec![
        "run".to_owned(),
        prepared.config.agent.provider.clone(),
        "--prompt-file".to_owned(),
        prepared.prompt_path.display().to_string(),
        "--iterations".to_owned(),
        "1".to_owned(),
        "--cwd".to_owned(),
        prepared.config.worktree.display().to_string(),
        "--json".to_owned(),
        "--no-fallback".to_owned(),
    ]
}

fn write_prompt(scratch: &Path, prompt: &[u8]) -> Result<PathBuf, AgentctlFailure> {
    let scratch = fs::canonicalize(scratch).map_err(|error| {
        AgentctlFailure::preflight(
            "AGENTCTL_SCRATCH_UNAVAILABLE",
            format!("cannot canonicalize operator scratch: {error}"),
        )
    })?;
    let sequence = INVOCATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = scratch.join(format!(
        "agentctl-prompt-{}-{sequence}.txt",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW);
    let mut file = options.open(&path).map_err(|error| {
        AgentctlFailure::preflight(
            "AGENTCTL_PROMPT_FILE_FAILED",
            format!("cannot create bounded prompt file: {error}"),
        )
    })?;
    file.write_all(prompt).map_err(|error| {
        AgentctlFailure::preflight(
            "AGENTCTL_PROMPT_FILE_FAILED",
            format!("cannot write bounded prompt file: {error}"),
        )
    })?;
    file.sync_all().map_err(|error| {
        AgentctlFailure::preflight(
            "AGENTCTL_PROMPT_FILE_FAILED",
            format!("cannot sync bounded prompt file: {error}"),
        )
    })?;
    Ok(path)
}

#[derive(Default)]
struct WaitResult {
    status: Option<ExitStatus>,
    timed_out: bool,
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> WaitResult {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return WaitResult {
                    status: Some(status),
                    timed_out: false,
                };
            }
            Ok(None) if started.elapsed() < timeout => thread::sleep(PROCESS_POLL_INTERVAL),
            Ok(None) => {
                terminate(child);
                return WaitResult {
                    status: child.wait().ok(),
                    timed_out: true,
                };
            }
            Err(_) => {
                terminate(child);
                return WaitResult::default();
            }
        }
    }
}

fn terminate(child: &mut Child) {
    let _ = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .env_clear()
        .status();
    let started = Instant::now();
    while started.elapsed() < TERMINATION_GRACE {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => thread::sleep(PROCESS_POLL_INTERVAL),
        }
    }
    let _ = child.kill();
}

fn capture_reader(
    reader: Option<impl Read + Send + 'static>,
    maximum: usize,
) -> thread::JoinHandle<CapturedStream> {
    thread::spawn(move || {
        let Some(mut reader) = reader else {
            return CapturedStream::default();
        };
        let mut bytes = Vec::new();
        let mut total_bytes = 0_u64;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let count = match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            total_bytes = total_bytes.saturating_add(count as u64);
            hash.update(&buffer[..count]);
            if bytes.len() < maximum {
                let retained = count.min(maximum - bytes.len());
                bytes.extend_from_slice(&buffer[..retained]);
            }
        }
        CapturedStream {
            truncated: total_bytes > bytes.len() as u64,
            bytes,
            total_bytes,
            sha256: encode_digest(hash.finalize().as_slice()),
        }
    })
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapturedStream {
    pub bytes: Vec<u8>,
    pub total_bytes: u64,
    pub sha256: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawLogEvidence {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub total_bytes: u64,
    pub sha256: String,
    pub truncated: bool,
}

fn read_raw_log(home: &Path, path: &Path) -> Result<RawLogEvidence, AgentctlFailure> {
    let canonical_home = fs::canonicalize(home).map_err(|error| {
        AgentctlFailure::raw_log(format!("cannot canonicalize operator home: {error}"))
    })?;
    let canonical = fs::canonicalize(path)
        .map_err(|error| AgentctlFailure::raw_log(format!("cannot open raw log: {error}")))?;
    let jobs_root = canonical_home.join(".agentctl/jobs");
    if !canonical.starts_with(&jobs_root) {
        return Err(AgentctlFailure::raw_log(
            "agentctl raw log escaped the isolated home".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| AgentctlFailure::raw_log(format!("cannot inspect raw log: {error}")))?;
    if !metadata.file_type().is_file() {
        return Err(AgentctlFailure::raw_log(
            "agentctl raw log is not a regular file".to_owned(),
        ));
    }
    let mut file = File::open(&canonical)
        .map_err(|error| AgentctlFailure::raw_log(format!("cannot read raw log: {error}")))?;
    let mut bytes = Vec::new();
    let mut hash = Sha256::new();
    let mut total_bytes = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| AgentctlFailure::raw_log(format!("cannot read raw log: {error}")))?;
        if count == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(count as u64);
        hash.update(&buffer[..count]);
        if bytes.len() < MAX_AGENTCTL_RAW_LOG_BYTES {
            let retained = count.min(MAX_AGENTCTL_RAW_LOG_BYTES - bytes.len());
            bytes.extend_from_slice(&buffer[..retained]);
        }
    }
    Ok(RawLogEvidence {
        path: canonical,
        sha256: encode_digest(hash.finalize().as_slice()),
        truncated: total_bytes > bytes.len() as u64,
        bytes,
        total_bytes,
    })
}

fn extract_model_stdout(raw_log: &[u8]) -> &[u8] {
    let Some(rest) = raw_log.strip_prefix(b"stdout:\n") else {
        return &[];
    };
    let output = find_subslice(rest, b"\nstderr:\n").map_or(rest, |index| &rest[..index]);
    output.strip_suffix(b"\n").unwrap_or(output)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForegroundReport {
    iteration: u32,
    iterations: u32,
    summary: AgentctlSummary,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentctlSummary {
    command: String,
    exit_code: i32,
    duration_ms: u64,
    preview_lines: Vec<String>,
    raw_log_path: String,
}

fn parse_report(bytes: &[u8]) -> Result<AgentctlSummary, AgentctlFailure> {
    let reports: Vec<ForegroundReport> = serde_json::from_slice(bytes).map_err(|error| {
        AgentctlFailure::report(format!("agentctl emitted malformed JSON report: {error}"))
    })?;
    if reports.len() != 1
        || reports[0].iteration != 1
        || reports[0].iterations != 1
        || reports[0].summary.exit_code != 0
        || reports[0].summary.command.is_empty()
        || reports[0].summary.preview_lines.len() > 1024
        || reports[0].summary.duration_ms == u64::MAX
    {
        return Err(AgentctlFailure::report(
            "agentctl report violated the one-iteration bounded contract".to_owned(),
        ));
    }
    Ok(reports.into_iter().next().expect("one report").summary)
}

fn list_raw_logs(home: &Path) -> Result<BTreeSet<PathBuf>, std::io::Error> {
    let root = home.join(".agentctl/jobs");
    let mut logs = BTreeSet::new();
    let Ok(entries) = fs::read_dir(root) else {
        return Ok(logs);
    };
    for entry in entries.take(16_384).flatten() {
        let path = entry.path().join("output.log");
        if path.is_file() {
            logs.insert(path);
        }
    }
    Ok(logs)
}

fn discover_raw_log(home: &Path, prior: &BTreeSet<PathBuf>) -> Option<PathBuf> {
    list_raw_logs(home)
        .ok()?
        .into_iter()
        .filter(|path| !prior.contains(path))
        .max_by_key(|path| {
            fs::metadata(path)
                .and_then(|metadata| metadata.modified())
                .ok()
        })
}

fn charge_failed_process(
    budget: &mut BudgetTracker,
    elapsed: Duration,
    original: AgentctlFailure,
) -> AgentctlFailure {
    let remaining = budget.remaining();
    let usage = ResourceUsage {
        model_calls: 1,
        tool_calls: 0,
        validation_seconds: elapsed_seconds(elapsed).min(remaining.validation_seconds),
    };
    match budget.charge(usage) {
        Ok(()) => original,
        Err(error) => AgentctlFailure::from_budget(error),
    }
}

fn elapsed_seconds(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis().saturating_add(999) / 1000)
        .unwrap_or(u64::MAX)
        .max(1)
}

fn inherited_path() -> std::ffi::OsString {
    std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into())
}

fn canonical_regular_file(path: &Path, subject: &str) -> Result<PathBuf, AgentctlError> {
    let canonical = fs::canonicalize(path).map_err(|source| AgentctlError::Io {
        operation: "canonicalize",
        subject: subject.to_owned(),
        source,
    })?;
    if !canonical.is_file() {
        return Err(AgentctlError::NotRegularFile(subject.to_owned()));
    }
    Ok(canonical)
}

fn hash_hex(bytes: &[u8]) -> String {
    encode_digest(Sha256::digest(bytes).as_slice())
}

fn encode_hex(bytes: &[u8]) -> String {
    encode_digest(bytes)
}

fn encode_digest(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[derive(Debug)]
pub struct AgentctlInvocationRecord {
    pub executable: PathBuf,
    /// Arguments only; the executable is pinned separately and no shell is used.
    pub command: Vec<String>,
    pub system_prompt_sha256: String,
    pub observation_sha256: String,
    /// Exact bounded prompt supplied through the temporary prompt file.
    pub prompt: Vec<u8>,
    pub prompt_sha256: String,
    pub duration_ms: u128,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
    pub raw_log: Option<RawLogEvidence>,
    /// Exact provider command reported by the pinned agentctl process.
    pub agent_command: Option<String>,
    pub outcome: AgentctlOutcome,
    pub provenance: ProvenanceStatus,
}

impl AgentctlInvocationRecord {
    /// Exact provider stdout retained at the model boundary. Process failures
    /// return any model stdout recovered from the raw agent log.
    #[must_use]
    pub fn raw_output(&self) -> &[u8] {
        match &self.outcome {
            AgentctlOutcome::Decision(decision) => decision.raw_output(),
            AgentctlOutcome::Failure(_) => self
                .raw_log
                .as_ref()
                .map_or(&[], |raw_log| extract_model_stdout(&raw_log.bytes)),
        }
    }

    fn new(executable: PathBuf, system_prompt_sha256: String, observation_sha256: String) -> Self {
        Self {
            executable,
            command: Vec::new(),
            system_prompt_sha256,
            observation_sha256,
            prompt: Vec::new(),
            prompt_sha256: String::new(),
            duration_ms: 0,
            exit_code: None,
            timed_out: false,
            stdout: CapturedStream::default(),
            stderr: CapturedStream::default(),
            raw_log: None,
            agent_command: None,
            outcome: AgentctlOutcome::Failure(AgentctlFailure::preflight(
                "AGENTCTL_INVOCATION_INCOMPLETE",
                "invocation did not reach a terminal state".to_owned(),
            )),
            provenance: ProvenanceStatus::Pending,
        }
    }

    fn finish(&mut self, started: Instant, outcome: AgentctlOutcome) {
        self.duration_ms = started.elapsed().as_millis();
        self.outcome = outcome;
    }
}

#[derive(Debug)]
pub enum AgentctlOutcome {
    Decision(DecisionRecord),
    Failure(AgentctlFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentctlFailure {
    pub code: &'static str,
    pub message: String,
}

impl AgentctlFailure {
    fn preflight(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    fn spawn(error: std::io::Error) -> Self {
        Self::preflight(
            "AGENTCTL_SPAWN_FAILED",
            format!("cannot spawn agentctl: {error}"),
        )
    }

    fn wait(message: &str) -> Self {
        Self::preflight("AGENTCTL_WAIT_FAILED", message.to_owned())
    }

    fn timeout(seconds: u64) -> Self {
        Self::preflight(
            "AGENTCTL_TIMEOUT",
            format!("agentctl exceeded the {seconds}-second validation budget"),
        )
    }

    fn crash(status: ExitStatus) -> Self {
        Self::preflight(
            "AGENTCTL_PROCESS_FAILED",
            format!("agentctl exited unsuccessfully with status {status}"),
        )
    }

    fn report(message: String) -> Self {
        Self::preflight("AGENTCTL_REPORT_MALFORMED", message)
    }

    fn raw_log(message: String) -> Self {
        Self::preflight("AGENTCTL_RAW_LOG_INVALID", message)
    }

    fn identity(message: String) -> Self {
        Self::preflight("AGENTCTL_IDENTITY_FAILED", message)
    }

    fn budget(message: &str) -> Self {
        Self::preflight("OPERATOR_BUDGET_EXCEEDED", message.to_owned())
    }

    fn from_budget(error: BudgetError) -> Self {
        Self::preflight(error.code(), error.to_string())
    }
}

#[derive(Debug)]
pub enum AgentctlError {
    NotRegularFile(String),
    Io {
        operation: &'static str,
        subject: String,
        source: std::io::Error,
    },
}

impl fmt::Display for AgentctlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegularFile(subject) => write!(formatter, "{subject} is not a regular file"),
            Self::Io {
                operation,
                subject,
                source,
            } => write!(formatter, "cannot {operation} {subject}: {source}"),
        }
    }
}

impl std::error::Error for AgentctlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::NotRegularFile(_) => None,
        }
    }
}
