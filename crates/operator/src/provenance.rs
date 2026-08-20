//! Immutable, host-private provenance for autonomous operator invocations.
//!
//! Every terminal `agentctl` attempt commits its sensitive bytes beneath the
//! operator's host-owned provenance root. Public node RPC has no handle to this
//! store; callers receive only a local manifest path and content hash.

use crate::{
    agentctl::{AgentctlInvocationRecord, AgentctlOutcome},
    budget::ResourceUsage,
    decision::{DecisionContext, DecisionResourceReport, ParsedDecision},
    host::ProvisionedOperator,
    observation::ObservationSnapshot,
};
use rachet_client::signing::canonical_action;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fmt, fs,
    io::Write as _,
    os::unix::{
        ffi::OsStrExt as _,
        fs::{OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Component, Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub const OPERATOR_PROVENANCE_SCHEMA_VERSION: &str = "operator-provenance.v1";
const MANIFEST_FILE: &str = "manifest.json";
const O_NOFOLLOW: i32 = 0o400_000;
static PROVENANCE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    pub path: String,
    pub media_type: String,
    pub bytes: u64,
    /// Content-addressed reference in `sha256:<lowercase hex>` form.
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorIdentityProvenance {
    pub operator_id: String,
    pub actor_id: String,
    pub role: String,
    pub objective: String,
    pub model: String,
    pub provider: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationHashes {
    pub system_prompt_sha256: String,
    pub observation_sha256: String,
    pub prompt_sha256: String,
    pub raw_output_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureProvenance {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperatorRunOutcome {
    Completed,
    Failed { failure: FailureProvenance },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionProvenance {
    pub parsed_decision: Option<ParsedDecision>,
    pub raw_output: ArtifactReference,
    pub failure: Option<FailureProvenance>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmittedActionProvenance {
    pub action_id: String,
    pub canonical_action: ArtifactReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCommandProvenance {
    pub boundary: String,
    pub executable: String,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedLogProvenance {
    pub retained: ArtifactReference,
    pub total_bytes: u64,
    /// SHA-256 of the complete source stream, including bytes beyond retention.
    pub source_sha256: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogProvenance {
    pub stdout: CapturedLogProvenance,
    pub stderr: CapturedLogProvenance,
    pub raw_agent_log: Option<CapturedLogProvenance>,
    pub raw_agent_log_source_location: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsageProvenance {
    pub used_before: ResourceUsage,
    pub used_after: ResourceUsage,
    pub charged: ResourceUsage,
    pub reported: Option<DecisionResourceReport>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTimeProvenance {
    pub started_unix_milliseconds: u128,
    pub finished_unix_milliseconds: u128,
    pub wall_clock_milliseconds: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UntrackedWorktreeEntry {
    /// Exact Git path bytes, hex encoded so non-UTF-8 names remain auditable.
    pub path_hex: String,
    pub file_type: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitWorktreeState {
    pub head_revision: String,
    pub status_porcelain_v2: ArtifactReference,
    pub diff_from_head: ArtifactReference,
    pub untracked: Vec<UntrackedWorktreeEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorktreeProvenance {
    pub before: GitWorktreeState,
    pub after: GitWorktreeState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifactProvenance {
    pub reference: String,
    pub evidence_id: String,
    pub job_id: String,
    pub claim_id: Option<String>,
    pub selected_by_decision: bool,
}

/// Complete section 30 record. Raw prompt, observation, output, logs, Git
/// projections, and canonical actions are represented only by immutable local
/// artifact references rather than being embedded in public-facing data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorProvenanceManifest {
    pub schema_version: String,
    pub invocation_id: String,
    pub operator: OperatorIdentityProvenance,
    pub hashes: InvocationHashes,
    pub system_prompt: ArtifactReference,
    pub observation: ArtifactReference,
    pub prompt: ArtifactReference,
    pub decision: DecisionProvenance,
    pub submitted_actions: Vec<SubmittedActionProvenance>,
    pub tool_commands: Vec<ToolCommandProvenance>,
    pub logs: LogProvenance,
    pub usage: UsageProvenance,
    pub time: ExecutionTimeProvenance,
    pub worktree: WorktreeProvenance,
    pub evidence_artifacts: Vec<EvidenceArtifactProvenance>,
    pub outcome: OperatorRunOutcome,
    pub artifacts: Vec<ArtifactReference>,
}

/// Host-private immutable pointer returned after a committed invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceReference {
    pub manifest_path: PathBuf,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceFailure {
    pub code: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProvenanceStatus {
    Pending,
    Committed(ProvenanceReference),
    Failed(ProvenanceFailure),
}

pub(crate) struct PendingProvenance {
    invocation_id: String,
    started_unix_milliseconds: u128,
    used_before: ResourceUsage,
    before: CapturedGitState,
}

struct CapturedGitState {
    state: GitWorktreeState,
    files: Vec<StagedArtifact>,
}

struct StagedArtifact {
    reference: ArtifactReference,
    bytes: Vec<u8>,
}

pub struct OperatorProvenanceStore;

impl OperatorProvenanceStore {
    pub(crate) fn begin(
        operator: &ProvisionedOperator,
    ) -> Result<PendingProvenance, ProvenanceFailure> {
        let started_unix_milliseconds = unix_milliseconds()?;
        let sequence = PROVENANCE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let invocation_id = format!(
            "{}-{}-{sequence}",
            started_unix_milliseconds,
            std::process::id()
        );
        let before = capture_git_state(operator.worktree(), "worktree-before")?;
        Ok(PendingProvenance {
            invocation_id,
            started_unix_milliseconds,
            used_before: operator.budget().used(),
            before,
        })
    }

    pub(crate) fn commit(
        pending: PendingProvenance,
        operator: &ProvisionedOperator,
        system_prompt: &[u8],
        observation: &ObservationSnapshot,
        context: DecisionContext<'_>,
        record: &AgentctlInvocationRecord,
    ) -> Result<ProvenanceReference, ProvenanceFailure> {
        let after = capture_git_state(operator.worktree(), "worktree-after")?;
        let finished_unix_milliseconds = unix_milliseconds()?;
        let mut files = pending.before.files;
        files.extend(after.files);

        let system_prompt_ref = stage(
            &mut files,
            "system-prompt.bin",
            "application/octet-stream",
            system_prompt.to_vec(),
        );
        let observation_ref = stage(
            &mut files,
            "observation.json",
            "application/json",
            observation.canonical_json().to_vec(),
        );
        let prompt_ref = stage(
            &mut files,
            "prompt.bin",
            "application/octet-stream",
            record.prompt.clone(),
        );
        let raw_output = exact_raw_output(record);
        let raw_output_ref = stage(
            &mut files,
            "raw-output.bin",
            "application/octet-stream",
            raw_output,
        );
        let stdout_ref = stage(
            &mut files,
            "agentctl-stdout.bin",
            "application/octet-stream",
            record.stdout.bytes.clone(),
        );
        let stderr_ref = stage(
            &mut files,
            "agentctl-stderr.bin",
            "application/octet-stream",
            record.stderr.bytes.clone(),
        );
        let raw_log_ref = record
            .raw_log
            .as_ref()
            .map(|raw_log| CapturedLogProvenance {
                retained: stage(
                    &mut files,
                    "agentctl-raw-log.bin",
                    "application/octet-stream",
                    raw_log.bytes.clone(),
                ),
                total_bytes: raw_log.total_bytes,
                source_sha256: raw_log.sha256.clone(),
                truncated: raw_log.truncated,
            });

        let (parsed_decision, decision_failure, reported, outcome) = match &record.outcome {
            AgentctlOutcome::Decision(decision) => {
                let failure = decision.failure.as_ref().map(|failure| FailureProvenance {
                    code: failure.code.to_owned(),
                    message: failure.message.clone(),
                });
                let outcome = failure
                    .clone()
                    .map_or(OperatorRunOutcome::Completed, |failure| {
                        OperatorRunOutcome::Failed { failure }
                    });
                (
                    decision.parsed_decision.clone(),
                    failure,
                    decision
                        .parsed_decision
                        .as_ref()
                        .map(|parsed| parsed.resource_report),
                    outcome,
                )
            }
            AgentctlOutcome::Failure(failure) => {
                let failure = FailureProvenance {
                    code: failure.code.to_owned(),
                    message: failure.message.clone(),
                };
                (
                    None,
                    Some(failure.clone()),
                    None,
                    OperatorRunOutcome::Failed { failure },
                )
            }
        };

        let mut submitted_actions = Vec::new();
        if let AgentctlOutcome::Decision(decision) = &record.outcome {
            for (index, action) in decision.signed_actions.iter().enumerate() {
                let reference = stage(
                    &mut files,
                    &format!("submitted-action-{index:04}.bin"),
                    "application/vnd.rachet.signed-action",
                    canonical_action(action),
                );
                submitted_actions.push(SubmittedActionProvenance {
                    action_id: encode_hex(action.action_id().as_bytes()),
                    canonical_action: reference,
                });
            }
        }

        let selected_evidence = selected_evidence_refs(parsed_decision.as_ref());
        let evidence_artifacts = context
            .available_evidence
            .iter()
            .map(|evidence| EvidenceArtifactProvenance {
                reference: evidence.reference.clone(),
                evidence_id: encode_hex(evidence.evidence_id.as_bytes()),
                job_id: encode_hex(evidence.job_id.as_bytes()),
                claim_id: evidence.claim_id.map(|claim| encode_hex(claim.as_bytes())),
                selected_by_decision: selected_evidence.contains(evidence.reference.as_str()),
            })
            .collect();

        let mut tool_commands = Vec::new();
        if !record.command.is_empty() {
            tool_commands.push(ToolCommandProvenance {
                boundary: "agentctl_process".to_owned(),
                executable: record.executable.display().to_string(),
                arguments: record.command.clone(),
            });
        }
        if let Some(command) = &record.agent_command {
            tool_commands.push(ToolCommandProvenance {
                boundary: "agent_provider".to_owned(),
                executable: command.clone(),
                arguments: Vec::new(),
            });
        }

        let used_after = operator.budget().used();
        let manifest = OperatorProvenanceManifest {
            schema_version: OPERATOR_PROVENANCE_SCHEMA_VERSION.to_owned(),
            invocation_id: pending.invocation_id.clone(),
            operator: OperatorIdentityProvenance {
                operator_id: operator.operator_id().to_owned(),
                actor_id: operator.actor_id().to_owned(),
                role: operator.role().to_owned(),
                objective: operator.objective().to_owned(),
                model: operator.agent().model.clone(),
                provider: operator.agent().provider.clone(),
            },
            hashes: InvocationHashes {
                system_prompt_sha256: digest_hex(system_prompt),
                observation_sha256: digest_hex(observation.canonical_json()),
                prompt_sha256: digest_hex(&record.prompt),
                raw_output_sha256: raw_output_ref.sha256[7..].to_owned(),
            },
            system_prompt: system_prompt_ref,
            observation: observation_ref,
            prompt: prompt_ref,
            decision: DecisionProvenance {
                parsed_decision,
                raw_output: raw_output_ref,
                failure: decision_failure,
            },
            submitted_actions,
            tool_commands,
            logs: LogProvenance {
                stdout: CapturedLogProvenance {
                    retained: stdout_ref,
                    total_bytes: record.stdout.total_bytes,
                    source_sha256: complete_stream_hash(
                        &record.stdout.sha256,
                        &record.stdout.bytes,
                    ),
                    truncated: record.stdout.truncated,
                },
                stderr: CapturedLogProvenance {
                    retained: stderr_ref,
                    total_bytes: record.stderr.total_bytes,
                    source_sha256: complete_stream_hash(
                        &record.stderr.sha256,
                        &record.stderr.bytes,
                    ),
                    truncated: record.stderr.truncated,
                },
                raw_agent_log: raw_log_ref,
                raw_agent_log_source_location: record
                    .raw_log
                    .as_ref()
                    .map(|raw_log| raw_log.path.display().to_string()),
            },
            usage: UsageProvenance {
                used_before: pending.used_before,
                used_after,
                charged: usage_difference(used_after, pending.used_before),
                reported,
            },
            time: ExecutionTimeProvenance {
                started_unix_milliseconds: pending.started_unix_milliseconds,
                finished_unix_milliseconds,
                wall_clock_milliseconds: record.duration_ms,
            },
            worktree: WorktreeProvenance {
                before: pending.before.state,
                after: after.state,
            },
            evidence_artifacts,
            outcome,
            artifacts: files.iter().map(|file| file.reference.clone()).collect(),
        };

        validate_manifest(&manifest)?;
        let run_root = operator.provenance_root().join(&pending.invocation_id);
        fs::create_dir(&run_root)
            .map_err(|error| failure("OPERATOR_PROVENANCE_CREATE_FAILED", error.to_string()))?;
        fs::set_permissions(&run_root, fs::Permissions::from_mode(0o700))
            .map_err(|error| failure("OPERATOR_PROVENANCE_CREATE_FAILED", error.to_string()))?;

        for file in &files {
            write_new(&run_root.join(&file.reference.path), &file.bytes)?;
        }
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| failure("OPERATOR_PROVENANCE_MANIFEST_INVALID", error.to_string()))?;
        manifest_bytes.push(b'\n');
        let manifest_path = run_root.join(MANIFEST_FILE);
        write_new(&manifest_path, &manifest_bytes)?;
        make_read_only(&run_root, &manifest)?;

        Ok(ProvenanceReference {
            manifest_path,
            manifest_sha256: format!("sha256:{}", digest_hex(&manifest_bytes)),
        })
    }

    /// Verifies the manifest hash, exact directory inventory, and every
    /// immutable artifact's length and SHA-256 reference.
    pub fn verify(
        reference: &ProvenanceReference,
    ) -> Result<OperatorProvenanceManifest, ProvenanceFailure> {
        let bytes = read_regular(&reference.manifest_path)?;
        let actual = format!("sha256:{}", digest_hex(&bytes));
        if actual != reference.manifest_sha256 {
            return Err(failure(
                "OPERATOR_PROVENANCE_HASH_MISMATCH",
                "manifest hash does not match its immutable reference".to_owned(),
            ));
        }
        let manifest: OperatorProvenanceManifest = serde_json::from_slice(&bytes)
            .map_err(|error| failure("OPERATOR_PROVENANCE_MANIFEST_INVALID", error.to_string()))?;
        validate_manifest(&manifest)?;
        let root = reference.manifest_path.parent().ok_or_else(|| {
            failure(
                "OPERATOR_PROVENANCE_MANIFEST_INVALID",
                "manifest has no parent directory".to_owned(),
            )
        })?;
        let expected: BTreeSet<_> = manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.path.clone())
            .chain(std::iter::once(MANIFEST_FILE.to_owned()))
            .collect();
        let actual: BTreeSet<_> = fs::read_dir(root)
            .map_err(|error| failure("OPERATOR_PROVENANCE_READ_FAILED", error.to_string()))?
            .map(|entry| {
                entry
                    .map_err(|error| failure("OPERATOR_PROVENANCE_READ_FAILED", error.to_string()))
                    .and_then(|entry| {
                        entry.file_name().into_string().map_err(|_| {
                            failure(
                                "OPERATOR_PROVENANCE_MANIFEST_INVALID",
                                "artifact file name is not UTF-8".to_owned(),
                            )
                        })
                    })
            })
            .collect::<Result<_, _>>()?;
        if actual != expected {
            return Err(failure(
                "OPERATOR_PROVENANCE_INVENTORY_MISMATCH",
                "provenance directory contains missing or unlisted artifacts".to_owned(),
            ));
        }
        for artifact in &manifest.artifacts {
            let artifact_bytes = read_regular(&root.join(&artifact.path))?;
            if artifact.bytes != artifact_bytes.len() as u64
                || artifact.sha256 != format!("sha256:{}", digest_hex(&artifact_bytes))
            {
                return Err(failure(
                    "OPERATOR_PROVENANCE_HASH_MISMATCH",
                    format!(
                        "artifact {} failed length or hash verification",
                        artifact.path
                    ),
                ));
            }
        }
        Ok(manifest)
    }
}

fn capture_git_state(worktree: &Path, prefix: &str) -> Result<CapturedGitState, ProvenanceFailure> {
    let head = git(worktree, &["rev-parse", "--verify", "HEAD"])?;
    let head_revision = String::from_utf8(head)
        .map_err(|error| failure("OPERATOR_PROVENANCE_GIT_FAILED", error.to_string()))?
        .trim()
        .to_owned();
    if head_revision.len() != 40 && head_revision.len() != 64 {
        return Err(failure(
            "OPERATOR_PROVENANCE_GIT_FAILED",
            "worktree HEAD is not a full object ID".to_owned(),
        ));
    }
    let status = git(worktree, &["status", "--porcelain=v2", "--branch", "-z"])?;
    let diff = git(
        worktree,
        &[
            "diff",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            "HEAD",
            "--",
        ],
    )?;
    let untracked_paths = git(
        worktree,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?;
    let mut files = Vec::new();
    let status_ref = stage(
        &mut files,
        &format!("{prefix}-status.bin"),
        "application/octet-stream",
        status,
    );
    let diff_ref = stage(
        &mut files,
        &format!("{prefix}-diff.bin"),
        "application/octet-stream",
        diff,
    );
    let mut untracked = Vec::new();
    for relative in untracked_paths
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let path = worktree.join(OsStr::from_bytes(relative));
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| failure("OPERATOR_PROVENANCE_GIT_FAILED", error.to_string()))?;
        let (file_type, bytes) = if metadata.file_type().is_file() {
            ("regular_file", fs::read(&path))
        } else if metadata.file_type().is_symlink() {
            (
                "symbolic_link",
                fs::read_link(&path).map(|target| target.as_os_str().as_bytes().to_vec()),
            )
        } else {
            return Err(failure(
                "OPERATOR_PROVENANCE_GIT_FAILED",
                "untracked worktree entry is not a regular file or symbolic link".to_owned(),
            ));
        };
        let bytes =
            bytes.map_err(|error| failure("OPERATOR_PROVENANCE_GIT_FAILED", error.to_string()))?;
        untracked.push(UntrackedWorktreeEntry {
            path_hex: encode_hex(relative),
            file_type: file_type.to_owned(),
            bytes: bytes.len() as u64,
            sha256: format!("sha256:{}", digest_hex(&bytes)),
        });
    }
    Ok(CapturedGitState {
        state: GitWorktreeState {
            head_revision,
            status_porcelain_v2: status_ref,
            diff_from_head: diff_ref,
            untracked,
        },
        files,
    })
}

fn git(worktree: &Path, arguments: &[&str]) -> Result<Vec<u8>, ProvenanceFailure> {
    let output = Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .map_err(|error| failure("OPERATOR_PROVENANCE_GIT_FAILED", error.to_string()))?;
    if !output.status.success() {
        return Err(failure(
            "OPERATOR_PROVENANCE_GIT_FAILED",
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(output.stdout)
}

fn exact_raw_output(record: &AgentctlInvocationRecord) -> Vec<u8> {
    if let AgentctlOutcome::Decision(decision) = &record.outcome {
        return decision.raw_output().to_vec();
    }
    let Some(raw_log) = &record.raw_log else {
        return Vec::new();
    };
    let Some(rest) = raw_log.bytes.strip_prefix(b"stdout:\n") else {
        return Vec::new();
    };
    let output = rest
        .windows(b"\nstderr:\n".len())
        .position(|window| window == b"\nstderr:\n")
        .map_or(rest, |index| &rest[..index]);
    output.strip_suffix(b"\n").unwrap_or(output).to_vec()
}

fn selected_evidence_refs(parsed: Option<&ParsedDecision>) -> BTreeSet<&str> {
    use crate::decision::ParsedDecisionKind;
    let claims = match parsed.map(|parsed| &parsed.kind) {
        Some(ParsedDecisionKind::Validate { claims, .. })
        | Some(ParsedDecisionKind::Challenge { claims, .. }) => claims.as_slice(),
        _ => &[],
    };
    claims
        .iter()
        .flat_map(|claim| claim.evidence_refs.iter().map(String::as_str))
        .collect()
}

fn complete_stream_hash(source_sha256: &str, retained: &[u8]) -> String {
    if source_sha256.is_empty() {
        digest_hex(retained)
    } else {
        source_sha256.to_owned()
    }
}

fn usage_difference(after: ResourceUsage, before: ResourceUsage) -> ResourceUsage {
    ResourceUsage {
        model_calls: after.model_calls.saturating_sub(before.model_calls),
        tool_calls: after.tool_calls.saturating_sub(before.tool_calls),
        validation_seconds: after
            .validation_seconds
            .saturating_sub(before.validation_seconds),
    }
}

fn stage(
    files: &mut Vec<StagedArtifact>,
    path: &str,
    media_type: &str,
    bytes: Vec<u8>,
) -> ArtifactReference {
    let reference = ArtifactReference {
        path: path.to_owned(),
        media_type: media_type.to_owned(),
        bytes: bytes.len() as u64,
        sha256: format!("sha256:{}", digest_hex(&bytes)),
    };
    files.push(StagedArtifact {
        reference: reference.clone(),
        bytes,
    });
    reference
}

fn validate_manifest(manifest: &OperatorProvenanceManifest) -> Result<(), ProvenanceFailure> {
    if manifest.schema_version != OPERATOR_PROVENANCE_SCHEMA_VERSION {
        return Err(failure(
            "OPERATOR_PROVENANCE_MANIFEST_INVALID",
            "unsupported provenance schema version".to_owned(),
        ));
    }
    let mut paths = BTreeSet::new();
    for artifact in &manifest.artifacts {
        validate_relative_name(&artifact.path)?;
        if !paths.insert(artifact.path.as_str()) || !valid_sha256_ref(&artifact.sha256) {
            return Err(failure(
                "OPERATOR_PROVENANCE_MANIFEST_INVALID",
                "artifact paths must be unique and hashes must be sha256 references".to_owned(),
            ));
        }
    }
    for reference in required_references(manifest) {
        if !manifest.artifacts.contains(reference) {
            return Err(failure(
                "OPERATOR_PROVENANCE_MANIFEST_INVALID",
                format!(
                    "nested artifact reference {} is not inventoried",
                    reference.path
                ),
            ));
        }
    }
    if manifest.hashes.system_prompt_sha256 != manifest.system_prompt.sha256[7..]
        || manifest.hashes.observation_sha256 != manifest.observation.sha256[7..]
        || manifest.hashes.prompt_sha256 != manifest.prompt.sha256[7..]
        || manifest.hashes.raw_output_sha256 != manifest.decision.raw_output.sha256[7..]
    {
        return Err(failure(
            "OPERATOR_PROVENANCE_MANIFEST_INVALID",
            "raw hash fields do not match immutable artifacts".to_owned(),
        ));
    }
    Ok(())
}

fn required_references(manifest: &OperatorProvenanceManifest) -> Vec<&ArtifactReference> {
    let mut references = vec![
        &manifest.system_prompt,
        &manifest.observation,
        &manifest.prompt,
        &manifest.decision.raw_output,
        &manifest.logs.stdout.retained,
        &manifest.logs.stderr.retained,
        &manifest.worktree.before.status_porcelain_v2,
        &manifest.worktree.before.diff_from_head,
        &manifest.worktree.after.status_porcelain_v2,
        &manifest.worktree.after.diff_from_head,
    ];
    references.extend(manifest.logs.raw_agent_log.iter().map(|log| &log.retained));
    references.extend(
        manifest
            .submitted_actions
            .iter()
            .map(|action| &action.canonical_action),
    );
    references
}

fn validate_relative_name(path: &str) -> Result<(), ProvenanceFailure> {
    let path = Path::new(path);
    if path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
        || path == Path::new(MANIFEST_FILE)
    {
        return Err(failure(
            "OPERATOR_PROVENANCE_MANIFEST_INVALID",
            "artifact path is not a direct relative file name".to_owned(),
        ));
    }
    Ok(())
}

fn valid_sha256_ref(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), ProvenanceFailure> {
    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| failure("OPERATOR_PROVENANCE_WRITE_FAILED", error.to_string()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| failure("OPERATOR_PROVENANCE_WRITE_FAILED", error.to_string()))
}

fn read_regular(path: &Path) -> Result<Vec<u8>, ProvenanceFailure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| failure("OPERATOR_PROVENANCE_READ_FAILED", error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(failure(
            "OPERATOR_PROVENANCE_READ_FAILED",
            format!("{} is not a regular file", path.display()),
        ));
    }
    fs::read(path).map_err(|error| failure("OPERATOR_PROVENANCE_READ_FAILED", error.to_string()))
}

fn make_read_only(
    root: &Path,
    manifest: &OperatorProvenanceManifest,
) -> Result<(), ProvenanceFailure> {
    for artifact in manifest
        .artifacts
        .iter()
        .map(|artifact| root.join(&artifact.path))
        .chain(std::iter::once(root.join(MANIFEST_FILE)))
    {
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o400))
            .map_err(|error| failure("OPERATOR_PROVENANCE_WRITE_FAILED", error.to_string()))?;
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o500))
        .map_err(|error| failure("OPERATOR_PROVENANCE_WRITE_FAILED", error.to_string()))
}

fn unix_milliseconds() -> Result<u128, ProvenanceFailure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| failure("OPERATOR_PROVENANCE_TIME_FAILED", error.to_string()))
}

fn digest_hex(bytes: &[u8]) -> String {
    encode_hex(Sha256::digest(bytes).as_slice())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn failure(code: &'static str, message: String) -> ProvenanceFailure {
    ProvenanceFailure { code, message }
}
