use commonware_codec::DecodeExt as _;
use rachet_client::{
    identity::{ActorIdentity, IdentityError},
    signing::{ActionSigningRequest, SigningError, canonical_action, sign_action},
    transport::{NodeClient, TransportError},
};
use rachet_core::{
    actions::{
        Action, ChallengeTarget, ClaimDefinition, CloseJob, CommitmentSubject, CreateChallenge,
        CreateCommitment, CreateJob, RegisterEvidence, ResolutionPolicy, ResolutionVerdict,
        ResolveChallenge, ResolveClaim, RevealCommitment, SubmitAttestation, Verdict,
    },
    artifacts::{ContentRef, GitArtifact, GitHash},
    bounded::{BoundedBytes, BoundedVec},
    limits::{
        MAX_ACTION_BYTES, MAX_CLAIM_STATEMENT_BYTES, MAX_CLAIMS_PER_JOB,
        MAX_COMMITMENT_PAYLOAD_BYTES, MAX_COMMITMENT_SALT_BYTES, MAX_CONTENT_LOCATOR_HINT_BYTES,
        MAX_COUNTERCLAIM_BYTES, MAX_EVIDENCE_IDS_PER_ACTION, MAX_MEDIA_TYPE_BYTES,
        MAX_METADATA_BYTES, MAX_REPOSITORY_LOCATOR_BYTES,
    },
    mechanisms::MechanismId,
    primitives::{
        ActorId, AttestationId, ChainId, ChallengeId, ClaimId, CommitmentId, Ed25519PublicKey,
        EvidenceId, JobId, ProtocolVersion, Sha256Digest,
    },
};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

const ACTOR_KEY_ENVIRONMENT_KEY: &str = "RCHT_ACTOR_KEY";
const NODE_URL_ENVIRONMENT_KEY: &str = "RCHT_NODE_URL";
const DEFAULT_NODE_URL: &str = "http://127.0.0.1:32000";
const DEFAULT_VALID_FOR_BLOCKS: u64 = 32;
const USAGE: &str = "rchtctl [--json] <command> [options]\n\n\
identity commands:\n\
  identity create [--key PATH]\n\
  identity show [--key PATH]\n\
  identity sign [--key PATH] --chain-id HEX --nonce U64\n\
                --valid-until-height U64 [--protocol-version U16] --action HEX\n\n\
job commands:\n\
  job create [--node-url URL] [--key PATH] --chain-id HEX\n\
             --repository LOCATOR --base-commit ALGORITHM:HEX\n\
             --candidate-commit ALGORITHM:HEX --specification-digest HEX\n\
             --specification-locator LOCATOR --specification-media-type TYPE\n\
             --claim STATEMENT [--claim STATEMENT ...]\n\
             --resolution-policy experiment-authority:ACTOR_HEX\n\
             --validation-opens-at U64 --validation-closes-at U64\n\
             [--reveal-closes-at U64] [--challenge-closes-at U64]\n\
             [--supersedes JOB_HEX] [--metadata TEXT] [signing options]\n\
  job list [--node-url URL]\n\
  job show [--node-url URL] --job-id HEX\n\
  job close [--node-url URL] [--key PATH] --chain-id HEX --job-id HEX\n\
            [signing options]\n\n\
evidence and attestation commands:\n\
  evidence register [--node-url URL] [--key PATH] --chain-id HEX --job-id HEX\n\
                    [--claim-id HEX] --evidence-digest HEX\n\
                    --evidence-locator LOCATOR --evidence-media-type TYPE\n\
                    --manifest-digest HEX [signing options]\n\
  attestation submit [--node-url URL] [--key PATH] --chain-id HEX\n\
                     --job-id HEX --claim-id HEX\n\
                     --verdict pass|fail|abstain|indeterminate\n\
                     --confidence-basis-points U16 [--evidence-id HEX ...]\n\
                     [signing options]\n\
  commitment create [--node-url URL] [--key PATH] --chain-id HEX\n\
                    --subject job:HEX|claim:HEX --digest HEX\n\
                    --reveal-after-height U64 --reveal-before-height U64\n\
                    [signing options]\n\
  commitment reveal [--node-url URL] [--key PATH] --chain-id HEX\n\
                    --commitment-id HEX --payload HEX --salt HEX [signing options]\n\n\
challenge and resolution commands:\n\
  challenge create [--node-url URL] [--key PATH] --chain-id HEX\n\
                   --target claim:HEX|attestation:HEX --counterclaim TEXT\n\
                   [--evidence-id HEX ...] [signing options]\n\
  resolution claim [--node-url URL] [--authority-key PATH | --key PATH]\n\
                   --chain-id HEX --job-id HEX --claim-id HEX\n\
                   --verdict pass|fail|unresolved [--evidence-id HEX ...]\n\
                   --resolution-digest HEX --resolution-locator LOCATOR\n\
                   --resolution-media-type TYPE [signing options]\n\
  resolution challenge [--node-url URL] [--authority-key PATH | --key PATH]\n\
                       --chain-id HEX --challenge-id HEX --upheld true|false\n\
                       [--evidence-id HEX ...] --resolution-digest HEX\n\
                       --resolution-locator LOCATOR --resolution-media-type TYPE\n\
                       [signing options]\n\n\
ledger inspection commands:\n\
  block show [--node-url URL] --height U64\n\
  state root [--node-url URL]\n\
  state actor [--node-url URL] --actor-id HEX\n\
  state mechanism [--node-url URL] --mechanism-id M00|M01\n\
  replay verify [--node-url URL]\n\n\
signing options:\n\
  [--nonce U64] [--valid-until-height U64 | --valid-for-blocks U64]\n\
  [--protocol-version U16]\n\n\
Git algorithms are sha1 or sha256. --nonce defaults to canonical actor state;\n\
expiry defaults to finalized height plus 32 blocks. RCHT_ACTOR_KEY and\n\
RCHT_NODE_URL supply defaults when their options are absent.\n";

/// Mutable process inputs captured once before command execution.
#[derive(Clone, Debug)]
pub struct StartupEnvironment {
    default_actor_key: PathBuf,
    default_node_url: String,
}

impl StartupEnvironment {
    pub fn capture() -> Self {
        let default_actor_key = std::env::var_os(ACTOR_KEY_ENVIRONMENT_KEY)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".rachet")
                    .join("actor.key")
            });
        let default_node_url = std::env::var(NODE_URL_ENVIRONMENT_KEY)
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_NODE_URL.to_owned());
        Self {
            default_actor_key,
            default_node_url,
        }
    }

    #[cfg(test)]
    fn fixed(default_actor_key: PathBuf) -> Self {
        Self {
            default_actor_key,
            default_node_url: DEFAULT_NODE_URL.to_owned(),
        }
    }
}

pub struct Invocation {
    pub json: bool,
    pub outcome: Result<Success, CliError>,
}

#[derive(Debug)]
pub struct Success {
    command: &'static str,
    result: Value,
}

#[derive(Clone, Copy)]
enum InputKind {
    Job,
    Evidence,
    Attestation,
    Commitment,
    Challenge,
    Resolution,
    Ledger,
}

impl InputKind {
    const fn error_code(self) -> &'static str {
        match self {
            Self::Job => "JOB_INPUT_INVALID",
            Self::Evidence => "EVIDENCE_INPUT_INVALID",
            Self::Attestation => "ATTESTATION_INPUT_INVALID",
            Self::Commitment => "COMMITMENT_INPUT_INVALID",
            Self::Challenge => "CHALLENGE_INPUT_INVALID",
            Self::Resolution => "RESOLUTION_INPUT_INVALID",
            Self::Ledger => "LEDGER_INPUT_INVALID",
        }
    }
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

    fn identity(error: IdentityError, requested_path: &Path) -> Self {
        let path = error.path().unwrap_or(requested_path);
        Self {
            code: error.code().to_owned(),
            message: error.to_string(),
            details: json!({"path": path}),
            exit_code: 1,
        }
    }

    fn signing(error: SigningError) -> Self {
        Self {
            code: error.code().to_owned(),
            message: error.to_string(),
            details: json!({}),
            exit_code: 1,
        }
    }

    fn action_input(message: impl Into<String>) -> Self {
        Self {
            code: "ACTION_INPUT_INVALID".to_owned(),
            message: message.into(),
            details: json!({}),
            exit_code: 2,
        }
    }

    fn input(kind: InputKind, message: impl Into<String>) -> Self {
        Self {
            code: kind.error_code().to_owned(),
            message: message.into(),
            details: json!({}),
            exit_code: 2,
        }
    }

    fn job_input(message: impl Into<String>) -> Self {
        Self::input(InputKind::Job, message)
    }

    fn transport(error: TransportError) -> Self {
        Self {
            code: error.code().to_owned(),
            message: error.to_string(),
            details: error.details(),
            exit_code: 1,
        }
    }
}

pub fn invoke(raw_args: Vec<String>, startup: &StartupEnvironment) -> Invocation {
    let json = raw_args.iter().any(|argument| argument == "--json");
    let args = raw_args
        .into_iter()
        .filter(|argument| argument != "--json")
        .collect();
    Invocation {
        json,
        outcome: dispatch(args, startup),
    }
}

pub fn render(invocation: &Invocation) -> String {
    match &invocation.outcome {
        Ok(success) if invocation.json => serde_json::to_string(&json!({
            "ok": true,
            "command": success.command,
            "result": success.result,
        }))
        .expect("CLI success envelope is JSON-serializable"),
        Ok(success) => format!(
            "{}: ok\n{}",
            success.command,
            serde_json::to_string_pretty(&success.result)
                .expect("CLI success result is JSON-serializable")
        ),
        Err(error) if invocation.json => serde_json::to_string(&json!({
            "error": {
                "code": error.code,
                "message": error.message,
                "details": error.details,
            }
        }))
        .expect("CLI error envelope is JSON-serializable"),
        Err(error) => format!("{}: {}", error.code, error.message),
    }
}

fn dispatch(mut args: Vec<String>, startup: &StartupEnvironment) -> Result<Success, CliError> {
    if args.is_empty() {
        return Err(CliError::usage("a command is required"));
    }
    if matches!(args[0].as_str(), "help" | "-h" | "--help") {
        return Ok(Success {
            command: "help",
            result: json!({"usage": USAGE}),
        });
    }
    let family = args.remove(0);
    if args.is_empty() {
        return Err(CliError::usage(format!("a {family} command is required")));
    }
    let command = args.remove(0);
    match (family.as_str(), command.as_str()) {
        ("identity", "create") => create_identity_command(args, startup),
        ("identity", "show") => show_identity_command(args, startup),
        ("identity", "sign") => sign_command(args, startup),
        ("job", "create") => create_job_command(args, startup),
        ("job", "list") => list_jobs_command(args, startup),
        ("job", "show") => show_job_command(args, startup),
        ("job", "close") => close_job_command(args, startup),
        ("evidence", "register") => register_evidence_command(args, startup),
        ("attestation", "submit") => submit_attestation_command(args, startup),
        ("commitment", "create") => create_commitment_command(args, startup),
        ("commitment", "reveal") => reveal_commitment_command(args, startup),
        ("challenge", "create") => create_challenge_command(args, startup),
        ("resolution", "claim") => resolve_claim_command(args, startup),
        ("resolution", "challenge") => resolve_challenge_command(args, startup),
        ("block", "show") => show_block_command(args, startup),
        ("state", "root") => state_root_command(args, startup),
        ("state", "actor") => state_actor_command(args, startup),
        ("state", "mechanism") => state_mechanism_command(args, startup),
        ("replay", "verify") => replay_verify_command(args, startup),
        ("identity", _) => Err(CliError::usage(format!(
            "unknown identity command {command:?}"
        ))),
        ("job", _) => Err(CliError::usage(format!("unknown job command {command:?}"))),
        ("evidence", _) => Err(CliError::usage(format!(
            "unknown evidence command {command:?}"
        ))),
        ("attestation", _) => Err(CliError::usage(format!(
            "unknown attestation command {command:?}"
        ))),
        ("commitment", _) => Err(CliError::usage(format!(
            "unknown commitment command {command:?}"
        ))),
        ("challenge", _) => Err(CliError::usage(format!(
            "unknown challenge command {command:?}"
        ))),
        ("resolution", _) => Err(CliError::usage(format!(
            "unknown resolution command {command:?}"
        ))),
        ("block", _) => Err(CliError::usage(format!(
            "unknown block command {command:?}"
        ))),
        ("state", _) => Err(CliError::usage(format!(
            "unknown state command {command:?}"
        ))),
        ("replay", _) => Err(CliError::usage(format!(
            "unknown replay command {command:?}"
        ))),
        _ => Err(CliError::usage(format!(
            "unknown command family {family:?}"
        ))),
    }
}

fn create_identity_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let path = options.key_path(startup)?;
    options.finish()?;
    let identity =
        ActorIdentity::create(&path).map_err(|error| CliError::identity(error, &path))?;
    Ok(identity_success("identity.create", &path, &identity))
}

fn show_identity_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let path = options.key_path(startup)?;
    options.finish()?;
    let identity = ActorIdentity::load(&path).map_err(|error| CliError::identity(error, &path))?;
    Ok(identity_success("identity.show", &path, &identity))
}

fn identity_success(command: &'static str, path: &Path, identity: &ActorIdentity) -> Success {
    Success {
        command,
        result: json!({
            "actor_id": encode_hex(identity.actor_id().as_bytes()),
            "key_path": path,
            "key_role": "network_actor",
            "key_algorithm": "Ed25519",
        }),
    }
}

fn sign_command(args: Vec<String>, startup: &StartupEnvironment) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let path = options.key_path(startup)?;
    let chain_hex = options.required("chain-id")?;
    let chain_id = ChainId::new(decode_action_array::<32>(&chain_hex, "chain ID")?);
    let nonce = options.required_parse::<u64>("nonce")?;
    let valid_until_height = options.required_parse::<u64>("valid-until-height")?;
    let protocol_version = options.optional_parse("protocol-version", 1_u16)?;
    let action_hex = options.required_alias("action", "payload")?;
    options.finish()?;

    if action_hex.len() > MAX_ACTION_BYTES.saturating_mul(2) {
        return Err(CliError::action_input(format!(
            "canonical action exceeds maximum hexadecimal length {}",
            MAX_ACTION_BYTES.saturating_mul(2)
        )));
    }
    let action_bytes = decode_hex(&action_hex, "action").map_err(CliError::action_input)?;
    let payload = Action::decode(action_bytes.as_slice()).map_err(|_| {
        CliError::action_input("--action is not one complete canonical Action payload")
    })?;
    let identity = ActorIdentity::load(&path).map_err(|error| CliError::identity(error, &path))?;
    let signed = sign_action(
        &identity,
        ActionSigningRequest {
            chain_id,
            protocol_version: ProtocolVersion::new(protocol_version),
            nonce,
            valid_until_height,
            payload,
        },
    )
    .map_err(CliError::signing)?;
    let canonical = canonical_action(&signed);

    Ok(Success {
        command: "identity.sign",
        result: json!({
            "action_id": encode_hex(signed.action_id().as_bytes()),
            "actor_id": encode_hex(signed.actor.as_bytes()),
            "chain_id": encode_hex(signed.chain_id.as_bytes()),
            "protocol_version": signed.version.get(),
            "nonce": signed.nonce,
            "valid_until_height": signed.valid_until_height,
            "canonical_action": encode_hex(&canonical),
        }),
    })
}

fn create_job_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let repository = bounded_job::<MAX_REPOSITORY_LOCATOR_BYTES>(
        options.required("repository")?,
        "repository locator",
    )?;
    let base_commit = parse_git_hash(&options.required("base-commit")?, "base commit")?;
    let candidate_commit =
        parse_git_hash(&options.required("candidate-commit")?, "candidate commit")?;
    let specification_digest = parse_digest(
        &options.required("specification-digest")?,
        "specification digest",
    )?;
    let specification_locator = bounded_job::<MAX_CONTENT_LOCATOR_HINT_BYTES>(
        options.required("specification-locator")?,
        "specification locator",
    )?;
    let specification_media_type = bounded_job::<MAX_MEDIA_TYPE_BYTES>(
        options.required("specification-media-type")?,
        "specification media type",
    )?;
    let claim_values = options.required_repeated("claim")?;
    let claims = claim_values
        .into_iter()
        .map(|statement| {
            bounded_job::<MAX_CLAIM_STATEMENT_BYTES>(statement, "claim statement")
                .map(ClaimDefinition::new)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let claims = BoundedVec::<_, MAX_CLAIMS_PER_JOB>::new(claims).map_err(|error| {
        CliError::job_input(format!(
            "claim count {} exceeds protocol maximum {}",
            error.actual(),
            error.maximum()
        ))
    })?;
    let resolution_policy = parse_resolution_policy(&mut options)?;
    let validation_opens_at = options.required_parse("validation-opens-at")?;
    let validation_closes_at = options.required_parse("validation-closes-at")?;
    let reveal_closes_at = options.optional_parse_value("reveal-closes-at")?;
    let challenge_closes_at = options.optional_parse_value("challenge-closes-at")?;
    let supersedes = options
        .optional("supersedes")?
        .map(|value| parse_job_id(&value))
        .transpose()?;
    let metadata = bounded_job::<MAX_METADATA_BYTES>(
        options.optional("metadata")?.unwrap_or_default(),
        "metadata",
    )?;

    let create = CreateJob {
        artifact: GitArtifact::new(
            repository,
            base_commit,
            candidate_commit,
            ContentRef::new(
                specification_digest,
                specification_locator,
                specification_media_type,
            ),
        ),
        claims,
        resolution_policy,
        validation_opens_at,
        validation_closes_at,
        reveal_closes_at,
        challenge_closes_at,
        supersedes,
        metadata,
    };
    submit_protocol_action(
        "job.create",
        Action::CreateJob(Box::new(create)),
        &mut options,
        startup,
        InputKind::Job,
    )
}

fn list_jobs_command(args: Vec<String>, startup: &StartupEnvironment) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let client = node_client(&mut options, startup)?;
    options.finish()?;
    let result = client.jobs().map_err(CliError::transport)?;
    Ok(Success {
        command: "job.list",
        result,
    })
}

fn show_job_command(args: Vec<String>, startup: &StartupEnvironment) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let job_id = parse_job_id(&options.required("job-id")?)?;
    let client = node_client(&mut options, startup)?;
    options.finish()?;
    let result = client
        .job(&encode_hex(job_id.as_bytes()))
        .map_err(CliError::transport)?;
    Ok(Success {
        command: "job.show",
        result,
    })
}

fn show_block_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let height = options.required_parse::<u64>("height")?;
    let client = node_client(&mut options, startup)?;
    options.finish()?;
    let result = client.block(height).map_err(CliError::transport)?;
    Ok(Success {
        command: "block.show",
        result,
    })
}

fn state_root_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let client = node_client(&mut options, startup)?;
    options.finish()?;
    let result = client.state_root().map_err(CliError::transport)?;
    Ok(Success {
        command: "state.root",
        result,
    })
}

fn state_actor_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let actor = parse_ledger_actor_id(&options.required("actor-id")?)?;
    let client = node_client(&mut options, startup)?;
    options.finish()?;
    let result = client
        .actor(&encode_hex(actor.as_bytes()))
        .map_err(CliError::transport)?;
    Ok(Success {
        command: "state.actor",
        result,
    })
}

fn state_mechanism_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let encoded = options.required_alias("mechanism-id", "mechanism")?;
    let mechanism = parse_mechanism_id(&encoded)?;
    let client = node_client(&mut options, startup)?;
    options.finish()?;
    let result = client
        .mechanism(&mechanism.to_string())
        .map_err(CliError::transport)?;
    Ok(Success {
        command: "state.mechanism",
        result,
    })
}

fn replay_verify_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let client = node_client(&mut options, startup)?;
    options.finish()?;
    let result = client.verify_replay().map_err(CliError::transport)?;
    Ok(Success {
        command: "replay.verify",
        result,
    })
}

fn close_job_command(args: Vec<String>, startup: &StartupEnvironment) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let job_id = parse_job_id(&options.required("job-id")?)?;
    submit_protocol_action(
        "job.close",
        Action::CloseJob(CloseJob::new(job_id)),
        &mut options,
        startup,
        InputKind::Job,
    )
}

fn register_evidence_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let job_id = parse_job_id_for(&options.required("job-id")?, InputKind::Evidence)?;
    let claim_id = options
        .optional("claim-id")?
        .map(|value| parse_claim_id(&value, InputKind::Evidence))
        .transpose()?;
    let evidence_digest = parse_digest_for(
        &options.required_alias("evidence-digest", "digest")?,
        "evidence digest",
        InputKind::Evidence,
    )?;
    let locator_hint = bounded_input::<MAX_CONTENT_LOCATOR_HINT_BYTES>(
        options.required_alias("evidence-locator", "locator-hint")?,
        "evidence locator hint",
        InputKind::Evidence,
    )?;
    let media_type = bounded_input::<MAX_MEDIA_TYPE_BYTES>(
        options.required_alias("evidence-media-type", "media-type")?,
        "evidence media type",
        InputKind::Evidence,
    )?;
    let manifest_digest = parse_digest_for(
        &options.required("manifest-digest")?,
        "evidence manifest digest",
        InputKind::Evidence,
    )?;
    let register = RegisterEvidence {
        job_id,
        claim_id,
        evidence: ContentRef::new(evidence_digest, locator_hint, media_type),
        manifest_digest,
    };
    submit_protocol_action(
        "evidence.register",
        Action::RegisterEvidence(register),
        &mut options,
        startup,
        InputKind::Evidence,
    )
}

fn submit_attestation_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let job_id = parse_job_id_for(&options.required("job-id")?, InputKind::Attestation)?;
    let claim_id = parse_claim_id(&options.required("claim-id")?, InputKind::Attestation)?;
    let verdict = parse_verdict(&options.required("verdict")?)?;
    let confidence_basis_points = options.required_parse("confidence-basis-points")?;
    let evidence_ids = options
        .repeated("evidence-id")
        .into_iter()
        .map(|value| parse_evidence_id(&value, InputKind::Attestation))
        .collect::<Result<Vec<_>, _>>()?;
    let evidence_ids =
        BoundedVec::<_, MAX_EVIDENCE_IDS_PER_ACTION>::new(evidence_ids).map_err(|error| {
            CliError::input(
                InputKind::Attestation,
                format!(
                    "evidence reference count {} exceeds protocol maximum {}",
                    error.actual(),
                    error.maximum()
                ),
            )
        })?;
    let attestation = SubmitAttestation {
        job_id,
        claim_id,
        verdict,
        confidence_basis_points,
        evidence_ids,
    };
    submit_protocol_action(
        "attestation.submit",
        Action::SubmitAttestation(attestation),
        &mut options,
        startup,
        InputKind::Attestation,
    )
}

fn create_commitment_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let subject = parse_commitment_subject(&mut options)?;
    let digest = parse_digest_for(
        &options.required_alias("digest", "commitment-digest")?,
        "commitment digest",
        InputKind::Commitment,
    )?;
    let create = CreateCommitment {
        subject,
        digest,
        reveal_after_height: options.required_parse("reveal-after-height")?,
        reveal_before_height: options.required_parse("reveal-before-height")?,
    };
    submit_protocol_action(
        "commitment.create",
        Action::CreateCommitment(create),
        &mut options,
        startup,
        InputKind::Commitment,
    )
}

fn reveal_commitment_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let commitment_id =
        parse_commitment_id(&options.required("commitment-id")?, InputKind::Commitment)?;
    let payload = decode_hex(
        &options.required_alias("payload", "payload-hex")?,
        "commitment payload",
    )
    .map_err(|message| CliError::input(InputKind::Commitment, message))?;
    let salt = decode_hex(
        &options.required_alias("salt", "salt-hex")?,
        "commitment salt",
    )
    .map_err(|message| CliError::input(InputKind::Commitment, message))?;
    let reveal = RevealCommitment {
        commitment_id,
        payload: bounded_raw::<MAX_COMMITMENT_PAYLOAD_BYTES>(
            payload,
            "commitment payload",
            InputKind::Commitment,
        )?,
        salt: bounded_raw::<MAX_COMMITMENT_SALT_BYTES>(
            salt,
            "commitment salt",
            InputKind::Commitment,
        )?,
    };
    submit_protocol_action(
        "commitment.reveal",
        Action::RevealCommitment(reveal),
        &mut options,
        startup,
        InputKind::Commitment,
    )
}

fn create_challenge_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let target = parse_challenge_target(&mut options)?;
    let counterclaim = bounded_input::<MAX_COUNTERCLAIM_BYTES>(
        options.required("counterclaim")?,
        "counterclaim",
        InputKind::Challenge,
    )?;
    let evidence_ids = parse_evidence_references(&mut options, InputKind::Challenge)?;
    let challenge = CreateChallenge {
        target,
        counterclaim,
        evidence_ids,
    };
    submit_protocol_action(
        "challenge.create",
        Action::CreateChallenge(challenge),
        &mut options,
        startup,
        InputKind::Challenge,
    )
}

fn resolve_claim_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    options.select_authority_key()?;
    let job_id = parse_job_id_for(&options.required("job-id")?, InputKind::Resolution)?;
    let claim_id = parse_claim_id(&options.required("claim-id")?, InputKind::Resolution)?;
    let verdict = parse_resolution_verdict(&options.required("verdict")?)?;
    let evidence_ids = parse_evidence_references(&mut options, InputKind::Resolution)?;
    let resolution_reference = parse_resolution_reference(&mut options)?;
    let resolution = ResolveClaim {
        job_id,
        claim_id,
        verdict,
        evidence_ids,
        resolution_reference,
    };
    submit_protocol_action(
        "resolution.claim",
        Action::ResolveClaim(resolution),
        &mut options,
        startup,
        InputKind::Resolution,
    )
}

fn resolve_challenge_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    options.select_authority_key()?;
    let challenge_id =
        parse_challenge_id(&options.required("challenge-id")?, InputKind::Resolution)?;
    let upheld = parse_upheld(&options.required("upheld")?)?;
    let evidence_ids = parse_evidence_references(&mut options, InputKind::Resolution)?;
    let resolution_reference = parse_resolution_reference(&mut options)?;
    let resolution = ResolveChallenge {
        challenge_id,
        upheld,
        evidence_ids,
        resolution_reference,
    };
    submit_protocol_action(
        "resolution.challenge",
        Action::ResolveChallenge(resolution),
        &mut options,
        startup,
        InputKind::Resolution,
    )
}

fn submit_protocol_action(
    command: &'static str,
    payload: Action,
    options: &mut Options,
    startup: &StartupEnvironment,
    input_kind: InputKind,
) -> Result<Success, CliError> {
    let key_path = options.key_path(startup)?;
    let chain_id = ChainId::new(
        decode_hex(&options.required("chain-id")?, "chain ID")
            .and_then(|bytes| {
                bytes.try_into().map_err(|bytes: Vec<u8>| {
                    format!(
                        "chain ID must be exactly 32 bytes, received {}",
                        bytes.len()
                    )
                })
            })
            .map_err(|message| CliError::input(input_kind, message))?,
    );
    let explicit_nonce = options.optional_parse_value::<u64>("nonce")?;
    let explicit_expiry = options.optional_parse_value::<u64>("valid-until-height")?;
    let valid_for_blocks = options.optional_parse_value::<u64>("valid-for-blocks")?;
    if explicit_expiry.is_some() && valid_for_blocks.is_some() {
        return Err(CliError::usage(
            "--valid-until-height and --valid-for-blocks cannot both be supplied",
        ));
    }
    let protocol_version = options.optional_parse("protocol-version", 1_u16)?;
    let client = node_client(options, startup)?;
    options.finish()?;

    let identity =
        ActorIdentity::load(&key_path).map_err(|error| CliError::identity(error, &key_path))?;
    let actor_hex = encode_hex(identity.actor_id().as_bytes());
    let nonce = match explicit_nonce {
        Some(nonce) => nonce,
        None => next_nonce(&client, &actor_hex)?,
    };
    let valid_until_height = match explicit_expiry {
        Some(height) => height,
        None => {
            let height = finalized_height(&client)?;
            height
                .checked_add(valid_for_blocks.unwrap_or(DEFAULT_VALID_FOR_BLOCKS))
                .ok_or_else(|| CliError::input(input_kind, "action expiry height overflows u64"))?
        }
    };
    let identifiers = action_identifiers(&payload, &identity.actor_id());
    let signed = sign_action(
        &identity,
        ActionSigningRequest {
            chain_id,
            protocol_version: ProtocolVersion::new(protocol_version),
            nonce,
            valid_until_height,
            payload,
        },
    )
    .map_err(CliError::signing)?;
    let action_id = encode_hex(signed.action_id().as_bytes());
    let canonical_hex = encode_hex(&canonical_action(&signed));
    let response = client
        .submit_action(&canonical_hex)
        .map_err(CliError::transport)?;
    let mut result = match response {
        Value::Object(object) => object,
        other => {
            let mut object = Map::new();
            object.insert("submission".to_owned(), other);
            object
        }
    };
    result.insert("action_id".to_owned(), Value::String(action_id));
    result.insert("actor_id".to_owned(), Value::String(actor_hex));
    result.insert("nonce".to_owned(), Value::from(nonce));
    result.insert(
        "valid_until_height".to_owned(),
        Value::from(valid_until_height),
    );
    result.extend(identifiers);
    Ok(Success {
        command,
        result: Value::Object(result),
    })
}

fn action_identifiers(payload: &Action, actor: &ActorId) -> Map<String, Value> {
    let mut identifiers = Map::new();
    let (name, encoded) = match payload {
        Action::CreateJob(create) => ("job_id", encode_hex(create.job_id().as_bytes())),
        Action::RegisterEvidence(register) => {
            ("evidence_id", encode_hex(register.evidence_id().as_bytes()))
        }
        Action::SubmitAttestation(attestation) => (
            "attestation_id",
            encode_hex(attestation.attestation_id(actor).as_bytes()),
        ),
        Action::CreateCommitment(commitment) => (
            "commitment_id",
            encode_hex(commitment.commitment_id(actor).as_bytes()),
        ),
        Action::RevealCommitment(reveal) => {
            ("commitment_id", encode_hex(reveal.commitment_id.as_bytes()))
        }
        Action::CreateChallenge(challenge) => (
            "challenge_id",
            encode_hex(challenge.challenge_id(actor).as_bytes()),
        ),
        Action::ResolveClaim(resolution) => {
            identifiers.insert(
                "job_id".to_owned(),
                Value::String(encode_hex(resolution.job_id.as_bytes())),
            );
            ("claim_id", encode_hex(resolution.claim_id.as_bytes()))
        }
        Action::ResolveChallenge(resolution) => (
            "challenge_id",
            encode_hex(resolution.challenge_id.as_bytes()),
        ),
        Action::CloseJob(close) => ("job_id", encode_hex(close.job_id.as_bytes())),
    };
    identifiers.insert(name.to_owned(), Value::String(encoded));
    identifiers
}

fn next_nonce(client: &NodeClient, actor_hex: &str) -> Result<u64, CliError> {
    match client.actor(actor_hex) {
        Ok(result) => result
            .get("next_nonce")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                CliError::transport(TransportError::MalformedResponse {
                    message: "actor response has no unsigned next_nonce".to_owned(),
                })
            }),
        Err(error) if error.is_remote_code("RPC_ACTOR_NOT_FOUND") => Ok(0),
        Err(error) => Err(CliError::transport(error)),
    }
}

fn finalized_height(client: &NodeClient) -> Result<u64, CliError> {
    client
        .health()
        .map_err(CliError::transport)?
        .get("finalized_height")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CliError::transport(TransportError::MalformedResponse {
                message: "health response has no unsigned finalized_height".to_owned(),
            })
        })
}

fn node_client(
    options: &mut Options,
    startup: &StartupEnvironment,
) -> Result<NodeClient, CliError> {
    let node_url = options
        .optional("node-url")?
        .unwrap_or_else(|| startup.default_node_url.clone());
    NodeClient::new(&node_url).map_err(CliError::transport)
}

fn parse_challenge_target(options: &mut Options) -> Result<ChallengeTarget, CliError> {
    let target = options.optional("target")?;
    let claim_id = options.optional("claim-id")?;
    let attestation_id = options.optional("attestation-id")?;
    match (target, claim_id, attestation_id) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => Err(CliError::usage(
            "--target cannot be combined with --claim-id or --attestation-id",
        )),
        (None, Some(_), Some(_)) => Err(CliError::usage(
            "--claim-id and --attestation-id cannot both select a challenge target",
        )),
        (None, Some(value), None) => {
            parse_claim_id(&value, InputKind::Challenge).map(ChallengeTarget::Claim)
        }
        (None, None, Some(value)) => {
            parse_attestation_id(&value, InputKind::Challenge).map(ChallengeTarget::Attestation)
        }
        (None, None, None) => Err(CliError::usage(
            "--target, --claim-id, or --attestation-id is required",
        )),
        (Some(target), None, None) => {
            let (kind, value) = target.split_once(':').ok_or_else(|| {
                CliError::input(
                    InputKind::Challenge,
                    "--target must be claim:HEX or attestation:HEX",
                )
            })?;
            match kind {
                "claim" => parse_claim_id(value, InputKind::Challenge).map(ChallengeTarget::Claim),
                "attestation" => parse_attestation_id(value, InputKind::Challenge)
                    .map(ChallengeTarget::Attestation),
                _ => Err(CliError::input(
                    InputKind::Challenge,
                    "--target must be claim:HEX or attestation:HEX",
                )),
            }
        }
    }
}

fn parse_evidence_references(
    options: &mut Options,
    input_kind: InputKind,
) -> Result<BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>, CliError> {
    let evidence_ids = options
        .repeated("evidence-id")
        .into_iter()
        .map(|value| parse_evidence_id(&value, input_kind))
        .collect::<Result<Vec<_>, _>>()?;
    BoundedVec::new(evidence_ids).map_err(|error| {
        CliError::input(
            input_kind,
            format!(
                "evidence reference count {} exceeds protocol maximum {}",
                error.actual(),
                error.maximum()
            ),
        )
    })
}

fn parse_resolution_reference(options: &mut Options) -> Result<ContentRef, CliError> {
    let digest = parse_digest_for(
        &options.required_alias("resolution-digest", "digest")?,
        "resolution digest",
        InputKind::Resolution,
    )?;
    let locator_hint = bounded_input::<MAX_CONTENT_LOCATOR_HINT_BYTES>(
        options.required_alias("resolution-locator", "locator-hint")?,
        "resolution locator hint",
        InputKind::Resolution,
    )?;
    let media_type = bounded_input::<MAX_MEDIA_TYPE_BYTES>(
        options.required_alias("resolution-media-type", "media-type")?,
        "resolution media type",
        InputKind::Resolution,
    )?;
    Ok(ContentRef::new(digest, locator_hint, media_type))
}

fn parse_resolution_verdict(value: &str) -> Result<ResolutionVerdict, CliError> {
    match value {
        "pass" => Ok(ResolutionVerdict::Pass),
        "fail" => Ok(ResolutionVerdict::Fail),
        "unresolved" => Ok(ResolutionVerdict::Unresolved),
        _ => Err(CliError::input(
            InputKind::Resolution,
            format!("verdict {value:?} must be pass, fail, or unresolved"),
        )),
    }
}

fn parse_upheld(value: &str) -> Result<bool, CliError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(CliError::input(
            InputKind::Resolution,
            format!("upheld value {value:?} must be true or false"),
        )),
    }
}

fn parse_verdict(value: &str) -> Result<Verdict, CliError> {
    match value {
        "pass" => Ok(Verdict::Pass),
        "fail" => Ok(Verdict::Fail),
        "abstain" => Ok(Verdict::Abstain),
        "indeterminate" => Ok(Verdict::Indeterminate),
        _ => Err(CliError::input(
            InputKind::Attestation,
            format!("verdict {value:?} must be pass, fail, abstain, or indeterminate"),
        )),
    }
}

fn parse_commitment_subject(options: &mut Options) -> Result<CommitmentSubject, CliError> {
    let subject = options.optional("subject")?;
    let job_id = options.optional("job-id")?;
    let claim_id = options.optional("claim-id")?;
    match (subject, job_id, claim_id) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => Err(CliError::usage(
            "--subject cannot be combined with --job-id or --claim-id",
        )),
        (None, Some(_), Some(_)) => Err(CliError::usage(
            "--job-id and --claim-id cannot both select a commitment subject",
        )),
        (None, Some(value), None) => {
            parse_job_id_for(&value, InputKind::Commitment).map(CommitmentSubject::Job)
        }
        (None, None, Some(value)) => {
            parse_claim_id(&value, InputKind::Commitment).map(CommitmentSubject::Claim)
        }
        (None, None, None) => Err(CliError::usage(
            "--subject, --job-id, or --claim-id is required",
        )),
        (Some(subject), None, None) => {
            let (kind, value) = subject.split_once(':').ok_or_else(|| {
                CliError::input(
                    InputKind::Commitment,
                    "--subject must be job:HEX or claim:HEX",
                )
            })?;
            match kind {
                "job" => parse_job_id_for(value, InputKind::Commitment).map(CommitmentSubject::Job),
                "claim" => {
                    parse_claim_id(value, InputKind::Commitment).map(CommitmentSubject::Claim)
                }
                _ => Err(CliError::input(
                    InputKind::Commitment,
                    "--subject must be job:HEX or claim:HEX",
                )),
            }
        }
    }
}

fn parse_resolution_policy(options: &mut Options) -> Result<ResolutionPolicy, CliError> {
    let policy = options.optional("resolution-policy")?;
    let authority = options.optional_alias("authority", "resolution-authority")?;
    let encoded = match (policy, authority) {
        (Some(_), Some(_)) => {
            return Err(CliError::usage(
                "--resolution-policy cannot be combined with --authority or --resolution-authority",
            ));
        }
        (None, None) => return Err(CliError::usage("--resolution-policy is required")),
        (None, Some(authority)) => authority,
        (Some(policy), None) => {
            let (kind, value) = policy.split_once(':').ok_or_else(|| {
                CliError::job_input("--resolution-policy must be experiment-authority:ACTOR_HEX")
            })?;
            if !matches!(kind, "experiment-authority" | "experiment_authority") {
                return Err(CliError::job_input(format!(
                    "resolution policy {kind:?} is not implemented"
                )));
            }
            value.to_owned()
        }
    };
    Ok(ResolutionPolicy::ExperimentAuthority {
        authority: parse_actor_id(&encoded)?,
    })
}

fn parse_git_hash(encoded: &str, label: &str) -> Result<GitHash, CliError> {
    let (algorithm, digest) = match encoded.split_once(':') {
        Some((algorithm, digest)) => (Some(algorithm), digest),
        None => (None, encoded),
    };
    let bytes = decode_hex(digest, label).map_err(CliError::job_input)?;
    match (algorithm, bytes.len()) {
        (Some("sha1"), 20) | (None, 20) => Ok(GitHash::sha1(
            bytes.try_into().expect("Git SHA-1 length was checked"),
        )),
        (Some("sha256"), 32) | (None, 32) => Ok(GitHash::sha256(
            bytes.try_into().expect("Git SHA-256 length was checked"),
        )),
        (Some("sha1"), actual) => Err(CliError::job_input(format!(
            "{label} sha1 digest must be 20 bytes, received {actual}"
        ))),
        (Some("sha256"), actual) => Err(CliError::job_input(format!(
            "{label} sha256 digest must be 32 bytes, received {actual}"
        ))),
        (Some(other), _) => Err(CliError::job_input(format!(
            "{label} uses unsupported Git hash algorithm {other:?}"
        ))),
        (None, actual) => Err(CliError::job_input(format!(
            "{label} must be a 20-byte SHA-1 or 32-byte SHA-256 digest, received {actual} bytes"
        ))),
    }
}

fn parse_mechanism_id(encoded: &str) -> Result<MechanismId, CliError> {
    let numeric = encoded.strip_prefix('M').ok_or_else(|| {
        CliError::input(
            InputKind::Ledger,
            "mechanism ID must have the form M00 or M01",
        )
    })?;
    if numeric.len() != 2 || !numeric.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CliError::input(
            InputKind::Ledger,
            "mechanism ID must have the form M00 or M01",
        ));
    }
    let value = numeric.parse::<u16>().map_err(|_| {
        CliError::input(
            InputKind::Ledger,
            "mechanism ID must have the form M00 or M01",
        )
    })?;
    Ok(MechanismId::new(value))
}

fn parse_ledger_actor_id(encoded: &str) -> Result<ActorId, CliError> {
    let bytes = decode_hex(encoded, "actor ID")
        .map_err(|message| CliError::input(InputKind::Ledger, message))?;
    if bytes.len() != 32 {
        return Err(CliError::input(
            InputKind::Ledger,
            format!(
                "actor ID must be exactly 32 bytes, received {}",
                bytes.len()
            ),
        ));
    }
    Ed25519PublicKey::decode(bytes.as_slice())
        .map(Into::into)
        .map_err(|_| {
            CliError::input(
                InputKind::Ledger,
                "actor ID is not a valid Ed25519 public key",
            )
        })
}

fn parse_actor_id(encoded: &str) -> Result<rachet_core::primitives::ActorId, CliError> {
    let bytes = decode_hex(encoded, "authority actor ID").map_err(CliError::job_input)?;
    if bytes.len() != 32 {
        return Err(CliError::job_input(format!(
            "authority actor ID must be exactly 32 bytes, received {}",
            bytes.len()
        )));
    }
    Ed25519PublicKey::decode(bytes.as_slice())
        .map(Into::into)
        .map_err(|_| CliError::job_input("authority actor ID is not a valid Ed25519 public key"))
}

fn parse_digest(encoded: &str, label: &str) -> Result<Sha256Digest, CliError> {
    parse_digest_for(encoded, label, InputKind::Job)
}

fn parse_digest_for(
    encoded: &str,
    label: &str,
    input_kind: InputKind,
) -> Result<Sha256Digest, CliError> {
    let bytes =
        decode_hex(encoded, label).map_err(|message| CliError::input(input_kind, message))?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        CliError::input(
            input_kind,
            format!("{label} must be exactly 32 bytes, received {}", bytes.len()),
        )
    })?;
    Ok(Sha256Digest::from(bytes))
}

fn parse_job_id(encoded: &str) -> Result<JobId, CliError> {
    parse_job_id_for(encoded, InputKind::Job)
}

fn parse_job_id_for(encoded: &str, input_kind: InputKind) -> Result<JobId, CliError> {
    parse_digest_for(encoded, "job ID", input_kind).map(JobId::from_digest)
}

fn parse_claim_id(encoded: &str, input_kind: InputKind) -> Result<ClaimId, CliError> {
    parse_digest_for(encoded, "claim ID", input_kind).map(ClaimId::from_digest)
}

fn parse_evidence_id(encoded: &str, input_kind: InputKind) -> Result<EvidenceId, CliError> {
    parse_digest_for(encoded, "evidence ID", input_kind).map(EvidenceId::from_digest)
}

fn parse_attestation_id(encoded: &str, input_kind: InputKind) -> Result<AttestationId, CliError> {
    parse_digest_for(encoded, "attestation ID", input_kind).map(AttestationId::from_digest)
}

fn parse_challenge_id(encoded: &str, input_kind: InputKind) -> Result<ChallengeId, CliError> {
    parse_digest_for(encoded, "challenge ID", input_kind).map(ChallengeId::from_digest)
}

fn parse_commitment_id(encoded: &str, input_kind: InputKind) -> Result<CommitmentId, CliError> {
    parse_digest_for(encoded, "commitment ID", input_kind).map(CommitmentId::from_digest)
}

fn bounded_job<const MAX: usize>(
    value: String,
    label: &str,
) -> Result<BoundedBytes<MAX>, CliError> {
    bounded_input(value, label, InputKind::Job)
}

fn bounded_input<const MAX: usize>(
    value: String,
    label: &str,
    input_kind: InputKind,
) -> Result<BoundedBytes<MAX>, CliError> {
    bounded_raw(value.into_bytes(), label, input_kind)
}

fn bounded_raw<const MAX: usize>(
    value: Vec<u8>,
    label: &str,
    input_kind: InputKind,
) -> Result<BoundedBytes<MAX>, CliError> {
    BoundedBytes::new(value).map_err(|error| {
        CliError::input(
            input_kind,
            format!(
                "{label} is {} bytes; protocol maximum is {}",
                error.actual(),
                error.maximum()
            ),
        )
    })
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
                .ok_or_else(|| {
                    CliError::usage(format!("unexpected positional argument {flag:?}"))
                })?;
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

    fn key_path(&mut self, startup: &StartupEnvironment) -> Result<PathBuf, CliError> {
        Ok(self
            .optional("key")?
            .map(PathBuf::from)
            .unwrap_or_else(|| startup.default_actor_key.clone()))
    }

    fn select_authority_key(&mut self) -> Result<(), CliError> {
        match (self.optional("authority-key")?, self.optional("key")?) {
            (Some(_), Some(_)) => Err(CliError::usage(
                "--authority-key and --key cannot both be supplied",
            )),
            (Some(path), None) | (None, Some(path)) => {
                self.values.insert("key".to_owned(), vec![path]);
                Ok(())
            }
            (None, None) => Ok(()),
        }
    }

    fn required(&mut self, key: &'static str) -> Result<String, CliError> {
        self.optional(key)?
            .ok_or_else(|| CliError::usage(format!("--{key} is required")))
    }

    fn optional(&mut self, key: &'static str) -> Result<Option<String>, CliError> {
        let Some(values) = self.values.remove(key) else {
            return Ok(None);
        };
        if values.len() != 1 {
            return Err(CliError::usage(format!(
                "--{key} was supplied more than once"
            )));
        }
        Ok(values.into_iter().next())
    }

    fn required_alias(
        &mut self,
        primary: &'static str,
        alias: &'static str,
    ) -> Result<String, CliError> {
        match (self.optional(primary)?, self.optional(alias)?) {
            (Some(value), None) | (None, Some(value)) => Ok(value),
            (Some(_), Some(_)) => Err(CliError::usage(format!(
                "--{primary} and --{alias} cannot both be supplied"
            ))),
            (None, None) => Err(CliError::usage(format!("--{primary} is required"))),
        }
    }

    fn optional_alias(
        &mut self,
        primary: &'static str,
        alias: &'static str,
    ) -> Result<Option<String>, CliError> {
        match (self.optional(primary)?, self.optional(alias)?) {
            (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
            (Some(_), Some(_)) => Err(CliError::usage(format!(
                "--{primary} and --{alias} cannot both be supplied"
            ))),
            (None, None) => Ok(None),
        }
    }

    fn required_repeated(&mut self, key: &'static str) -> Result<Vec<String>, CliError> {
        self.values
            .remove(key)
            .filter(|values| !values.is_empty())
            .ok_or_else(|| CliError::usage(format!("--{key} is required")))
    }

    fn repeated(&mut self, key: &'static str) -> Vec<String> {
        self.values.remove(key).unwrap_or_default()
    }

    fn required_parse<T>(&mut self, key: &'static str) -> Result<T, CliError>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        let value = self.required(key)?;
        value
            .parse()
            .map_err(|error| CliError::usage(format!("invalid --{key} {value:?}: {error}")))
    }

    fn optional_parse<T>(&mut self, key: &'static str, default: T) -> Result<T, CliError>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        self.optional_parse_value(key)?.map_or(Ok(default), Ok)
    }

    fn optional_parse_value<T>(&mut self, key: &'static str) -> Result<Option<T>, CliError>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        self.optional(key)?
            .map(|value| {
                value
                    .parse()
                    .map_err(|error| CliError::usage(format!("invalid --{key} {value:?}: {error}")))
            })
            .transpose()
    }

    fn finish(&self) -> Result<(), CliError> {
        if let Some(key) = self.values.keys().next() {
            return Err(CliError::usage(format!("unknown option --{key}")));
        }
        Ok(())
    }
}

fn decode_action_array<const N: usize>(encoded: &str, label: &str) -> Result<[u8; N], CliError> {
    let bytes = decode_hex(encoded, label).map_err(CliError::action_input)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        CliError::action_input(format!(
            "{label} must be exactly {N} bytes, received {}",
            bytes.len()
        ))
    })
}

fn decode_hex(encoded: &str, label: &str) -> Result<Vec<u8>, String> {
    if !encoded.len().is_multiple_of(2) {
        return Err(format!("{label} must be an even-length hexadecimal string"));
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])
            .ok_or_else(|| format!("{label} contains non-hexadecimal characters"))?;
        let low = hex_nibble(pair[1])
            .ok_or_else(|| format!("{label} contains non-hexadecimal characters"))?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use rachet_core::{
        actions::{ActionVerificationContext, decode_signed_action},
        primitives::JobId,
    };
    use std::{
        fs,
        io::{Read as _, Write as _},
        net::TcpListener,
        sync::{
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn create_show_and_sign_have_public_json_contracts_and_core_verification() {
        let temp = TempDirectory::new();
        let key = temp.path().join("actor.key");
        let startup = StartupEnvironment::fixed(key.clone());

        let create = invoke(
            vec!["--json".into(), "identity".into(), "create".into()],
            &startup,
        );
        let created = assert_json_success(&create, "identity.create");
        let actor_id = created["result"]["actor_id"].as_str().unwrap().to_owned();
        assert_eq!(created["result"]["key_role"], "network_actor");
        assert!(!render(&create).contains("private"));

        let show = invoke(
            vec!["identity".into(), "show".into(), "--json".into()],
            &startup,
        );
        let shown = assert_json_success(&show, "identity.show");
        assert_eq!(shown["result"]["actor_id"], actor_id);

        let payload = Action::CloseJob(CloseJob {
            job_id: JobId::derive(b"rchtctl fixture"),
        });
        let action_hex = encode_hex(payload.encode().as_ref());
        let chain = [0x59_u8; 32];
        let sign = invoke(
            vec![
                "identity".into(),
                "sign".into(),
                "--chain-id".into(),
                encode_hex(&chain),
                "--nonce".into(),
                "3".into(),
                "--valid-until-height".into(),
                "99".into(),
                "--action".into(),
                action_hex,
                "--json".into(),
            ],
            &startup,
        );
        let signed_json = assert_json_success(&sign, "identity.sign");
        assert_eq!(signed_json["result"]["actor_id"], actor_id);
        assert_eq!(signed_json["result"]["nonce"], 3);
        let canonical = decode_hex(
            signed_json["result"]["canonical_action"].as_str().unwrap(),
            "fixture",
        )
        .unwrap();
        let signed = decode_signed_action::<Action>(&canonical, &()).unwrap();
        signed
            .verify(
                &ActionVerificationContext::current(ChainId::new(chain), 99),
                3,
            )
            .unwrap();
    }

    #[test]
    fn job_create_builds_signs_and_submits_only_canonical_references() {
        let temp = TempDirectory::new();
        let key = temp.path().join("actor.key");
        ActorIdentity::create(&key).unwrap();
        let authority = ActorIdentity::generate().unwrap().actor_id();
        let (url, request) = one_response_server(
            "202 Accepted",
            r#"{"ok":true,"result":{"action_id":"server","status":"pending","insertion":"inserted"}}"#,
        );
        let startup = StartupEnvironment::fixed(key);
        let invocation = invoke(
            vec![
                "job".into(),
                "create".into(),
                "--node-url".into(),
                url,
                "--chain-id".into(),
                "52".repeat(32),
                "--repository".into(),
                "https://git.invalid/project.git".into(),
                "--base-commit".into(),
                format!("sha1:{}", "11".repeat(20)),
                "--candidate-commit".into(),
                format!("sha256:{}", "22".repeat(32)),
                "--specification-digest".into(),
                "33".repeat(32),
                "--specification-locator".into(),
                "cas://specification".into(),
                "--specification-media-type".into(),
                "application/json".into(),
                "--claim".into(),
                "tests pass".into(),
                "--claim".into(),
                "no regressions".into(),
                "--resolution-policy".into(),
                format!("experiment-authority:{}", encode_hex(authority.as_bytes())),
                "--validation-opens-at".into(),
                "10".into(),
                "--validation-closes-at".into(),
                "20".into(),
                "--nonce".into(),
                "4".into(),
                "--valid-until-height".into(),
                "30".into(),
                "--json".into(),
            ],
            &startup,
        );
        let result = assert_json_success(&invocation, "job.create");
        assert_eq!(result["result"]["nonce"], 4);
        assert_eq!(result["result"]["valid_until_height"], 30);

        let request = request.recv().unwrap();
        assert!(request.starts_with("POST /v1/actions "));
        let body = request.split("\r\n\r\n").nth(1).unwrap();
        let wrapper: Value = serde_json::from_str(body).unwrap();
        let canonical =
            decode_hex(wrapper["canonical_action"].as_str().unwrap(), "action").unwrap();
        let signed = decode_signed_action::<Action>(&canonical, &()).unwrap();
        let Action::CreateJob(create) = signed.payload else {
            panic!("expected create-job action");
        };
        assert_eq!(
            create.artifact.repository.as_slice(),
            b"https://git.invalid/project.git"
        );
        assert_eq!(create.claims.len(), 2);
        assert_eq!(
            create.artifact.specification.digest,
            Sha256Digest::from([0x33; 32])
        );
        assert_eq!(signed.nonce, 4);
        assert_eq!(signed.valid_until_height, 30);
    }

    #[test]
    fn evidence_attestation_and_commitment_commands_submit_canonical_references() {
        let temp = TempDirectory::new();
        let key = temp.path().join("actor.key");
        let identity = ActorIdentity::create(&key).unwrap();
        let startup = StartupEnvironment::fixed(key);
        let chain = "52".repeat(32);
        let job = "61".repeat(32);
        let claim = "62".repeat(32);
        let evidence_digest = "63".repeat(32);

        let (url, request) = one_response_server(
            "202 Accepted",
            r#"{"ok":true,"result":{"status":"pending"}}"#,
        );
        let registration = invoke(
            vec![
                "evidence".into(),
                "register".into(),
                "--node-url".into(),
                url,
                "--chain-id".into(),
                chain.clone(),
                "--job-id".into(),
                job.clone(),
                "--claim-id".into(),
                claim.clone(),
                "--evidence-digest".into(),
                evidence_digest.clone(),
                "--evidence-locator".into(),
                "cas://private/evidence".into(),
                "--evidence-media-type".into(),
                "application/json".into(),
                "--manifest-digest".into(),
                "64".repeat(32),
                "--nonce".into(),
                "0".into(),
                "--valid-until-height".into(),
                "30".into(),
                "--json".into(),
            ],
            &startup,
        );
        let result = assert_json_success(&registration, "evidence.register");
        assert_eq!(result["result"]["evidence_id"].as_str().unwrap().len(), 64);
        let request = request.recv().unwrap();
        let wrapper: Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(wrapper.as_object().unwrap().len(), 1);
        let signed = signed_request(&request);
        signed
            .verify(
                &ActionVerificationContext::current(ChainId::new([0x52; 32]), 1),
                0,
            )
            .unwrap();
        let Action::RegisterEvidence(register) = signed.payload else {
            panic!("expected register-evidence action");
        };
        assert_eq!(register.evidence.digest, Sha256Digest::from([0x63; 32]));
        assert_eq!(
            register.evidence.locator_hint.as_slice(),
            b"cas://private/evidence"
        );
        assert_eq!(register.evidence.media_type.as_slice(), b"application/json");

        let (url, request) = one_response_server(
            "202 Accepted",
            r#"{"ok":true,"result":{"status":"pending"}}"#,
        );
        let attestation = invoke(
            vec![
                "attestation".into(),
                "submit".into(),
                "--node-url".into(),
                url,
                "--chain-id".into(),
                chain.clone(),
                "--job-id".into(),
                job.clone(),
                "--claim-id".into(),
                claim.clone(),
                "--verdict".into(),
                "pass".into(),
                "--confidence-basis-points".into(),
                "8750".into(),
                "--evidence-id".into(),
                "65".repeat(32),
                "--nonce".into(),
                "1".into(),
                "--valid-until-height".into(),
                "30".into(),
                "--json".into(),
            ],
            &startup,
        );
        let result = assert_json_success(&attestation, "attestation.submit");
        assert_eq!(
            result["result"]["attestation_id"].as_str().unwrap().len(),
            64
        );
        let signed = signed_request(&request.recv().unwrap());
        let Action::SubmitAttestation(attestation) = signed.payload else {
            panic!("expected submit-attestation action");
        };
        assert_eq!(attestation.verdict, Verdict::Pass);
        assert_eq!(attestation.confidence_basis_points, 8750);
        assert_eq!(attestation.evidence_ids.len(), 1);

        let payload =
            BoundedBytes::<MAX_COMMITMENT_PAYLOAD_BYTES>::try_from(b"verdict".as_slice()).unwrap();
        let salt =
            BoundedBytes::<MAX_COMMITMENT_SALT_BYTES>::try_from(b"secret".as_slice()).unwrap();
        let digest = rachet_core::actions::reveal_digest(&payload, &salt);
        let (url, request) = one_response_server(
            "202 Accepted",
            r#"{"ok":true,"result":{"status":"pending"}}"#,
        );
        let creation = invoke(
            vec![
                "commitment".into(),
                "create".into(),
                "--node-url".into(),
                url,
                "--chain-id".into(),
                chain.clone(),
                "--subject".into(),
                format!("claim:{claim}"),
                "--digest".into(),
                encode_hex(digest.as_ref()),
                "--reveal-after-height".into(),
                "10".into(),
                "--reveal-before-height".into(),
                "20".into(),
                "--nonce".into(),
                "2".into(),
                "--valid-until-height".into(),
                "30".into(),
                "--json".into(),
            ],
            &startup,
        );
        let result = assert_json_success(&creation, "commitment.create");
        let commitment_id = result["result"]["commitment_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let signed = signed_request(&request.recv().unwrap());
        let Action::CreateCommitment(create) = signed.payload else {
            panic!("expected create-commitment action");
        };
        assert_eq!(create.digest, digest);
        assert_eq!(
            create.commitment_id(&identity.actor_id()),
            CommitmentId::from_digest(
                parse_digest_for(&commitment_id, "fixture", InputKind::Commitment).unwrap()
            )
        );

        let (url, request) = one_response_server(
            "202 Accepted",
            r#"{"ok":true,"result":{"status":"pending"}}"#,
        );
        let reveal = invoke(
            vec![
                "commitment".into(),
                "reveal".into(),
                "--node-url".into(),
                url,
                "--chain-id".into(),
                chain,
                "--commitment-id".into(),
                commitment_id,
                "--payload".into(),
                encode_hex(payload.as_slice()),
                "--salt".into(),
                encode_hex(salt.as_slice()),
                "--nonce".into(),
                "3".into(),
                "--valid-until-height".into(),
                "30".into(),
                "--json".into(),
            ],
            &startup,
        );
        assert_json_success(&reveal, "commitment.reveal");
        let signed = signed_request(&request.recv().unwrap());
        let Action::RevealCommitment(reveal) = signed.payload else {
            panic!("expected reveal-commitment action");
        };
        assert_eq!(reveal.digest(), digest);
    }

    #[test]
    fn challenge_and_authority_resolution_commands_sign_canonical_references() {
        let temp = TempDirectory::new();
        let challenger_key = temp.path().join("challenger.key");
        let authority_key = temp.path().join("authority.key");
        let challenger = ActorIdentity::create(&challenger_key).unwrap();
        let authority = ActorIdentity::create(&authority_key).unwrap();
        let startup = StartupEnvironment::fixed(challenger_key);
        let chain = "52".repeat(32);
        let job = "71".repeat(32);
        let claim = "72".repeat(32);
        let attestation = "73".repeat(32);
        let evidence = "74".repeat(32);

        let (url, request) = one_response_server(
            "202 Accepted",
            r#"{"ok":true,"result":{"status":"pending"}}"#,
        );
        let creation = invoke(
            vec![
                "challenge".into(),
                "create".into(),
                "--node-url".into(),
                url,
                "--chain-id".into(),
                chain.clone(),
                "--target".into(),
                format!("attestation:{attestation}"),
                "--counterclaim".into(),
                "the attestation omitted a failing boundary case".into(),
                "--evidence-id".into(),
                evidence.clone(),
                "--nonce".into(),
                "0".into(),
                "--valid-until-height".into(),
                "30".into(),
                "--json".into(),
            ],
            &startup,
        );
        let result = assert_json_success(&creation, "challenge.create");
        let signed = signed_request(&request.recv().unwrap());
        assert_eq!(signed.actor, challenger.actor_id());
        let Action::CreateChallenge(challenge) = signed.payload else {
            panic!("expected create-challenge action");
        };
        assert_eq!(
            challenge.target,
            ChallengeTarget::Attestation(AttestationId::from_digest(Sha256Digest::from(
                [0x73; 32]
            )))
        );
        assert_eq!(challenge.evidence_ids.len(), 1);
        assert_eq!(
            result["result"]["challenge_id"],
            encode_hex(challenge.challenge_id(&challenger.actor_id()).as_bytes())
        );

        let (url, request) = one_response_server(
            "202 Accepted",
            r#"{"ok":true,"result":{"status":"pending"}}"#,
        );
        let claim_resolution = invoke(
            vec![
                "resolution".into(),
                "claim".into(),
                "--node-url".into(),
                url,
                "--authority-key".into(),
                authority_key.display().to_string(),
                "--chain-id".into(),
                chain.clone(),
                "--job-id".into(),
                job.clone(),
                "--claim-id".into(),
                claim.clone(),
                "--verdict".into(),
                "fail".into(),
                "--evidence-id".into(),
                evidence.clone(),
                "--resolution-digest".into(),
                "75".repeat(32),
                "--resolution-locator".into(),
                "cas://private/claim-resolution".into(),
                "--resolution-media-type".into(),
                "application/json".into(),
                "--nonce".into(),
                "0".into(),
                "--valid-until-height".into(),
                "30".into(),
                "--json".into(),
            ],
            &startup,
        );
        let result = assert_json_success(&claim_resolution, "resolution.claim");
        assert_eq!(
            result["result"]["actor_id"],
            encode_hex(authority.actor_id().as_bytes())
        );
        assert_eq!(result["result"]["job_id"], job);
        assert_eq!(result["result"]["claim_id"], claim);
        let signed = signed_request(&request.recv().unwrap());
        assert_eq!(signed.actor, authority.actor_id());
        let Action::ResolveClaim(resolution) = signed.payload else {
            panic!("expected resolve-claim action");
        };
        assert_eq!(resolution.verdict, ResolutionVerdict::Fail);
        assert_eq!(resolution.evidence_ids.len(), 1);
        assert_eq!(
            resolution.resolution_reference.digest,
            Sha256Digest::from([0x75; 32])
        );
        assert_eq!(
            resolution.resolution_reference.locator_hint.as_slice(),
            b"cas://private/claim-resolution"
        );

        let challenge_id = "76".repeat(32);
        let (url, request) = one_response_server(
            "202 Accepted",
            r#"{"ok":true,"result":{"status":"pending"}}"#,
        );
        let challenge_resolution = invoke(
            vec![
                "resolution".into(),
                "challenge".into(),
                "--node-url".into(),
                url,
                "--authority-key".into(),
                authority_key.display().to_string(),
                "--chain-id".into(),
                chain,
                "--challenge-id".into(),
                challenge_id.clone(),
                "--upheld".into(),
                "true".into(),
                "--evidence-id".into(),
                evidence,
                "--resolution-digest".into(),
                "77".repeat(32),
                "--resolution-locator".into(),
                "cas://private/challenge-resolution".into(),
                "--resolution-media-type".into(),
                "application/json".into(),
                "--nonce".into(),
                "1".into(),
                "--valid-until-height".into(),
                "30".into(),
                "--json".into(),
            ],
            &startup,
        );
        let result = assert_json_success(&challenge_resolution, "resolution.challenge");
        assert_eq!(result["result"]["challenge_id"], challenge_id);
        let signed = signed_request(&request.recv().unwrap());
        assert_eq!(signed.actor, authority.actor_id());
        let Action::ResolveChallenge(resolution) = signed.payload else {
            panic!("expected resolve-challenge action");
        };
        assert!(resolution.upheld);
        assert_eq!(resolution.evidence_ids.len(), 1);
        assert_eq!(
            resolution.resolution_reference.digest,
            Sha256Digest::from([0x77; 32])
        );
    }

    #[test]
    fn challenge_resolution_inputs_and_authorization_fail_stably() {
        let startup = StartupEnvironment::fixed(PathBuf::from("missing-key"));
        let oversized = invoke(
            vec![
                "challenge".into(),
                "create".into(),
                "--target".into(),
                format!("claim:{}", "11".repeat(32)),
                "--counterclaim".into(),
                "x".repeat(MAX_COUNTERCLAIM_BYTES + 1),
                "--json".into(),
            ],
            &startup,
        );
        assert_eq!(
            json_value(&oversized)["error"]["code"],
            "CHALLENGE_INPUT_INVALID"
        );

        let malformed = invoke(
            vec![
                "resolution".into(),
                "claim".into(),
                "--job-id".into(),
                "11".repeat(32),
                "--claim-id".into(),
                "22".repeat(32),
                "--verdict".into(),
                "accepted".into(),
                "--json".into(),
            ],
            &startup,
        );
        assert_eq!(
            json_value(&malformed)["error"]["code"],
            "RESOLUTION_INPUT_INVALID"
        );

        let duplicate_keys = invoke(
            vec![
                "resolution".into(),
                "challenge".into(),
                "--authority-key".into(),
                "authority.key".into(),
                "--key".into(),
                "actor.key".into(),
                "--json".into(),
            ],
            &startup,
        );
        assert_eq!(
            json_value(&duplicate_keys)["error"]["code"],
            "CLI_USAGE_INVALID"
        );

        let temp = TempDirectory::new();
        let key = temp.path().join("authority.key");
        ActorIdentity::create(&key).unwrap();
        let startup = StartupEnvironment::fixed(key);
        let cases = [
            ("RESOLUTION_UNAUTHORIZED", "resolution", "claim"),
            ("RESOLUTION_TOO_LATE", "resolution", "claim"),
            ("CHALLENGE_TOO_LATE", "challenge", "create"),
            ("CHALLENGE_ALREADY_EXISTS", "challenge", "create"),
            ("CHALLENGE_ALREADY_RESOLVED", "resolution", "challenge"),
        ];
        for (code, family, command) in cases {
            let body = format!(
                r#"{{"error":{{"code":"{code}","message":"rejected","details":{{"current_height":31}}}}}}"#
            );
            let (url, request) = one_owned_response_server("422 Unprocessable Entity", body);
            let mut args = match (family, command) {
                ("challenge", "create") => vec![
                    "challenge".to_owned(),
                    "create".to_owned(),
                    "--target".to_owned(),
                    format!("claim:{}", "21".repeat(32)),
                    "--counterclaim".to_owned(),
                    "counterexample".to_owned(),
                ],
                ("resolution", "claim") => vec![
                    "resolution".to_owned(),
                    "claim".to_owned(),
                    "--job-id".to_owned(),
                    "22".repeat(32),
                    "--claim-id".to_owned(),
                    "23".repeat(32),
                    "--verdict".to_owned(),
                    "pass".to_owned(),
                    "--resolution-digest".to_owned(),
                    "24".repeat(32),
                    "--resolution-locator".to_owned(),
                    "cas://resolution".to_owned(),
                    "--resolution-media-type".to_owned(),
                    "application/json".to_owned(),
                ],
                ("resolution", "challenge") => vec![
                    "resolution".to_owned(),
                    "challenge".to_owned(),
                    "--challenge-id".to_owned(),
                    "25".repeat(32),
                    "--upheld".to_owned(),
                    "false".to_owned(),
                    "--resolution-digest".to_owned(),
                    "26".repeat(32),
                    "--resolution-locator".to_owned(),
                    "cas://resolution".to_owned(),
                    "--resolution-media-type".to_owned(),
                    "application/json".to_owned(),
                ],
                _ => unreachable!(),
            };
            args.extend([
                "--node-url".to_owned(),
                url,
                "--chain-id".to_owned(),
                "52".repeat(32),
                "--nonce".to_owned(),
                "0".to_owned(),
                "--valid-until-height".to_owned(),
                "30".to_owned(),
                "--json".to_owned(),
            ]);
            let error = json_value(&invoke(args, &startup));
            request.recv().unwrap();
            assert_eq!(error["error"]["code"], code);
            assert_eq!(error["error"]["details"]["current_height"], 31);
            assert_eq!(error["error"]["details"]["http_status"], 422);
        }
    }

    #[test]
    fn evidence_and_commitment_input_bounds_and_references_fail_stably() {
        let startup = StartupEnvironment::fixed(PathBuf::from("missing-key"));
        let oversized = invoke(
            vec![
                "evidence".into(),
                "register".into(),
                "--job-id".into(),
                "11".repeat(32),
                "--evidence-digest".into(),
                "22".repeat(32),
                "--evidence-locator".into(),
                "x".repeat(MAX_CONTENT_LOCATOR_HINT_BYTES + 1),
                "--evidence-media-type".into(),
                "application/json".into(),
                "--manifest-digest".into(),
                "33".repeat(32),
                "--json".into(),
            ],
            &startup,
        );
        assert_eq!(
            json_value(&oversized)["error"]["code"],
            "EVIDENCE_INPUT_INVALID"
        );

        let bad_reference = invoke(
            vec![
                "commitment".into(),
                "create".into(),
                "--subject".into(),
                "claim:not-hex".into(),
                "--json".into(),
            ],
            &startup,
        );
        assert_eq!(
            json_value(&bad_reference)["error"]["code"],
            "COMMITMENT_INPUT_INVALID"
        );

        let oversized_reveal = invoke(
            vec![
                "commitment".into(),
                "reveal".into(),
                "--commitment-id".into(),
                "44".repeat(32),
                "--payload".into(),
                "aa".repeat(MAX_COMMITMENT_PAYLOAD_BYTES + 1),
                "--salt".into(),
                String::new(),
                "--json".into(),
            ],
            &startup,
        );
        assert_eq!(
            json_value(&oversized_reveal)["error"]["code"],
            "COMMITMENT_INPUT_INVALID"
        );
    }

    #[test]
    fn reveal_window_hash_and_nonce_server_errors_are_preserved() {
        let temp = TempDirectory::new();
        let key = temp.path().join("actor.key");
        ActorIdentity::create(&key).unwrap();
        let startup = StartupEnvironment::fixed(key);
        let cases = [
            (
                "COMMITMENT_REVEAL_WINDOW_INVALID",
                vec![
                    "commitment",
                    "create",
                    "--subject",
                    "job:1111111111111111111111111111111111111111111111111111111111111111",
                    "--digest",
                    "2222222222222222222222222222222222222222222222222222222222222222",
                    "--reveal-after-height",
                    "20",
                    "--reveal-before-height",
                    "10",
                ],
            ),
            (
                "COMMITMENT_REVEAL_DIGEST_MISMATCH",
                vec![
                    "commitment",
                    "reveal",
                    "--commitment-id",
                    "3333333333333333333333333333333333333333333333333333333333333333",
                    "--payload",
                    "aa",
                    "--salt",
                    "bb",
                ],
            ),
            (
                "ACTION_NONCE_INVALID",
                vec![
                    "evidence",
                    "register",
                    "--job-id",
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    "--evidence-digest",
                    "4444444444444444444444444444444444444444444444444444444444444444",
                    "--evidence-locator",
                    "cas://evidence",
                    "--evidence-media-type",
                    "application/json",
                    "--manifest-digest",
                    "5555555555555555555555555555555555555555555555555555555555555555",
                ],
            ),
        ];
        for (code, command) in cases {
            let body = format!(
                r#"{{"error":{{"code":"{code}","message":"rejected","details":{{"expected_nonce":7}}}}}}"#
            );
            let (url, request) = one_owned_response_server("422 Unprocessable Entity", body);
            let mut args = command.into_iter().map(str::to_owned).collect::<Vec<_>>();
            args.extend([
                "--node-url".to_owned(),
                url,
                "--chain-id".to_owned(),
                "52".repeat(32),
                "--nonce".to_owned(),
                "6".to_owned(),
                "--valid-until-height".to_owned(),
                "30".to_owned(),
                "--json".to_owned(),
            ]);
            let error = json_value(&invoke(args, &startup));
            request.recv().unwrap();
            assert_eq!(error["error"]["code"], code);
            assert_eq!(error["error"]["details"]["expected_nonce"], 7);
            assert_eq!(error["error"]["details"]["http_status"], 422);
        }
    }

    #[test]
    fn auto_nonce_expiry_and_server_error_codes_are_preserved() {
        let temp = TempDirectory::new();
        let key = temp.path().join("actor.key");
        ActorIdentity::create(&key).unwrap();
        let responses = vec![
            ("200 OK", r#"{"ok":true,"result":{"next_nonce":7}}"#),
            ("200 OK", r#"{"ok":true,"result":{"finalized_height":40}}"#),
            (
                "422 Unprocessable Entity",
                r#"{"error":{"code":"JOB_LIFECYCLE_OPEN","message":"window remains open","details":{"final_closes_at":44}}}"#,
            ),
        ];
        let url = response_server(responses);
        let startup = StartupEnvironment::fixed(key);
        let invocation = invoke(
            vec![
                "job".into(),
                "close".into(),
                "--node-url".into(),
                url,
                "--chain-id".into(),
                "52".repeat(32),
                "--job-id".into(),
                "91".repeat(32),
                "--valid-for-blocks".into(),
                "5".into(),
                "--json".into(),
            ],
            &startup,
        );
        let error = json_value(&invocation);
        assert_eq!(error["error"]["code"], "JOB_LIFECYCLE_OPEN");
        assert_eq!(error["error"]["details"]["final_closes_at"], 44);
        assert_eq!(error["error"]["details"]["http_status"], 422);
    }

    #[test]
    fn ledger_inspection_commands_query_finalized_surfaces_and_preserve_mismatches() {
        let startup = StartupEnvironment::fixed(PathBuf::from("unused-key"));
        let actor = ActorIdentity::generate().unwrap().actor_id();
        let cases = [
            (
                vec!["block", "show", "--height", "7"],
                "block.show",
                r#"{"ok":true,"result":{"height":7,"block_id":"aa"}}"#,
                "/v1/blocks/7",
            ),
            (
                vec!["state", "root"],
                "state.root",
                r#"{"ok":true,"result":{"height":7,"state_root":"bb"}}"#,
                "/v1/state/root",
            ),
            (
                vec!["state", "actor", "--actor-id", "ACTOR"],
                "state.actor",
                r#"{"ok":true,"result":{"next_nonce":8}}"#,
                "/v1/actors/",
            ),
            (
                vec!["state", "mechanism", "--mechanism", "M01"],
                "state.mechanism",
                r#"{"ok":true,"result":{"mechanism_id":"M01","entries":[]}}"#,
                "/v1/state/mechanisms/M01",
            ),
            (
                vec!["replay", "verify"],
                "replay.verify",
                r#"{"ok":true,"result":{"verified":true,"blocks_verified":8}}"#,
                "/v1/replay/verify",
            ),
        ];
        for (arguments, command, body, expected_path) in cases {
            let (url, request) = one_response_server("200 OK", body);
            let mut args = arguments.into_iter().map(str::to_owned).collect::<Vec<_>>();
            if let Some(position) = args.iter().position(|argument| argument == "ACTOR") {
                args[position] = encode_hex(actor.as_bytes());
            }
            args.extend(["--node-url".to_owned(), url, "--json".to_owned()]);
            assert_json_success(&invoke(args, &startup), command);
            let request = request.recv().unwrap();
            assert!(request.starts_with(&format!("GET {expected_path}")));
        }

        let (url, request) = one_response_server(
            "409 Conflict",
            r#"{"error":{"code":"REPLAY_MISMATCH","message":"diverged","details":{"height":4,"field":"post_state_root","expected":"aa","actual":"bb"}}}"#,
        );
        let mismatch = json_value(&invoke(
            vec![
                "replay".into(),
                "verify".into(),
                "--node-url".into(),
                url,
                "--json".into(),
            ],
            &startup,
        ));
        request.recv().unwrap();
        assert_eq!(mismatch["error"]["code"], "REPLAY_MISMATCH");
        assert_eq!(mismatch["error"]["details"]["height"], 4);
        assert_eq!(mismatch["error"]["details"]["field"], "post_state_root");
        assert_eq!(mismatch["error"]["details"]["expected"], "aa");
        assert_eq!(mismatch["error"]["details"]["actual"], "bb");
    }

    #[test]
    fn malformed_bounds_fail_stably_before_transport() {
        let startup = StartupEnvironment::fixed(PathBuf::from("missing-key"));
        let invocation = invoke(
            vec![
                "job".into(),
                "create".into(),
                "--repository".into(),
                "x".repeat(MAX_REPOSITORY_LOCATOR_BYTES + 1),
                "--json".into(),
            ],
            &startup,
        );
        assert_eq!(
            json_value(&invocation)["error"]["code"],
            "JOB_INPUT_INVALID"
        );
    }

    #[test]
    fn storage_and_input_failures_have_stable_json_codes_without_key_material() {
        let temp = TempDirectory::new();
        let key = temp.path().join("actor.key");
        let startup = StartupEnvironment::fixed(key);
        let args = vec!["identity".into(), "create".into(), "--json".into()];
        assert_json_success(&invoke(args.clone(), &startup), "identity.create");
        let exists = json_value(&invoke(args, &startup));
        assert_eq!(exists["error"]["code"], "IDENTITY_KEY_EXISTS");

        let invalid = invoke(
            vec![
                "identity".into(),
                "sign".into(),
                "--chain-id".into(),
                "00".into(),
                "--nonce".into(),
                "skipped".into(),
                "--valid-until-height".into(),
                "1".into(),
                "--action".into(),
                "zz".into(),
                "--json".into(),
            ],
            &startup,
        );
        assert_eq!(
            json_value(&invalid)["error"]["code"],
            "ACTION_INPUT_INVALID"
        );
    }

    fn one_response_server(
        status: &'static str,
        body: &'static str,
    ) -> (String, mpsc::Receiver<String>) {
        let (sender, receiver) = mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            sender.send(request).unwrap();
            write_response(&mut stream, status, body);
        });
        (format!("http://{address}"), receiver)
    }

    fn one_owned_response_server(
        status: &'static str,
        body: String,
    ) -> (String, mpsc::Receiver<String>) {
        let (sender, receiver) = mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            sender.send(request).unwrap();
            write_response(&mut stream, status, &body);
        });
        (format!("http://{address}"), receiver)
    }

    fn signed_request(request: &str) -> rachet_core::actions::SignedAction<Action> {
        let body = request.split("\r\n\r\n").nth(1).unwrap();
        let wrapper: Value = serde_json::from_str(body).unwrap();
        let canonical =
            decode_hex(wrapper["canonical_action"].as_str().unwrap(), "action").unwrap();
        decode_signed_action::<Action>(&canonical, &()).unwrap()
    }

    fn response_server(responses: Vec<(&'static str, &'static str)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let _ = read_request(&mut stream);
                write_response(&mut stream, status, body);
            }
        });
        format!("http://{address}")
    }

    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let count = stream.read(&mut chunk).unwrap();
            bytes.extend_from_slice(&chunk[..count]);
            let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap_or(0);
            if bytes.len() >= header_end + content_length {
                break;
            }
        }
        String::from_utf8(bytes).unwrap()
    }

    fn write_response(stream: &mut std::net::TcpStream, status: &str, body: &str) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    }

    fn assert_json_success(invocation: &Invocation, command: &str) -> Value {
        let value = json_value(invocation);
        assert_eq!(value["ok"], true);
        assert_eq!(value["command"], command);
        value
    }

    fn json_value(invocation: &Invocation) -> Value {
        serde_json::from_str(&render(invocation)).unwrap()
    }

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("rchtctl-{}-{nonce}-{sequence}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
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
