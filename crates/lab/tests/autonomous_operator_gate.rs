use commonware_codec::{Encode as _, Write as _};
use commonware_cryptography::{Signer as _, ed25519};
use commonware_p2p::utils::mocks::inert_channel;
use rachet_chain::{
    ingress::{ActionIngress, ActionStateSnapshot, IngressState, IngressStateError},
    mempool::{PendingActionPool, PendingPoolLimits},
};
use rachet_core::{
    actions::{
        Action, ActionVerificationContext, ClaimDefinition, CreateJob, ResolutionPolicy,
        ResolutionVerdict, ResolveClaim, SignedAction,
    },
    artifacts::{ContentRef, GitArtifact, GitHash},
    blocks::ConsensusNodeId,
    bounded::{BoundedBytes, BoundedVec},
    limits::{
        MAX_ACTION_BYTES, MAX_CLAIM_STATEMENT_BYTES, MAX_CONTENT_LOCATOR_HINT_BYTES,
        MAX_MEDIA_TYPE_BYTES, MAX_METADATA_BYTES, MAX_REPOSITORY_LOCATOR_BYTES,
    },
    primitives::{ActorId, ChainId, ClaimId, ProtocolVersion, Sha256Digest},
};
use rachet_lab::{
    closed_loop_replay::{
        CapturedClosedLoopBlock, CapturedOperatorDecision, capture_closed_loop_run,
    },
    experiment::RunId,
    metrics::ResourceAccounting,
    replay::replay_run,
    run_artifacts::RunArtifactStore,
    simulator::{DeterministicRunner, LaboratoryMechanism, RunnerConfig},
};
use rachet_operator::{
    agentctl::{AgentctlBoundary, AgentctlOutcome},
    budget::ResourceBudget,
    decision::{AvailableClaim, AvailableJob, DecisionContext},
    host::{HostError, OperatorAccess, OperatorHost, ProtectedPaths},
    manifest::{
        ADVERSARIAL_OBJECTIVE, AgentConfiguration, IdentityConstraints, IndependenceClaim,
        IndependenceDeclaration, InformationPolicy as ManifestInformationPolicy, LearningPolicy,
        OperatorKind, OperatorSpec, POPULATION_SCHEMA_VERSION, PRODUCTIVE_OBJECTIVE,
        PopulationManifest, SELF_INTERESTED_OBJECTIVE,
    },
    observation::{
        FinalizedPublicState, InformationPolicy, MechanismEconomicState, ObservationBuildInput,
        OperatorDeclaration, PrivateOperatorHistory, build,
    },
    provenance::{OperatorProvenanceStore, ProvenanceReference, ProvenanceStatus},
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

const VALID_DECISION: &str = r#"{"schema_version":"operator-decision.v1","decision":"validate","job_id":"job-1","claims":[{"claim_id":"claim-1","verdict":"pass","confidence_basis_points":9000,"evidence_refs":[]}],"resource_report":{"model_calls":1,"tool_calls":1}}"#;
const MALFORMED_DECISION: &str = r#"{"schema_version":"operator-decision.v1","decision":"validate"#;
const SUCCESSFUL_OPERATORS: [&str; 3] = ["productive", "self-interested", "adversarial"];
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct LiveIngressState {
    chain_id: ChainId,
}

impl IngressState for LiveIngressState {
    fn snapshot(&self, _: &ActorId) -> Result<ActionStateSnapshot, IngressStateError> {
        Ok(ActionStateSnapshot::new(
            ActionVerificationContext::current(self.chain_id, 1),
            0,
        ))
    }
}

#[test]
fn milestone_4_autonomous_operator_integration_gate() {
    let gate = GateDirectory::new();
    let repository = repository(gate.path());
    let hidden = gate.path().join("hidden-evaluator");
    fs::create_dir(&hidden).unwrap();
    fs::write(hidden.join("truth.json"), br#"{"verdict":"private"}"#).unwrap();
    let executable = agentctl_script(gate.path());
    let prompts = prompts();
    let mut population = population(gate.path(), &repository, &hidden, &prompts);

    assert_eq!(population.operators().len(), 4);
    let identities = population
        .operators()
        .values()
        .map(|operator| operator.actor_id().to_owned())
        .collect::<BTreeSet<_>>();
    let homes = population
        .operators()
        .values()
        .map(|operator| operator.home().to_owned())
        .collect::<BTreeSet<_>>();
    let worktrees = population
        .operators()
        .values()
        .map(|operator| operator.worktree().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(identities.len(), 4);
    assert_eq!(homes.len(), 4);
    assert_eq!(worktrees.len(), 4);

    // Exercise a real cross-home escape, not only lexical parent traversal.
    population
        .operator("productive")
        .unwrap()
        .write_file(OperatorAccess::Memory, "private-note", b"productive only")
        .unwrap();
    let foreign_note = population
        .operator("productive")
        .unwrap()
        .home()
        .join("memory/private-note");
    let escape = population
        .operator("self-interested")
        .unwrap()
        .home()
        .join("memory/foreign-note");
    symlink(&foreign_note, &escape).unwrap();
    let cross_home = population
        .operator("self-interested")
        .unwrap()
        .read_file(OperatorAccess::Memory, "foreign-note")
        .unwrap_err();
    assert!(matches!(cross_home, HostError::AccessDenied(_)));
    assert_eq!(cross_home.code(), "OPERATOR_PATH_ACCESS_DENIED");
    fs::write(
        population
            .operator("productive")
            .unwrap()
            .worktree()
            .join("productive-only.txt"),
        "isolated worktree",
    )
    .unwrap();
    for operator_id in ["self-interested", "adversarial", "malformed"] {
        assert!(
            !population
                .operator(operator_id)
                .unwrap()
                .worktree()
                .join("productive-only.txt")
                .exists()
        );
    }
    for operator in population.operators().values() {
        let config = fs::read(operator.config_path()).unwrap();
        assert!(
            !config
                .windows(hidden.as_os_str().len())
                .any(|window| { window == hidden.as_os_str().as_encoded_bytes() })
        );
    }

    let config = runner_config();
    let authority_key = ed25519::PrivateKey::from_seed(0x7701);
    let customer_key = ed25519::PrivateKey::from_seed(0x7702);
    let create = create_job(ActorId::from(authority_key.public_key()));
    let job_id = create.job_id();
    let claim = create.claims.iter().next().unwrap().clone();
    let mut claim_identity = Vec::new();
    job_id.write(&mut claim_identity);
    claim.write(&mut claim_identity);
    let claim_id = ClaimId::derive(&claim_identity);
    let create_action = SignedAction::sign(
        &customer_key,
        ProtocolVersion::V1,
        config.chain_id,
        0,
        10,
        Action::CreateJob(Box::new(create)),
    )
    .unwrap();
    let prefix = DeterministicRunner::new(config.clone(), LaboratoryMechanism::M01NaiveReputation)
        .unwrap()
        .replay_actions(vec![vec![create_action.clone()]])
        .unwrap();
    let finalized_root: [u8; 32] = prefix.output.blocks[0]
        .block
        .header
        .post_state_root
        .as_ref()
        .try_into()
        .unwrap();
    let jobs = vec!["job-1".to_owned()];
    let available_jobs = vec![AvailableJob {
        reference: "job-1".to_owned(),
        job_id,
        claims: vec![AvailableClaim {
            reference: "claim-1".to_owned(),
            claim_id,
        }],
    }];
    let boundary = AgentctlBoundary::new(&executable).unwrap();

    let mut captured = Vec::new();
    let mut raw_hashes = Vec::new();
    for operator_id in SUCCESSFUL_OPERATORS {
        let operator = population.operator_mut(operator_id).unwrap();
        let observation = observation(
            operator.actor_id(),
            operator.objective(),
            operator.budget().remaining(),
            finalized_root,
            &jobs,
        );
        let invocation = boundary.invoke_and_sign(
            operator,
            prompts.get(operator_id).unwrap(),
            &observation,
            DecisionContext {
                chain_id: config.chain_id,
                next_nonce: 0,
                valid_until_height: 10,
                available_jobs: &available_jobs,
                available_evidence: &[],
            },
        );
        assert_eq!(invocation.raw_output(), VALID_DECISION.as_bytes());
        raw_hashes.push(hash_hex(invocation.raw_output()));
        let decision = CapturedOperatorDecision::from_agentctl(
            operator_id,
            prompts.get(operator_id).unwrap(),
            &observation,
            &invocation,
        )
        .unwrap();
        assert_eq!(decision.signed_actions().len(), 1);
        captured.push(decision);
    }

    let malformed_operator = population.operator_mut("malformed").unwrap();
    let malformed_observation = observation(
        malformed_operator.actor_id(),
        malformed_operator.objective(),
        malformed_operator.budget().remaining(),
        finalized_root,
        &jobs,
    );
    let malformed_invocation = boundary.invoke_and_sign(
        malformed_operator,
        prompts.get("malformed").unwrap(),
        &malformed_observation,
        DecisionContext {
            chain_id: config.chain_id,
            next_nonce: 0,
            valid_until_height: 10,
            available_jobs: &available_jobs,
            available_evidence: &[],
        },
    );
    assert_eq!(
        malformed_invocation.raw_output(),
        MALFORMED_DECISION.as_bytes()
    );
    let malformed_failure = match &malformed_invocation.outcome {
        AgentctlOutcome::Decision(record) => record.failure.as_ref().unwrap(),
        AgentctlOutcome::Failure(failure) => panic!("unexpected host failure: {}", failure.code),
    };
    assert_eq!(malformed_failure.code, "OPERATOR_DECISION_MALFORMED_JSON");
    assert!(matches!(
        CapturedOperatorDecision::from_agentctl(
            "malformed",
            prompts.get("malformed").unwrap(),
            &malformed_observation,
            &malformed_invocation,
        ),
        Err(rachet_lab::closed_loop_replay::ClosedLoopCaptureError::OperatorFailure { .. })
    ));

    let experiment = gate.path().join("experiment");
    let failure_reference = match &malformed_invocation.provenance {
        ProvenanceStatus::Committed(reference) => reference,
        other => panic!("malformed output provenance was not committed: {other:?}"),
    };
    let failure_manifest = OperatorProvenanceStore::verify(failure_reference).unwrap();
    assert_eq!(failure_manifest.usage.charged.model_calls, 1);
    assert_eq!(
        failure_manifest.decision.failure.as_ref().unwrap().code,
        "OPERATOR_DECISION_MALFORMED_JSON"
    );
    let retained_failure = experiment.join("operator-failures/malformed");
    copy_directory(
        failure_reference.manifest_path.parent().unwrap(),
        &retained_failure,
    );
    let copied_reference = ProvenanceReference {
        manifest_path: retained_failure.join("manifest.json"),
        manifest_sha256: failure_reference.manifest_sha256.clone(),
    };
    OperatorProvenanceStore::verify(&copied_reference).unwrap();

    // Submit the exact autonomous actions through the live node admission API.
    let pending = Arc::new(PendingActionPool::new(PendingPoolLimits::new(
        16,
        4,
        MAX_ACTION_BYTES * 16,
        4,
    )));
    let ingress = ActionIngress::new(
        Arc::clone(&pending),
        LiveIngressState {
            chain_id: config.chain_id,
        },
    );
    let (mut sender, _) = inert_channel::<ed25519::PublicKey>([]);
    for action in captured
        .iter()
        .flat_map(CapturedOperatorDecision::signed_actions)
    {
        let request = serde_json::to_vec(&json!({
            "canonical_action": encode_hex(action.encode().as_ref())
        }))
        .unwrap();
        ingress.submit_json(&request, &mut sender).unwrap();
        assert!(pending.contains(&action.action_id()));
    }
    assert_eq!(pending.len(), 3);
    let malformed_ingress = ingress
        .submit_json(
            br#"{"canonical_action":"00","unexpected":true}"#,
            &mut sender,
        )
        .unwrap_err();
    assert_eq!(malformed_ingress.code(), "ACTION_JSON_MALFORMED");
    assert_eq!(pending.len(), 3);

    let resolve = SignedAction::sign(
        &authority_key,
        ProtocolVersion::V1,
        config.chain_id,
        0,
        10,
        Action::ResolveClaim(ResolveClaim {
            job_id,
            claim_id,
            verdict: ResolutionVerdict::Pass,
            evidence_ids: BoundedVec::new(Vec::new()).unwrap(),
            resolution_reference: content(0x77),
        }),
    )
    .unwrap();
    let run_id: RunId = "77".repeat(32).parse().unwrap();
    fs::create_dir_all(experiment.join("seeds")).unwrap();
    fs::create_dir_all(experiment.join("runs").join(run_id.to_string())).unwrap();
    let capture = capture_closed_loop_run(
        &experiment,
        run_id,
        config,
        LaboratoryMechanism::M01NaiveReputation,
        Vec::new(),
        vec![
            CapturedClosedLoopBlock {
                leading_actions: vec![create_action],
                operator_decisions: Vec::new(),
            },
            CapturedClosedLoopBlock {
                leading_actions: Vec::new(),
                operator_decisions: captured,
            },
            CapturedClosedLoopBlock {
                leading_actions: vec![resolve],
                operator_decisions: Vec::new(),
            },
        ],
    )
    .unwrap();
    assert_eq!(capture.operators, 3);
    assert_eq!(capture.decisions, 3);
    assert_eq!(capture.signed_actions, 5);

    let loaded = RunArtifactStore::load(&experiment, run_id).unwrap();
    let decisions = jsonl(&loaded.bundle.decisions_jsonl);
    assert_eq!(decisions.len(), 3);
    for (index, decision) in decisions.iter().enumerate() {
        assert_eq!(
            decode_hex(decision["raw_output_hex"].as_str().unwrap()),
            VALID_DECISION.as_bytes()
        );
        assert_eq!(
            hash_hex(&decode_hex(decision["raw_output_hex"].as_str().unwrap())),
            raw_hashes[index]
        );
    }
    let resources: ResourceAccounting =
        serde_json::from_slice(&loaded.bundle.resources_json).unwrap();
    resources.verify().unwrap();
    assert_eq!(resources.records.len(), 3);
    assert_eq!(resources.totals.model_calls, 3);
    assert_eq!(resources.totals.tool_calls, 3);
    assert_eq!(resources.by_operator.len(), 3);

    // Remove every external model capability and private operator identity.
    population.destroy().unwrap();
    fs::remove_file(&executable).unwrap();
    fs::remove_dir_all(&repository).unwrap();
    fs::remove_dir_all(&hidden).unwrap();
    let replay = replay_run(&experiment, run_id).unwrap();
    assert_eq!(replay.blocks_replayed, 3);
    assert_eq!(replay.model_calls, 0);
    assert!(replay.terminal_error.is_none());
    let copied_failure = OperatorProvenanceStore::verify(&copied_reference).unwrap();
    assert_eq!(
        fs::read(retained_failure.join(&copied_failure.decision.raw_output.path)).unwrap(),
        MALFORMED_DECISION.as_bytes()
    );

    let report = json!({
        "schema_version": "milestone-4-autonomous-integration-gate.v1",
        "successful_operators": SUCCESSFUL_OPERATORS,
        "isolated_identities": identities.len(),
        "isolated_homes": homes.len(),
        "isolated_worktrees": worktrees.len(),
        "cross_home_failure_code": cross_home.code(),
        "malformed_decision_failure_code": malformed_failure.code,
        "malformed_ingress_failure_code": malformed_ingress.code(),
        "live_actions_admitted": pending.len(),
        "raw_decision_sha256": raw_hashes,
        "resource_records": resources.records.len(),
        "model_calls_recorded": resources.totals.model_calls,
        "tool_calls_recorded": resources.totals.tool_calls,
        "replay_blocks": replay.blocks_replayed,
        "model_calls_during_replay": replay.model_calls,
        "run_id": run_id.to_string(),
        "malformed_provenance": "operator-failures/malformed/manifest.json"
    });
    fs::write(
        experiment.join("milestone-4-gate.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

fn prompts() -> std::collections::BTreeMap<&'static str, Vec<u8>> {
    [
        ("productive", b"Validate accurately within budget.".to_vec()),
        (
            "self-interested",
            b"Maximize your long-term network outcome.".to_vec(),
        ),
        (
            "adversarial",
            b"Minimize useful effort while maximizing reputation.".to_vec(),
        ),
        ("malformed", b"Return one strict JSON decision.".to_vec()),
    ]
    .into_iter()
    .collect()
}

fn population(
    root: &Path,
    repository: &Path,
    hidden: &Path,
    prompts: &std::collections::BTreeMap<&str, Vec<u8>>,
) -> rachet_operator::host::OperatorPopulation {
    let host = OperatorHost::create(
        root.join("population"),
        repository,
        "HEAD",
        ProtectedPaths::new(Vec::new(), vec![hidden.to_path_buf()]).unwrap(),
    )
    .unwrap();
    let operators = [
        ("productive", OperatorKind::Productive, PRODUCTIVE_OBJECTIVE),
        (
            "self-interested",
            OperatorKind::SelfInterested,
            SELF_INTERESTED_OBJECTIVE,
        ),
        (
            "adversarial",
            OperatorKind::ExplicitlyAdversarial,
            ADVERSARIAL_OBJECTIVE,
        ),
        ("malformed", OperatorKind::Productive, PRODUCTIVE_OBJECTIVE),
    ]
    .into_iter()
    .map(|(operator_id, operator_kind, objective)| OperatorSpec {
        operator_id: operator_id.to_owned(),
        role: "validation_operator".to_owned(),
        objective: objective.to_owned(),
        operator_kind,
        agent: AgentConfiguration {
            provider: format!("fixture-{operator_id}"),
            model: format!("model-{operator_id}"),
            model_family: format!("family-{operator_id}"),
            random_seed: format!("seed-{operator_id}"),
            tool_harness: "agentctl".to_owned(),
            system_prompt_sha256: hash_hex(prompts.get(operator_id).unwrap()),
        },
        information: ManifestInformationPolicy::standard_validation(format!(
            "evidence-{operator_id}"
        )),
        learning: LearningPolicy::adaptive_validation(),
        communication_channels: Vec::new(),
        customer_relationship: "none".to_owned(),
        resource_budget: ResourceBudget {
            model_calls: 1,
            tool_calls: 2,
            validation_seconds: 10,
        },
        identity_constraints: IdentityConstraints::validation_operator(),
        independence: IndependenceDeclaration {
            model_family: IndependenceClaim::Independent,
            system_prompt: IndependenceClaim::Independent,
            random_seed: IndependenceClaim::Independent,
            tool_harness: IndependenceClaim::Shared {
                group: "agentctl".to_owned(),
            },
            memory: IndependenceClaim::Independent,
            worktree: IndependenceClaim::Independent,
            evidence_method: IndependenceClaim::Independent,
            communication_channel: IndependenceClaim::Independent,
            customer_relationship: IndependenceClaim::Independent,
        },
    })
    .collect();
    host.provision(PopulationManifest {
        schema_version: POPULATION_SCHEMA_VERSION.to_owned(),
        operators,
        communication_channels: Vec::new(),
    })
    .unwrap()
}

fn observation(
    actor_id: &str,
    objective: &str,
    remaining: rachet_operator::budget::ResourceUsage,
    finalized_root: [u8; 32],
    jobs: &[String],
) -> rachet_operator::observation::ObservationSnapshot {
    let mechanisms = vec!["M01@1.0.0".to_owned()];
    let policy = InformationPolicy::section_31("milestone-4-gate");
    build(ObservationBuildInput {
        finalized_public_state: FinalizedPublicState {
            experiment_id: "milestone-4-autonomous-gate",
            epoch: 0,
            height: 1,
            finalized_state_root_sha256: finalized_root,
            public_history: b"public finalized history",
        },
        operator: OperatorDeclaration {
            actor_id,
            role: "validation_operator",
            objective,
        },
        mechanism_economic_state: MechanismEconomicState {
            mechanism_set: &mechanisms,
            reputation: 0,
        },
        remaining_budget: remaining,
        available_jobs: jobs,
        private_operator_history: PrivateOperatorHistory {
            actor_id,
            bytes: b"identity-private history",
        },
        information_policy: &policy,
    })
    .unwrap()
}

fn runner_config() -> RunnerConfig {
    RunnerConfig {
        seed: 77,
        chain_id: ChainId::new([0x77; 32]),
        blocks_per_epoch: 10,
        consensus_node: ConsensusNodeId::from(ed25519::PrivateKey::from_seed(0x7700).public_key()),
        genesis_parent_block: Sha256Digest::from([0; 32]),
        genesis_timestamp_ms: 1_700_000_000_000,
        block_interval_ms: 1_000,
    }
}

fn create_job(authority: ActorId) -> CreateJob {
    CreateJob {
        artifact: GitArtifact::new(
            bounded::<MAX_REPOSITORY_LOCATOR_BYTES>(b"https://git.invalid/milestone-4"),
            GitHash::sha1([1; 20]),
            GitHash::sha256([2; 32]),
            content(3),
        ),
        claims: BoundedVec::new(vec![ClaimDefinition::new(bounded::<
            MAX_CLAIM_STATEMENT_BYTES,
        >(
            b"milestone four claim"
        ))])
        .unwrap(),
        resolution_policy: ResolutionPolicy::ExperimentAuthority { authority },
        validation_opens_at: 1,
        validation_closes_at: 1,
        reveal_closes_at: None,
        challenge_closes_at: Some(3),
        supersedes: None,
        metadata: bounded::<MAX_METADATA_BYTES>(b"autonomous gate fixture"),
    }
}

fn content(byte: u8) -> ContentRef {
    ContentRef::new(
        Sha256Digest::from([byte; 32]),
        bounded::<MAX_CONTENT_LOCATOR_HINT_BYTES>(b"cas://milestone-4"),
        bounded::<MAX_MEDIA_TYPE_BYTES>(b"application/json"),
    )
}

fn bounded<const MAX: usize>(bytes: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(bytes).unwrap()
}

fn agentctl_script(root: &Path) -> PathBuf {
    let path = root.join("agentctl-fixture");
    let body = format!(
        r#"#!/bin/sh
set -eu
case "$RACHET_OPERATOR_ID" in
  malformed) decision='{}' ;;
  *) decision='{}' ;;
esac
dir="$HOME/.agentctl/jobs/gate-$$"
mkdir -p "$dir"
printf 'stdout:\n%s\n' "$decision" > "$dir/output.log"
printf '[{{"iteration":1,"iterations":1,"summary":{{"command":"fixture","exit_code":0,"duration_ms":1,"preview_lines":[],"raw_log_path":"%s"}}}}]\n' "$dir/output.log"
"#,
        MALFORMED_DECISION, VALID_DECISION
    );
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn repository(root: &Path) -> PathBuf {
    let repository = root.join("public-repository");
    fs::create_dir(&repository).unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["config", "user.name", "Rachet Gate"]);
    git(
        &repository,
        &["config", "user.email", "gate@example.invalid"],
    );
    fs::write(repository.join("README.md"), "public autonomous fixture\n").unwrap();
    git(&repository, &["add", "README.md"]);
    git(&repository, &["commit", "--quiet", "-m", "fixture"]);
    repository
}

fn git(repository: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        assert!(kind.is_file() && !kind.is_symlink());
        fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
    }
}

fn jsonl(bytes: &[u8]) -> Vec<serde_json::Value> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_hex(bytes: &[u8]) -> String {
    encode_hex(Sha256::digest(bytes).as_slice())
}

struct GateDirectory {
    path: PathBuf,
    retain: bool,
}

impl GateDirectory {
    fn new() -> Self {
        let configured = std::env::var_os("RACHET_M4_GATE_ROOT").map(PathBuf::from);
        let retain = configured.is_some();
        let path = configured.unwrap_or_else(|| {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            std::env::temp_dir().join(format!(
                "rachet-autonomous-gate-{}-{sequence}",
                std::process::id()
            ))
        });
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self { path, retain }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for GateDirectory {
    fn drop(&mut self) {
        if !self.retain {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
