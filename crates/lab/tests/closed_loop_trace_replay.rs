use commonware_codec::Write as _;
use commonware_cryptography::{Signer as _, ed25519};
use rachet_core::{
    actions::{
        Action, ClaimDefinition, CreateJob, ResolutionPolicy, ResolutionVerdict, ResolveClaim,
        SignedAction,
    },
    artifacts::{ContentRef, GitArtifact, GitHash},
    blocks::ConsensusNodeId,
    bounded::{BoundedBytes, BoundedVec},
    limits::{
        MAX_CLAIM_STATEMENT_BYTES, MAX_CONTENT_LOCATOR_HINT_BYTES, MAX_MEDIA_TYPE_BYTES,
        MAX_METADATA_BYTES, MAX_REPOSITORY_LOCATOR_BYTES,
    },
    primitives::{ActorId, ChainId, ClaimId, ProtocolVersion, Sha256Digest},
};
use rachet_lab::{
    closed_loop_replay::{
        CapturedClosedLoopBlock, CapturedOperatorDecision, capture_closed_loop_run,
    },
    experiment::RunId,
    replay::replay_run,
    run_artifacts::RunArtifactStore,
    simulator::{DeterministicRunner, LaboratoryMechanism, RunnerConfig},
};
use rachet_operator::{
    agentctl::AgentctlBoundary,
    budget::ResourceBudget,
    decision::{AvailableClaim, AvailableJob, DecisionContext},
    host::{OperatorHost, ProtectedPaths},
    manifest::{
        AgentConfiguration, IdentityConstraints, IndependenceClaim, IndependenceDeclaration,
        InformationPolicy as ManifestInformationPolicy, LearningPolicy, OperatorKind, OperatorSpec,
        POPULATION_SCHEMA_VERSION, PRODUCTIVE_OBJECTIVE, PopulationManifest,
    },
    observation::{
        FinalizedPublicState, InformationPolicy, MechanismEconomicState, ObservationBuildInput,
        OperatorDeclaration, PrivateOperatorHistory, build,
    },
};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

const SYSTEM_PROMPT: &[u8] = b"Inspect the advertised claim and return strict JSON.";
const RAW_DECISION: &str = r#"{"schema_version":"operator-decision.v1","decision":"validate","job_id":"job-1","claims":[{"claim_id":"claim-1","verdict":"pass","confidence_basis_points":9000,"evidence_refs":[]}],"resource_report":{"model_calls":1,"tool_calls":0}}"#;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[test]
fn captured_multi_operator_run_replays_exactly_after_model_boundary_is_removed() {
    let temp = TempDirectory::new();
    let repository = repository(temp.path());
    let executable = script(temp.path());
    let mut population = population(temp.path(), &repository);
    let config = config();

    let authority_key = ed25519::PrivateKey::from_seed(742);
    let customer_key = ed25519::PrivateKey::from_seed(743);
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
    let finalized_root = digest_bytes(
        prefix.output.blocks[0]
            .block
            .header
            .post_state_root
            .as_ref(),
    );
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
    let mut expected_observations = Vec::new();
    let mut expected_prompts = Vec::new();
    for operator_id in ["alpha", "beta"] {
        let operator = population.operator_mut(operator_id).unwrap();
        let observation = observation(
            operator.actor_id(),
            operator.budget().remaining(),
            finalized_root,
            &jobs,
        );
        let invocation = boundary.invoke_and_sign(
            operator,
            SYSTEM_PROMPT,
            &observation,
            DecisionContext {
                chain_id: config.chain_id,
                next_nonce: 0,
                valid_until_height: 10,
                available_jobs: &available_jobs,
                available_evidence: &[],
            },
        );
        expected_observations.push(observation.canonical_json().to_vec());
        expected_prompts.push(invocation.prompt.clone());
        let decision = CapturedOperatorDecision::from_agentctl(
            operator_id,
            SYSTEM_PROMPT,
            &observation,
            &invocation,
        )
        .unwrap();
        assert_eq!(decision.signed_actions().len(), 1);
        captured.push(decision);
    }

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
            resolution_reference: content(0x74),
        }),
    )
    .unwrap();

    let experiment = temp.path().join("experiment");
    let run_id: RunId = "74".repeat(32).parse().unwrap();
    fs::create_dir_all(experiment.join("seeds")).unwrap();
    fs::create_dir_all(experiment.join("runs").join(run_id.to_string())).unwrap();
    let report = capture_closed_loop_run(
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
    assert_eq!(report.operators, 2);
    assert_eq!(report.decisions, 2);
    assert_eq!(report.signed_actions, 4);
    assert_eq!(report.blocks_executed, 3);

    let loaded = RunArtifactStore::load(&experiment, run_id).unwrap();
    let observations = jsonl(&loaded.bundle.observations_jsonl);
    let decisions = jsonl(&loaded.bundle.decisions_jsonl);
    assert_eq!(observations.len(), 2);
    assert_eq!(decisions.len(), 2);
    for index in 0..2 {
        assert_eq!(
            decode_hex(
                observations[index]["canonical_observation_hex"]
                    .as_str()
                    .unwrap()
            ),
            expected_observations[index]
        );
        assert_eq!(
            decode_hex(decisions[index]["system_prompt_hex"].as_str().unwrap()),
            SYSTEM_PROMPT
        );
        assert_eq!(
            decode_hex(decisions[index]["prompt_hex"].as_str().unwrap()),
            expected_prompts[index]
        );
        assert_eq!(
            decode_hex(decisions[index]["raw_output_hex"].as_str().unwrap()),
            RAW_DECISION.as_bytes()
        );
    }
    let economic = String::from_utf8(loaded.bundle.economic_state_jsonl.clone()).unwrap();
    assert!(economic.contains("\\\"m01_scores\\\"") || economic.contains("\"m01_scores\""));
    assert!(economic.lines().last().unwrap().contains("reputation"));

    // The external executable and all operator homes/keys/provenance disappear.
    // Replay still has only immutable initial state and captured signed actions.
    population.destroy().unwrap();
    fs::remove_file(executable).unwrap();
    let replay = replay_run(&experiment, run_id).unwrap();
    assert_eq!(replay.blocks_replayed, 3);
    assert_eq!(replay.model_calls, 0);
    assert!(replay.terminal_error.is_none());
}

fn config() -> RunnerConfig {
    RunnerConfig {
        seed: 74,
        chain_id: ChainId::new([0x74; 32]),
        blocks_per_epoch: 10,
        consensus_node: ConsensusNodeId::from(ed25519::PrivateKey::from_seed(740).public_key()),
        genesis_parent_block: Sha256Digest::from([0; 32]),
        genesis_timestamp_ms: 1_700_000_000_000,
        block_interval_ms: 1_000,
    }
}

fn create_job(authority: ActorId) -> CreateJob {
    CreateJob {
        artifact: GitArtifact::new(
            bounded::<MAX_REPOSITORY_LOCATOR_BYTES>(b"https://git.invalid/closed-loop"),
            GitHash::sha1([1; 20]),
            GitHash::sha256([2; 32]),
            content(3),
        ),
        claims: BoundedVec::new(vec![ClaimDefinition::new(bounded::<
            MAX_CLAIM_STATEMENT_BYTES,
        >(b"tests pass"))])
        .unwrap(),
        resolution_policy: ResolutionPolicy::ExperimentAuthority { authority },
        validation_opens_at: 1,
        validation_closes_at: 1,
        reveal_closes_at: None,
        challenge_closes_at: Some(3),
        supersedes: None,
        metadata: bounded::<MAX_METADATA_BYTES>(b"closed-loop fixture"),
    }
}

fn content(byte: u8) -> ContentRef {
    ContentRef::new(
        Sha256Digest::from([byte; 32]),
        bounded::<MAX_CONTENT_LOCATOR_HINT_BYTES>(b"cas://closed-loop"),
        bounded::<MAX_MEDIA_TYPE_BYTES>(b"application/json"),
    )
}

fn bounded<const MAX: usize>(bytes: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(bytes).unwrap()
}

fn observation(
    actor_id: &str,
    remaining: rachet_operator::budget::ResourceUsage,
    finalized_root: [u8; 32],
    jobs: &[String],
) -> rachet_operator::observation::ObservationSnapshot {
    let mechanisms = vec!["M01@1.0.0".to_owned()];
    let policy = InformationPolicy::section_31("section-31");
    build(ObservationBuildInput {
        finalized_public_state: FinalizedPublicState {
            experiment_id: "closed-loop-replay-test",
            epoch: 0,
            height: 1,
            finalized_state_root_sha256: finalized_root,
            public_history: b"public",
        },
        operator: OperatorDeclaration {
            actor_id,
            role: "validation_operator",
            objective: "maximize validation accuracy under the budget",
        },
        mechanism_economic_state: MechanismEconomicState {
            mechanism_set: &mechanisms,
            reputation: 0,
        },
        remaining_budget: remaining,
        available_jobs: jobs,
        private_operator_history: PrivateOperatorHistory {
            actor_id,
            bytes: b"private",
        },
        information_policy: &policy,
    })
    .unwrap()
}

fn population(root: &Path, repository: &Path) -> rachet_operator::host::OperatorPopulation {
    let host = OperatorHost::create(
        root.join("population"),
        repository,
        "HEAD",
        ProtectedPaths::empty(),
    )
    .unwrap();
    host.provision(PopulationManifest {
        schema_version: POPULATION_SCHEMA_VERSION.to_owned(),
        operators: ["alpha", "beta"]
            .into_iter()
            .map(|operator_id| OperatorSpec {
                operator_id: operator_id.to_owned(),
                role: "validation_operator".to_owned(),
                objective: PRODUCTIVE_OBJECTIVE.to_owned(),
                operator_kind: OperatorKind::Productive,
                agent: AgentConfiguration {
                    provider: "fixture".to_owned(),
                    model: "fixture-model".to_owned(),
                    model_family: "fixture-family".to_owned(),
                    random_seed: format!("fixture-seed-{operator_id}"),
                    tool_harness: "agentctl".to_owned(),
                    system_prompt_sha256: hash_hex(SYSTEM_PROMPT),
                },
                information: ManifestInformationPolicy::standard_validation(
                    "independent-inspection",
                ),
                learning: LearningPolicy::adaptive_validation(),
                communication_channels: Vec::new(),
                customer_relationship: "none".to_owned(),
                resource_budget: ResourceBudget {
                    model_calls: 2,
                    tool_calls: 2,
                    validation_seconds: 3,
                },
                identity_constraints: IdentityConstraints::validation_operator(),
                independence: IndependenceDeclaration {
                    model_family: IndependenceClaim::Shared {
                        group: "fixture-family".to_owned(),
                    },
                    system_prompt: IndependenceClaim::Shared {
                        group: "fixture-prompt".to_owned(),
                    },
                    random_seed: IndependenceClaim::Independent,
                    tool_harness: IndependenceClaim::Shared {
                        group: "agentctl-fixture".to_owned(),
                    },
                    memory: IndependenceClaim::Independent,
                    worktree: IndependenceClaim::Independent,
                    evidence_method: IndependenceClaim::Shared {
                        group: "independent-inspection".to_owned(),
                    },
                    communication_channel: IndependenceClaim::Independent,
                    customer_relationship: IndependenceClaim::Independent,
                },
            })
            .collect(),
        communication_channels: Vec::new(),
    })
    .unwrap()
}

fn script(root: &Path) -> PathBuf {
    let path = root.join("fake-agentctl");
    let body = format!(
        "#!/bin/sh\nset -eu\ntest -f \"$RACHET_OPERATOR_CONFIG\"\ndir=\"$HOME/.agentctl/jobs/fixture\"\nmkdir -p \"$dir\"\nprintf 'stdout:\\n%s\\n' '{}' > \"$dir/output.log\"\nprintf '[{{\"iteration\":1,\"iterations\":1,\"summary\":{{\"command\":\"fixture\",\"exit_code\":0,\"duration_ms\":1,\"preview_lines\":[],\"raw_log_path\":\"%s\"}}}}]\\n' \"$dir/output.log\"\n",
        RAW_DECISION
    );
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn repository(root: &Path) -> PathBuf {
    let repository = root.join("repository");
    fs::create_dir_all(&repository).unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["config", "user.name", "Rachet Test"]);
    git(
        &repository,
        &["config", "user.email", "rachet@example.invalid"],
    );
    fs::write(repository.join("README.md"), "public\n").unwrap();
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
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
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
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().unwrap()
}

fn hash_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rachet-closed-loop-replay-{}-{sequence}",
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
