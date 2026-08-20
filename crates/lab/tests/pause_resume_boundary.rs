use commonware_cryptography::{Signer as _, ed25519};
use rachet_core::{
    blocks::ConsensusNodeId,
    primitives::{ChainId, Sha256Digest},
    state::{InMemoryStateBatch, StateBatch as _},
};
use rachet_lab::{
    decision_boundary::{BoundaryPhase, PauseResumeBoundary},
    simulator::{LaboratoryMechanism, RunnerConfig},
};
use rachet_operator::{
    agentctl::AgentctlBoundary,
    budget::ResourceBudget,
    decision::DecisionContext,
    host::{OperatorHost, ProtectedPaths},
    manifest::{
        AgentConfiguration, IdentityConstraints, IndependenceDeclaration,
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

const SYSTEM_PROMPT: &[u8] = b"Act as a bounded validation operator.";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[test]
fn pause_invoke_restart_and_explicit_resume_are_durable() {
    let temp = TempDirectory::new("success");
    let repository = repository(temp.path());
    let executable = script(temp.path(), WAIT_SCRIPT);
    let (mut population, config) = population_and_config(temp.path(), &repository);
    let operator = population.operator_mut("alpha").unwrap();
    let observation = observation(
        operator.actor_id(),
        operator.budget().remaining(),
        empty_state_root(),
    );
    let boundary_root = temp.path().join("boundary");

    let paused = PauseResumeBoundary::pause(
        &boundary_root,
        config.clone(),
        LaboratoryMechanism::M00RecordOnly,
        Vec::new(),
        Vec::new(),
        observation,
    )
    .unwrap();
    assert_eq!(paused.status().phase, BoundaryPhase::Paused);
    assert!(boundary_root.join("observation.json").is_file());
    drop(paused);

    let mut restored = PauseResumeBoundary::open(&boundary_root).unwrap();
    assert_eq!(restored.status().phase, BoundaryPhase::Paused);
    let external = AgentctlBoundary::new(executable).unwrap();
    let status = restored
        .invoke_external(
            &external,
            operator,
            SYSTEM_PROMPT,
            DecisionContext {
                chain_id: config.chain_id,
                next_nonce: 0,
                valid_until_height: 10,
                available_jobs: &[],
                available_evidence: &[],
            },
        )
        .unwrap();
    assert_eq!(status.phase, BoundaryPhase::Ready);
    assert!(boundary_root.join("raw-output.bin").is_file());
    assert!(boundary_root.join("decision.json").is_file());
    assert!(boundary_root.join("decision-actions.bin").is_file());
    drop(restored);

    let mut ready_after_restart = PauseResumeBoundary::open(&boundary_root).unwrap();
    assert_eq!(ready_after_restart.status().phase, BoundaryPhase::Ready);
    let resumed = ready_after_restart.resume().unwrap();
    assert_eq!(resumed.output.blocks.len(), 1);
    assert!(resumed.output.blocks[0].block.actions.is_empty());
    let expected =
        rachet_lab::simulator::DeterministicRunner::new(config, LaboratoryMechanism::M00RecordOnly)
            .unwrap()
            .replay_actions(vec![Vec::new()])
            .unwrap();
    assert_eq!(
        resumed.output.canonical_bytes(),
        expected.output.canonical_bytes()
    );
    drop(ready_after_restart);

    let terminal = PauseResumeBoundary::open(&boundary_root).unwrap();
    assert_eq!(terminal.status().phase, BoundaryPhase::Resumed);
    assert!(boundary_root.join("resume.json").is_file());
    population.destroy().unwrap();
}

#[test]
fn in_flight_host_intent_is_failed_not_reinvoked_after_restart() {
    let temp = TempDirectory::new("interrupted");
    let repository = repository(temp.path());
    let (mut population, config) = population_and_config(temp.path(), &repository);
    let operator = population.operator_mut("alpha").unwrap();
    let observation = observation(
        operator.actor_id(),
        operator.budget().remaining(),
        empty_state_root(),
    );
    let boundary_root = temp.path().join("boundary");
    let boundary = PauseResumeBoundary::pause(
        &boundary_root,
        config,
        LaboratoryMechanism::M00RecordOnly,
        Vec::new(),
        Vec::new(),
        observation,
    )
    .unwrap();
    drop(boundary);

    let state_path = boundary_root.join("boundary-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    state["phase"] = serde_json::json!({"status": "invoking"});
    fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let recovered = PauseResumeBoundary::open(&boundary_root).unwrap();
    assert_eq!(recovered.status().phase, BoundaryPhase::Failed);
    assert_eq!(
        recovered.status().failure.unwrap().code,
        "LAB_EXTERNAL_INVOCATION_INTERRUPTED"
    );
    drop(recovered);
    assert_eq!(
        PauseResumeBoundary::open(&boundary_root)
            .unwrap()
            .status()
            .phase,
        BoundaryPhase::Failed
    );
    population.destroy().unwrap();
}

#[test]
fn malformed_external_output_becomes_a_restart_stable_failure() {
    let temp = TempDirectory::new("malformed");
    let repository = repository(temp.path());
    let executable = script(temp.path(), &WAIT_SCRIPT.replace(DECISION, "not-json"));
    let (mut population, config) = population_and_config(temp.path(), &repository);
    let operator = population.operator_mut("alpha").unwrap();
    let observation = observation(
        operator.actor_id(),
        operator.budget().remaining(),
        empty_state_root(),
    );
    let boundary_root = temp.path().join("boundary");
    let mut boundary = PauseResumeBoundary::pause(
        &boundary_root,
        config.clone(),
        LaboratoryMechanism::M00RecordOnly,
        Vec::new(),
        Vec::new(),
        observation,
    )
    .unwrap();
    let external = AgentctlBoundary::new(executable).unwrap();
    let status = boundary
        .invoke_external(
            &external,
            operator,
            SYSTEM_PROMPT,
            DecisionContext {
                chain_id: config.chain_id,
                next_nonce: 0,
                valid_until_height: 10,
                available_jobs: &[],
                available_evidence: &[],
            },
        )
        .unwrap();
    assert_eq!(status.phase, BoundaryPhase::Failed);
    assert_eq!(
        status.failure.unwrap().code,
        "OPERATOR_DECISION_MALFORMED_JSON"
    );
    assert_eq!(
        fs::read(boundary_root.join("raw-output.bin")).unwrap(),
        b"not-json"
    );
    assert!(boundary.resume().is_err());
    drop(boundary);

    let restored = PauseResumeBoundary::open(&boundary_root).unwrap();
    assert_eq!(restored.status().phase, BoundaryPhase::Failed);
    assert_eq!(
        restored.status().failure.unwrap().code,
        "OPERATOR_DECISION_MALFORMED_JSON"
    );
    population.destroy().unwrap();
}

const DECISION: &str = r#"{"schema_version":"operator-decision.v1","decision":"wait","resource_report":{"model_calls":1,"tool_calls":0}}"#;
const WAIT_SCRIPT: &str = r#"
test -f "$RACHET_OPERATOR_CONFIG"
prompt=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '--prompt-file' ]; then prompt="$2"; shift 2; else shift; fi
done
grep -q 'operator-observation.v1' "$prompt"
dir="$HOME/.agentctl/jobs/fixture"
mkdir -p "$dir"
printf 'stdout:\n%s\n' '{"schema_version":"operator-decision.v1","decision":"wait","resource_report":{"model_calls":1,"tool_calls":0}}' > "$dir/output.log"
printf '[{"iteration":1,"iterations":1,"summary":{"command":"fixture","exit_code":0,"duration_ms":1,"preview_lines":[],"raw_log_path":"%s"}}]\n' "$dir/output.log"
"#;

fn population_and_config(
    root: &Path,
    repository: &Path,
) -> (rachet_operator::host::OperatorPopulation, RunnerConfig) {
    let host = OperatorHost::create(
        root.join("population"),
        repository,
        "HEAD",
        ProtectedPaths::empty(),
    )
    .unwrap();
    let population = host
        .provision(PopulationManifest {
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
                independence: IndependenceDeclaration::all_independent(),
            }],
            communication_channels: Vec::new(),
        })
        .unwrap();
    let config = RunnerConfig {
        seed: 73,
        chain_id: ChainId::new([0x73; 32]),
        blocks_per_epoch: 10,
        consensus_node: ConsensusNodeId::from(ed25519::PrivateKey::from_seed(730).public_key()),
        genesis_parent_block: Sha256Digest::from([0; 32]),
        genesis_timestamp_ms: 1_700_000_000_000,
        block_interval_ms: 1_000,
    };
    (population, config)
}

fn observation(
    actor_id: &str,
    remaining: rachet_operator::budget::ResourceUsage,
    finalized_root: [u8; 32],
) -> rachet_operator::observation::ObservationSnapshot {
    let mechanisms = vec!["M00@1.0.0".to_owned()];
    let jobs = Vec::new();
    let policy = InformationPolicy::section_31("section-31");
    build(ObservationBuildInput {
        finalized_public_state: FinalizedPublicState {
            experiment_id: "pause-resume-test",
            epoch: 0,
            height: 0,
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
        available_jobs: &jobs,
        private_operator_history: PrivateOperatorHistory {
            actor_id,
            bytes: b"private",
        },
        information_policy: &policy,
    })
    .unwrap()
}

fn empty_state_root() -> [u8; 32] {
    let root = InMemoryStateBatch::new().root();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(root.as_ref());
    bytes
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
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn script(root: &Path, body: &str) -> PathBuf {
    let path = root.join("fake-agentctl");
    fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn hash_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(name: &str) -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rachet-pause-resume-{name}-{}-{sequence}",
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
