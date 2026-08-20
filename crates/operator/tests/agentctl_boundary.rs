use rachet_core::primitives::{ChainId, ClaimId, EvidenceId, JobId};
use rachet_operator::{
    agentctl::{AgentctlBoundary, AgentctlOutcome},
    budget::ResourceBudget,
    decision::{AvailableClaim, AvailableEvidence, AvailableJob, DecisionContext},
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
    provenance::{
        OperatorProvenanceManifest, OperatorProvenanceStore, OperatorRunOutcome, ProvenanceStatus,
    },
};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const SYSTEM_PROMPT: &[u8] = b"Act as a bounded validation operator.";

fn temporary_path(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rachet-agentctl-{name}-{}-{unique}",
        std::process::id()
    ))
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

fn hash_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn operator(budget: ResourceBudget) -> OperatorSpec {
    OperatorSpec {
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
        information: ManifestInformationPolicy::standard_validation("independent-inspection"),
        learning: LearningPolicy::adaptive_validation(),
        communication_channels: Vec::new(),
        customer_relationship: "none".to_owned(),
        resource_budget: budget,
        identity_constraints: IdentityConstraints::validation_operator(),
        independence: IndependenceDeclaration::all_independent(),
    }
}

fn script(root: &Path, body: &str) -> PathBuf {
    let path = root.join("fake-agentctl");
    fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn observation(
    actor_id: &str,
    remaining: rachet_operator::budget::ResourceUsage,
) -> rachet_operator::observation::ObservationSnapshot {
    let mechanisms = vec!["M01@1.0.0".to_owned()];
    let jobs = Vec::new();
    let policy = InformationPolicy::section_31("section-31");
    build(ObservationBuildInput {
        finalized_public_state: FinalizedPublicState {
            experiment_id: "agentctl-test",
            epoch: 1,
            height: 7,
            finalized_state_root_sha256: [3; 32],
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

fn run_case(
    name: &str,
    budget: ResourceBudget,
    body: &str,
) -> (
    rachet_operator::agentctl::AgentctlInvocationRecord,
    rachet_operator::budget::ResourceUsage,
    OperatorProvenanceManifest,
) {
    let root = temporary_path(name);
    fs::create_dir_all(&root).unwrap();
    let repository = repository(&root);
    let executable = script(&root, body);
    let host = OperatorHost::create(
        root.join("population"),
        &repository,
        "HEAD",
        ProtectedPaths::empty(),
    )
    .unwrap();
    let mut population = host
        .provision(PopulationManifest {
            schema_version: POPULATION_SCHEMA_VERSION.to_owned(),
            operators: vec![operator(budget)],
            communication_channels: Vec::new(),
        })
        .unwrap();
    let operator = population.operator_mut("alpha").unwrap();
    let snapshot = observation(operator.actor_id(), operator.budget().remaining());
    let boundary = AgentctlBoundary::new(executable).unwrap();
    let job_id = JobId::derive(b"agentctl fixture job");
    let claim_id = ClaimId::derive(b"agentctl fixture claim");
    let available_jobs = [AvailableJob {
        reference: "job-1".to_owned(),
        job_id,
        claims: vec![AvailableClaim {
            reference: "claim-1".to_owned(),
            claim_id,
        }],
    }];
    let available_evidence = [AvailableEvidence {
        reference: "evidence-1".to_owned(),
        evidence_id: EvidenceId::derive(b"agentctl fixture evidence"),
        job_id,
        claim_id: Some(claim_id),
    }];
    let record = boundary.invoke_and_sign(
        operator,
        SYSTEM_PROMPT,
        &snapshot,
        DecisionContext {
            chain_id: ChainId::new([9; 32]),
            next_nonce: 0,
            valid_until_height: 10,
            available_jobs: &available_jobs,
            available_evidence: &available_evidence,
        },
    );
    let used = operator.budget().used();
    let provenance = match &record.provenance {
        ProvenanceStatus::Committed(reference) => {
            OperatorProvenanceStore::verify(reference).unwrap()
        }
        status => panic!("operator provenance was not committed: {status:?}"),
    };
    population.destroy().unwrap();
    fs::remove_dir_all(root).unwrap();
    (record, used, provenance)
}

const SUCCESS_SCRIPT: &str = r#"
test "$HOME" = "$AGENTCTL_HOME"
test -f "$RACHET_OPERATOR_CONFIG"
test "$RACHET_REMAINING_MODEL_CALLS" -ge 1
test "$RACHET_REMAINING_VALIDATION_SECONDS" -ge 1
prompt=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '--prompt-file' ]; then prompt="$2"; shift 2; else shift; fi
done
test -f "$prompt"
grep -q 'operator-observation.v1' "$prompt"
dir="$HOME/.agentctl/jobs/fixture"
mkdir -p "$dir"
printf 'stdout:\n%s\n' '{"schema_version":"operator-decision.v1","decision":"wait","resource_report":{"model_calls":1,"tool_calls":0}}' > "$dir/output.log"
printf '[{"iteration":1,"iterations":1,"summary":{"command":"fixture","exit_code":0,"duration_ms":1,"preview_lines":[],"raw_log_path":"%s"}}]\n' "$dir/output.log"
"#;

#[test]
fn successful_agentctl_decision_is_bounded_charged_and_signed() {
    let (record, used, _) = run_case(
        "success",
        ResourceBudget {
            model_calls: 2,
            tool_calls: 2,
            validation_seconds: 3,
        },
        SUCCESS_SCRIPT,
    );
    assert_eq!(record.exit_code, Some(0));
    assert!(!record.timed_out);
    assert!(record.raw_log.as_ref().unwrap().path.is_absolute());
    match record.outcome {
        AgentctlOutcome::Decision(decision) => {
            assert!(decision.succeeded());
            assert!(decision.signed_actions.is_empty());
        }
        AgentctlOutcome::Failure(failure) => panic!("unexpected failure: {failure:?}"),
    }
    assert_eq!(used.model_calls, 1);
    assert_eq!(used.tool_calls, 0);
    assert!(used.validation_seconds <= 1);
}

#[test]
fn malformed_model_json_is_retained_without_action() {
    let body = SUCCESS_SCRIPT.replace(
        "{\"schema_version\":\"operator-decision.v1\",\"decision\":\"wait\",\"resource_report\":{\"model_calls\":1,\"tool_calls\":0}}",
        "not-json",
    );
    let (record, used, _) = run_case(
        "malformed",
        ResourceBudget {
            model_calls: 1,
            tool_calls: 1,
            validation_seconds: 3,
        },
        &body,
    );
    assert!(
        record
            .raw_log
            .as_ref()
            .unwrap()
            .bytes
            .windows(8)
            .any(|w| w == b"not-json")
    );
    match record.outcome {
        AgentctlOutcome::Decision(decision) => {
            assert!(!decision.succeeded());
            assert_eq!(
                decision.failure.unwrap().code,
                "OPERATOR_DECISION_MALFORMED_JSON"
            );
            assert!(decision.signed_actions.is_empty());
        }
        AgentctlOutcome::Failure(failure) => panic!("unexpected failure: {failure:?}"),
    }
    assert_eq!(used.model_calls, 1);
}

#[test]
fn reported_resource_exhaustion_rejects_decision_atomically() {
    let body = SUCCESS_SCRIPT.replace("\"model_calls\":1", "\"model_calls\":2");
    let (record, used, _) = run_case(
        "budget",
        ResourceBudget {
            model_calls: 1,
            tool_calls: 1,
            validation_seconds: 3,
        },
        &body,
    );
    match record.outcome {
        AgentctlOutcome::Decision(decision) => {
            assert_eq!(decision.failure.unwrap().code, "OPERATOR_BUDGET_EXCEEDED");
            assert!(decision.signed_actions.is_empty());
        }
        AgentctlOutcome::Failure(failure) => panic!("unexpected failure: {failure:?}"),
    }
    assert_eq!(used.model_calls, 0);
}

#[test]
fn crash_and_timeout_terminate_with_raw_process_evidence() {
    let crash = r#"
dir="$HOME/.agentctl/jobs/crash"
mkdir -p "$dir"
printf 'stdout:\npartial model output\n' > "$dir/output.log"
echo 'agentctl fixture crashed' >&2
exit 17
"#;
    let (crashed, crash_usage, _) = run_case(
        "crash",
        ResourceBudget {
            model_calls: 2,
            tool_calls: 1,
            validation_seconds: 3,
        },
        crash,
    );
    assert_eq!(crashed.exit_code, Some(17));
    assert!(crashed.stderr.bytes.windows(7).any(|w| w == b"crashed"));
    assert!(crashed.raw_log.is_some());
    assert_eq!(crash_usage.model_calls, 1);
    assert!(matches!(
        crashed.outcome,
        AgentctlOutcome::Failure(ref failure) if failure.code == "AGENTCTL_PROCESS_FAILED"
    ));

    let (timed_out, timeout_usage, _) = run_case(
        "timeout",
        ResourceBudget {
            model_calls: 1,
            tool_calls: 0,
            validation_seconds: 1,
        },
        "exec sleep 30",
    );
    assert!(timed_out.timed_out);
    assert!(timed_out.duration_ms < 5_000);
    assert_eq!(timeout_usage.model_calls, 1);
    assert_eq!(timeout_usage.validation_seconds, 1);
    assert!(matches!(
        timed_out.outcome,
        AgentctlOutcome::Failure(ref failure) if failure.code == "AGENTCTL_TIMEOUT"
    ));
}

#[test]
fn deterministic_actor_source_has_no_external_process_boundary() {
    let simulator = include_str!("../../lab/src/simulator/mod.rs");
    for forbidden in [
        "agentctl::",
        "invoke_and_sign(",
        "std::process",
        "Command::new(",
    ] {
        assert!(
            !simulator.contains(forbidden),
            "deterministic simulator contains external boundary {forbidden}"
        );
    }
}

#[test]
fn complete_success_and_failure_provenance_is_content_addressed() {
    let validate = r#"{"schema_version":"operator-decision.v1","decision":"validate","job_id":"job-1","claims":[{"claim_id":"claim-1","verdict":"pass","confidence_basis_points":9000,"evidence_refs":["evidence-1"]}],"resource_report":{"model_calls":1,"tool_calls":1}}"#;
    let body = format!(
        "{}\nprintf 'generated evidence' > generated.txt",
        SUCCESS_SCRIPT.replace(
            r#"{"schema_version":"operator-decision.v1","decision":"wait","resource_report":{"model_calls":1,"tool_calls":0}}"#,
            validate,
        )
    );
    let (_, _, success) = run_case(
        "provenance-success",
        ResourceBudget {
            model_calls: 2,
            tool_calls: 2,
            validation_seconds: 3,
        },
        &body,
    );
    assert!(matches!(success.outcome, OperatorRunOutcome::Completed));
    assert_eq!(success.operator.operator_id, "alpha");
    assert_eq!(success.operator.role, "validation_operator");
    assert_eq!(success.operator.provider, "fixture");
    assert_eq!(success.operator.model, "fixture-model");
    assert_eq!(success.submitted_actions.len(), 1);
    assert!(success.evidence_artifacts[0].selected_by_decision);
    assert_eq!(success.tool_commands.len(), 2);
    assert!(success.logs.raw_agent_log.is_some());
    assert_eq!(success.usage.charged.model_calls, 1);
    assert_eq!(success.usage.charged.tool_calls, 1);
    assert!(success.time.finished_unix_milliseconds >= success.time.started_unix_milliseconds);
    assert!(
        success
            .worktree
            .after
            .untracked
            .iter()
            .any(|entry| entry.path_hex == hash_path_hex(b"generated.txt"))
    );
    for hash in [
        &success.hashes.system_prompt_sha256,
        &success.hashes.observation_sha256,
        &success.hashes.prompt_sha256,
        &success.hashes.raw_output_sha256,
    ] {
        assert_eq!(hash.len(), 64);
    }

    let (_, _, failed) = run_case(
        "provenance-failure",
        ResourceBudget {
            model_calls: 1,
            tool_calls: 1,
            validation_seconds: 3,
        },
        &SUCCESS_SCRIPT.replace(
            r#"{"schema_version":"operator-decision.v1","decision":"wait","resource_report":{"model_calls":1,"tool_calls":0}}"#,
            "not-json",
        ),
    );
    assert!(matches!(failed.outcome, OperatorRunOutcome::Failed { .. }));
    assert!(failed.decision.parsed_decision.is_none());
    assert!(failed.submitted_actions.is_empty());
    assert_eq!(failed.decision.raw_output.bytes, 8);
}

fn hash_path_hex(path: &[u8]) -> String {
    path.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn public_node_rpc_has_no_operator_provenance_or_raw_evidence_surface() {
    let rpc = include_str!("../../chain/src/rpc/mod.rs");
    let chain_manifest = include_str!("../../chain/Cargo.toml");
    for sensitive in ["operator-provenance", "system-prompt.bin", "raw-output.bin"] {
        assert!(!rpc.contains(sensitive));
    }
    assert!(!chain_manifest.contains("rachet-operator"));
}

#[test]
fn exhausted_preflight_budget_never_spawns_agentctl() {
    let (record, used, _) = run_case(
        "preflight-budget",
        ResourceBudget {
            model_calls: 0,
            tool_calls: 4,
            validation_seconds: 2,
        },
        "echo spawned > \"$HOME/spawned\"; exit 99",
    );
    assert!(record.command.is_empty());
    assert_eq!(record.exit_code, None);
    assert_eq!(used.model_calls, 0);
    assert!(matches!(
        record.outcome,
        AgentctlOutcome::Failure(ref failure) if failure.code == "OPERATOR_BUDGET_EXCEEDED"
    ));
}
