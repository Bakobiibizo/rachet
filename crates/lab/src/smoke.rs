//! Fixture-backed section 38 Phase 1 orchestration.
//!
//! This path is deliberately bounded to the public/private smoke partition and
//! declared fixed-heuristic controls. It exercises jobs, decisions, a retained
//! malformed-response failure, hidden authority resolution, artifact capture,
//! model-free replay, and audit. Its metrics remain diagnostic-only.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    str::FromStr as _,
};

use commonware_codec::Write as _;
use commonware_cryptography::{Signer as _, ed25519};
use rachet_core::{
    actions::{Action, ClaimDefinition, CreateJob, ResolutionPolicy, SignedAction, Verdict},
    artifacts::{ContentRef, GitArtifact, GitHash},
    bounded::{BoundedBytes, BoundedVec},
    limits::{
        MAX_CLAIM_STATEMENT_BYTES, MAX_CONTENT_LOCATOR_HINT_BYTES, MAX_MEDIA_TYPE_BYTES,
        MAX_METADATA_BYTES, MAX_REPOSITORY_LOCATOR_BYTES,
    },
    primitives::{ActorId, ClaimId, ProtocolVersion, Sha256Digest},
};
use rachet_mechanisms::m01_naive_reputation::{M01NaiveReputation, NaiveReputation};
use rachet_operator::{
    manifest::{FixedHeuristic, OperatorKind, PopulationManifest},
    policy::{
        ObservedClaim, ObservedJob, PolicyObservation, PolicyResourceBudget, ScriptedDecisionKind,
        ScriptedPolicy, VerdictTally,
    },
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{
    evaluator::{
        ClaimResolutionBinding, ExperimentAuthorityConfig, ExperimentAuthorityEvaluator,
        ExperimentRoles, FixtureResolutionBinding,
    },
    experiment::RunId,
    fixtures::{
        FixtureClass, FixtureSetKind, IntegrityHash, LoadedPublicFixtureSet, PublicFixtureLoader,
        private::PrivateFixtureLoader, schema::GroundTruthVerdict,
    },
    metrics::{
        CounterpartyRecord, JobSelectionRecord, LaboratoryMetricInput, LaboratoryMetricReport,
        ReputationSnapshot, ResourceAccounting, ResourceRecord, UsefulFindingRecord,
        ValidationRecord, ValidationTruth, ValidationVerdict,
    },
    replay::{ReplayCapture, replay_bundle},
    run_artifacts::{RunArtifactBundle, RunArtifactStore},
    simulator::{
        DeterministicRunner, EvaluatorActionBatch, LaboratoryMechanism, ScriptedBlock,
        ScriptedDecisionPoint, ScriptedOperator, ScriptedRun, ScriptedStep,
    },
    workflow::{AuditReport, WorkflowError, audit},
};

const SMOKE_BLOCKS: usize = 3;
const VALIDATION_HEIGHT: u64 = 1;
const RESOLUTION_HEIGHT: u64 = 2;
const MALFORMED_OUTPUT: &[u8] = br#"{"schema_version":"operator-decision.v1","decision":"validate"#;
const MALFORMED_FAILURE_CODE: &str = "OPERATOR_DECISION_MALFORMED_JSON";

/// Complete host-side input for one paired M00/M01 smoke execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmokeOrchestrationConfig {
    pub experiment_root: PathBuf,
    pub public_fixture_root: PathBuf,
    pub private_fixture_root: PathBuf,
    pub repository_root: PathBuf,
    pub operator_manifest: PathBuf,
    pub expected_private_manifest_hash: IntegrityHash,
    pub seed: u64,
}

/// One immutable, exactly replayed mechanism run in the smoke pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SmokeMechanismReport {
    pub run_id: String,
    pub mechanism: &'static str,
    pub fixtures_processed: usize,
    pub jobs_created: usize,
    pub observations_retained: usize,
    pub successful_decisions_retained: usize,
    pub malformed_decisions_retained: usize,
    pub decision_provenance_records: usize,
    pub distinct_operator_identities: usize,
    pub signed_actions_retained: usize,
    pub authority_resolutions: usize,
    pub blocks_executed: usize,
    pub events_retained: usize,
    pub resource_records: usize,
    pub validation_metric_records: usize,
    pub decisions_closed_before_private_access: bool,
    pub replay_model_calls: u64,
    pub replay_exact: bool,
    pub audit: AuditReport,
}

/// Section 38 Phase 1 result. This shape cannot encode a research conclusion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SmokeOrchestrationReport {
    pub phase: &'static str,
    pub fixture_set: &'static str,
    pub fixtures_verified: usize,
    pub claims_verified: usize,
    pub validation_operators: usize,
    pub operator_manifest_sha256: String,
    pub isolation_declarations_verified: bool,
    pub expected_private_manifest_hash: IntegrityHash,
    pub public_private_integrity_verified: bool,
    pub diagnostic_only: bool,
    pub thresholds_used: bool,
    pub calibration_or_formal_fixtures_used: bool,
    pub research_conclusion: Option<String>,
    pub runs: Vec<SmokeMechanismReport>,
}

#[derive(Clone)]
struct DeclaredOperator {
    id: String,
    policy: ScriptedPolicy,
    key_seed: u64,
    validation_seconds: u64,
}

#[derive(Clone)]
struct JobBinding {
    fixture_id: String,
    public_fixture_hash: IntegrityHash,
    job_id: rachet_core::primitives::JobId,
    claim_id: ClaimId,
    fixture_claim_id: String,
    publicly_trivial: bool,
}

#[derive(Clone)]
struct ScheduledDecision {
    fixture_index: usize,
    operator_index: usize,
}

struct FixtureJobs {
    create_actions: Vec<SignedAction<Action>>,
    jobs: Vec<JobBinding>,
    resolution_bindings: Vec<FixtureResolutionBinding>,
}

#[derive(Serialize)]
struct SmokeObservationRecord<'a> {
    schema_version: &'static str,
    mechanism: &'static str,
    height: u64,
    epoch: u64,
    operator_id: &'a str,
    operator_actor: String,
    fixture_id: &'a str,
    public_fixture_sha256: IntegrityHash,
    job_id: String,
    claim_id: String,
    fixture_claim_id: &'a str,
    hidden_truth_present: bool,
    remaining_model_calls: u64,
    remaining_tool_calls: u64,
    remaining_validation_seconds: u64,
    observation_sha256: String,
}

#[derive(Serialize)]
struct SmokeDecisionRecord<'a> {
    schema_version: &'static str,
    mechanism: &'static str,
    height: u64,
    operator_id: &'a str,
    operator_actor: String,
    fixture_id: &'a str,
    status: &'static str,
    policy_id: &'a str,
    raw_output_hex: String,
    raw_output_sha256: String,
    parsed_decision: Option<Value>,
    signed_action_count: usize,
    failure: Option<SmokeFailureRecord<'a>>,
    provenance: SmokeDecisionProvenance<'a>,
}

#[derive(Serialize)]
struct SmokeFailureRecord<'a> {
    code: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct SmokeDecisionProvenance<'a> {
    source: &'static str,
    operator_manifest_sha256: &'a str,
    public_fixture_sha256: IntegrityHash,
    observation_sha256: String,
    raw_output_sha256: String,
    action_count: usize,
}

/// Runs the exact smoke fixtures under M00 and M01 and commits both runs.
pub fn orchestrate_smoke(
    config: &SmokeOrchestrationConfig,
) -> Result<SmokeOrchestrationReport, WorkflowError> {
    let public = PublicFixtureLoader::new(&config.public_fixture_root, &config.repository_root)
        .map_err(fixture_error)?
        .load()
        .map_err(fixture_error)?;
    if public.set() != FixtureSetKind::Smoke {
        return Err(WorkflowError::FixtureSet {
            expected: "smoke",
            actual: fixture_set_name(public.set()),
        });
    }
    let claims_verified = public
        .fixtures()
        .iter()
        .map(|fixture| fixture.definition().claims.len())
        .try_fold(0_usize, |total, count| total.checked_add(count))
        .ok_or_else(|| WorkflowError::InvalidInput("fixture claim count overflow".to_owned()))?;

    let manifest_bytes = read_bounded(&config.operator_manifest, 16 * 1024 * 1024)?;
    let manifest: PopulationManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            WorkflowError::InvalidInput(format!("invalid operator manifest: {error}"))
        })?;
    manifest
        .validate()
        .map_err(|error| WorkflowError::InvalidInput(error.to_string()))?;
    let operators = declared_fixed_operators(&manifest, config.seed)?;
    let manifest_hash = format!("sha256:{}", hash_hex(&manifest_bytes));

    fs::create_dir_all(config.experiment_root.join("runs")).map_err(|error| {
        io_error(
            "create experiment run root",
            &config.experiment_root.join("runs"),
            error,
        )
    })?;
    fs::create_dir_all(config.experiment_root.join("seeds")).map_err(|error| {
        io_error(
            "create experiment seed root",
            &config.experiment_root.join("seeds"),
            error,
        )
    })?;

    let mut runs = Vec::with_capacity(2);
    for (offset, mechanism) in [
        LaboratoryMechanism::M00RecordOnly,
        LaboratoryMechanism::M01NaiveReputation,
    ]
    .into_iter()
    .enumerate()
    {
        let run_seed = config.seed.checked_add(offset as u64).ok_or_else(|| {
            WorkflowError::InvalidInput("paired smoke seed overflowed".to_owned())
        })?;
        runs.push(run_mechanism(
            config,
            &public,
            &operators,
            &manifest_hash,
            mechanism,
            run_seed,
        )?);
    }

    Ok(SmokeOrchestrationReport {
        phase: "smoke",
        fixture_set: "smoke",
        fixtures_verified: public.fixtures().len(),
        claims_verified,
        validation_operators: operators.len(),
        operator_manifest_sha256: manifest_hash,
        isolation_declarations_verified: true,
        expected_private_manifest_hash: config.expected_private_manifest_hash,
        public_private_integrity_verified: true,
        diagnostic_only: true,
        thresholds_used: false,
        calibration_or_formal_fixtures_used: false,
        research_conclusion: None,
        runs,
    })
}

fn run_mechanism(
    config: &SmokeOrchestrationConfig,
    public: &LoadedPublicFixtureSet,
    declared: &[DeclaredOperator],
    manifest_hash: &str,
    mechanism: LaboratoryMechanism,
    seed: u64,
) -> Result<SmokeMechanismReport, WorkflowError> {
    let runner_config = super::workflow::runner_config(seed);
    let authority_key = ed25519::PrivateKey::from_seed(seed ^ 0xa11c_e001);
    let customer_key = ed25519::PrivateKey::from_seed(seed ^ 0xc057_0001);
    let customer = ActorId::from(customer_key.public_key());
    let authority = ActorId::from(authority_key.public_key());

    let mut scripted_operators = Vec::with_capacity(declared.len());
    let mut operator_actors = Vec::with_capacity(declared.len());
    for operator in declared {
        let key = ed25519::PrivateKey::from_seed(operator.key_seed ^ seed);
        operator_actors.push(ActorId::from(key.public_key()));
        scripted_operators.push(ScriptedOperator::new(key, 0, operator.policy));
    }
    let roles = ExperimentRoles::new(customer.clone(), operator_actors.iter().cloned())
        .map_err(|error| WorkflowError::InvalidInput(error.to_string()))?;
    let mut evaluator = ExperimentAuthorityEvaluator::new(
        authority_key,
        ExperimentAuthorityConfig {
            chain_id: runner_config.chain_id,
            initial_nonce: 0,
            private_fixture_root: config.private_fixture_root.clone(),
            expected_private_manifest_hash: config.expected_private_manifest_hash,
            roles,
        },
        public.clone(),
    )
    .map_err(|error| WorkflowError::InvalidInput(error.to_string()))?;

    let fixture_jobs =
        create_fixture_jobs(public, &customer_key, &authority, runner_config.chain_id)?;
    let FixtureJobs {
        create_actions,
        jobs,
        resolution_bindings,
    } = fixture_jobs;
    let mut scheduled = Vec::with_capacity(jobs.len() * declared.len());
    let mut decision_steps = Vec::with_capacity(jobs.len() * declared.len());
    for (fixture_index, job) in jobs.iter().enumerate() {
        for (operator_index, _) in declared.iter().enumerate() {
            let observed_job = ObservedJob::new(
                job.job_id,
                vec![ObservedClaim::new(job.claim_id, VerdictTally::default())],
                job.publicly_trivial,
            )
            .map_err(|error| WorkflowError::InvalidInput(error.to_string()))?;
            let observation = PolicyObservation::new(
                0,
                VALIDATION_HEIGHT,
                PolicyResourceBudget::default(),
                vec![observed_job],
                VerdictTally::default(),
            )
            .map_err(|error| WorkflowError::InvalidInput(error.to_string()))?;
            scheduled.push(ScheduledDecision {
                fixture_index,
                operator_index,
            });
            decision_steps.push(ScriptedStep::DecisionPoint(ScriptedDecisionPoint {
                operator_index,
                observation,
                valid_until_height: RESOLUTION_HEIGHT,
            }));
        }
    }

    // Execute and freeze every public operator decision before closing the
    // boundary that enables any private fixture access.
    let mut public_output = DeterministicRunner::new(runner_config.clone(), mechanism)
        .map_err(|error| WorkflowError::Runner(error.to_string()))?
        .run(ScriptedRun {
            operators: scripted_operators,
            blocks: vec![
                ScriptedBlock::new(vec![ScriptedStep::CanonicalActions(create_actions)]),
                ScriptedBlock::new(decision_steps),
            ],
        })
        .map_err(|error| WorkflowError::Runner(error.to_string()))?;
    if public_output.blocks.len() != 2 || public_output.decisions.len() != scheduled.len() {
        return Err(WorkflowError::Audit(
            "smoke execution did not retain its complete bounded public schedule".to_owned(),
        ));
    }
    let decisions = std::mem::take(&mut public_output.decisions);
    let mut action_blocks = public_output
        .blocks
        .iter()
        .map(|block| block.block.actions.iter().cloned().collect::<Vec<_>>())
        .collect::<Vec<_>>();

    evaluator
        .close_operator_decisions()
        .map_err(|error| WorkflowError::InvalidInput(error.to_string()))?;
    let mut evaluator_actions = EvaluatorActionBatch::default();
    let resolutions = evaluator
        .submit_claim_resolutions(
            &resolution_bindings,
            RESOLUTION_HEIGHT,
            &mut evaluator_actions,
        )
        .map_err(|error| WorkflowError::Fixture(error.to_string()))?;
    if evaluator_actions
        .actions()
        .iter()
        .any(|action| action.actor != *evaluator.authority())
    {
        return Err(WorkflowError::Audit(
            "hidden evaluator emitted a non-authority action".to_owned(),
        ));
    }
    action_blocks.push(evaluator_actions.actions().to_vec());
    let execution = DeterministicRunner::new(runner_config.clone(), mechanism)
        .map_err(|error| WorkflowError::Runner(error.to_string()))?
        .replay_actions(action_blocks)
        .map_err(|error| WorkflowError::Runner(error.to_string()))?;
    if let Some(error) = execution.terminal_error {
        return Err(WorkflowError::Runner(format!(
            "fixture-backed trace failed ({}): {}",
            error.code, error.message
        )));
    }
    let output = execution.output;
    if output.blocks.len() != SMOKE_BLOCKS {
        return Err(WorkflowError::Audit(
            "smoke trace did not execute all three bounded blocks".to_owned(),
        ));
    }

    // This second private load occurs only after the same irreversible close and
    // is used solely to derive diagnostic records from retained decisions.
    let private = PrivateFixtureLoader::new(&config.private_fixture_root)
        .map_err(fixture_error)?
        .load_for(public, config.expected_private_manifest_hash)
        .map_err(fixture_error)?;

    let mechanism_label = mechanism_name(mechanism);
    let mut observations_jsonl = Vec::new();
    let mut decisions_jsonl = Vec::new();
    let mut resources = Vec::with_capacity(decisions.len() + 1);
    let mut metric_input = LaboratoryMetricInput::default();
    let mut useful_by_operator = BTreeMap::<String, u64>::new();

    for (record, schedule) in decisions.iter().zip(&scheduled) {
        let fixture = &jobs[schedule.fixture_index];
        let operator = &declared[schedule.operator_index];
        let actor = &operator_actors[schedule.operator_index];
        if record.operator != *actor || record.policy_id != operator.policy.metadata().id() {
            return Err(WorkflowError::Audit(
                "retained decision provenance does not match the declared schedule".to_owned(),
            ));
        }
        let observation_hash = smoke_observation_hash(mechanism_label, operator, actor, fixture);
        append_jsonl(
            &mut observations_jsonl,
            &SmokeObservationRecord {
                schema_version: "hrep-smoke-observation.v1",
                mechanism: mechanism_label,
                height: VALIDATION_HEIGHT,
                epoch: 0,
                operator_id: &operator.id,
                operator_actor: actor_hex(actor),
                fixture_id: &fixture.fixture_id,
                public_fixture_sha256: fixture.public_fixture_hash,
                job_id: hex(fixture.job_id.as_bytes()),
                claim_id: hex(fixture.claim_id.as_bytes()),
                fixture_claim_id: &fixture.fixture_claim_id,
                hidden_truth_present: false,
                remaining_model_calls: 0,
                remaining_tool_calls: 0,
                remaining_validation_seconds: operator.validation_seconds,
                observation_sha256: observation_hash.clone(),
            },
        )?;

        let parsed = decision_json(&record.decision, fixture);
        let raw = serde_json::to_vec(&parsed).map_err(json_error)?;
        let raw_hash = hash_hex(&raw);
        let action_count = decision_action_count(&record.decision, fixture);
        append_jsonl(
            &mut decisions_jsonl,
            &SmokeDecisionRecord {
                schema_version: "hrep-smoke-decision.v1",
                mechanism: mechanism_label,
                height: VALIDATION_HEIGHT,
                operator_id: &operator.id,
                operator_actor: actor_hex(actor),
                fixture_id: &fixture.fixture_id,
                status: "completed",
                policy_id: record.policy_id,
                raw_output_hex: hex(&raw),
                raw_output_sha256: raw_hash.clone(),
                parsed_decision: Some(parsed),
                signed_action_count: action_count,
                failure: None,
                provenance: SmokeDecisionProvenance {
                    source: "declared-fixed-heuristic-population",
                    operator_manifest_sha256: manifest_hash,
                    public_fixture_sha256: fixture.public_fixture_hash,
                    observation_sha256: observation_hash,
                    raw_output_sha256: raw_hash,
                    action_count,
                },
            },
        )?;

        let (selected, claims_evaluated) = selection_and_claim_count(&record.decision, fixture);
        resources.push(ResourceRecord {
            operator: operator.id.clone(),
            epoch: 0,
            model_calls: 0,
            input_tokens: Some(0),
            output_tokens: Some(0),
            tool_calls: 0,
            command_duration_ms: 0,
            cpu_time_ms: Some(0),
            validation_wall_clock_allowance_ms: operator
                .validation_seconds
                .checked_mul(1_000)
                .ok_or_else(|| WorkflowError::Audit("resource allowance overflow".to_owned()))?,
            git_objects_read: 0,
            files_inspected: 0,
            tests_executed: 0,
            jobs_inspected: 1,
            jobs_accepted: u64::from(selected),
            claims_evaluated,
            evidence_bytes: 0,
            compute_units: Some(0),
        });
        metric_input.job_selections.push(JobSelectionRecord {
            epoch: 0,
            operator: operator.id.clone(),
            available_jobs: vec![fixture.fixture_id.clone()],
            selected_job: selected.then(|| fixture.fixture_id.clone()),
        });
        append_validation_metrics(
            &mut metric_input,
            &mut useful_by_operator,
            &record.decision,
            operator,
            fixture,
            private.fixtures[schedule.fixture_index].claims[0].verdict,
        );
    }

    append_malformed_probe(
        mechanism_label,
        manifest_hash,
        &jobs[0],
        &declared[0],
        &operator_actors[0],
        &mut observations_jsonl,
        &mut decisions_jsonl,
        &mut resources,
        &mut metric_input,
    )?;

    for (operator, actor) in declared.iter().zip(&operator_actors) {
        let reputation = match mechanism {
            LaboratoryMechanism::M00RecordOnly => 0,
            LaboratoryMechanism::M01NaiveReputation => output
                .final_state
                .iter()
                .find(|(key, _)| *key == M01NaiveReputation::reputation_state_key(actor))
                .map(|(_, value)| NaiveReputation::decode(value).map(|value| value.score))
                .transpose()
                .map_err(|error| WorkflowError::Audit(error.to_string()))?
                .unwrap_or(0),
        };
        metric_input.reputation.push(ReputationSnapshot {
            epoch: 0,
            operator: operator.id.clone(),
            reputation,
        });
        metric_input.useful_findings.push(UsefulFindingRecord {
            epoch: 0,
            operator: operator.id.clone(),
            findings: useful_by_operator.get(&operator.id).copied().unwrap_or(0),
        });
        metric_input.counterparties.push(CounterpartyRecord {
            source: operator.id.clone(),
            target: actor_hex(&customer),
            interactions: jobs.len() as u64,
            jobs: jobs.len() as u64,
            claims: jobs.len() as u64,
            evidence_bytes: 0,
        });
    }

    let accounting = ResourceAccounting::from_records(resources)
        .map_err(|error| WorkflowError::Audit(error.to_string()))?;
    let metrics = LaboratoryMetricReport::derive(&metric_input, &accounting)
        .map_err(|error| WorkflowError::Audit(error.to_string()))?;
    let capture = ReplayCapture::from_completed_run(&runner_config, mechanism, &[], &output)
        .map_err(|error| WorkflowError::Replay(error.to_string()))?;
    let mut bundle = RunArtifactBundle {
        initial_state: Vec::new(),
        observations_jsonl,
        decisions_jsonl,
        signed_actions: Vec::new(),
        blocks: Vec::new(),
        events: Vec::new(),
        economic_state_jsonl: Vec::new(),
        resources_json: accounting.to_json_bytes().map_err(json_error)?,
        metrics_json: metrics.to_json_bytes().map_err(json_error)?,
        discovered_strategies_markdown:
            b"# Discovered strategies\n\nSmoke failure-path exercise only; no strategy or research conclusion recorded.\n"
                .to_vec(),
    };
    let outcome = capture.apply_to(&mut bundle);
    let replay = replay_bundle(&bundle, &outcome)
        .map_err(|error| WorkflowError::Replay(error.to_string()))?;
    let run_id = smoke_run_id(public, manifest_hash, mechanism, seed)?;
    let run_root = config.experiment_root.join("runs").join(run_id.to_string());
    fs::create_dir(&run_root)
        .map_err(|error| io_error("create immutable smoke run directory", &run_root, error))?;
    RunArtifactStore::capture(&config.experiment_root, run_id, outcome, &bundle)
        .map_err(|error| WorkflowError::Artifact(error.to_string()))?;
    let audit_report = audit(&super::workflow::RunReference {
        experiment_root: config.experiment_root.clone(),
        run_id,
    })?;

    Ok(SmokeMechanismReport {
        run_id: run_id.to_string(),
        mechanism: mechanism_label,
        fixtures_processed: jobs.len(),
        jobs_created: jobs.len(),
        observations_retained: decisions.len() + 1,
        successful_decisions_retained: decisions.len(),
        malformed_decisions_retained: 1,
        decision_provenance_records: decisions.len() + 1,
        distinct_operator_identities: operator_actors
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        signed_actions_retained: output
            .blocks
            .iter()
            .map(|block| block.block.actions.len())
            .sum(),
        authority_resolutions: resolutions.action_ids.len(),
        blocks_executed: output.blocks.len(),
        events_retained: output.blocks.iter().map(|block| block.events.len()).sum(),
        resource_records: accounting.records.len(),
        validation_metric_records: metric_input.validations.len(),
        decisions_closed_before_private_access: evaluator.operator_decisions_are_closed(),
        replay_model_calls: replay.model_calls,
        replay_exact: true,
        audit: audit_report,
    })
}

fn create_fixture_jobs(
    public: &LoadedPublicFixtureSet,
    customer_key: &ed25519::PrivateKey,
    authority: &ActorId,
    chain_id: rachet_core::primitives::ChainId,
) -> Result<FixtureJobs, WorkflowError> {
    let mut actions = Vec::with_capacity(public.fixtures().len());
    let mut jobs = Vec::with_capacity(public.fixtures().len());
    let mut resolutions = Vec::with_capacity(public.fixtures().len());
    for (index, loaded) in public.fixtures().iter().enumerate() {
        let fixture = loaded.definition();
        if fixture.claims.len() != 1 {
            return Err(WorkflowError::InvalidInput(format!(
                "smoke fixture {} must contain exactly one claim",
                fixture.fixture_id
            )));
        }
        let definition = ClaimDefinition::new(bounded::<MAX_CLAIM_STATEMENT_BYTES>(
            fixture.claims[0].statement.as_bytes(),
            "fixture claim statement",
        )?);
        let create = CreateJob {
            artifact: GitArtifact::new(
                bounded::<MAX_REPOSITORY_LOCATOR_BYTES>(
                    format!("fixture://{}", fixture.fixture_id).as_bytes(),
                    "fixture repository locator",
                )?,
                git_hash(&fixture.repository.base_commit)?,
                git_hash(&fixture.repository.candidate_commit)?,
                ContentRef::new(
                    Sha256Digest::from(*fixture.specification.sha256.as_bytes()),
                    bounded::<MAX_CONTENT_LOCATOR_HINT_BYTES>(
                        format!("fixture://{}/specification", fixture.fixture_id).as_bytes(),
                        "fixture specification locator",
                    )?,
                    bounded::<MAX_MEDIA_TYPE_BYTES>(
                        fixture.specification.media_type.as_bytes(),
                        "fixture specification media type",
                    )?,
                ),
            ),
            claims: BoundedVec::new(vec![definition.clone()])
                .map_err(|_| WorkflowError::InvalidInput("too many fixture claims".to_owned()))?,
            resolution_policy: ResolutionPolicy::ExperimentAuthority {
                authority: authority.clone(),
            },
            validation_opens_at: VALIDATION_HEIGHT,
            validation_closes_at: VALIDATION_HEIGHT,
            reveal_closes_at: None,
            challenge_closes_at: Some(RESOLUTION_HEIGHT),
            supersedes: None,
            metadata: bounded::<MAX_METADATA_BYTES>(
                format!("fixture/{}", fixture.fixture_id).as_bytes(),
                "fixture metadata",
            )?,
        };
        let job_id = create.job_id();
        let mut claim_identity = Vec::new();
        job_id.write(&mut claim_identity);
        definition.write(&mut claim_identity);
        let claim_id = ClaimId::derive(&claim_identity);
        let nonce = u64::try_from(index)
            .map_err(|_| WorkflowError::InvalidInput("fixture nonce overflow".to_owned()))?;
        actions.push(
            SignedAction::sign(
                customer_key,
                ProtocolVersion::V1,
                chain_id,
                nonce,
                RESOLUTION_HEIGHT,
                Action::CreateJob(Box::new(create)),
            )
            .map_err(|error| WorkflowError::InvalidInput(error.to_string()))?,
        );
        let resolution_reference = ContentRef::new(
            Sha256Digest::from(*loaded.fixture_hash().as_bytes()),
            bounded::<MAX_CONTENT_LOCATOR_HINT_BYTES>(
                format!("hidden-resolution://{}", fixture.fixture_id).as_bytes(),
                "resolution locator",
            )?,
            bounded::<MAX_MEDIA_TYPE_BYTES>(b"application/json", "resolution media type")?,
        );
        jobs.push(JobBinding {
            fixture_id: fixture.fixture_id.clone(),
            public_fixture_hash: loaded.fixture_hash(),
            job_id,
            claim_id,
            fixture_claim_id: fixture.claims[0].claim_id.clone(),
            publicly_trivial: matches!(
                fixture.class,
                FixtureClass::CleanChange | FixtureClass::ObviousRegression
            ),
        });
        resolutions.push(FixtureResolutionBinding {
            fixture_id: fixture.fixture_id.clone(),
            job_id,
            claims: vec![ClaimResolutionBinding {
                fixture_claim_id: fixture.claims[0].claim_id.clone(),
                claim_id,
                evidence_ids: BoundedVec::default(),
                resolution_reference,
            }],
        });
    }
    Ok(FixtureJobs {
        create_actions: actions,
        jobs,
        resolution_bindings: resolutions,
    })
}

#[allow(clippy::too_many_arguments)]
fn append_malformed_probe(
    mechanism: &'static str,
    manifest_hash: &str,
    fixture: &JobBinding,
    operator: &DeclaredOperator,
    actor: &ActorId,
    observations: &mut Vec<u8>,
    decisions: &mut Vec<u8>,
    resources: &mut Vec<ResourceRecord>,
    metrics: &mut LaboratoryMetricInput,
) -> Result<(), WorkflowError> {
    let observation_hash = smoke_observation_hash(mechanism, operator, actor, fixture);
    append_jsonl(
        observations,
        &SmokeObservationRecord {
            schema_version: "hrep-smoke-observation.v1",
            mechanism,
            height: VALIDATION_HEIGHT,
            epoch: 0,
            operator_id: &operator.id,
            operator_actor: actor_hex(actor),
            fixture_id: &fixture.fixture_id,
            public_fixture_sha256: fixture.public_fixture_hash,
            job_id: hex(fixture.job_id.as_bytes()),
            claim_id: hex(fixture.claim_id.as_bytes()),
            fixture_claim_id: &fixture.fixture_claim_id,
            hidden_truth_present: false,
            remaining_model_calls: 0,
            remaining_tool_calls: 0,
            remaining_validation_seconds: operator.validation_seconds,
            observation_sha256: observation_hash.clone(),
        },
    )?;
    let raw_hash = hash_hex(MALFORMED_OUTPUT);
    append_jsonl(
        decisions,
        &SmokeDecisionRecord {
            schema_version: "hrep-smoke-decision.v1",
            mechanism,
            height: VALIDATION_HEIGHT,
            operator_id: &operator.id,
            operator_actor: actor_hex(actor),
            fixture_id: &fixture.fixture_id,
            status: "failed",
            policy_id: "malformed-response-probe",
            raw_output_hex: hex(MALFORMED_OUTPUT),
            raw_output_sha256: raw_hash.clone(),
            parsed_decision: None,
            signed_action_count: 0,
            failure: Some(SmokeFailureRecord {
                code: MALFORMED_FAILURE_CODE,
                message: "fixture response ended before a complete strict JSON object",
            }),
            provenance: SmokeDecisionProvenance {
                source: "section-38-failure-path-probe",
                operator_manifest_sha256: manifest_hash,
                public_fixture_sha256: fixture.public_fixture_hash,
                observation_sha256: observation_hash,
                raw_output_sha256: raw_hash,
                action_count: 0,
            },
        },
    )?;
    resources.push(ResourceRecord {
        operator: operator.id.clone(),
        epoch: 0,
        model_calls: 0,
        input_tokens: Some(0),
        output_tokens: Some(0),
        tool_calls: 0,
        command_duration_ms: 0,
        cpu_time_ms: Some(0),
        validation_wall_clock_allowance_ms: operator.validation_seconds * 1_000,
        git_objects_read: 0,
        files_inspected: 0,
        tests_executed: 0,
        jobs_inspected: 1,
        jobs_accepted: 0,
        claims_evaluated: 0,
        evidence_bytes: 0,
        compute_units: Some(0),
    });
    metrics.job_selections.push(JobSelectionRecord {
        epoch: 0,
        operator: operator.id.clone(),
        available_jobs: vec![fixture.fixture_id.clone()],
        selected_job: None,
    });
    Ok(())
}

fn append_validation_metrics(
    metrics: &mut LaboratoryMetricInput,
    useful: &mut BTreeMap<String, u64>,
    decision: &rachet_operator::policy::ScriptedDecision,
    operator: &DeclaredOperator,
    fixture: &JobBinding,
    truth: GroundTruthVerdict,
) {
    let truth_metric = match truth {
        GroundTruthVerdict::Valid => ValidationTruth::Pass,
        GroundTruthVerdict::Invalid => ValidationTruth::Fail,
        GroundTruthVerdict::Ambiguous => ValidationTruth::Unresolved,
    };
    let verdict = match &decision.kind {
        ScriptedDecisionKind::Validate { claims, .. } => Some(claims[0].verdict),
        ScriptedDecisionKind::Abstain { .. } => Some(Verdict::Abstain),
        ScriptedDecisionKind::Wait => None,
    };
    let Some(verdict) = verdict else { return };
    let verdict_metric = match verdict {
        Verdict::Pass => ValidationVerdict::Pass,
        Verdict::Fail => ValidationVerdict::Fail,
        Verdict::Abstain => ValidationVerdict::Abstain,
        Verdict::Indeterminate => ValidationVerdict::Indeterminate,
    };
    metrics.validations.push(ValidationRecord {
        epoch: 0,
        operator: operator.id.clone(),
        job: fixture.fixture_id.clone(),
        claim: fixture.fixture_claim_id.clone(),
        verdict: verdict_metric,
        truth: truth_metric,
    });
    let correct = matches!(
        (verdict_metric, truth_metric),
        (ValidationVerdict::Pass, ValidationTruth::Pass)
            | (ValidationVerdict::Fail, ValidationTruth::Fail)
    );
    if correct {
        *useful.entry(operator.id.clone()).or_default() += 1;
    }
}

fn decision_json(
    decision: &rachet_operator::policy::ScriptedDecision,
    fixture: &JobBinding,
) -> Value {
    match &decision.kind {
        ScriptedDecisionKind::Validate { claims, .. } => json!({
            "schema_version": "operator-decision.v1",
            "decision": "validate",
            "job_id": fixture.fixture_id,
            "claims": [{
                "claim_id": fixture.fixture_claim_id,
                "verdict": verdict_name(claims[0].verdict),
                "confidence_basis_points": claims[0].confidence_basis_points,
                "evidence_refs": []
            }],
            "resource_report": {"model_calls": 0, "tool_calls": 0}
        }),
        ScriptedDecisionKind::Abstain { .. } => json!({
            "schema_version": "operator-decision.v1",
            "decision": "abstain",
            "job_id": fixture.fixture_id,
            "resource_report": {"model_calls": 0, "tool_calls": 0}
        }),
        ScriptedDecisionKind::Wait => json!({
            "schema_version": "operator-decision.v1",
            "decision": "wait",
            "resource_report": {"model_calls": 0, "tool_calls": 0}
        }),
    }
}

fn selection_and_claim_count(
    decision: &rachet_operator::policy::ScriptedDecision,
    _fixture: &JobBinding,
) -> (bool, u64) {
    match &decision.kind {
        ScriptedDecisionKind::Validate { claims, .. } => (true, claims.len() as u64),
        ScriptedDecisionKind::Abstain { .. } => (true, 1),
        ScriptedDecisionKind::Wait => (false, 0),
    }
}

fn decision_action_count(
    decision: &rachet_operator::policy::ScriptedDecision,
    fixture: &JobBinding,
) -> usize {
    selection_and_claim_count(decision, fixture).1 as usize
}

fn declared_fixed_operators(
    manifest: &PopulationManifest,
    seed: u64,
) -> Result<Vec<DeclaredOperator>, WorkflowError> {
    manifest
        .operators
        .iter()
        .enumerate()
        .map(|(index, operator)| {
            let OperatorKind::FixedHeuristic { heuristic } = operator.operator_kind else {
                return Err(WorkflowError::InvalidInput(format!(
                    "smoke scripted population contains non-fixed operator {}",
                    operator.operator_id
                )));
            };
            let index = u64::try_from(index)
                .map_err(|_| WorkflowError::InvalidInput("operator index overflow".to_owned()))?;
            Ok(DeclaredOperator {
                id: operator.operator_id.clone(),
                policy: policy(heuristic, seed ^ index),
                key_seed: 0x0f00_0000 ^ index,
                validation_seconds: operator.resource_budget.validation_seconds,
            })
        })
        .collect()
}

const fn policy(heuristic: FixedHeuristic, seed: u64) -> ScriptedPolicy {
    match heuristic {
        FixedHeuristic::AlwaysPass => ScriptedPolicy::AlwaysPass,
        FixedHeuristic::AlwaysFail => ScriptedPolicy::AlwaysFail,
        FixedHeuristic::RandomVerdict => ScriptedPolicy::RandomVerdict { seed },
        FixedHeuristic::ValidateOnlyTrivialJobs => ScriptedPolicy::TrivialJobsOnly,
        FixedHeuristic::ConsensusFollower => ScriptedPolicy::ConsensusFollower,
        FixedHeuristic::MaximumVolumeOperator => ScriptedPolicy::MaximumVolume,
        FixedHeuristic::PerfectAbstainer => ScriptedPolicy::PerfectAbstainer,
        FixedHeuristic::HistoricalMajorityFollower => ScriptedPolicy::HistoricalMajorityFollower,
    }
}

fn smoke_observation_hash(
    mechanism: &str,
    operator: &DeclaredOperator,
    actor: &ActorId,
    fixture: &JobBinding,
) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"rachet/hrep-smoke-observation/v1\0");
    bytes.extend_from_slice(mechanism.as_bytes());
    bytes.extend_from_slice(operator.id.as_bytes());
    bytes.extend_from_slice(actor.as_bytes());
    bytes.extend_from_slice(fixture.public_fixture_hash.as_bytes());
    bytes.extend_from_slice(fixture.job_id.as_bytes());
    bytes.extend_from_slice(fixture.claim_id.as_bytes());
    hash_hex(&bytes)
}

fn smoke_run_id(
    public: &LoadedPublicFixtureSet,
    manifest_hash: &str,
    mechanism: LaboratoryMechanism,
    seed: u64,
) -> Result<RunId, WorkflowError> {
    let mut hash = Sha256::new();
    hash.update(b"rachet/hrep-smoke-run/v1\0");
    hash.update(public.manifest_hash().as_bytes());
    hash.update(manifest_hash.as_bytes());
    hash.update(mechanism_name(mechanism).as_bytes());
    hash.update(seed.to_be_bytes());
    RunId::from_str(&hex(hash.finalize().as_slice()))
        .map_err(|error| WorkflowError::InvalidInput(error.to_string()))
}

fn git_hash(value: &str) -> Result<GitHash, WorkflowError> {
    let bytes = decode_hex(value)?;
    GitHash::try_from(bytes).map_err(|error| WorkflowError::InvalidInput(error.to_string()))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, WorkflowError> {
    if !value.len().is_multiple_of(2) {
        return Err(WorkflowError::InvalidInput(
            "Git hash has odd-length hexadecimal text".to_owned(),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|error| {
                WorkflowError::InvalidInput(format!("invalid Git hash text: {error}"))
            })?;
            u8::from_str_radix(text, 16).map_err(|error| {
                WorkflowError::InvalidInput(format!("invalid Git hash text: {error}"))
            })
        })
        .collect()
}

fn bounded<const MAX: usize>(
    bytes: &[u8],
    field: &str,
) -> Result<BoundedBytes<MAX>, WorkflowError> {
    BoundedBytes::try_from(bytes).map_err(|error| {
        WorkflowError::InvalidInput(format!(
            "{field} has {} bytes; maximum is {}",
            error.actual(),
            error.maximum()
        ))
    })
}

fn append_jsonl<T: Serialize>(output: &mut Vec<u8>, value: &T) -> Result<(), WorkflowError> {
    serde_json::to_writer(&mut *output, value).map_err(json_error)?;
    output.push(b'\n');
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, WorkflowError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect bounded file", path, error))?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(WorkflowError::InvalidInput(format!(
            "{} must be a regular file of at most {maximum} bytes",
            path.display()
        )));
    }
    fs::read(path).map_err(|error| io_error("read bounded file", path, error))
}

fn fixture_error(error: crate::fixtures::FixtureError) -> WorkflowError {
    WorkflowError::Fixture(error.to_string())
}

fn json_error(error: serde_json::Error) -> WorkflowError {
    WorkflowError::Json(error.to_string())
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> WorkflowError {
    WorkflowError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn actor_hex(actor: &ActorId) -> String {
    hex(actor.as_bytes())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_hex(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_slice())
}

const fn mechanism_name(mechanism: LaboratoryMechanism) -> &'static str {
    match mechanism {
        LaboratoryMechanism::M00RecordOnly => "m00_record_only",
        LaboratoryMechanism::M01NaiveReputation => "m01_naive_reputation",
    }
}

const fn fixture_set_name(set: FixtureSetKind) -> &'static str {
    match set {
        FixtureSetKind::Smoke => "smoke",
        FixtureSetKind::Calibration => "calibration",
        FixtureSetKind::Formal => "formal",
    }
}

const fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Pass => "pass",
        Verdict::Fail => "fail",
        Verdict::Abstain => "abstain",
        Verdict::Indeterminate => "indeterminate",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use rachet_core::actions::Action;

    use super::*;
    use crate::{replay::decode_checkpoint, run_artifacts::RunArtifactStore};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn fixture_backed_pair_retains_failure_resolutions_metrics_and_exact_replay() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let root = std::env::temp_dir().join(format!(
            "rachet-hrep-smoke-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let public = workspace.join("fixtures/jobs-public/smoke");
        let expected_private_manifest_hash =
            fs::read_to_string(public.join("private-manifest.sha256"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
        let report = orchestrate_smoke(&SmokeOrchestrationConfig {
            experiment_root: root.clone(),
            public_fixture_root: public,
            private_fixture_root: workspace.join("fixtures/ground-truth-private/smoke"),
            repository_root: workspace.join("fixtures/repositories"),
            operator_manifest: workspace
                .join("experiments/H-REP-001/operators/fixed-heuristics.json"),
            expected_private_manifest_hash,
            seed: 81_003,
        })
        .unwrap();

        assert_eq!(report.fixtures_verified, 9);
        assert_eq!(report.claims_verified, 9);
        assert_eq!(report.validation_operators, 8);
        assert!(report.operator_manifest_sha256.starts_with("sha256:"));
        assert!(report.isolation_declarations_verified);
        assert!(report.public_private_integrity_verified);
        assert!(report.diagnostic_only);
        assert!(!report.thresholds_used);
        assert!(!report.calibration_or_formal_fixtures_used);
        assert!(report.research_conclusion.is_none());
        assert_eq!(report.runs.len(), 2);

        for run in &report.runs {
            assert_eq!(run.fixtures_processed, 9);
            assert_eq!(run.jobs_created, 9);
            assert_eq!(run.observations_retained, 73);
            assert_eq!(run.successful_decisions_retained, 72);
            assert_eq!(run.malformed_decisions_retained, 1);
            assert_eq!(run.decision_provenance_records, 73);
            assert_eq!(run.distinct_operator_identities, 8);
            assert_eq!(run.authority_resolutions, 9);
            assert_eq!(run.blocks_executed, 3);
            assert!(run.events_retained > 0);
            assert_eq!(run.resource_records, 73);
            assert!(run.validation_metric_records > 0);
            assert!(run.decisions_closed_before_private_access);
            assert!(run.replay_exact);
            assert_eq!(run.replay_model_calls, 0);
            assert!(run.audit.resources_reconciled);
            assert!(run.audit.metrics_diagnostic_only);

            let run_id: RunId = run.run_id.parse().unwrap();
            let loaded = RunArtifactStore::load(&root, run_id).unwrap();
            assert!(!loaded.bundle.observations_jsonl.is_empty());
            assert!(!loaded.bundle.decisions_jsonl.is_empty());
            assert!(!loaded.bundle.signed_actions.is_empty());
            assert!(!loaded.bundle.blocks.is_empty());
            assert!(!loaded.bundle.events.is_empty());
            assert!(!loaded.bundle.economic_state_jsonl.is_empty());
            let observations = String::from_utf8(loaded.bundle.observations_jsonl.clone()).unwrap();
            assert!(!observations.contains("ground_truth"));
            assert!(!observations.contains("seeded_defect"));
            let decisions = String::from_utf8(loaded.bundle.decisions_jsonl.clone()).unwrap();
            assert!(decisions.contains(MALFORMED_FAILURE_CODE));
            assert!(decisions.contains("\"status\":\"completed\""));
            assert!(decisions.contains("\"status\":\"failed\""));

            let resources: ResourceAccounting =
                serde_json::from_slice(&loaded.bundle.resources_json).unwrap();
            resources.verify().unwrap();
            assert_eq!(resources.records.len(), 73);
            assert!(resources.totals.jobs_inspected > 0);
            let metrics: LaboratoryMetricReport =
                serde_json::from_slice(&loaded.bundle.metrics_json).unwrap();
            assert!(metrics.diagnostic_only);
            assert!(metrics.validation.overall.evaluated > 0);
            assert!(metrics.job_selection.decisions > 0);
            assert!(!metrics.reputation.by_epoch.is_empty());
            assert!(!metrics.counterparty_graph.edges.is_empty());

            let trace =
                decode_checkpoint(&loaded.bundle.initial_state, &loaded.bundle.signed_actions)
                    .unwrap();
            assert_eq!(trace.actions.len(), 3);
            assert_eq!(
                trace.actions[2]
                    .iter()
                    .filter(|action| matches!(action.payload, Action::ResolveClaim(_)))
                    .count(),
                9
            );
            let resolution_actors = trace.actions[2]
                .iter()
                .map(|action| action.actor.clone())
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(resolution_actors.len(), 1);
        }

        fs::remove_dir_all(root).unwrap();
    }
}
