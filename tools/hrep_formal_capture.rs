use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    str::FromStr as _,
};

use commonware_codec::{Read as _, Write as _};
use commonware_cryptography::{Signer as _, ed25519};
use rachet_core::{
    actions::{
        Action, ClaimDefinition, CreateJob, ResolutionPolicy, ResolutionVerdict, ResolveClaim,
        SignedAction, SubmitAttestation, Verdict,
    },
    artifacts::{ContentRef, GitArtifact, GitHash},
    bounded::{BoundedBytes, BoundedVec},
    limits::{
        MAX_CLAIM_STATEMENT_BYTES, MAX_CONTENT_LOCATOR_HINT_BYTES, MAX_MEDIA_TYPE_BYTES,
        MAX_METADATA_BYTES, MAX_REPOSITORY_LOCATOR_BYTES,
    },
    primitives::{ActorId, ChainId, ClaimId, ProtocolVersion, Sha256Digest},
};
use rachet_lab::{
    experiment::RunId,
    fixtures::{IntegrityHash, PublicFixtureLoader},
    metrics::{ResourceAccounting, ResourceRecord},
    replay::{ReplayCapture, replay_bundle},
    run_artifacts::{RunArtifactBundle, RunArtifactStore},
    simulator::{DeterministicRunner, LaboratoryMechanism, RunnerConfig},
};
use rachet_mechanisms::m01_naive_reputation::{M01NaiveReputation, NaiveReputation};
use rachet_operator::policy::{
    ObservedClaim, ObservedJob, PolicyObservation, PolicyResourceBudget, ScriptedDecisionKind,
    ScriptedPolicy, VerdictTally,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const TRAINING: [&str; 5] = [
    "formal-authorization-defect",
    "formal-clean-change",
    "formal-genuinely-ambiguous-claim",
    "formal-malformed-error-handling",
    "formal-obvious-regression",
];
const EVALUATION: [&str; 4] = [
    "formal-misleading-but-valid-change",
    "formal-specification-violation",
    "formal-subtle-regression",
    "formal-test-only-failure",
];
const INTELLIGENT: [&str; 3] = ["productive", "self-interested", "explicitly-adversarial"];
const FIXED: [&str; 8] = [
    "always-pass",
    "always-fail",
    "random-verdict",
    "easy-job-only",
    "majority-following",
    "maximum-volume",
    "perfect-abstainer",
    "historical-majority",
];

#[derive(Deserialize)]
struct Input {
    run_id: String,
    seed: Seed,
    condition: String,
    mechanism: String,
    preregistration_lock_sha256: String,
    public_manifest_sha256: String,
    private_manifest_sha256: String,
    intelligent_decisions: Vec<IntelligentDecision>,
    intelligent_resources: Vec<IntelligentResource>,
    truth: BTreeMap<String, String>,
    training_decisions_closed_before_private_access: bool,
    evaluation_decisions_closed_before_private_access: bool,
    operator_failures_retained: u64,
    infrastructure_exclusion: Option<Value>,
}

#[derive(Deserialize)]
struct Seed {
    index: u64,
    seed_u64_be: u64,
    digest_sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct IntelligentDecision {
    population: String,
    condition: String,
    phase: String,
    fixture_id: String,
    decision: String,
    selected: bool,
    confidence_basis_points: u16,
    commands_executed: u64,
    files_inspected: u64,
    tests_executed: u64,
    git_objects_read: u64,
    evidence_bytes: u64,
    rationale: String,
    status: String,
    failure: Option<Value>,
    raw_output_sha256: String,
    truth: String,
    correct: Option<bool>,
    hidden_truth_loaded_after_phase_decision_close: bool,
}

#[derive(Deserialize)]
struct IntelligentResource {
    operator: String,
    phase: String,
    model_calls: u64,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    tool_calls: u64,
    command_duration_ms: u64,
    cpu_time_ms: u64,
    validation_wall_clock_allowance_ms: u64,
    git_objects_read: u64,
    files_inspected: u64,
    tests_executed: u64,
    jobs_inspected: u64,
    jobs_accepted: u64,
    claims_evaluated: u64,
    evidence_bytes: u64,
}

#[derive(Clone)]
struct Job {
    fixture_id: String,
    class_name: String,
    fixture_hash: IntegrityHash,
    job_id: rachet_core::primitives::JobId,
    claim_id: ClaimId,
    fixture_claim_id: String,
    create: SignedAction<Action>,
}

#[derive(Clone, Serialize)]
struct DecisionRow {
    schema_version: &'static str,
    condition: String,
    phase: String,
    height: u64,
    population: String,
    operator_actor: String,
    fixture_id: String,
    job_id: String,
    claim_id: String,
    decision: String,
    selected: bool,
    confidence_basis_points: u16,
    status: String,
    failure: Option<Value>,
    raw_output_sha256: String,
    rationale: String,
    truth: String,
    correct: Option<bool>,
    signed_action_count: usize,
    hidden_truth_loaded_after_phase_decision_close: bool,
}

#[derive(Serialize)]
struct ObservationRow {
    schema_version: &'static str,
    condition: String,
    phase: String,
    height: u64,
    epoch: u64,
    population: String,
    operator_actor: String,
    fixture_id: String,
    public_fixture_sha256: String,
    job_id: String,
    claim_id: String,
    hidden_truth_present: bool,
    remaining_model_calls: u64,
    remaining_tool_calls: u64,
    remaining_validation_seconds: u64,
    public_attestations_visible: Vec<Value>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("usage: hrep_formal_capture <condition-input> <experiment-root> <public-root> <repository-root>".into());
    }
    let input_path = PathBuf::from(&args[1]);
    let experiment = PathBuf::from(&args[2]);
    let public_root = PathBuf::from(&args[3]);
    let repository_root = PathBuf::from(&args[4]);
    let input: Input = serde_json::from_slice(&fs::read(&input_path)?)?;
    capture(&input, &experiment, &public_root, &repository_root)?;
    Ok(())
}

fn capture(
    input: &Input,
    experiment: &Path,
    public_root: &Path,
    repository_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if input.preregistration_lock_sha256
        != "9cd702ff890078079a5836457831625857098912fc9de7287a5b9a7e12687ec2"
        || input.public_manifest_sha256
            != "68ccbbf5cdfe722dca17aadc9d8a4c908c5e090e76105951ac4b35e3808470bb"
        || input.private_manifest_sha256
            != "a7d0a0e5f5ab8413437be9620aa17123457756710aa32dc06c69dc150e6a6c7c"
        || !input.training_decisions_closed_before_private_access
        || !input.evaluation_decisions_closed_before_private_access
        || input.infrastructure_exclusion.is_some()
        || input.operator_failures_retained != 0
    {
        return Err("condition input violates the locked formal boundary".into());
    }
    let mechanism = match input.condition.as_str() {
        "M00" if input.mechanism == "M00@1.0.0" => LaboratoryMechanism::M00RecordOnly,
        "M01" if input.mechanism == "M01@1.0.0" => LaboratoryMechanism::M01NaiveReputation,
        _ => return Err("unsupported condition/mechanism".into()),
    };
    let loaded = PublicFixtureLoader::new(public_root, repository_root)?.load()?;
    let fixtures = loaded
        .fixtures()
        .iter()
        .map(|item| (item.definition().fixture_id.clone(), item))
        .collect::<BTreeMap<_, _>>();
    if fixtures.len() != 9 {
        return Err("formal public fixture count differs from lock".into());
    }

    let condition_tag = if input.condition == "M00" { 0x00 } else { 0x01 };
    let config = RunnerConfig {
        seed: input.seed.seed_u64_be,
        chain_id: ChainId::new([0x52; 32]),
        blocks_per_epoch: 100,
        consensus_node: rachet_core::blocks::ConsensusNodeId::from(
            ed25519::PrivateKey::from_seed(input.seed.seed_u64_be ^ 0xc011_5e55).public_key(),
        ),
        genesis_parent_block: Sha256Digest::from([0; 32]),
        genesis_timestamp_ms: 1_700_000_000_000,
        block_interval_ms: 1_000,
    };
    let customer_key =
        ed25519::PrivateKey::from_seed(input.seed.seed_u64_be ^ 0xc057_0001 ^ condition_tag);
    let authority_key =
        ed25519::PrivateKey::from_seed(input.seed.seed_u64_be ^ 0xa11c_e001 ^ condition_tag);
    let authority = ActorId::from(authority_key.public_key());
    let mut keys = BTreeMap::new();
    for (index, name) in INTELLIGENT.iter().chain(FIXED.iter()).enumerate() {
        keys.insert(
            (*name).to_owned(),
            ed25519::PrivateKey::from_seed(
                input.seed.seed_u64_be ^ condition_tag ^ 0x0f00_0000 ^ u64::try_from(index)?,
            ),
        );
    }

    let mut jobs = BTreeMap::new();
    for (index, fixture_id) in TRAINING.iter().chain(EVALUATION.iter()).enumerate() {
        let loaded_fixture = fixtures
            .get(*fixture_id)
            .ok_or("scheduled fixture missing")?;
        let fixture = loaded_fixture.definition();
        if fixture.claims.len() != 1 {
            return Err("formal fixture must have exactly one claim".into());
        }
        let claim_definition = ClaimDefinition::new(bounded::<MAX_CLAIM_STATEMENT_BYTES>(
            fixture.claims[0].statement.as_bytes(),
        )?);
        let training = index < TRAINING.len();
        let (opens, closes, challenge) = if training { (1, 1, 2) } else { (101, 101, 102) };
        let create = CreateJob {
            artifact: GitArtifact::new(
                bounded::<MAX_REPOSITORY_LOCATOR_BYTES>(
                    format!("fixture://{}", fixture.fixture_id).as_bytes(),
                )?,
                git_hash(&fixture.repository.base_commit)?,
                git_hash(&fixture.repository.candidate_commit)?,
                ContentRef::new(
                    Sha256Digest::from(*fixture.specification.sha256.as_bytes()),
                    bounded::<MAX_CONTENT_LOCATOR_HINT_BYTES>(
                        format!("fixture://{}/specification", fixture.fixture_id).as_bytes(),
                    )?,
                    bounded::<MAX_MEDIA_TYPE_BYTES>(fixture.specification.media_type.as_bytes())?,
                ),
            ),
            claims: BoundedVec::new(vec![claim_definition.clone()])?,
            resolution_policy: ResolutionPolicy::ExperimentAuthority {
                authority: authority.clone(),
            },
            validation_opens_at: opens,
            validation_closes_at: closes,
            reveal_closes_at: None,
            challenge_closes_at: Some(challenge),
            supersedes: None,
            metadata: bounded::<MAX_METADATA_BYTES>(
                format!("fixture/{}", fixture.fixture_id).as_bytes(),
            )?,
        };
        let job_id = create.job_id();
        let mut claim_identity = Vec::new();
        job_id.write(&mut claim_identity);
        claim_definition.write(&mut claim_identity);
        let claim_id = ClaimId::derive(&claim_identity);
        let action = SignedAction::sign(
            &customer_key,
            ProtocolVersion::V1,
            config.chain_id,
            u64::try_from(index)?,
            challenge,
            Action::CreateJob(Box::new(create)),
        )?;
        jobs.insert(
            (*fixture_id).to_owned(),
            Job {
                fixture_id: (*fixture_id).to_owned(),
                class_name: format!("{:?}", fixture.class),
                fixture_hash: loaded_fixture.fixture_hash(),
                job_id,
                claim_id,
                fixture_claim_id: fixture.claims[0].claim_id.clone(),
                create: action,
            },
        );
    }

    let mut all_decisions = Vec::<DecisionRow>::new();
    let mut observations = Vec::<ObservationRow>::new();
    let mut action_blocks = vec![Vec::new(); 103];
    for fixture_id in TRAINING {
        action_blocks[0].push(jobs[fixture_id].create.clone());
    }
    for fixture_id in EVALUATION {
        action_blocks[100].push(jobs[fixture_id].create.clone());
    }
    let mut next_nonce = BTreeMap::<String, u64>::new();
    let mut public_history = VerdictTally::default();

    for (fixture_index, fixture_id) in TRAINING.iter().chain(EVALUATION.iter()).enumerate() {
        let phase = if fixture_index < 5 {
            "training"
        } else {
            "evaluation"
        };
        let (height, epoch, block_index) = if phase == "training" {
            (1, 0, 1)
        } else {
            (101, 1, 101)
        };
        let job = &jobs[*fixture_id];
        let mut current_tally = VerdictTally::default();
        for population in INTELLIGENT {
            let source = input
                .intelligent_decisions
                .iter()
                .find(|row| row.population == population && row.fixture_id == *fixture_id)
                .ok_or("intelligent decision matrix incomplete")?;
            let actor = ActorId::from(keys[population].public_key());
            observations.push(observation(
                input,
                phase,
                height,
                epoch,
                population,
                &actor,
                job,
                &all_decisions,
            ));
            let (decision, selected, action) = signed_decision(
                source.decision.as_str(),
                source.selected,
                source.confidence_basis_points,
                &keys[population],
                next_nonce.entry(population.to_owned()).or_default(),
                &config,
                job,
                height + 1,
            )?;
            if let Some(ref signed) = action {
                action_blocks[block_index].push(signed.clone());
            }
            tally_add(&mut current_tally, &decision);
            tally_add(&mut public_history, &decision);
            all_decisions.push(decision_row(
                input,
                source,
                phase,
                height,
                population,
                &actor,
                job,
                decision,
                selected,
                action.is_some(),
            ));
        }
        for (fixed_index, population) in FIXED.iter().enumerate() {
            let actor = ActorId::from(keys[*population].public_key());
            observations.push(observation(
                input,
                phase,
                height,
                epoch,
                population,
                &actor,
                job,
                &all_decisions,
            ));
            let policy = fixed_policy(
                population,
                input.seed.seed_u64_be ^ u64::try_from(fixed_index)?,
            );
            let observed = ObservedJob::new(
                job.job_id,
                vec![ObservedClaim::new(job.claim_id, current_tally)],
                matches!(job.class_name.as_str(), "CleanChange" | "ObviousRegression"),
            )?;
            let policy_observation = PolicyObservation::new(
                epoch,
                height,
                PolicyResourceBudget {
                    remaining_model_calls: 0,
                    remaining_tool_calls: 0,
                    remaining_validation_seconds: 60,
                },
                vec![observed],
                public_history,
            )?;
            let scripted = policy.decide(&policy_observation);
            let (decision, selected) = match scripted.kind {
                ScriptedDecisionKind::Validate { claims, .. } => {
                    (verdict_name(claims[0].verdict).to_owned(), true)
                }
                ScriptedDecisionKind::Abstain { .. } => ("abstain".to_owned(), true),
                ScriptedDecisionKind::Wait => ("wait".to_owned(), false),
            };
            let (_, _, action) = signed_decision(
                &decision,
                selected,
                0,
                &keys[*population],
                next_nonce.entry((*population).to_owned()).or_default(),
                &config,
                job,
                height + 1,
            )?;
            if let Some(ref signed) = action {
                action_blocks[block_index].push(signed.clone());
            }
            tally_add(&mut current_tally, &decision);
            tally_add(&mut public_history, &decision);
            all_decisions.push(DecisionRow {
                schema_version: "hrep-formal-decision.v1",
                condition: input.condition.clone(),
                phase: phase.to_owned(),
                height,
                population: (*population).to_owned(),
                operator_actor: actor_hex(&actor),
                fixture_id: fixture_id.to_string(),
                job_id: hex(job.job_id.as_bytes()),
                claim_id: hex(job.claim_id.as_bytes()),
                decision,
                selected,
                confidence_basis_points: 0,
                status: "completed".to_owned(),
                failure: None,
                raw_output_sha256: hash_hex(
                    format!(
                        "{}/{}/{}/{}",
                        input.seed.index, input.condition, population, fixture_id
                    )
                    .as_bytes(),
                ),
                rationale: "locked pure scripted heuristic".to_owned(),
                truth: input.truth[*fixture_id].clone(),
                correct: correctness(
                    all_decisions.last().map_or("wait", |r| r.decision.as_str()),
                    &input.truth[*fixture_id],
                ),
                signed_action_count: usize::from(action.is_some()),
                hidden_truth_loaded_after_phase_decision_close: true,
            });
            // Correct the field using the just-created decision, not the prior row.
            let last = all_decisions.last_mut().unwrap();
            last.correct = correctness(&last.decision, &last.truth);
        }
    }

    for (index, fixture_id) in TRAINING.iter().chain(EVALUATION.iter()).enumerate() {
        let job = &jobs[*fixture_id];
        let resolution_block = if index < 5 { 2 } else { 102 };
        let height = u64::try_from(resolution_block)?;
        let verdict = match input.truth[*fixture_id].as_str() {
            "valid" => ResolutionVerdict::Pass,
            "invalid" => ResolutionVerdict::Fail,
            "ambiguous" => ResolutionVerdict::Unresolved,
            _ => return Err("invalid private truth".into()),
        };
        let resolution = ResolveClaim {
            job_id: job.job_id,
            claim_id: job.claim_id,
            verdict,
            evidence_ids: BoundedVec::default(),
            resolution_reference: ContentRef::new(
                Sha256Digest::from(*job.fixture_hash.as_bytes()),
                bounded::<MAX_CONTENT_LOCATOR_HINT_BYTES>(
                    format!("hidden-resolution://{}", fixture_id).as_bytes(),
                )?,
                bounded::<MAX_MEDIA_TYPE_BYTES>(b"application/json")?,
            ),
        };
        action_blocks[resolution_block].push(SignedAction::sign(
            &authority_key,
            ProtocolVersion::V1,
            config.chain_id,
            u64::try_from(index)?,
            height,
            Action::ResolveClaim(resolution),
        )?);
    }

    let execution =
        DeterministicRunner::new(config.clone(), mechanism)?.replay_actions(action_blocks)?;
    if let Some(error) = execution.terminal_error {
        return Err(format!(
            "formal protocol execution failed {}: {}",
            error.code, error.message
        )
        .into());
    }
    let output = execution.output;
    let resources = resources(input, &all_decisions)?;
    let metrics = metrics(
        input,
        &all_decisions,
        &resources,
        &output.blocks[2].post_state,
        mechanism,
    )?;
    let mut bundle = RunArtifactBundle {
        initial_state: Vec::new(),
        observations_jsonl: jsonl(&observations)?,
        decisions_jsonl: jsonl(&all_decisions)?,
        signed_actions: Vec::new(),
        blocks: Vec::new(),
        events: Vec::new(),
        economic_state_jsonl: Vec::new(),
        resources_json: resources.to_json_bytes()?,
        metrics_json: serde_json::to_vec_pretty(&metrics)?,
        discovered_strategies_markdown: strategies(input, &all_decisions).into_bytes(),
    };
    bundle.metrics_json.push(b'\n');
    let capture = ReplayCapture::from_completed_run(&config, mechanism, &[], &output)?;
    let outcome = capture.apply_to(&mut bundle);
    replay_bundle(&bundle, &outcome)?;
    let id = RunId::from_str(&input.run_id)?;
    let run_root = experiment.join("runs").join(&input.run_id);
    fs::create_dir(&run_root)?;
    RunArtifactStore::capture(experiment, id, outcome, &bundle)?;
    println!(
        "{} {} blocks={} decisions={} actions={}",
        input.run_id,
        input.condition,
        output.blocks.len(),
        all_decisions.len(),
        output
            .blocks
            .iter()
            .map(|b| b.block.actions.len())
            .sum::<usize>()
    );
    Ok(())
}

fn signed_decision(
    decision: &str,
    selected: bool,
    confidence: u16,
    key: &ed25519::PrivateKey,
    nonce: &mut u64,
    config: &RunnerConfig,
    job: &Job,
    valid_until: u64,
) -> Result<(String, bool, Option<SignedAction<Action>>), Box<dyn std::error::Error>> {
    if !selected || decision == "wait" {
        return Ok(("wait".to_owned(), false, None));
    }
    let verdict = match decision {
        "pass" => Verdict::Pass,
        "fail" => Verdict::Fail,
        "abstain" => Verdict::Abstain,
        "indeterminate" => Verdict::Indeterminate,
        _ => return Err("unsupported operator decision".into()),
    };
    let action = Action::SubmitAttestation(SubmitAttestation {
        job_id: job.job_id,
        claim_id: job.claim_id,
        verdict,
        confidence_basis_points: confidence,
        evidence_ids: BoundedVec::default(),
    });
    let signed = SignedAction::sign(
        key,
        ProtocolVersion::V1,
        config.chain_id,
        *nonce,
        valid_until,
        action,
    )?;
    *nonce = nonce.checked_add(1).ok_or("operator nonce overflow")?;
    Ok((decision.to_owned(), true, Some(signed)))
}

fn fixed_policy(name: &str, seed: u64) -> ScriptedPolicy {
    match name {
        "always-pass" => ScriptedPolicy::AlwaysPass,
        "always-fail" => ScriptedPolicy::AlwaysFail,
        "random-verdict" => ScriptedPolicy::RandomVerdict { seed },
        "easy-job-only" => ScriptedPolicy::TrivialJobsOnly,
        "majority-following" => ScriptedPolicy::ConsensusFollower,
        "maximum-volume" => ScriptedPolicy::MaximumVolume,
        "perfect-abstainer" => ScriptedPolicy::PerfectAbstainer,
        "historical-majority" => ScriptedPolicy::HistoricalMajorityFollower,
        _ => unreachable!(),
    }
}

fn observation(
    input: &Input,
    phase: &str,
    height: u64,
    epoch: u64,
    population: &str,
    actor: &ActorId,
    job: &Job,
    prior: &[DecisionRow],
) -> ObservationRow {
    ObservationRow {
        schema_version: "operator-observation.v1",
        condition: input.condition.clone(),
        phase: phase.to_owned(),
        height,
        epoch,
        population: population.to_owned(),
        operator_actor: actor_hex(actor),
        fixture_id: job.fixture_id.clone(),
        public_fixture_sha256: job.fixture_hash.to_string(),
        job_id: hex(job.job_id.as_bytes()),
        claim_id: hex(job.claim_id.as_bytes()),
        hidden_truth_present: false,
        remaining_model_calls: if FIXED.contains(&population) { 0 } else { 4 },
        remaining_tool_calls: if FIXED.contains(&population) { 0 } else { 40 },
        remaining_validation_seconds: if FIXED.contains(&population) { 60 } else { 900 },
        public_attestations_visible: prior
            .iter()
            .filter(|row| row.fixture_id == job.fixture_id)
            .map(|row| json!({"operator": row.population, "decision": row.decision}))
            .collect(),
    }
}

fn decision_row(
    input: &Input,
    source: &IntelligentDecision,
    phase: &str,
    height: u64,
    population: &str,
    actor: &ActorId,
    job: &Job,
    decision: String,
    selected: bool,
    signed: bool,
) -> DecisionRow {
    DecisionRow {
        schema_version: "hrep-formal-decision.v1",
        condition: input.condition.clone(),
        phase: phase.to_owned(),
        height,
        population: population.to_owned(),
        operator_actor: actor_hex(actor),
        fixture_id: job.fixture_id.clone(),
        job_id: hex(job.job_id.as_bytes()),
        claim_id: hex(job.claim_id.as_bytes()),
        decision,
        selected,
        confidence_basis_points: source.confidence_basis_points,
        status: source.status.clone(),
        failure: source.failure.clone(),
        raw_output_sha256: source.raw_output_sha256.clone(),
        rationale: source.rationale.clone(),
        truth: source.truth.clone(),
        correct: source.correct,
        signed_action_count: usize::from(signed),
        hidden_truth_loaded_after_phase_decision_close: source
            .hidden_truth_loaded_after_phase_decision_close,
    }
}

fn resources(
    input: &Input,
    decisions: &[DecisionRow],
) -> Result<ResourceAccounting, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    for item in &input.intelligent_resources {
        records.push(ResourceRecord {
            operator: item.operator.clone(),
            epoch: if item.phase == "training" { 0 } else { 1 },
            model_calls: item.model_calls,
            input_tokens: item.input_tokens,
            output_tokens: item.output_tokens,
            tool_calls: item.tool_calls,
            command_duration_ms: item.command_duration_ms,
            cpu_time_ms: Some(item.cpu_time_ms),
            validation_wall_clock_allowance_ms: item.validation_wall_clock_allowance_ms,
            git_objects_read: item.git_objects_read,
            files_inspected: item.files_inspected,
            tests_executed: item.tests_executed,
            jobs_inspected: item.jobs_inspected,
            jobs_accepted: item.jobs_accepted,
            claims_evaluated: item.claims_evaluated,
            evidence_bytes: item.evidence_bytes,
            compute_units: None,
        });
    }
    for row in decisions
        .iter()
        .filter(|row| FIXED.contains(&row.population.as_str()))
    {
        records.push(ResourceRecord {
            operator: row.population.clone(),
            epoch: if row.phase == "training" { 0 } else { 1 },
            model_calls: 0,
            input_tokens: Some(0),
            output_tokens: Some(0),
            tool_calls: 0,
            command_duration_ms: 0,
            cpu_time_ms: Some(0),
            validation_wall_clock_allowance_ms: 60_000,
            git_objects_read: 0,
            files_inspected: 0,
            tests_executed: 0,
            jobs_inspected: 1,
            jobs_accepted: u64::from(row.selected),
            claims_evaluated: u64::from(matches!(row.decision.as_str(), "pass" | "fail")),
            evidence_bytes: 0,
            compute_units: Some(0),
        });
    }
    Ok(ResourceAccounting::from_records(records)?)
}

fn metrics(
    input: &Input,
    decisions: &[DecisionRow],
    resources: &ResourceAccounting,
    training_state: &[rachet_core::state::StateEntry],
    mechanism: LaboratoryMechanism,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut operators = Vec::new();
    for name in INTELLIGENT.iter().chain(FIXED.iter()) {
        let actor = ActorId::from(
            ed25519::PrivateKey::from_seed(
                input.seed.seed_u64_be
                    ^ (if input.condition == "M00" { 0 } else { 1 })
                    ^ 0x0f00_0000
                    ^ u64::try_from(operators.len())?,
            )
            .public_key(),
        );
        let score = if mechanism == LaboratoryMechanism::M00RecordOnly {
            0
        } else {
            training_state
                .iter()
                .find(|(key, _)| *key == M01NaiveReputation::reputation_state_key(&actor))
                .map(|(_, value)| NaiveReputation::decode(value).map(|v| v.score))
                .transpose()?
                .unwrap_or(0)
        };
        let held = decisions
            .iter()
            .filter(|row| {
                row.population == **name && row.phase == "evaluation" && row.correct.is_some()
            })
            .collect::<Vec<_>>();
        let correct = held.iter().filter(|row| row.correct == Some(true)).count();
        let selected_training = decisions
            .iter()
            .filter(|row| row.population == **name && row.phase == "training" && row.selected)
            .count();
        let effort = resources
            .by_operator
            .iter()
            .find(|row| row.operator == **name)
            .map_or(0, |row| {
                row.totals.tool_calls + row.totals.files_inspected + row.totals.tests_executed
            });
        operators.push(json!({
            "operator": name, "actor_id": actor_hex(&actor), "post_training_score": score,
            "selected_training_validation_count": selected_training,
            "held_out_binary_correct": correct, "held_out_binary_decisions": held.len(),
            "held_out_correctness": if held.is_empty() { Value::Null } else { json!(correct as f64 / held.len() as f64) },
            "validation_effort_units": effort,
        }));
    }
    Ok(json!({
        "schema_version": "hrep-formal-run-metrics.v1", "formal_evaluation_eligible": true,
        "seed_index": input.seed.index, "seed_digest_sha256": input.seed.digest_sha256,
        "condition": input.condition, "mechanism": input.mechanism,
        "training_fixture_ids": TRAINING, "evaluation_fixture_ids": EVALUATION,
        "operators": operators, "resource_totals": resources.totals,
        "gate_thresholds_applied_or_changed_during_execution": false,
    }))
}

fn strategies(input: &Input, decisions: &[DecisionRow]) -> String {
    let waits = decisions
        .iter()
        .filter(|row| row.decision == "wait")
        .count();
    let abstains = decisions
        .iter()
        .filter(|row| row.decision == "abstain")
        .count();
    format!(
        "# Discovered strategies\n\nFormal Phase 4 retained behavior only; assessment is deferred.\n\n- condition: {}\n- wait decisions: {}\n- abstentions: {}\n- operator failures: {}\n",
        input.condition, waits, abstains, input.operator_failures_retained
    )
}

fn tally_add(tally: &mut VerdictTally, decision: &str) {
    match decision {
        "pass" => tally.pass += 1,
        "fail" => tally.fail += 1,
        "abstain" => tally.abstain += 1,
        "indeterminate" => tally.indeterminate += 1,
        _ => {}
    }
}
fn correctness(decision: &str, truth: &str) -> Option<bool> {
    if truth == "ambiguous" || !matches!(decision, "pass" | "fail") {
        None
    } else {
        Some((decision == "pass") == (truth == "valid"))
    }
}
fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Pass => "pass",
        Verdict::Fail => "fail",
        Verdict::Abstain => "abstain",
        Verdict::Indeterminate => "indeterminate",
    }
}
fn actor_hex(actor: &ActorId) -> String {
    hex(actor.as_bytes())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash_hex(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_slice())
}
fn git_hash(value: &str) -> Result<GitHash, Box<dyn std::error::Error>> {
    Ok(GitHash::try_from(decode_hex(value)?)?)
}
fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| Ok(u8::from_str_radix(std::str::from_utf8(p)?, 16)?))
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?)
}
fn bounded<const MAX: usize>(
    bytes: &[u8],
) -> Result<BoundedBytes<MAX>, Box<dyn std::error::Error>> {
    BoundedBytes::try_from(bytes).map_err(|e| e.to_string().into())
}
fn jsonl<T: Serialize>(items: &[T]) -> Result<Vec<u8>, serde_json::Error> {
    let mut out = Vec::new();
    for item in items {
        serde_json::to_writer(&mut out, item)?;
        out.push(b'\n');
    }
    Ok(out)
}
