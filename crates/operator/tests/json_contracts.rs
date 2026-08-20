use std::{fs, path::PathBuf};

use serde_json::{Value, json};

fn schema_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas")
}

fn load(relative_path: &str) -> Value {
    let path = schema_root().join(relative_path);
    let bytes =
        fs::read(&path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("invalid JSON in {}: {error}", path.display()))
}

fn validator(relative_path: &str) -> jsonschema::Validator {
    let schema = load(relative_path);
    assert!(
        jsonschema::meta::is_valid(&schema),
        "{relative_path} is not a valid JSON Schema"
    );
    jsonschema::validator_for(&schema)
        .unwrap_or_else(|error| panic!("cannot compile {relative_path}: {error}"))
}

#[derive(Debug, Eq, PartialEq)]
enum DecisionFailure {
    MalformedJson,
    SchemaViolation,
}

fn validate_decision_bytes(bytes: &[u8]) -> Result<Value, DecisionFailure> {
    let value = serde_json::from_slice(bytes).map_err(|_| DecisionFailure::MalformedJson)?;
    validator("operator-decision/operator-decision-v1.schema.json")
        .validate(&value)
        .map_err(|_| DecisionFailure::SchemaViolation)?;
    Ok(value)
}

#[test]
fn observation_example_validates_and_contains_only_permitted_information() {
    let validator = validator("operator-observation/operator-observation-v1.schema.json");
    let example = load("operator-observation/operator-observation-v1.example.json");
    assert!(validator.is_valid(&example));

    let serialized = serde_json::to_string(&example).unwrap();
    for forbidden in [
        "ground_truth",
        "seeded_defect_description",
        "peer_private_reasoning",
        "unrevealed_peer_decisions",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "observation fixture leaked {forbidden}"
        );
    }

    for forbidden in [
        "ground_truth",
        "peer_private_reasoning",
        "unrevealed_peer_decisions",
    ] {
        let mut injected = example.clone();
        injected
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_owned(), json!("hidden"));
        assert!(
            !validator.is_valid(&injected),
            "observation schema accepted forbidden field {forbidden}"
        );
    }

    let mut nested_injection = example;
    nested_injection["operator"]["unrevealed_peer_decisions"] = json!([]);
    assert!(!validator.is_valid(&nested_injection));
}

#[test]
fn all_four_decision_examples_validate() {
    let validator = validator("operator-decision/operator-decision-v1.schema.json");
    for example in [
        "operator-decision/validate-v1.example.json",
        "operator-decision/abstain-v1.example.json",
        "operator-decision/challenge-v1.example.json",
        "operator-decision/wait-v1.example.json",
    ] {
        assert!(
            validator.is_valid(&load(example)),
            "invalid example {example}"
        );
    }
}

#[test]
fn decision_variants_enforce_their_exact_shapes() {
    let validator = validator("operator-decision/operator-decision-v1.schema.json");

    let mut validate_without_claims = load("operator-decision/validate-v1.example.json");
    validate_without_claims
        .as_object_mut()
        .unwrap()
        .remove("claims");
    assert!(!validator.is_valid(&validate_without_claims));

    let mut abstain_with_claims = load("operator-decision/abstain-v1.example.json");
    abstain_with_claims["claims"] = json!([{
        "claim_id": "claim-001",
        "verdict": "abstain",
        "confidence_basis_points": 0,
        "evidence_refs": []
    }]);
    assert!(!validator.is_valid(&abstain_with_claims));

    let mut challenge_without_job = load("operator-decision/challenge-v1.example.json");
    challenge_without_job
        .as_object_mut()
        .unwrap()
        .remove("job_id");
    assert!(!validator.is_valid(&challenge_without_job));

    let mut wait_with_job = load("operator-decision/wait-v1.example.json");
    wait_with_job["job_id"] = json!("job-001");
    assert!(!validator.is_valid(&wait_with_job));
}

#[test]
fn unknown_oversized_and_malformed_decisions_fail_explicitly() {
    let mut unknown = load("operator-decision/validate-v1.example.json");
    unknown["silent_repair"] = json!(true);
    assert_eq!(
        validate_decision_bytes(&serde_json::to_vec(&unknown).unwrap()),
        Err(DecisionFailure::SchemaViolation)
    );

    let mut oversized_id = load("operator-decision/validate-v1.example.json");
    oversized_id["job_id"] = json!("j".repeat(129));
    assert_eq!(
        validate_decision_bytes(&serde_json::to_vec(&oversized_id).unwrap()),
        Err(DecisionFailure::SchemaViolation)
    );

    let mut oversized_claims = load("operator-decision/validate-v1.example.json");
    let claim = oversized_claims["claims"][0].clone();
    oversized_claims["claims"] = Value::Array(vec![claim; 129]);
    assert_eq!(
        validate_decision_bytes(&serde_json::to_vec(&oversized_claims).unwrap()),
        Err(DecisionFailure::SchemaViolation)
    );

    let mut oversized_evidence = load("operator-decision/validate-v1.example.json");
    oversized_evidence["claims"][0]["evidence_refs"] = Value::Array(
        (0..65)
            .map(|index| json!(format!("evidence-{index}")))
            .collect(),
    );
    assert_eq!(
        validate_decision_bytes(&serde_json::to_vec(&oversized_evidence).unwrap()),
        Err(DecisionFailure::SchemaViolation)
    );

    assert_eq!(
        validate_decision_bytes(br#"{"schema_version":"operator-decision.v1","decision":wait}"#),
        Err(DecisionFailure::MalformedJson)
    );
}

#[test]
fn versions_reports_claims_and_budgets_are_strictly_bounded() {
    let observation = validator("operator-observation/operator-observation-v1.schema.json");
    let decision = validator("operator-decision/operator-decision-v1.schema.json");

    let mut wrong_observation_version =
        load("operator-observation/operator-observation-v1.example.json");
    wrong_observation_version["schema_version"] = json!("operator-observation.v2");
    assert!(!observation.is_valid(&wrong_observation_version));

    let mut unknown_budget = load("operator-observation/operator-observation-v1.example.json");
    unknown_budget["resource_budget"]["remaining_input_tokens"] = json!(100);
    assert!(!observation.is_valid(&unknown_budget));

    let mut negative_budget = load("operator-observation/operator-observation-v1.example.json");
    negative_budget["resource_budget"]["remaining_model_calls"] = json!(-1);
    assert!(!observation.is_valid(&negative_budget));

    let mut wrong_decision_version = load("operator-decision/validate-v1.example.json");
    wrong_decision_version["schema_version"] = json!("operator-decision.v2");
    assert!(!decision.is_valid(&wrong_decision_version));

    let mut excessive_confidence = load("operator-decision/validate-v1.example.json");
    excessive_confidence["claims"][0]["confidence_basis_points"] = json!(10_001);
    assert!(!decision.is_valid(&excessive_confidence));

    let mut unknown_report = load("operator-decision/validate-v1.example.json");
    unknown_report["resource_report"]["wall_clock_seconds"] = json!(10);
    assert!(!decision.is_valid(&unknown_report));
}
