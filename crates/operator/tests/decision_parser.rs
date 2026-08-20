use rachet_client::identity::ActorIdentity;
use rachet_core::{
    actions::{Action, ActionVerificationContext, ChallengeTarget, Verdict},
    primitives::{ChainId, ClaimId, EvidenceId, JobId, Sha256Digest},
};
use rachet_operator::{
    budget::{BudgetTracker, ResourceBudget},
    decision::{
        AvailableClaim, AvailableEvidence, AvailableJob, DecisionContext,
        MAX_DECISION_OUTPUT_BYTES, ParsedDecisionKind, parse_and_sign,
    },
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from([byte; 32])
}

fn job_id() -> JobId {
    JobId::from_digest(digest(0x10))
}

fn claim_id(byte: u8) -> ClaimId {
    ClaimId::from_digest(digest(byte))
}

fn evidence_id(byte: u8) -> EvidenceId {
    EvidenceId::from_digest(digest(byte))
}

fn jobs() -> Vec<AvailableJob> {
    vec![AvailableJob {
        reference: "job-001".to_owned(),
        job_id: job_id(),
        claims: vec![
            AvailableClaim {
                reference: "claim-001".to_owned(),
                claim_id: claim_id(0x21),
            },
            AvailableClaim {
                reference: "claim-002".to_owned(),
                claim_id: claim_id(0x22),
            },
        ],
    }]
}

fn evidence() -> Vec<AvailableEvidence> {
    vec![
        AvailableEvidence {
            reference: "evidence-001".to_owned(),
            evidence_id: evidence_id(0x31),
            job_id: job_id(),
            claim_id: Some(claim_id(0x21)),
        },
        AvailableEvidence {
            reference: "evidence-002".to_owned(),
            evidence_id: evidence_id(0x32),
            job_id: job_id(),
            claim_id: None,
        },
    ]
}

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/operator-decision")
        .join(name);
    fs::read(path).unwrap()
}

fn budget(model_calls: u64, tool_calls: u64) -> BudgetTracker {
    BudgetTracker::new(ResourceBudget {
        model_calls,
        tool_calls,
        validation_seconds: 0,
    })
}

fn run(raw: Vec<u8>, budget: &mut BudgetTracker) -> rachet_operator::decision::DecisionRecord {
    let jobs = jobs();
    let evidence = evidence();
    let identity = ActorIdentity::generate().unwrap();
    parse_and_sign(
        raw,
        DecisionContext {
            chain_id: ChainId::new([0x41; 32]),
            next_nonce: 7,
            valid_until_height: 50,
            available_jobs: &jobs,
            available_evidence: &evidence,
        },
        &identity,
        budget,
    )
}

#[test]
fn validate_fixture_becomes_expected_verified_attestation() {
    let mut budget = budget(4, 40);
    let record = run(fixture("validate-v1.example.json"), &mut budget);
    assert!(record.succeeded(), "{:?}", record.failure);
    assert_eq!(record.signed_actions.len(), 1);
    assert_eq!(record.next_nonce, 8);
    record.signed_actions[0]
        .verify(
            &ActionVerificationContext::current(ChainId::new([0x41; 32]), 49),
            7,
        )
        .unwrap();
    let Action::SubmitAttestation(attestation) = &record.signed_actions[0].payload else {
        panic!("validate did not produce an attestation");
    };
    assert_eq!(attestation.job_id, job_id());
    assert_eq!(attestation.claim_id, claim_id(0x21));
    assert_eq!(attestation.verdict, Verdict::Fail);
    assert_eq!(attestation.confidence_basis_points, 8_200);
    assert_eq!(attestation.evidence_ids.as_slice(), &[evidence_id(0x31)]);
    assert_eq!(budget.used().model_calls, 2);
    assert_eq!(budget.used().tool_calls, 18);
}

#[test]
fn abstain_challenge_and_wait_fixtures_have_exact_action_shapes() {
    let mut abstain_budget = budget(4, 40);
    let abstain = run(fixture("abstain-v1.example.json"), &mut abstain_budget);
    assert!(abstain.succeeded());
    assert_eq!(abstain.signed_actions.len(), 2);
    for (index, signed) in abstain.signed_actions.iter().enumerate() {
        let Action::SubmitAttestation(attestation) = &signed.payload else {
            panic!("abstain did not produce attestations");
        };
        assert_eq!(attestation.verdict, Verdict::Abstain);
        assert_eq!(attestation.confidence_basis_points, 0);
        assert!(attestation.evidence_ids.is_empty());
        assert_eq!(signed.nonce, 7 + u64::try_from(index).unwrap());
    }

    let mut challenge_budget = budget(4, 40);
    let challenge = run(fixture("challenge-v1.example.json"), &mut challenge_budget);
    assert!(challenge.succeeded(), "{:?}", challenge.failure);
    assert_eq!(challenge.signed_actions.len(), 1);
    let Action::CreateChallenge(action) = &challenge.signed_actions[0].payload else {
        panic!("challenge did not produce a canonical challenge");
    };
    assert_eq!(action.target, ChallengeTarget::Claim(claim_id(0x21)));
    assert_eq!(
        action.evidence_ids.as_slice(),
        &[evidence_id(0x31), evidence_id(0x32)]
    );
    assert_eq!(
        action.counterclaim.as_slice(),
        br#"{"claim_id":"claim-001","verdict":"fail","confidence_basis_points":9100}"#
    );

    let mut wait_budget = budget(0, 0);
    let wait = run(fixture("wait-v1.example.json"), &mut wait_budget);
    assert!(wait.succeeded());
    assert!(wait.signed_actions.is_empty());
    assert_eq!(wait.next_nonce, 7);
    assert!(matches!(
        wait.parsed_decision.unwrap().kind,
        ParsedDecisionKind::Wait
    ));
}

#[test]
fn malformed_extra_and_markdown_wrapped_output_is_retained_without_repair() {
    for raw in [
        br#"{"schema_version":"operator-decision.v1","decision":wait}"#.to_vec(),
        br#"{"schema_version":"operator-decision.v1","decision":"wait","resource_report":{"model_calls":0,"tool_calls":0},"extra":true}"#.to_vec(),
        b"```json\n{\"schema_version\":\"operator-decision.v1\",\"decision\":\"wait\",\"resource_report\":{\"model_calls\":0,\"tool_calls\":0}}\n```".to_vec(),
    ] {
        let mut budget = budget(10, 10);
        let record = run(raw.clone(), &mut budget);
        assert!(!record.succeeded());
        assert_eq!(record.raw_output(), raw);
        assert_eq!(record.raw_output_sha256().len(), 64);
        assert!(record.signed_actions.is_empty());
        assert_eq!(record.next_nonce, 7);
        assert_eq!(budget.used().model_calls, 0);
    }
}

#[test]
fn duplicate_keys_null_fields_and_variant_shape_violations_are_rejected() {
    for raw in [
        br#"{"schema_version":"operator-decision.v1","decision":"wait","decision":"validate","resource_report":{"model_calls":0,"tool_calls":0}}"#.as_slice(),
        br#"{"schema_version":"operator-decision.v1","decision":"wait","job_id":null,"resource_report":{"model_calls":0,"tool_calls":0}}"#.as_slice(),
        br#"{"schema_version":"operator-decision.v1","decision":"abstain","job_id":"job-001","claims":[],"resource_report":{"model_calls":0,"tool_calls":0}}"#.as_slice(),
    ] {
        let mut budget = budget(10, 10);
        let record = run(raw.to_vec(), &mut budget);
        assert!(!record.succeeded());
        assert!(record.signed_actions.is_empty());
    }
}

#[test]
fn oversized_and_over_budget_outputs_fail_atomically() {
    let oversized = vec![b' '; MAX_DECISION_OUTPUT_BYTES + 1];
    let mut ample = budget(10, 10);
    let record = run(oversized.clone(), &mut ample);
    assert_eq!(record.raw_output(), oversized);
    assert_eq!(
        record.failure.unwrap().code,
        "OPERATOR_DECISION_OUTPUT_TOO_LARGE"
    );
    assert!(record.signed_actions.is_empty());

    let mut insufficient = budget(1, 40);
    let before = insufficient;
    let record = run(fixture("validate-v1.example.json"), &mut insufficient);
    assert_eq!(record.failure.unwrap().code, "OPERATOR_BUDGET_EXCEEDED");
    assert!(record.parsed_decision.is_some());
    assert!(record.signed_actions.is_empty());
    assert_eq!(record.next_nonce, 7);
    assert_eq!(insufficient, before);
}

#[test]
fn unavailable_jobs_claims_and_evidence_never_produce_actions() {
    let cases = [
        json!({
            "schema_version": "operator-decision.v1",
            "decision": "validate",
            "job_id": "job-missing",
            "claims": [{"claim_id":"claim-001","verdict":"pass","confidence_basis_points":1,"evidence_refs":[]}],
            "resource_report": {"model_calls":0,"tool_calls":0}
        }),
        json!({
            "schema_version": "operator-decision.v1",
            "decision": "validate",
            "job_id": "job-001",
            "claims": [{"claim_id":"claim-missing","verdict":"pass","confidence_basis_points":1,"evidence_refs":[]}],
            "resource_report": {"model_calls":0,"tool_calls":0}
        }),
        json!({
            "schema_version": "operator-decision.v1",
            "decision": "validate",
            "job_id": "job-001",
            "claims": [{"claim_id":"claim-002","verdict":"pass","confidence_basis_points":1,"evidence_refs":["evidence-001"]}],
            "resource_report": {"model_calls":0,"tool_calls":0}
        }),
    ];
    for value in cases {
        let mut budget = budget(10, 10);
        let record = run(serde_json::to_vec(&value).unwrap(), &mut budget);
        assert!(!record.succeeded());
        assert!(record.signed_actions.is_empty());
        assert_eq!(budget.used().model_calls, 0);
    }
}

#[test]
fn schema_limits_and_duplicate_references_are_enforced_by_parser() {
    let mut value: Value = serde_json::from_slice(&fixture("validate-v1.example.json")).unwrap();
    value["claims"][0]["confidence_basis_points"] = json!(10_001);
    let mut tracker = budget(10, 40);
    assert!(!run(serde_json::to_vec(&value).unwrap(), &mut tracker).succeeded());

    let mut value: Value = serde_json::from_slice(&fixture("validate-v1.example.json")).unwrap();
    value["claims"][0]["evidence_refs"] = json!(["evidence-001", "evidence-001"]);
    let mut tracker = budget(10, 40);
    let record = run(serde_json::to_vec(&value).unwrap(), &mut tracker);
    assert_eq!(
        record.failure.unwrap().code,
        "OPERATOR_DECISION_EVIDENCE_DUPLICATE"
    );
    assert!(record.signed_actions.is_empty());
}
