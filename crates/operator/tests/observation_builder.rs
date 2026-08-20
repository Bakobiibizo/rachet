use std::{fs, path::PathBuf};

use rachet_operator::{
    budget::ResourceUsage,
    observation::{
        FinalizedPublicState, InformationClass, InformationPolicy, MechanismEconomicState,
        ObservationBuildInput, ObservationError, OperatorDeclaration, PrivateOperatorHistory,
        build,
    },
};
use serde_json::Value;

fn schema_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas")
}

fn validator() -> jsonschema::Validator {
    let path = schema_root().join("operator-observation/operator-observation-v1.schema.json");
    let schema: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn build_fixture(
    mechanism_set: &[&str],
    jobs: &[&str],
    public_history: &[u8],
    private_history: &[u8],
) -> rachet_operator::observation::ObservationSnapshot {
    let mechanism_set = mechanism_set
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let jobs = jobs
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let policy = InformationPolicy::section_31("section-31-default");
    build(ObservationBuildInput {
        finalized_public_state: FinalizedPublicState {
            experiment_id: "experiment-003",
            epoch: 12,
            height: 1_240,
            finalized_state_root_sha256: [0x31; 32],
            public_history,
        },
        operator: OperatorDeclaration {
            actor_id: "actor-validation-01",
            role: "validation_operator",
            objective: "maximize_long_term_reputation",
        },
        mechanism_economic_state: MechanismEconomicState {
            mechanism_set: &mechanism_set,
            reputation: 14,
        },
        remaining_budget: ResourceUsage {
            model_calls: 4,
            tool_calls: 40,
            validation_seconds: 900,
        },
        available_jobs: &jobs,
        private_operator_history: PrivateOperatorHistory {
            actor_id: "actor-validation-01",
            bytes: private_history,
        },
        information_policy: &policy,
    })
    .unwrap()
}

#[test]
fn snapshot_matches_schema_and_has_exact_content_references() {
    let snapshot = build_fixture(
        &["M02@1.0.0", "M01@1.0.0"],
        &["job-002", "job-001"],
        b"public finalized history\n",
        b"private operator history\n",
    );
    let value: Value = serde_json::from_slice(snapshot.canonical_json()).unwrap();
    assert!(validator().is_valid(&value));
    assert_eq!(
        value["economic_state"]["mechanism_set"],
        serde_json::json!(["M01@1.0.0", "M02@1.0.0"])
    );
    assert_eq!(
        value["available_jobs"],
        serde_json::json!(["job-001", "job-002"])
    );
    assert_eq!(
        value["public_history_ref"],
        format!("sha256:{}", snapshot.provenance().public_history_sha256)
    );
    assert_eq!(
        value["private_operator_history_ref"],
        format!(
            "sha256:{}",
            snapshot.provenance().private_operator_history_sha256
        )
    );
    assert_eq!(
        snapshot.provenance().finalized_state_root_sha256.as_str(),
        "31".repeat(32)
    );
}

#[test]
fn observation_and_all_projection_hashes_are_replay_stable() {
    let first = build_fixture(
        &["M02@1.0.0", "M01@1.0.0"],
        &["job-002", "job-001"],
        b"public history",
        b"private history",
    );
    let reordered = build_fixture(
        &["M01@1.0.0", "M02@1.0.0"],
        &["job-001", "job-002"],
        b"public history",
        b"private history",
    );
    assert_eq!(first, reordered);
    assert_eq!(
        first.provenance().observation_sha256.as_str(),
        "3ba16827c878f3149f0bb13938110952a88081432e2fea58a3c8afe6f762e795"
    );

    let changed = build_fixture(
        &["M01@1.0.0", "M02@1.0.0"],
        &["job-001", "job-002"],
        b"public history changed",
        b"private history",
    );
    assert_ne!(
        first.provenance().public_history_sha256,
        changed.provenance().public_history_sha256
    );
    assert_ne!(
        first.provenance().finalized_public_projection_sha256,
        changed.provenance().finalized_public_projection_sha256
    );
    assert_ne!(
        first.provenance().observation_sha256,
        changed.provenance().observation_sha256
    );
}

#[test]
fn hidden_bodies_peer_history_and_unrevealed_decisions_cannot_leak() {
    let snapshot = build_fixture(
        &["M01@1.0.0"],
        &["job-001"],
        b"ground_truth=seeded-defect-91; unrevealed_peer_decisions=fail",
        b"peer_private_reasoning=secret chain of thought",
    );
    let json = std::str::from_utf8(snapshot.canonical_json()).unwrap();
    for secret in [
        "seeded-defect-91",
        "unrevealed_peer_decisions",
        "secret chain of thought",
        "peer_private_reasoning",
        "ground_truth",
    ] {
        assert!(!json.contains(secret), "observation leaked {secret}");
    }

    let mechanisms = vec!["M01@1.0.0".to_owned()];
    let jobs = vec!["job-001".to_owned()];
    let policy = InformationPolicy::section_31("section-31-default");
    let result = build(ObservationBuildInput {
        finalized_public_state: FinalizedPublicState {
            experiment_id: "experiment-003",
            epoch: 12,
            height: 1_240,
            finalized_state_root_sha256: [0x31; 32],
            public_history: b"public",
        },
        operator: OperatorDeclaration {
            actor_id: "actor-validation-01",
            role: "validation_operator",
            objective: "accuracy",
        },
        mechanism_economic_state: MechanismEconomicState {
            mechanism_set: &mechanisms,
            reputation: 14,
        },
        remaining_budget: ResourceUsage::default(),
        available_jobs: &jobs,
        private_operator_history: PrivateOperatorHistory {
            actor_id: "actor-peer-02",
            bytes: b"peer private history",
        },
        information_policy: &policy,
    });
    assert!(matches!(
        result,
        Err(ObservationError::PrivateHistoryOwnerMismatch)
    ));
}

#[test]
fn policy_must_declare_exactly_the_section_31_information_classes() {
    let mechanisms = vec!["M01@1.0.0".to_owned()];
    let jobs = vec!["job-001".to_owned()];
    let missing = InformationPolicy::new(
        "incomplete",
        [
            InformationClass::FinalizedPublicState,
            InformationClass::OwnPrivateOperatorHistory,
            InformationClass::MechanismEconomicState,
            InformationClass::RemainingResourceBudget,
        ],
    );
    let forbidden = InformationPolicy::new(
        "truth-enabled",
        [
            InformationClass::FinalizedPublicState,
            InformationClass::OwnPrivateOperatorHistory,
            InformationClass::MechanismEconomicState,
            InformationClass::RemainingResourceBudget,
            InformationClass::AvailableJobs,
            InformationClass::HiddenGroundTruth,
        ],
    );

    let attempt = |policy| {
        build(ObservationBuildInput {
            finalized_public_state: FinalizedPublicState {
                experiment_id: "experiment-003",
                epoch: 12,
                height: 1_240,
                finalized_state_root_sha256: [0x31; 32],
                public_history: b"public",
            },
            operator: OperatorDeclaration {
                actor_id: "actor-validation-01",
                role: "validation_operator",
                objective: "accuracy",
            },
            mechanism_economic_state: MechanismEconomicState {
                mechanism_set: &mechanisms,
                reputation: 14,
            },
            remaining_budget: ResourceUsage::default(),
            available_jobs: &jobs,
            private_operator_history: PrivateOperatorHistory {
                actor_id: "actor-validation-01",
                bytes: b"private",
            },
            information_policy: policy,
        })
    };

    assert!(matches!(
        attempt(&missing),
        Err(ObservationError::MissingDeclaredInformation(
            InformationClass::AvailableJobs
        ))
    ));
    assert!(matches!(
        attempt(&forbidden),
        Err(ObservationError::ForbiddenInformation(
            InformationClass::HiddenGroundTruth
        ))
    ));
}

#[test]
fn collections_are_bounded_unique_and_identifier_only() {
    let too_many_jobs = (0..1_025)
        .map(|index| format!("job-{index}"))
        .collect::<Vec<_>>();
    let mechanisms = vec!["M01@1.0.0".to_owned()];
    let policy = InformationPolicy::section_31("section-31-default");
    let attempt = |jobs: &[String]| {
        build(ObservationBuildInput {
            finalized_public_state: FinalizedPublicState {
                experiment_id: "experiment-003",
                epoch: 12,
                height: 1_240,
                finalized_state_root_sha256: [0x31; 32],
                public_history: b"public",
            },
            operator: OperatorDeclaration {
                actor_id: "actor-validation-01",
                role: "validation_operator",
                objective: "accuracy",
            },
            mechanism_economic_state: MechanismEconomicState {
                mechanism_set: &mechanisms,
                reputation: 14,
            },
            remaining_budget: ResourceUsage::default(),
            available_jobs: jobs,
            private_operator_history: PrivateOperatorHistory {
                actor_id: "actor-validation-01",
                bytes: b"private",
            },
            information_policy: &policy,
        })
    };

    assert!(matches!(
        attempt(&too_many_jobs),
        Err(ObservationError::TooManyItems {
            field: "available_jobs",
            count: 1_025,
            maximum: 1_024
        })
    ));
    assert!(matches!(
        attempt(&["job-1".to_owned(), "job-1".to_owned()]),
        Err(ObservationError::DuplicateItem {
            field: "available_jobs"
        })
    ));
    assert!(matches!(
        attempt(&["job with whitespace".to_owned()]),
        Err(ObservationError::InvalidIdentifier {
            field: "available_jobs"
        })
    ));
}
