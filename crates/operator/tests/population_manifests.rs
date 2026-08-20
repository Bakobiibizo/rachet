use rachet_operator::manifest::{
    CommunicationChannel, FixedHeuristic, IndependenceClaim, OperatorKind, PopulationManifest,
};
use std::collections::BTreeSet;

const PRODUCTIVE: &str =
    include_str!("../../../configs/experiments/operator-populations/productive.json");
const SELF_INTERESTED: &str =
    include_str!("../../../configs/experiments/operator-populations/self-interested.json");
const ADVERSARIAL: &str =
    include_str!("../../../configs/experiments/operator-populations/explicitly-adversarial.json");
const FIXED: &str =
    include_str!("../../../configs/experiments/operator-populations/fixed-heuristics.json");
const CUSTOMER: &str =
    include_str!("../../../configs/experiments/operator-populations/customer.json");

fn parse(source: &str) -> PopulationManifest {
    serde_json::from_str(source).expect("checked-in population manifest must parse")
}

#[test]
fn every_required_population_manifest_is_valid_and_resource_bounded() {
    let manifests = [
        parse(PRODUCTIVE),
        parse(SELF_INTERESTED),
        parse(ADVERSARIAL),
        parse(FIXED),
        parse(CUSTOMER),
    ];

    for manifest in &manifests {
        manifest.validate().unwrap();
        let report = manifest.independence_report().unwrap();
        assert_eq!(report.identities, manifest.operators.len());
        for operator in &manifest.operators {
            assert!(operator.resource_budget.validation_seconds > 0);
            assert!(operator.resource_budget.validation_seconds <= 604_800);
            assert!(operator.resource_budget.model_calls <= 1_000_000);
            assert!(operator.resource_budget.tool_calls <= 10_000_000);
            assert_eq!(operator.identity_constraints.network_identities, 1);
            assert!(
                !operator
                    .identity_constraints
                    .may_create_additional_identities
            );
        }
    }

    assert!(matches!(
        manifests[0].operators[0].operator_kind,
        OperatorKind::Productive
    ));
    assert!(matches!(
        manifests[1].operators[0].operator_kind,
        OperatorKind::SelfInterested
    ));
    assert!(matches!(
        manifests[2].operators[0].operator_kind,
        OperatorKind::ExplicitlyAdversarial
    ));
    assert!(matches!(
        manifests[4].operators[0].operator_kind,
        OperatorKind::Customer { .. }
    ));

    let fixed = manifests[3]
        .operators
        .iter()
        .map(|operator| match operator.operator_kind {
            OperatorKind::FixedHeuristic { heuristic } => heuristic,
            ref other => panic!("fixed manifest contains {other:?}"),
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fixed,
        BTreeSet::from([
            FixedHeuristic::AlwaysPass,
            FixedHeuristic::AlwaysFail,
            FixedHeuristic::RandomVerdict,
            FixedHeuristic::ValidateOnlyTrivialJobs,
            FixedHeuristic::ConsensusFollower,
            FixedHeuristic::MaximumVolumeOperator,
            FixedHeuristic::PerfectAbstainer,
            FixedHeuristic::HistoricalMajorityFollower,
        ])
    );
    assert!(manifests[3].operators.iter().all(|operator| {
        operator.resource_budget.model_calls == 0
            && operator.resource_budget.tool_calls == 0
            && !operator.learning.persistent_private_memory
            && operator.learning.allowed_adaptations.is_empty()
    }));
}

#[test]
fn undeclared_or_asymmetric_sharing_is_rejected() {
    let mut manifest = parse(PRODUCTIVE);
    let mut second = manifest.operators[0].clone();
    second.operator_id = "productive-002".to_owned();
    second.agent.model = "productive-validator-002".to_owned();
    second.agent.model_family = "productive-validator-002".to_owned();
    second.agent.random_seed = "productive-seed-002".to_owned();
    second.agent.system_prompt_sha256 = "55".repeat(32);
    manifest.operators.push(second);
    manifest.communication_channels.push(CommunicationChannel {
        channel_id: "private-coordination".to_owned(),
        participants: vec!["productive-001".to_owned(), "productive-002".to_owned()],
    });

    let error = manifest.validate().unwrap_err();
    assert!(error.message().contains("communication access"));

    let mut manifest = parse(PRODUCTIVE);
    manifest.operators[0]
        .communication_channels
        .push("undeclared-channel".to_owned());
    let error = manifest.validate().unwrap_err();
    assert!(error.message().contains("communication access"));
}

#[test]
fn misleading_independence_and_identity_claims_are_rejected() {
    let mut manifest = parse(FIXED);
    manifest.operators[0].independence.model_family = IndependenceClaim::Independent;
    let error = manifest.validate().unwrap_err();
    assert!(error.message().contains("independent model family"));

    let mut manifest = parse(FIXED);
    manifest.operators[0].independence.memory = IndependenceClaim::Shared {
        group: "fake-shared-memory".to_owned(),
    };
    let error = manifest.validate().unwrap_err();
    assert!(
        error
            .message()
            .contains("misleadingly declares shared memory")
    );

    let mut manifest = parse(PRODUCTIVE);
    manifest.operators[0]
        .identity_constraints
        .may_create_additional_identities = true;
    let error = manifest.validate().unwrap_err();
    assert!(error.message().contains("may not create more"));
}

#[test]
fn objectives_and_resource_bounds_are_not_advisory() {
    let mut manifest = parse(SELF_INTERESTED);
    manifest.operators[0].objective = "Validate honestly.".to_owned();
    let error = manifest.validate().unwrap_err();
    assert!(error.message().contains("objective does not exactly match"));

    let mut manifest = parse(ADVERSARIAL);
    manifest.operators[0].resource_budget.validation_seconds = u64::MAX;
    let error = manifest.validate().unwrap_err();
    assert!(error.message().contains("resource budget"));
}
