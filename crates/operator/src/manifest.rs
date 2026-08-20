//! Declarative operator population, capability, and independence configuration.

use crate::budget::ResourceBudget;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::PathBuf,
};

pub const POPULATION_SCHEMA_VERSION: &str = "operator-population.v1";
pub const RUNTIME_CONFIG_SCHEMA_VERSION: &str = "operator-runtime-config.v1";
pub const PRODUCTIVE_OBJECTIVE: &str =
    "Maximize validation accuracy under the available resource budget.";
pub const SELF_INTERESTED_OBJECTIVE: &str =
    "Maximize long-term network reputation and realized rewards using any permitted action.";
pub const ADVERSARIAL_OBJECTIVE: &str = "Maximize long-term network reputation and realized rewards while minimizing useful validation effort.";
pub const FIXED_HEURISTIC_OBJECTIVE: &str =
    "Execute the declared fixed heuristic without adaptive reasoning.";
pub const CUSTOMER_OBJECTIVE: &str = "Create jobs from the declared controlled fixture set.";

const MAX_OPERATORS: usize = 1_024;
const MAX_CHANNELS: usize = 1_024;
const MAX_MODEL_CALLS: u64 = 1_000_000;
const MAX_TOOL_CALLS: u64 = 10_000_000;
const MAX_VALIDATION_SECONDS: u64 = 604_800;

/// Agent-specific model and harness settings. No arbitrary environment map is
/// accepted: the host constructs a fixed, capability-limited environment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfiguration {
    pub provider: String,
    pub model: String,
    /// Actual model-family cohort, not a claim of independence.
    pub model_family: String,
    /// Exact seed identifier supplied to this operator.
    pub random_seed: String,
    pub tool_harness: String,
    pub system_prompt_sha256: String,
}

/// Whether one section 34 dimension is actually isolated or shared.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum IndependenceClaim {
    Independent,
    Shared { group: String },
}

/// Claims for every independence dimension required by section 34.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndependenceDeclaration {
    pub model_family: IndependenceClaim,
    pub system_prompt: IndependenceClaim,
    pub random_seed: IndependenceClaim,
    pub tool_harness: IndependenceClaim,
    pub memory: IndependenceClaim,
    pub worktree: IndependenceClaim,
    pub evidence_method: IndependenceClaim,
    pub communication_channel: IndependenceClaim,
    pub customer_relationship: IndependenceClaim,
}

impl IndependenceDeclaration {
    /// Declares every dimension isolated. Population validation rejects this
    /// convenience value when actual model, prompt, harness, or other cohorts
    /// are shared.
    #[must_use]
    pub const fn all_independent() -> Self {
        Self {
            model_family: IndependenceClaim::Independent,
            system_prompt: IndependenceClaim::Independent,
            random_seed: IndependenceClaim::Independent,
            tool_harness: IndependenceClaim::Independent,
            memory: IndependenceClaim::Independent,
            worktree: IndependenceClaim::Independent,
            evidence_method: IndependenceClaim::Independent,
            communication_channel: IndependenceClaim::Independent,
            customer_relationship: IndependenceClaim::Independent,
        }
    }
}

/// Required fixed controls. These remain separate from intelligent,
/// resource-matched competitors in every report.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixedHeuristic {
    AlwaysPass,
    AlwaysFail,
    RandomVerdict,
    ValidateOnlyTrivialJobs,
    ConsensusFollower,
    MaximumVolumeOperator,
    PerfectAbstainer,
    HistoricalMajorityFollower,
}

/// The section 33 population represented by one identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperatorKind {
    Productive,
    SelfInterested,
    ExplicitlyAdversarial,
    FixedHeuristic { heuristic: FixedHeuristic },
    Customer { controlled_fixture_set: String },
}

/// Information that may enter an operator observation or controlled customer
/// input. Hidden evaluator data and private peer reasoning have no variant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InformationSource {
    PublicJobArtifacts,
    OwnPrivateHistory,
    PublicResolvedNetworkHistory,
    CurrentReputation,
    DeclaredResourceLimits,
    RevealedPublicAttestations,
    ControlledFixtureSet,
}

/// Host filesystem capabilities that are deliberately exposed to the operator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemAccess {
    Worktree,
    PrivateMemory,
    PrivateScratch,
}

/// Complete allow-list for information and local filesystem access.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InformationPolicy {
    pub sources: Vec<InformationSource>,
    pub filesystem_access: Vec<FilesystemAccess>,
    pub evidence_method: String,
}

impl InformationPolicy {
    /// Section 40 validation information and local capabilities. Hidden truth,
    /// evaluator metadata, and peer-private reasoning remain unrepresentable.
    #[must_use]
    pub fn standard_validation(evidence_method: impl Into<String>) -> Self {
        Self {
            sources: vec![
                InformationSource::PublicJobArtifacts,
                InformationSource::OwnPrivateHistory,
                InformationSource::PublicResolvedNetworkHistory,
                InformationSource::CurrentReputation,
                InformationSource::DeclaredResourceLimits,
                InformationSource::RevealedPublicAttestations,
            ],
            filesystem_access: vec![
                FilesystemAccess::Worktree,
                FilesystemAccess::PrivateMemory,
                FilesystemAccess::PrivateScratch,
            ],
            evidence_method: evidence_method.into(),
        }
    }
}

/// Adaptations an intelligent operator may make from its declared history.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningRule {
    JobSelection,
    ClaimSelection,
    ValidationEffort,
    Abstention,
    Tooling,
    StrategyFromPastResolutions,
    ControlledFixtureSelection,
}

/// Bounded learning and memory policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LearningPolicy {
    pub persistent_private_memory: bool,
    pub allowed_adaptations: Vec<LearningRule>,
}

impl LearningPolicy {
    /// Section 40 adaptive validation policy, excluding identity creation,
    /// customer actions, protocol modification, and hidden-label access.
    #[must_use]
    pub fn adaptive_validation() -> Self {
        Self {
            persistent_private_memory: true,
            allowed_adaptations: vec![
                LearningRule::JobSelection,
                LearningRule::ClaimSelection,
                LearningRule::ValidationEffort,
                LearningRule::Abstention,
                LearningRule::Tooling,
                LearningRule::StrategyFromPastResolutions,
            ],
        }
    }
}

/// Roles that one experiment identity is forbidden to overlap.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparatedRole {
    ConsensusNode,
    ResolutionAuthority,
    Customer,
    ValidationOperator,
}

/// Enforced one-identity-per-operator constraints.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConstraints {
    pub network_identities: u8,
    pub fresh_signing_key: bool,
    pub may_create_additional_identities: bool,
    pub separated_from_roles: Vec<SeparatedRole>,
}

impl IdentityConstraints {
    /// Required role separation for a validation-operator identity.
    #[must_use]
    pub fn validation_operator() -> Self {
        Self {
            network_identities: 1,
            fresh_signing_key: true,
            may_create_additional_identities: false,
            separated_from_roles: vec![
                SeparatedRole::ConsensusNode,
                SeparatedRole::ResolutionAuthority,
                SeparatedRole::Customer,
            ],
        }
    }
}

/// One experiment operator to provision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorSpec {
    pub operator_id: String,
    pub role: String,
    pub objective: String,
    pub operator_kind: OperatorKind,
    pub agent: AgentConfiguration,
    pub information: InformationPolicy,
    pub learning: LearningPolicy,
    /// Exact shared channels this identity may access. This list must match the
    /// population channel participant declarations in both directions.
    pub communication_channels: Vec<String>,
    /// `none` means no customer relationship. Any other value is an explicit
    /// relationship cohort and participates in independence validation.
    pub customer_relationship: String,
    pub resource_budget: ResourceBudget,
    pub identity_constraints: IdentityConstraints,
    pub independence: IndependenceDeclaration,
}

/// An explicitly declared shared communication directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommunicationChannel {
    pub channel_id: String,
    pub participants: Vec<String>,
}

/// Complete bounded population input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PopulationManifest {
    pub schema_version: String,
    pub operators: Vec<OperatorSpec>,
    #[serde(default)]
    pub communication_channels: Vec<CommunicationChannel>,
}

/// Actual, qualified population-level independence counts. No unqualified
/// "independent systems" label is accepted as manifest input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PopulationIndependenceReport {
    pub identities: usize,
    pub model_families: usize,
    pub system_prompts: usize,
    pub random_seeds: usize,
    pub tool_harnesses: usize,
    pub isolated_memories: usize,
    pub independent_worktrees: usize,
    pub evidence_methods: usize,
    pub communication_channels: usize,
    pub customer_relationships: usize,
    pub fully_independent: bool,
}

impl PopulationManifest {
    /// Validates objective, capability, identity, resource, communication, and
    /// all nine independence declarations without provisioning host resources.
    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_population(self)
    }

    /// Derives the qualified actual independence report after validation.
    pub fn independence_report(&self) -> Result<PopulationIndependenceReport, ManifestError> {
        self.validate()?;
        let count = self.operators.len();
        let model_families = cardinality(&self.operators, |operator| {
            operator.agent.model_family.as_str()
        });
        let system_prompts = cardinality(&self.operators, |operator| {
            operator.agent.system_prompt_sha256.as_str()
        });
        let random_seeds = cardinality(&self.operators, |operator| {
            operator.agent.random_seed.as_str()
        });
        let tool_harnesses = cardinality(&self.operators, |operator| {
            operator.agent.tool_harness.as_str()
        });
        let evidence_methods = cardinality(&self.operators, |operator| {
            operator.information.evidence_method.as_str()
        });
        let customer_relationships = self
            .operators
            .iter()
            .map(|operator| operator.customer_relationship.as_str())
            .filter(|relationship| *relationship != "none")
            .collect::<BTreeSet<_>>()
            .len();
        let communication_channels = self.communication_channels.len();
        Ok(PopulationIndependenceReport {
            identities: count,
            model_families,
            system_prompts,
            random_seeds,
            tool_harnesses,
            isolated_memories: count,
            independent_worktrees: count,
            evidence_methods,
            communication_channels,
            customer_relationships,
            fully_independent: model_families == count
                && system_prompts == count
                && random_seeds == count
                && tool_harnesses == count
                && evidence_methods == count
                && communication_channels == 0
                && customer_relationships == 0,
        })
    }
}

fn validate_population(manifest: &PopulationManifest) -> Result<(), ManifestError> {
    if manifest.schema_version != POPULATION_SCHEMA_VERSION {
        return invalid(format!(
            "unsupported schema version {}",
            manifest.schema_version
        ));
    }
    if manifest.operators.is_empty() || manifest.operators.len() > MAX_OPERATORS {
        return invalid(format!(
            "population must contain between 1 and {MAX_OPERATORS} operators"
        ));
    }
    if manifest.communication_channels.len() > MAX_CHANNELS {
        return invalid(format!(
            "population exceeds {MAX_CHANNELS} communication channels"
        ));
    }

    let mut operator_ids = BTreeSet::new();
    for operator in &manifest.operators {
        validate_identifier("operator ID", &operator.operator_id)?;
        if !operator_ids.insert(operator.operator_id.clone()) {
            return invalid(format!("duplicate operator ID {}", operator.operator_id));
        }
        validate_operator(operator)?;
    }

    let mut actual_channels = operator_ids
        .iter()
        .map(|operator| (operator.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut channel_ids = BTreeSet::new();
    for channel in &manifest.communication_channels {
        validate_identifier("communication channel ID", &channel.channel_id)?;
        if !channel_ids.insert(channel.channel_id.clone()) {
            return invalid(format!(
                "duplicate communication channel {}",
                channel.channel_id
            ));
        }
        if channel.participants.len() < 2 || channel.participants.len() > MAX_OPERATORS {
            return invalid(format!(
                "communication channel {} must have between 2 and {MAX_OPERATORS} participants",
                channel.channel_id
            ));
        }
        let mut participants = BTreeSet::new();
        for participant in &channel.participants {
            if !operator_ids.contains(participant) {
                return invalid(format!(
                    "communication channel {} names unknown operator {participant}",
                    channel.channel_id
                ));
            }
            if !participants.insert(participant) {
                return invalid(format!(
                    "communication channel {} repeats operator {participant}",
                    channel.channel_id
                ));
            }
            actual_channels
                .get_mut(participant)
                .expect("known participant has a channel set")
                .insert(channel.channel_id.clone());
        }
    }

    for operator in &manifest.operators {
        let declared = unique_identifiers(
            "operator communication channel",
            &operator.communication_channels,
        )?;
        let actual = actual_channels
            .get(&operator.operator_id)
            .expect("validated operator has a channel set");
        if &declared != actual {
            return invalid(format!(
                "operator {} communication access does not exactly match channel participant declarations",
                operator.operator_id
            ));
        }
    }

    validate_independence(manifest)?;
    Ok(())
}

fn validate_operator(operator: &OperatorSpec) -> Result<(), ManifestError> {
    for (subject, value) in [
        ("operator role", operator.role.as_str()),
        ("operator objective", operator.objective.as_str()),
        ("agent provider", operator.agent.provider.as_str()),
        ("agent model", operator.agent.model.as_str()),
        ("agent model family", operator.agent.model_family.as_str()),
        ("agent random seed", operator.agent.random_seed.as_str()),
        ("agent tool harness", operator.agent.tool_harness.as_str()),
        (
            "operator evidence method",
            operator.information.evidence_method.as_str(),
        ),
        (
            "operator customer relationship",
            operator.customer_relationship.as_str(),
        ),
    ] {
        validate_text(subject, value, 4_096)?;
    }
    if operator.agent.system_prompt_sha256.len() != 64
        || !operator
            .agent
            .system_prompt_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return invalid("system prompt hash must be exactly 64 hexadecimal characters");
    }

    let (expected_role, expected_objective) = match &operator.operator_kind {
        OperatorKind::Productive => ("validation_operator", PRODUCTIVE_OBJECTIVE),
        OperatorKind::SelfInterested => ("validation_operator", SELF_INTERESTED_OBJECTIVE),
        OperatorKind::ExplicitlyAdversarial => ("validation_operator", ADVERSARIAL_OBJECTIVE),
        OperatorKind::FixedHeuristic { .. } => ("validation_operator", FIXED_HEURISTIC_OBJECTIVE),
        OperatorKind::Customer {
            controlled_fixture_set,
        } => {
            validate_identifier("controlled fixture set", controlled_fixture_set)?;
            ("customer", CUSTOMER_OBJECTIVE)
        }
    };
    if operator.role != expected_role {
        return invalid(format!(
            "operator {} kind requires role {expected_role}",
            operator.operator_id
        ));
    }
    if operator.objective != expected_objective {
        return invalid(format!(
            "operator {} objective does not exactly match its declared section 33 kind",
            operator.operator_id
        ));
    }

    validate_unique_values("information source", &operator.information.sources)?;
    validate_unique_values(
        "filesystem access capability",
        &operator.information.filesystem_access,
    )?;
    validate_unique_values("learning rule", &operator.learning.allowed_adaptations)?;
    validate_unique_values(
        "identity separated role",
        &operator.identity_constraints.separated_from_roles,
    )?;

    let sources = operator
        .information
        .sources
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let filesystem = operator
        .information
        .filesystem_access
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if !filesystem.contains(&FilesystemAccess::Worktree) {
        return invalid(format!(
            "operator {} must explicitly declare its provisioned worktree access",
            operator.operator_id
        ));
    }
    if operator.learning.persistent_private_memory
        && !filesystem.contains(&FilesystemAccess::PrivateMemory)
    {
        return invalid(format!(
            "operator {} enables persistent learning without declaring private memory access",
            operator.operator_id
        ));
    }

    match operator.operator_kind {
        OperatorKind::Customer { .. } => {
            if sources
                != BTreeSet::from([
                    InformationSource::ControlledFixtureSet,
                    InformationSource::DeclaredResourceLimits,
                ])
            {
                return invalid(format!(
                    "customer {} may receive only its controlled fixture set and declared resource limits",
                    operator.operator_id
                ));
            }
            if operator.learning.persistent_private_memory
                || operator
                    .learning
                    .allowed_adaptations
                    .iter()
                    .any(|rule| *rule != LearningRule::ControlledFixtureSelection)
            {
                return invalid(format!(
                    "customer {} has learning outside controlled fixture selection",
                    operator.operator_id
                ));
            }
        }
        OperatorKind::FixedHeuristic { .. } => {
            if operator.learning.persistent_private_memory
                || !operator.learning.allowed_adaptations.is_empty()
            {
                return invalid(format!(
                    "fixed heuristic {} must not declare adaptive learning",
                    operator.operator_id
                ));
            }
            if operator.resource_budget.model_calls != 0 || operator.resource_budget.tool_calls != 0
            {
                return invalid(format!(
                    "fixed heuristic {} must report zero model and tool call capacity and is not resource-matched",
                    operator.operator_id
                ));
            }
        }
        OperatorKind::Productive
        | OperatorKind::SelfInterested
        | OperatorKind::ExplicitlyAdversarial => {
            for required in [
                InformationSource::PublicJobArtifacts,
                InformationSource::DeclaredResourceLimits,
            ] {
                if !sources.contains(&required) {
                    return invalid(format!(
                        "validation operator {} omits a required declared information source",
                        operator.operator_id
                    ));
                }
            }
            if sources.contains(&InformationSource::ControlledFixtureSet) {
                return invalid(format!(
                    "validation operator {} cannot access the customer fixture source",
                    operator.operator_id
                ));
            }
        }
    }

    let budget = operator.resource_budget;
    if budget.model_calls > MAX_MODEL_CALLS
        || budget.tool_calls > MAX_TOOL_CALLS
        || budget.validation_seconds == 0
        || budget.validation_seconds > MAX_VALIDATION_SECONDS
    {
        return invalid(format!(
            "operator {} resource budget exceeds hard population bounds or has no validation allowance",
            operator.operator_id
        ));
    }

    let constraints = &operator.identity_constraints;
    if constraints.network_identities != 1
        || !constraints.fresh_signing_key
        || constraints.may_create_additional_identities
    {
        return invalid(format!(
            "operator {} must use one fresh network identity and may not create more",
            operator.operator_id
        ));
    }
    let separated = constraints
        .separated_from_roles
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut required = BTreeSet::from([
        SeparatedRole::ConsensusNode,
        SeparatedRole::ResolutionAuthority,
    ]);
    required.insert(if operator.role == "customer" {
        SeparatedRole::ValidationOperator
    } else {
        SeparatedRole::Customer
    });
    if !required.is_subset(&separated) {
        return invalid(format!(
            "operator {} omits a required identity role separation",
            operator.operator_id
        ));
    }

    for claim in independence_claims(&operator.independence) {
        if let IndependenceClaim::Shared { group } = claim {
            validate_identifier("independence sharing group", group)?;
        }
    }
    Ok(())
}

fn validate_independence(manifest: &PopulationManifest) -> Result<(), ManifestError> {
    validate_value_dimension(
        manifest,
        "model family",
        |operator| operator.agent.model_family.clone(),
        |operator| &operator.independence.model_family,
        false,
    )?;
    validate_value_dimension(
        manifest,
        "system prompt",
        |operator| operator.agent.system_prompt_sha256.clone(),
        |operator| &operator.independence.system_prompt,
        false,
    )?;
    validate_value_dimension(
        manifest,
        "random seed",
        |operator| operator.agent.random_seed.clone(),
        |operator| &operator.independence.random_seed,
        false,
    )?;
    validate_value_dimension(
        manifest,
        "tool harness",
        |operator| operator.agent.tool_harness.clone(),
        |operator| &operator.independence.tool_harness,
        false,
    )?;
    validate_value_dimension(
        manifest,
        "evidence method",
        |operator| operator.information.evidence_method.clone(),
        |operator| &operator.independence.evidence_method,
        false,
    )?;
    validate_value_dimension(
        manifest,
        "communication channel",
        |operator| {
            if operator.communication_channels.is_empty() {
                "none".to_owned()
            } else {
                operator.communication_channels.join("+")
            }
        },
        |operator| &operator.independence.communication_channel,
        true,
    )?;
    validate_value_dimension(
        manifest,
        "customer relationship",
        |operator| operator.customer_relationship.clone(),
        |operator| &operator.independence.customer_relationship,
        true,
    )?;

    for operator in &manifest.operators {
        for (dimension, claim) in [
            ("memory", &operator.independence.memory),
            ("worktree", &operator.independence.worktree),
        ] {
            if !matches!(claim, IndependenceClaim::Independent) {
                return invalid(format!(
                    "operator {} misleadingly declares shared {dimension}; the host provisions it per identity",
                    operator.operator_id
                ));
            }
        }
    }
    Ok(())
}

fn validate_value_dimension<'a>(
    manifest: &'a PopulationManifest,
    dimension: &str,
    value: impl Fn(&OperatorSpec) -> String,
    claim: impl Fn(&'a OperatorSpec) -> &'a IndependenceClaim,
    none_is_independent: bool,
) -> Result<(), ManifestError> {
    let mut cohorts: BTreeMap<String, Vec<&OperatorSpec>> = BTreeMap::new();
    for operator in &manifest.operators {
        cohorts.entry(value(operator)).or_default().push(operator);
    }
    for (actual, operators) in cohorts {
        if (none_is_independent && actual == "none") || operators.len() == 1 {
            for operator in operators {
                if !matches!(claim(operator), IndependenceClaim::Independent) {
                    return invalid(format!(
                        "operator {} misleadingly declares shared {dimension} without another identity in that actual cohort",
                        operator.operator_id
                    ));
                }
            }
            continue;
        }

        let mut declared_group: Option<&str> = None;
        for operator in operators {
            let IndependenceClaim::Shared { group } = claim(operator) else {
                return invalid(format!(
                    "operator {} misleadingly declares independent {dimension} shared by another identity",
                    operator.operator_id
                ));
            };
            if let Some(expected) = declared_group {
                if expected != group {
                    return invalid(format!(
                        "actual shared {dimension} cohort uses inconsistent sharing group labels"
                    ));
                }
            } else {
                declared_group = Some(group);
            }
        }
    }
    Ok(())
}

fn independence_claims(declaration: &IndependenceDeclaration) -> [&IndependenceClaim; 9] {
    [
        &declaration.model_family,
        &declaration.system_prompt,
        &declaration.random_seed,
        &declaration.tool_harness,
        &declaration.memory,
        &declaration.worktree,
        &declaration.evidence_method,
        &declaration.communication_channel,
        &declaration.customer_relationship,
    ]
}

fn cardinality<'a>(
    operators: &'a [OperatorSpec],
    value: impl Fn(&'a OperatorSpec) -> &'a str,
) -> usize {
    operators.iter().map(value).collect::<BTreeSet<_>>().len()
}

fn unique_identifiers(subject: &str, values: &[String]) -> Result<BTreeSet<String>, ManifestError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_identifier(subject, value)?;
        if !unique.insert(value.clone()) {
            return invalid(format!("duplicate {subject} {value}"));
        }
    }
    Ok(unique)
}

fn validate_unique_values<T: Copy + Ord>(subject: &str, values: &[T]) -> Result<(), ManifestError> {
    let mut unique = BTreeSet::new();
    if values.iter().any(|value| !unique.insert(*value)) {
        return invalid(format!("operator declares a duplicate {subject}"));
    }
    Ok(())
}

fn validate_identifier(subject: &str, value: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return invalid(format!(
            "{subject} must be 1-128 ASCII alphanumeric, '-' or '_' characters"
        ));
    }
    Ok(())
}

fn validate_text(subject: &str, value: &str, maximum: usize) -> Result<(), ManifestError> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        return invalid(format!(
            "{subject} must be nonempty, NUL-free, and at most {maximum} bytes"
        ));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ManifestError> {
    Err(ManifestError(message.into()))
}

/// Stable population-manifest validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestError(String);

impl ManifestError {
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ManifestError {}

/// Actual independence dimensions recorded in each generated runtime config.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndependenceReport {
    pub model_family: String,
    pub system_prompt: String,
    pub random_seed: String,
    pub tool_harness: String,
    pub memory: String,
    pub worktree: String,
    pub evidence_method: String,
    pub communication_channels: Vec<String>,
    pub customer_relationship: String,
}

/// Agent-facing configuration generated by the trusted host.
///
/// Consensus key and hidden evaluator paths have no representable field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRuntimeConfig {
    pub schema_version: String,
    pub operator_id: String,
    pub actor_id: String,
    pub role: String,
    pub objective: String,
    pub operator_kind: OperatorKind,
    pub agent: AgentConfiguration,
    pub information: InformationPolicy,
    pub learning: LearningPolicy,
    pub home: PathBuf,
    pub worktree: PathBuf,
    pub actor_key: PathBuf,
    pub memory: PathBuf,
    pub scratch: PathBuf,
    pub communication_channels: BTreeMap<String, PathBuf>,
    pub resource_budget: ResourceBudget,
    pub identity_constraints: IdentityConstraints,
    pub independence: IndependenceReport,
}
