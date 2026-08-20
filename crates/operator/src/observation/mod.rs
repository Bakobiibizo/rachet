//! Bounded, hash-stable `operator-observation.v1` snapshots.
//!
//! The trusted host projects only declared information into this module. Source
//! history bodies are represented in the observation by content-addressed
//! references and are never copied into agent-facing JSON.

use crate::budget::ResourceUsage;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, error::Error, fmt};

pub const OBSERVATION_SCHEMA_VERSION: &str = "operator-observation.v1";
pub const VALIDATION_OPERATOR_ROLE: &str = "validation_operator";
pub const MAX_MECHANISMS: usize = 128;
pub const MAX_AVAILABLE_JOBS: usize = 1_024;
pub const MAX_REFERENCED_HISTORY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_OBSERVATION_BYTES: usize = 256 * 1024;

const MAX_IDENTIFIER_CHARS: usize = 128;
const MAX_OBJECTIVE_CHARS: usize = 4_096;

/// One information class that a host policy can declare.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InformationClass {
    FinalizedPublicState,
    OwnPrivateOperatorHistory,
    MechanismEconomicState,
    RemainingResourceBudget,
    AvailableJobs,
    HiddenGroundTruth,
    PeerPrivateReasoning,
    UnrevealedPeerDecisions,
}

impl InformationClass {
    const fn name(self) -> &'static str {
        match self {
            Self::FinalizedPublicState => "finalized_public_state",
            Self::OwnPrivateOperatorHistory => "own_private_operator_history",
            Self::MechanismEconomicState => "mechanism_economic_state",
            Self::RemainingResourceBudget => "remaining_resource_budget",
            Self::AvailableJobs => "available_jobs",
            Self::HiddenGroundTruth => "hidden_ground_truth",
            Self::PeerPrivateReasoning => "peer_private_reasoning",
            Self::UnrevealedPeerDecisions => "unrevealed_peer_decisions",
        }
    }
}

const REQUIRED_INFORMATION: [InformationClass; 5] = [
    InformationClass::FinalizedPublicState,
    InformationClass::OwnPrivateOperatorHistory,
    InformationClass::MechanismEconomicState,
    InformationClass::RemainingResourceBudget,
    InformationClass::AvailableJobs,
];

/// Auditable declaration of the information permitted at one decision point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InformationPolicy {
    policy_id: String,
    permitted: BTreeSet<InformationClass>,
}

impl InformationPolicy {
    /// Constructs a declaration. The builder enforces the exact v1 class set.
    pub fn new(
        policy_id: impl Into<String>,
        permitted: impl IntoIterator<Item = InformationClass>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            permitted: permitted.into_iter().collect(),
        }
    }

    /// The exact information policy required by section 31.
    pub fn section_31(policy_id: impl Into<String>) -> Self {
        Self::new(policy_id, REQUIRED_INFORMATION)
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn permits(&self, class: InformationClass) -> bool {
        self.permitted.contains(&class)
    }
}

/// Finalized public decision-point metadata and its public history body.
///
/// `finalized_state_root_sha256` must be the root reported by finalized chain
/// storage. The history body is hashed exactly and is not serialized into the
/// observation.
pub struct FinalizedPublicState<'a> {
    pub experiment_id: &'a str,
    pub epoch: u64,
    pub height: u64,
    pub finalized_state_root_sha256: [u8; 32],
    pub public_history: &'a [u8],
}

/// The validation operator identity and declared objective.
pub struct OperatorDeclaration<'a> {
    pub actor_id: &'a str,
    pub role: &'a str,
    pub objective: &'a str,
}

/// Mechanism and economic projection visible to this operator.
pub struct MechanismEconomicState<'a> {
    pub mechanism_set: &'a [String],
    pub reputation: i64,
}

/// Private history belonging to exactly one operator.
pub struct PrivateOperatorHistory<'a> {
    pub actor_id: &'a str,
    pub bytes: &'a [u8],
}

/// Complete trusted-host input for one observation build.
pub struct ObservationBuildInput<'a> {
    pub finalized_public_state: FinalizedPublicState<'a>,
    pub operator: OperatorDeclaration<'a>,
    pub mechanism_economic_state: MechanismEconomicState<'a>,
    pub remaining_budget: ResourceUsage,
    pub available_jobs: &'a [String],
    pub private_operator_history: PrivateOperatorHistory<'a>,
    pub information_policy: &'a InformationPolicy,
}

/// Lowercase SHA-256 of exact canonical bytes.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProvenanceHash(String);

impl ProvenanceHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn digest(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            use fmt::Write as _;
            write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        Self(encoded)
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut encoded = String::with_capacity(64);
        for byte in bytes {
            use fmt::Write as _;
            write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        Self(encoded)
    }

    fn content_ref(&self) -> String {
        format!("sha256:{}", self.0)
    }
}

impl fmt::Display for ProvenanceHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Host-side provenance sidecar for every source projection and final snapshot.
///
/// This sidecar is retained with the observation trace; it is deliberately not
/// embedded in the strict section 31 JSON contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationProvenance {
    pub finalized_state_root_sha256: ProvenanceHash,
    pub finalized_public_projection_sha256: ProvenanceHash,
    pub operator_declaration_sha256: ProvenanceHash,
    pub public_history_sha256: ProvenanceHash,
    pub private_operator_history_sha256: ProvenanceHash,
    pub mechanism_economic_state_sha256: ProvenanceHash,
    pub remaining_resource_budget_sha256: ProvenanceHash,
    pub available_jobs_sha256: ProvenanceHash,
    pub information_policy_sha256: ProvenanceHash,
    pub observation_sha256: ProvenanceHash,
}

/// The strict agent-facing section 31 JSON value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorObservation {
    schema_version: String,
    experiment_id: String,
    epoch: u64,
    height: u64,
    operator: ObservationOperator,
    economic_state: ObservationEconomicState,
    resource_budget: ObservationResourceBudget,
    available_jobs: Vec<String>,
    public_history_ref: String,
    private_operator_history_ref: String,
}

impl OperatorObservation {
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn experiment_id(&self) -> &str {
        &self.experiment_id
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub fn actor_id(&self) -> &str {
        &self.operator.actor_id
    }

    pub fn available_jobs(&self) -> &[String] {
        &self.available_jobs
    }

    pub fn public_history_ref(&self) -> &str {
        &self.public_history_ref
    }

    pub fn private_operator_history_ref(&self) -> &str {
        &self.private_operator_history_ref
    }

    /// Exact remaining allowance advertised to the external operator.
    #[must_use]
    pub const fn remaining_budget(&self) -> ResourceUsage {
        ResourceUsage {
            model_calls: self.resource_budget.remaining_model_calls,
            tool_calls: self.resource_budget.remaining_tool_calls,
            validation_seconds: self.resource_budget.remaining_validation_seconds,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservationOperator {
    actor_id: String,
    role: String,
    objective: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservationEconomicState {
    mechanism_set: Vec<String>,
    reputation: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservationResourceBudget {
    remaining_model_calls: u64,
    remaining_tool_calls: u64,
    remaining_validation_seconds: u64,
}

/// Immutable observation JSON and its exact provenance sidecar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationSnapshot {
    observation: OperatorObservation,
    canonical_json: Vec<u8>,
    provenance: ObservationProvenance,
}

impl ObservationSnapshot {
    pub const fn observation(&self) -> &OperatorObservation {
        &self.observation
    }

    /// Exact compact JSON bytes covered by `observation_sha256`.
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }

    pub const fn provenance(&self) -> &ObservationProvenance {
        &self.provenance
    }

    /// Restores a previously captured observation only when its JSON is the
    /// exact canonical encoding committed by its provenance sidecar.
    pub fn from_captured(
        canonical_json: Vec<u8>,
        provenance: ObservationProvenance,
    ) -> Result<Self, ObservationError> {
        if canonical_json.len() > MAX_OBSERVATION_BYTES {
            return Err(ObservationError::ObservationTooLarge {
                bytes: canonical_json.len(),
                maximum: MAX_OBSERVATION_BYTES,
            });
        }
        let observation: OperatorObservation =
            serde_json::from_slice(&canonical_json).map_err(|_| ObservationError::Serialization)?;
        if observation.schema_version != OBSERVATION_SCHEMA_VERSION
            || serde_json::to_vec(&observation).map_err(|_| ObservationError::Serialization)?
                != canonical_json
        {
            return Err(ObservationError::CapturedObservationInvalid);
        }
        if provenance.observation_sha256 != ProvenanceHash::digest(&canonical_json)
            || !provenance.hashes_are_valid()
        {
            return Err(ObservationError::CapturedObservationHashMismatch);
        }
        Ok(Self {
            observation,
            canonical_json,
            provenance,
        })
    }
}

impl ObservationProvenance {
    fn hashes_are_valid(&self) -> bool {
        [
            &self.finalized_state_root_sha256,
            &self.finalized_public_projection_sha256,
            &self.operator_declaration_sha256,
            &self.public_history_sha256,
            &self.private_operator_history_sha256,
            &self.mechanism_economic_state_sha256,
            &self.remaining_resource_budget_sha256,
            &self.available_jobs_sha256,
            &self.information_policy_sha256,
            &self.observation_sha256,
        ]
        .into_iter()
        .all(|hash| {
            hash.0.len() == 64
                && hash
                    .0
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    }
}

/// Builds one bounded observation and hashes every exact source projection.
pub fn build(input: ObservationBuildInput<'_>) -> Result<ObservationSnapshot, ObservationError> {
    validate_identifier("experiment_id", input.finalized_public_state.experiment_id)?;
    validate_identifier("operator.actor_id", input.operator.actor_id)?;
    validate_identifier(
        "private_operator_history.actor_id",
        input.private_operator_history.actor_id,
    )?;
    validate_identifier(
        "information_policy.policy_id",
        input.information_policy.policy_id(),
    )?;
    if input.operator.role != VALIDATION_OPERATOR_ROLE {
        return Err(ObservationError::InvalidRole);
    }
    validate_objective(input.operator.objective)?;
    if input.private_operator_history.actor_id != input.operator.actor_id {
        return Err(ObservationError::PrivateHistoryOwnerMismatch);
    }
    validate_history(
        "public_history",
        input.finalized_public_state.public_history,
    )?;
    validate_history(
        "private_operator_history",
        input.private_operator_history.bytes,
    )?;
    validate_policy(input.information_policy)?;

    let mechanism_set = bounded_identifiers(
        "economic_state.mechanism_set",
        input.mechanism_economic_state.mechanism_set,
        MAX_MECHANISMS,
    )?;
    let available_jobs =
        bounded_identifiers("available_jobs", input.available_jobs, MAX_AVAILABLE_JOBS)?;

    let operator = ObservationOperator {
        actor_id: input.operator.actor_id.to_owned(),
        role: input.operator.role.to_owned(),
        objective: input.operator.objective.to_owned(),
    };
    let economic_state = ObservationEconomicState {
        mechanism_set,
        reputation: input.mechanism_economic_state.reputation,
    };
    let resource_budget = ObservationResourceBudget {
        remaining_model_calls: input.remaining_budget.model_calls,
        remaining_tool_calls: input.remaining_budget.tool_calls,
        remaining_validation_seconds: input.remaining_budget.validation_seconds,
    };

    let public_history_sha256 = ProvenanceHash::digest(input.finalized_public_state.public_history);
    let private_operator_history_sha256 =
        ProvenanceHash::digest(input.private_operator_history.bytes);
    let finalized_state_root_sha256 =
        ProvenanceHash::from_bytes(input.finalized_public_state.finalized_state_root_sha256);

    let finalized_projection = FinalizedProjection {
        experiment_id: input.finalized_public_state.experiment_id,
        epoch: input.finalized_public_state.epoch,
        height: input.finalized_public_state.height,
        finalized_state_root_sha256: &finalized_state_root_sha256,
        public_history_sha256: &public_history_sha256,
    };
    let finalized_public_projection_sha256 = hash_json(&finalized_projection)?;

    let observation = OperatorObservation {
        schema_version: OBSERVATION_SCHEMA_VERSION.to_owned(),
        experiment_id: input.finalized_public_state.experiment_id.to_owned(),
        epoch: input.finalized_public_state.epoch,
        height: input.finalized_public_state.height,
        operator,
        economic_state,
        resource_budget,
        available_jobs,
        public_history_ref: public_history_sha256.content_ref(),
        private_operator_history_ref: private_operator_history_sha256.content_ref(),
    };
    let canonical_json = canonical_json(&observation)?;
    if canonical_json.len() > MAX_OBSERVATION_BYTES {
        return Err(ObservationError::ObservationTooLarge {
            bytes: canonical_json.len(),
            maximum: MAX_OBSERVATION_BYTES,
        });
    }

    let provenance = ObservationProvenance {
        finalized_state_root_sha256,
        finalized_public_projection_sha256,
        operator_declaration_sha256: hash_json(&observation.operator)?,
        public_history_sha256,
        private_operator_history_sha256,
        mechanism_economic_state_sha256: hash_json(&observation.economic_state)?,
        remaining_resource_budget_sha256: hash_json(&observation.resource_budget)?,
        available_jobs_sha256: hash_json(&observation.available_jobs)?,
        information_policy_sha256: hash_json(input.information_policy)?,
        observation_sha256: ProvenanceHash::digest(&canonical_json),
    };

    Ok(ObservationSnapshot {
        observation,
        canonical_json,
        provenance,
    })
}

#[derive(Serialize)]
struct FinalizedProjection<'a> {
    experiment_id: &'a str,
    epoch: u64,
    height: u64,
    finalized_state_root_sha256: &'a ProvenanceHash,
    public_history_sha256: &'a ProvenanceHash,
}

fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, ObservationError> {
    serde_json::to_vec(value).map_err(|_| ObservationError::Serialization)
}

fn hash_json(value: &impl Serialize) -> Result<ProvenanceHash, ObservationError> {
    canonical_json(value).map(|bytes| ProvenanceHash::digest(&bytes))
}

fn validate_policy(policy: &InformationPolicy) -> Result<(), ObservationError> {
    for required in REQUIRED_INFORMATION {
        if !policy.permits(required) {
            return Err(ObservationError::MissingDeclaredInformation(required));
        }
    }
    for permitted in &policy.permitted {
        if !REQUIRED_INFORMATION.contains(permitted) {
            return Err(ObservationError::ForbiddenInformation(*permitted));
        }
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ObservationError> {
    let chars = value.chars().count();
    if chars == 0 || chars > MAX_IDENTIFIER_CHARS || value.chars().any(char::is_whitespace) {
        return Err(ObservationError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_objective(value: &str) -> Result<(), ObservationError> {
    let chars = value.chars().count();
    if chars == 0 || chars > MAX_OBJECTIVE_CHARS {
        return Err(ObservationError::InvalidObjective);
    }
    Ok(())
}

fn validate_history(field: &'static str, bytes: &[u8]) -> Result<(), ObservationError> {
    if bytes.len() > MAX_REFERENCED_HISTORY_BYTES {
        return Err(ObservationError::HistoryTooLarge {
            field,
            bytes: bytes.len(),
            maximum: MAX_REFERENCED_HISTORY_BYTES,
        });
    }
    Ok(())
}

fn bounded_identifiers(
    field: &'static str,
    values: &[String],
    maximum: usize,
) -> Result<Vec<String>, ObservationError> {
    if values.len() > maximum {
        return Err(ObservationError::TooManyItems {
            field,
            count: values.len(),
            maximum,
        });
    }
    for value in values {
        validate_identifier(field, value)?;
    }
    let mut canonical = values.to_vec();
    canonical.sort_unstable();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ObservationError::DuplicateItem { field });
    }
    Ok(canonical)
}

/// Stable rejection for an unbounded, ambiguous, or undeclared observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationError {
    InvalidIdentifier {
        field: &'static str,
    },
    InvalidRole,
    InvalidObjective,
    PrivateHistoryOwnerMismatch,
    HistoryTooLarge {
        field: &'static str,
        bytes: usize,
        maximum: usize,
    },
    TooManyItems {
        field: &'static str,
        count: usize,
        maximum: usize,
    },
    DuplicateItem {
        field: &'static str,
    },
    MissingDeclaredInformation(InformationClass),
    ForbiddenInformation(InformationClass),
    ObservationTooLarge {
        bytes: usize,
        maximum: usize,
    },
    CapturedObservationInvalid,
    CapturedObservationHashMismatch,
    Serialization,
}

impl ObservationError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidIdentifier { .. } => "OPERATOR_OBSERVATION_INVALID_IDENTIFIER",
            Self::InvalidRole => "OPERATOR_OBSERVATION_INVALID_ROLE",
            Self::InvalidObjective => "OPERATOR_OBSERVATION_INVALID_OBJECTIVE",
            Self::PrivateHistoryOwnerMismatch => {
                "OPERATOR_OBSERVATION_PRIVATE_HISTORY_OWNER_MISMATCH"
            }
            Self::HistoryTooLarge { .. } => "OPERATOR_OBSERVATION_HISTORY_TOO_LARGE",
            Self::TooManyItems { .. } => "OPERATOR_OBSERVATION_TOO_MANY_ITEMS",
            Self::DuplicateItem { .. } => "OPERATOR_OBSERVATION_DUPLICATE_ITEM",
            Self::MissingDeclaredInformation(_) => {
                "OPERATOR_OBSERVATION_MISSING_DECLARED_INFORMATION"
            }
            Self::ForbiddenInformation(_) => "OPERATOR_OBSERVATION_FORBIDDEN_INFORMATION",
            Self::ObservationTooLarge { .. } => "OPERATOR_OBSERVATION_TOO_LARGE",
            Self::CapturedObservationInvalid => "OPERATOR_OBSERVATION_CAPTURE_INVALID",
            Self::CapturedObservationHashMismatch => "OPERATOR_OBSERVATION_CAPTURE_HASH_MISMATCH",
            Self::Serialization => "OPERATOR_OBSERVATION_SERIALIZATION_FAILURE",
        }
    }
}

impl fmt::Display for ObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier { field } => write!(formatter, "invalid {field}"),
            Self::InvalidRole => formatter.write_str("operator role must be validation_operator"),
            Self::InvalidObjective => formatter.write_str("invalid operator objective"),
            Self::PrivateHistoryOwnerMismatch => {
                formatter.write_str("private history does not belong to the observed operator")
            }
            Self::HistoryTooLarge {
                field,
                bytes,
                maximum,
            } => write!(
                formatter,
                "{field} is {bytes} bytes; maximum is {maximum} bytes"
            ),
            Self::TooManyItems {
                field,
                count,
                maximum,
            } => write!(formatter, "{field} has {count} items; maximum is {maximum}"),
            Self::DuplicateItem { field } => write!(formatter, "{field} contains a duplicate"),
            Self::MissingDeclaredInformation(class) => write!(
                formatter,
                "information policy does not permit required class {}",
                class.name()
            ),
            Self::ForbiddenInformation(class) => write!(
                formatter,
                "information policy permits forbidden class {}",
                class.name()
            ),
            Self::ObservationTooLarge { bytes, maximum } => write!(
                formatter,
                "operator observation is {bytes} bytes; maximum is {maximum} bytes"
            ),
            Self::CapturedObservationInvalid => formatter
                .write_str("captured observation is not canonical operator-observation.v1 JSON"),
            Self::CapturedObservationHashMismatch => {
                formatter.write_str("captured observation does not match its provenance hash")
            }
            Self::Serialization => formatter.write_str("operator observation serialization failed"),
        }
    }
}

impl Error for ObservationError {}
