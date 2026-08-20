use serde::{Deserialize, Serialize};

use super::IntegrityHash;

pub const FIXTURE_SCHEMA_VERSION: u32 = 1;

/// Experiment partition. Formal fixtures are held out from calibration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureSetKind {
    Smoke,
    Calibration,
    Formal,
}

/// One indexed fixture file and the hash of its exact bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureManifestEntry {
    pub fixture_id: String,
    pub path: String,
    pub sha256: IntegrityHash,
}

/// Ordered public or private fixture index.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureManifest {
    pub schema_version: u32,
    pub set: FixtureSetKind,
    pub fixtures: Vec<FixtureManifestEntry>,
}

/// Classes used to stratify validation examples.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureClass {
    CleanChange,
    ObviousRegression,
    SubtleRegression,
    AuthorizationDefect,
    MalformedErrorHandling,
    SpecificationViolation,
    TestOnlyFailure,
    MisleadingButValidChange,
    GenuinelyAmbiguousClaim,
}

/// A repository fixture bound to exact base and candidate commits and content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryFixture {
    /// Safe path relative to the separately configured repository root.
    pub path: String,
    /// Full lowercase SHA-1 or SHA-256 Git object identifier.
    pub base_commit: String,
    /// Full lowercase SHA-1 or SHA-256 Git object identifier.
    pub candidate_commit: String,
    /// SHA-256 over canonical commit, tree-listing, and blob content inputs.
    pub integrity_sha256: IntegrityHash,
}

/// A public file whose exact bytes are fixture inputs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicArtifact {
    pub artifact_id: String,
    pub path: String,
    pub media_type: String,
    pub sha256: IntegrityHash,
}

/// A claim visible to validation operators.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicClaim {
    pub claim_id: String,
    pub statement: String,
}

/// One allowed command represented as argv, never shell text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermittedCommand {
    pub argv: Vec<String>,
}

/// Hard per-fixture operator limits. Zero explicitly prohibits a capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub wall_clock_seconds: u64,
    pub cpu_seconds: u64,
    pub model_calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub tool_calls: u64,
    pub git_objects_read: u64,
    pub files_inspected: u64,
    pub tests_executed: u64,
    pub evidence_bytes: u64,
}

/// Everything an operator may receive for one validation fixture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicFixture {
    pub schema_version: u32,
    pub fixture_id: String,
    pub class: FixtureClass,
    pub repository: RepositoryFixture,
    pub specification: PublicArtifact,
    pub artifacts: Vec<PublicArtifact>,
    pub claims: Vec<PublicClaim>,
    pub permitted_commands: Vec<PermittedCommand>,
    pub resource_limits: ResourceLimits,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundTruthVerdict {
    Valid,
    Invalid,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguityClassification {
    None,
    SpecificationIncomplete,
    EnvironmentDependent,
    EvidenceInsufficient,
    MultipleReasonableInterpretations,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DifficultyTier {
    Obvious,
    Moderate,
    Subtle,
    Expert,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DifficultyMetadata {
    pub tier: DifficultyTier,
    pub expected_validation_seconds: u64,
    pub skill_tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimGroundTruth {
    pub claim_id: String,
    pub verdict: GroundTruthVerdict,
    pub seeded_defect_description: Option<String>,
    pub reproduction_procedure: Vec<PermittedCommand>,
    pub expected_evidence: Vec<String>,
    pub ambiguity: AmbiguityClassification,
    pub difficulty: DifficultyMetadata,
}

/// Evaluator-only truth. This type is deliberately not exported by the crate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateFixture {
    pub schema_version: u32,
    pub fixture_id: String,
    /// Hash of the exact public fixture JSON bytes this truth describes.
    pub public_fixture_sha256: IntegrityHash,
    pub claims: Vec<ClaimGroundTruth>,
}
