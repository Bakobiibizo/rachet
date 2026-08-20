use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use super::{
    FIXTURE_SCHEMA_VERSION, FixtureError, FixtureManifest, FixtureManifestEntry, FixtureSetKind,
    IntegrityHash, PublicArtifact, PublicFixture, repository::verify_repository,
};

const MANIFEST_FILE: &str = "manifest.json";
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FIXTURES: usize = 10_000;
const MAX_ITEMS_PER_FIXTURE: usize = 10_000;
const MAX_TEXT_BYTES: usize = 1024 * 1024;

/// Capability-limited loader for operator-visible fixture inputs.
///
/// It is configured with only public and repository roots. There is no method
/// that accepts, lists, or reads the private truth root.
#[derive(Clone, Debug)]
pub struct PublicFixtureLoader {
    public_root: PathBuf,
    repository_root: PathBuf,
}

/// One completely verified public fixture.
#[derive(Clone, Debug)]
pub struct LoadedPublicFixture {
    definition: PublicFixture,
    fixture_hash: IntegrityHash,
    repository_path: PathBuf,
    specification_path: PathBuf,
    artifact_paths: BTreeMap<String, PathBuf>,
}

impl LoadedPublicFixture {
    #[must_use]
    pub const fn definition(&self) -> &PublicFixture {
        &self.definition
    }

    #[must_use]
    pub const fn fixture_hash(&self) -> IntegrityHash {
        self.fixture_hash
    }

    #[must_use]
    pub fn repository_path(&self) -> &Path {
        &self.repository_path
    }

    #[must_use]
    pub fn specification_path(&self) -> &Path {
        &self.specification_path
    }

    #[must_use]
    pub const fn artifact_paths(&self) -> &BTreeMap<String, PathBuf> {
        &self.artifact_paths
    }
}

/// A manifest-ordered, verified fixture partition.
#[derive(Clone, Debug)]
pub struct LoadedPublicFixtureSet {
    set: FixtureSetKind,
    manifest_hash: IntegrityHash,
    fixtures: Vec<LoadedPublicFixture>,
}

impl LoadedPublicFixtureSet {
    #[must_use]
    pub const fn set(&self) -> FixtureSetKind {
        self.set
    }

    #[must_use]
    pub const fn manifest_hash(&self) -> IntegrityHash {
        self.manifest_hash
    }

    #[must_use]
    pub fn fixtures(&self) -> &[LoadedPublicFixture] {
        &self.fixtures
    }

    #[cfg(test)]
    pub(crate) fn empty_for_test(set: FixtureSetKind) -> Self {
        Self {
            set,
            manifest_hash: IntegrityHash::digest(b"test public manifest"),
            fixtures: Vec::new(),
        }
    }
}

impl PublicFixtureLoader {
    /// Creates a loader from two existing directory capabilities.
    pub fn new(
        public_root: impl AsRef<Path>,
        repository_root: impl AsRef<Path>,
    ) -> Result<Self, FixtureError> {
        Ok(Self {
            public_root: canonical_directory(public_root.as_ref(), "public fixture root")?,
            repository_root: canonical_directory(
                repository_root.as_ref(),
                "fixture repository root",
            )?,
        })
    }

    /// Loads `manifest.json` and every referenced fixture in manifest order.
    pub fn load(&self) -> Result<LoadedPublicFixtureSet, FixtureError> {
        let manifest_path = self.public_root.join(MANIFEST_FILE);
        let manifest_bytes = read_bounded(&manifest_path)?;
        let manifest_hash = IntegrityHash::digest(&manifest_bytes);
        let manifest: FixtureManifest = parse_json(&manifest_path, &manifest_bytes)?;
        validate_manifest(&manifest, "public fixture manifest")?;

        let mut fixtures = Vec::with_capacity(manifest.fixtures.len());
        for entry in &manifest.fixtures {
            fixtures.push(self.load_fixture(entry)?);
        }

        Ok(LoadedPublicFixtureSet {
            set: manifest.set,
            manifest_hash,
            fixtures,
        })
    }

    fn load_fixture(
        &self,
        entry: &FixtureManifestEntry,
    ) -> Result<LoadedPublicFixture, FixtureError> {
        let path = resolve_file(&self.public_root, &entry.path, "public fixture")?;
        let bytes = read_bounded(&path)?;
        verify_hash(
            format!("public fixture {}", entry.fixture_id),
            entry.sha256,
            &bytes,
        )?;
        let fixture: PublicFixture = parse_json(&path, &bytes)?;
        validate_public_fixture(&fixture, &entry.fixture_id)?;

        let repository_path = resolve_directory(
            &self.repository_root,
            &fixture.repository.path,
            "fixture repository",
        )?;
        verify_repository(&repository_path, &fixture.repository)?;

        let specification_path = verify_artifact(&self.public_root, &fixture.specification)?;
        let mut artifact_paths = BTreeMap::new();
        artifact_paths.insert(
            fixture.specification.artifact_id.clone(),
            specification_path.clone(),
        );
        for artifact in &fixture.artifacts {
            let path = verify_artifact(&self.public_root, artifact)?;
            if artifact_paths
                .insert(artifact.artifact_id.clone(), path)
                .is_some()
            {
                return Err(invalid(
                    format!("fixture {} artifacts", fixture.fixture_id),
                    format!("duplicate artifact ID {}", artifact.artifact_id),
                ));
            }
        }

        Ok(LoadedPublicFixture {
            definition: fixture,
            fixture_hash: entry.sha256,
            repository_path,
            specification_path,
            artifact_paths,
        })
    }
}

/// Enforces distinct labels and no fixture or candidate overlap between the
/// calibration and held-out formal partitions.
pub fn verify_calibration_formal_disjoint(
    calibration: &LoadedPublicFixtureSet,
    formal: &LoadedPublicFixtureSet,
) -> Result<(), FixtureError> {
    if calibration.set != FixtureSetKind::Calibration || formal.set != FixtureSetKind::Formal {
        return Err(invalid(
            "fixture partitions",
            "expected calibration followed by formal set",
        ));
    }

    let mut fixture_ids = BTreeSet::new();
    let mut repository_cases = BTreeSet::new();
    for fixture in &calibration.fixtures {
        fixture_ids.insert(fixture.definition.fixture_id.as_str());
        repository_cases.insert((
            fixture.definition.repository.base_commit.as_str(),
            fixture.definition.repository.candidate_commit.as_str(),
            fixture.definition.repository.integrity_sha256,
        ));
    }
    for fixture in &formal.fixtures {
        if fixture_ids.contains(fixture.definition.fixture_id.as_str()) {
            return Err(invalid(
                "formal fixture set",
                format!(
                    "fixture ID {} also occurs in calibration",
                    fixture.definition.fixture_id
                ),
            ));
        }
        let case = (
            fixture.definition.repository.base_commit.as_str(),
            fixture.definition.repository.candidate_commit.as_str(),
            fixture.definition.repository.integrity_sha256,
        );
        if repository_cases.contains(&case) {
            return Err(invalid(
                "formal fixture set",
                format!(
                    "repository candidate for {} also occurs in calibration",
                    fixture.definition.fixture_id
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_manifest(
    manifest: &FixtureManifest,
    subject: &str,
) -> Result<(), FixtureError> {
    if manifest.schema_version != FIXTURE_SCHEMA_VERSION {
        return Err(invalid(
            subject,
            format!("unsupported schema version {}", manifest.schema_version),
        ));
    }
    if manifest.fixtures.is_empty() || manifest.fixtures.len() > MAX_FIXTURES {
        return Err(invalid(
            subject,
            format!("must contain between 1 and {MAX_FIXTURES} fixtures"),
        ));
    }

    let mut prior: Option<&str> = None;
    let mut paths = BTreeSet::new();
    for entry in &manifest.fixtures {
        validate_identifier("fixture ID", &entry.fixture_id)?;
        validate_relative_path(&entry.path, "fixture path")?;
        if prior.is_some_and(|value| value >= entry.fixture_id.as_str()) {
            return Err(invalid(
                subject,
                "fixtures must be strictly sorted by fixture_id",
            ));
        }
        if !paths.insert(entry.path.as_str()) {
            return Err(invalid(subject, format!("duplicate path {}", entry.path)));
        }
        prior = Some(&entry.fixture_id);
    }
    Ok(())
}

fn validate_public_fixture(fixture: &PublicFixture, expected_id: &str) -> Result<(), FixtureError> {
    if fixture.schema_version != FIXTURE_SCHEMA_VERSION {
        return Err(invalid(
            format!("fixture {expected_id}"),
            format!("unsupported schema version {}", fixture.schema_version),
        ));
    }
    if fixture.fixture_id != expected_id {
        return Err(invalid(
            format!("fixture {expected_id}"),
            format!("declares fixture ID {}", fixture.fixture_id),
        ));
    }
    validate_identifier("fixture ID", &fixture.fixture_id)?;
    validate_relative_path(&fixture.repository.path, "repository path")?;
    validate_artifact(&fixture.specification)?;
    if fixture.artifacts.len() > MAX_ITEMS_PER_FIXTURE {
        return Err(invalid("fixture artifacts", "too many artifacts"));
    }
    for artifact in &fixture.artifacts {
        validate_artifact(artifact)?;
    }

    if fixture.claims.is_empty() || fixture.claims.len() > MAX_ITEMS_PER_FIXTURE {
        return Err(invalid(
            "fixture claims",
            format!("must contain between 1 and {MAX_ITEMS_PER_FIXTURE} claims"),
        ));
    }
    let mut claims = BTreeSet::new();
    for claim in &fixture.claims {
        validate_identifier("claim ID", &claim.claim_id)?;
        validate_text("claim statement", &claim.statement)?;
        if !claims.insert(claim.claim_id.as_str()) {
            return Err(invalid(
                "fixture claims",
                format!("duplicate claim ID {}", claim.claim_id),
            ));
        }
    }

    if fixture.permitted_commands.is_empty()
        || fixture.permitted_commands.len() > MAX_ITEMS_PER_FIXTURE
    {
        return Err(invalid(
            "permitted commands",
            format!("must contain between 1 and {MAX_ITEMS_PER_FIXTURE} commands"),
        ));
    }
    for command in &fixture.permitted_commands {
        validate_command(command)?;
    }

    Ok(())
}

pub(super) fn validate_command(command: &super::PermittedCommand) -> Result<(), FixtureError> {
    if command.argv.is_empty() || command.argv.len() > 256 {
        return Err(invalid(
            "command argv",
            "must contain between 1 and 256 arguments",
        ));
    }
    for argument in &command.argv {
        validate_text("command argument", argument)?;
        if argument.contains('\0') {
            return Err(invalid("command argument", "contains NUL"));
        }
    }
    Ok(())
}

pub(super) fn validate_identifier(subject: &str, value: &str) -> Result<(), FixtureError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(invalid(
            subject,
            "must be 1-128 ASCII identifier characters",
        ));
    }
    Ok(())
}

pub(super) fn validate_text(subject: &str, value: &str) -> Result<(), FixtureError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
        return Err(invalid(
            subject,
            format!("must be nonempty, NUL-free, and at most {MAX_TEXT_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn validate_artifact(artifact: &PublicArtifact) -> Result<(), FixtureError> {
    validate_identifier("artifact ID", &artifact.artifact_id)?;
    validate_relative_path(&artifact.path, "artifact path")?;
    validate_text("artifact media type", &artifact.media_type)
}

fn verify_artifact(root: &Path, artifact: &PublicArtifact) -> Result<PathBuf, FixtureError> {
    let path = resolve_file(root, &artifact.path, "public artifact")?;
    let bytes = read_bounded(&path)?;
    verify_hash(
        format!("artifact {}", artifact.artifact_id),
        artifact.sha256,
        &bytes,
    )?;
    Ok(path)
}

pub(super) fn read_bounded(path: &Path) -> Result<Vec<u8>, FixtureError> {
    let metadata = fs::metadata(path).map_err(|source| FixtureError::Io {
        operation: "inspect",
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(invalid(
            format!("file {}", path.display()),
            "is not a regular file",
        ));
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(invalid(
            format!("file {}", path.display()),
            format!("exceeds {MAX_FILE_BYTES} bytes"),
        ));
    }
    let bytes = fs::read(path).map_err(|source| FixtureError::Io {
        operation: "read",
        path: path.to_owned(),
        source,
    })?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(invalid(
            format!("file {}", path.display()),
            format!("exceeds {MAX_FILE_BYTES} bytes"),
        ));
    }
    Ok(bytes)
}

pub(super) fn parse_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    bytes: &[u8],
) -> Result<T, FixtureError> {
    serde_json::from_slice(bytes).map_err(|source| FixtureError::Json {
        path: path.to_owned(),
        source,
    })
}

pub(super) fn verify_hash(
    subject: String,
    expected: IntegrityHash,
    bytes: &[u8],
) -> Result<(), FixtureError> {
    let actual = IntegrityHash::digest(bytes);
    if expected != actual {
        return Err(FixtureError::HashMismatch {
            subject,
            expected,
            actual,
        });
    }
    Ok(())
}

pub(super) fn canonical_directory(path: &Path, subject: &str) -> Result<PathBuf, FixtureError> {
    let canonical = fs::canonicalize(path).map_err(|source| FixtureError::Io {
        operation: "canonicalize",
        path: path.to_owned(),
        source,
    })?;
    if !canonical.is_dir() {
        return Err(invalid(subject, "is not a directory"));
    }
    Ok(canonical)
}

pub(super) fn resolve_file(
    root: &Path,
    relative: &str,
    subject: &str,
) -> Result<PathBuf, FixtureError> {
    let path = resolve(root, relative, subject)?;
    if !path.is_file() {
        return Err(invalid(subject, "is not a regular file"));
    }
    Ok(path)
}

fn resolve_directory(root: &Path, relative: &str, subject: &str) -> Result<PathBuf, FixtureError> {
    let path = resolve(root, relative, subject)?;
    if !path.is_dir() {
        return Err(invalid(subject, "is not a directory"));
    }
    Ok(path)
}

fn resolve(root: &Path, relative: &str, subject: &str) -> Result<PathBuf, FixtureError> {
    validate_relative_path(relative, subject)?;
    let joined = root.join(relative);
    let canonical = fs::canonicalize(&joined).map_err(|source| FixtureError::Io {
        operation: "canonicalize",
        path: joined,
        source,
    })?;
    if !canonical.starts_with(root) {
        return Err(invalid(subject, "resolves outside its configured root"));
    }
    Ok(canonical)
}

fn validate_relative_path(value: &str, subject: &str) -> Result<(), FixtureError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || (value != "."
            && !path
                .components()
                .all(|component| matches!(component, Component::Normal(_))))
    {
        return Err(invalid(
            subject,
            "must be a nonempty normalized relative path",
        ));
    }
    Ok(())
}

pub(super) fn invalid(subject: impl Into<String>, reason: impl Into<String>) -> FixtureError {
    FixtureError::Invalid {
        subject: subject.into(),
        reason: reason.into(),
    }
}
