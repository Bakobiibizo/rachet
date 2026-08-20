//! Immutable section 37 outputs for one experiment run.
//!
//! A run directory is committed once. The manifest is written last and is the
//! completion marker: capture failures may leave forensic files behind, but a
//! later invocation will never replace or complete those files in place.

use std::{
    collections::BTreeSet,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{experiment::RunId, fixtures::IntegrityHash};

const MANIFEST_SCHEMA_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "artifact-manifest.json";
const MAX_FAILURE_CODE_BYTES: usize = 128;
const MAX_FAILURE_MESSAGE_BYTES: usize = 4_096;

const RUN_ARTIFACTS: [(&str, &str); 10] = [
    ("initial-state.bin", "application/octet-stream"),
    ("observations.jsonl", "application/x-ndjson"),
    ("decisions.jsonl", "application/x-ndjson"),
    ("actions.bin", "application/octet-stream"),
    ("blocks.bin", "application/octet-stream"),
    ("events.bin", "application/octet-stream"),
    ("economic-state.jsonl", "application/x-ndjson"),
    ("resources.json", "application/json"),
    ("metrics.json", "application/json"),
    ("discovered-strategies.md", "text/markdown; charset=utf-8"),
];

/// Exact bytes retained for every required section 37 run output.
///
/// Binary fields must already use their canonical framing. JSONL fields are
/// checked as newline-terminated JSON values, and the two JSON documents must
/// be objects. Keeping capture byte-oriented allows it to retain successful and
/// failed runs without inventing a second protocol representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunArtifactBundle {
    pub initial_state: Vec<u8>,
    pub observations_jsonl: Vec<u8>,
    pub decisions_jsonl: Vec<u8>,
    pub signed_actions: Vec<u8>,
    pub blocks: Vec<u8>,
    pub events: Vec<u8>,
    pub economic_state_jsonl: Vec<u8>,
    pub resources_json: Vec<u8>,
    pub metrics_json: Vec<u8>,
    pub discovered_strategies_markdown: Vec<u8>,
}

impl RunArtifactBundle {
    fn files(&self) -> [(&'static str, &'static str, &[u8]); 10] {
        [
            (RUN_ARTIFACTS[0].0, RUN_ARTIFACTS[0].1, &self.initial_state),
            (
                RUN_ARTIFACTS[1].0,
                RUN_ARTIFACTS[1].1,
                &self.observations_jsonl,
            ),
            (
                RUN_ARTIFACTS[2].0,
                RUN_ARTIFACTS[2].1,
                &self.decisions_jsonl,
            ),
            (RUN_ARTIFACTS[3].0, RUN_ARTIFACTS[3].1, &self.signed_actions),
            (RUN_ARTIFACTS[4].0, RUN_ARTIFACTS[4].1, &self.blocks),
            (RUN_ARTIFACTS[5].0, RUN_ARTIFACTS[5].1, &self.events),
            (
                RUN_ARTIFACTS[6].0,
                RUN_ARTIFACTS[6].1,
                &self.economic_state_jsonl,
            ),
            (RUN_ARTIFACTS[7].0, RUN_ARTIFACTS[7].1, &self.resources_json),
            (RUN_ARTIFACTS[8].0, RUN_ARTIFACTS[8].1, &self.metrics_json),
            (
                RUN_ARTIFACTS[9].0,
                RUN_ARTIFACTS[9].1,
                &self.discovered_strategies_markdown,
            ),
        ]
    }

    fn validate(&self) -> Result<(), RunArtifactError> {
        validate_jsonl("observations.jsonl", &self.observations_jsonl)?;
        validate_jsonl("decisions.jsonl", &self.decisions_jsonl)?;
        validate_jsonl("economic-state.jsonl", &self.economic_state_jsonl)?;
        validate_json_object("resources.json", &self.resources_json)?;
        validate_json_object("metrics.json", &self.metrics_json)?;
        std::str::from_utf8(&self.discovered_strategies_markdown).map_err(|_| {
            RunArtifactError::InvalidArtifact {
                path: "discovered-strategies.md".to_owned(),
                reason: "must be UTF-8".to_owned(),
            }
        })?;
        Ok(())
    }
}

/// Terminal result represented by a committed run manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunOutcome {
    Completed,
    Failed { failure: RunFailure },
}

impl RunOutcome {
    fn validate(&self) -> Result<(), RunArtifactError> {
        if let Self::Failed { failure } = self {
            validate_failure_field("failure code", &failure.code, MAX_FAILURE_CODE_BYTES)?;
            validate_failure_field(
                "failure message",
                &failure.message,
                MAX_FAILURE_MESSAGE_BYTES,
            )?;
        }
        Ok(())
    }
}

/// Stable failure information for an experiment that terminated unsuccessfully.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunFailure {
    pub code: String,
    pub message: String,
}

impl RunFailure {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<Self, RunArtifactError> {
        let failure = Self {
            code: code.into(),
            message: message.into(),
        };
        RunOutcome::Failed {
            failure: failure.clone(),
        }
        .validate()?;
        Ok(failure)
    }
}

/// One exact file committed by the run manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifestEntry {
    pub path: String,
    pub media_type: String,
    pub bytes: u64,
    pub sha256: IntegrityHash,
}

impl ArtifactManifestEntry {
    fn from_bytes(path: String, media_type: String, bytes: &[u8]) -> Self {
        Self {
            path,
            media_type,
            bytes: u64::try_from(bytes.len()).expect("supported Linux file lengths fit u64"),
            sha256: IntegrityHash::digest(bytes),
        }
    }
}

/// Complete, deterministic inventory of one terminal run and its committed seeds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunArtifactManifest {
    pub schema_version: u32,
    pub run_id: String,
    pub outcome: RunOutcome,
    pub artifacts: Vec<ArtifactManifestEntry>,
    pub seeds: Vec<ArtifactManifestEntry>,
}

/// A verified manifest and the exact retained bytes it commits to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedRunArtifacts {
    pub manifest: RunArtifactManifest,
    pub bundle: RunArtifactBundle,
}

/// Append-only section 37 artifact operations.
pub struct RunArtifactStore;

impl RunArtifactStore {
    /// Commits all required outputs into an existing empty `runs/<run-id>`
    /// directory and writes its manifest last.
    pub fn capture(
        experiment_root: impl AsRef<Path>,
        run_id: RunId,
        outcome: RunOutcome,
        bundle: &RunArtifactBundle,
    ) -> Result<RunArtifactManifest, RunArtifactError> {
        bundle.validate()?;
        outcome.validate()?;

        let experiment_root = experiment_root.as_ref();
        let run_root = experiment_root.join("runs").join(run_id.to_string());
        ensure_real_directory(&run_root, "run directory")?;
        ensure_empty_directory(&run_root)?;

        let seed_root = experiment_root.join("seeds");
        ensure_real_directory(&seed_root, "seed directory")?;
        let seeds = collect_files(&seed_root)?;
        let seed_entries = seeds
            .iter()
            .map(|file| {
                ArtifactManifestEntry::from_bytes(
                    file.relative_path.clone(),
                    "application/octet-stream".to_owned(),
                    &file.bytes,
                )
            })
            .collect();

        let artifacts = bundle
            .files()
            .iter()
            .map(|(path, media_type, bytes)| {
                ArtifactManifestEntry::from_bytes(
                    (*path).to_owned(),
                    (*media_type).to_owned(),
                    bytes,
                )
            })
            .collect();
        let manifest = RunArtifactManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            run_id: run_id.to_string(),
            outcome,
            artifacts,
            seeds: seed_entries,
        };

        for (path, _, bytes) in bundle.files() {
            write_new(&run_root.join(path), bytes)?;
        }
        let mut manifest_bytes =
            serde_json::to_vec_pretty(&manifest).map_err(RunArtifactError::ManifestEncode)?;
        manifest_bytes.push(b'\n');
        write_new(&run_root.join(MANIFEST_FILE), &manifest_bytes)?;
        Ok(manifest)
    }

    /// Verifies and loads the exact retained run bytes without interpretation.
    pub fn load(
        experiment_root: impl AsRef<Path>,
        run_id: RunId,
    ) -> Result<LoadedRunArtifacts, RunArtifactError> {
        let experiment_root = experiment_root.as_ref();
        let manifest = Self::verify(experiment_root, run_id)?;
        let run_root = experiment_root.join("runs").join(run_id.to_string());
        let bundle = RunArtifactBundle {
            initial_state: read_regular_file(&run_root.join(RUN_ARTIFACTS[0].0))?,
            observations_jsonl: read_regular_file(&run_root.join(RUN_ARTIFACTS[1].0))?,
            decisions_jsonl: read_regular_file(&run_root.join(RUN_ARTIFACTS[2].0))?,
            signed_actions: read_regular_file(&run_root.join(RUN_ARTIFACTS[3].0))?,
            blocks: read_regular_file(&run_root.join(RUN_ARTIFACTS[4].0))?,
            events: read_regular_file(&run_root.join(RUN_ARTIFACTS[5].0))?,
            economic_state_jsonl: read_regular_file(&run_root.join(RUN_ARTIFACTS[6].0))?,
            resources_json: read_regular_file(&run_root.join(RUN_ARTIFACTS[7].0))?,
            metrics_json: read_regular_file(&run_root.join(RUN_ARTIFACTS[8].0))?,
            discovered_strategies_markdown: read_regular_file(&run_root.join(RUN_ARTIFACTS[9].0))?,
        };
        Ok(LoadedRunArtifacts { manifest, bundle })
    }

    /// Verifies manifest shape, required file presence, exact lengths and every
    /// SHA-256 digest. Unlisted run outputs or seeds are rejected as unaudited.
    pub fn verify(
        experiment_root: impl AsRef<Path>,
        run_id: RunId,
    ) -> Result<RunArtifactManifest, RunArtifactError> {
        let experiment_root = experiment_root.as_ref();
        let run_root = experiment_root.join("runs").join(run_id.to_string());
        ensure_real_directory(&run_root, "run directory")?;
        let manifest_path = run_root.join(MANIFEST_FILE);
        let manifest_bytes = read_regular_file(&manifest_path)?;
        let manifest: RunArtifactManifest =
            serde_json::from_slice(&manifest_bytes).map_err(RunArtifactError::ManifestDecode)?;
        validate_manifest_shape(&manifest, run_id)?;

        let expected_run_paths: BTreeSet<_> = RUN_ARTIFACTS
            .iter()
            .map(|(path, _)| (*path).to_owned())
            .chain(std::iter::once(MANIFEST_FILE.to_owned()))
            .collect();
        let actual_run_paths: BTreeSet<_> = collect_files(&run_root)?
            .into_iter()
            .map(|file| file.relative_path)
            .collect();
        compare_inventory("run directory", &expected_run_paths, &actual_run_paths)?;

        for entry in &manifest.artifacts {
            verify_entry(&run_root, entry)?;
        }

        let seed_root = experiment_root.join("seeds");
        ensure_real_directory(&seed_root, "seed directory")?;
        let actual_seed_paths: BTreeSet<_> = collect_files(&seed_root)?
            .into_iter()
            .map(|file| file.relative_path)
            .collect();
        let expected_seed_paths: BTreeSet<_> = manifest
            .seeds
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        if expected_seed_paths.len() != manifest.seeds.len() {
            return Err(RunArtifactError::InvalidManifest(
                "seed entries contain a duplicate path".to_owned(),
            ));
        }
        compare_inventory("seed directory", &expected_seed_paths, &actual_seed_paths)?;
        for entry in &manifest.seeds {
            verify_entry(&seed_root, entry)?;
        }
        validate_retained_formats(&run_root)?;
        Ok(manifest)
    }
}

#[derive(Debug)]
pub enum RunArtifactError {
    InvalidArtifact {
        path: String,
        reason: String,
    },
    InvalidOutcome {
        field: &'static str,
        reason: String,
    },
    InvalidManifest(String),
    MissingArtifact(PathBuf),
    UnlistedArtifact(PathBuf),
    ArtifactExists(PathBuf),
    ArtifactLength {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    ArtifactHash {
        path: PathBuf,
        expected: IntegrityHash,
        actual: IntegrityHash,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    ManifestEncode(serde_json::Error),
    ManifestDecode(serde_json::Error),
}

impl fmt::Display for RunArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifact { path, reason } => {
                write!(formatter, "invalid run artifact {path}: {reason}")
            }
            Self::InvalidOutcome { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::InvalidManifest(reason) => write!(formatter, "invalid run manifest: {reason}"),
            Self::MissingArtifact(path) => {
                write!(
                    formatter,
                    "required artifact is missing: {}",
                    path.display()
                )
            }
            Self::UnlistedArtifact(path) => {
                write!(
                    formatter,
                    "artifact is not listed by the manifest: {}",
                    path.display()
                )
            }
            Self::ArtifactExists(path) => write!(
                formatter,
                "run output already exists and will not be rewritten: {}",
                path.display()
            ),
            Self::ArtifactLength {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "artifact {} has {actual} bytes; manifest commits to {expected}",
                path.display()
            ),
            Self::ArtifactHash {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "artifact {} hashes to {actual}; manifest commits to {expected}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "cannot {operation} {}: {source}", path.display()),
            Self::ManifestEncode(source) => {
                write!(formatter, "cannot encode run manifest: {source}")
            }
            Self::ManifestDecode(source) => {
                write!(formatter, "cannot decode run manifest: {source}")
            }
        }
    }
}

impl Error for RunArtifactError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::ManifestEncode(source) | Self::ManifestDecode(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct CollectedFile {
    relative_path: String,
    bytes: Vec<u8>,
}

fn validate_jsonl(path: &str, bytes: &[u8]) -> Result<(), RunArtifactError> {
    if bytes.is_empty() {
        return Ok(());
    }
    if !bytes.ends_with(b"\n") {
        return Err(RunArtifactError::InvalidArtifact {
            path: path.to_owned(),
            reason: "non-empty JSONL must end with a newline".to_owned(),
        });
    }
    for (index, line) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if line.is_empty() {
            return Err(RunArtifactError::InvalidArtifact {
                path: path.to_owned(),
                reason: format!("line {} is empty", index + 1),
            });
        }
        serde_json::from_slice::<serde_json::Value>(line).map_err(|source| {
            RunArtifactError::InvalidArtifact {
                path: path.to_owned(),
                reason: format!("line {} is not JSON: {source}", index + 1),
            }
        })?;
    }
    Ok(())
}

fn validate_json_object(path: &str, bytes: &[u8]) -> Result<(), RunArtifactError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|source| RunArtifactError::InvalidArtifact {
            path: path.to_owned(),
            reason: format!("must contain one JSON object: {source}"),
        })?;
    if !value.is_object() {
        return Err(RunArtifactError::InvalidArtifact {
            path: path.to_owned(),
            reason: "must contain one JSON object".to_owned(),
        });
    }
    Ok(())
}

fn validate_failure_field(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), RunArtifactError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(RunArtifactError::InvalidOutcome {
            field,
            reason: format!("must be 1..={maximum} bytes without control characters"),
        });
    }
    Ok(())
}

fn validate_manifest_shape(
    manifest: &RunArtifactManifest,
    expected_run_id: RunId,
) -> Result<(), RunArtifactError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(RunArtifactError::InvalidManifest(format!(
            "schema version {} is not supported",
            manifest.schema_version
        )));
    }
    if manifest.run_id != expected_run_id.to_string() {
        return Err(RunArtifactError::InvalidManifest(
            "run ID does not match the containing directory".to_owned(),
        ));
    }
    manifest.outcome.validate()?;
    if manifest.artifacts.len() != RUN_ARTIFACTS.len() {
        return Err(RunArtifactError::InvalidManifest(format!(
            "expected {} run artifacts, found {}",
            RUN_ARTIFACTS.len(),
            manifest.artifacts.len()
        )));
    }
    for (entry, (expected_path, expected_media_type)) in
        manifest.artifacts.iter().zip(RUN_ARTIFACTS)
    {
        if entry.path != expected_path || entry.media_type != expected_media_type {
            return Err(RunArtifactError::InvalidManifest(format!(
                "expected artifact {expected_path} with media type {expected_media_type}"
            )));
        }
    }
    let mut previous = None;
    for seed in &manifest.seeds {
        validate_portable_path(&seed.path)?;
        if seed.media_type != "application/octet-stream" {
            return Err(RunArtifactError::InvalidManifest(format!(
                "seed {} has an unsupported media type",
                seed.path
            )));
        }
        if previous.is_some_and(|path: &str| path >= seed.path.as_str()) {
            return Err(RunArtifactError::InvalidManifest(
                "seed entries must have unique ascending paths".to_owned(),
            ));
        }
        previous = Some(seed.path.as_str());
    }
    Ok(())
}

fn validate_retained_formats(run_root: &Path) -> Result<(), RunArtifactError> {
    for path in [
        "observations.jsonl",
        "decisions.jsonl",
        "economic-state.jsonl",
    ] {
        validate_jsonl(path, &read_regular_file(&run_root.join(path))?)?;
    }
    for path in ["resources.json", "metrics.json"] {
        validate_json_object(path, &read_regular_file(&run_root.join(path))?)?;
    }
    std::str::from_utf8(&read_regular_file(
        &run_root.join("discovered-strategies.md"),
    )?)
    .map_err(|_| RunArtifactError::InvalidArtifact {
        path: "discovered-strategies.md".to_owned(),
        reason: "must be UTF-8".to_owned(),
    })?;
    Ok(())
}

fn compare_inventory(
    label: &'static str,
    expected: &BTreeSet<String>,
    actual: &BTreeSet<String>,
) -> Result<(), RunArtifactError> {
    if let Some(path) = expected.difference(actual).next() {
        return Err(RunArtifactError::MissingArtifact(
            PathBuf::from(label).join(path),
        ));
    }
    if let Some(path) = actual.difference(expected).next() {
        return Err(RunArtifactError::UnlistedArtifact(
            PathBuf::from(label).join(path),
        ));
    }
    Ok(())
}

fn verify_entry(root: &Path, entry: &ArtifactManifestEntry) -> Result<(), RunArtifactError> {
    validate_portable_path(&entry.path)?;
    let path = root.join(&entry.path);
    let bytes = read_regular_file(&path)?;
    let actual_length = u64::try_from(bytes.len()).expect("supported Linux file lengths fit u64");
    if actual_length != entry.bytes {
        return Err(RunArtifactError::ArtifactLength {
            path,
            expected: entry.bytes,
            actual: actual_length,
        });
    }
    let actual_hash = IntegrityHash::digest(&bytes);
    if actual_hash != entry.sha256 {
        return Err(RunArtifactError::ArtifactHash {
            path,
            expected: entry.sha256,
            actual: actual_hash,
        });
    }
    Ok(())
}

fn ensure_real_directory(path: &Path, label: &'static str) -> Result<(), RunArtifactError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            RunArtifactError::MissingArtifact(path.to_path_buf())
        } else {
            RunArtifactError::Io {
                operation: "inspect artifact directory",
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if !metadata.file_type().is_dir() {
        return Err(RunArtifactError::InvalidArtifact {
            path: path.display().to_string(),
            reason: format!("{label} must be a real directory, not a file or symlink"),
        });
    }
    Ok(())
}

fn ensure_empty_directory(path: &Path) -> Result<(), RunArtifactError> {
    let mut entries = fs::read_dir(path).map_err(|source| RunArtifactError::Io {
        operation: "inspect run directory",
        path: path.to_path_buf(),
        source,
    })?;
    match entries.next() {
        Some(Ok(entry)) => Err(RunArtifactError::ArtifactExists(entry.path())),
        Some(Err(source)) => Err(RunArtifactError::Io {
            operation: "inspect run directory entry",
            path: path.to_path_buf(),
            source,
        }),
        None => Ok(()),
    }
}

fn collect_files(root: &Path) -> Result<Vec<CollectedFile>, RunArtifactError> {
    fn visit(
        root: &Path,
        directory: &Path,
        output: &mut Vec<CollectedFile>,
    ) -> Result<(), RunArtifactError> {
        let entries = fs::read_dir(directory).map_err(|source| RunArtifactError::Io {
            operation: "list artifact directory",
            path: directory.to_path_buf(),
            source,
        })?;
        for result in entries {
            let entry = result.map_err(|source| RunArtifactError::Io {
                operation: "read artifact directory entry",
                path: directory.to_path_buf(),
                source,
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| RunArtifactError::Io {
                operation: "inspect artifact",
                path: path.clone(),
                source,
            })?;
            if metadata.file_type().is_dir() {
                visit(root, &path, output)?;
            } else if metadata.file_type().is_file() {
                let relative =
                    path.strip_prefix(root)
                        .map_err(|_| RunArtifactError::InvalidArtifact {
                            path: path.display().to_string(),
                            reason: "artifact escaped its declared root".to_owned(),
                        })?;
                let relative_path = relative
                    .to_str()
                    .ok_or_else(|| RunArtifactError::InvalidArtifact {
                        path: path.display().to_string(),
                        reason: "path must be UTF-8".to_owned(),
                    })?
                    .replace('\\', "/");
                validate_portable_path(&relative_path)?;
                output.push(CollectedFile {
                    relative_path,
                    bytes: read_regular_file(&path)?,
                });
            } else {
                return Err(RunArtifactError::InvalidArtifact {
                    path: path.display().to_string(),
                    reason: "artifact trees may contain only regular files and directories"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    let mut output = Vec::new();
    visit(root, root, &mut output)?;
    output.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(output)
}

fn validate_portable_path(value: &str) -> Result<(), RunArtifactError> {
    if value.is_empty() || value.starts_with('/') || value.ends_with('/') {
        return Err(RunArtifactError::InvalidManifest(format!(
            "artifact path {value:?} is not portable"
        )));
    }
    for segment in value.split('/') {
        if segment.is_empty()
            || matches!(segment, "." | "..")
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(RunArtifactError::InvalidManifest(format!(
                "artifact path {value:?} is not portable"
            )));
        }
    }
    Ok(())
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, RunArtifactError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            RunArtifactError::MissingArtifact(path.to_path_buf())
        } else {
            RunArtifactError::Io {
                operation: "inspect artifact",
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(RunArtifactError::InvalidArtifact {
            path: path.display().to_string(),
            reason: "must be a regular file, not a directory or symlink".to_owned(),
        });
    }
    fs::read(path).map_err(|source| RunArtifactError::Io {
        operation: "read artifact",
        path: path.to_path_buf(),
        source,
    })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), RunArtifactError> {
    use std::io::Write as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                RunArtifactError::ArtifactExists(path.to_path_buf())
            } else {
                RunArtifactError::Io {
                    operation: "create immutable run artifact",
                    path: path.to_path_buf(),
                    source,
                }
            }
        })?;
    file.write_all(bytes)
        .map_err(|source| RunArtifactError::Io {
            operation: "write immutable run artifact",
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn run_id(byte: u8) -> RunId {
        std::iter::repeat_n(format!("{byte:02x}"), 32)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    fn bundle() -> RunArtifactBundle {
        RunArtifactBundle {
            initial_state: b"\0\0\0\0\0\0\0\0".to_vec(),
            observations_jsonl: b"{\"height\":0}\n".to_vec(),
            decisions_jsonl: b"{\"decision\":\"wait\"}\n".to_vec(),
            signed_actions: b"actions-v1".to_vec(),
            blocks: b"blocks-v1".to_vec(),
            events: b"events-v1".to_vec(),
            economic_state_jsonl: b"{\"height\":0,\"entries\":[]}\n".to_vec(),
            resources_json: b"{\"model_calls\":0,\"tool_calls\":0}".to_vec(),
            metrics_json: b"{\"jobs_accepted\":0}".to_vec(),
            discovered_strategies_markdown: b"# Discovered strategies\n\nNone.\n".to_vec(),
        }
    }

    fn layout(temp: &TempDirectory, run_id: RunId) -> PathBuf {
        let experiment = temp.path().join("H-REP-001");
        fs::create_dir_all(experiment.join("seeds/formal")).unwrap();
        fs::write(experiment.join("seeds/formal/operator-001.seed"), b"42\n").unwrap();
        fs::create_dir_all(experiment.join("runs").join(run_id.to_string())).unwrap();
        experiment
    }

    #[test]
    fn completed_and_failed_runs_have_complete_verifiable_manifests() {
        for (index, outcome) in [
            RunOutcome::Completed,
            RunOutcome::Failed {
                failure: RunFailure::new("RUNNER_FAILED", "fixture rejected").unwrap(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let temp = TempDirectory::new();
            let id = run_id(u8::try_from(index + 1).unwrap());
            let experiment = layout(&temp, id);
            let manifest =
                RunArtifactStore::capture(&experiment, id, outcome.clone(), &bundle()).unwrap();

            assert_eq!(manifest.outcome, outcome);
            assert_eq!(manifest.artifacts.len(), RUN_ARTIFACTS.len());
            assert_eq!(manifest.seeds.len(), 1);
            assert_eq!(RunArtifactStore::verify(&experiment, id).unwrap(), manifest);
            assert!(
                experiment
                    .join("runs")
                    .join(id.to_string())
                    .join(MANIFEST_FILE)
                    .is_file()
            );
        }
    }

    #[test]
    fn missing_corrupt_and_unlisted_artifacts_are_detected() {
        let missing_temp = TempDirectory::new();
        let missing_id = run_id(3);
        let missing_experiment = layout(&missing_temp, missing_id);
        RunArtifactStore::capture(
            &missing_experiment,
            missing_id,
            RunOutcome::Completed,
            &bundle(),
        )
        .unwrap();
        fs::remove_file(
            missing_experiment
                .join("runs")
                .join(missing_id.to_string())
                .join("events.bin"),
        )
        .unwrap();
        assert!(matches!(
            RunArtifactStore::verify(&missing_experiment, missing_id),
            Err(RunArtifactError::MissingArtifact(_))
        ));

        let corrupt_temp = TempDirectory::new();
        let corrupt_id = run_id(4);
        let corrupt_experiment = layout(&corrupt_temp, corrupt_id);
        RunArtifactStore::capture(
            &corrupt_experiment,
            corrupt_id,
            RunOutcome::Completed,
            &bundle(),
        )
        .unwrap();
        fs::write(
            corrupt_experiment
                .join("runs")
                .join(corrupt_id.to_string())
                .join("blocks.bin"),
            b"changed!!",
        )
        .unwrap();
        assert!(matches!(
            RunArtifactStore::verify(&corrupt_experiment, corrupt_id),
            Err(RunArtifactError::ArtifactHash { .. })
        ));

        let unlisted_temp = TempDirectory::new();
        let unlisted_id = run_id(5);
        let unlisted_experiment = layout(&unlisted_temp, unlisted_id);
        RunArtifactStore::capture(
            &unlisted_experiment,
            unlisted_id,
            RunOutcome::Completed,
            &bundle(),
        )
        .unwrap();
        fs::write(
            unlisted_experiment
                .join("runs")
                .join(unlisted_id.to_string())
                .join("replacement.bin"),
            b"unaudited",
        )
        .unwrap();
        assert!(matches!(
            RunArtifactStore::verify(&unlisted_experiment, unlisted_id),
            Err(RunArtifactError::UnlistedArtifact(_))
        ));
    }

    #[test]
    fn capture_never_rewrites_any_old_output() {
        let temp = TempDirectory::new();
        let id = run_id(6);
        let experiment = layout(&temp, id);
        let first = bundle();
        RunArtifactStore::capture(&experiment, id, RunOutcome::Completed, &first).unwrap();
        let run_root = experiment.join("runs").join(id.to_string());
        let retained = fs::read(run_root.join("observations.jsonl")).unwrap();

        let mut replacement = bundle();
        replacement.observations_jsonl = b"{\"height\":99}\n".to_vec();
        assert!(matches!(
            RunArtifactStore::capture(&experiment, id, RunOutcome::Completed, &replacement),
            Err(RunArtifactError::ArtifactExists(_))
        ));
        assert_eq!(
            fs::read(run_root.join("observations.jsonl")).unwrap(),
            retained
        );
    }

    #[test]
    fn malformed_structured_outputs_fail_before_writing() {
        let temp = TempDirectory::new();
        let id = run_id(7);
        let experiment = layout(&temp, id);
        let mut malformed = bundle();
        malformed.decisions_jsonl = b"not-json\n".to_vec();

        assert!(matches!(
            RunArtifactStore::capture(&experiment, id, RunOutcome::Completed, &malformed),
            Err(RunArtifactError::InvalidArtifact { .. })
        ));
        assert!(
            fs::read_dir(experiment.join("runs").join(id.to_string()))
                .unwrap()
                .next()
                .is_none()
        );
    }

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rachet-run-artifacts-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
