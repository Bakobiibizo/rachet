//! Experiment definition, identity, and immutable artifact layout.

use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    str::FromStr,
};

use rachet_core::primitives::ExperimentId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::fixtures::IntegrityHash;

const IDENTITY_FORMAT_VERSION: u32 = 1;
const PROTOCOL_LOCK_SCHEMA_VERSION: u32 = 1;

/// One path-bound file committed by an experiment definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedFile {
    relative_path: String,
    bytes: Vec<u8>,
}

impl CommittedFile {
    /// Constructs a committed file with a portable, traversal-free relative path.
    pub fn new(
        relative_path: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, ExperimentError> {
        let relative_path = relative_path.into();
        validate_relative_path(&relative_path)?;
        Ok(Self {
            relative_path,
            bytes: bytes.into(),
        })
    }

    /// Returns the slash-separated relative path.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Returns the exact committed bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// All immutable inputs to one formal experiment run.
///
/// The experiment name is supplied separately because it also names the
/// directory under `experiments/`. Every field below, plus that name, is part
/// of identity. Collection order is not: named files are ordered by their
/// validated relative paths before hashing or writing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentInputs {
    pub protocol_git_commit: String,
    pub cargo_lock: Vec<u8>,
    pub hypothesis: Vec<u8>,
    pub preregistration: Vec<u8>,
    pub mechanism_set: Vec<u8>,
    pub public_fixture_manifest: Vec<u8>,
    pub private_fixture_manifest_hash: IntegrityHash,
    pub operators: Vec<CommittedFile>,
    pub prompts: Vec<CommittedFile>,
    pub seeds: Vec<CommittedFile>,
}

impl ExperimentInputs {
    /// Derives both identities after validating the complete input set.
    pub fn identity(&self, experiment_name: &str) -> Result<ExperimentIdentity, ExperimentError> {
        let canonical = self.canonical_identity_bytes(experiment_name)?;
        Ok(ExperimentIdentity {
            experiment_id: ExperimentId::derive(&canonical),
            run_id: RunId(Sha256::digest(&canonical).into()),
        })
    }

    /// Returns the protocol lock retained beside the experiment definition.
    pub fn protocol_lock(&self) -> Result<ProtocolLock, ExperimentError> {
        validate_protocol_revision(&self.protocol_git_commit)?;
        if self.cargo_lock.is_empty() {
            return Err(ExperimentError::InvalidInput {
                subject: "Cargo.lock".to_owned(),
                reason: "must not be empty".to_owned(),
            });
        }
        Ok(ProtocolLock {
            schema_version: PROTOCOL_LOCK_SCHEMA_VERSION,
            protocol_git_commit: self.protocol_git_commit.clone(),
            cargo_lock_sha256: IntegrityHash::digest(&self.cargo_lock),
        })
    }

    fn canonical_identity_bytes(&self, experiment_name: &str) -> Result<Vec<u8>, ExperimentError> {
        validate_experiment_name(experiment_name)?;
        validate_protocol_revision(&self.protocol_git_commit)?;
        validate_required_bytes("Cargo.lock", &self.cargo_lock)?;
        validate_required_bytes("hypothesis", &self.hypothesis)?;
        validate_required_bytes("preregistration", &self.preregistration)?;
        validate_required_bytes("mechanism set", &self.mechanism_set)?;
        validate_required_bytes("public fixture manifest", &self.public_fixture_manifest)?;

        let operators = sorted_files("operators", &self.operators)?;
        let prompts = sorted_files("prompts", &self.prompts)?;
        let seeds = sorted_files("seeds", &self.seeds)?;

        let mut canonical = Vec::new();
        canonical.extend_from_slice(&IDENTITY_FORMAT_VERSION.to_be_bytes());
        push_field(
            &mut canonical,
            b"experiment-name",
            experiment_name.as_bytes(),
        );
        push_field(
            &mut canonical,
            b"protocol-git-commit",
            self.protocol_git_commit.as_bytes(),
        );
        push_field(
            &mut canonical,
            b"cargo-lock-sha256",
            IntegrityHash::digest(&self.cargo_lock).as_bytes(),
        );
        push_field(&mut canonical, b"hypothesis", &self.hypothesis);
        push_field(&mut canonical, b"experiment-config", &self.preregistration);
        push_field(&mut canonical, b"mechanism-set", &self.mechanism_set);
        push_field(
            &mut canonical,
            b"public-fixture-manifest",
            &self.public_fixture_manifest,
        );
        push_field(
            &mut canonical,
            b"private-fixture-manifest-hash",
            self.private_fixture_manifest_hash.as_bytes(),
        );
        push_files(&mut canonical, b"operator-manifests", &operators, false);
        push_files(&mut canonical, b"prompt-hashes", &prompts, true);
        push_files(&mut canonical, b"seeds", &seeds, false);
        Ok(canonical)
    }
}

/// The domain-separated experiment ID and section 37 run ID for one input set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExperimentIdentity {
    experiment_id: ExperimentId,
    run_id: RunId,
}

impl ExperimentIdentity {
    /// Returns the protocol-domain-separated experiment identity.
    #[must_use]
    pub const fn experiment_id(self) -> ExperimentId {
        self.experiment_id
    }

    /// Returns the run directory identity.
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }
}

/// A SHA-256 run identity rendered as lowercase hexadecimal in artifact paths.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunId([u8; 32]);

impl RunId {
    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for RunId {
    type Err = ExperimentError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(ExperimentError::InvalidInput {
                subject: "run ID".to_owned(),
                reason: "must contain exactly 64 lowercase hexadecimal characters".to_owned(),
            });
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }
}

/// Canonical metadata binding protocol source and dependency resolution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolLock {
    pub schema_version: u32,
    pub protocol_git_commit: String,
    pub cargo_lock_sha256: IntegrityHash,
}

/// Paths created for an immutable experiment definition and its initial run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentLayout {
    experiment_root: PathBuf,
    run_root: PathBuf,
    identity: ExperimentIdentity,
}

impl ExperimentLayout {
    /// Atomically claims a new experiment directory and writes every committed input.
    ///
    /// An existing experiment directory is always an error, even when its bytes
    /// appear equivalent. This prevents a repeated invocation from rewriting old
    /// definitions or run outputs.
    pub fn create(
        experiments_root: impl AsRef<Path>,
        experiment_name: &str,
        inputs: &ExperimentInputs,
    ) -> Result<Self, ExperimentError> {
        let identity = inputs.identity(experiment_name)?;
        let protocol_lock = inputs.protocol_lock()?;
        let experiment_root = experiments_root.as_ref().join(experiment_name);
        let run_root = experiment_root
            .join("runs")
            .join(identity.run_id.to_string());

        fs::create_dir_all(experiments_root.as_ref()).map_err(|source| ExperimentError::Io {
            operation: "create experiments root",
            path: experiments_root.as_ref().to_path_buf(),
            source,
        })?;
        match fs::create_dir(&experiment_root) {
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                return Err(ExperimentError::ExperimentExists(experiment_root));
            }
            Err(source) => {
                return Err(ExperimentError::Io {
                    operation: "create experiment directory",
                    path: experiment_root,
                    source,
                });
            }
        }

        let result = (|| {
            create_directory(&experiment_root.join("operators"))?;
            create_directory(&experiment_root.join("prompts"))?;
            create_directory(&experiment_root.join("seeds"))?;
            create_directory(&experiment_root.join("runs"))?;

            write_new(&experiment_root.join("hypothesis.md"), &inputs.hypothesis)?;
            write_new(
                &experiment_root.join("preregistration.toml"),
                &inputs.preregistration,
            )?;
            write_new(
                &experiment_root.join("mechanism-set.toml"),
                &inputs.mechanism_set,
            )?;
            let mut protocol_lock_bytes = serde_json::to_vec_pretty(&protocol_lock)
                .map_err(ExperimentError::ProtocolLockJson)?;
            protocol_lock_bytes.push(b'\n');
            write_new(
                &experiment_root.join("protocol-lock.json"),
                &protocol_lock_bytes,
            )?;
            write_new(&experiment_root.join("Cargo.lock"), &inputs.cargo_lock)?;
            write_new(
                &experiment_root.join("fixture-manifest-public.json"),
                &inputs.public_fixture_manifest,
            )?;
            write_new(
                &experiment_root.join("fixture-manifest-private.hash"),
                format!("{}\n", inputs.private_fixture_manifest_hash).as_bytes(),
            )?;
            write_files(&experiment_root.join("operators"), &inputs.operators)?;
            write_files(&experiment_root.join("prompts"), &inputs.prompts)?;
            write_files(&experiment_root.join("seeds"), &inputs.seeds)?;
            create_directory(&run_root)
        })();

        if let Err(error) = result {
            let _ = fs::remove_dir_all(&experiment_root);
            return Err(error);
        }

        Ok(Self {
            experiment_root,
            run_root,
            identity,
        })
    }

    /// Returns the immutable experiment definition directory.
    #[must_use]
    pub fn experiment_root(&self) -> &Path {
        &self.experiment_root
    }

    /// Returns `runs/<run-id>` for this input set.
    #[must_use]
    pub fn run_root(&self) -> &Path {
        &self.run_root
    }

    /// Returns the identities represented by this layout.
    #[must_use]
    pub const fn identity(&self) -> ExperimentIdentity {
        self.identity
    }

    /// Claims another run directory without replacing any existing directory.
    pub fn create_run_directory(&self, run_id: RunId) -> Result<PathBuf, ExperimentError> {
        let path = self.experiment_root.join("runs").join(run_id.to_string());
        match fs::create_dir(&path) {
            Ok(()) => Ok(path),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                Err(ExperimentError::RunExists(path))
            }
            Err(source) => Err(ExperimentError::Io {
                operation: "create run directory",
                path,
                source,
            }),
        }
    }
}

/// A validation or immutable-layout failure.
#[derive(Debug)]
pub enum ExperimentError {
    InvalidInput {
        subject: String,
        reason: String,
    },
    DuplicatePath {
        collection: &'static str,
        path: String,
    },
    ExperimentExists(PathBuf),
    RunExists(PathBuf),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    ProtocolLockJson(serde_json::Error),
}

impl fmt::Display for ExperimentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { subject, reason } => {
                write!(formatter, "invalid {subject}: {reason}")
            }
            Self::DuplicatePath { collection, path } => {
                write!(formatter, "duplicate {collection} path {path}")
            }
            Self::ExperimentExists(path) => write!(
                formatter,
                "experiment directory already exists and will not be overwritten: {}",
                path.display()
            ),
            Self::RunExists(path) => write!(
                formatter,
                "run directory already exists and will not be overwritten: {}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "cannot {operation} {}: {source}", path.display()),
            Self::ProtocolLockJson(source) => {
                write!(formatter, "cannot encode protocol lock: {source}")
            }
        }
    }
}

impl Error for ExperimentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::ProtocolLockJson(source) => Some(source),
            Self::InvalidInput { .. }
            | Self::DuplicatePath { .. }
            | Self::ExperimentExists(_)
            | Self::RunExists(_) => None,
        }
    }
}

fn validate_experiment_name(value: &str) -> Result<(), ExperimentError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ExperimentError::InvalidInput {
            subject: "experiment name".to_owned(),
            reason: "must be 1..=128 ASCII letters, digits, '-' or '_'".to_owned(),
        });
    }
    Ok(())
}

fn validate_protocol_revision(value: &str) -> Result<(), ExperimentError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ExperimentError::InvalidInput {
            subject: "protocol Git commit".to_owned(),
            reason: "must be a full 40- or 64-character lowercase hexadecimal object ID".to_owned(),
        });
    }
    Ok(())
}

fn validate_required_bytes(subject: &str, bytes: &[u8]) -> Result<(), ExperimentError> {
    if bytes.is_empty() {
        return Err(ExperimentError::InvalidInput {
            subject: subject.to_owned(),
            reason: "must not be empty".to_owned(),
        });
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), ExperimentError> {
    if value.is_empty() || value.len() > 512 || value.starts_with('/') || value.ends_with('/') {
        return Err(invalid_committed_path());
    }
    for segment in value.split('/') {
        if segment.is_empty()
            || matches!(segment, "." | "..")
            || segment.len() > 128
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(invalid_committed_path());
        }
    }
    Ok(())
}

fn invalid_committed_path() -> ExperimentError {
    ExperimentError::InvalidInput {
        subject: "committed file path".to_owned(),
        reason:
            "must be a portable slash-separated relative path without empty, '.' or '..' segments"
                .to_owned(),
    }
}

fn sorted_files<'a>(
    collection: &'static str,
    files: &'a [CommittedFile],
) -> Result<Vec<&'a CommittedFile>, ExperimentError> {
    let mut sorted: Vec<_> = files.iter().collect();
    for file in &sorted {
        validate_relative_path(file.relative_path())?;
    }
    sorted.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    for pair in sorted.windows(2) {
        if pair[0].relative_path == pair[1].relative_path {
            return Err(ExperimentError::DuplicatePath {
                collection,
                path: pair[0].relative_path.clone(),
            });
        }
    }
    Ok(sorted)
}

fn push_field(canonical: &mut Vec<u8>, tag: &[u8], value: &[u8]) {
    push_length(canonical, tag.len());
    canonical.extend_from_slice(tag);
    push_length(canonical, value.len());
    canonical.extend_from_slice(value);
}

fn push_files(canonical: &mut Vec<u8>, tag: &[u8], files: &[&CommittedFile], hash_contents: bool) {
    push_length(canonical, tag.len());
    canonical.extend_from_slice(tag);
    push_length(canonical, files.len());
    for file in files {
        push_field(canonical, b"path", file.relative_path.as_bytes());
        if hash_contents {
            push_field(
                canonical,
                b"sha256",
                IntegrityHash::digest(&file.bytes).as_bytes(),
            );
        } else {
            push_field(canonical, b"content", &file.bytes);
        }
    }
}

fn push_length(canonical: &mut Vec<u8>, length: usize) {
    let length = u64::try_from(length).expect("supported Linux object lengths fit u64");
    canonical.extend_from_slice(&length.to_be_bytes());
}

fn create_directory(path: &Path) -> Result<(), ExperimentError> {
    fs::create_dir(path).map_err(|source| ExperimentError::Io {
        operation: "create artifact directory",
        path: path.to_path_buf(),
        source,
    })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), ExperimentError> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ExperimentError::Io {
            operation: "create artifact parent directory",
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| ExperimentError::Io {
            operation: "create immutable artifact",
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| ExperimentError::Io {
        operation: "write immutable artifact",
        path: path.to_path_buf(),
        source,
    })
}

fn write_files(root: &Path, files: &[CommittedFile]) -> Result<(), ExperimentError> {
    let sorted = sorted_files("artifact", files)?;
    for file in sorted {
        write_new(&root.join(&file.relative_path), &file.bytes)?;
    }
    Ok(())
}

fn hex_nibble(byte: u8) -> Result<u8, ExperimentError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ExperimentError::InvalidInput {
            subject: "run ID".to_owned(),
            reason: "must use lowercase hexadecimal".to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn committed(path: &str, bytes: &[u8]) -> CommittedFile {
        CommittedFile::new(path, bytes).unwrap()
    }

    fn inputs() -> ExperimentInputs {
        ExperimentInputs {
            protocol_git_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            cargo_lock: b"version = 4\n[[package]]\nname = \"rachet\"\n".to_vec(),
            hypothesis: b"# H-REP-001\n".to_vec(),
            preregistration: b"schema_version = 1\nphase = \"formal\"\n".to_vec(),
            mechanism_set: b"schema_version = 1\nmechanisms = [\"M01@1.0.0\"]\n".to_vec(),
            public_fixture_manifest: b"{\"schema_version\":1,\"fixtures\":[] }\n".to_vec(),
            private_fixture_manifest_hash: IntegrityHash::digest(b"private manifest"),
            operators: vec![
                committed("operator-002.toml", b"policy = \"wait\"\n"),
                committed("operator-001.toml", b"policy = \"validate\"\n"),
            ],
            prompts: vec![committed("validator/system.md", b"Validate exactly.\n")],
            seeds: vec![committed("formal-001.seed", b"42\n")],
        }
    }

    #[test]
    fn equivalent_inputs_have_stable_order_independent_identities() {
        let baseline = inputs();
        let mut reordered = baseline.clone();
        reordered.operators.reverse();

        let first = baseline.identity("H-REP-001").unwrap();
        let second = reordered.identity("H-REP-001").unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.run_id().to_string(),
            "37f3f6a00c4ff7ac455291e544041016cb146b31049216e138a33fb20f504413"
        );
        assert_eq!(
            lower_hex(first.experiment_id().as_bytes()),
            "7adfa1c5c6c601bb42ae570cf5ae17c4e132aeab331b59c2fbb9f5928ee344be"
        );
        assert_eq!(
            first.run_id().to_string().parse::<RunId>().unwrap(),
            first.run_id()
        );
    }

    #[test]
    fn every_committed_input_changes_experiment_and_run_identity() {
        let baseline = inputs();
        let expected = baseline.identity("H-REP-001").unwrap();
        let mut variants = Vec::new();

        let mut value = baseline.clone();
        value.protocol_git_commit = "1123456789abcdef0123456789abcdef01234567".to_owned();
        variants.push(value);
        let mut value = baseline.clone();
        value.cargo_lock.push(b'#');
        variants.push(value);
        let mut value = baseline.clone();
        value.hypothesis.push(b'!');
        variants.push(value);
        let mut value = baseline.clone();
        value.preregistration.push(b'#');
        variants.push(value);
        let mut value = baseline.clone();
        value.mechanism_set.push(b'#');
        variants.push(value);
        let mut value = baseline.clone();
        value.public_fixture_manifest.push(b' ');
        variants.push(value);
        let mut value = baseline.clone();
        value.private_fixture_manifest_hash = IntegrityHash::digest(b"different private manifest");
        variants.push(value);
        let mut value = baseline.clone();
        value.operators[0] = committed("operator-002.toml", b"policy = \"pass\"\n");
        variants.push(value);
        let mut value = baseline.clone();
        value.prompts[0] = committed("validator/system.md", b"Changed prompt.\n");
        variants.push(value);
        let mut value = baseline.clone();
        value.seeds[0] = committed("formal-001.seed", b"43\n");
        variants.push(value);

        for variant in variants {
            let actual = variant.identity("H-REP-001").unwrap();
            assert_ne!(actual.experiment_id(), expected.experiment_id());
            assert_ne!(actual.run_id(), expected.run_id());
        }
        assert_ne!(
            baseline.identity("H-REP-002").unwrap(),
            baseline.identity("H-REP-001").unwrap()
        );
    }

    #[test]
    fn creates_section_37_layout_with_exact_committed_bytes() {
        let temp = TempDirectory::new();
        let inputs = inputs();
        let layout = ExperimentLayout::create(temp.path(), "H-REP-001", &inputs).unwrap();

        assert_eq!(
            fs::read(layout.experiment_root().join("Cargo.lock")).unwrap(),
            inputs.cargo_lock
        );
        assert_eq!(
            fs::read(layout.experiment_root().join("operators/operator-001.toml")).unwrap(),
            b"policy = \"validate\"\n"
        );
        assert_eq!(
            fs::read(layout.experiment_root().join("prompts/validator/system.md")).unwrap(),
            b"Validate exactly.\n"
        );
        assert!(layout.run_root().is_dir());
        assert_eq!(
            layout.run_root().file_name().unwrap().to_str().unwrap(),
            layout.identity().run_id().to_string()
        );

        let lock: ProtocolLock = serde_json::from_slice(
            &fs::read(layout.experiment_root().join("protocol-lock.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(lock, inputs.protocol_lock().unwrap());
        assert_eq!(
            fs::read_to_string(
                layout
                    .experiment_root()
                    .join("fixture-manifest-private.hash")
            )
            .unwrap(),
            format!("{}\n", inputs.private_fixture_manifest_hash)
        );
    }

    #[test]
    fn equivalent_inputs_create_equivalent_relative_layouts() {
        let first_temp = TempDirectory::new();
        let second_temp = TempDirectory::new();
        let first = inputs();
        let mut second = first.clone();
        second.operators.reverse();

        let first_layout =
            ExperimentLayout::create(first_temp.path(), "H-REP-001", &first).unwrap();
        let second_layout =
            ExperimentLayout::create(second_temp.path(), "H-REP-001", &second).unwrap();
        assert_eq!(
            snapshot(first_layout.experiment_root()),
            snapshot(second_layout.experiment_root())
        );
    }

    #[test]
    fn existing_experiment_and_run_outputs_are_never_overwritten() {
        let temp = TempDirectory::new();
        let inputs = inputs();
        let layout = ExperimentLayout::create(temp.path(), "H-REP-001", &inputs).unwrap();
        let output = layout.run_root().join("observations.jsonl");
        fs::write(&output, b"retained output\n").unwrap();

        let error = ExperimentLayout::create(temp.path(), "H-REP-001", &inputs).unwrap_err();
        assert!(matches!(error, ExperimentError::ExperimentExists(_)));
        assert_eq!(fs::read(&output).unwrap(), b"retained output\n");

        let error = layout
            .create_run_directory(layout.identity().run_id())
            .unwrap_err();
        assert!(matches!(error, ExperimentError::RunExists(_)));
        assert_eq!(fs::read(output).unwrap(), b"retained output\n");
    }

    #[test]
    fn ambiguous_or_unsafe_inputs_fail_before_creating_a_layout() {
        assert!(CommittedFile::new("../escape", b"bad".to_vec()).is_err());
        assert!(CommittedFile::new("nested//file", b"bad".to_vec()).is_err());

        let mut duplicate = inputs();
        duplicate
            .operators
            .push(committed("operator-001.toml", b"duplicate"));
        assert!(matches!(
            duplicate.identity("H-REP-001"),
            Err(ExperimentError::DuplicatePath {
                collection: "operators",
                ..
            })
        ));

        let temp = TempDirectory::new();
        assert!(ExperimentLayout::create(temp.path(), "../escape", &inputs()).is_err());
        assert!(fs::read_dir(temp.path()).unwrap().next().is_none());
    }

    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn snapshot(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
        fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<String, Option<Vec<u8>>>) {
            let mut children: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            children.sort();
            for child in children {
                let relative = child
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if child.is_dir() {
                    entries.insert(format!("{relative}/"), None);
                    visit(root, &child, entries);
                } else {
                    entries.insert(relative, Some(fs::read(child).unwrap()));
                }
            }
        }

        let mut entries = BTreeMap::new();
        visit(root, root, &mut entries);
        entries
    }

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rachet-experiment-layout-{}-{sequence}",
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
