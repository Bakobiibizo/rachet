//! Isolated operator home and Git worktree provisioning.

use crate::{
    budget::{BudgetError, BudgetTracker, ResourceUsage},
    manifest::{
        AgentConfiguration, FilesystemAccess, IndependenceClaim, IndependenceReport,
        OperatorRuntimeConfig, OperatorSpec, PopulationIndependenceReport, PopulationManifest,
        RUNTIME_CONFIG_SCHEMA_VERSION,
    },
};
use rachet_client::identity::{ActorIdentity, IdentityError};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    process::{Command, Output},
};

const MAX_PRIVATE_FILE_BYTES: usize = 64 * 1024 * 1024;
// Linux O_NOFOLLOW. Rachet's supported production environment is Linux/WSL2.
const O_NOFOLLOW: i32 = 0o400_000;

/// Existing host-private locations that must never overlap an operator-visible
/// root. These paths are checked but are deliberately not exposed by accessors
/// or serialized into runtime configuration.
#[derive(Clone, Debug)]
pub struct ProtectedPaths {
    paths: Vec<ProtectedPath>,
}

#[derive(Clone, Debug)]
struct ProtectedPath {
    kind: &'static str,
    path: PathBuf,
}

impl ProtectedPaths {
    pub fn new(
        consensus_key_paths: impl IntoIterator<Item = PathBuf>,
        hidden_evaluator_paths: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, HostError> {
        let mut paths = Vec::new();
        for path in consensus_key_paths {
            paths.push(ProtectedPath {
                kind: "consensus_key",
                path: canonical_existing(&path)?,
            });
        }
        for path in hidden_evaluator_paths {
            paths.push(ProtectedPath {
                kind: "hidden_evaluator",
                path: canonical_existing(&path)?,
            });
        }
        Ok(Self { paths })
    }

    #[must_use]
    pub const fn empty() -> Self {
        Self { paths: Vec::new() }
    }

    fn reject_overlap(&self, subject: &str, candidate: &Path) -> Result<(), HostError> {
        for protected in &self.paths {
            if overlaps(candidate, &protected.path) {
                return Err(HostError::ProtectedPathOverlap {
                    subject: subject.to_owned(),
                    protected_kind: protected.kind,
                });
            }
        }
        Ok(())
    }
}

/// Trusted provisioner configured with a public source repository and a set of
/// host-only protected paths.
#[derive(Debug)]
pub struct OperatorHost {
    root: PathBuf,
    repository: PathBuf,
    revision: String,
    protected: ProtectedPaths,
}

impl OperatorHost {
    /// Creates a fresh isolated population root. Existing roots are rejected so
    /// identities, memory, and configuration are never silently reused.
    pub fn create(
        root: impl AsRef<Path>,
        repository: impl AsRef<Path>,
        revision: impl Into<String>,
        protected: ProtectedPaths,
    ) -> Result<Self, HostError> {
        let repository = canonical_directory(repository.as_ref(), "source repository")?;
        protected.reject_overlap("source repository", &repository)?;

        let revision = revision.into();
        validate_text("Git revision", &revision, 256)?;
        let revision = resolve_revision(&repository, &revision)?;

        let requested_root = root.as_ref();
        if requested_root.exists() {
            return Err(HostError::RootAlreadyExists(requested_root.to_path_buf()));
        }
        create_private_directory(requested_root)?;
        let root = match fs::canonicalize(requested_root) {
            Ok(root) => root,
            Err(source) => {
                let _ = fs::remove_dir(requested_root);
                return Err(HostError::Io {
                    operation: "canonicalize operator root",
                    path: requested_root.to_path_buf(),
                    source,
                });
            }
        };
        if let Err(error) = protected.reject_overlap("operator root", &root) {
            let _ = fs::remove_dir(&root);
            return Err(error);
        }

        Ok(Self {
            root,
            repository,
            revision,
            protected,
        })
    }

    /// Provisions all identities, homes, independent worktrees, and declared
    /// communication roots in one bounded population.
    pub fn provision(self, manifest: PopulationManifest) -> Result<OperatorPopulation, HostError> {
        let declarations = validate_manifest(&manifest)?;
        let independence_report = manifest
            .independence_report()
            .map_err(|error| HostError::InvalidManifest(error.to_string()))?;
        self.protected.reject_overlap("operator root", &self.root)?;

        let rollback_repository = self.repository.clone();
        let rollback_root = self.root.clone();
        let result = self.provision_inner(manifest, &declarations, independence_report);
        if result.is_err() {
            rollback_population(&rollback_repository, &rollback_root);
        }
        result
    }

    fn provision_inner(
        self,
        manifest: PopulationManifest,
        declarations: &BTreeMap<String, BTreeSet<String>>,
        independence_report: PopulationIndependenceReport,
    ) -> Result<OperatorPopulation, HostError> {
        let operators_root = self.root.join("operators");
        let communication_root = self.root.join("communication");
        create_private_directory(&operators_root)?;
        create_private_directory(&communication_root)?;

        let mut channel_paths = BTreeMap::new();
        for channel in &manifest.communication_channels {
            let path = communication_root.join(&channel.channel_id);
            create_private_directory(&path)?;
            channel_paths.insert(
                channel.channel_id.clone(),
                fs::canonicalize(path).map_err(|source| HostError::Io {
                    operation: "canonicalize communication channel",
                    path: communication_root.join(&channel.channel_id),
                    source,
                })?,
            );
        }

        let report_path = self.root.join("independence-report.json");
        let report_bytes =
            serde_json::to_vec_pretty(&independence_report).map_err(HostError::Json)?;
        write_private_file(&report_path, &report_bytes, true)?;

        let mut operators = BTreeMap::new();
        for spec in manifest.operators {
            let operator = provision_operator(
                &operators_root,
                &self.repository,
                &self.revision,
                spec,
                declarations,
                &channel_paths,
            )?;
            let prior = operators.insert(operator.operator_id.clone(), operator);
            debug_assert!(prior.is_none());
        }

        Ok(OperatorPopulation {
            root: self.root,
            repository: self.repository,
            operators,
            independence_report,
        })
    }
}

/// Agent-visible filesystem capability. There is intentionally no arbitrary
/// host-path variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorAccess<'a> {
    Home,
    Worktree,
    Memory,
    Scratch,
    Communication(&'a str),
}

/// One provisioned identity and its host-owned budget state.
#[derive(Debug)]
pub struct ProvisionedOperator {
    operator_id: String,
    actor_id: String,
    role: String,
    objective: String,
    agent: AgentConfiguration,
    home: PathBuf,
    worktree: PathBuf,
    memory: PathBuf,
    scratch: PathBuf,
    config_path: PathBuf,
    provenance_root: PathBuf,
    communication: BTreeMap<String, PathBuf>,
    filesystem_access: BTreeSet<FilesystemAccess>,
    budget: BudgetTracker,
}

impl ProvisionedOperator {
    /// Reopens one provisioned identity for its single durable decision boundary.
    ///
    /// The runtime configuration is accepted only from its fixed location under
    /// the isolated home, and every configured capability is canonicalized
    /// again. Budget use starts at zero; callers must pair this with a durable
    /// boundary that permits at most one external invocation.
    pub fn open(config_path: impl AsRef<Path>) -> Result<Self, HostError> {
        let requested_config = config_path.as_ref();
        let metadata = fs::symlink_metadata(requested_config).map_err(|source| HostError::Io {
            operation: "inspect operator runtime config",
            path: requested_config.to_path_buf(),
            source,
        })?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_PRIVATE_FILE_BYTES as u64 {
            return Err(HostError::InvalidManifest(
                "operator runtime config must be a bounded regular file".to_owned(),
            ));
        }
        let config_path = fs::canonicalize(requested_config).map_err(|source| HostError::Io {
            operation: "canonicalize operator runtime config",
            path: requested_config.to_path_buf(),
            source,
        })?;
        let config_bytes = fs::read(&config_path).map_err(|source| HostError::Io {
            operation: "read operator runtime config",
            path: config_path.clone(),
            source,
        })?;
        let config: OperatorRuntimeConfig =
            serde_json::from_slice(&config_bytes).map_err(HostError::Json)?;
        if config.schema_version != RUNTIME_CONFIG_SCHEMA_VERSION {
            return Err(HostError::InvalidManifest(
                "unsupported operator runtime config schema".to_owned(),
            ));
        }

        let home = canonical_directory(&config.home, "operator home")?;
        let worktree = canonical_directory(&config.worktree, "operator worktree")?;
        let memory = canonical_directory(&config.memory, "operator memory")?;
        let scratch = canonical_directory(&config.scratch, "operator scratch")?;
        let operator_root = home.parent().ok_or_else(|| {
            HostError::InvalidManifest("operator home has no identity root".to_owned())
        })?;
        let expected_config = home.join(".config/rachet/agent.json");
        if fs::canonicalize(&expected_config).ok().as_deref() != Some(config_path.as_path())
            || worktree != operator_root.join("worktree")
            || memory != home.join("memory")
            || scratch != home.join("scratch")
        {
            return Err(HostError::InvalidManifest(
                "operator runtime paths do not belong to the isolated identity".to_owned(),
            ));
        }
        let actor_key = fs::canonicalize(&config.actor_key).map_err(|source| HostError::Io {
            operation: "canonicalize operator actor key",
            path: config.actor_key.clone(),
            source,
        })?;
        if actor_key != home.join("identity/actor.key") {
            return Err(HostError::InvalidManifest(
                "operator actor key is outside its fixed isolated location".to_owned(),
            ));
        }
        let identity = ActorIdentity::load(&actor_key).map_err(HostError::Identity)?;
        if encode_hex(identity.actor_id().as_bytes()) != config.actor_id {
            return Err(HostError::InvalidManifest(
                "operator runtime actor ID does not match its signing key".to_owned(),
            ));
        }
        let provenance_root = canonical_directory(
            &operator_root.join("provenance"),
            "operator provenance root",
        )?;
        let communication = config
            .communication_channels
            .iter()
            .map(|(channel, path)| {
                canonical_directory(path, "operator communication channel")
                    .map(|path| (channel.clone(), path))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let filesystem_access = config
            .information
            .filesystem_access
            .iter()
            .copied()
            .collect();

        Ok(Self {
            operator_id: config.operator_id,
            actor_id: config.actor_id,
            role: config.role,
            objective: config.objective,
            agent: config.agent,
            home,
            worktree,
            memory,
            scratch,
            config_path,
            provenance_root,
            communication,
            filesystem_access,
            budget: BudgetTracker::new(config.resource_budget),
        })
    }

    #[must_use]
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }

    #[must_use]
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    #[must_use]
    pub fn objective(&self) -> &str {
        &self.objective
    }

    #[must_use]
    pub const fn agent(&self) -> &AgentConfiguration {
        &self.agent
    }

    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    #[must_use]
    pub fn worktree(&self) -> &Path {
        &self.worktree
    }

    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub(crate) fn provenance_root(&self) -> &Path {
        &self.provenance_root
    }

    #[must_use]
    pub const fn budget(&self) -> &BudgetTracker {
        &self.budget
    }

    pub(crate) const fn budget_mut(&mut self) -> &mut BudgetTracker {
        &mut self.budget
    }

    pub fn charge(&mut self, usage: ResourceUsage) -> Result<(), BudgetError> {
        self.budget.charge(usage)
    }

    /// Resolves an existing path beneath one declared capability. Absolute,
    /// parent-traversal, and symlink escapes are rejected.
    pub fn authorize_existing(
        &self,
        access: OperatorAccess<'_>,
        relative: impl AsRef<Path>,
    ) -> Result<PathBuf, HostError> {
        let root = self.access_root(access)?;
        resolve_existing(root, relative.as_ref())
    }

    /// Reads one bounded regular file through the capability API.
    pub fn read_file(
        &self,
        access: OperatorAccess<'_>,
        relative: impl AsRef<Path>,
    ) -> Result<Vec<u8>, HostError> {
        let path = self.authorize_existing(access, relative)?;
        let metadata = fs::symlink_metadata(&path).map_err(|source| HostError::Io {
            operation: "inspect operator file",
            path: path.clone(),
            source,
        })?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_PRIVATE_FILE_BYTES as u64 {
            return Err(HostError::AccessDenied(
                "operator reads require a bounded regular file".to_owned(),
            ));
        }
        fs::read(&path).map_err(|source| HostError::Io {
            operation: "read operator file",
            path,
            source,
        })
    }

    /// Writes one direct child file only to mutable private or explicitly
    /// shared storage. Home internals and worktrees are not writable through
    /// this narrow host API (agents use their own process capabilities there).
    pub fn write_file(
        &self,
        access: OperatorAccess<'_>,
        relative: impl AsRef<Path>,
        contents: &[u8],
    ) -> Result<(), HostError> {
        if contents.len() > MAX_PRIVATE_FILE_BYTES {
            return Err(HostError::AccessDenied(
                "operator write exceeds private file bound".to_owned(),
            ));
        }
        if matches!(access, OperatorAccess::Home | OperatorAccess::Worktree) {
            return Err(HostError::AccessDenied(
                "host API writes are limited to memory, scratch, and declared communication"
                    .to_owned(),
            ));
        }
        let root = self.access_root(access)?;
        let resolved_root = fs::canonicalize(root).map_err(|source| HostError::Io {
            operation: "canonicalize mutable operator root",
            path: root.to_path_buf(),
            source,
        })?;
        if resolved_root != root {
            return Err(HostError::AccessDenied(
                "mutable operator root was replaced or redirected".to_owned(),
            ));
        }
        let relative = relative.as_ref();
        validate_direct_child(relative)?;
        let path = root.join(relative);
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && !metadata.file_type().is_file()
        {
            return Err(HostError::AccessDenied(
                "operator write target is not a regular file".to_owned(),
            ));
        }
        write_private_file(&path, contents, false)
    }

    fn access_root(&self, access: OperatorAccess<'_>) -> Result<&Path, HostError> {
        let required = match access {
            OperatorAccess::Home | OperatorAccess::Communication(_) => None,
            OperatorAccess::Worktree => Some(FilesystemAccess::Worktree),
            OperatorAccess::Memory => Some(FilesystemAccess::PrivateMemory),
            OperatorAccess::Scratch => Some(FilesystemAccess::PrivateScratch),
        };
        if required.is_some_and(|capability| !self.filesystem_access.contains(&capability)) {
            return Err(HostError::AccessDenied(
                "filesystem capability was not declared by the population manifest".to_owned(),
            ));
        }
        match access {
            OperatorAccess::Home => Ok(&self.home),
            OperatorAccess::Worktree => Ok(&self.worktree),
            OperatorAccess::Memory => Ok(&self.memory),
            OperatorAccess::Scratch => Ok(&self.scratch),
            OperatorAccess::Communication(channel) => self
                .communication
                .get(channel)
                .map(PathBuf::as_path)
                .ok_or_else(|| HostError::UndeclaredCommunication(channel.to_owned())),
        }
    }
}

/// A complete provisioned population.
#[derive(Debug)]
pub struct OperatorPopulation {
    root: PathBuf,
    repository: PathBuf,
    operators: BTreeMap<String, ProvisionedOperator>,
    independence_report: PopulationIndependenceReport,
}

impl OperatorPopulation {
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub const fn operators(&self) -> &BTreeMap<String, ProvisionedOperator> {
        &self.operators
    }

    #[must_use]
    pub const fn independence_report(&self) -> &PopulationIndependenceReport {
        &self.independence_report
    }

    #[must_use]
    pub fn operator(&self, operator_id: &str) -> Option<&ProvisionedOperator> {
        self.operators.get(operator_id)
    }

    #[must_use]
    pub fn operator_mut(&mut self, operator_id: &str) -> Option<&mut ProvisionedOperator> {
        self.operators.get_mut(operator_id)
    }

    /// Removes Git worktree registrations and the isolated population root.
    pub fn destroy(self) -> Result<(), HostError> {
        for operator in self.operators.values() {
            remove_worktree(&self.repository, &operator.worktree)?;
            unlock_provenance_for_removal(&operator.provenance_root)?;
        }
        fs::remove_dir_all(&self.root).map_err(|source| HostError::Io {
            operation: "remove operator population",
            path: self.root,
            source,
        })
    }
}

fn unlock_provenance_for_removal(root: &Path) -> Result<(), HostError> {
    for entry in fs::read_dir(root).map_err(|source| HostError::Io {
        operation: "list operator provenance",
        path: root.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| HostError::Io {
            operation: "read operator provenance entry",
            path: root.to_path_buf(),
            source,
        })?;
        let run = entry.path();
        let metadata = fs::symlink_metadata(&run).map_err(|source| HostError::Io {
            operation: "inspect operator provenance entry",
            path: run.clone(),
            source,
        })?;
        if !metadata.file_type().is_dir() {
            continue;
        }
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).map_err(|source| {
            HostError::Io {
                operation: "unlock operator provenance directory",
                path: run.clone(),
                source,
            }
        })?;
        for artifact in fs::read_dir(&run).map_err(|source| HostError::Io {
            operation: "list operator provenance artifacts",
            path: run.clone(),
            source,
        })? {
            let artifact = artifact.map_err(|source| HostError::Io {
                operation: "read operator provenance artifact",
                path: run.clone(),
                source,
            })?;
            let path = artifact.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| HostError::Io {
                operation: "inspect operator provenance artifact",
                path: path.clone(),
                source,
            })?;
            if metadata.file_type().is_file() {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(
                    |source| HostError::Io {
                        operation: "unlock operator provenance artifact",
                        path,
                        source,
                    },
                )?;
            }
        }
    }
    Ok(())
}

fn provision_operator(
    operators_root: &Path,
    repository: &Path,
    revision: &str,
    spec: OperatorSpec,
    declarations: &BTreeMap<String, BTreeSet<String>>,
    channel_paths: &BTreeMap<String, PathBuf>,
) -> Result<ProvisionedOperator, HostError> {
    let operator_root = operators_root.join(&spec.operator_id);
    let home = operator_root.join("home");
    let worktree = operator_root.join("worktree");
    let identity_directory = home.join("identity");
    let config_home = home.join(".config");
    let config_directory = config_home.join("rachet");
    let memory = home.join("memory");
    let scratch = home.join("scratch");
    let provenance_root = operator_root.join("provenance");
    for directory in [
        &operator_root,
        &home,
        &identity_directory,
        &config_home,
        &config_directory,
        &memory,
        &scratch,
        &provenance_root,
    ] {
        create_private_directory(directory)?;
    }

    let actor_key = identity_directory.join("actor.key");
    let identity = ActorIdentity::create(&actor_key).map_err(HostError::Identity)?;
    let actor_id = encode_hex(identity.actor_id().as_bytes());
    add_worktree(repository, &worktree, revision)?;

    let declared = declarations
        .get(&spec.operator_id)
        .expect("validated operator declaration exists");
    let communication = declared
        .iter()
        .map(|channel| {
            (
                channel.clone(),
                channel_paths
                    .get(channel)
                    .expect("validated channel path exists")
                    .clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let independence = IndependenceReport {
        model_family: independence_label(&spec.independence.model_family),
        system_prompt: independence_label(&spec.independence.system_prompt),
        random_seed: independence_label(&spec.independence.random_seed),
        tool_harness: independence_label(&spec.independence.tool_harness),
        memory: independence_label(&spec.independence.memory),
        worktree: independence_label(&spec.independence.worktree),
        evidence_method: independence_label(&spec.independence.evidence_method),
        communication_channels: communication.keys().cloned().collect(),
        customer_relationship: independence_label(&spec.independence.customer_relationship),
    };
    let filesystem_access = spec
        .information
        .filesystem_access
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let config = OperatorRuntimeConfig {
        schema_version: RUNTIME_CONFIG_SCHEMA_VERSION.to_owned(),
        operator_id: spec.operator_id.clone(),
        actor_id: actor_id.clone(),
        role: spec.role,
        objective: spec.objective,
        operator_kind: spec.operator_kind,
        agent: spec.agent,
        information: spec.information,
        learning: spec.learning,
        home: fs::canonicalize(&home).map_err(|source| HostError::Io {
            operation: "canonicalize operator home",
            path: home.clone(),
            source,
        })?,
        worktree: fs::canonicalize(&worktree).map_err(|source| HostError::Io {
            operation: "canonicalize operator worktree",
            path: worktree.clone(),
            source,
        })?,
        actor_key: actor_key.clone(),
        memory: fs::canonicalize(&memory).map_err(|source| HostError::Io {
            operation: "canonicalize operator memory",
            path: memory.clone(),
            source,
        })?,
        scratch: fs::canonicalize(&scratch).map_err(|source| HostError::Io {
            operation: "canonicalize operator scratch",
            path: scratch.clone(),
            source,
        })?,
        communication_channels: communication.clone(),
        resource_budget: spec.resource_budget,
        identity_constraints: spec.identity_constraints,
        independence,
    };
    let config_path = config_directory.join("agent.json");
    let config_bytes = serde_json::to_vec_pretty(&config).map_err(HostError::Json)?;
    write_private_file(&config_path, &config_bytes, true)?;

    Ok(ProvisionedOperator {
        operator_id: config.operator_id.clone(),
        actor_id,
        role: config.role.clone(),
        objective: config.objective.clone(),
        agent: config.agent.clone(),
        home: config.home,
        worktree: config.worktree,
        memory: config.memory,
        scratch: config.scratch,
        config_path,
        provenance_root: fs::canonicalize(&provenance_root).map_err(|source| HostError::Io {
            operation: "canonicalize operator provenance root",
            path: provenance_root,
            source,
        })?,
        communication,
        filesystem_access,
        budget: BudgetTracker::new(spec.resource_budget),
    })
}

fn independence_label(claim: &IndependenceClaim) -> String {
    match claim {
        IndependenceClaim::Independent => "independent".to_owned(),
        IndependenceClaim::Shared { group } => format!("shared:{group}"),
    }
}

fn validate_manifest(
    manifest: &PopulationManifest,
) -> Result<BTreeMap<String, BTreeSet<String>>, HostError> {
    manifest
        .validate()
        .map_err(|error| HostError::InvalidManifest(error.to_string()))?;
    let mut declarations = manifest
        .operators
        .iter()
        .map(|operator| (operator.operator_id.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for channel in &manifest.communication_channels {
        for participant in &channel.participants {
            declarations
                .get_mut(participant)
                .expect("manifest validation checked channel participants")
                .insert(channel.channel_id.clone());
        }
    }
    Ok(declarations)
}

fn validate_text(subject: &str, value: &str, maximum: usize) -> Result<(), HostError> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(HostError::InvalidManifest(format!(
            "{subject} must be nonempty, NUL-free, and at most {maximum} bytes"
        )));
    }
    Ok(())
}

fn validate_direct_child(relative: &Path) -> Result<(), HostError> {
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().count() != 1
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(HostError::AccessDenied(
            "operator file must be one normalized relative path component".to_owned(),
        ));
    }
    Ok(())
}

fn resolve_existing(root: &Path, relative: &Path) -> Result<PathBuf, HostError> {
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(HostError::AccessDenied(
            "operator path must be normalized and relative".to_owned(),
        ));
    }
    let requested = root.join(relative);
    let resolved = fs::canonicalize(&requested).map_err(|source| HostError::Io {
        operation: "canonicalize operator path",
        path: requested,
        source,
    })?;
    if !resolved.starts_with(root) {
        return Err(HostError::AccessDenied(
            "operator path resolves outside its declared capability".to_owned(),
        ));
    }
    Ok(resolved)
}

fn create_private_directory(path: &Path) -> Result<(), HostError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false).mode(0o700);
    builder.create(path).map_err(|source| HostError::Io {
        operation: "create private directory",
        path: path.to_path_buf(),
        source,
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| HostError::Io {
        operation: "restrict private directory",
        path: path.to_path_buf(),
        source,
    })
}

fn write_private_file(path: &Path, contents: &[u8], create_new: bool) -> Result<(), HostError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .truncate(!create_new)
        .create(!create_new)
        .create_new(create_new)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW);
    let mut file = options.open(path).map_err(|source| HostError::Io {
        operation: "open private file",
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(contents).map_err(|source| HostError::Io {
        operation: "write private file",
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| HostError::Io {
        operation: "sync private file",
        path: path.to_path_buf(),
        source,
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| HostError::Io {
        operation: "restrict private file",
        path: path.to_path_buf(),
        source,
    })
}

fn canonical_existing(path: &Path) -> Result<PathBuf, HostError> {
    fs::canonicalize(path).map_err(|source| HostError::Io {
        operation: "canonicalize protected path",
        path: path.to_path_buf(),
        source,
    })
}

fn canonical_directory(path: &Path, subject: &str) -> Result<PathBuf, HostError> {
    let canonical = canonical_existing(path)?;
    if !canonical.is_dir() {
        return Err(HostError::InvalidManifest(format!(
            "{subject} is not a directory"
        )));
    }
    Ok(canonical)
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn resolve_revision(repository: &Path, revision: &str) -> Result<String, HostError> {
    let output = git(repository)
        .args(["rev-parse", "--verify", "--end-of-options"])
        .arg(format!("{revision}^{{commit}}"))
        .output()
        .map_err(|source| HostError::Io {
            operation: "resolve Git revision",
            path: repository.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(git_failed("resolve revision", output));
    }
    let commit = String::from_utf8(output.stdout)
        .map_err(|_| HostError::Git("Git emitted a non-UTF-8 commit ID".to_owned()))?;
    let commit = commit.trim();
    if commit.len() != 40 && commit.len() != 64
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(HostError::Git(
            "Git emitted an invalid resolved commit ID".to_owned(),
        ));
    }
    Ok(commit.to_owned())
}

fn add_worktree(repository: &Path, worktree: &Path, revision: &str) -> Result<(), HostError> {
    let output = git(repository)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "worktree",
            "add",
            "--detach",
        ])
        .arg(worktree)
        .arg(revision)
        .output()
        .map_err(|source| HostError::Io {
            operation: "create Git worktree",
            path: worktree.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(git_failed("create worktree", output));
    }
    Ok(())
}

fn remove_worktree(repository: &Path, worktree: &Path) -> Result<(), HostError> {
    let output = git(repository)
        .args(["worktree", "remove", "--force"])
        .arg(worktree)
        .output()
        .map_err(|source| HostError::Io {
            operation: "remove Git worktree",
            path: worktree.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(git_failed("remove worktree", output));
    }
    Ok(())
}

fn rollback_population(repository: &Path, root: &Path) {
    let operators = root.join("operators");
    if let Ok(entries) = fs::read_dir(operators) {
        for entry in entries.flatten() {
            let worktree = entry.path().join("worktree");
            if worktree.exists() {
                let _ = remove_worktree(repository, &worktree);
            }
        }
    }
    let _ = fs::remove_dir_all(root);
    let _ = git(repository).args(["worktree", "prune"]).status();
}

fn git(repository: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repository)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
    command
}

fn git_failed(operation: &'static str, output: Output) -> HostError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    HostError::Git(format!(
        "Git could not {operation} (status {}): {}",
        output.status,
        stderr.trim()
    ))
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

/// Stable operator-host failure.
#[derive(Debug)]
pub enum HostError {
    RootAlreadyExists(PathBuf),
    ProtectedPathOverlap {
        subject: String,
        protected_kind: &'static str,
    },
    InvalidManifest(String),
    UndeclaredCommunication(String),
    AccessDenied(String),
    Git(String),
    Identity(IdentityError),
    Json(serde_json::Error),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

impl HostError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RootAlreadyExists(_) => "OPERATOR_ROOT_EXISTS",
            Self::ProtectedPathOverlap { .. } => "OPERATOR_PROTECTED_PATH_OVERLAP",
            Self::InvalidManifest(_) => "OPERATOR_MANIFEST_INVALID",
            Self::UndeclaredCommunication(_) => "OPERATOR_COMMUNICATION_UNDECLARED",
            Self::AccessDenied(_) => "OPERATOR_PATH_ACCESS_DENIED",
            Self::Git(_) => "OPERATOR_GIT_FAILED",
            Self::Identity(_) => "OPERATOR_IDENTITY_FAILED",
            Self::Json(_) => "OPERATOR_CONFIG_JSON_FAILED",
            Self::Io { .. } => "OPERATOR_FILESYSTEM_FAILED",
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootAlreadyExists(path) => {
                write!(formatter, "operator root {} already exists", path.display())
            }
            Self::ProtectedPathOverlap {
                subject,
                protected_kind,
            } => write!(
                formatter,
                "{subject} overlaps protected {protected_kind} storage"
            ),
            Self::InvalidManifest(message) => {
                write!(formatter, "invalid operator manifest: {message}")
            }
            Self::UndeclaredCommunication(channel) => write!(
                formatter,
                "operator is not a participant in communication channel {channel}"
            ),
            Self::AccessDenied(message) => {
                write!(formatter, "operator path access denied: {message}")
            }
            Self::Git(message) => formatter.write_str(message),
            Self::Identity(error) => write!(formatter, "cannot provision actor identity: {error}"),
            Self::Json(error) => write!(formatter, "cannot encode operator configuration: {error}"),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "cannot {operation} {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for HostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
