//! Deterministic mechanism execution, dependency ordering, and state isolation.

use super::{
    MechanismExportId, MechanismId, MechanismManifest, MechanismSetConfig, MechanismStatus,
    MechanismVersion,
};
use crate::{
    actions::{Action, SignedAction},
    events::CanonicalEvent,
    primitives::MechanismSetId,
    state::{MechanismNamespace, StateBatch, StateKey, StateValue},
};
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

/// A deterministic compiled economic mechanism.
pub trait Mechanism {
    fn manifest(&self) -> MechanismManifest;

    fn validate_config(&self, config: &[u8]) -> Result<(), MechanismError>;

    fn pre_action(
        &self,
        view: &MechanismReadView<'_>,
        action: &SignedAction<Action>,
    ) -> Result<(), MechanismError>;

    fn on_event(
        &self,
        view: &MechanismReadView<'_>,
        event: &CanonicalEvent,
    ) -> Result<Vec<MechanismMutation>, MechanismError>;

    fn on_epoch(
        &self,
        view: &MechanismReadView<'_>,
        epoch: u64,
    ) -> Result<Vec<MechanismMutation>, MechanismError>;

    fn check_invariants(&self, view: &MechanismReadView<'_>)
    -> Result<(), MechanismInvariantError>;
}

/// A stable mechanism failure suitable for propagation through execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MechanismError {
    code: &'static str,
    message: String,
}

impl MechanismError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MechanismError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MechanismError {}

/// A failed post-mutation mechanism invariant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MechanismInvariantError {
    code: &'static str,
    message: String,
}

impl MechanismInvariantError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MechanismInvariantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MechanismInvariantError {}

/// The globally unambiguous identity of one exported mechanism value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MechanismExportKey {
    pub mechanism_id: MechanismId,
    pub export_id: MechanismExportId,
}

impl MechanismExportKey {
    pub const fn new(mechanism_id: MechanismId, export_id: MechanismExportId) -> Self {
        Self {
            mechanism_id,
            export_id,
        }
    }
}

/// An immutable finalized collection of mechanism exports.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MechanismExports(BTreeMap<MechanismExportKey, StateValue>);

impl MechanismExports {
    pub fn new(
        exports: impl IntoIterator<Item = (MechanismExportKey, StateValue)>,
    ) -> Result<Self, MechanismExportError> {
        let mut values = BTreeMap::new();
        for (key, value) in exports {
            if values.insert(key, value).is_some() {
                return Err(MechanismExportError::Collision(key));
            }
        }
        Ok(Self(values))
    }

    pub const fn empty() -> Self {
        Self(BTreeMap::new())
    }

    pub fn get(&self, key: MechanismExportKey) -> Option<StateValue> {
        self.0.get(&key).cloned()
    }

    fn keys(&self) -> impl Iterator<Item = MechanismExportKey> + '_ {
        self.0.keys().copied()
    }
}

/// Invalid construction of an immutable export snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MechanismExportError {
    Collision(MechanismExportKey),
}

impl fmt::Display for MechanismExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collision(key) => write!(
                formatter,
                "duplicate export {} from {}",
                key.export_id.get(),
                key.mechanism_id
            ),
        }
    }
}

impl std::error::Error for MechanismExportError {}

/// A restricted, immutable mechanism view over finalized state and exports.
pub struct MechanismReadView<'a> {
    state: &'a dyn StateBatch,
    manifest: &'a MechanismManifest,
    exports: &'a MechanismExports,
}

impl<'a> MechanismReadView<'a> {
    fn new(
        state: &'a dyn StateBatch,
        manifest: &'a MechanismManifest,
        exports: &'a MechanismExports,
    ) -> Self {
        Self {
            state,
            manifest,
            exports,
        }
    }

    /// Reads canonical protocol state. Mechanism-private keys require `own`.
    pub fn canonical(&self, key: &StateKey) -> Result<Option<StateValue>, MechanismReadError> {
        if key.namespace() == crate::state::StateNamespace::Mechanism {
            return Err(MechanismReadError::MechanismStateThroughCanonicalAccessor);
        }
        Ok(self.state.get(key))
    }

    /// Returns canonical protocol entries in ascending binary-key order.
    pub fn canonical_entries(&self) -> Vec<(StateKey, StateValue)> {
        self.state
            .entries()
            .into_iter()
            .filter(|(key, _)| key.namespace() != crate::state::StateNamespace::Mechanism)
            .collect()
    }

    /// Constructs this mechanism's version-isolated state key.
    pub fn own_key(&self, local_key: &[u8]) -> StateKey {
        mechanism_state_key(
            self.manifest.state_namespace,
            self.manifest.version,
            local_key,
        )
    }

    /// Reads this mechanism's own version-isolated state.
    pub fn own(&self, local_key: &[u8]) -> Option<StateValue> {
        self.state.get(&self.own_key(local_key))
    }

    /// Returns this mechanism's own entries in ascending local-key order.
    pub fn own_entries(&self) -> Vec<(Box<[u8]>, StateValue)> {
        let prefix = mechanism_state_prefix(self.manifest.state_namespace, self.manifest.version);
        self.state
            .entries()
            .into_iter()
            .filter_map(|(key, value)| {
                key.as_bytes()
                    .strip_prefix(prefix.as_slice())
                    .map(|local| (local.into(), value))
            })
            .collect()
    }

    /// Reads only an export declared by both dependency and export ID.
    pub fn dependency_export(
        &self,
        provider: MechanismId,
        export_id: MechanismExportId,
    ) -> Result<Option<StateValue>, MechanismReadError> {
        if !self.manifest.requires.iter().any(|id| *id == provider) {
            return Err(MechanismReadError::UndeclaredDependency(provider));
        }
        if !self
            .manifest
            .reads_exports
            .iter()
            .any(|id| *id == export_id)
        {
            return Err(MechanismReadError::UndeclaredExport(export_id));
        }
        Ok(self
            .exports
            .get(MechanismExportKey::new(provider, export_id)))
    }
}

/// A mechanism attempted a read outside its declared view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MechanismReadError {
    MechanismStateThroughCanonicalAccessor,
    UndeclaredDependency(MechanismId),
    UndeclaredExport(MechanismExportId),
}

impl fmt::Display for MechanismReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MechanismStateThroughCanonicalAccessor => {
                formatter.write_str("mechanism state is not canonical state")
            }
            Self::UndeclaredDependency(id) => write!(formatter, "undeclared dependency {id}"),
            Self::UndeclaredExport(id) => {
                write!(formatter, "undeclared mechanism export {}", id.get())
            }
        }
    }
}

impl std::error::Error for MechanismReadError {}

impl From<MechanismReadError> for MechanismError {
    fn from(error: MechanismReadError) -> Self {
        Self::new("MECHANISM_READ_UNDECLARED", error.to_string())
    }
}

/// One requested mechanism-private state change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MechanismMutation {
    key: StateKey,
    value: Option<StateValue>,
}

impl MechanismMutation {
    pub fn put(key: StateKey, value: StateValue) -> Self {
        Self {
            key,
            value: Some(value),
        }
    }

    pub fn delete(key: StateKey) -> Self {
        Self { key, value: None }
    }

    pub fn key(&self) -> &StateKey {
        &self.key
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}

/// Produces the only state-key prefix writable by a manifest version.
pub fn mechanism_state_key(
    namespace: MechanismNamespace,
    version: MechanismVersion,
    local_key: &[u8],
) -> StateKey {
    let mut versioned_key = Vec::with_capacity(6 + local_key.len());
    versioned_key.extend_from_slice(&version.major.to_be_bytes());
    versioned_key.extend_from_slice(&version.minor.to_be_bytes());
    versioned_key.extend_from_slice(&version.patch.to_be_bytes());
    versioned_key.extend_from_slice(local_key);
    StateKey::mechanism(namespace, &versioned_key)
}

fn mechanism_state_prefix(namespace: MechanismNamespace, version: MechanismVersion) -> [u8; 9] {
    let key = mechanism_state_key(namespace, version, &[]);
    key.as_bytes()
        .try_into()
        .expect("an empty versioned mechanism key has a fixed length")
}

/// A compiled, genesis-validated mechanism registry.
#[derive(Debug)]
pub struct MechanismRegistry<M> {
    modules: Vec<RegisteredMechanism<M>>,
}

/// A genesis-fixed compiled mechanism set and its finalized export snapshot.
///
/// This is the mechanism value accepted by authoritative block execution. The
/// registry order is validated once at construction, and exports are immutable
/// for the lifetime of the set so executions cannot observe mutable ambient
/// configuration.
#[derive(Debug)]
pub struct MechanismSet<M> {
    id: MechanismSetId,
    registry: MechanismRegistry<M>,
    exports: MechanismExports,
}

impl<M: Mechanism> MechanismSet<M> {
    /// Compiles a set whose mechanisms do not consume finalized exports.
    pub fn compile(
        config: &MechanismSetConfig,
        instances: Vec<M>,
    ) -> Result<Self, MechanismRegistryError> {
        Self::compile_with_exports(config, instances, MechanismExports::empty())
    }

    /// Compiles a set with one immutable finalized dependency-export snapshot.
    pub fn compile_with_exports(
        config: &MechanismSetConfig,
        instances: Vec<M>,
        exports: MechanismExports,
    ) -> Result<Self, MechanismRegistryError> {
        let registry = MechanismRegistry::compile(config, instances)?;
        registry.validate_exports(&exports)?;
        Ok(Self {
            id: config.id(),
            registry,
            exports,
        })
    }

    /// Returns the exact genesis-committed mechanism-set identity.
    pub const fn id(&self) -> MechanismSetId {
        self.id
    }

    /// Returns mechanism IDs in deterministic dependency order.
    pub fn ordered_ids(&self) -> Vec<MechanismId> {
        self.registry.ordered_ids()
    }

    /// Runs every active mechanism's pre-action validation.
    pub fn pre_action(
        &self,
        state: &dyn StateBatch,
        action: &SignedAction<Action>,
    ) -> Result<(), MechanismRegistryError> {
        self.registry.pre_action(state, &self.exports, action)
    }

    /// Passes one event through the deterministic per-event mutation pipeline.
    pub fn on_event(
        &self,
        state: &mut dyn StateBatch,
        event: &CanonicalEvent,
    ) -> Result<(), MechanismRegistryError> {
        self.registry.on_event(state, &self.exports, event)
    }

    /// Runs the deterministic epoch hook for every active mechanism.
    pub fn on_epoch(
        &self,
        state: &mut dyn StateBatch,
        epoch: u64,
    ) -> Result<(), MechanismRegistryError> {
        self.registry.on_epoch(state, &self.exports, epoch)
    }

    /// Runs every active mechanism invariant against final candidate state.
    pub fn check_invariants(&self, state: &dyn StateBatch) -> Result<(), MechanismRegistryError> {
        self.registry.check_invariants(state, &self.exports)
    }
}

#[derive(Debug)]
struct RegisteredMechanism<M> {
    instance: M,
    manifest: MechanismManifest,
}

impl<M: Mechanism> MechanismRegistry<M> {
    /// Validates selections, module configs, manifests, and dependency order.
    pub fn compile(
        config: &MechanismSetConfig,
        instances: Vec<M>,
    ) -> Result<Self, MechanismRegistryError> {
        let selections: BTreeMap<_, _> = config
            .mechanisms()
            .iter()
            .map(|selection| (selection.id, selection))
            .collect();
        let mut modules = BTreeMap::new();
        let mut manifests = Vec::with_capacity(instances.len());

        for instance in instances {
            let manifest = instance.manifest();
            let selection = selections
                .get(&manifest.id)
                .ok_or(MechanismRegistryError::UnselectedInstance(manifest.id))?;
            if modules.contains_key(&manifest.id) {
                return Err(MechanismRegistryError::DuplicateManifest(manifest.id));
            }
            if manifest.version != selection.version {
                return Err(MechanismRegistryError::VersionMismatch {
                    mechanism: manifest.id,
                    selected: selection.version,
                    compiled: manifest.version,
                });
            }
            if manifest.config_digest != selection.config.digest() {
                return Err(MechanismRegistryError::ConfigDigestMismatch(manifest.id));
            }
            instance
                .validate_config(selection.config.as_slice())
                .map_err(|error| MechanismRegistryError::Module {
                    mechanism: manifest.id,
                    error,
                })?;
            manifests.push(manifest.clone());
            modules.insert(manifest.id, RegisteredMechanism { instance, manifest });
        }

        for id in selections.keys() {
            if !modules.contains_key(id) {
                return Err(MechanismRegistryError::MissingInstance(*id));
            }
        }

        let order = validate_and_order_manifests(&manifests)?;
        let ordered = order
            .into_iter()
            .map(|id| modules.remove(&id).expect("validated manifest exists"))
            .collect();
        Ok(Self { modules: ordered })
    }

    pub fn ordered_ids(&self) -> Vec<MechanismId> {
        self.modules
            .iter()
            .map(|module| module.manifest.id)
            .collect()
    }

    pub fn manifests(&self) -> impl ExactSizeIterator<Item = &MechanismManifest> {
        self.modules.iter().map(|module| &module.manifest)
    }

    /// Runs every pre-action check against one immutable finalized view.
    pub fn pre_action(
        &self,
        state: &dyn StateBatch,
        exports: &MechanismExports,
        action: &SignedAction<Action>,
    ) -> Result<(), MechanismRegistryError> {
        self.validate_exports(exports)?;
        for module in &self.modules {
            let view = MechanismReadView::new(state, &module.manifest, exports);
            module.instance.pre_action(&view, action).map_err(|error| {
                MechanismRegistryError::Module {
                    mechanism: module.manifest.id,
                    error,
                }
            })?;
        }
        Ok(())
    }

    /// Collects all event outputs from the same pre-event view, then applies them atomically.
    pub fn on_event(
        &self,
        state: &mut dyn StateBatch,
        exports: &MechanismExports,
        event: &CanonicalEvent,
    ) -> Result<(), MechanismRegistryError> {
        self.validate_exports(exports)?;
        let mut emitted = Vec::new();
        for module in &self.modules {
            let view = MechanismReadView::new(state, &module.manifest, exports);
            let mutations = module.instance.on_event(&view, event).map_err(|error| {
                MechanismRegistryError::Module {
                    mechanism: module.manifest.id,
                    error,
                }
            })?;
            emitted.extend(
                mutations
                    .into_iter()
                    .map(|mutation| (module.manifest.id, mutation)),
            );
        }
        self.apply_and_check(state, exports, emitted)
    }

    /// Collects all epoch outputs from the same pre-epoch view, then applies them atomically.
    pub fn on_epoch(
        &self,
        state: &mut dyn StateBatch,
        exports: &MechanismExports,
        epoch: u64,
    ) -> Result<(), MechanismRegistryError> {
        self.validate_exports(exports)?;
        let mut emitted = Vec::new();
        for module in &self.modules {
            let view = MechanismReadView::new(state, &module.manifest, exports);
            let mutations = module.instance.on_epoch(&view, epoch).map_err(|error| {
                MechanismRegistryError::Module {
                    mechanism: module.manifest.id,
                    error,
                }
            })?;
            emitted.extend(
                mutations
                    .into_iter()
                    .map(|mutation| (module.manifest.id, mutation)),
            );
        }
        self.apply_and_check(state, exports, emitted)
    }

    /// Runs every invariant against the same current state and export snapshot.
    pub fn check_invariants(
        &self,
        state: &dyn StateBatch,
        exports: &MechanismExports,
    ) -> Result<(), MechanismRegistryError> {
        self.validate_exports(exports)?;
        for module in &self.modules {
            let view = MechanismReadView::new(state, &module.manifest, exports);
            module.instance.check_invariants(&view).map_err(|error| {
                MechanismRegistryError::Invariant {
                    mechanism: module.manifest.id,
                    error,
                }
            })?;
        }
        Ok(())
    }

    fn validate_exports(&self, exports: &MechanismExports) -> Result<(), MechanismRegistryError> {
        let selected: BTreeSet<_> = self
            .modules
            .iter()
            .map(|module| module.manifest.id)
            .collect();
        for key in exports.keys() {
            if !selected.contains(&key.mechanism_id) {
                return Err(MechanismRegistryError::ExportProviderNotSelected(key));
            }
        }
        Ok(())
    }

    fn apply_and_check(
        &self,
        state: &mut dyn StateBatch,
        exports: &MechanismExports,
        mut emitted: Vec<(MechanismId, MechanismMutation)>,
    ) -> Result<(), MechanismRegistryError> {
        emitted.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.key.cmp(&right.1.key))
        });

        for (id, mutation) in &emitted {
            let manifest = &self
                .modules
                .iter()
                .find(|module| module.manifest.id == *id)
                .expect("only registered mechanisms emit mutations")
                .manifest;
            let prefix = mechanism_state_prefix(manifest.state_namespace, manifest.version);
            if !mutation.key.as_bytes().starts_with(&prefix) {
                return Err(MechanismRegistryError::CrossNamespaceWrite {
                    mechanism: *id,
                    key: mutation.key.clone(),
                });
            }
        }
        for pair in emitted.windows(2) {
            if pair[0].1.key == pair[1].1.key {
                return Err(MechanismRegistryError::MutationCollision(
                    pair[0].1.key.clone(),
                ));
            }
        }

        state.fork();
        for (_, mutation) in emitted {
            if let Some(value) = mutation.value {
                state.put(mutation.key, value);
            } else {
                state.delete(&mutation.key);
            }
        }
        if let Err(error) = self.check_invariants(state, exports) {
            state
                .rollback()
                .expect("the registry opened the transaction being rolled back");
            return Err(error);
        }
        state
            .commit()
            .expect("the registry opened the transaction being committed");
        Ok(())
    }
}

/// Validates manifests and returns a stable topological order with ID tie-breaking.
pub fn validate_and_order_manifests(
    manifests: &[MechanismManifest],
) -> Result<Vec<MechanismId>, MechanismRegistryError> {
    let mut by_id = BTreeMap::new();
    let mut namespaces = BTreeMap::new();
    for manifest in manifests {
        if by_id.insert(manifest.id, manifest).is_some() {
            return Err(MechanismRegistryError::DuplicateManifest(manifest.id));
        }
        if let Some(prior) = namespaces.insert(manifest.state_namespace, manifest.id) {
            return Err(MechanismRegistryError::NamespaceCollision {
                first: prior,
                second: manifest.id,
                namespace: manifest.state_namespace,
            });
        }
        if !matches!(
            manifest.status,
            MechanismStatus::Implemented
                | MechanismStatus::Experimental
                | MechanismStatus::Accepted
        ) {
            return Err(MechanismRegistryError::StatusNotSelectable {
                mechanism: manifest.id,
                status: manifest.status,
            });
        }

        let mut dependencies = BTreeSet::new();
        for dependency in manifest.requires.iter().copied() {
            if !dependencies.insert(dependency) {
                return Err(MechanismRegistryError::DuplicateDependency {
                    mechanism: manifest.id,
                    dependency,
                });
            }
        }
        let mut export_ids = BTreeSet::new();
        for export_id in manifest.reads_exports.iter().copied() {
            if !export_ids.insert(export_id) {
                return Err(MechanismRegistryError::DuplicateExportRead {
                    mechanism: manifest.id,
                    export_id,
                });
            }
        }
        if !manifest.reads_exports.is_empty() && manifest.requires.is_empty() {
            return Err(MechanismRegistryError::ExportWithoutDependency(manifest.id));
        }
    }

    let mut indegree = BTreeMap::new();
    let mut dependents: BTreeMap<MechanismId, BTreeSet<MechanismId>> = BTreeMap::new();
    for manifest in manifests {
        indegree.insert(manifest.id, manifest.requires.len());
        for dependency in manifest.requires.iter().copied() {
            if !by_id.contains_key(&dependency) {
                return Err(MechanismRegistryError::DependencyNotSelected {
                    mechanism: manifest.id,
                    dependency,
                });
            }
            dependents
                .entry(dependency)
                .or_default()
                .insert(manifest.id);
        }
    }

    let mut ready: BTreeSet<_> = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
        .collect();
    let mut ordered = Vec::with_capacity(manifests.len());
    while let Some(id) = ready.pop_first() {
        ordered.push(id);
        if let Some(children) = dependents.get(&id) {
            for child in children {
                let degree = indegree
                    .get_mut(child)
                    .expect("a dependent manifest has an indegree");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(*child);
                }
            }
        }
    }
    if ordered.len() != manifests.len() {
        let cycle = indegree
            .into_iter()
            .filter_map(|(id, degree)| (degree != 0).then_some(id))
            .collect();
        return Err(MechanismRegistryError::DependencyCycle(cycle));
    }
    Ok(ordered)
}

/// Invalid registry configuration or deterministic execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MechanismRegistryError {
    MissingInstance(MechanismId),
    UnselectedInstance(MechanismId),
    DuplicateManifest(MechanismId),
    VersionMismatch {
        mechanism: MechanismId,
        selected: MechanismVersion,
        compiled: MechanismVersion,
    },
    ConfigDigestMismatch(MechanismId),
    Module {
        mechanism: MechanismId,
        error: MechanismError,
    },
    Invariant {
        mechanism: MechanismId,
        error: MechanismInvariantError,
    },
    StatusNotSelectable {
        mechanism: MechanismId,
        status: MechanismStatus,
    },
    NamespaceCollision {
        first: MechanismId,
        second: MechanismId,
        namespace: MechanismNamespace,
    },
    DuplicateDependency {
        mechanism: MechanismId,
        dependency: MechanismId,
    },
    DependencyNotSelected {
        mechanism: MechanismId,
        dependency: MechanismId,
    },
    DependencyCycle(Vec<MechanismId>),
    DuplicateExportRead {
        mechanism: MechanismId,
        export_id: MechanismExportId,
    },
    ExportWithoutDependency(MechanismId),
    ExportProviderNotSelected(MechanismExportKey),
    CrossNamespaceWrite {
        mechanism: MechanismId,
        key: StateKey,
    },
    MutationCollision(StateKey),
}

impl MechanismRegistryError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingInstance(_) => "MECHANISM_INSTANCE_MISSING",
            Self::UnselectedInstance(_) => "MECHANISM_INSTANCE_NOT_SELECTED",
            Self::DuplicateManifest(_) => "MECHANISM_MANIFEST_DUPLICATE",
            Self::VersionMismatch { .. } => "MECHANISM_VERSION_MISMATCH",
            Self::ConfigDigestMismatch(_) => "MECHANISM_CONFIG_DIGEST_MISMATCH",
            Self::Module { .. } => "MECHANISM_EXECUTION_FAILED",
            Self::Invariant { .. } => "MECHANISM_INVARIANT_FAILED",
            Self::StatusNotSelectable { .. } => "MECHANISM_STATUS_NOT_SELECTABLE",
            Self::NamespaceCollision { .. } => "MECHANISM_NAMESPACE_COLLISION",
            Self::DuplicateDependency { .. } => "MECHANISM_DEPENDENCY_DUPLICATE",
            Self::DependencyNotSelected { .. } => "MECHANISM_DEPENDENCY_MISSING",
            Self::DependencyCycle(_) => "MECHANISM_DEPENDENCY_CYCLE",
            Self::DuplicateExportRead { .. } => "MECHANISM_EXPORT_READ_DUPLICATE",
            Self::ExportWithoutDependency(_) => "MECHANISM_EXPORT_DEPENDENCY_MISSING",
            Self::ExportProviderNotSelected(_) => "MECHANISM_EXPORT_PROVIDER_MISSING",
            Self::CrossNamespaceWrite { .. } => "MECHANISM_CROSS_NAMESPACE_WRITE",
            Self::MutationCollision(_) => "MECHANISM_MUTATION_COLLISION",
        }
    }
}

impl fmt::Display for MechanismRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingInstance(id) => {
                write!(formatter, "selected mechanism {id} has no instance")
            }
            Self::UnselectedInstance(id) => write!(formatter, "instance {id} was not selected"),
            Self::DuplicateManifest(id) => write!(formatter, "duplicate manifest for {id}"),
            Self::VersionMismatch {
                mechanism,
                selected,
                compiled,
            } => write!(
                formatter,
                "{mechanism} selected version {selected}, compiled version is {compiled}"
            ),
            Self::ConfigDigestMismatch(id) => write!(formatter, "config digest mismatch for {id}"),
            Self::Module { mechanism, error } => write!(formatter, "{mechanism}: {error}"),
            Self::Invariant { mechanism, error } => write!(formatter, "{mechanism}: {error}"),
            Self::StatusNotSelectable { mechanism, status } => {
                write!(formatter, "{mechanism} status {status:?} is not selectable")
            }
            Self::NamespaceCollision {
                first,
                second,
                namespace,
            } => write!(
                formatter,
                "{first} and {second} share namespace {}",
                namespace.get()
            ),
            Self::DuplicateDependency {
                mechanism,
                dependency,
            } => write!(
                formatter,
                "{mechanism} declares dependency {dependency} twice"
            ),
            Self::DependencyNotSelected {
                mechanism,
                dependency,
            } => write!(formatter, "{mechanism} requires unselected {dependency}"),
            Self::DependencyCycle(ids) => write!(formatter, "mechanism dependency cycle: {ids:?}"),
            Self::DuplicateExportRead {
                mechanism,
                export_id,
            } => write!(
                formatter,
                "{mechanism} declares export {} twice",
                export_id.get()
            ),
            Self::ExportWithoutDependency(id) => {
                write!(formatter, "{id} reads exports without a dependency")
            }
            Self::ExportProviderNotSelected(key) => write!(
                formatter,
                "export provider {} for export {} is not selected",
                key.mechanism_id,
                key.export_id.get()
            ),
            Self::CrossNamespaceWrite { mechanism, key } => write!(
                formatter,
                "{mechanism} attempted a write outside its namespace: {:02x?}",
                key.as_bytes()
            ),
            Self::MutationCollision(key) => {
                write!(
                    formatter,
                    "multiple mutations target {:02x?}",
                    key.as_bytes()
                )
            }
        }
    }
}

impl std::error::Error for MechanismRegistryError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bounded::BoundedVec,
        mechanisms::CanonicalMechanismConfig,
        primitives::{JobId, ProtocolVersion},
        state::InMemoryStateBatch,
    };

    #[derive(Clone, Debug)]
    enum Behavior {
        None,
        Put {
            key: StateKey,
            value: StateValue,
        },
        TwoPuts(StateKey),
        CopyExport {
            provider: MechanismId,
            export: MechanismExportId,
            target: StateKey,
        },
    }

    #[derive(Debug)]
    struct TestMechanism {
        manifest: MechanismManifest,
        behavior: Behavior,
        config_valid: bool,
    }

    impl Mechanism for TestMechanism {
        fn manifest(&self) -> MechanismManifest {
            self.manifest.clone()
        }

        fn validate_config(&self, _config: &[u8]) -> Result<(), MechanismError> {
            if self.config_valid {
                Ok(())
            } else {
                Err(MechanismError::new("TEST_CONFIG", "invalid test config"))
            }
        }

        fn pre_action(
            &self,
            _view: &MechanismReadView<'_>,
            _action: &SignedAction<Action>,
        ) -> Result<(), MechanismError> {
            Ok(())
        }

        fn on_event(
            &self,
            view: &MechanismReadView<'_>,
            _event: &CanonicalEvent,
        ) -> Result<Vec<MechanismMutation>, MechanismError> {
            match &self.behavior {
                Behavior::None => Ok(Vec::new()),
                Behavior::Put { key, value } => {
                    Ok(vec![MechanismMutation::put(key.clone(), value.clone())])
                }
                Behavior::TwoPuts(key) => Ok(vec![
                    MechanismMutation::put(key.clone(), b"first".as_slice().into()),
                    MechanismMutation::put(key.clone(), b"second".as_slice().into()),
                ]),
                Behavior::CopyExport {
                    provider,
                    export,
                    target,
                } => {
                    let value = view
                        .dependency_export(*provider, *export)?
                        .unwrap_or_else(|| b"missing".as_slice().into());
                    Ok(vec![MechanismMutation::put(target.clone(), value)])
                }
            }
        }

        fn on_epoch(
            &self,
            _view: &MechanismReadView<'_>,
            _epoch: u64,
        ) -> Result<Vec<MechanismMutation>, MechanismError> {
            Ok(Vec::new())
        }

        fn check_invariants(
            &self,
            _view: &MechanismReadView<'_>,
        ) -> Result<(), MechanismInvariantError> {
            Ok(())
        }
    }

    fn selection(id: MechanismId) -> super::super::MechanismSelection {
        super::super::MechanismSelection::new(
            id,
            MechanismVersion::V1_0_0,
            CanonicalMechanismConfig::empty(),
        )
    }

    fn manifest(
        id: MechanismId,
        requires: Vec<MechanismId>,
        reads: Vec<MechanismExportId>,
    ) -> MechanismManifest {
        MechanismManifest {
            id,
            version: MechanismVersion::V1_0_0,
            status: MechanismStatus::Implemented,
            requires: BoundedVec::new(requires).unwrap(),
            reads_exports: BoundedVec::new(reads).unwrap(),
            state_namespace: MechanismNamespace::new(id.get()),
            config_digest: CanonicalMechanismConfig::empty().digest(),
        }
    }

    fn module(manifest: MechanismManifest, behavior: Behavior) -> TestMechanism {
        TestMechanism {
            manifest,
            behavior,
            config_valid: true,
        }
    }

    fn config(ids: &[MechanismId]) -> MechanismSetConfig {
        MechanismSetConfig::new(
            ProtocolVersion::V1,
            ids.iter().copied().map(selection).collect(),
        )
        .unwrap()
    }

    fn event() -> CanonicalEvent {
        CanonicalEvent::JobClosed {
            job_id: JobId::derive(b"registry-test"),
        }
    }

    #[test]
    fn topology_is_stable_by_dependency_then_id_and_cycles_fail() {
        let dependent = manifest(MechanismId::M00, vec![MechanismId::M01], vec![]);
        let dependency = manifest(MechanismId::M01, vec![], vec![]);
        let registry = MechanismRegistry::compile(
            &config(&[MechanismId::M00, MechanismId::M01]),
            vec![
                module(dependent.clone(), Behavior::None),
                module(dependency.clone(), Behavior::None),
            ],
        )
        .unwrap();
        assert_eq!(
            registry.ordered_ids(),
            vec![MechanismId::M01, MechanismId::M00]
        );

        let mut first = dependent;
        first.requires = BoundedVec::new(vec![MechanismId::M01]).unwrap();
        let mut second = dependency;
        second.requires = BoundedVec::new(vec![MechanismId::M00]).unwrap();
        let error = validate_and_order_manifests(&[first, second]).unwrap_err();
        assert_eq!(error.code(), "MECHANISM_DEPENDENCY_CYCLE");
    }

    #[test]
    fn proposed_status_missing_dependencies_and_namespace_collisions_fail() {
        let mut proposed = manifest(MechanismId::M00, vec![], vec![]);
        proposed.status = MechanismStatus::Proposed;
        assert_eq!(
            validate_and_order_manifests(&[proposed])
                .unwrap_err()
                .code(),
            "MECHANISM_STATUS_NOT_SELECTABLE"
        );

        let missing = manifest(MechanismId::M00, vec![MechanismId::M01], vec![]);
        assert_eq!(
            validate_and_order_manifests(&[missing]).unwrap_err().code(),
            "MECHANISM_DEPENDENCY_MISSING"
        );

        let first = manifest(MechanismId::M00, vec![], vec![]);
        let mut second = manifest(MechanismId::M01, vec![], vec![]);
        second.state_namespace = first.state_namespace;
        assert_eq!(
            validate_and_order_manifests(&[first, second])
                .unwrap_err()
                .code(),
            "MECHANISM_NAMESPACE_COLLISION"
        );
    }

    #[test]
    fn compile_delegates_config_validation_and_locks_digest() {
        let mut invalid = module(manifest(MechanismId::M00, vec![], vec![]), Behavior::None);
        invalid.config_valid = false;
        assert_eq!(
            MechanismRegistry::compile(&config(&[MechanismId::M00]), vec![invalid])
                .unwrap_err()
                .code(),
            "MECHANISM_EXECUTION_FAILED"
        );

        let mut wrong_digest = manifest(MechanismId::M00, vec![], vec![]);
        wrong_digest.config_digest = CanonicalMechanismConfig::new(vec![1]).unwrap().digest();
        assert_eq!(
            MechanismRegistry::compile(
                &config(&[MechanismId::M00]),
                vec![module(wrong_digest, Behavior::None)]
            )
            .unwrap_err()
            .code(),
            "MECHANISM_CONFIG_DIGEST_MISMATCH"
        );
    }

    #[test]
    fn undeclared_export_reads_fail() {
        let export = MechanismExportId::new(7);
        let consumer_manifest = manifest(MechanismId::M01, vec![], vec![]);
        let target = mechanism_state_key(
            consumer_manifest.state_namespace,
            consumer_manifest.version,
            b"copied",
        );
        let registry = MechanismRegistry::compile(
            &config(&[MechanismId::M01]),
            vec![module(
                consumer_manifest,
                Behavior::CopyExport {
                    provider: MechanismId::M00,
                    export,
                    target,
                },
            )],
        )
        .unwrap();
        let mut state = InMemoryStateBatch::new();
        let error = registry
            .on_event(&mut state, &MechanismExports::empty(), &event())
            .unwrap_err();
        assert_eq!(error.code(), "MECHANISM_EXECUTION_FAILED");
        let MechanismRegistryError::Module { error, .. } = error else {
            panic!("expected module error")
        };
        assert_eq!(error.code(), "MECHANISM_READ_UNDECLARED");
    }

    #[test]
    fn cross_namespace_writes_and_duplicate_keys_fail_without_writes() {
        let own_manifest = manifest(MechanismId::M00, vec![], vec![]);
        let foreign_key = mechanism_state_key(
            MechanismNamespace::new(99),
            MechanismVersion::V1_0_0,
            b"foreign",
        );
        let registry = MechanismRegistry::compile(
            &config(&[MechanismId::M00]),
            vec![module(
                own_manifest,
                Behavior::Put {
                    key: foreign_key,
                    value: b"bad".as_slice().into(),
                },
            )],
        )
        .unwrap();
        let mut state = InMemoryStateBatch::new();
        assert_eq!(
            registry
                .on_event(&mut state, &MechanismExports::empty(), &event())
                .unwrap_err()
                .code(),
            "MECHANISM_CROSS_NAMESPACE_WRITE"
        );
        assert!(state.entries().is_empty());

        let duplicate_manifest = manifest(MechanismId::M00, vec![], vec![]);
        let duplicate_key = mechanism_state_key(
            duplicate_manifest.state_namespace,
            duplicate_manifest.version,
            b"same",
        );
        let registry = MechanismRegistry::compile(
            &config(&[MechanismId::M00]),
            vec![module(duplicate_manifest, Behavior::TwoPuts(duplicate_key))],
        )
        .unwrap();
        assert_eq!(
            registry
                .on_event(&mut state, &MechanismExports::empty(), &event())
                .unwrap_err()
                .code(),
            "MECHANISM_MUTATION_COLLISION"
        );
        assert!(state.entries().is_empty());
    }

    #[test]
    fn all_modules_observe_the_same_frozen_export_snapshot() {
        let export = MechanismExportId::new(3);
        let provider_manifest = manifest(MechanismId::M00, vec![], vec![]);
        let provider_key = mechanism_state_key(
            provider_manifest.state_namespace,
            provider_manifest.version,
            b"source",
        );
        let consumer_manifest = manifest(MechanismId::M01, vec![MechanismId::M00], vec![export]);
        let consumer_key = mechanism_state_key(
            consumer_manifest.state_namespace,
            consumer_manifest.version,
            b"copy",
        );
        let registry = MechanismRegistry::compile(
            &config(&[MechanismId::M01, MechanismId::M00]),
            vec![
                module(
                    consumer_manifest,
                    Behavior::CopyExport {
                        provider: MechanismId::M00,
                        export,
                        target: consumer_key.clone(),
                    },
                ),
                module(
                    provider_manifest,
                    Behavior::Put {
                        key: provider_key.clone(),
                        value: b"same-event-new".as_slice().into(),
                    },
                ),
            ],
        )
        .unwrap();
        let exports = MechanismExports::new([(
            MechanismExportKey::new(MechanismId::M00, export),
            b"finalized-old".as_slice().into(),
        )])
        .unwrap();
        let mut state = InMemoryStateBatch::new();
        registry.on_event(&mut state, &exports, &event()).unwrap();

        assert_eq!(
            state.get(&provider_key).as_deref(),
            Some(b"same-event-new".as_slice())
        );
        assert_eq!(
            state.get(&consumer_key).as_deref(),
            Some(b"finalized-old".as_slice())
        );
        let keys: Vec<_> = state.entries().into_iter().map(|entry| entry.0).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn export_snapshot_collisions_fail() {
        let key = MechanismExportKey::new(MechanismId::M00, MechanismExportId::new(1));
        assert_eq!(
            MechanismExports::new([
                (key, b"one".as_slice().into()),
                (key, b"two".as_slice().into())
            ]),
            Err(MechanismExportError::Collision(key))
        );
    }
}
