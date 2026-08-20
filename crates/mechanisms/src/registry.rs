//! Concrete registry of mechanism implementations compiled into this binary.

use core::fmt;
use rachet_core::{
    actions::{Action, SignedAction},
    events::CanonicalEvent,
    mechanisms::{
        Mechanism, MechanismError, MechanismExports, MechanismInvariantError, MechanismManifest,
        MechanismMutation, MechanismReadView, MechanismRegistry, MechanismRegistryError,
        MechanismSetConfig,
    },
    state::StateBatch,
};

/// A closed wrapper around every mechanism implementation compiled for v1.
///
/// Adding a proposed catalog entry here is forbidden. A new variant is added
/// only when that mechanism's implementation work begins.
pub enum MechanismInstance {
    M00RecordOnly(Box<dyn Mechanism + Send>),
    M01NaiveReputation(Box<dyn Mechanism + Send>),
}

impl MechanismInstance {
    pub fn m00(instance: impl Mechanism + Send + 'static) -> Result<Self, MechanismInstanceError> {
        Self::boxed_m00(Box::new(instance))
    }

    pub fn m01(instance: impl Mechanism + Send + 'static) -> Result<Self, MechanismInstanceError> {
        Self::boxed_m01(Box::new(instance))
    }

    fn boxed_m00(instance: Box<dyn Mechanism + Send>) -> Result<Self, MechanismInstanceError> {
        let actual = instance.manifest().id;
        if actual != rachet_core::mechanisms::MechanismId::M00 {
            return Err(MechanismInstanceError::WrongVariant {
                expected: rachet_core::mechanisms::MechanismId::M00,
                actual,
            });
        }
        Ok(Self::M00RecordOnly(instance))
    }

    fn boxed_m01(instance: Box<dyn Mechanism + Send>) -> Result<Self, MechanismInstanceError> {
        let actual = instance.manifest().id;
        if actual != rachet_core::mechanisms::MechanismId::M01 {
            return Err(MechanismInstanceError::WrongVariant {
                expected: rachet_core::mechanisms::MechanismId::M01,
                actual,
            });
        }
        Ok(Self::M01NaiveReputation(instance))
    }

    fn inner(&self) -> &dyn Mechanism {
        match self {
            Self::M00RecordOnly(instance) | Self::M01NaiveReputation(instance) => instance.as_ref(),
        }
    }
}

impl Mechanism for MechanismInstance {
    fn manifest(&self) -> MechanismManifest {
        self.inner().manifest()
    }

    fn validate_config(&self, config: &[u8]) -> Result<(), MechanismError> {
        self.inner().validate_config(config)
    }

    fn pre_action(
        &self,
        view: &MechanismReadView<'_>,
        action: &SignedAction<Action>,
    ) -> Result<(), MechanismError> {
        self.inner().pre_action(view, action)
    }

    fn on_event(
        &self,
        view: &MechanismReadView<'_>,
        event: &CanonicalEvent,
    ) -> Result<Vec<MechanismMutation>, MechanismError> {
        self.inner().on_event(view, event)
    }

    fn on_epoch(
        &self,
        view: &MechanismReadView<'_>,
        epoch: u64,
    ) -> Result<Vec<MechanismMutation>, MechanismError> {
        self.inner().on_epoch(view, epoch)
    }

    fn check_invariants(
        &self,
        view: &MechanismReadView<'_>,
    ) -> Result<(), MechanismInvariantError> {
        self.inner().check_invariants(view)
    }
}

/// A mechanism was placed in the wrong closed enum variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MechanismInstanceError {
    WrongVariant {
        expected: rachet_core::mechanisms::MechanismId,
        actual: rachet_core::mechanisms::MechanismId,
    },
}

impl fmt::Display for MechanismInstanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongVariant { expected, actual } => {
                write!(
                    formatter,
                    "variant {expected} cannot wrap implementation {actual}"
                )
            }
        }
    }
}

impl std::error::Error for MechanismInstanceError {}

/// The concrete genesis-fixed mechanism registry used by execution.
pub struct CompiledMechanismRegistry {
    inner: MechanismRegistry<MechanismInstance>,
}

impl CompiledMechanismRegistry {
    pub fn compile(
        config: &MechanismSetConfig,
        instances: Vec<MechanismInstance>,
    ) -> Result<Self, MechanismRegistryError> {
        Ok(Self {
            inner: MechanismRegistry::compile(config, instances)?,
        })
    }

    pub fn ordered_ids(&self) -> Vec<rachet_core::mechanisms::MechanismId> {
        self.inner.ordered_ids()
    }

    pub fn manifests(&self) -> impl ExactSizeIterator<Item = &MechanismManifest> {
        self.inner.manifests()
    }

    pub fn pre_action(
        &self,
        state: &dyn StateBatch,
        exports: &MechanismExports,
        action: &SignedAction<Action>,
    ) -> Result<(), MechanismRegistryError> {
        self.inner.pre_action(state, exports, action)
    }

    pub fn on_event(
        &self,
        state: &mut dyn StateBatch,
        exports: &MechanismExports,
        event: &CanonicalEvent,
    ) -> Result<(), MechanismRegistryError> {
        self.inner.on_event(state, exports, event)
    }

    pub fn on_epoch(
        &self,
        state: &mut dyn StateBatch,
        exports: &MechanismExports,
        epoch: u64,
    ) -> Result<(), MechanismRegistryError> {
        self.inner.on_epoch(state, exports, epoch)
    }

    pub fn check_invariants(
        &self,
        state: &dyn StateBatch,
        exports: &MechanismExports,
    ) -> Result<(), MechanismRegistryError> {
        self.inner.check_invariants(state, exports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rachet_core::{
        bounded::BoundedVec,
        mechanisms::{
            CanonicalMechanismConfig, MechanismExportId, MechanismId, MechanismSelection,
            MechanismStatus, MechanismVersion,
        },
        primitives::ProtocolVersion,
        state::{InMemoryStateBatch, MechanismNamespace},
    };

    struct EmptyMechanism(MechanismManifest);

    impl Mechanism for EmptyMechanism {
        fn manifest(&self) -> MechanismManifest {
            self.0.clone()
        }

        fn validate_config(&self, config: &[u8]) -> Result<(), MechanismError> {
            if config.is_empty() {
                Ok(())
            } else {
                Err(MechanismError::new("TEST_CONFIG", "expected empty config"))
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
            _view: &MechanismReadView<'_>,
            _event: &CanonicalEvent,
        ) -> Result<Vec<MechanismMutation>, MechanismError> {
            Ok(Vec::new())
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

    fn implementation(id: MechanismId, dependencies: Vec<MechanismId>) -> EmptyMechanism {
        EmptyMechanism(MechanismManifest {
            id,
            version: MechanismVersion::V1_0_0,
            status: MechanismStatus::Implemented,
            requires: BoundedVec::new(dependencies).unwrap(),
            reads_exports: BoundedVec::<MechanismExportId, 32>::default(),
            state_namespace: MechanismNamespace::new(id.get()),
            config_digest: CanonicalMechanismConfig::empty().digest(),
        })
    }

    fn selection(id: MechanismId) -> MechanismSelection {
        MechanismSelection::new(
            id,
            MechanismVersion::V1_0_0,
            CanonicalMechanismConfig::empty(),
        )
    }

    #[test]
    fn closed_variants_reject_mismatched_implementations() {
        let error = MechanismInstance::m00(implementation(MechanismId::M01, Vec::new()))
            .err()
            .expect("mismatched variant must fail");
        assert_eq!(
            error,
            MechanismInstanceError::WrongVariant {
                expected: MechanismId::M00,
                actual: MechanismId::M01,
            }
        );
    }

    #[test]
    fn concrete_registry_uses_deterministic_topological_order() {
        let config = MechanismSetConfig::new(
            ProtocolVersion::V1,
            vec![selection(MechanismId::M00), selection(MechanismId::M01)],
        )
        .unwrap();
        let registry = CompiledMechanismRegistry::compile(
            &config,
            vec![
                MechanismInstance::m00(implementation(MechanismId::M00, vec![MechanismId::M01]))
                    .unwrap(),
                MechanismInstance::m01(implementation(MechanismId::M01, Vec::new())).unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(
            registry.ordered_ids(),
            vec![MechanismId::M01, MechanismId::M00]
        );

        let mut state = InMemoryStateBatch::new();
        registry
            .on_event(
                &mut state,
                &MechanismExports::empty(),
                &CanonicalEvent::EpochChanged {
                    previous: 0,
                    current: 1,
                },
            )
            .unwrap();
        assert!(state.entries().is_empty());
    }
}
