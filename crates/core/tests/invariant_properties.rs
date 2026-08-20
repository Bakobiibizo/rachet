use commonware_cryptography::{Signer as _, ed25519};
use proptest::prelude::*;
use rachet_core::{
    actions::{
        Action, ActionValidationError, ClaimDefinition, CloseJob, CreateJob, ResolutionPolicy,
        SignedAction,
    },
    artifacts::{ContentRef, GitArtifact, GitHash},
    blocks::{ConsensusNodeId, action_root},
    bounded::{BoundedBytes, BoundedVec},
    events::CanonicalEvent,
    invariants::check_core_invariants,
    mechanisms::{
        CanonicalMechanismConfig, Mechanism, MechanismError, MechanismExportId, MechanismId,
        MechanismInvariantError, MechanismManifest, MechanismMutation, MechanismReadView,
        MechanismRegistryError, MechanismSelection, MechanismSet, MechanismSetConfig,
        MechanismStatus, MechanismVersion,
    },
    primitives::{
        ActionId, ActorId, ChainId, ClaimId, JobId, MechanismSetId, ProtocolVersion, Sha256Digest,
    },
    state::{InMemoryStateBatch, MechanismNamespace, StateBatch, StateKey},
    transition::{
        BlockExecutionError, JobTransitionError, TransitionContext, create_job, execute_block,
    },
};

const CHAIN: ChainId = ChainId::new([0x29; 32]);

fn actor(seed: u64) -> ActorId {
    ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
}

fn bounded<const MAX: usize>(bytes: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(bytes).unwrap()
}

fn create_job_payload(candidate: [u8; 32], authority: ActorId) -> CreateJob {
    CreateJob {
        artifact: GitArtifact::new(
            bounded(b"https://git.invalid/property"),
            GitHash::sha1([1; 20]),
            GitHash::sha256(candidate),
            ContentRef::new(
                Sha256Digest::from([3; 32]),
                bounded(b"cas://property-spec"),
                bounded(b"text/plain"),
            ),
        ),
        claims: BoundedVec::new(vec![ClaimDefinition::new(bounded(b"property claim"))]).unwrap(),
        resolution_policy: ResolutionPolicy::ExperimentAuthority { authority },
        validation_opens_at: 10,
        validation_closes_at: 20,
        reveal_closes_at: None,
        challenge_closes_at: Some(30),
        supersedes: None,
        metadata: bounded(b"property"),
    }
}

#[derive(Clone, Copy, Debug)]
enum MutationMode {
    None,
    Own,
    Foreign(MechanismNamespace),
}

#[derive(Debug)]
struct PropertyMechanism {
    mode: MutationMode,
}

impl PropertyMechanism {
    fn manifest_value() -> MechanismManifest {
        MechanismManifest {
            id: MechanismId::M00,
            version: MechanismVersion::V1_0_0,
            status: MechanismStatus::Implemented,
            requires: BoundedVec::default(),
            reads_exports: BoundedVec::<MechanismExportId, 32>::default(),
            state_namespace: MechanismNamespace::new(0),
            config_digest: CanonicalMechanismConfig::empty().digest(),
        }
    }
}

impl Mechanism for PropertyMechanism {
    fn manifest(&self) -> MechanismManifest {
        Self::manifest_value()
    }

    fn validate_config(&self, config: &[u8]) -> Result<(), MechanismError> {
        if config.is_empty() {
            Ok(())
        } else {
            Err(MechanismError::new(
                "PROPERTY_CONFIG",
                "expected empty config",
            ))
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
        match self.mode {
            MutationMode::None => Ok(Vec::new()),
            MutationMode::Own => Ok(vec![MechanismMutation::put(
                view.own_key(b"event"),
                b"observed".as_slice().into(),
            )]),
            MutationMode::Foreign(namespace) => Ok(vec![MechanismMutation::put(
                rachet_core::mechanisms::mechanism_state_key(
                    namespace,
                    MechanismVersion::V1_0_0,
                    b"event",
                ),
                b"forbidden".as_slice().into(),
            )]),
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

fn mechanism_config() -> MechanismSetConfig {
    MechanismSetConfig::new(
        ProtocolVersion::V1,
        vec![MechanismSelection::new(
            MechanismId::M00,
            MechanismVersion::V1_0_0,
            CanonicalMechanismConfig::empty(),
        )],
    )
    .unwrap()
}

fn mechanism_set(mode: MutationMode) -> MechanismSet<PropertyMechanism> {
    MechanismSet::compile(&mechanism_config(), vec![PropertyMechanism { mode }]).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn content_ids_are_deterministic_domain_separated_and_mutation_sensitive(
        bytes in prop::collection::vec(any::<u8>(), 1..256),
        replacement in any::<u8>(),
    ) {
        let baseline = JobId::derive(&bytes);
        prop_assert_eq!(baseline, JobId::derive(&bytes));
        let claim_id = ClaimId::derive(&bytes);
        prop_assert_ne!(baseline.as_bytes(), claim_id.as_bytes());

        let mut changed = bytes.clone();
        let index = bytes.len() / 2;
        changed[index] = replacement;
        if changed == bytes {
            changed[index] ^= 1;
        }
        prop_assert_ne!(baseline, JobId::derive(&changed));
        prop_assert_ne!(ActionId::derive(&bytes), ActionId::derive(&changed));
    }

    #[test]
    fn actor_nonces_advance_contiguously_and_reject_every_skip(
        seed in any::<u64>(),
        initial in 0_u64..(u64::MAX - 33),
        count in 1_u64..32,
    ) {
        let private = ed25519::PrivateKey::from_seed(seed);
        let actor = ActorId::from(private.public_key());
        let context = rachet_core::actions::ActionVerificationContext::current(CHAIN, 10);
        let mut state = InMemoryStateBatch::new();
        state.put(StateKey::account(&actor), initial.to_be_bytes().as_slice().into());

        for offset in 0..count {
            let nonce = initial + offset;
            let action = SignedAction::sign(
                &private,
                ProtocolVersion::V1,
                CHAIN,
                nonce,
                10,
                Action::CloseJob(CloseJob::new(JobId::derive(&nonce.to_be_bytes()))),
            ).unwrap();
            action.verify_and_advance_nonce(&mut state, &context).unwrap();
        }
        let stored = state.get(&StateKey::account(&actor)).unwrap();
        let expected_nonce = (initial + count).to_be_bytes();
        prop_assert_eq!(stored.as_ref(), expected_nonce.as_slice());

        let skipped = initial + count + 1;
        let action = SignedAction::sign(
            &private,
            ProtocolVersion::V1,
            CHAIN,
            skipped,
            10,
            Action::CloseJob(CloseJob::new(JobId::derive(&skipped.to_be_bytes()))),
        ).unwrap();
        prop_assert_eq!(
            action.verify_and_advance_nonce(&mut state, &context),
            Err(ActionValidationError::InvalidNonce {
                expected: initial + count,
                received: skipped,
            }),
        );
    }

    #[test]
    fn state_and_action_roots_reproduce_and_detect_mutations(
        entries in prop::collection::btree_map(any::<u16>(), any::<u64>(), 1..64),
        seed in any::<u64>(),
    ) {
        let mut forward = InMemoryStateBatch::new();
        let mut reverse = InMemoryStateBatch::new();
        for (key, value) in &entries {
            forward.put(
                StateKey::mechanism(MechanismNamespace::new(77), &key.to_be_bytes()),
                value.to_be_bytes().as_slice().into(),
            );
        }
        for (key, value) in entries.iter().rev() {
            reverse.put(
                StateKey::mechanism(MechanismNamespace::new(77), &key.to_be_bytes()),
                value.to_be_bytes().as_slice().into(),
            );
        }
        prop_assert_eq!(forward.root(), reverse.root());

        let (&first_key, &first_value) = entries.first_key_value().unwrap();
        reverse.put(
            StateKey::mechanism(MechanismNamespace::new(77), &first_key.to_be_bytes()),
            first_value.wrapping_add(1).to_be_bytes().as_slice().into(),
        );
        prop_assert_ne!(forward.root(), reverse.root());

        let private = ed25519::PrivateKey::from_seed(seed);
        let action = SignedAction::sign(
            &private,
            ProtocolVersion::V1,
            CHAIN,
            0,
            10,
            Action::CloseJob(CloseJob::new(JobId::derive(b"root"))),
        ).unwrap();
        let mut changed = action.clone();
        changed.valid_until_height = 11;
        prop_assert_eq!(action_root(core::slice::from_ref(&action)), action_root(core::slice::from_ref(&action)));
        prop_assert_ne!(action_root(&[action]), action_root(&[changed]));
    }

    #[test]
    fn resolution_authorities_remain_disjoint_from_customers(
        customer_seed in any::<u64>(),
        authority_seed in any::<u64>(),
        candidate in any::<[u8; 32]>(),
    ) {
        prop_assume!(actor(customer_seed) != actor(authority_seed));
        let customer = actor(customer_seed);
        let authority = actor(authority_seed);
        let mut state = InMemoryStateBatch::new();
        create_job(
            &mut state,
            &customer,
            10,
            &create_job_payload(candidate, authority),
        ).unwrap();
        prop_assert_eq!(check_core_invariants(&state), Ok(()));

        let before = state.root();
        let conflict = create_job_payload(candidate.map(|byte| byte ^ 1), customer.clone());
        prop_assert_eq!(
            create_job(&mut state, &actor(authority_seed), 10, &conflict),
            Err(JobTransitionError::RoleConflict),
        );
        prop_assert_eq!(state.root(), before);
    }

    #[test]
    fn mechanism_namespace_isolation_rejects_every_foreign_namespace(
        foreign in 1_u16..=u16::MAX,
        event_bytes in any::<[u8; 32]>(),
    ) {
        let event = CanonicalEvent::JobClosed {
            job_id: JobId::from_digest(Sha256Digest::from(event_bytes)),
        };
        let mut valid_state = InMemoryStateBatch::new();
        mechanism_set(MutationMode::Own).on_event(&mut valid_state, &event).unwrap();
        prop_assert_eq!(valid_state.entries().len(), 1);

        let mut invalid_state = InMemoryStateBatch::new();
        let before = invalid_state.root();
        let error = mechanism_set(MutationMode::Foreign(MechanismNamespace::new(foreign)))
            .on_event(&mut invalid_state, &event)
            .unwrap_err();
        let rejected_foreign_write = matches!(
            error,
            MechanismRegistryError::CrossNamespaceWrite { .. }
        );
        prop_assert!(rejected_foreign_write);
        prop_assert_eq!(invalid_state.root(), before);
    }

    #[test]
    fn canonical_events_are_immutable_across_mechanism_processing(
        job in any::<[u8; 32]>(),
    ) {
        let event = CanonicalEvent::JobClosed {
            job_id: JobId::from_digest(Sha256Digest::from(job)),
        };
        let prior = event;
        let mut state = InMemoryStateBatch::new();
        mechanism_set(MutationMode::Own).on_event(&mut state, &event).unwrap();
        prop_assert_eq!(event, prior);
        let only_mechanism_state = state.entries().iter().all(|(key, _)| {
            key.namespace() == rachet_core::state::StateNamespace::Mechanism
        });
        prop_assert!(only_mechanism_state);
    }

    #[test]
    fn genesis_mechanism_set_is_fixed_for_every_execution(
        foreign in any::<[u8; 32]>(),
    ) {
        let mechanisms = mechanism_set(MutationMode::None);
        let valid_context = TransitionContext {
            chain_id: CHAIN,
            protocol_version: ProtocolVersion::V1,
            height: 0,
            epoch: 0,
            mechanism_set_id: mechanisms.id(),
        };
        let mut valid_state = InMemoryStateBatch::new();
        let output = execute_block(&mut valid_state, &valid_context, &[], &mechanisms).unwrap();
        prop_assert_eq!(output.post_state_root, valid_state.root());

        let foreign_id = MechanismSetId::from_digest(Sha256Digest::from(foreign));
        prop_assume!(foreign_id != mechanisms.id());
        let mut mismatched = valid_context;
        mismatched.mechanism_set_id = foreign_id;
        let mut state = InMemoryStateBatch::new();
        let before = state.root();
        prop_assert_eq!(
            execute_block(&mut state, &mismatched, &[], &mechanisms),
            Err(BlockExecutionError::MechanismSetMismatch),
        );
        prop_assert_eq!(state.root(), before);
    }
}

#[test]
fn consensus_and_actor_keys_are_distinct_protocol_types() {
    let public_key = ed25519::PrivateKey::from_seed(29).public_key();
    let actor = ActorId::from(public_key.clone());
    let consensus = ConsensusNodeId::from(public_key);
    assert_eq!(actor.as_bytes(), consensus.as_bytes());
    assert_ne!(
        core::any::type_name::<ActorId>(),
        core::any::type_name::<ConsensusNodeId>()
    );
}
