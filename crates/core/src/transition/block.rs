//! The single authoritative, atomic block execution path.

use super::{ActionExecutionError, HeightEventError, apply_verified_action, execute_height_events};
use crate::{
    actions::{Action, ActionValidationError, ActionVerificationContext, SignedAction},
    blocks::{action_root, receipt_root},
    events::{ActionReceipt, CanonicalEvent},
    invariants::{CoreInvariantError, check_core_invariants, check_transition_invariants},
    limits::{MAX_ACTIONS_PER_BLOCK, MAX_BLOCK_BODY_BYTES},
    mechanisms::{Mechanism, MechanismRegistryError, MechanismSet},
    primitives::{ActionId, ActorId, ChainId, MechanismSetId, ProtocolVersion, Sha256Digest},
    state::{StateBatch, StateBatchError, StateKey},
};
use commonware_codec::EncodeSize;
use core::fmt;

/// Consensus-independent values fixed for one candidate block transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionContext {
    pub chain_id: ChainId,
    pub protocol_version: ProtocolVersion,
    pub height: u64,
    pub epoch: u64,
    pub mechanism_set_id: MechanismSetId,
}

/// Complete deterministic output of one accepted candidate block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOutput {
    /// System and action events in canonical processing order.
    pub events: Vec<CanonicalEvent>,
    /// Exactly one receipt for each accepted action, in body order.
    pub receipts: Vec<ActionReceipt>,
    pub action_root: Sha256Digest,
    pub receipt_root: Sha256Digest,
    pub post_state_root: Sha256Digest,
}

struct PendingReceipt {
    action_id: ActionId,
    actor: ActorId,
    nonce: u64,
    events: crate::bounded::BoundedVec<CanonicalEvent, { crate::limits::MAX_EVENTS_PER_ACTION }>,
}

/// Executes a candidate through section 16's only authoritative path.
///
/// The outer fork makes the complete candidate atomic. Every fallible stage
/// returns immediately and rolls back all nonce, canonical, height, and
/// mechanism writes; no invalid action can be caught and skipped.
pub fn execute_block<M: Mechanism>(
    parent: &mut dyn StateBatch,
    context: &TransitionContext,
    actions: &[SignedAction<Action>],
    mechanisms: &MechanismSet<M>,
) -> Result<ExecutionOutput, BlockExecutionError> {
    // 1. Verify block-level limits and context bindings.
    verify_block_limits(context, actions, mechanisms)?;
    check_core_invariants(parent).map_err(BlockExecutionError::CoreInvariant)?;
    let parent_entries = parent.entries();

    parent.fork();
    let result = execute_in_fork(parent, &parent_entries, context, actions, mechanisms);
    match result {
        Ok(output) => {
            parent.commit().map_err(BlockExecutionError::State)?;
            Ok(output)
        }
        Err(error) => {
            parent.rollback().map_err(BlockExecutionError::State)?;
            Err(error)
        }
    }
}

fn execute_in_fork<M: Mechanism>(
    state: &mut dyn StateBatch,
    parent_entries: &[crate::state::StateEntry],
    context: &TransitionContext,
    actions: &[SignedAction<Action>],
    mechanisms: &MechanismSet<M>,
) -> Result<ExecutionOutput, BlockExecutionError> {
    let verification =
        ActionVerificationContext::new(context.chain_id, context.protocol_version, context.height);

    // 2. Verify every envelope and advance candidate-local contiguous nonces.
    let mut action_ids = Vec::with_capacity(actions.len());
    for (index, action) in actions.iter().enumerate() {
        let action_id = action
            .verify_and_advance_nonce(state, &verification)
            .map_err(|error| BlockExecutionError::ActionEnvelope { index, error })?;
        action_ids.push(action_id);
    }

    // 3. Run every active mechanism's pre-action validation before any
    // canonical action transition is applied.
    for (index, action) in actions.iter().enumerate() {
        mechanisms
            .pre_action(state, action)
            .map_err(|error| BlockExecutionError::MechanismPreAction { index, error })?;
    }

    // 4 and 5. Apply canonical transitions and retain their emitted events.
    // Height-derived transitions are canonical block transitions and precede
    // body actions at the candidate height.
    let previous_epoch = stored_epoch(state)?;
    let system_events = execute_height_events(state, context.height, previous_epoch, context.epoch)
        .map_err(BlockExecutionError::HeightTransition)?;
    let mut pending = Vec::with_capacity(actions.len());
    for ((index, action), action_id) in actions.iter().enumerate().zip(action_ids.into_iter()) {
        let events = apply_verified_action(state, context.height, action)
            .map_err(|error| BlockExecutionError::ActionTransition { index, error })?;
        pending.push(PendingReceipt {
            action_id,
            actor: action.actor.clone(),
            nonce: action.nonce,
            events,
        });
    }

    let mut events = system_events;
    events.extend(
        pending
            .iter()
            .flat_map(|receipt| receipt.events.iter().copied()),
    );

    // 6 and 7. Pass each canonical event to every mechanism; the compiled set
    // collects from a shared pre-event view and applies sorted mutations using
    // the registry's deterministic dependency configuration.
    for (index, event) in events.iter().enumerate() {
        mechanisms
            .on_event(state, event)
            .map_err(|error| BlockExecutionError::MechanismEvent { index, error })?;
        if let CanonicalEvent::EpochChanged { current, .. } = event {
            mechanisms.on_epoch(state, *current).map_err(|error| {
                BlockExecutionError::MechanismEpoch {
                    epoch: *current,
                    error,
                }
            })?;
        }
    }

    // 8. Run final core and mechanism invariants on the complete candidate.
    check_core_invariants(state).map_err(BlockExecutionError::CoreInvariant)?;
    check_transition_invariants(parent_entries, state, actions, context.epoch)
        .map_err(BlockExecutionError::CoreInvariant)?;
    mechanisms
        .check_invariants(state)
        .map_err(BlockExecutionError::MechanismInvariant)?;

    // 9. Merkleize the complete visible candidate state.
    let post_state_root = state.root();

    // 10. Materialize receipts and all deterministic roots.
    let receipts: Vec<_> = pending
        .into_iter()
        .map(|receipt| {
            ActionReceipt::from_bounded_events(
                receipt.action_id,
                receipt.actor,
                receipt.nonce,
                receipt.events,
            )
        })
        .collect();
    Ok(ExecutionOutput {
        events,
        receipts: receipts.clone(),
        action_root: action_root(actions),
        receipt_root: receipt_root(&receipts),
        post_state_root,
    })
}

fn verify_block_limits<M: Mechanism>(
    context: &TransitionContext,
    actions: &[SignedAction<Action>],
    mechanisms: &MechanismSet<M>,
) -> Result<(), BlockExecutionError> {
    if !context.protocol_version.is_supported() {
        return Err(BlockExecutionError::UnsupportedProtocolVersion {
            received: context.protocol_version.get(),
        });
    }
    if context.mechanism_set_id != mechanisms.id() {
        return Err(BlockExecutionError::MechanismSetMismatch);
    }
    if actions.len() > MAX_ACTIONS_PER_BLOCK {
        return Err(BlockExecutionError::ActionCountExceeded {
            maximum: MAX_ACTIONS_PER_BLOCK,
            actual: actions.len(),
        });
    }
    let body_bytes = actions
        .iter()
        .fold(actions.len().encode_size(), |total, action| {
            total.saturating_add(action.encode_size())
        });
    if body_bytes > MAX_BLOCK_BODY_BYTES {
        return Err(BlockExecutionError::BlockBodyTooLarge {
            maximum: MAX_BLOCK_BODY_BYTES,
            actual: body_bytes,
        });
    }
    Ok(())
}

fn stored_epoch(state: &dyn StateBatch) -> Result<u64, BlockExecutionError> {
    let Some(value) = state.get(&StateKey::protocol_epoch()) else {
        return Ok(0);
    };
    let actual = value.len();
    let bytes: [u8; 8] = value
        .as_ref()
        .try_into()
        .map_err(|_| BlockExecutionError::StoredEpochMalformed { actual })?;
    Ok(u64::from_be_bytes(bytes))
}

/// Stable, index-bearing failure from authoritative candidate execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockExecutionError {
    UnsupportedProtocolVersion {
        received: u16,
    },
    MechanismSetMismatch,
    ActionCountExceeded {
        maximum: usize,
        actual: usize,
    },
    BlockBodyTooLarge {
        maximum: usize,
        actual: usize,
    },
    StoredEpochMalformed {
        actual: usize,
    },
    ActionEnvelope {
        index: usize,
        error: ActionValidationError,
    },
    MechanismPreAction {
        index: usize,
        error: MechanismRegistryError,
    },
    HeightTransition(HeightEventError),
    ActionTransition {
        index: usize,
        error: ActionExecutionError,
    },
    MechanismEvent {
        index: usize,
        error: MechanismRegistryError,
    },
    MechanismEpoch {
        epoch: u64,
        error: MechanismRegistryError,
    },
    CoreInvariant(CoreInvariantError),
    MechanismInvariant(MechanismRegistryError),
    State(StateBatchError),
}

impl BlockExecutionError {
    /// Returns the stable machine-readable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedProtocolVersion { .. } => "BLOCK_VERSION_UNSUPPORTED",
            Self::MechanismSetMismatch => "BLOCK_MECHANISM_SET_INVALID",
            Self::ActionCountExceeded { .. } => "BLOCK_ACTION_COUNT_INVALID",
            Self::BlockBodyTooLarge { .. } => "BLOCK_BODY_TOO_LARGE",
            Self::StoredEpochMalformed { .. } => "EPOCH_STATE_MALFORMED",
            Self::ActionEnvelope { error, .. } => error.code(),
            Self::MechanismPreAction { error, .. }
            | Self::MechanismEvent { error, .. }
            | Self::MechanismEpoch { error, .. }
            | Self::MechanismInvariant(error) => error.code(),
            Self::HeightTransition(error) => error.code(),
            Self::ActionTransition { error, .. } => error.code(),
            Self::CoreInvariant(error) => error.code(),
            Self::State(StateBatchError::NoOpenFork) => "STATE_TRANSACTION_INVALID",
        }
    }
}

impl fmt::Display for BlockExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for BlockExecutionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{CommitmentSubject, CreateCommitment},
        bounded::BoundedVec,
        mechanisms::{
            CanonicalMechanismConfig, MechanismError, MechanismExportId, MechanismInvariantError,
            MechanismManifest, MechanismMutation, MechanismReadView, MechanismSelection,
            MechanismSetConfig, MechanismStatus, MechanismVersion,
        },
        primitives::{ClaimId, MechanismSetId},
        state::{InMemoryStateBatch, MechanismNamespace},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{Signer as _, ed25519};
    use std::{cell::RefCell, rc::Rc};

    #[derive(Debug)]
    struct TestMechanism {
        trace: Option<Rc<RefCell<Vec<&'static str>>>>,
        fail_event: bool,
    }

    impl TestMechanism {
        fn quiet() -> Self {
            Self {
                trace: None,
                fail_event: false,
            }
        }

        fn traced(trace: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self {
                trace: Some(trace),
                fail_event: false,
            }
        }

        fn record(&self, stage: &'static str) {
            if let Some(trace) = &self.trace {
                trace.borrow_mut().push(stage);
            }
        }
    }

    impl Mechanism for TestMechanism {
        fn manifest(&self) -> MechanismManifest {
            MechanismManifest {
                id: crate::mechanisms::MechanismId::M00,
                version: MechanismVersion::V1_0_0,
                status: MechanismStatus::Implemented,
                requires: BoundedVec::default(),
                reads_exports: BoundedVec::<MechanismExportId, 32>::default(),
                state_namespace: MechanismNamespace::new(0),
                config_digest: CanonicalMechanismConfig::empty().digest(),
            }
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
            view: &MechanismReadView<'_>,
            action: &SignedAction<Action>,
        ) -> Result<(), MechanismError> {
            self.record("pre-action");
            let Action::CreateCommitment(commitment) = &action.payload else {
                return Err(MechanismError::new("TEST_ACTION", "unexpected action"));
            };
            let key = StateKey::commitment(&commitment.commitment_id(&action.actor));
            if view.canonical(&key)?.is_some() {
                return Err(MechanismError::new(
                    "TEST_ORDER",
                    "canonical transition ran before pre-action",
                ));
            }
            Ok(())
        }

        fn on_event(
            &self,
            view: &MechanismReadView<'_>,
            event: &CanonicalEvent,
        ) -> Result<Vec<MechanismMutation>, MechanismError> {
            self.record("event");
            if self.fail_event {
                return Err(MechanismError::new("TEST_EVENT", "rejected event"));
            }
            let CanonicalEvent::CommitmentCreated { commitment_id } = event else {
                return Ok(Vec::new());
            };
            if view
                .canonical(&StateKey::commitment(commitment_id))?
                .is_none()
            {
                return Err(MechanismError::new(
                    "TEST_ORDER",
                    "event ran before canonical transition",
                ));
            }
            Ok(vec![MechanismMutation::put(
                view.own_key(b"observed"),
                b"yes".as_slice().into(),
            )])
        }

        fn on_epoch(
            &self,
            _view: &MechanismReadView<'_>,
            _epoch: u64,
        ) -> Result<Vec<MechanismMutation>, MechanismError> {
            self.record("epoch");
            Ok(Vec::new())
        }

        fn check_invariants(
            &self,
            _view: &MechanismReadView<'_>,
        ) -> Result<(), MechanismInvariantError> {
            self.record("invariant");
            Ok(())
        }
    }

    fn config() -> MechanismSetConfig {
        MechanismSetConfig::new(
            ProtocolVersion::V1,
            vec![MechanismSelection::new(
                crate::mechanisms::MechanismId::M00,
                MechanismVersion::V1_0_0,
                CanonicalMechanismConfig::empty(),
            )],
        )
        .unwrap()
    }

    fn set(mechanism: TestMechanism) -> MechanismSet<TestMechanism> {
        MechanismSet::compile(&config(), vec![mechanism]).unwrap()
    }

    fn context(mechanism_set_id: MechanismSetId) -> TransitionContext {
        TransitionContext {
            chain_id: ChainId::new([7; 32]),
            protocol_version: ProtocolVersion::V1,
            height: 10,
            epoch: 0,
            mechanism_set_id,
        }
    }

    fn action(nonce: u64) -> SignedAction<Action> {
        SignedAction::sign(
            &ed25519::PrivateKey::from_seed(70),
            ProtocolVersion::V1,
            ChainId::new([7; 32]),
            nonce,
            10,
            Action::CreateCommitment(CreateCommitment {
                subject: CommitmentSubject::Claim(ClaimId::derive(b"executor-claim")),
                digest: Sha256Digest::from([8; 32]),
                reveal_after_height: 11,
                reveal_before_height: 20,
            }),
        )
        .unwrap()
    }

    #[test]
    fn authoritative_stages_have_the_required_observable_order() {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mechanisms = set(TestMechanism::traced(trace.clone()));
        let context = context(mechanisms.id());
        let action = action(0);
        let mut state = InMemoryStateBatch::new();

        let output = execute_block(
            &mut state,
            &context,
            core::slice::from_ref(&action),
            &mechanisms,
        )
        .unwrap();
        assert_eq!(output.receipts.len(), 1);
        assert_eq!(output.receipts[0].events.as_slice(), output.events);
        assert_eq!(output.action_root, action_root(&[action]));
        assert_eq!(output.receipt_root, receipt_root(&output.receipts));
        assert_eq!(output.post_state_root, state.root());
        assert_eq!(
            trace.borrow().as_slice(),
            ["pre-action", "event", "invariant", "invariant"]
        );
    }

    #[test]
    fn one_thousand_identical_executions_match_writes_events_receipts_and_roots() {
        let mechanisms = set(TestMechanism::quiet());
        let context = context(mechanisms.id());
        let actions = [action(0)];
        let initial = InMemoryStateBatch::new();
        let mut expected_state = initial.clone();
        let expected = execute_block(&mut expected_state, &context, &actions, &mechanisms).unwrap();
        let expected_receipts = expected
            .receipts
            .iter()
            .flat_map(|receipt| receipt.encode())
            .collect::<Vec<_>>();

        for _ in 0..1_000 {
            let mut state = initial.clone();
            let output = execute_block(&mut state, &context, &actions, &mechanisms).unwrap();
            assert_eq!(output, expected);
            assert_eq!(state.entries(), expected_state.entries());
            assert_eq!(state.root(), expected_state.root());
            assert_eq!(
                output
                    .receipts
                    .iter()
                    .flat_map(|receipt| receipt.encode())
                    .collect::<Vec<_>>(),
                expected_receipts
            );
        }
    }

    #[test]
    fn any_invalid_envelope_rolls_back_the_full_candidate() {
        let mechanisms = set(TestMechanism::quiet());
        let context = context(mechanisms.id());
        let first = action(0);
        let mut invalid = action(1);
        invalid.signature = action(0).signature;
        let actions = [first, invalid];
        let before = InMemoryStateBatch::new();
        let mut expected_state = before.clone();
        let expected = execute_block(&mut expected_state, &context, &actions, &mechanisms)
            .expect_err("the second envelope must be rejected");
        assert!(matches!(
            expected,
            BlockExecutionError::ActionEnvelope {
                index: 1,
                error: ActionValidationError::InvalidSignature
            }
        ));
        assert_eq!(expected_state, before);

        for _ in 0..1_000 {
            let mut state = before.clone();
            assert_eq!(
                execute_block(&mut state, &context, &actions, &mechanisms),
                Err(expected.clone())
            );
            assert_eq!(state, before);
        }
    }

    #[test]
    fn a_late_transition_or_mechanism_failure_rolls_back_every_write() {
        let mechanisms = set(TestMechanism::quiet());
        let execution_context = context(mechanisms.id());
        let mut state = InMemoryStateBatch::new();
        let before = state.clone();
        let error = execute_block(
            &mut state,
            &execution_context,
            &[action(0), action(1)],
            &mechanisms,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BlockExecutionError::ActionTransition { index: 1, .. }
        ));
        assert_eq!(state, before);

        let failing = set(TestMechanism {
            trace: None,
            fail_event: true,
        });
        let failing_context = context(failing.id());
        let error =
            execute_block(&mut state, &failing_context, &[action(0)], &failing).unwrap_err();
        assert!(matches!(
            error,
            BlockExecutionError::MechanismEvent { index: 0, .. }
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn block_context_and_count_fail_before_opening_a_transaction() {
        let mechanisms = set(TestMechanism::quiet());
        let mut state = InMemoryStateBatch::new();
        let mut wrong = context(MechanismSetId::from_digest(Sha256Digest::from([99; 32])));
        assert_eq!(
            execute_block(&mut state, &wrong, &[], &mechanisms),
            Err(BlockExecutionError::MechanismSetMismatch)
        );
        assert_eq!(state.fork_depth(), 0);

        wrong = context(mechanisms.id());
        let actions = vec![action(0); MAX_ACTIONS_PER_BLOCK + 1];
        assert_eq!(
            execute_block(&mut state, &wrong, &actions, &mechanisms),
            Err(BlockExecutionError::ActionCountExceeded {
                maximum: MAX_ACTIONS_PER_BLOCK,
                actual: MAX_ACTIONS_PER_BLOCK + 1,
            })
        );
        assert_eq!(state.fork_depth(), 0);
    }
}
