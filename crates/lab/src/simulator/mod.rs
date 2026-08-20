//! Single-process deterministic protocol execution.
//!
//! A run script contains only canonical actions, pure scripted-policy decision
//! points, and authority-signed evaluator actions. All potentially external
//! work (including hidden-fixture loading and future model calls) happens while
//! constructing those inputs, before the Commonware deterministic actor starts.
//! The actor executes the real block model, pure transition engine, state batch,
//! and compiled M00/M01 mechanism set; this module contains no alternate economy.

pub mod p2p;

use std::{convert::Infallible, error::Error, fmt};

use commonware_codec::Write as _;
use commonware_cryptography::{Signer as _, ed25519};
use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, deterministic};
use rachet_core::{
    actions::{Action, ActionValidationError, SignedAction, SubmitAttestation, Verdict},
    blocks::{
        Block, BlockHeader, BlockValidationContext, BlockValidationError, ConsensusContext,
        ConsensusNodeId, action_root, epoch_for_height,
    },
    events::{ActionReceipt, CanonicalEvent},
    mechanisms::{
        MechanismId, MechanismRegistryError, MechanismSelection, MechanismSet, MechanismSetConfig,
        MechanismVersion,
    },
    primitives::{ActorId, ChainId, ProtocolVersion, Sha256Digest},
    state::{InMemoryStateBatch, StateBatch, StateEntry},
    transition::{BlockExecutionError, TransitionContext, execute_block},
};
use rachet_mechanisms::{
    m00_record_only::{M00Config, M00RecordOnly},
    m01_naive_reputation::{M01Config, M01NaiveReputation},
    registry::{MechanismInstance, MechanismInstanceError},
};
use rachet_operator::policy::{
    PolicyObservation, ScriptedDecision, ScriptedDecisionKind, ScriptedPolicy,
};

use crate::evaluator::CanonicalActionSink;

/// The implemented economic mechanism selected for one laboratory run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaboratoryMechanism {
    M00RecordOnly,
    M01NaiveReputation,
}

/// Deterministic genesis and scheduling inputs for one single-process run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerConfig {
    pub seed: u64,
    pub chain_id: ChainId,
    pub blocks_per_epoch: u64,
    pub consensus_node: ConsensusNodeId,
    pub genesis_parent_block: Sha256Digest,
    pub genesis_timestamp_ms: u64,
    pub block_interval_ms: u64,
}

/// One pure scripted operator and its canonical signing state.
pub struct ScriptedOperator {
    key: ed25519::PrivateKey,
    next_nonce: u64,
    policy: ScriptedPolicy,
}

impl ScriptedOperator {
    #[must_use]
    pub const fn new(key: ed25519::PrivateKey, next_nonce: u64, policy: ScriptedPolicy) -> Self {
        Self {
            key,
            next_nonce,
            policy,
        }
    }

    #[must_use]
    pub fn actor(&self) -> ActorId {
        ActorId::from(self.key.public_key())
    }

    #[must_use]
    pub const fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    #[must_use]
    pub const fn policy(&self) -> ScriptedPolicy {
        self.policy
    }
}

/// A policy invocation at an exact application height and epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptedDecisionPoint {
    pub operator_index: usize,
    pub observation: PolicyObservation,
    pub valid_until_height: u64,
}

/// Authority-signed evaluator output collected outside deterministic actors.
///
/// This is a [`CanonicalActionSink`], so the hidden evaluator cannot bypass the
/// same canonical block path used by customers and validation operators.
#[derive(Default)]
pub struct EvaluatorActionBatch {
    actions: Vec<SignedAction<Action>>,
}

impl EvaluatorActionBatch {
    #[must_use]
    pub fn actions(&self) -> &[SignedAction<Action>] {
        &self.actions
    }
}

impl CanonicalActionSink for EvaluatorActionBatch {
    type Error = Infallible;

    fn submit(&mut self, action: SignedAction<Action>) -> Result<(), Self::Error> {
        self.actions.push(action);
        Ok(())
    }
}

/// One ordered source of actions in a scripted block.
pub enum ScriptedStep {
    /// Already-signed protocol actions (for example customer job creation).
    CanonicalActions(Vec<SignedAction<Action>>),
    /// A pure policy decision converted to signed canonical attestations.
    DecisionPoint(ScriptedDecisionPoint),
    /// Hidden-evaluator resolutions signed and collected before actor startup.
    EvaluatorActions(EvaluatorActionBatch),
}

/// One application block in the exact script order.
pub struct ScriptedBlock {
    pub steps: Vec<ScriptedStep>,
}

impl ScriptedBlock {
    #[must_use]
    pub fn new(steps: Vec<ScriptedStep>) -> Self {
        Self { steps }
    }

    /// Produces an empty block, useful for advancing height and epoch boundaries.
    #[must_use]
    pub fn empty() -> Self {
        Self { steps: Vec::new() }
    }
}

/// Complete bounded input to a deterministic actor run.
pub struct ScriptedRun {
    pub operators: Vec<ScriptedOperator>,
    pub blocks: Vec<ScriptedBlock>,
}

/// Auditable output from one pure policy invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionRecord {
    pub height: u64,
    pub operator: ActorId,
    pub policy_id: &'static str,
    pub decision: ScriptedDecision,
}

/// A canonical block and the transition products omitted from the block body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutedBlock {
    pub block: Block,
    pub events: Vec<CanonicalEvent>,
    pub receipts: Vec<ActionReceipt>,
    /// Exact economic state after this block, in canonical key order.
    pub post_state: Vec<StateEntry>,
}

/// Complete deterministic output of one scripted experiment run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunOutput {
    pub blocks: Vec<ExecutedBlock>,
    pub decisions: Vec<DecisionRecord>,
    pub final_state: Vec<StateEntry>,
    /// Commonware's deterministic scheduler audit. This is runtime evidence,
    /// not part of protocol state or any economic transition.
    pub runtime_audit: String,
}

impl RunOutput {
    /// Encodes all canonical protocol results with explicit sequence framing.
    /// Runtime scheduling evidence and policy metadata are intentionally absent.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_len(&mut bytes, self.blocks.len());
        for executed in &self.blocks {
            executed.block.write(&mut bytes);
            push_len(&mut bytes, executed.events.len());
            for event in &executed.events {
                event.write(&mut bytes);
            }
            push_len(&mut bytes, executed.receipts.len());
            for receipt in &executed.receipts {
                receipt.write(&mut bytes);
            }
        }
        push_len(&mut bytes, self.final_state.len());
        for (key, value) in &self.final_state {
            push_bytes(&mut bytes, key.as_bytes());
            push_bytes(&mut bytes, value);
        }
        bytes
    }
}

/// Stable terminal failure retained by action-trace execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceTerminalError {
    pub code: String,
    pub message: String,
}

impl From<&RunnerError> for TraceTerminalError {
    fn from(error: &RunnerError) -> Self {
        Self {
            code: error.code().to_owned(),
            message: error.to_string(),
        }
    }
}

/// Complete or partially completed execution of a retained action trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceRunOutput {
    /// Complete retained input, including the block that produced an error.
    pub action_blocks: Vec<Vec<SignedAction<Action>>>,
    pub output: RunOutput,
    pub terminal_error: Option<TraceTerminalError>,
}

/// Compiles and runs scripts using Commonware's seeded deterministic runtime.
pub struct DeterministicRunner {
    config: RunnerConfig,
    initial_state: InMemoryStateBatch,
    mechanisms: MechanismSet<MechanismInstance>,
}

impl DeterministicRunner {
    /// Creates a runner with an empty canonical state and a real M00 or M01 set.
    pub fn new(
        config: RunnerConfig,
        mechanism: LaboratoryMechanism,
    ) -> Result<Self, RunnerSetupError> {
        if config.blocks_per_epoch == 0 {
            return Err(RunnerSetupError::ZeroBlocksPerEpoch);
        }
        let mechanisms = compile_mechanism(mechanism)?;
        Ok(Self {
            config,
            initial_state: InMemoryStateBatch::new(),
            mechanisms,
        })
    }

    /// Replaces the empty genesis state with an explicitly supplied canonical state.
    #[must_use]
    pub fn with_initial_state(mut self, state: InMemoryStateBatch) -> Self {
        self.initial_state = state;
        self
    }

    /// Runs exactly one supervised protocol actor. The script is fully fixed
    /// before startup, so no filesystem, model, shell, Git, or network call can
    /// occur at a decision boundary inside this deterministic actor.
    pub fn run(self, script: ScriptedRun) -> Result<RunOutput, RunnerError> {
        let seed = self.config.seed;
        deterministic::Runner::seeded(seed).start(|context| async move {
            let actor = context.child("protocol_runner").spawn(move |_| async move {
                execute_script(self.config, self.initial_state, self.mechanisms, script)
            });
            let mut output = actor
                .await
                .map_err(|error| RunnerError::RuntimeActor(error.to_string()))??;
            output.runtime_audit = context.auditor().state();
            Ok(output)
        })
    }

    /// Executes already-signed actions grouped by block, retaining any exact
    /// terminal protocol error and all blocks completed before it. There is no
    /// policy or model callback on this path.
    pub fn replay_actions(
        self,
        blocks: Vec<Vec<SignedAction<Action>>>,
    ) -> Result<TraceRunOutput, RunnerError> {
        let seed = self.config.seed;
        deterministic::Runner::seeded(seed).start(|context| async move {
            let actor = context.child("trace_replay").spawn(move |_| async move {
                execute_action_trace(self.config, self.initial_state, self.mechanisms, blocks)
            });
            let mut execution = actor
                .await
                .map_err(|error| RunnerError::RuntimeActor(error.to_string()))?;
            execution.output.runtime_audit = context.auditor().state();
            Ok(execution)
        })
    }
}

fn compile_mechanism(
    selected: LaboratoryMechanism,
) -> Result<MechanismSet<MechanismInstance>, RunnerSetupError> {
    let (selection, instance) = match selected {
        LaboratoryMechanism::M00RecordOnly => (
            MechanismSelection::new(
                MechanismId::M00,
                MechanismVersion::V1_0_0,
                M00Config.canonical(),
            ),
            MechanismInstance::m00(M00RecordOnly::default())?,
        ),
        LaboratoryMechanism::M01NaiveReputation => (
            MechanismSelection::new(
                MechanismId::M01,
                MechanismVersion::V1_0_0,
                M01Config.canonical(),
            ),
            MechanismInstance::m01(M01NaiveReputation::default())?,
        ),
    };
    let config = MechanismSetConfig::new(ProtocolVersion::V1, vec![selection])
        .map_err(RunnerSetupError::MechanismConfig)?;
    MechanismSet::compile(&config, vec![instance]).map_err(RunnerSetupError::MechanismRegistry)
}

fn execute_script(
    config: RunnerConfig,
    mut state: InMemoryStateBatch,
    mechanisms: MechanismSet<MechanismInstance>,
    mut script: ScriptedRun,
) -> Result<RunOutput, RunnerError> {
    let mut parent_block = config.genesis_parent_block;
    let mut executed_blocks = Vec::with_capacity(script.blocks.len());
    let mut decisions = Vec::new();

    for (index, scripted_block) in script.blocks.into_iter().enumerate() {
        let height = u64::try_from(index).map_err(|_| RunnerError::HeightOverflow)?;
        let epoch = epoch_for_height(height, config.blocks_per_epoch)
            .map_err(RunnerError::BlockValidation)?;
        let mut actions = Vec::new();
        for step in scripted_block.steps {
            match step {
                ScriptedStep::CanonicalActions(mut canonical) => actions.append(&mut canonical),
                ScriptedStep::EvaluatorActions(mut evaluator) => {
                    actions.append(&mut evaluator.actions)
                }
                ScriptedStep::DecisionPoint(point) => append_decision_actions(
                    &config,
                    height,
                    epoch,
                    point,
                    &mut script.operators,
                    &mut actions,
                    &mut decisions,
                )?,
            }
        }

        let executed = execute_action_block(
            &config,
            &mut state,
            &mechanisms,
            height,
            epoch,
            parent_block,
            actions,
        )?;
        parent_block = executed.block.digest();
        executed_blocks.push(executed);
    }

    Ok(RunOutput {
        blocks: executed_blocks,
        decisions,
        final_state: state.entries(),
        runtime_audit: String::new(),
    })
}

fn execute_action_trace(
    config: RunnerConfig,
    mut state: InMemoryStateBatch,
    mechanisms: MechanismSet<MechanismInstance>,
    blocks: Vec<Vec<SignedAction<Action>>>,
) -> TraceRunOutput {
    let action_blocks = blocks.clone();
    let mut parent_block = config.genesis_parent_block;
    let mut executed_blocks = Vec::with_capacity(blocks.len());
    let mut terminal_error = None;

    for (index, actions) in blocks.into_iter().enumerate() {
        let result = u64::try_from(index)
            .map_err(|_| RunnerError::HeightOverflow)
            .and_then(|height| {
                let epoch = epoch_for_height(height, config.blocks_per_epoch)
                    .map_err(RunnerError::BlockValidation)?;
                execute_action_block(
                    &config,
                    &mut state,
                    &mechanisms,
                    height,
                    epoch,
                    parent_block,
                    actions,
                )
            });
        match result {
            Ok(executed) => {
                parent_block = executed.block.digest();
                executed_blocks.push(executed);
            }
            Err(error) => {
                terminal_error = Some(TraceTerminalError::from(&error));
                break;
            }
        }
    }

    TraceRunOutput {
        action_blocks,
        output: RunOutput {
            blocks: executed_blocks,
            decisions: Vec::new(),
            final_state: state.entries(),
            runtime_audit: String::new(),
        },
        terminal_error,
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_action_block(
    config: &RunnerConfig,
    state: &mut InMemoryStateBatch,
    mechanisms: &MechanismSet<MechanismInstance>,
    height: u64,
    epoch: u64,
    parent_block: Sha256Digest,
    actions: Vec<SignedAction<Action>>,
) -> Result<ExecutedBlock, RunnerError> {
    let parent_state_root = state.root();
    let context = ConsensusContext {
        consensus_epoch: epoch,
        view: height,
        leader: config.consensus_node.clone(),
        parent_view: height.saturating_sub(1),
        parent_block,
    };
    let transition = TransitionContext {
        chain_id: config.chain_id,
        protocol_version: ProtocolVersion::V1,
        height,
        epoch,
        mechanism_set_id: mechanisms.id(),
    };
    let output =
        execute_block(state, &transition, &actions, mechanisms).map_err(RunnerError::Execution)?;
    let timestamp_ms = config
        .block_interval_ms
        .checked_mul(height)
        .and_then(|elapsed| config.genesis_timestamp_ms.checked_add(elapsed))
        .ok_or(RunnerError::TimestampOverflow)?;
    let header = BlockHeader {
        protocol_version: ProtocolVersion::V1,
        chain_id: config.chain_id,
        height,
        epoch,
        parent_block,
        parent_state_root,
        action_root: action_root(&actions),
        receipt_root: output.receipt_root,
        post_state_root: output.post_state_root,
        mechanism_set_id: mechanisms.id(),
        timestamp_ms,
    };
    let block =
        Block::new(context.clone(), header, actions).map_err(RunnerError::BlockValidation)?;
    let validation = BlockValidationContext {
        consensus_context: context,
        protocol_version: ProtocolVersion::V1,
        chain_id: config.chain_id,
        height,
        parent_block,
        parent_state_root,
        mechanism_set_id: mechanisms.id(),
        blocks_per_epoch: config.blocks_per_epoch,
        limits: rachet_core::limits::ProtocolLimits::V1,
    };
    block
        .validate_structure(&validation)
        .map_err(RunnerError::BlockValidation)?;
    block
        .validate_execution(&output.receipts, output.post_state_root)
        .map_err(RunnerError::BlockValidation)?;

    Ok(ExecutedBlock {
        block,
        events: output.events,
        receipts: output.receipts,
        post_state: state.entries(),
    })
}

#[allow(clippy::too_many_arguments)]
fn append_decision_actions(
    config: &RunnerConfig,
    height: u64,
    epoch: u64,
    point: ScriptedDecisionPoint,
    operators: &mut [ScriptedOperator],
    actions: &mut Vec<SignedAction<Action>>,
    records: &mut Vec<DecisionRecord>,
) -> Result<(), RunnerError> {
    if point.observation.height() != height || point.observation.epoch() != epoch {
        return Err(RunnerError::DecisionContextMismatch {
            expected_height: height,
            received_height: point.observation.height(),
            expected_epoch: epoch,
            received_epoch: point.observation.epoch(),
        });
    }
    let operator = operators
        .get_mut(point.operator_index)
        .ok_or(RunnerError::UnknownOperator(point.operator_index))?;
    let decision = operator.policy.decide(&point.observation);
    if decision.resource_report.model_calls != 0 || decision.resource_report.tool_calls != 0 {
        return Err(RunnerError::ScriptedPolicyUsedExternalResource);
    }

    let attestations = decision_attestations(&point.observation, &decision)?;
    for attestation in attestations {
        let next_nonce = operator
            .next_nonce
            .checked_add(1)
            .ok_or(RunnerError::OperatorNonceExhausted(point.operator_index))?;
        let signed = SignedAction::sign(
            &operator.key,
            ProtocolVersion::V1,
            config.chain_id,
            operator.next_nonce,
            point.valid_until_height,
            Action::SubmitAttestation(attestation),
        )
        .map_err(RunnerError::Signing)?;
        operator.next_nonce = next_nonce;
        actions.push(signed);
    }
    records.push(DecisionRecord {
        height,
        operator: operator.actor(),
        policy_id: operator.policy.metadata().id(),
        decision,
    });
    Ok(())
}

fn decision_attestations(
    observation: &PolicyObservation,
    decision: &ScriptedDecision,
) -> Result<Vec<SubmitAttestation>, RunnerError> {
    match &decision.kind {
        ScriptedDecisionKind::Validate { job_id, claims } => Ok(claims
            .iter()
            .map(|claim| SubmitAttestation {
                job_id: *job_id,
                claim_id: claim.claim_id,
                verdict: claim.verdict,
                confidence_basis_points: claim.confidence_basis_points,
                evidence_ids: Default::default(),
            })
            .collect()),
        ScriptedDecisionKind::Abstain { job_id } => {
            let job = observation
                .jobs()
                .iter()
                .find(|job| job.job_id() == *job_id)
                .ok_or(RunnerError::DecisionJobMissing)?;
            Ok(job
                .claims()
                .iter()
                .map(|claim| SubmitAttestation {
                    job_id: *job_id,
                    claim_id: claim.claim_id(),
                    verdict: Verdict::Abstain,
                    confidence_basis_points: 0,
                    evidence_ids: Default::default(),
                })
                .collect())
        }
        ScriptedDecisionKind::Wait => Ok(Vec::new()),
    }
}

fn push_len(bytes: &mut Vec<u8>, length: usize) {
    bytes.extend_from_slice(
        &u64::try_from(length)
            .expect("supported Linux collection lengths fit u64")
            .to_be_bytes(),
    );
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    push_len(bytes, value.len());
    bytes.extend_from_slice(value);
}

/// Invalid deterministic runner construction.
#[derive(Debug)]
pub enum RunnerSetupError {
    ZeroBlocksPerEpoch,
    MechanismInstance(MechanismInstanceError),
    MechanismConfig(rachet_core::mechanisms::MechanismSetConfigError),
    MechanismRegistry(MechanismRegistryError),
}

impl From<MechanismInstanceError> for RunnerSetupError {
    fn from(error: MechanismInstanceError) -> Self {
        Self::MechanismInstance(error)
    }
}

impl fmt::Display for RunnerSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBlocksPerEpoch => formatter.write_str("blocks per epoch must be nonzero"),
            Self::MechanismInstance(error) => {
                write!(formatter, "invalid mechanism instance: {error}")
            }
            Self::MechanismConfig(error) => write!(formatter, "invalid mechanism set: {error}"),
            Self::MechanismRegistry(error) => {
                write!(formatter, "cannot compile mechanism set: {error}")
            }
        }
    }
}

impl Error for RunnerSetupError {}

/// A deterministic script or canonical execution failure.
#[derive(Debug)]
pub enum RunnerError {
    RuntimeActor(String),
    HeightOverflow,
    TimestampOverflow,
    UnknownOperator(usize),
    OperatorNonceExhausted(usize),
    DecisionContextMismatch {
        expected_height: u64,
        received_height: u64,
        expected_epoch: u64,
        received_epoch: u64,
    },
    DecisionJobMissing,
    ScriptedPolicyUsedExternalResource,
    Signing(ActionValidationError),
    Execution(BlockExecutionError),
    BlockValidation(BlockValidationError),
}

impl RunnerError {
    /// Stable machine-readable terminal code used by retained trace replay.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::RuntimeActor(_) => "LAB_RUNTIME_ACTOR_FAILED",
            Self::HeightOverflow => "LAB_HEIGHT_OVERFLOW",
            Self::TimestampOverflow => "LAB_TIMESTAMP_OVERFLOW",
            Self::UnknownOperator(_) => "LAB_OPERATOR_UNKNOWN",
            Self::OperatorNonceExhausted(_) => "LAB_OPERATOR_NONCE_EXHAUSTED",
            Self::DecisionContextMismatch { .. } => "LAB_DECISION_CONTEXT_INVALID",
            Self::DecisionJobMissing => "LAB_DECISION_JOB_MISSING",
            Self::ScriptedPolicyUsedExternalResource => "LAB_SCRIPTED_RESOURCE_INVALID",
            Self::Signing(error) => error.code(),
            Self::Execution(error) => error.code(),
            Self::BlockValidation(error) => error.code(),
        }
    }
}

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeActor(error) => write!(formatter, "deterministic actor failed: {error}"),
            Self::HeightOverflow => formatter.write_str("script has more blocks than u64 heights"),
            Self::TimestampOverflow => {
                formatter.write_str("deterministic block timestamp overflowed")
            }
            Self::UnknownOperator(index) => {
                write!(formatter, "decision names unknown operator {index}")
            }
            Self::OperatorNonceExhausted(index) => {
                write!(formatter, "operator {index} nonce exhausted")
            }
            Self::DecisionContextMismatch {
                expected_height,
                received_height,
                expected_epoch,
                received_epoch,
            } => write!(
                formatter,
                "decision context ({received_height}, {received_epoch}) does not match block ({expected_height}, {expected_epoch})"
            ),
            Self::DecisionJobMissing => {
                formatter.write_str("policy decision names a job absent from its observation")
            }
            Self::ScriptedPolicyUsedExternalResource => {
                formatter.write_str("scripted policy reported a model or tool call")
            }
            Self::Signing(error) => write!(formatter, "cannot sign scripted action: {error}"),
            Self::Execution(error) => {
                write!(formatter, "canonical block execution failed: {error}")
            }
            Self::BlockValidation(error) => {
                write!(formatter, "canonical block validation failed: {error}")
            }
        }
    }
}

impl Error for RunnerError {}
