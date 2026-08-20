//! Hidden `ExperimentAuthority` evaluation and canonical resolution submission.
//!
//! The evaluator deliberately has no truth-inspection API. Private fixture
//! contents are loaded only after [`ExperimentAuthorityEvaluator::close_operator_decisions`]
//! and can leave this module only as signed canonical resolution actions.

use std::{collections::BTreeSet, fmt, path::PathBuf};

use commonware_cryptography::{Signer as _, ed25519};
use rachet_core::{
    actions::{
        Action, ActionValidationError, ResolutionVerdict, ResolveChallenge, ResolveClaim,
        SignedAction,
    },
    artifacts::ContentRef,
    bounded::BoundedVec,
    limits::MAX_EVIDENCE_IDS_PER_ACTION,
    primitives::{
        ActionId, ActorId, CURRENT_PROTOCOL_VERSION, ChainId, ChallengeId, ClaimId, EvidenceId,
        JobId,
    },
};

use crate::fixtures::{
    FixtureError, IntegrityHash, LoadedPublicFixtureSet,
    private::{LoadedPrivateFixtureSet, PrivateFixtureLoader},
    schema::GroundTruthVerdict,
};

/// The customer and validation identities participating in an experiment.
///
/// Construction rejects identity reuse between these roles. The authority is
/// checked separately when the evaluator is created because its actor ID is
/// derived from its signing key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentRoles {
    customer: ActorId,
    validation_operators: BTreeSet<ActorId>,
}

impl ExperimentRoles {
    /// Builds a role assignment with pairwise-distinct customer and validation
    /// operator identities.
    pub fn new(
        customer: ActorId,
        validation_operators: impl IntoIterator<Item = ActorId>,
    ) -> Result<Self, EvaluatorSetupError> {
        let mut operators = BTreeSet::new();
        for operator in validation_operators {
            if operator == customer {
                return Err(EvaluatorSetupError::CustomerIsValidationOperator);
            }
            if !operators.insert(operator) {
                return Err(EvaluatorSetupError::DuplicateValidationOperator);
            }
        }
        Ok(Self {
            customer,
            validation_operators: operators,
        })
    }

    #[must_use]
    pub const fn customer(&self) -> &ActorId {
        &self.customer
    }

    #[must_use]
    pub const fn validation_operators(&self) -> &BTreeSet<ActorId> {
        &self.validation_operators
    }
}

/// Non-secret evaluator configuration fixed before operator execution.
#[derive(Clone, Debug)]
pub struct ExperimentAuthorityConfig {
    pub chain_id: ChainId,
    pub initial_nonce: u64,
    pub private_fixture_root: PathBuf,
    pub expected_private_manifest_hash: IntegrityHash,
    pub roles: ExperimentRoles,
}

/// Maps one public fixture claim to its canonical protocol target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimResolutionBinding {
    pub fixture_claim_id: String,
    pub claim_id: ClaimId,
    pub evidence_ids: BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>,
    pub resolution_reference: ContentRef,
}

/// Maps every claim in one fixture to a single canonical job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureResolutionBinding {
    pub fixture_id: String,
    pub job_id: JobId,
    pub claims: Vec<ClaimResolutionBinding>,
}

/// Closed operator counterclaim data needed to resolve one challenge.
///
/// `counterclaim_verdict` is the challenger's asserted verdict, not hidden
/// truth. The challenge is upheld exactly when it matches the private verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeResolutionBinding {
    pub fixture_id: String,
    pub fixture_claim_id: String,
    pub challenge_id: ChallengeId,
    pub counterclaim_verdict: ResolutionVerdict,
    pub evidence_ids: BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>,
    pub resolution_reference: ContentRef,
}

/// The only egress accepted by the hidden evaluator.
///
/// Implementations route the signed action through the same ingress or
/// deterministic runner path used by every other actor. The evaluator never
/// calls a resolution transition directly.
pub trait CanonicalActionSink {
    type Error;

    fn submit(&mut self, action: SignedAction<Action>) -> Result<(), Self::Error>;
}

/// Public, truth-free accounting for an accepted submission batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionSubmission {
    pub action_ids: Vec<ActionId>,
    pub next_nonce: u64,
}

/// A private-fixture-backed resolution authority.
///
/// This type intentionally does not implement `Debug`: its cached private
/// fixture set must not be exposed through logs or operator observations.
pub struct ExperimentAuthorityEvaluator {
    authority_key: ed25519::PrivateKey,
    authority: ActorId,
    chain_id: ChainId,
    next_nonce: u64,
    private_fixture_root: PathBuf,
    expected_private_manifest_hash: IntegrityHash,
    public_fixtures: LoadedPublicFixtureSet,
    roles: ExperimentRoles,
    decisions_closed: bool,
    private_fixtures: Option<LoadedPrivateFixtureSet>,
}

impl ExperimentAuthorityEvaluator {
    /// Configures an evaluator without opening or reading the private fixture
    /// root. Private loading is deferred until a submission method is called
    /// after operator decisions close.
    pub fn new(
        authority_key: ed25519::PrivateKey,
        config: ExperimentAuthorityConfig,
        public_fixtures: LoadedPublicFixtureSet,
    ) -> Result<Self, EvaluatorSetupError> {
        let authority = ActorId::from(authority_key.public_key());
        if authority == config.roles.customer {
            return Err(EvaluatorSetupError::AuthorityIsCustomer);
        }
        if config.roles.validation_operators.contains(&authority) {
            return Err(EvaluatorSetupError::AuthorityIsValidationOperator);
        }
        Ok(Self {
            authority_key,
            authority,
            chain_id: config.chain_id,
            next_nonce: config.initial_nonce,
            private_fixture_root: config.private_fixture_root,
            expected_private_manifest_hash: config.expected_private_manifest_hash,
            public_fixtures,
            roles: config.roles,
            decisions_closed: false,
            private_fixtures: None,
        })
    }

    #[must_use]
    pub const fn authority(&self) -> &ActorId {
        &self.authority
    }

    #[must_use]
    pub const fn roles(&self) -> &ExperimentRoles {
        &self.roles
    }

    #[must_use]
    pub const fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    #[must_use]
    pub const fn operator_decisions_are_closed(&self) -> bool {
        self.decisions_closed
    }

    /// Irreversibly closes operator decisions and enables private evaluation.
    /// No private filesystem access occurs in this state transition itself.
    pub fn close_operator_decisions(&mut self) -> Result<(), EvaluatorSetupError> {
        if self.decisions_closed {
            return Err(EvaluatorSetupError::OperatorDecisionsAlreadyClosed);
        }
        self.decisions_closed = true;
        Ok(())
    }

    /// Resolves all fixture claims in private-manifest order and submits each
    /// result as an authority-signed canonical action.
    pub fn submit_claim_resolutions<S: CanonicalActionSink>(
        &mut self,
        bindings: &[FixtureResolutionBinding],
        valid_until_height: u64,
        sink: &mut S,
    ) -> Result<ResolutionSubmission, EvaluationError<S::Error>> {
        self.ensure_private_fixtures()?;
        let actions = build_claim_actions(
            self.private_fixtures
                .as_ref()
                .expect("private fixtures were loaded"),
            bindings,
        )?;
        self.sign_and_submit(actions, valid_until_height, sink)
    }

    /// Resolves closed counterclaims against private truth and submits the
    /// outcomes as authority-signed canonical actions.
    pub fn submit_challenge_resolutions<S: CanonicalActionSink>(
        &mut self,
        bindings: &[ChallengeResolutionBinding],
        valid_until_height: u64,
        sink: &mut S,
    ) -> Result<ResolutionSubmission, EvaluationError<S::Error>> {
        self.ensure_private_fixtures()?;
        let actions = build_challenge_actions(
            self.private_fixtures
                .as_ref()
                .expect("private fixtures were loaded"),
            bindings,
        )?;
        self.sign_and_submit(actions, valid_until_height, sink)
    }

    fn ensure_private_fixtures<E>(&mut self) -> Result<(), EvaluationError<E>> {
        if !self.decisions_closed {
            return Err(EvaluationError::OperatorDecisionsOpen);
        }
        if self.private_fixtures.is_none() {
            let loader = PrivateFixtureLoader::new(&self.private_fixture_root)
                .map_err(EvaluationError::Fixture)?;
            let fixtures = loader
                .load_for(&self.public_fixtures, self.expected_private_manifest_hash)
                .map_err(EvaluationError::Fixture)?;
            debug_assert_eq!(fixtures.set, self.public_fixtures.set());
            debug_assert_eq!(fixtures.manifest_hash, self.expected_private_manifest_hash);
            self.private_fixtures = Some(fixtures);
        }
        Ok(())
    }

    fn sign_and_submit<S: CanonicalActionSink>(
        &mut self,
        actions: Vec<Action>,
        valid_until_height: u64,
        sink: &mut S,
    ) -> Result<ResolutionSubmission, EvaluationError<S::Error>> {
        let mut action_ids = Vec::with_capacity(actions.len());
        for action in actions {
            let next_nonce = self
                .next_nonce
                .checked_add(1)
                .ok_or(EvaluationError::NonceExhausted)?;
            let signed = SignedAction::sign(
                &self.authority_key,
                CURRENT_PROTOCOL_VERSION,
                self.chain_id,
                self.next_nonce,
                valid_until_height,
                action,
            )
            .map_err(EvaluationError::Signing)?;
            let action_id = signed.action_id();
            sink.submit(signed).map_err(EvaluationError::Submission)?;
            self.next_nonce = next_nonce;
            action_ids.push(action_id);
        }
        Ok(ResolutionSubmission {
            action_ids,
            next_nonce: self.next_nonce,
        })
    }
}

fn build_claim_actions<E>(
    private: &LoadedPrivateFixtureSet,
    bindings: &[FixtureResolutionBinding],
) -> Result<Vec<Action>, EvaluationError<E>> {
    if bindings.len() != private.fixtures.len() {
        return Err(invalid_binding(
            "fixture binding count does not match private fixtures",
        ));
    }

    let mut actions = Vec::new();
    for (fixture, binding) in private.fixtures.iter().zip(bindings) {
        if binding.fixture_id != fixture.fixture_id {
            return Err(invalid_binding(
                "fixture bindings are not in manifest order",
            ));
        }
        if binding.claims.len() != fixture.claims.len() {
            return Err(invalid_binding(
                "claim binding count does not match fixture truth",
            ));
        }
        for (truth, claim) in fixture.claims.iter().zip(&binding.claims) {
            if claim.fixture_claim_id != truth.claim_id {
                return Err(invalid_binding("claim bindings are not in fixture order"));
            }
            actions.push(Action::ResolveClaim(ResolveClaim {
                job_id: binding.job_id,
                claim_id: claim.claim_id,
                verdict: protocol_verdict(truth.verdict),
                evidence_ids: claim.evidence_ids.clone(),
                resolution_reference: claim.resolution_reference.clone(),
            }));
        }
    }
    Ok(actions)
}

fn build_challenge_actions<E>(
    private: &LoadedPrivateFixtureSet,
    bindings: &[ChallengeResolutionBinding],
) -> Result<Vec<Action>, EvaluationError<E>> {
    let mut seen = BTreeSet::new();
    let mut actions = Vec::with_capacity(bindings.len());
    for binding in bindings {
        if !seen.insert(binding.challenge_id) {
            return Err(invalid_binding("duplicate challenge resolution binding"));
        }
        let fixture = private
            .fixtures
            .iter()
            .find(|fixture| fixture.fixture_id == binding.fixture_id)
            .ok_or_else(|| invalid_binding("challenge names an unknown fixture"))?;
        let truth = fixture
            .claims
            .iter()
            .find(|truth| truth.claim_id == binding.fixture_claim_id)
            .ok_or_else(|| invalid_binding("challenge names an unknown fixture claim"))?;
        actions.push(Action::ResolveChallenge(ResolveChallenge {
            challenge_id: binding.challenge_id,
            upheld: binding.counterclaim_verdict == protocol_verdict(truth.verdict),
            evidence_ids: binding.evidence_ids.clone(),
            resolution_reference: binding.resolution_reference.clone(),
        }));
    }
    Ok(actions)
}

const fn protocol_verdict(verdict: GroundTruthVerdict) -> ResolutionVerdict {
    match verdict {
        GroundTruthVerdict::Valid => ResolutionVerdict::Pass,
        GroundTruthVerdict::Invalid => ResolutionVerdict::Fail,
        GroundTruthVerdict::Ambiguous => ResolutionVerdict::Unresolved,
    }
}

fn invalid_binding<E>(reason: &'static str) -> EvaluationError<E> {
    EvaluationError::InvalidBinding(reason)
}

/// Configuration failures that occur without reading private truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluatorSetupError {
    CustomerIsValidationOperator,
    DuplicateValidationOperator,
    AuthorityIsCustomer,
    AuthorityIsValidationOperator,
    OperatorDecisionsAlreadyClosed,
}

impl fmt::Display for EvaluatorSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CustomerIsValidationOperator => "customer identity is also a validation operator",
            Self::DuplicateValidationOperator => "validation operator identity is duplicated",
            Self::AuthorityIsCustomer => "experiment authority identity is also the customer",
            Self::AuthorityIsValidationOperator => {
                "experiment authority identity is also a validation operator"
            }
            Self::OperatorDecisionsAlreadyClosed => "operator decisions are already closed",
        })
    }
}

impl std::error::Error for EvaluatorSetupError {}

/// Failures while privately evaluating or submitting canonical resolutions.
#[derive(Debug)]
pub enum EvaluationError<E> {
    OperatorDecisionsOpen,
    Fixture(FixtureError),
    InvalidBinding(&'static str),
    NonceExhausted,
    Signing(ActionValidationError),
    Submission(E),
}

impl<E: fmt::Display> fmt::Display for EvaluationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperatorDecisionsOpen => formatter.write_str("operator decisions remain open"),
            Self::Fixture(error) => write!(formatter, "private fixture loading failed: {error}"),
            Self::InvalidBinding(reason) => {
                write!(formatter, "invalid resolution binding: {reason}")
            }
            Self::NonceExhausted => formatter.write_str("authority nonce space is exhausted"),
            Self::Signing(error) => write!(formatter, "canonical action signing failed: {error}"),
            Self::Submission(error) => {
                write!(formatter, "canonical action submission failed: {error}")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for EvaluationError<E> {}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, path::PathBuf};

    use commonware_cryptography::{Signer as _, ed25519};
    use rachet_core::{
        actions::{
            Action, ActionVerificationContext, ClaimDefinition, CreateChallenge, CreateJob,
            ResolutionPolicy, SignedAction,
        },
        artifacts::{ContentRef, GitArtifact, GitHash},
        blocks::ConsensusNodeId,
        bounded::{BoundedBytes, BoundedVec},
        events::CanonicalEvent,
        limits::{MAX_COUNTERCLAIM_BYTES, MAX_EVIDENCE_IDS_PER_ACTION},
        primitives::{ActorId, ChainId, ProtocolVersion, Sha256Digest},
        state::{ChallengeStatus, ClaimStatus, InMemoryStateBatch},
        transition::{
            ActionExecutionError, create_challenge, create_job, execute_action, load_challenge,
            load_claim,
        },
    };

    use rachet_mechanisms::m01_naive_reputation::{M01NaiveReputation, NaiveReputation};
    use rachet_operator::policy::{
        ObservedClaim, ObservedJob, PolicyObservation, PolicyResourceBudget, ScriptedPolicy,
        VerdictTally,
    };

    use super::*;
    use crate::{
        fixtures::{
            FixtureSetKind,
            private::LoadedPrivateFixtureSet,
            schema::{
                AmbiguityClassification, ClaimGroundTruth, DifficultyMetadata, DifficultyTier,
                GroundTruthVerdict, PrivateFixture,
            },
        },
        simulator::{
            DeterministicRunner, EvaluatorActionBatch, LaboratoryMechanism, RunOutput,
            RunnerConfig, ScriptedBlock, ScriptedDecisionPoint, ScriptedOperator, ScriptedRun,
            ScriptedStep,
        },
    };

    fn actor(seed: u64) -> ActorId {
        ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
    }

    fn bounded<const MAX: usize>(bytes: &[u8]) -> BoundedBytes<MAX> {
        BoundedBytes::try_from(bytes).unwrap()
    }

    fn content(byte: u8) -> ContentRef {
        ContentRef::new(
            Sha256Digest::from([byte; 32]),
            bounded(b"cas://evaluator-resolution"),
            bounded(b"application/json"),
        )
    }

    fn roles() -> ExperimentRoles {
        ExperimentRoles::new(actor(10), [actor(11), actor(12)]).unwrap()
    }

    fn evaluator(
        authority_key: ed25519::PrivateKey,
        private_fixture_root: PathBuf,
    ) -> ExperimentAuthorityEvaluator {
        ExperimentAuthorityEvaluator::new(
            authority_key,
            ExperimentAuthorityConfig {
                chain_id: ChainId::from([7; 32]),
                initial_nonce: 0,
                private_fixture_root,
                expected_private_manifest_hash: IntegrityHash::digest(b"private manifest"),
                roles: roles(),
            },
            LoadedPublicFixtureSet::empty_for_test(FixtureSetKind::Smoke),
        )
        .unwrap()
    }

    struct UnreachableSink;

    impl CanonicalActionSink for UnreachableSink {
        type Error = Infallible;

        fn submit(&mut self, _: SignedAction<Action>) -> Result<(), Self::Error> {
            panic!("submission must not occur")
        }
    }

    struct ExecutingSink<'a> {
        state: &'a mut InMemoryStateBatch,
        context: ActionVerificationContext,
        accepted_actors: Vec<ActorId>,
    }

    impl CanonicalActionSink for ExecutingSink<'_> {
        type Error = ActionExecutionError;

        fn submit(&mut self, action: SignedAction<Action>) -> Result<(), Self::Error> {
            execute_action(self.state, &self.context, &action)?;
            self.accepted_actors.push(action.actor);
            Ok(())
        }
    }

    #[test]
    fn private_root_is_not_read_before_operator_decisions_close() {
        let missing = std::env::temp_dir().join(format!(
            "rachet-hidden-evaluator-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&missing);
        let mut evaluator = evaluator(ed25519::PrivateKey::from_seed(20), missing);
        let mut sink = UnreachableSink;

        assert!(matches!(
            evaluator.submit_claim_resolutions(&[], 30, &mut sink),
            Err(EvaluationError::OperatorDecisionsOpen)
        ));
        assert!(!evaluator.operator_decisions_are_closed());

        evaluator.close_operator_decisions().unwrap();
        assert!(matches!(
            evaluator.close_operator_decisions(),
            Err(EvaluatorSetupError::OperatorDecisionsAlreadyClosed)
        ));
        assert!(matches!(
            evaluator.submit_claim_resolutions(&[], 30, &mut sink),
            Err(EvaluationError::Fixture(FixtureError::Io { .. }))
        ));
    }

    #[test]
    fn authority_customer_and_validation_operator_roles_cannot_overlap() {
        let customer = actor(30);
        assert_eq!(
            ExperimentRoles::new(customer.clone(), [customer.clone()]),
            Err(EvaluatorSetupError::CustomerIsValidationOperator)
        );
        assert_eq!(
            ExperimentRoles::new(customer.clone(), [actor(31), actor(31)]),
            Err(EvaluatorSetupError::DuplicateValidationOperator)
        );

        let customer_key = ed25519::PrivateKey::from_seed(30);
        let result = ExperimentAuthorityEvaluator::new(
            customer_key,
            ExperimentAuthorityConfig {
                chain_id: ChainId::from([7; 32]),
                initial_nonce: 0,
                private_fixture_root: PathBuf::new(),
                expected_private_manifest_hash: IntegrityHash::digest(b"private manifest"),
                roles: ExperimentRoles::new(customer, [actor(31)]).unwrap(),
            },
            LoadedPublicFixtureSet::empty_for_test(FixtureSetKind::Smoke),
        );
        assert!(matches!(
            result,
            Err(EvaluatorSetupError::AuthorityIsCustomer)
        ));

        let authority_key = ed25519::PrivateKey::from_seed(32);
        let authority = ActorId::from(authority_key.public_key());
        let result = ExperimentAuthorityEvaluator::new(
            authority_key,
            ExperimentAuthorityConfig {
                chain_id: ChainId::from([7; 32]),
                initial_nonce: 0,
                private_fixture_root: PathBuf::new(),
                expected_private_manifest_hash: IntegrityHash::digest(b"private manifest"),
                roles: ExperimentRoles::new(actor(33), [authority]).unwrap(),
            },
            LoadedPublicFixtureSet::empty_for_test(FixtureSetKind::Smoke),
        );
        assert!(matches!(
            result,
            Err(EvaluatorSetupError::AuthorityIsValidationOperator)
        ));
    }

    #[test]
    fn truth_becomes_authorized_signed_claim_and_challenge_actions() {
        let authority_key = ed25519::PrivateKey::from_seed(40);
        let authority = ActorId::from(authority_key.public_key());
        let customer = actor(10);
        let mut state = InMemoryStateBatch::new();
        let created = create_job(
            &mut state,
            &customer,
            10,
            &CreateJob {
                artifact: GitArtifact::new(
                    bounded(b"https://git.invalid/evaluator"),
                    GitHash::sha1([1; 20]),
                    GitHash::sha256([2; 32]),
                    content(3),
                ),
                claims: BoundedVec::new(vec![ClaimDefinition::new(bounded(b"candidate valid"))])
                    .unwrap(),
                resolution_policy: ResolutionPolicy::ExperimentAuthority {
                    authority: authority.clone(),
                },
                validation_opens_at: 10,
                validation_closes_at: 20,
                reveal_closes_at: None,
                challenge_closes_at: Some(30),
                supersedes: None,
                metadata: bounded(b"fixture/smoke-001"),
            },
        )
        .unwrap();
        let claim_id = created.claim_ids.as_slice()[0];

        let mut evaluator = evaluator(authority_key, PathBuf::new());
        evaluator.close_operator_decisions().unwrap();
        evaluator.private_fixtures = Some(LoadedPrivateFixtureSet {
            set: FixtureSetKind::Smoke,
            manifest_hash: IntegrityHash::digest(b"private manifest"),
            fixtures: vec![PrivateFixture {
                schema_version: 1,
                fixture_id: "smoke-001".to_owned(),
                public_fixture_sha256: IntegrityHash::digest(b"public fixture"),
                claims: vec![ClaimGroundTruth {
                    claim_id: "claim/candidate-valid".to_owned(),
                    verdict: GroundTruthVerdict::Invalid,
                    seeded_defect_description: Some("hidden defect".to_owned()),
                    reproduction_procedure: Vec::new(),
                    expected_evidence: vec!["hidden evidence".to_owned()],
                    ambiguity: AmbiguityClassification::None,
                    difficulty: DifficultyMetadata {
                        tier: DifficultyTier::Subtle,
                        expected_validation_seconds: 60,
                        skill_tags: vec!["rust".to_owned()],
                    },
                }],
            }],
        });

        let claim_binding = FixtureResolutionBinding {
            fixture_id: "smoke-001".to_owned(),
            job_id: created.job_id,
            claims: vec![ClaimResolutionBinding {
                fixture_claim_id: "claim/candidate-valid".to_owned(),
                claim_id,
                evidence_ids: BoundedVec::<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>::default(),
                resolution_reference: content(9),
            }],
        };
        let claim_submission;
        {
            let mut sink = ExecutingSink {
                state: &mut state,
                context: ActionVerificationContext::current(ChainId::from([7; 32]), 21),
                accepted_actors: Vec::new(),
            };
            claim_submission = evaluator
                .submit_claim_resolutions(&[claim_binding], 30, &mut sink)
                .unwrap();
            assert_eq!(
                sink.accepted_actors.as_slice(),
                std::slice::from_ref(&authority)
            );
        }
        assert_eq!(claim_submission.action_ids.len(), 1);
        assert_eq!(claim_submission.next_nonce, 1);
        assert!(matches!(
            load_claim(&state, created.job_id, claim_id).unwrap().status,
            ClaimStatus::Resolved(rachet_core::state::ClaimResolution {
                verdict: ResolutionVerdict::Fail,
                ..
            })
        ));

        let challenge_action = CreateChallenge {
            target: rachet_core::actions::ChallengeTarget::Claim(claim_id),
            counterclaim: bounded::<MAX_COUNTERCLAIM_BYTES>(b"the candidate is invalid"),
            evidence_ids: BoundedVec::default(),
        };
        let challenge_id = create_challenge(&mut state, &actor(50), 22, &challenge_action).unwrap();
        let challenge_binding = ChallengeResolutionBinding {
            fixture_id: "smoke-001".to_owned(),
            fixture_claim_id: "claim/candidate-valid".to_owned(),
            challenge_id,
            counterclaim_verdict: ResolutionVerdict::Fail,
            evidence_ids: BoundedVec::default(),
            resolution_reference: content(10),
        };
        {
            let mut sink = ExecutingSink {
                state: &mut state,
                context: ActionVerificationContext::current(ChainId::from([7; 32]), 23),
                accepted_actors: Vec::new(),
            };
            let submission = evaluator
                .submit_challenge_resolutions(&[challenge_binding], 30, &mut sink)
                .unwrap();
            assert_eq!(submission.next_nonce, 2);
            assert_eq!(sink.accepted_actors, [authority]);
        }
        assert!(matches!(
            load_challenge(&state, challenge_id).unwrap().status,
            ChallengeStatus::Resolved { upheld: true, .. }
        ));
        assert_eq!(
            load_claim(&state, created.job_id, claim_id).unwrap().status,
            ClaimStatus::Open
        );
    }

    fn deterministic_fixture_run() -> RunOutput {
        let chain_id = ChainId::from([7; 32]);
        let customer_key = ed25519::PrivateKey::from_seed(10);
        let authority_key = ed25519::PrivateKey::from_seed(40);
        let authority = ActorId::from(authority_key.public_key());
        let operator_key = ed25519::PrivateKey::from_seed(11);
        let operator = ActorId::from(operator_key.public_key());
        let create = CreateJob {
            artifact: GitArtifact::new(
                bounded(b"https://git.invalid/deterministic-runner"),
                GitHash::sha1([51; 20]),
                GitHash::sha256([52; 32]),
                content(53),
            ),
            claims: BoundedVec::new(vec![ClaimDefinition::new(bounded(b"candidate is valid"))])
                .unwrap(),
            resolution_policy: ResolutionPolicy::ExperimentAuthority {
                authority: authority.clone(),
            },
            validation_opens_at: 0,
            validation_closes_at: 0,
            reveal_closes_at: None,
            challenge_closes_at: Some(3),
            supersedes: None,
            metadata: bounded(b"fixture/smoke-001"),
        };
        let mut planning_state = InMemoryStateBatch::new();
        let created = create_job(&mut planning_state, &actor(10), 0, &create).unwrap();
        let claim_id = created.claim_ids.as_slice()[0];

        let mut evaluator = evaluator(authority_key, PathBuf::new());
        evaluator.close_operator_decisions().unwrap();
        evaluator.private_fixtures = Some(LoadedPrivateFixtureSet {
            set: FixtureSetKind::Smoke,
            manifest_hash: IntegrityHash::digest(b"private manifest"),
            fixtures: vec![PrivateFixture {
                schema_version: 1,
                fixture_id: "smoke-001".to_owned(),
                public_fixture_sha256: IntegrityHash::digest(b"public fixture"),
                claims: vec![ClaimGroundTruth {
                    claim_id: "claim/candidate-valid".to_owned(),
                    verdict: GroundTruthVerdict::Valid,
                    seeded_defect_description: None,
                    reproduction_procedure: Vec::new(),
                    expected_evidence: vec!["fixture truth".to_owned()],
                    ambiguity: AmbiguityClassification::None,
                    difficulty: DifficultyMetadata {
                        tier: DifficultyTier::Moderate,
                        expected_validation_seconds: 30,
                        skill_tags: vec!["rust".to_owned()],
                    },
                }],
            }],
        });
        let mut evaluator_actions = EvaluatorActionBatch::default();
        evaluator
            .submit_claim_resolutions(
                &[FixtureResolutionBinding {
                    fixture_id: "smoke-001".to_owned(),
                    job_id: created.job_id,
                    claims: vec![ClaimResolutionBinding {
                        fixture_claim_id: "claim/candidate-valid".to_owned(),
                        claim_id,
                        evidence_ids: BoundedVec::default(),
                        resolution_reference: content(54),
                    }],
                }],
                3,
                &mut evaluator_actions,
            )
            .unwrap();

        let create_action = SignedAction::sign(
            &customer_key,
            ProtocolVersion::V1,
            chain_id,
            0,
            3,
            Action::CreateJob(Box::new(create)),
        )
        .unwrap();
        let observation = PolicyObservation::new(
            0,
            0,
            PolicyResourceBudget::default(),
            vec![
                ObservedJob::new(
                    created.job_id,
                    vec![ObservedClaim::new(claim_id, VerdictTally::default())],
                    false,
                )
                .unwrap(),
            ],
            VerdictTally::default(),
        )
        .unwrap();
        let script = ScriptedRun {
            operators: vec![ScriptedOperator::new(
                operator_key,
                0,
                ScriptedPolicy::AlwaysPass,
            )],
            blocks: vec![
                ScriptedBlock::new(vec![
                    ScriptedStep::CanonicalActions(vec![create_action]),
                    ScriptedStep::DecisionPoint(ScriptedDecisionPoint {
                        operator_index: 0,
                        observation,
                        valid_until_height: 3,
                    }),
                ]),
                ScriptedBlock::new(vec![ScriptedStep::EvaluatorActions(evaluator_actions)]),
            ],
        };
        let config = RunnerConfig {
            seed: 0x5241_4348_4554,
            chain_id,
            blocks_per_epoch: 1,
            consensus_node: ConsensusNodeId::from(ed25519::PrivateKey::from_seed(90).public_key()),
            genesis_parent_block: Sha256Digest::from([0; 32]),
            genesis_timestamp_ms: 1_700_000_000_000,
            block_interval_ms: 1_000,
        };
        let output = DeterministicRunner::new(config, LaboratoryMechanism::M01NaiveReputation)
            .unwrap()
            .run(script)
            .unwrap();

        let reputation_key = M01NaiveReputation::reputation_state_key(&operator);
        let reputation = output
            .final_state
            .iter()
            .find_map(|(key, value)| (key == &reputation_key).then_some(value))
            .expect("M01 must update the scripted operator");
        assert_eq!(
            NaiveReputation::decode(reputation).unwrap(),
            NaiveReputation {
                score: 1,
                correct: 1,
                ..NaiveReputation::default()
            }
        );
        output
    }

    #[test]
    fn scripted_fixture_runs_real_blocks_epochs_evaluator_and_m01_deterministically() {
        let first = deterministic_fixture_run();
        let second = deterministic_fixture_run();

        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_eq!(first.blocks.len(), 2);
        assert_eq!(first.blocks[0].block.header.epoch, 0);
        assert_eq!(first.blocks[1].block.header.epoch, 1);
        assert!(matches!(
            first.blocks[1].events.first(),
            Some(CanonicalEvent::EpochChanged {
                previous: 0,
                current: 1
            })
        ));
        assert!(first.blocks[1].events.iter().any(|event| matches!(
            event,
            CanonicalEvent::ClaimResolved {
                verdict: ResolutionVerdict::Pass,
                ..
            }
        )));
        assert_eq!(first.blocks[1].block.actions.as_slice()[0].actor, actor(40));
        assert_eq!(first.decisions.len(), 1);
        assert_eq!(first.decisions[0].operator, actor(11));
        assert_eq!(first.decisions[0].decision.resource_report.model_calls, 0);
        assert_eq!(first.decisions[0].decision.resource_report.tool_calls, 0);
        assert!(!first.runtime_audit.is_empty());
    }
}
