//! Atomic canonical action dispatch and receipt production.

use super::{
    ChallengeResolutionError, CommitmentTransitionError, EvidenceAttestationError,
    JobTransitionError, close_job, create_challenge, create_commitment, create_job,
    register_evidence, resolve_challenge, resolve_claim, reveal_commitment, submit_attestation,
};
use crate::{
    actions::{Action, ActionValidationError, ActionVerificationContext, SignedAction},
    bounded::BoundedVec,
    events::{ActionReceipt, CanonicalEvent},
    limits::MAX_EVENTS_PER_ACTION,
    state::{StateBatch, StateBatchError},
};
use core::fmt;

/// Verifies and applies exactly one signed action in a nested state transaction.
///
/// Receipt events are emitted in semantic transition order. In particular,
/// `CreateJob` emits the job before claims in action order, claim resolution
/// precedes derived job resolution, and challenge resolution precedes any
/// derived claim reopening. Any failure rolls back the nonce and every action
/// write and returns no partial receipt.
pub fn execute_action(
    state: &mut dyn StateBatch,
    context: &ActionVerificationContext,
    signed: &SignedAction<Action>,
) -> Result<ActionReceipt, ActionExecutionError> {
    state.fork();
    let execution = execute_in_fork(state, context, signed);
    match execution {
        Ok(receipt) => {
            state.commit().map_err(ActionExecutionError::State)?;
            Ok(receipt)
        }
        Err(error) => {
            state.rollback().map_err(ActionExecutionError::State)?;
            Err(error)
        }
    }
}

fn execute_in_fork(
    state: &mut dyn StateBatch,
    context: &ActionVerificationContext,
    signed: &SignedAction<Action>,
) -> Result<ActionReceipt, ActionExecutionError> {
    let action_id = signed
        .verify_and_advance_nonce(state, context)
        .map_err(ActionExecutionError::Validation)?;
    let events = apply_verified_action(state, context.height, signed)?;
    Ok(ActionReceipt::from_bounded_events(
        action_id,
        signed.actor.clone(),
        signed.nonce,
        events,
    ))
}

/// Applies an envelope already verified by the authoritative block executor.
///
/// This is crate-visible so block execution can complete envelope verification
/// for the entire candidate before beginning canonical transitions. Callers
/// must hold an enclosing transaction: this function deliberately performs no
/// signature or nonce work and does not catch transition failures.
pub(crate) fn apply_verified_action(
    state: &mut dyn StateBatch,
    height: u64,
    signed: &SignedAction<Action>,
) -> Result<BoundedVec<CanonicalEvent, MAX_EVENTS_PER_ACTION>, ActionExecutionError> {
    let events = apply_payload(state, &signed.actor, height, &signed.payload)?;
    Ok(BoundedVec::new(events)
        .expect("canonical action transitions cannot exceed the protocol event bound"))
}

fn apply_payload(
    state: &mut dyn StateBatch,
    actor: &crate::primitives::ActorId,
    height: u64,
    action: &Action,
) -> Result<Vec<CanonicalEvent>, ActionExecutionError> {
    match action {
        Action::CreateJob(action) => {
            let created =
                create_job(state, actor, height, action).map_err(ActionExecutionError::Job)?;
            let mut events = Vec::with_capacity(created.claim_ids.len() + 1);
            events.push(CanonicalEvent::JobCreated {
                job_id: created.job_id,
            });
            events.extend(
                created
                    .claim_ids
                    .iter()
                    .map(|claim_id| CanonicalEvent::ClaimCreated {
                        job_id: created.job_id,
                        claim_id: *claim_id,
                    }),
            );
            Ok(events)
        }
        Action::RegisterEvidence(action) => {
            let evidence_id = register_evidence(state, actor, height, action)
                .map_err(ActionExecutionError::EvidenceAttestation)?;
            Ok(vec![CanonicalEvent::EvidenceRegistered { evidence_id }])
        }
        Action::SubmitAttestation(action) => {
            let attestation_id = submit_attestation(state, actor, height, action)
                .map_err(ActionExecutionError::EvidenceAttestation)?;
            Ok(vec![CanonicalEvent::AttestationSubmitted {
                attestation_id,
            }])
        }
        Action::CreateCommitment(action) => Ok(vec![
            create_commitment(state, actor, height, action)
                .map_err(ActionExecutionError::Commitment)?,
        ]),
        Action::RevealCommitment(action) => Ok(vec![
            reveal_commitment(state, actor, height, action)
                .map_err(ActionExecutionError::Commitment)?,
        ]),
        Action::CreateChallenge(action) => {
            let challenge_id = create_challenge(state, actor, height, action)
                .map_err(ActionExecutionError::ChallengeResolution)?;
            Ok(vec![CanonicalEvent::ChallengeCreated { challenge_id }])
        }
        Action::ResolveClaim(action) => {
            let outcome = resolve_claim(state, actor, height, action)
                .map_err(ActionExecutionError::ChallengeResolution)?;
            let mut events = vec![CanonicalEvent::ClaimResolved {
                claim_id: outcome.claim_id,
                verdict: action.verdict,
            }];
            if outcome.job_resolved {
                events.push(CanonicalEvent::JobResolved {
                    job_id: action.job_id,
                });
            }
            Ok(events)
        }
        Action::ResolveChallenge(action) => {
            let outcome = resolve_challenge(state, actor, height, action)
                .map_err(ActionExecutionError::ChallengeResolution)?;
            let mut events = vec![CanonicalEvent::ChallengeResolved {
                challenge_id: outcome.challenge_id,
                upheld: action.upheld,
            }];
            if let Some(claim_id) = outcome.reopened_claim {
                events.push(CanonicalEvent::ClaimReopened { claim_id });
            }
            Ok(events)
        }
        Action::CloseJob(action) => {
            let job_id =
                close_job(state, actor, height, action).map_err(ActionExecutionError::Job)?;
            Ok(vec![CanonicalEvent::JobClosed { job_id }])
        }
    }
}

/// Stable failure categories from one atomic action execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionExecutionError {
    Validation(ActionValidationError),
    Job(JobTransitionError),
    EvidenceAttestation(EvidenceAttestationError),
    Commitment(CommitmentTransitionError),
    ChallengeResolution(ChallengeResolutionError),
    State(StateBatchError),
}

impl ActionExecutionError {
    /// Returns the stable machine-readable code of the underlying failure.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Validation(error) => error.code(),
            Self::Job(error) => error.code(),
            Self::EvidenceAttestation(error) => error.code(),
            Self::Commitment(error) => error.code(),
            Self::ChallengeResolution(error) => error.code(),
            Self::State(StateBatchError::NoOpenFork) => "STATE_TRANSACTION_INVALID",
        }
    }
}

impl fmt::Display for ActionExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ActionExecutionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{
            ChallengeTarget, ClaimDefinition, CloseJob, CommitmentSubject, CreateChallenge,
            CreateCommitment, CreateJob, RegisterEvidence, ResolutionPolicy, ResolutionVerdict,
            ResolveChallenge, ResolveClaim, RevealCommitment, SubmitAttestation, Verdict,
            reveal_digest,
        },
        artifacts::{ContentRef, GitArtifact, GitHash},
        bounded::{BoundedBytes, BoundedVec},
        limits::{MAX_COMMITMENT_PAYLOAD_BYTES, MAX_COMMITMENT_SALT_BYTES},
        primitives::{ActorId, ChainId, ProtocolVersion, Sha256Digest},
        state::{InMemoryStateBatch, StateBatch, StateKey},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{Signer as _, ed25519};

    fn key(seed: u64) -> ed25519::PrivateKey {
        ed25519::PrivateKey::from_seed(seed)
    }

    fn actor(seed: u64) -> ActorId {
        ActorId::from(key(seed).public_key())
    }

    fn bounded<const MAX: usize>(value: &[u8]) -> BoundedBytes<MAX> {
        BoundedBytes::try_from(value).unwrap()
    }

    fn content(byte: u8) -> ContentRef {
        ContentRef::new(
            Sha256Digest::from([byte; 32]),
            bounded(b"cas://content"),
            bounded(b"application/json"),
        )
    }

    fn create_job_action(authority: ActorId) -> CreateJob {
        CreateJob {
            artifact: GitArtifact::new(
                bounded(b"https://git.invalid/events"),
                GitHash::sha1([1; 20]),
                GitHash::sha256([2; 32]),
                content(3),
            ),
            claims: BoundedVec::new(vec![ClaimDefinition::new(bounded(b"tests pass"))]).unwrap(),
            resolution_policy: ResolutionPolicy::ExperimentAuthority { authority },
            validation_opens_at: 10,
            validation_closes_at: 20,
            reveal_closes_at: Some(25),
            challenge_closes_at: Some(30),
            supersedes: None,
            metadata: bounded(b"events fixture"),
        }
    }

    fn signed(seed: u64, nonce: u64, payload: Action) -> SignedAction<Action> {
        SignedAction::sign(
            &key(seed),
            ProtocolVersion::V1,
            ChainId::new([9; 32]),
            nonce,
            100,
            payload,
        )
        .unwrap()
    }

    fn execute(
        state: &mut InMemoryStateBatch,
        height: u64,
        action: &SignedAction<Action>,
    ) -> ActionReceipt {
        execute_action(
            state,
            &ActionVerificationContext::current(ChainId::new([9; 32]), height),
            action,
        )
        .unwrap()
    }

    fn assert_receipt(
        receipt: &ActionReceipt,
        signed: &SignedAction<Action>,
        expected: &[CanonicalEvent],
    ) {
        assert_eq!(receipt.action_id, signed.action_id());
        assert_eq!(receipt.actor, signed.actor);
        assert_eq!(receipt.nonce, signed.nonce);
        assert_eq!(receipt.events.as_slice(), expected);
    }

    #[test]
    fn every_successful_action_emits_the_exact_ordered_receipt() {
        let customer_seed = 1;
        let authority_seed = 2;
        let producer_seed = 3;
        let operator_seed = 4;
        let committer_seed = 5;
        let challenger_seed = 6;
        let mut state = InMemoryStateBatch::new();

        let create = create_job_action(actor(authority_seed));
        let job_id = create.job_id();
        let create_signed = signed(customer_seed, 0, Action::CreateJob(Box::new(create)));
        let receipt = execute(&mut state, 10, &create_signed);
        let CanonicalEvent::ClaimCreated { claim_id, .. } = receipt.events.as_slice()[1] else {
            panic!("create job must emit its claim")
        };
        assert_receipt(
            &receipt,
            &create_signed,
            &[
                CanonicalEvent::JobCreated { job_id },
                CanonicalEvent::ClaimCreated { job_id, claim_id },
            ],
        );

        let registration = RegisterEvidence {
            job_id,
            claim_id: Some(claim_id),
            evidence: content(20),
            manifest_digest: Sha256Digest::from([21; 32]),
        };
        let evidence_id = registration.evidence_id();
        let register_signed = signed(producer_seed, 0, Action::RegisterEvidence(registration));
        let receipt = execute(&mut state, 10, &register_signed);
        assert_receipt(
            &receipt,
            &register_signed,
            &[CanonicalEvent::EvidenceRegistered { evidence_id }],
        );

        let attestation = SubmitAttestation {
            job_id,
            claim_id,
            verdict: Verdict::Pass,
            confidence_basis_points: 9_000,
            evidence_ids: BoundedVec::new(vec![evidence_id]).unwrap(),
        };
        let attestation_id = attestation.attestation_id(&actor(operator_seed));
        let attest_signed = signed(operator_seed, 0, Action::SubmitAttestation(attestation));
        let receipt = execute(&mut state, 10, &attest_signed);
        assert_receipt(
            &receipt,
            &attest_signed,
            &[CanonicalEvent::AttestationSubmitted { attestation_id }],
        );

        let payload = bounded::<MAX_COMMITMENT_PAYLOAD_BYTES>(b"verdict");
        let salt = bounded::<MAX_COMMITMENT_SALT_BYTES>(b"salt");
        let commitment = CreateCommitment {
            subject: CommitmentSubject::Claim(claim_id),
            digest: reveal_digest(&payload, &salt),
            reveal_after_height: 12,
            reveal_before_height: 20,
        };
        let commitment_id = commitment.commitment_id(&actor(committer_seed));
        let commit_signed = signed(committer_seed, 0, Action::CreateCommitment(commitment));
        let receipt = execute(&mut state, 10, &commit_signed);
        assert_receipt(
            &receipt,
            &commit_signed,
            &[CanonicalEvent::CommitmentCreated { commitment_id }],
        );

        let reveal_signed = signed(
            committer_seed,
            1,
            Action::RevealCommitment(RevealCommitment {
                commitment_id,
                payload,
                salt,
            }),
        );
        let receipt = execute(&mut state, 12, &reveal_signed);
        assert_receipt(
            &receipt,
            &reveal_signed,
            &[CanonicalEvent::CommitmentRevealed { commitment_id }],
        );

        let resolve_signed = signed(
            authority_seed,
            0,
            Action::ResolveClaim(ResolveClaim {
                job_id,
                claim_id,
                verdict: ResolutionVerdict::Pass,
                evidence_ids: BoundedVec::new(vec![evidence_id]).unwrap(),
                resolution_reference: content(22),
            }),
        );
        let receipt = execute(&mut state, 26, &resolve_signed);
        assert_receipt(
            &receipt,
            &resolve_signed,
            &[
                CanonicalEvent::ClaimResolved {
                    claim_id,
                    verdict: ResolutionVerdict::Pass,
                },
                CanonicalEvent::JobResolved { job_id },
            ],
        );

        let challenge = CreateChallenge {
            target: ChallengeTarget::Claim(claim_id),
            counterclaim: bounded(b"counterexample"),
            evidence_ids: BoundedVec::new(vec![evidence_id]).unwrap(),
        };
        let challenge_id = challenge.challenge_id(&actor(challenger_seed));
        let challenge_signed = signed(challenger_seed, 0, Action::CreateChallenge(challenge));
        let receipt = execute(&mut state, 27, &challenge_signed);
        assert_receipt(
            &receipt,
            &challenge_signed,
            &[CanonicalEvent::ChallengeCreated { challenge_id }],
        );

        let challenge_resolution_signed = signed(
            authority_seed,
            1,
            Action::ResolveChallenge(ResolveChallenge {
                challenge_id,
                upheld: true,
                evidence_ids: BoundedVec::new(vec![evidence_id]).unwrap(),
                resolution_reference: content(23),
            }),
        );
        let receipt = execute(&mut state, 28, &challenge_resolution_signed);
        assert_receipt(
            &receipt,
            &challenge_resolution_signed,
            &[
                CanonicalEvent::ChallengeResolved {
                    challenge_id,
                    upheld: true,
                },
                CanonicalEvent::ClaimReopened { claim_id },
            ],
        );

        let close_signed = signed(customer_seed, 1, Action::CloseJob(CloseJob::new(job_id)));
        let receipt = execute(&mut state, 31, &close_signed);
        assert_receipt(
            &receipt,
            &close_signed,
            &[CanonicalEvent::JobClosed { job_id }],
        );
    }

    #[test]
    fn maximum_create_job_fills_but_never_exceeds_the_receipt_event_bound() {
        let mut create = create_job_action(actor(32));
        create.claims = BoundedVec::new(
            (0_u16..128)
                .map(|index| ClaimDefinition::new(bounded(&index.to_be_bytes())))
                .collect(),
        )
        .unwrap();
        let expected_job = create.job_id();
        let signed = signed(31, 0, Action::CreateJob(Box::new(create)));
        let mut state = InMemoryStateBatch::new();
        let receipt = execute(&mut state, 10, &signed);

        assert_eq!(receipt.events.len(), MAX_EVENTS_PER_ACTION);
        assert_eq!(
            receipt.events.as_slice()[0],
            CanonicalEvent::JobCreated {
                job_id: expected_job
            }
        );
        assert!(receipt.events.as_slice()[1..].iter().all(
            |event| matches!(event, CanonicalEvent::ClaimCreated { job_id, .. } if *job_id == expected_job)
        ));
        assert!(
            receipt.events.as_slice()[1..]
                .windows(2)
                .all(|pair| pair[0] != pair[1])
        );
    }

    #[test]
    fn failed_actions_return_no_receipt_and_roll_back_nonce_and_transition_writes() {
        let mut state = InMemoryStateBatch::new();
        let create = create_job_action(actor(12));
        let job_id = create.job_id();
        execute(
            &mut state,
            10,
            &signed(11, 0, Action::CreateJob(Box::new(create))),
        );

        let registration = RegisterEvidence {
            job_id,
            claim_id: None,
            evidence: content(40),
            manifest_digest: Sha256Digest::from([41; 32]),
        };
        execute(
            &mut state,
            10,
            &signed(13, 0, Action::RegisterEvidence(registration.clone())),
        );
        let before = state.root();
        let failed = signed(13, 1, Action::RegisterEvidence(registration));
        assert_eq!(
            execute_action(
                &mut state,
                &ActionVerificationContext::current(ChainId::new([9; 32]), 11),
                &failed,
            ),
            Err(ActionExecutionError::EvidenceAttestation(
                EvidenceAttestationError::EvidenceAlreadyExists
            ))
        );
        assert_eq!(state.root(), before);
        assert_eq!(
            state.get(&StateKey::account(&failed.actor)).as_deref(),
            Some(1_u64.to_be_bytes().as_slice())
        );
    }

    #[test]
    fn repeated_execution_from_identical_state_has_identical_receipt_bytes() {
        let authority = actor(22);
        let action = signed(
            21,
            0,
            Action::CreateJob(Box::new(create_job_action(authority))),
        );
        let mut first_state = InMemoryStateBatch::new();
        let mut second_state = first_state.clone();
        let first = execute(&mut first_state, 10, &action);
        let second = execute(&mut second_state, 10, &action);

        assert_eq!(first, second);
        assert_eq!(first.encode(), second.encode());
        assert_eq!(first_state, second_state);
    }
}
