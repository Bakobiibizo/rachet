//! Bounded state-machine fuzzing for the complete canonical transition surface.

use commonware_cryptography::{Signer as _, ed25519};
use commonware_invariants::minifuzz;
use rachet_core::{
    actions::{
        Action, ChallengeTarget, ClaimDefinition, CloseJob, CommitmentSubject, CreateChallenge,
        CreateCommitment, CreateJob, RegisterEvidence, ResolutionPolicy, ResolutionVerdict,
        ResolveChallenge, ResolveClaim, RevealCommitment, SignedAction, SubmitAttestation, Verdict,
        reveal_digest,
    },
    artifacts::{ContentRef, GitArtifact, GitHash},
    bounded::{BoundedBytes, BoundedVec},
    invariants::check_core_invariants,
    limits::{MAX_COMMITMENT_PAYLOAD_BYTES, MAX_COMMITMENT_SALT_BYTES},
    mechanisms::{
        MechanismId, MechanismSelection, MechanismSet, MechanismSetConfig, MechanismVersion,
    },
    primitives::{
        ActorId, AttestationId, ChainId, ChallengeId, ClaimId, CommitmentId, EvidenceId, JobId,
        ProtocolVersion, Sha256Digest,
    },
    state::{InMemoryStateBatch, StateBatch, StateEntry, StateKey},
    transition::{BlockExecutionError, ExecutionOutput, TransitionContext, execute_block},
};
use rachet_mechanisms::{
    m00_record_only::{M00Config, M00RecordOnly},
    m01_naive_reputation::{M01Config, M01NaiveReputation},
    registry::MechanismInstance,
};
use std::{
    any::Any,
    panic::{AssertUnwindSafe, catch_unwind},
};

const CHAIN: ChainId = ChainId::new([0x19; 32]);
const FUZZ_SEED: u64 = 0x5241_4348_4554_0019;
const SMOKE_CASES: u64 = 32;
const MIN_STEPS: usize = StepKind::COUNT;
const MAX_STEPS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StepKind {
    CreateJob,
    RegisterEvidence,
    SubmitAttestation,
    CreateCommitment,
    RevealCommitment,
    CreateChallenge,
    ResolveClaim,
    ResolveChallenge,
    CloseJob,
    EpochChange,
}

impl StepKind {
    const COUNT: usize = 10;

    const ALL: [Self; Self::COUNT] = [
        Self::CreateJob,
        Self::RegisterEvidence,
        Self::SubmitAttestation,
        Self::CreateCommitment,
        Self::RevealCommitment,
        Self::CreateChallenge,
        Self::ResolveClaim,
        Self::ResolveChallenge,
        Self::CloseJob,
        Self::EpochChange,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Step {
    kind: StepKind,
    selector: u8,
    flags: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StepOutcome {
    Accepted(ExecutionOutput),
    Rejected(BlockExecutionError),
}

#[derive(Debug, Eq, PartialEq)]
struct RunSnapshot {
    entries: Vec<StateEntry>,
    outcomes: Vec<StepOutcome>,
}

#[derive(Clone, Copy)]
struct JobFixture {
    job_id: JobId,
    claim_id: ClaimId,
}

#[derive(Clone)]
struct CommitmentFixture {
    commitment_id: CommitmentId,
    creator_seed: u64,
    payload: BoundedBytes<MAX_COMMITMENT_PAYLOAD_BYTES>,
    salt: BoundedBytes<MAX_COMMITMENT_SALT_BYTES>,
}

struct Scenario {
    state: InMemoryStateBatch,
    mechanisms: MechanismSet<MechanismInstance>,
    height: u64,
    epoch: u64,
    jobs: Vec<JobFixture>,
    evidence: Vec<EvidenceId>,
    attestations: Vec<AttestationId>,
    commitments: Vec<CommitmentFixture>,
    challenges: Vec<ChallengeId>,
}

impl Scenario {
    fn new() -> Self {
        let config = MechanismSetConfig::new(
            ProtocolVersion::V1,
            vec![
                MechanismSelection::new(
                    MechanismId::M00,
                    MechanismVersion::V1_0_0,
                    M00Config.canonical(),
                ),
                MechanismSelection::new(
                    MechanismId::M01,
                    MechanismVersion::V1_0_0,
                    M01Config.canonical(),
                ),
            ],
        )
        .unwrap();
        let mechanisms = MechanismSet::compile(
            &config,
            vec![
                MechanismInstance::m00(M00RecordOnly::default()).unwrap(),
                MechanismInstance::m01(M01NaiveReputation::default()).unwrap(),
            ],
        )
        .unwrap();
        Self {
            state: InMemoryStateBatch::new(),
            mechanisms,
            height: 0,
            epoch: 0,
            jobs: Vec::new(),
            evidence: Vec::new(),
            attestations: Vec::new(),
            commitments: Vec::new(),
            challenges: Vec::new(),
        }
    }

    fn execute(&mut self, step: Step, index: usize) -> Result<StepOutcome, String> {
        self.height += 1 + u64::from(step.flags % 3);
        let (actions, pending) = if step.kind == StepKind::EpochChange {
            self.epoch += 1 + u64::from(step.selector % 3);
            (Vec::new(), None)
        } else {
            let (action, pending) = self.action(step, index);
            (vec![action], pending)
        };
        let context = TransitionContext {
            chain_id: CHAIN,
            protocol_version: ProtocolVersion::V1,
            height: self.height,
            epoch: self.epoch,
            mechanism_set_id: self.mechanisms.id(),
        };
        let before = self.state.clone();
        let result = execute_block(&mut self.state, &context, &actions, &self.mechanisms);
        let outcome = match result {
            Ok(output) => {
                if output.post_state_root != self.state.root() {
                    return Err(format!(
                        "step {index}: accepted output root differs from state"
                    ));
                }
                let expected_receipts = usize::from(!actions.is_empty());
                if output.receipts.len() != expected_receipts {
                    return Err(format!(
                        "step {index}: expected {expected_receipts} receipts, got {}",
                        output.receipts.len()
                    ));
                }
                self.record_success(pending, &output);
                StepOutcome::Accepted(output)
            }
            Err(error) => {
                if self.state != before {
                    return Err(format!(
                        "step {index}: rejected {} changed canonical state",
                        error.code()
                    ));
                }
                StepOutcome::Rejected(error)
            }
        };
        check_core_invariants(&self.state)
            .map_err(|error| format!("step {index}: core invariant {error}"))?;
        self.mechanisms
            .check_invariants(&self.state)
            .map_err(|error| format!("step {index}: mechanism invariant {error}"))?;
        Ok(outcome)
    }

    fn action(&self, step: Step, index: usize) -> (SignedAction<Action>, Option<Pending>) {
        let missing_job = JobFixture {
            job_id: JobId::derive(&trace_bytes(index, step.selector, 0x91)),
            claim_id: ClaimId::derive(&trace_bytes(index, step.selector, 0x92)),
        };
        let job = choose(&self.jobs, step.selector, missing_job);
        let (seed, payload, pending) = match step.kind {
            StepKind::CreateJob => {
                let create = create_job(index, step, self.height);
                (1, Action::CreateJob(Box::new(create)), Some(Pending::Job))
            }
            StepKind::RegisterEvidence => {
                let evidence_digest = digest(index, step.selector, 0x31);
                let registration = RegisterEvidence {
                    job_id: job.job_id,
                    claim_id: (step.flags & 1 == 0).then_some(job.claim_id),
                    evidence: content(evidence_digest),
                    manifest_digest: digest(index, step.flags, 0x32),
                };
                (
                    3,
                    Action::RegisterEvidence(registration),
                    Some(Pending::Evidence),
                )
            }
            StepKind::SubmitAttestation => {
                let evidence_ids = choose_optional(&self.evidence, step.flags)
                    .into_iter()
                    .collect();
                (
                    4 + u64::from(step.selector % 3),
                    Action::SubmitAttestation(SubmitAttestation {
                        job_id: job.job_id,
                        claim_id: job.claim_id,
                        verdict: verdict(step.flags),
                        confidence_basis_points: u16::from(step.selector) * 40,
                        evidence_ids: BoundedVec::new(evidence_ids).unwrap(),
                    }),
                    Some(Pending::Attestation),
                )
            }
            StepKind::CreateCommitment => {
                let creator_seed = 8 + u64::from(step.selector % 2);
                let payload = bounded(&trace_bytes(index, step.selector, 0x41));
                let salt = bounded(&trace_bytes(index, step.flags, 0x42));
                let create = CreateCommitment {
                    subject: if step.flags & 1 == 0 {
                        CommitmentSubject::Claim(job.claim_id)
                    } else {
                        CommitmentSubject::Job(job.job_id)
                    },
                    digest: reveal_digest(&payload, &salt),
                    reveal_after_height: self.height + u64::from(step.flags % 2),
                    reveal_before_height: self.height + 2 + u64::from(step.selector % 3),
                };
                (
                    creator_seed,
                    Action::CreateCommitment(create),
                    Some(Pending::Commitment {
                        creator_seed,
                        payload,
                        salt,
                    }),
                )
            }
            StepKind::RevealCommitment => {
                let fallback = CommitmentFixture {
                    commitment_id: CommitmentId::derive(&trace_bytes(index, step.selector, 0x51)),
                    creator_seed: 8,
                    payload: bounded(b"missing-payload"),
                    salt: bounded(b"missing-salt"),
                };
                let commitment = choose(&self.commitments, step.selector, fallback);
                (
                    commitment.creator_seed,
                    Action::RevealCommitment(RevealCommitment {
                        commitment_id: commitment.commitment_id,
                        payload: commitment.payload,
                        salt: commitment.salt,
                    }),
                    None,
                )
            }
            StepKind::CreateChallenge => {
                let target = if step.flags & 1 == 0 {
                    ChallengeTarget::Claim(job.claim_id)
                } else {
                    ChallengeTarget::Attestation(choose(
                        &self.attestations,
                        step.selector,
                        AttestationId::derive(&trace_bytes(index, step.selector, 0x61)),
                    ))
                };
                (
                    12 + u64::from(step.selector % 3),
                    Action::CreateChallenge(CreateChallenge {
                        target,
                        counterclaim: bounded(&trace_bytes(index, step.flags, 0x62)),
                        evidence_ids: BoundedVec::default(),
                    }),
                    Some(Pending::Challenge),
                )
            }
            StepKind::ResolveClaim => (
                2,
                Action::ResolveClaim(ResolveClaim {
                    job_id: job.job_id,
                    claim_id: job.claim_id,
                    verdict: resolution_verdict(step.flags),
                    evidence_ids: BoundedVec::default(),
                    resolution_reference: content(digest(index, step.selector, 0x71)),
                }),
                None,
            ),
            StepKind::ResolveChallenge => (
                2,
                Action::ResolveChallenge(ResolveChallenge {
                    challenge_id: choose(
                        &self.challenges,
                        step.selector,
                        ChallengeId::derive(&trace_bytes(index, step.selector, 0x72)),
                    ),
                    upheld: step.flags & 1 != 0,
                    evidence_ids: BoundedVec::default(),
                    resolution_reference: content(digest(index, step.flags, 0x73)),
                }),
                None,
            ),
            StepKind::CloseJob => (1, Action::CloseJob(CloseJob::new(job.job_id)), None),
            StepKind::EpochChange => unreachable!("epoch steps have no signed action"),
        };
        let private = private(seed);
        let nonce = expected_nonce(&self.state, &ActorId::from(private.public_key()));
        let signed = SignedAction::sign(
            &private,
            ProtocolVersion::V1,
            CHAIN,
            nonce,
            u64::MAX,
            payload,
        )
        .unwrap();
        (signed, pending)
    }

    fn record_success(&mut self, pending: Option<Pending>, output: &ExecutionOutput) {
        let Some(pending) = pending else { return };
        let events = output.receipts[0].events.as_slice();
        match pending {
            Pending::Job => {
                let mut job_id = None;
                let mut claim_id = None;
                for event in events {
                    match event {
                        rachet_core::events::CanonicalEvent::JobCreated { job_id: id } => {
                            job_id = Some(*id)
                        }
                        rachet_core::events::CanonicalEvent::ClaimCreated {
                            claim_id: id, ..
                        } => claim_id = Some(*id),
                        _ => {}
                    }
                }
                self.jobs.push(JobFixture {
                    job_id: job_id.expect("successful job creation emits its job"),
                    claim_id: claim_id.expect("successful job creation emits its claim"),
                });
            }
            Pending::Evidence => {
                let rachet_core::events::CanonicalEvent::EvidenceRegistered { evidence_id } =
                    events[0]
                else {
                    panic!("successful evidence registration emits its ID")
                };
                self.evidence.push(evidence_id);
            }
            Pending::Attestation => {
                let rachet_core::events::CanonicalEvent::AttestationSubmitted { attestation_id } =
                    events[0]
                else {
                    panic!("successful attestation emits its ID")
                };
                self.attestations.push(attestation_id);
            }
            Pending::Commitment {
                creator_seed,
                payload,
                salt,
            } => {
                let rachet_core::events::CanonicalEvent::CommitmentCreated { commitment_id } =
                    events[0]
                else {
                    panic!("successful commitment creation emits its ID")
                };
                self.commitments.push(CommitmentFixture {
                    commitment_id,
                    creator_seed,
                    payload,
                    salt,
                });
            }
            Pending::Challenge => {
                let rachet_core::events::CanonicalEvent::ChallengeCreated { challenge_id } =
                    events[0]
                else {
                    panic!("successful challenge creation emits its ID")
                };
                self.challenges.push(challenge_id);
            }
        }
    }
}

enum Pending {
    Job,
    Evidence,
    Attestation,
    Commitment {
        creator_seed: u64,
        payload: BoundedBytes<MAX_COMMITMENT_PAYLOAD_BYTES>,
        salt: BoundedBytes<MAX_COMMITMENT_SALT_BYTES>,
    },
    Challenge,
}

fn create_job(index: usize, step: Step, height: u64) -> CreateJob {
    CreateJob {
        artifact: GitArtifact::new(
            bounded(b"https://git.invalid/minifuzz"),
            GitHash::sha1([0x19; 20]),
            GitHash::sha256(trace_digest(index, step.selector, 0x11)),
            content(digest(index, step.flags, 0x12)),
        ),
        claims: BoundedVec::new(vec![ClaimDefinition::new(bounded(&trace_bytes(
            index,
            step.selector,
            0x13,
        )))])
        .unwrap(),
        resolution_policy: ResolutionPolicy::ExperimentAuthority {
            authority: ActorId::from(private(2).public_key()),
        },
        validation_opens_at: height,
        validation_closes_at: height + 3,
        reveal_closes_at: Some(height + 6),
        challenge_closes_at: Some(height + 12),
        supersedes: None,
        metadata: bounded(&trace_bytes(index, step.flags, 0x14)),
    }
}

fn plan(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<Step>> {
    let length = MIN_STEPS + usize::from(u.arbitrary::<u8>()?) % (MAX_STEPS - MIN_STEPS + 1);
    let mut sampled = Vec::with_capacity(length);
    for _ in 0..length {
        sampled.push((
            u.arbitrary::<u8>()?,
            u.arbitrary::<u8>()?,
            u.arbitrary::<u8>()?,
        ));
    }

    let mut required = StepKind::ALL;
    for index in (1..StepKind::COUNT).rev() {
        required.swap(index, usize::from(sampled[index].0) % (index + 1));
    }
    Ok(sampled
        .into_iter()
        .enumerate()
        .map(|(index, (selector, flags, kind))| Step {
            kind: if index < StepKind::COUNT {
                required[index]
            } else {
                StepKind::ALL[usize::from(kind) % StepKind::COUNT]
            },
            selector,
            flags,
        })
        .collect())
}

fn run_sequence(steps: &[Step]) -> Result<RunSnapshot, String> {
    let mut scenario = Scenario::new();
    let mut outcomes = Vec::with_capacity(steps.len());
    for (index, step) in steps.iter().copied().enumerate() {
        outcomes.push(scenario.execute(step, index)?);
    }
    Ok(RunSnapshot {
        entries: scenario.state.entries(),
        outcomes,
    })
}

fn deterministic_run(steps: &[Step]) -> Result<(), String> {
    let first = run_sequence(steps)?;
    let second = run_sequence(steps)?;
    if first == second {
        Ok(())
    } else {
        Err("identical transition traces produced different outcomes or state".to_owned())
    }
}

fn failure(steps: &[Step]) -> Option<String> {
    match catch_unwind(AssertUnwindSafe(|| deterministic_run(steps))) {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(payload) => Some(panic_message(payload.as_ref())),
    }
}

fn shrink_failure(mut steps: Vec<Step>) -> (Vec<Step>, String) {
    let mut error = failure(&steps).expect("shrinking starts from a failing trace");
    let mut index = 0;
    while index < steps.len() {
        let mut candidate = steps.clone();
        candidate.remove(index);
        if let Some(candidate_error) = failure(&candidate) {
            steps = candidate;
            error = candidate_error;
        } else {
            index += 1;
        }
    }
    (steps, error)
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|message| (*message).to_owned())
        })
        .unwrap_or_else(|| "non-string panic".to_owned())
}

fn private(seed: u64) -> ed25519::PrivateKey {
    ed25519::PrivateKey::from_seed(seed)
}

fn expected_nonce(state: &dyn StateBatch, actor: &ActorId) -> u64 {
    state
        .get(&StateKey::account(actor))
        .map(|value| u64::from_be_bytes(value.as_ref().try_into().unwrap()))
        .unwrap_or(0)
}

fn choose<T: Clone>(values: &[T], selector: u8, fallback: T) -> T {
    if values.is_empty() || selector.is_multiple_of(4) {
        fallback
    } else {
        values[usize::from(selector) % values.len()].clone()
    }
}

fn choose_optional<T: Copy>(values: &[T], selector: u8) -> Option<T> {
    (!values.is_empty() && selector & 1 == 0).then(|| values[usize::from(selector) % values.len()])
}

fn bounded<const MAX: usize>(bytes: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(bytes).unwrap()
}

fn content(digest: Sha256Digest) -> ContentRef {
    ContentRef::new(
        digest,
        bounded(b"cas://minifuzz"),
        bounded(b"application/json"),
    )
}

fn digest(index: usize, sampled: u8, domain: u8) -> Sha256Digest {
    Sha256Digest::from(trace_digest(index, sampled, domain))
}

fn trace_digest(index: usize, sampled: u8, domain: u8) -> [u8; 32] {
    let mut bytes = [domain; 32];
    bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
    bytes[8] = sampled;
    bytes
}

fn trace_bytes(index: usize, sampled: u8, domain: u8) -> Vec<u8> {
    let mut bytes = vec![domain, sampled];
    bytes.extend_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
    bytes
}

fn verdict(value: u8) -> Verdict {
    match value % 4 {
        0 => Verdict::Pass,
        1 => Verdict::Fail,
        2 => Verdict::Abstain,
        _ => Verdict::Indeterminate,
    }
}

fn resolution_verdict(value: u8) -> ResolutionVerdict {
    match value % 3 {
        0 => ResolutionVerdict::Pass,
        1 => ResolutionVerdict::Fail,
        _ => ResolutionVerdict::Unresolved,
    }
}

#[test]
fn bounded_canonical_transition_sequences_preserve_all_invariants() {
    let builder = minifuzz::Builder::default()
        .with_search_limit(SMOKE_CASES)
        .with_min_iterations(SMOKE_CASES);
    let builder = match std::env::var("MINIFUZZ_BRANCH") {
        Ok(branch) => builder.with_reproduce(&branch),
        Err(_) => builder.with_seed(FUZZ_SEED),
    };
    builder.test(|u| {
        let steps = plan(u)?;
        if let Some(error) = failure(&steps) {
            let (minimal, minimal_error) = shrink_failure(steps.clone());
            panic!(
                "canonical transition minifuzz failed\nconfigured_seed=0x{FUZZ_SEED:016x}\noriginal_sequence={steps:#?}\nshrunk_sequence={minimal:#?}\nfailure={error}\nshrunk_failure={minimal_error}"
            );
        }
        Ok(())
    });
}
