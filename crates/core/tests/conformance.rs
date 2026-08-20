//! Checked-in protocol conformance hashes.
//!
//! Each marker commits all variants in one public consensus-object family. The
//! `commonware_conformance` harness hashes deterministic seeds and compares the
//! result with `crates/core/conformance.toml`.

use commonware_codec::Encode as _;
use commonware_conformance::Conformance;
use commonware_cryptography::{Signer as _, ed25519};
use rachet_core::{
    actions::{
        Action, ChallengeTarget, ClaimDefinition, CloseJob, CommitmentSubject, CreateChallenge,
        CreateCommitment, CreateJob, RegisterEvidence, ResolutionPolicy, ResolutionVerdict,
        ResolveChallenge, ResolveClaim, RevealCommitment, SignedAction, SubmitAttestation, Verdict,
    },
    artifacts::{ContentRef, GitArtifact, GitHash},
    blocks::BlockHeader,
    bounded::{BoundedBytes, BoundedVec},
    events::{ActionReceipt, CanonicalEvent},
    limits::{
        MAX_CLAIM_STATEMENT_BYTES, MAX_COMMITMENT_PAYLOAD_BYTES, MAX_COMMITMENT_SALT_BYTES,
        MAX_CONTENT_LOCATOR_HINT_BYTES, MAX_COUNTERCLAIM_BYTES, MAX_MEDIA_TYPE_BYTES,
        MAX_METADATA_BYTES, MAX_REPOSITORY_LOCATOR_BYTES,
    },
    mechanisms::{
        CanonicalMechanismConfig, GenesisConfig, GenesisProtocolConfig, MechanismId,
        MechanismSelection, MechanismSetConfig, MechanismVersion,
    },
    primitives::{
        ActionId, ActorId, AttestationId, ChainId, ChallengeId, ClaimId, CommitmentId, EvidenceId,
        JobId, MechanismSetId, ProtocolVersion, Sha256Digest,
    },
    state::{MechanismNamespace, StateKey},
};

const CASES: usize = 32;

struct CanonicalActions;
struct BlockHeaders;
struct CanonicalEvents;
struct ActionReceipts;
struct StateKeys;
struct GenesisConfiguration;
struct MechanismSetIdentity;

fn bounded<const MAX: usize>(bytes: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(bytes).expect("conformance fixture is bounded")
}

fn fixture_bytes(seed: u64, tag: u8) -> [u8; 32] {
    let mut bytes = [tag; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    bytes
}

fn digest(seed: u64, tag: u8) -> Sha256Digest {
    Sha256Digest::from(fixture_bytes(seed, tag))
}

fn actor(seed: u64) -> ActorId {
    ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
}

fn content(seed: u64, tag: u8) -> ContentRef {
    let locator = [b"cas://vector/".as_slice(), &seed.to_be_bytes(), &[tag]].concat();
    ContentRef::new(
        digest(seed, tag),
        bounded::<MAX_CONTENT_LOCATOR_HINT_BYTES>(&locator),
        bounded::<MAX_MEDIA_TYPE_BYTES>(b"application/rachet-vector"),
    )
}

fn frame(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(
        &u64::try_from(bytes.len())
            .expect("fixture length fits u64")
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
}

fn frame_encoded<T: commonware_codec::Encode>(output: &mut Vec<u8>, value: &T) {
    frame(output, value.encode().as_ref());
}

fn ids(
    seed: u64,
) -> (
    JobId,
    ClaimId,
    EvidenceId,
    AttestationId,
    CommitmentId,
    ChallengeId,
) {
    (
        JobId::from_digest(digest(seed, 0x10)),
        ClaimId::from_digest(digest(seed, 0x11)),
        EvidenceId::from_digest(digest(seed, 0x12)),
        AttestationId::from_digest(digest(seed, 0x13)),
        CommitmentId::from_digest(digest(seed, 0x14)),
        ChallengeId::from_digest(digest(seed, 0x15)),
    )
}

fn action_payloads(seed: u64) -> Vec<Action> {
    let (job_id, claim_id, evidence_id, attestation_id, commitment_id, challenge_id) = ids(seed);
    let resolution_policy = if seed.is_multiple_of(2) {
        ResolutionPolicy::ExperimentAuthority {
            authority: actor(seed.wrapping_add(100)),
        }
    } else {
        ResolutionPolicy::DeterministicVerifier {
            verifier_id: digest(seed, 0x40),
            verifier_spec: content(seed, 0x41),
        }
    };
    let create_job = CreateJob {
        artifact: GitArtifact::new(
            bounded::<MAX_REPOSITORY_LOCATOR_BYTES>(b"https://git.invalid/conformance.git"),
            GitHash::sha1([0x21; 20]),
            GitHash::sha256(fixture_bytes(seed, 0x22)),
            content(seed, 0x23),
        ),
        claims: BoundedVec::new(vec![
            ClaimDefinition::new(bounded::<MAX_CLAIM_STATEMENT_BYTES>(b"tests pass")),
            ClaimDefinition::new(bounded::<MAX_CLAIM_STATEMENT_BYTES>(b"codec is canonical")),
        ])
        .expect("fixture claim count is bounded"),
        resolution_policy,
        validation_opens_at: seed,
        validation_closes_at: seed.saturating_add(10),
        reveal_closes_at: seed.is_multiple_of(2).then_some(seed.saturating_add(11)),
        challenge_closes_at: Some(seed.saturating_add(12)),
        supersedes: (!seed.is_multiple_of(2)).then_some(JobId::derive(b"superseded")),
        metadata: bounded::<MAX_METADATA_BYTES>(&seed.to_be_bytes()),
    };
    let evidence_ids =
        || BoundedVec::new(vec![evidence_id]).expect("fixture evidence count is bounded");

    vec![
        Action::CreateJob(Box::new(create_job)),
        Action::RegisterEvidence(RegisterEvidence {
            job_id,
            claim_id: seed.is_multiple_of(2).then_some(claim_id),
            evidence: content(seed, 0x24),
            manifest_digest: digest(seed, 0x25),
        }),
        Action::SubmitAttestation(SubmitAttestation {
            job_id,
            claim_id,
            verdict: match seed % 4 {
                0 => Verdict::Pass,
                1 => Verdict::Fail,
                2 => Verdict::Abstain,
                _ => Verdict::Indeterminate,
            },
            confidence_basis_points: u16::try_from(seed % 10_001).expect("bounded by modulo"),
            evidence_ids: evidence_ids(),
        }),
        Action::CreateCommitment(CreateCommitment {
            subject: if seed.is_multiple_of(2) {
                CommitmentSubject::Job(job_id)
            } else {
                CommitmentSubject::Claim(claim_id)
            },
            digest: digest(seed, 0x26),
            reveal_after_height: seed,
            reveal_before_height: seed.saturating_add(5),
        }),
        Action::RevealCommitment(RevealCommitment {
            commitment_id,
            payload: bounded::<MAX_COMMITMENT_PAYLOAD_BYTES>(&seed.to_be_bytes()),
            salt: bounded::<MAX_COMMITMENT_SALT_BYTES>(&[0x27, seed as u8]),
        }),
        Action::CreateChallenge(CreateChallenge {
            target: if seed.is_multiple_of(2) {
                ChallengeTarget::Claim(claim_id)
            } else {
                ChallengeTarget::Attestation(attestation_id)
            },
            counterclaim: bounded::<MAX_COUNTERCLAIM_BYTES>(b"counterexample"),
            evidence_ids: evidence_ids(),
        }),
        Action::ResolveClaim(ResolveClaim {
            job_id,
            claim_id,
            verdict: match seed % 3 {
                0 => ResolutionVerdict::Pass,
                1 => ResolutionVerdict::Fail,
                _ => ResolutionVerdict::Unresolved,
            },
            evidence_ids: evidence_ids(),
            resolution_reference: content(seed, 0x28),
        }),
        Action::ResolveChallenge(ResolveChallenge {
            challenge_id,
            upheld: seed.is_multiple_of(2),
            evidence_ids: evidence_ids(),
            resolution_reference: content(seed, 0x29),
        }),
        Action::CloseJob(CloseJob::new(job_id)),
    ]
}

impl Conformance for CanonicalActions {
    async fn commit(seed: u64) -> Vec<u8> {
        let chain_id = ChainId::new(fixture_bytes(seed, 0x31));
        let key = ed25519::PrivateKey::from_seed(seed.wrapping_add(1));
        let mut output = Vec::new();
        for (index, payload) in action_payloads(seed).into_iter().enumerate() {
            let action = SignedAction::sign(
                &key,
                ProtocolVersion::V1,
                chain_id,
                u64::try_from(index).expect("fixture index fits u64"),
                seed.saturating_add(1_000),
                payload,
            )
            .expect("fixture action is valid");
            frame_encoded(&mut output, &action);
            frame(&mut output, action.action_id().as_ref());
        }
        output
    }
}

impl Conformance for BlockHeaders {
    async fn commit(seed: u64) -> Vec<u8> {
        let header = BlockHeader {
            protocol_version: ProtocolVersion::V1,
            chain_id: ChainId::new(fixture_bytes(seed, 0x50)),
            height: seed,
            epoch: seed / 100,
            parent_block: digest(seed, 0x51),
            parent_state_root: digest(seed, 0x52),
            action_root: digest(seed, 0x53),
            receipt_root: digest(seed, 0x54),
            post_state_root: digest(seed, 0x55),
            mechanism_set_id: MechanismSetId::from_digest(digest(seed, 0x56)),
            timestamp_ms: 1_725_000_000_000_u64.saturating_add(seed),
        };
        header.encode().to_vec()
    }
}

fn events(seed: u64) -> Vec<CanonicalEvent> {
    let (job_id, claim_id, evidence_id, attestation_id, commitment_id, challenge_id) = ids(seed);
    vec![
        CanonicalEvent::JobCreated { job_id },
        CanonicalEvent::ClaimCreated { job_id, claim_id },
        CanonicalEvent::EvidenceRegistered { evidence_id },
        CanonicalEvent::AttestationSubmitted { attestation_id },
        CanonicalEvent::CommitmentCreated { commitment_id },
        CanonicalEvent::CommitmentRevealed { commitment_id },
        CanonicalEvent::CommitmentExpired { commitment_id },
        CanonicalEvent::ChallengeCreated { challenge_id },
        CanonicalEvent::ClaimResolved {
            claim_id,
            verdict: match seed % 3 {
                0 => ResolutionVerdict::Pass,
                1 => ResolutionVerdict::Fail,
                _ => ResolutionVerdict::Unresolved,
            },
        },
        CanonicalEvent::ClaimReopened { claim_id },
        CanonicalEvent::ChallengeResolved {
            challenge_id,
            upheld: seed.is_multiple_of(2),
        },
        CanonicalEvent::JobResolved { job_id },
        CanonicalEvent::JobClosed { job_id },
        CanonicalEvent::EpochChanged {
            previous: seed,
            current: seed.saturating_add(1),
        },
    ]
}

impl Conformance for CanonicalEvents {
    async fn commit(seed: u64) -> Vec<u8> {
        let mut output = Vec::new();
        for event in events(seed) {
            frame_encoded(&mut output, &event);
        }
        output
    }
}

impl Conformance for ActionReceipts {
    async fn commit(seed: u64) -> Vec<u8> {
        ActionReceipt::new(
            ActionId::from_digest(digest(seed, 0x60)),
            actor(seed.wrapping_add(2)),
            seed,
            events(seed),
        )
        .expect("all canonical event variants fit one receipt")
        .encode()
        .to_vec()
    }
}

impl Conformance for StateKeys {
    async fn commit(seed: u64) -> Vec<u8> {
        let actor = actor(seed.wrapping_add(3));
        let (job, claim, evidence, attestation, commitment, challenge) = ids(seed);
        let keys = [
            StateKey::account(&actor),
            StateKey::job(&job),
            StateKey::claim(&claim),
            StateKey::evidence(&evidence),
            StateKey::attestation(&attestation),
            StateKey::commitment(&commitment),
            StateKey::challenge(&challenge),
            StateKey::job_by_customer(&actor, &job),
            StateKey::attestation_by_operator(&actor, &attestation),
            StateKey::claim_by_job(&job, &claim),
            StateKey::mechanism(MechanismNamespace::new(seed as u16), &seed.to_be_bytes()),
            StateKey::protocol_config(),
            StateKey::protocol_epoch(),
        ];
        let mut output = Vec::new();
        for key in keys {
            frame(&mut output, key.as_ref());
        }
        output
    }
}

fn mechanism_selections() -> Vec<MechanismSelection> {
    vec![
        MechanismSelection::new(
            MechanismId::M00,
            MechanismVersion::V1_0_0,
            CanonicalMechanismConfig::empty(),
        ),
        MechanismSelection::new(
            MechanismId::M01,
            MechanismVersion::V1_0_0,
            CanonicalMechanismConfig::empty(),
        ),
    ]
}

impl Conformance for GenesisConfiguration {
    async fn commit(_seed: u64) -> Vec<u8> {
        let genesis = GenesisConfig::new(GenesisProtocolConfig::V1, mechanism_selections())
            .expect("v1 genesis fixture is valid");
        let mut output = Vec::new();
        frame_encoded(&mut output, &GenesisProtocolConfig::V1);
        frame_encoded(&mut output, genesis.mechanism_set());
        frame_encoded(&mut output, &genesis);
        output
    }
}

impl Conformance for MechanismSetIdentity {
    async fn commit(_seed: u64) -> Vec<u8> {
        let mechanism_set = MechanismSetConfig::new(ProtocolVersion::V1, mechanism_selections())
            .expect("v1 mechanism set fixture is valid");
        let mut output = mechanism_set.encode().to_vec();
        output.extend_from_slice(mechanism_set.id().as_ref());
        output
    }
}

commonware_conformance::conformance_tests! {
    CanonicalActions => CASES,
    BlockHeaders => CASES,
    CanonicalEvents => CASES,
    ActionReceipts => CASES,
    StateKeys => CASES,
    GenesisConfiguration => 1,
    MechanismSetIdentity => 1,
}
