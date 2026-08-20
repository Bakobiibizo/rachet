//! M01 naive-reputation mechanism.
//!
//! M01 records only cumulative validation correctness. It intentionally has no
//! stake, standing, maturity, weighting, transfer, payout, or consensus effect.

use commonware_codec::Decode as _;
use rachet_core::{
    actions::{Action, ResolutionPolicy, ResolutionVerdict, SignedAction, Verdict},
    bounded::BoundedVec,
    events::CanonicalEvent,
    mechanisms::{
        CanonicalMechanismConfig, Mechanism, MechanismError, MechanismExportId, MechanismId,
        MechanismInvariantError, MechanismManifest, MechanismMutation, MechanismReadView,
        MechanismStatus, MechanismVersion, mechanism_state_key,
    },
    numeric::checked_add,
    primitives::ActorId,
    state::{
        AttestationRecord, ClaimRecord, ClaimStatus, JobRecord, MechanismNamespace, StateKey,
        StateNamespace, StateValue,
    },
};
use std::collections::BTreeMap;

/// Checked-in M01 vectors for every attestation/resolution verdict combination.
pub const M01_CONFORMANCE_TOML: &str =
    include_str!("../../../../conformance/m01_naive_reputation.toml");

const REPUTATION_KEY_TAG: u8 = 0;
const REPUTATION_ENCODED_LEN: usize = 5 * 8;

/// M01 has one fixed configuration: matching `+1`, contradicting `-1`, and all
/// non-directional outcomes `0`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct M01Config;

impl M01Config {
    /// Decodes the sole canonical M01 configuration.
    pub fn decode(config: &[u8]) -> Result<Self, MechanismError> {
        if config.is_empty() {
            Ok(Self)
        } else {
            Err(MechanismError::new(
                "M01_CONFIG_NONEMPTY",
                format!(
                    "M01 deltas are fixed and canonical config must be empty, received {} bytes",
                    config.len()
                ),
            ))
        }
    }

    /// Returns the sole canonical representation of M01's fixed deltas.
    pub const fn as_bytes(self) -> &'static [u8] {
        &[]
    }

    /// Returns the bounded configuration committed at genesis.
    pub fn canonical(self) -> CanonicalMechanismConfig {
        CanonicalMechanismConfig::empty()
    }
}

impl TryFrom<&[u8]> for M01Config {
    type Error = MechanismError;

    fn try_from(config: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(config)
    }
}

/// One validation operator's cumulative M01 history.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct NaiveReputation {
    pub score: i64,
    pub correct: u64,
    pub incorrect: u64,
    pub abstained: u64,
    pub unresolved: u64,
}

impl NaiveReputation {
    /// Decodes the exact fixed-width M01 state representation.
    pub fn decode(bytes: &[u8]) -> Result<Self, MechanismError> {
        if bytes.len() != REPUTATION_ENCODED_LEN {
            return Err(MechanismError::new(
                "M01_REPUTATION_MALFORMED",
                format!(
                    "M01 reputation must be {REPUTATION_ENCODED_LEN} bytes, received {}",
                    bytes.len()
                ),
            ));
        }

        Ok(Self {
            score: i64::from_be_bytes(bytes[0..8].try_into().expect("length checked")),
            correct: u64::from_be_bytes(bytes[8..16].try_into().expect("length checked")),
            incorrect: u64::from_be_bytes(bytes[16..24].try_into().expect("length checked")),
            abstained: u64::from_be_bytes(bytes[24..32].try_into().expect("length checked")),
            unresolved: u64::from_be_bytes(bytes[32..40].try_into().expect("length checked")),
        })
    }

    /// Encodes signed score followed by the four counters as big-endian
    /// fixed-width integers.
    pub fn encode(self) -> StateValue {
        let mut bytes = Vec::with_capacity(REPUTATION_ENCODED_LEN);
        bytes.extend_from_slice(&self.score.to_be_bytes());
        bytes.extend_from_slice(&self.correct.to_be_bytes());
        bytes.extend_from_slice(&self.incorrect.to_be_bytes());
        bytes.extend_from_slice(&self.abstained.to_be_bytes());
        bytes.extend_from_slice(&self.unresolved.to_be_bytes());
        bytes.into_boxed_slice()
    }

    fn evaluate(
        &mut self,
        verdict: Verdict,
        resolution: ResolutionVerdict,
    ) -> Result<(), MechanismError> {
        match resolution {
            ResolutionVerdict::Unresolved => {
                self.unresolved = checked_counter(self.unresolved, "unresolved")?;
            }
            ResolutionVerdict::Pass | ResolutionVerdict::Fail => match verdict {
                Verdict::Abstain | Verdict::Indeterminate => {
                    self.abstained = checked_counter(self.abstained, "abstained")?;
                }
                Verdict::Pass | Verdict::Fail if verdict_matches(verdict, resolution) => {
                    self.score = checked_add(self.score, 1_i64).map_err(|_| {
                        MechanismError::new(
                            "M01_SCORE_OVERFLOW",
                            "M01 matching-verdict score increment overflowed i64",
                        )
                    })?;
                    self.correct = checked_counter(self.correct, "correct")?;
                }
                Verdict::Pass | Verdict::Fail => {
                    self.score = checked_add(self.score, -1_i64).map_err(|_| {
                        MechanismError::new(
                            "M01_SCORE_OVERFLOW",
                            "M01 contradicting-verdict score decrement overflowed i64",
                        )
                    })?;
                    self.incorrect = checked_counter(self.incorrect, "incorrect")?;
                }
            },
        }
        Ok(())
    }

    fn has_consistent_score(self) -> bool {
        i128::from(self.score) == i128::from(self.correct) - i128::from(self.incorrect)
    }
}

fn checked_counter(value: u64, name: &'static str) -> Result<u64, MechanismError> {
    checked_add(value, 1_u64).map_err(|_| {
        MechanismError::new(
            "M01_COUNTER_OVERFLOW",
            format!("M01 {name} counter increment overflowed u64"),
        )
    })
}

const fn verdict_matches(verdict: Verdict, resolution: ResolutionVerdict) -> bool {
    matches!(
        (verdict, resolution),
        (Verdict::Pass, ResolutionVerdict::Pass) | (Verdict::Fail, ResolutionVerdict::Fail)
    )
}

/// Section 28's deliberately weak cumulative-correctness mechanism.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct M01NaiveReputation {
    config: M01Config,
}

impl M01NaiveReputation {
    pub const VERSION: MechanismVersion = MechanismVersion::V1_0_0;
    pub const STATE_NAMESPACE: MechanismNamespace = MechanismNamespace::new(1);

    pub const fn new(config: M01Config) -> Self {
        Self { config }
    }

    pub const fn config(self) -> M01Config {
        self.config
    }

    /// Returns the isolated state key for one operator's non-transferable score.
    pub fn reputation_state_key(operator: &ActorId) -> StateKey {
        let mut local_key = Vec::with_capacity(1 + operator.as_ref().len());
        local_key.push(REPUTATION_KEY_TAG);
        local_key.extend_from_slice(operator.as_ref());
        mechanism_state_key(Self::STATE_NAMESPACE, Self::VERSION, &local_key)
    }

    /// Identifies an exact M01 v1 reputation key in retained economic state.
    #[must_use]
    pub fn is_reputation_state_key(key: &StateKey) -> bool {
        let prefix =
            mechanism_state_key(Self::STATE_NAMESPACE, Self::VERSION, &[REPUTATION_KEY_TAG]);
        key.as_bytes().len() == prefix.as_bytes().len() + 32
            && key.as_bytes().starts_with(prefix.as_bytes())
    }

    fn local_reputation_key(operator: &ActorId) -> Vec<u8> {
        let mut local_key = Vec::with_capacity(1 + operator.as_ref().len());
        local_key.push(REPUTATION_KEY_TAG);
        local_key.extend_from_slice(operator.as_ref());
        local_key
    }

    fn authorized_resolution(
        view: &MechanismReadView<'_>,
        claim_id: &rachet_core::primitives::ClaimId,
        verdict: ResolutionVerdict,
    ) -> Result<(ClaimRecord, JobRecord), MechanismError> {
        let claim_value = view
            .canonical(&StateKey::claim(claim_id))?
            .ok_or_else(|| unauthorized_resolution("claim is absent"))?;
        let claim = ClaimRecord::decode_cfg(claim_value.as_ref(), &())
            .map_err(|_| unauthorized_resolution("claim state is malformed"))?;
        let ClaimStatus::Resolved(resolution) = &claim.status else {
            return Err(unauthorized_resolution("claim is not resolved"));
        };
        if resolution.verdict != verdict {
            return Err(unauthorized_resolution(
                "event verdict does not match stored authority resolution",
            ));
        }

        let job_value = view
            .canonical(&StateKey::job(&claim.job_id))?
            .ok_or_else(|| unauthorized_resolution("resolution job is absent"))?;
        let job = JobRecord::decode_cfg(job_value.as_ref(), &())
            .map_err(|_| unauthorized_resolution("resolution job state is malformed"))?;
        if job.job_id() != claim.job_id || !job.claim_ids.iter().any(|id| id == claim_id) {
            return Err(unauthorized_resolution(
                "claim is not a member of its resolution job",
            ));
        }
        if !matches!(
            job.resolution_policy,
            ResolutionPolicy::ExperimentAuthority { .. }
        ) {
            return Err(unauthorized_resolution(
                "resolution policy is not an active experiment authority",
            ));
        }
        Ok((claim, job))
    }

    fn resolution_authorities(
        view: &MechanismReadView<'_>,
    ) -> Result<Vec<ActorId>, MechanismError> {
        let mut authorities = Vec::new();
        for (key, value) in view.canonical_entries() {
            if key.namespace() != StateNamespace::Job {
                continue;
            }
            let job = JobRecord::decode_cfg(value.as_ref(), &()).map_err(|_| {
                MechanismError::new("M01_CANONICAL_STATE_MALFORMED", "job state is malformed")
            })?;
            if StateKey::job(&job.job_id()) != key {
                return Err(MechanismError::new(
                    "M01_CANONICAL_STATE_MALFORMED",
                    "job state key does not match its canonical identity",
                ));
            }
            if let ResolutionPolicy::ExperimentAuthority { authority } = job.resolution_policy {
                authorities.push(authority);
            }
        }
        Ok(authorities)
    }
}

fn unauthorized_resolution(reason: &'static str) -> MechanismError {
    MechanismError::new(
        "M01_RESOLUTION_NOT_AUTHORIZED",
        format!("M01 ignored a non-authoritative resolution event: {reason}"),
    )
}

impl Mechanism for M01NaiveReputation {
    fn manifest(&self) -> MechanismManifest {
        MechanismManifest {
            id: MechanismId::M01,
            version: Self::VERSION,
            status: MechanismStatus::Implemented,
            requires: BoundedVec::default(),
            reads_exports: BoundedVec::<MechanismExportId, 32>::default(),
            state_namespace: Self::STATE_NAMESPACE,
            config_digest: self.config.canonical().digest(),
        }
    }

    fn validate_config(&self, config: &[u8]) -> Result<(), MechanismError> {
        M01Config::decode(config).map(|_| ())
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
        event: &CanonicalEvent,
    ) -> Result<Vec<MechanismMutation>, MechanismError> {
        let CanonicalEvent::ClaimResolved { claim_id, verdict } = event else {
            return Ok(Vec::new());
        };
        let (_claim, _job) = Self::authorized_resolution(view, claim_id, *verdict)?;
        let authorities = Self::resolution_authorities(view)?;
        let mut updates = BTreeMap::<ActorId, NaiveReputation>::new();

        for (key, value) in view.canonical_entries() {
            if key.namespace() != StateNamespace::Attestation {
                continue;
            }
            let attestation = AttestationRecord::decode_cfg(value.as_ref(), &()).map_err(|_| {
                MechanismError::new(
                    "M01_CANONICAL_STATE_MALFORMED",
                    "attestation state is malformed",
                )
            })?;
            if StateKey::attestation(&attestation.attestation_id()) != key {
                return Err(MechanismError::new(
                    "M01_CANONICAL_STATE_MALFORMED",
                    "attestation state key does not match its canonical identity",
                ));
            }
            if attestation.claim_id != *claim_id {
                continue;
            }
            if authorities
                .iter()
                .any(|authority| authority == &attestation.operator)
            {
                continue;
            }

            let mut reputation = match updates.get(&attestation.operator).copied() {
                Some(reputation) => reputation,
                None => {
                    let local_key = Self::local_reputation_key(&attestation.operator);
                    match view.own(&local_key) {
                        Some(bytes) => NaiveReputation::decode(bytes.as_ref())?,
                        None => NaiveReputation::default(),
                    }
                }
            };
            reputation.evaluate(attestation.verdict, *verdict)?;
            updates.insert(attestation.operator, reputation);
        }

        Ok(updates
            .into_iter()
            .map(|(operator, reputation)| {
                MechanismMutation::put(
                    view.own_key(&Self::local_reputation_key(&operator)),
                    reputation.encode(),
                )
            })
            .collect())
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
        view: &MechanismReadView<'_>,
    ) -> Result<(), MechanismInvariantError> {
        let authorities = Self::resolution_authorities(view).map_err(|error| {
            MechanismInvariantError::new(error.code(), error.message().to_owned())
        })?;
        for (key, value) in view.own_entries() {
            if key.len() != 33 || key.first().copied() != Some(REPUTATION_KEY_TAG) {
                return Err(MechanismInvariantError::new(
                    "M01_STATE_KEY_MALFORMED",
                    "M01 state contains a key other than an operator reputation key",
                ));
            }
            if authorities
                .iter()
                .any(|authority| authority.as_ref() == &key[1..])
            {
                return Err(MechanismInvariantError::new(
                    "M01_AUTHORITY_REPUTATION",
                    "a resolution authority cannot hold validation reputation",
                ));
            }
            let reputation = NaiveReputation::decode(value.as_ref()).map_err(|error| {
                MechanismInvariantError::new(error.code(), error.message().to_owned())
            })?;
            if !reputation.has_consistent_score() {
                return Err(MechanismInvariantError::new(
                    "M01_SCORE_INCONSISTENT",
                    "M01 score does not equal correct minus incorrect",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{CompiledMechanismRegistry, MechanismInstance};
    use commonware_codec::Encode as _;
    use commonware_conformance::Conformance;
    use commonware_cryptography::{Signer as _, ed25519};
    use rachet_core::{
        actions::{ClaimDefinition, CloseJob, CreateJob, ResolveClaim, SubmitAttestation},
        artifacts::{ContentRef, GitArtifact, GitHash},
        bounded::BoundedBytes,
        mechanisms::{MechanismExports, MechanismSelection, MechanismSetConfig},
        primitives::{ChainId, ClaimId, JobId, ProtocolVersion, Sha256Digest},
        state::{InMemoryStateBatch, StateBatch},
        transition::{ChallengeResolutionError, create_job, resolve_claim, submit_attestation},
    };
    use std::fmt::Write as _;

    struct M01Updates;

    fn actor(seed: u64) -> ActorId {
        ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
    }

    fn bounded<const MAX: usize>(value: &[u8]) -> BoundedBytes<MAX> {
        BoundedBytes::try_from(value).unwrap()
    }

    fn content(byte: u8) -> ContentRef {
        ContentRef::new(
            Sha256Digest::from([byte; 32]),
            bounded(b"cas://m01"),
            bounded(b"application/json"),
        )
    }

    fn registry() -> CompiledMechanismRegistry {
        let config = MechanismSetConfig::new(
            ProtocolVersion::V1,
            vec![MechanismSelection::new(
                MechanismId::M01,
                MechanismVersion::V1_0_0,
                M01Config.canonical(),
            )],
        )
        .unwrap();
        CompiledMechanismRegistry::compile(
            &config,
            vec![MechanismInstance::m01(M01NaiveReputation::default()).unwrap()],
        )
        .unwrap()
    }

    fn create(candidate: u8, authority: ActorId) -> CreateJob {
        CreateJob {
            artifact: GitArtifact::new(
                bounded(b"https://git.invalid/m01"),
                GitHash::sha1([1; 20]),
                GitHash::sha256([candidate; 32]),
                content(2),
            ),
            claims: BoundedVec::new(vec![ClaimDefinition::new(bounded(b"claim"))]).unwrap(),
            resolution_policy: ResolutionPolicy::ExperimentAuthority { authority },
            validation_opens_at: 10,
            validation_closes_at: 20,
            reveal_closes_at: None,
            challenge_closes_at: Some(30),
            supersedes: None,
            metadata: bounded(b"fixture"),
        }
    }

    struct Fixture {
        state: InMemoryStateBatch,
        authority: ActorId,
        operator: ActorId,
        job_id: JobId,
        claim_id: ClaimId,
    }

    fn fixture(candidate: u8, verdict: Verdict) -> Fixture {
        let customer = actor(1_000 + u64::from(candidate));
        let authority = actor(2_000 + u64::from(candidate));
        let operator = actor(3_000 + u64::from(candidate));
        let mut state = InMemoryStateBatch::new();
        let created = create_job(
            &mut state,
            &customer,
            10,
            &create(candidate, authority.clone()),
        )
        .unwrap();
        let claim_id = created.claim_ids.as_slice()[0];
        submit_attestation(
            &mut state,
            &operator,
            10,
            &SubmitAttestation {
                job_id: created.job_id,
                claim_id,
                verdict,
                confidence_basis_points: 10_000,
                evidence_ids: BoundedVec::default(),
            },
        )
        .unwrap();
        Fixture {
            state,
            authority,
            operator,
            job_id: created.job_id,
            claim_id,
        }
    }

    fn resolution(fixture: &Fixture, verdict: ResolutionVerdict) -> ResolveClaim {
        ResolveClaim {
            job_id: fixture.job_id,
            claim_id: fixture.claim_id,
            verdict,
            evidence_ids: BoundedVec::default(),
            resolution_reference: content(9),
        }
    }

    fn evaluate(
        verdict: Verdict,
        resolution_verdict: ResolutionVerdict,
        candidate: u8,
    ) -> NaiveReputation {
        let mut fixture = fixture(candidate, verdict);
        let resolution = resolution(&fixture, resolution_verdict);
        resolve_claim(&mut fixture.state, &fixture.authority, 21, &resolution).unwrap();
        registry()
            .on_event(
                &mut fixture.state,
                &MechanismExports::empty(),
                &CanonicalEvent::ClaimResolved {
                    claim_id: fixture.claim_id,
                    verdict: resolution_verdict,
                },
            )
            .unwrap();
        let bytes = fixture
            .state
            .get(&M01NaiveReputation::reputation_state_key(&fixture.operator))
            .unwrap();
        NaiveReputation::decode(bytes.as_ref()).unwrap()
    }

    impl Conformance for M01Updates {
        async fn commit(seed: u64) -> Vec<u8> {
            let cases = [
                (Verdict::Pass, ResolutionVerdict::Pass),
                (Verdict::Fail, ResolutionVerdict::Pass),
                (Verdict::Abstain, ResolutionVerdict::Pass),
                (Verdict::Indeterminate, ResolutionVerdict::Pass),
                (Verdict::Pass, ResolutionVerdict::Fail),
                (Verdict::Fail, ResolutionVerdict::Fail),
                (Verdict::Abstain, ResolutionVerdict::Fail),
                (Verdict::Indeterminate, ResolutionVerdict::Fail),
                (Verdict::Pass, ResolutionVerdict::Unresolved),
                (Verdict::Fail, ResolutionVerdict::Unresolved),
                (Verdict::Abstain, ResolutionVerdict::Unresolved),
                (Verdict::Indeterminate, ResolutionVerdict::Unresolved),
            ];
            let mut output = M01NaiveReputation::default().manifest().encode().to_vec();
            for (index, (verdict, resolution)) in cases.into_iter().enumerate() {
                let candidate = u8::try_from((seed * 12 + index as u64) % 200 + 1).unwrap();
                let operator = actor(3_000 + u64::from(candidate));
                let key = M01NaiveReputation::reputation_state_key(&operator);
                let reputation = evaluate(verdict, resolution, candidate).encode();
                for bytes in [key.as_ref(), reputation.as_ref()] {
                    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
                    output.extend_from_slice(bytes);
                }
            }
            output
        }
    }

    commonware_conformance::conformance_tests! {
        M01Updates => 16,
    }

    #[test]
    fn reputation_key_recognition_is_version_and_shape_exact() {
        let operator = actor(901);
        let key = M01NaiveReputation::reputation_state_key(&operator);
        assert!(M01NaiveReputation::is_reputation_state_key(&key));
        assert!(!M01NaiveReputation::is_reputation_state_key(
            &StateKey::mechanism(M01NaiveReputation::STATE_NAMESPACE, b"short")
        ));
        assert!(!M01NaiveReputation::is_reputation_state_key(
            &StateKey::account(&operator)
        ));
    }

    #[test]
    fn config_manifest_and_fixed_state_codec_are_exact() {
        assert_eq!(M01Config::decode(&[]), Ok(M01Config));
        assert_eq!(M01Config.as_bytes(), &[]);
        assert_eq!(
            M01Config::decode(&[1]).unwrap_err().code(),
            "M01_CONFIG_NONEMPTY"
        );

        let manifest = M01NaiveReputation::default().manifest();
        assert_eq!(manifest.id, MechanismId::M01);
        assert_eq!(manifest.version, MechanismVersion::V1_0_0);
        assert_eq!(manifest.status, MechanismStatus::Implemented);
        assert!(manifest.requires.is_empty());
        assert!(manifest.reads_exports.is_empty());
        assert_eq!(manifest.state_namespace, MechanismNamespace::new(1));
        assert_eq!(
            manifest.config_digest.as_ref(),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );

        let reputation = NaiveReputation {
            score: -7,
            correct: 11,
            incorrect: 18,
            abstained: 3,
            unresolved: 4,
        };
        assert_eq!(
            NaiveReputation::decode(reputation.encode().as_ref()).unwrap(),
            reputation
        );
        assert_eq!(
            NaiveReputation::decode(&[]).unwrap_err().code(),
            "M01_REPUTATION_MALFORMED"
        );
    }

    #[test]
    fn every_verdict_resolution_combination_has_the_section_28_result() {
        let cases = [
            (
                Verdict::Pass,
                ResolutionVerdict::Pass,
                NaiveReputation {
                    score: 1,
                    correct: 1,
                    ..NaiveReputation::default()
                },
            ),
            (
                Verdict::Fail,
                ResolutionVerdict::Pass,
                NaiveReputation {
                    score: -1,
                    incorrect: 1,
                    ..NaiveReputation::default()
                },
            ),
            (
                Verdict::Abstain,
                ResolutionVerdict::Pass,
                NaiveReputation {
                    abstained: 1,
                    ..NaiveReputation::default()
                },
            ),
            (
                Verdict::Indeterminate,
                ResolutionVerdict::Pass,
                NaiveReputation {
                    abstained: 1,
                    ..NaiveReputation::default()
                },
            ),
            (
                Verdict::Pass,
                ResolutionVerdict::Fail,
                NaiveReputation {
                    score: -1,
                    incorrect: 1,
                    ..NaiveReputation::default()
                },
            ),
            (
                Verdict::Fail,
                ResolutionVerdict::Fail,
                NaiveReputation {
                    score: 1,
                    correct: 1,
                    ..NaiveReputation::default()
                },
            ),
            (
                Verdict::Abstain,
                ResolutionVerdict::Fail,
                NaiveReputation {
                    abstained: 1,
                    ..NaiveReputation::default()
                },
            ),
            (
                Verdict::Indeterminate,
                ResolutionVerdict::Fail,
                NaiveReputation {
                    abstained: 1,
                    ..NaiveReputation::default()
                },
            ),
            (
                Verdict::Pass,
                ResolutionVerdict::Unresolved,
                NaiveReputation {
                    unresolved: 1,
                    ..NaiveReputation::default()
                },
            ),
            (
                Verdict::Fail,
                ResolutionVerdict::Unresolved,
                NaiveReputation {
                    unresolved: 1,
                    ..NaiveReputation::default()
                },
            ),
            (
                Verdict::Abstain,
                ResolutionVerdict::Unresolved,
                NaiveReputation {
                    unresolved: 1,
                    ..NaiveReputation::default()
                },
            ),
            (
                Verdict::Indeterminate,
                ResolutionVerdict::Unresolved,
                NaiveReputation {
                    unresolved: 1,
                    ..NaiveReputation::default()
                },
            ),
        ];

        for (index, (verdict, resolution, expected)) in cases.into_iter().enumerate() {
            assert_eq!(
                evaluate(verdict, resolution, u8::try_from(index + 1).unwrap()),
                expected,
                "{verdict:?} against {resolution:?}"
            );
        }
    }

    #[test]
    fn multiple_attestations_by_one_operator_accumulate_without_key_collisions() {
        let mut fixture = fixture(19, Verdict::Pass);
        submit_attestation(
            &mut fixture.state,
            &fixture.operator,
            11,
            &SubmitAttestation {
                job_id: fixture.job_id,
                claim_id: fixture.claim_id,
                verdict: Verdict::Fail,
                confidence_basis_points: 5_000,
                evidence_ids: BoundedVec::default(),
            },
        )
        .unwrap();
        let resolution = resolution(&fixture, ResolutionVerdict::Pass);
        resolve_claim(&mut fixture.state, &fixture.authority, 21, &resolution).unwrap();
        registry()
            .on_event(
                &mut fixture.state,
                &MechanismExports::empty(),
                &CanonicalEvent::ClaimResolved {
                    claim_id: fixture.claim_id,
                    verdict: ResolutionVerdict::Pass,
                },
            )
            .unwrap();

        let bytes = fixture
            .state
            .get(&M01NaiveReputation::reputation_state_key(&fixture.operator))
            .unwrap();
        assert_eq!(
            NaiveReputation::decode(bytes.as_ref()).unwrap(),
            NaiveReputation {
                score: 0,
                correct: 1,
                incorrect: 1,
                abstained: 0,
                unresolved: 0,
            }
        );
    }

    #[test]
    fn only_stored_authority_resolutions_update_and_authorities_never_earn() {
        let registry = registry();
        let exports = MechanismExports::empty();
        let mut fixture = fixture(20, Verdict::Pass);
        let resolution = resolution(&fixture, ResolutionVerdict::Pass);
        let before = fixture.state.root();
        assert_eq!(
            resolve_claim(&mut fixture.state, &actor(99), 21, &resolution),
            Err(ChallengeResolutionError::ResolutionUnauthorized)
        );
        assert_eq!(fixture.state.root(), before);

        let error = registry
            .on_event(
                &mut fixture.state,
                &exports,
                &CanonicalEvent::ClaimResolved {
                    claim_id: fixture.claim_id,
                    verdict: ResolutionVerdict::Pass,
                },
            )
            .unwrap_err();
        assert_eq!(error.code(), "MECHANISM_EXECUTION_FAILED");
        assert_eq!(fixture.state.root(), before);

        resolve_claim(&mut fixture.state, &fixture.authority, 21, &resolution).unwrap();
        registry
            .on_event(
                &mut fixture.state,
                &exports,
                &CanonicalEvent::ClaimResolved {
                    claim_id: fixture.claim_id,
                    verdict: ResolutionVerdict::Pass,
                },
            )
            .unwrap();
        assert!(
            fixture
                .state
                .get(&M01NaiveReputation::reputation_state_key(&fixture.operator))
                .is_some()
        );
        assert!(
            fixture
                .state
                .get(&M01NaiveReputation::reputation_state_key(
                    &fixture.authority
                ))
                .is_none()
        );
    }

    #[test]
    fn invariant_rejects_reputation_assigned_to_a_resolution_authority() {
        let mut fixture = fixture(22, Verdict::Pass);
        fixture.state.put(
            M01NaiveReputation::reputation_state_key(&fixture.authority),
            NaiveReputation::default().encode(),
        );

        let error = registry()
            .check_invariants(&fixture.state, &MechanismExports::empty())
            .unwrap_err();
        let rachet_core::mechanisms::MechanismRegistryError::Invariant { error, .. } = error else {
            panic!("expected mechanism invariant failure")
        };
        assert_eq!(error.code(), "M01_AUTHORITY_REPUTATION");
    }

    #[test]
    fn score_and_every_counter_reject_their_arithmetic_boundaries() {
        let mut maximum_score = NaiveReputation {
            score: i64::MAX,
            ..NaiveReputation::default()
        };
        assert_eq!(
            maximum_score
                .evaluate(Verdict::Pass, ResolutionVerdict::Pass)
                .unwrap_err()
                .code(),
            "M01_SCORE_OVERFLOW"
        );
        let mut minimum_score = NaiveReputation {
            score: i64::MIN,
            ..NaiveReputation::default()
        };
        assert_eq!(
            minimum_score
                .evaluate(Verdict::Pass, ResolutionVerdict::Fail)
                .unwrap_err()
                .code(),
            "M01_SCORE_OVERFLOW"
        );

        for (mut reputation, verdict, resolution) in [
            (
                NaiveReputation {
                    correct: u64::MAX,
                    ..NaiveReputation::default()
                },
                Verdict::Pass,
                ResolutionVerdict::Pass,
            ),
            (
                NaiveReputation {
                    incorrect: u64::MAX,
                    ..NaiveReputation::default()
                },
                Verdict::Pass,
                ResolutionVerdict::Fail,
            ),
            (
                NaiveReputation {
                    abstained: u64::MAX,
                    ..NaiveReputation::default()
                },
                Verdict::Abstain,
                ResolutionVerdict::Pass,
            ),
            (
                NaiveReputation {
                    unresolved: u64::MAX,
                    ..NaiveReputation::default()
                },
                Verdict::Pass,
                ResolutionVerdict::Unresolved,
            ),
        ] {
            assert_eq!(
                reputation.evaluate(verdict, resolution).unwrap_err().code(),
                "M01_COUNTER_OVERFLOW"
            );
        }
    }

    #[test]
    fn non_resolution_inputs_epochs_and_actions_cannot_move_reputation() {
        let registry = registry();
        let exports = MechanismExports::empty();
        let mut fixture = fixture(21, Verdict::Fail);
        let before = fixture.state.root();
        for event in [
            CanonicalEvent::JobCreated {
                job_id: fixture.job_id,
            },
            CanonicalEvent::AttestationSubmitted {
                attestation_id: rachet_core::primitives::AttestationId::derive(b"other"),
            },
            CanonicalEvent::ClaimReopened {
                claim_id: fixture.claim_id,
            },
            CanonicalEvent::EpochChanged {
                previous: 1,
                current: 2,
            },
        ] {
            registry
                .on_event(&mut fixture.state, &exports, &event)
                .unwrap();
        }
        registry
            .on_epoch(&mut fixture.state, &exports, u64::MAX)
            .unwrap();

        let action = SignedAction::sign(
            &ed25519::PrivateKey::from_seed(21),
            ProtocolVersion::V1,
            ChainId::new([21; 32]),
            0,
            100,
            Action::CloseJob(CloseJob::new(fixture.job_id)),
        )
        .unwrap();
        registry
            .pre_action(&fixture.state, &exports, &action)
            .unwrap();
        assert_eq!(fixture.state.root(), before);
        assert!(
            fixture
                .state
                .entries()
                .into_iter()
                .all(|(key, _)| key.namespace() != StateNamespace::Mechanism)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(output, "{byte:02x}").unwrap();
        }
        output
    }

    #[test]
    fn checked_in_conformance_output_is_locked() {
        let cases = [
            ("pass-pass", Verdict::Pass, ResolutionVerdict::Pass),
            ("fail-pass", Verdict::Fail, ResolutionVerdict::Pass),
            ("abstain-pass", Verdict::Abstain, ResolutionVerdict::Pass),
            (
                "indeterminate-pass",
                Verdict::Indeterminate,
                ResolutionVerdict::Pass,
            ),
            ("pass-fail", Verdict::Pass, ResolutionVerdict::Fail),
            ("fail-fail", Verdict::Fail, ResolutionVerdict::Fail),
            ("abstain-fail", Verdict::Abstain, ResolutionVerdict::Fail),
            (
                "indeterminate-fail",
                Verdict::Indeterminate,
                ResolutionVerdict::Fail,
            ),
            (
                "pass-unresolved",
                Verdict::Pass,
                ResolutionVerdict::Unresolved,
            ),
            (
                "fail-unresolved",
                Verdict::Fail,
                ResolutionVerdict::Unresolved,
            ),
            (
                "abstain-unresolved",
                Verdict::Abstain,
                ResolutionVerdict::Unresolved,
            ),
            (
                "indeterminate-unresolved",
                Verdict::Indeterminate,
                ResolutionVerdict::Unresolved,
            ),
        ];
        let mut actual = String::from(
            "schema_version = 1\nmechanism_id = \"M01\"\nversion = \"1.0.0\"\ncanonical_config_hex = \"\"\nconfig_sha256 = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n",
        );
        for (name, verdict, resolution) in cases {
            let mut reputation = NaiveReputation::default();
            reputation.evaluate(verdict, resolution).unwrap();
            writeln!(
                actual,
                "\n[[case]]\nname = \"{name}\"\nscore = {}\ncorrect = {}\nincorrect = {}\nabstained = {}\nunresolved = {}\nstate_hex = \"{}\"",
                reputation.score,
                reputation.correct,
                reputation.incorrect,
                reputation.abstained,
                reputation.unresolved,
                hex(reputation.encode().as_ref()),
            )
            .unwrap();
        }
        assert_eq!(actual, M01_CONFORMANCE_TOML);
    }
}
