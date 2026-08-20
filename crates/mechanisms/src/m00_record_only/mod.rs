//! M00 record-only control mechanism.
//!
//! M00 consumes the complete mechanism interface while deliberately producing
//! no economic state. Its empty own namespace is an invariant, making it the
//! null economy against which stateful mechanisms are compared.

use rachet_core::{
    actions::{Action, SignedAction},
    bounded::BoundedVec,
    events::CanonicalEvent,
    mechanisms::{
        CanonicalMechanismConfig, Mechanism, MechanismError, MechanismExportId, MechanismId,
        MechanismInvariantError, MechanismManifest, MechanismMutation, MechanismReadView,
        MechanismStatus, MechanismVersion,
    },
    state::MechanismNamespace,
};

/// Checked-in M00 output vectors covering every canonical event and epoch edges.
pub const M00_CONFORMANCE_TOML: &str = include_str!("../../../../conformance/m00_record_only.toml");

/// M00 has exactly one canonical configuration: an empty byte sequence.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct M00Config;

impl M00Config {
    /// Decodes and validates the canonical M00 configuration.
    pub fn decode(config: &[u8]) -> Result<Self, MechanismError> {
        if config.is_empty() {
            Ok(Self)
        } else {
            Err(MechanismError::new(
                "M00_CONFIG_NONEMPTY",
                format!(
                    "M00 canonical config must be empty, received {} bytes",
                    config.len()
                ),
            ))
        }
    }

    /// Returns the sole canonical representation of this configuration.
    pub const fn as_bytes(self) -> &'static [u8] {
        &[]
    }

    /// Returns the bounded configuration committed by genesis.
    pub fn canonical(self) -> CanonicalMechanismConfig {
        CanonicalMechanismConfig::empty()
    }
}

impl TryFrom<&[u8]> for M00Config {
    type Error = MechanismError;

    fn try_from(config: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(config)
    }
}

/// Section 27's record-only economy.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct M00RecordOnly {
    config: M00Config,
}

impl M00RecordOnly {
    pub const VERSION: MechanismVersion = MechanismVersion::V1_0_0;
    pub const STATE_NAMESPACE: MechanismNamespace = MechanismNamespace::new(0);

    pub const fn new(config: M00Config) -> Self {
        Self { config }
    }

    pub const fn config(self) -> M00Config {
        self.config
    }
}

impl Mechanism for M00RecordOnly {
    fn manifest(&self) -> MechanismManifest {
        MechanismManifest {
            id: MechanismId::M00,
            version: Self::VERSION,
            status: MechanismStatus::Implemented,
            requires: BoundedVec::default(),
            reads_exports: BoundedVec::<MechanismExportId, 32>::default(),
            state_namespace: Self::STATE_NAMESPACE,
            config_digest: self.config.canonical().digest(),
        }
    }

    fn validate_config(&self, config: &[u8]) -> Result<(), MechanismError> {
        M00Config::decode(config).map(|_| ())
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
        view: &MechanismReadView<'_>,
    ) -> Result<(), MechanismInvariantError> {
        let entries = view.own_entries();
        if entries.is_empty() {
            Ok(())
        } else {
            Err(MechanismInvariantError::new(
                "M00_STATE_NOT_EMPTY",
                format!("M00 economic state contains {} entries", entries.len()),
            ))
        }
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
        actions::{CloseJob, ResolutionVerdict},
        mechanisms::{
            MechanismExports, MechanismRegistryError, MechanismSelection, MechanismSetConfig,
            mechanism_state_key,
        },
        primitives::{
            AttestationId, ChainId, ChallengeId, ClaimId, CommitmentId, EvidenceId, JobId,
            ProtocolVersion,
        },
        state::{InMemoryStateBatch, StateBatch, StateKey},
    };
    use std::fmt::Write as _;

    fn selection(config: CanonicalMechanismConfig) -> MechanismSelection {
        MechanismSelection::new(MechanismId::M00, MechanismVersion::V1_0_0, config)
    }

    fn registry() -> CompiledMechanismRegistry {
        let config =
            MechanismSetConfig::new(ProtocolVersion::V1, vec![selection(M00Config.canonical())])
                .unwrap();
        CompiledMechanismRegistry::compile(
            &config,
            vec![MechanismInstance::m00(M00RecordOnly::default()).unwrap()],
        )
        .unwrap()
    }

    struct M00Outputs;

    fn event_vectors() -> Vec<(&'static str, CanonicalEvent)> {
        let job_id = JobId::derive(b"m00-job");
        let claim_id = ClaimId::derive(b"m00-claim");
        let evidence_id = EvidenceId::derive(b"m00-evidence");
        let attestation_id = AttestationId::derive(b"m00-attestation");
        let commitment_id = CommitmentId::derive(b"m00-commitment");
        let challenge_id = ChallengeId::derive(b"m00-challenge");

        vec![
            ("job-created", CanonicalEvent::JobCreated { job_id }),
            (
                "claim-created",
                CanonicalEvent::ClaimCreated { job_id, claim_id },
            ),
            (
                "evidence-registered",
                CanonicalEvent::EvidenceRegistered { evidence_id },
            ),
            (
                "attestation-submitted",
                CanonicalEvent::AttestationSubmitted { attestation_id },
            ),
            (
                "commitment-created",
                CanonicalEvent::CommitmentCreated { commitment_id },
            ),
            (
                "commitment-revealed",
                CanonicalEvent::CommitmentRevealed { commitment_id },
            ),
            (
                "commitment-expired",
                CanonicalEvent::CommitmentExpired { commitment_id },
            ),
            (
                "challenge-created",
                CanonicalEvent::ChallengeCreated { challenge_id },
            ),
            (
                "claim-resolved-pass",
                CanonicalEvent::ClaimResolved {
                    claim_id,
                    verdict: ResolutionVerdict::Pass,
                },
            ),
            (
                "claim-resolved-fail",
                CanonicalEvent::ClaimResolved {
                    claim_id,
                    verdict: ResolutionVerdict::Fail,
                },
            ),
            (
                "claim-resolved-unresolved",
                CanonicalEvent::ClaimResolved {
                    claim_id,
                    verdict: ResolutionVerdict::Unresolved,
                },
            ),
            ("claim-reopened", CanonicalEvent::ClaimReopened { claim_id }),
            (
                "challenge-resolved-upheld",
                CanonicalEvent::ChallengeResolved {
                    challenge_id,
                    upheld: true,
                },
            ),
            (
                "challenge-resolved-rejected",
                CanonicalEvent::ChallengeResolved {
                    challenge_id,
                    upheld: false,
                },
            ),
            ("job-resolved", CanonicalEvent::JobResolved { job_id }),
            ("job-closed", CanonicalEvent::JobClosed { job_id }),
            (
                "epoch-changed",
                CanonicalEvent::EpochChanged {
                    previous: 6,
                    current: 7,
                },
            ),
        ]
    }

    impl Conformance for M00Outputs {
        async fn commit(_seed: u64) -> Vec<u8> {
            let registry = registry();
            let exports = MechanismExports::empty();
            let mut state = InMemoryStateBatch::new();
            let mut output = M00RecordOnly::default().manifest().encode().to_vec();

            for (_, event) in event_vectors() {
                registry.on_event(&mut state, &exports, &event).unwrap();
                output.extend_from_slice(state.root().as_ref());
            }
            for epoch in [0, 1, u64::MAX] {
                registry.on_epoch(&mut state, &exports, epoch).unwrap();
                output.extend_from_slice(state.root().as_ref());
            }
            output
        }
    }

    commonware_conformance::conformance_tests! {
        M00Outputs => 1,
    }

    #[test]
    fn config_and_manifest_are_exact_and_nonempty_config_is_rejected() {
        assert_eq!(M00Config::decode(&[]), Ok(M00Config));
        assert_eq!(M00Config.as_bytes(), &[]);

        let mechanism = M00RecordOnly::new(M00Config);
        let error = mechanism.validate_config(&[0]).unwrap_err();
        assert_eq!(error.code(), "M00_CONFIG_NONEMPTY");
        assert_eq!(
            error.message(),
            "M00 canonical config must be empty, received 1 bytes"
        );

        let manifest = mechanism.manifest();
        assert_eq!(manifest.id, MechanismId::M00);
        assert_eq!(manifest.version, MechanismVersion::V1_0_0);
        assert_eq!(manifest.status, MechanismStatus::Implemented);
        assert!(manifest.requires.is_empty());
        assert!(manifest.reads_exports.is_empty());
        assert_eq!(manifest.state_namespace, MechanismNamespace::new(0));
        assert_eq!(
            manifest.config_digest.as_ref(),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn pre_action_accepts_without_mutating_canonical_state() {
        let registry = registry();
        let action = SignedAction::sign(
            &ed25519::PrivateKey::from_seed(26),
            ProtocolVersion::V1,
            ChainId::new([0x26; 32]),
            0,
            100,
            Action::CloseJob(CloseJob::new(JobId::derive(b"m00-pre-action"))),
        )
        .unwrap();
        let mut state = InMemoryStateBatch::new();
        state.put(
            StateKey::protocol_epoch(),
            9_u64.to_be_bytes().as_slice().into(),
        );
        let before = state.entries();
        let before_root = state.root();

        registry
            .pre_action(&state, &MechanismExports::empty(), &action)
            .unwrap();

        assert_eq!(state.entries(), before);
        assert_eq!(state.root(), before_root);
    }

    #[test]
    fn every_event_and_epoch_produces_no_economic_state_or_mutations() {
        let registry = registry();
        let exports = MechanismExports::empty();
        let mut state = InMemoryStateBatch::new();
        let empty_root = state.root();

        for (_, event) in event_vectors() {
            registry.on_event(&mut state, &exports, &event).unwrap();
            assert!(state.entries().is_empty());
            assert_eq!(state.root(), empty_root);
        }
        for epoch in [0, 1, u64::MAX] {
            registry.on_epoch(&mut state, &exports, epoch).unwrap();
            assert!(state.entries().is_empty());
            assert_eq!(state.root(), empty_root);
        }
        registry.check_invariants(&state, &exports).unwrap();
    }

    #[test]
    fn nonempty_m00_namespace_violates_the_null_economy_invariant() {
        let registry = registry();
        let mut state = InMemoryStateBatch::new();
        state.put(
            mechanism_state_key(
                M00RecordOnly::STATE_NAMESPACE,
                M00RecordOnly::VERSION,
                b"unexpected",
            ),
            b"economic-state".as_slice().into(),
        );

        let error = registry
            .check_invariants(&state, &MechanismExports::empty())
            .unwrap_err();
        assert_eq!(error.code(), "MECHANISM_INVARIANT_FAILED");
        let MechanismRegistryError::Invariant { error, .. } = error else {
            panic!("expected M00 invariant failure")
        };
        assert_eq!(error.code(), "M00_STATE_NOT_EMPTY");
        assert_eq!(error.message(), "M00 economic state contains 1 entries");
    }

    #[test]
    fn checked_in_conformance_output_is_locked() {
        let registry = registry();
        let exports = MechanismExports::empty();
        let mut state = InMemoryStateBatch::new();
        let mut actual = String::from(
            "schema_version = 1\nmechanism_id = \"M00\"\nversion = \"1.0.0\"\ncanonical_config_hex = \"\"\nconfig_sha256 = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\neconomic_state_entries = 0\n",
        );

        for (name, event) in event_vectors() {
            registry.on_event(&mut state, &exports, &event).unwrap();
            writeln!(actual, "\n[[event]]\nname = \"{name}\"\nmutation_count = 0").unwrap();
            assert!(state.entries().is_empty());
        }
        for epoch in [0, 1, u64::MAX] {
            registry.on_epoch(&mut state, &exports, epoch).unwrap();
            writeln!(
                actual,
                "\n[[epoch]]\nepoch = \"{epoch}\"\nmutation_count = 0"
            )
            .unwrap();
            assert!(state.entries().is_empty());
        }

        assert_eq!(actual, M00_CONFORMANCE_TOML);
    }
}
