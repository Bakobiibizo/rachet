//! Genesis-committed v1 protocol limits.

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt as _, Write};
use core::fmt;

/// Maximum repository locator length.
pub const MAX_REPOSITORY_LOCATOR_BYTES: usize = 512;
/// Maximum informational content locator length.
pub const MAX_CONTENT_LOCATOR_HINT_BYTES: usize = 512;
/// Maximum content media-type length.
pub const MAX_MEDIA_TYPE_BYTES: usize = 128;
/// Maximum canonical claim statement length.
pub const MAX_CLAIM_STATEMENT_BYTES: usize = 4 * 1024;
/// Maximum challenge counterclaim length.
pub const MAX_COUNTERCLAIM_BYTES: usize = 4 * 1024;
/// Maximum job metadata length.
pub const MAX_METADATA_BYTES: usize = 8 * 1024;
/// Maximum canonical encoded action length.
pub const MAX_ACTION_BYTES: usize = 64 * 1024;
/// Maximum evidence manifest reference length.
pub const MAX_EVIDENCE_MANIFEST_REF_BYTES: usize = 2 * 1024;
/// Maximum commitment reveal payload length.
pub const MAX_COMMITMENT_PAYLOAD_BYTES: usize = 65_536;
/// Maximum commitment reveal salt length.
pub const MAX_COMMITMENT_SALT_BYTES: usize = 128;
/// Maximum evidence references carried by one action.
pub const MAX_EVIDENCE_IDS_PER_ACTION: usize = 64;
/// Maximum actions carried by one block.
pub const MAX_ACTIONS_PER_BLOCK: usize = 1_024;
/// Maximum canonical encoded block body length.
pub const MAX_BLOCK_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum claims created by one job.
pub const MAX_CLAIMS_PER_JOB: usize = 128;
/// Maximum attestations retained for one claim.
pub const MAX_ATTESTATIONS_PER_CLAIM: usize = 1_024;
/// Maximum simultaneously open challenges for one claim.
pub const MAX_OPEN_CHALLENGES_PER_CLAIM: usize = 256;
/// Maximum core events emitted by one action.
///
/// `CreateJob` is the largest event producer: one job event plus one event for
/// each of the 128 claims allowed in the job.
pub const MAX_EVENTS_PER_ACTION: usize = MAX_CLAIMS_PER_JOB + 1;

/// Raw values supplied by a genesis configuration.
///
/// Values are fixed-width `u32`s so their canonical representation is
/// architecture independent. Construct [`ProtocolLimits`] to validate them
/// against the limits implemented by this binary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtocolLimitsConfig {
    pub repository_locator_bytes: u32,
    pub content_locator_hint_bytes: u32,
    pub media_type_bytes: u32,
    pub claim_statement_bytes: u32,
    pub counterclaim_bytes: u32,
    pub metadata_bytes: u32,
    pub action_bytes: u32,
    pub evidence_manifest_ref_bytes: u32,
    pub commitment_payload_bytes: u32,
    pub commitment_salt_bytes: u32,
    pub evidence_ids_per_action: u32,
    pub actions_per_block: u32,
    pub block_body_bytes: u32,
    pub claims_per_job: u32,
    pub attestations_per_claim: u32,
    pub open_challenges_per_claim: u32,
    pub events_per_action: u32,
}

impl ProtocolLimitsConfig {
    const FIELD_COUNT: usize = 17;

    /// The initial v1 values required by the protocol specification.
    pub const V1: Self = Self {
        repository_locator_bytes: 512,
        content_locator_hint_bytes: 512,
        media_type_bytes: 128,
        claim_statement_bytes: 4_096,
        counterclaim_bytes: 4_096,
        metadata_bytes: 8_192,
        action_bytes: 65_536,
        evidence_manifest_ref_bytes: 2_048,
        commitment_payload_bytes: 65_536,
        commitment_salt_bytes: 128,
        evidence_ids_per_action: 64,
        actions_per_block: 1_024,
        block_body_bytes: 4_194_304,
        claims_per_job: 128,
        attestations_per_claim: 1_024,
        open_challenges_per_claim: 256,
        events_per_action: 129,
    };
}

/// Validated limits committed by a chain's genesis configuration.
///
/// A genesis may select stricter positive values than the v1 defaults. It may
/// not advertise a value above the implementation maximum, which would make
/// peers disagree about values that this binary can decode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct ProtocolLimits(ProtocolLimitsConfig);

impl ProtocolLimits {
    /// The initial v1 genesis limits.
    pub const V1: Self = Self(ProtocolLimitsConfig::V1);

    /// Validates limits loaded from genesis.
    pub fn new(config: ProtocolLimitsConfig) -> Result<Self, ProtocolLimitsError> {
        let fields = [
            (
                "repository_locator_bytes",
                config.repository_locator_bytes,
                MAX_REPOSITORY_LOCATOR_BYTES,
            ),
            (
                "content_locator_hint_bytes",
                config.content_locator_hint_bytes,
                MAX_CONTENT_LOCATOR_HINT_BYTES,
            ),
            (
                "media_type_bytes",
                config.media_type_bytes,
                MAX_MEDIA_TYPE_BYTES,
            ),
            (
                "claim_statement_bytes",
                config.claim_statement_bytes,
                MAX_CLAIM_STATEMENT_BYTES,
            ),
            (
                "counterclaim_bytes",
                config.counterclaim_bytes,
                MAX_COUNTERCLAIM_BYTES,
            ),
            ("metadata_bytes", config.metadata_bytes, MAX_METADATA_BYTES),
            ("action_bytes", config.action_bytes, MAX_ACTION_BYTES),
            (
                "evidence_manifest_ref_bytes",
                config.evidence_manifest_ref_bytes,
                MAX_EVIDENCE_MANIFEST_REF_BYTES,
            ),
            (
                "commitment_payload_bytes",
                config.commitment_payload_bytes,
                MAX_COMMITMENT_PAYLOAD_BYTES,
            ),
            (
                "commitment_salt_bytes",
                config.commitment_salt_bytes,
                MAX_COMMITMENT_SALT_BYTES,
            ),
            (
                "evidence_ids_per_action",
                config.evidence_ids_per_action,
                MAX_EVIDENCE_IDS_PER_ACTION,
            ),
            (
                "actions_per_block",
                config.actions_per_block,
                MAX_ACTIONS_PER_BLOCK,
            ),
            (
                "block_body_bytes",
                config.block_body_bytes,
                MAX_BLOCK_BODY_BYTES,
            ),
            ("claims_per_job", config.claims_per_job, MAX_CLAIMS_PER_JOB),
            (
                "attestations_per_claim",
                config.attestations_per_claim,
                MAX_ATTESTATIONS_PER_CLAIM,
            ),
            (
                "open_challenges_per_claim",
                config.open_challenges_per_claim,
                MAX_OPEN_CHALLENGES_PER_CLAIM,
            ),
            (
                "events_per_action",
                config.events_per_action,
                MAX_EVENTS_PER_ACTION,
            ),
        ];

        for (field, value, maximum) in fields {
            let maximum = u32::try_from(maximum).expect("v1 limits fit the wire format");
            if value == 0 || value > maximum {
                return Err(ProtocolLimitsError {
                    field,
                    value,
                    maximum,
                });
            }
        }
        Ok(Self(config))
    }

    /// Returns the validated raw genesis values.
    pub const fn config(self) -> ProtocolLimitsConfig {
        self.0
    }
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self::V1
    }
}

impl TryFrom<ProtocolLimitsConfig> for ProtocolLimits {
    type Error = ProtocolLimitsError;

    fn try_from(config: ProtocolLimitsConfig) -> Result<Self, Self::Error> {
        Self::new(config)
    }
}

/// A genesis limit was zero or exceeded the implementation maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLimitsError {
    field: &'static str,
    value: u32,
    maximum: u32,
}

impl ProtocolLimitsError {
    /// Returns the invalid field name.
    pub const fn field(self) -> &'static str {
        self.field
    }

    /// Returns the rejected value.
    pub const fn value(self) -> u32 {
        self.value
    }

    /// Returns the implementation maximum.
    pub const fn maximum(self) -> u32 {
        self.maximum
    }
}

impl fmt::Display for ProtocolLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "genesis limit {}={} must be in 1..={}",
            self.field, self.value, self.maximum
        )
    }
}

impl std::error::Error for ProtocolLimitsError {}

impl Write for ProtocolLimits {
    fn write(&self, buf: &mut impl BufMut) {
        let config = self.0;
        config.repository_locator_bytes.write(buf);
        config.content_locator_hint_bytes.write(buf);
        config.media_type_bytes.write(buf);
        config.claim_statement_bytes.write(buf);
        config.counterclaim_bytes.write(buf);
        config.metadata_bytes.write(buf);
        config.action_bytes.write(buf);
        config.evidence_manifest_ref_bytes.write(buf);
        config.commitment_payload_bytes.write(buf);
        config.commitment_salt_bytes.write(buf);
        config.evidence_ids_per_action.write(buf);
        config.actions_per_block.write(buf);
        config.block_body_bytes.write(buf);
        config.claims_per_job.write(buf);
        config.attestations_per_claim.write(buf);
        config.open_challenges_per_claim.write(buf);
        config.events_per_action.write(buf);
    }
}

impl FixedSize for ProtocolLimits {
    const SIZE: usize = ProtocolLimitsConfig::FIELD_COUNT * core::mem::size_of::<u32>();
}

impl Read for ProtocolLimits {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let config = ProtocolLimitsConfig {
            repository_locator_bytes: u32::read(buf)?,
            content_locator_hint_bytes: u32::read(buf)?,
            media_type_bytes: u32::read(buf)?,
            claim_statement_bytes: u32::read(buf)?,
            counterclaim_bytes: u32::read(buf)?,
            metadata_bytes: u32::read(buf)?,
            action_bytes: u32::read(buf)?,
            evidence_manifest_ref_bytes: u32::read(buf)?,
            commitment_payload_bytes: u32::read(buf)?,
            commitment_salt_bytes: u32::read(buf)?,
            evidence_ids_per_action: u32::read(buf)?,
            actions_per_block: u32::read(buf)?,
            block_body_bytes: u32::read(buf)?,
            claims_per_job: u32::read(buf)?,
            attestations_per_claim: u32::read(buf)?,
            open_challenges_per_claim: u32::read(buf)?,
            events_per_action: u32::read(buf)?,
        };
        Self::new(config).map_err(|error| CodecError::Wrapped("ProtocolLimits", Box::new(error)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};

    #[test]
    fn v1_limits_cover_every_specified_variable_length_surface() {
        let config = ProtocolLimits::V1.config();
        assert_eq!(
            config,
            ProtocolLimitsConfig {
                repository_locator_bytes: 512,
                content_locator_hint_bytes: 512,
                media_type_bytes: 128,
                claim_statement_bytes: 4_096,
                counterclaim_bytes: 4_096,
                metadata_bytes: 8_192,
                action_bytes: 65_536,
                evidence_manifest_ref_bytes: 2_048,
                commitment_payload_bytes: 65_536,
                commitment_salt_bytes: 128,
                evidence_ids_per_action: 64,
                actions_per_block: 1_024,
                block_body_bytes: 4_194_304,
                claims_per_job: 128,
                attestations_per_claim: 1_024,
                open_challenges_per_claim: 256,
                events_per_action: 129,
            }
        );
    }

    #[test]
    fn genesis_limit_encoding_is_fixed_width_and_stable() {
        let expected = [
            0x00, 0x00, 0x02, 0x00, // repository locator
            0x00, 0x00, 0x02, 0x00, // content locator hint
            0x00, 0x00, 0x00, 0x80, // media type
            0x00, 0x00, 0x10, 0x00, // claim statement
            0x00, 0x00, 0x10, 0x00, // counterclaim
            0x00, 0x00, 0x20, 0x00, // metadata
            0x00, 0x01, 0x00, 0x00, // action
            0x00, 0x00, 0x08, 0x00, // evidence manifest reference
            0x00, 0x01, 0x00, 0x00, // commitment payload
            0x00, 0x00, 0x00, 0x80, // commitment salt
            0x00, 0x00, 0x00, 0x40, // evidence ids per action
            0x00, 0x00, 0x04, 0x00, // actions per block
            0x00, 0x40, 0x00, 0x00, // block body
            0x00, 0x00, 0x00, 0x80, // claims per job
            0x00, 0x00, 0x04, 0x00, // attestations per claim
            0x00, 0x00, 0x01, 0x00, // open challenges per claim
            0x00, 0x00, 0x00, 0x81, // events per action
        ];
        let encoded = ProtocolLimits::V1.encode();
        assert_eq!(encoded.as_ref(), expected);
        assert_eq!(encoded.len(), ProtocolLimits::SIZE);
        assert_eq!(
            ProtocolLimits::decode_cfg(encoded, &()).unwrap(),
            ProtocolLimits::V1
        );
    }

    #[test]
    fn stricter_genesis_limits_are_valid_but_zero_and_oversized_are_not() {
        let mut config = ProtocolLimitsConfig::V1;
        config.repository_locator_bytes = 511;
        let limits = ProtocolLimits::new(config).expect("stricter genesis is supported");
        assert_eq!(limits.config().repository_locator_bytes, 511);

        config.repository_locator_bytes = 0;
        let error = ProtocolLimits::new(config).expect_err("zero is not a usable maximum");
        assert_eq!(error.field(), "repository_locator_bytes");
        assert_eq!(error.value(), 0);
        assert_eq!(error.maximum(), 512);

        config.repository_locator_bytes = 513;
        let error = ProtocolLimits::new(config).expect_err("implementation maximum is fixed");
        assert_eq!(error.value(), 513);
        assert_eq!(error.maximum(), 512);
    }

    #[test]
    fn malformed_genesis_limit_encodings_are_rejected() {
        let mut zero = ProtocolLimits::V1.encode().to_vec();
        zero[..4].copy_from_slice(&0_u32.to_be_bytes());
        assert!(matches!(
            ProtocolLimits::decode_cfg(zero.as_slice(), &()),
            Err(CodecError::Wrapped("ProtocolLimits", _))
        ));

        let mut oversized = ProtocolLimits::V1.encode().to_vec();
        oversized[..4].copy_from_slice(&513_u32.to_be_bytes());
        assert!(matches!(
            ProtocolLimits::decode_cfg(oversized.as_slice(), &()),
            Err(CodecError::Wrapped("ProtocolLimits", _))
        ));

        let mut truncated = ProtocolLimits::V1.encode().to_vec();
        truncated.pop();
        assert!(matches!(
            ProtocolLimits::decode_cfg(truncated.as_slice(), &()),
            Err(CodecError::EndOfBuffer)
        ));

        let mut trailing = ProtocolLimits::V1.encode().to_vec();
        trailing.push(0);
        assert!(matches!(
            ProtocolLimits::decode_cfg(trailing.as_slice(), &()),
            Err(CodecError::ExtraData(1))
        ));
    }
}
