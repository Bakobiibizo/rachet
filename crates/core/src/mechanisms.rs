//! Genesis-fixed mechanism manifests, configuration, identity, and execution.

mod runtime;

pub use runtime::{
    Mechanism, MechanismError, MechanismExportError, MechanismExportKey, MechanismExports,
    MechanismInvariantError, MechanismMutation, MechanismReadError, MechanismReadView,
    MechanismRegistry, MechanismRegistryError, MechanismSet, mechanism_state_key,
    validate_and_order_manifests,
};

use crate::{
    bounded::{BoundedBytes, BoundedVec, LengthExceeded},
    limits::{MAX_ACTIONS_PER_BLOCK, MAX_BLOCK_BODY_BYTES},
    primitives::{MechanismSetId, ProtocolVersion, Sha256Digest},
    state::MechanismNamespace,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_cryptography::{Hasher as _, Sha256};
use core::fmt;

/// Maximum number of declared dependencies for one mechanism.
pub const MAX_MECHANISM_DEPENDENCIES: usize = 16;
/// Maximum number of exports read by one mechanism.
pub const MAX_MECHANISM_EXPORTS: usize = 32;
/// Maximum number of mechanisms selectable in one genesis.
pub const MAX_MECHANISMS: usize = 16;
/// Maximum canonical configuration size for one mechanism.
pub const MAX_MECHANISM_CONFIG_BYTES: usize = 64 * 1024;

/// A stable, open-ended mechanism catalog identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct MechanismId(u16);

impl MechanismId {
    pub const M00: Self = Self(0);
    pub const M01: Self = Self(1);
    pub const M02: Self = Self(2);
    pub const M03: Self = Self(3);
    pub const M04: Self = Self(4);
    pub const M05: Self = Self(5);
    pub const M06: Self = Self(6);
    pub const M07: Self = Self(7);
    pub const M08: Self = Self(8);
    pub const M09: Self = Self(9);
    pub const M10: Self = Self(10);
    pub const M11: Self = Self(11);
    pub const M12: Self = Self(12);

    /// Constructs an allocated or future mechanism identifier.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the numeric portion of the catalog identifier.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Returns whether this binary contains the mechanism implementation.
    pub const fn is_implemented(self) -> bool {
        matches!(self, Self::M00 | Self::M01)
    }
}

impl fmt::Display for MechanismId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "M{:02}", self.0)
    }
}

impl From<u16> for MechanismId {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<MechanismId> for u16 {
    fn from(value: MechanismId) -> Self {
        value.get()
    }
}

/// A canonical semantic version for one compiled mechanism.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MechanismVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl MechanismVersion {
    pub const V1_0_0: Self = Self::new(1, 0, 0);

    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for MechanismVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A stable identifier for a declared mechanism export.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct MechanismExportId(u16);

impl MechanismExportId {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Lifecycle status declared by a mechanism manifest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MechanismStatus {
    Proposed = 0,
    Implemented = 1,
    Experimental = 2,
    Accepted = 3,
    Rejected = 4,
    Superseded = 5,
}

/// Consensus-visible metadata declared by one compiled mechanism.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MechanismManifest {
    pub id: MechanismId,
    pub version: MechanismVersion,
    pub status: MechanismStatus,
    pub requires: BoundedVec<MechanismId, MAX_MECHANISM_DEPENDENCIES>,
    pub reads_exports: BoundedVec<MechanismExportId, MAX_MECHANISM_EXPORTS>,
    pub state_namespace: MechanismNamespace,
    pub config_digest: Sha256Digest,
}

/// Opaque, bounded bytes in the canonical format defined by a mechanism version.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CanonicalMechanismConfig(BoundedBytes<MAX_MECHANISM_CONFIG_BYTES>);

impl CanonicalMechanismConfig {
    pub fn new(bytes: Vec<u8>) -> Result<Self, LengthExceeded> {
        BoundedBytes::new(bytes).map(Self)
    }

    pub fn empty() -> Self {
        Self(BoundedBytes::default())
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the unscoped SHA-256 digest recorded by a manifest.
    pub fn digest(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(self.as_slice());
        hasher.finalize()
    }
}

impl TryFrom<Vec<u8>> for CanonicalMechanismConfig {
    type Error = LengthExceeded;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

/// One ordered mechanism selection and its canonical configuration.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MechanismSelection {
    pub id: MechanismId,
    pub version: MechanismVersion,
    pub config: CanonicalMechanismConfig,
}

impl MechanismSelection {
    pub fn new(
        id: MechanismId,
        version: MechanismVersion,
        config: CanonicalMechanismConfig,
    ) -> Self {
        Self {
            id,
            version,
            config,
        }
    }
}

/// The protocol version and ordered mechanism selections committed by an ID.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MechanismSetConfig {
    protocol_version: ProtocolVersion,
    mechanisms: BoundedVec<MechanismSelection, MAX_MECHANISMS>,
}

impl MechanismSetConfig {
    pub fn new(
        protocol_version: ProtocolVersion,
        mechanisms: Vec<MechanismSelection>,
    ) -> Result<Self, MechanismSetConfigError> {
        if !protocol_version.is_supported() {
            return Err(MechanismSetConfigError::UnsupportedProtocolVersion(
                protocol_version,
            ));
        }
        let mechanisms = BoundedVec::new(mechanisms).map_err(MechanismSetConfigError::Length)?;
        Self::from_bounded(protocol_version, mechanisms)
    }

    fn from_bounded(
        protocol_version: ProtocolVersion,
        mechanisms: BoundedVec<MechanismSelection, MAX_MECHANISMS>,
    ) -> Result<Self, MechanismSetConfigError> {
        if !protocol_version.is_supported() {
            return Err(MechanismSetConfigError::UnsupportedProtocolVersion(
                protocol_version,
            ));
        }
        for (index, mechanism) in mechanisms.iter().enumerate() {
            if !mechanism.id.is_implemented() {
                return Err(MechanismSetConfigError::MechanismNotImplemented(
                    mechanism.id,
                ));
            }
            if mechanisms.as_slice()[..index]
                .iter()
                .any(|prior| prior.id == mechanism.id)
            {
                return Err(MechanismSetConfigError::DuplicateMechanism(mechanism.id));
            }
        }
        Ok(Self {
            protocol_version,
            mechanisms,
        })
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub fn mechanisms(&self) -> &[MechanismSelection] {
        self.mechanisms.as_slice()
    }

    /// Derives the domain-separated identity from this exact canonical encoding.
    pub fn id(&self) -> MechanismSetId {
        MechanismSetId::derive(self.encode().as_ref())
    }
}

/// Invalid mechanism-set configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MechanismSetConfigError {
    UnsupportedProtocolVersion(ProtocolVersion),
    Length(LengthExceeded),
    MechanismNotImplemented(MechanismId),
    DuplicateMechanism(MechanismId),
}

impl MechanismSetConfigError {
    /// Stable machine-readable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedProtocolVersion(_) => "PROTOCOL_VERSION_UNSUPPORTED",
            Self::Length(_) => "MECHANISM_SET_TOO_LARGE",
            Self::MechanismNotImplemented(_) => "MECHANISM_NOT_IMPLEMENTED",
            Self::DuplicateMechanism(_) => "MECHANISM_DUPLICATE",
        }
    }
}

impl fmt::Display for MechanismSetConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtocolVersion(version) => {
                write!(
                    formatter,
                    "protocol version {} is unsupported",
                    version.get()
                )
            }
            Self::Length(error) => error.fmt(formatter),
            Self::MechanismNotImplemented(id) => {
                write!(formatter, "mechanism {id} is not implemented")
            }
            Self::DuplicateMechanism(id) => {
                write!(formatter, "mechanism {id} is selected more than once")
            }
        }
    }
}

impl std::error::Error for MechanismSetConfigError {}

/// Genesis-fixed protocol parameters from section 23.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GenesisProtocolConfig {
    version: ProtocolVersion,
    blocks_per_epoch: u64,
    max_block_bytes: u32,
    max_actions_per_block: u32,
}

impl GenesisProtocolConfig {
    pub const V1: Self = Self {
        version: ProtocolVersion::V1,
        blocks_per_epoch: 100,
        max_block_bytes: 4_194_304,
        max_actions_per_block: 1_024,
    };

    pub fn new(
        version: ProtocolVersion,
        blocks_per_epoch: u64,
        max_block_bytes: u32,
        max_actions_per_block: u32,
    ) -> Result<Self, GenesisConfigError> {
        if !version.is_supported() {
            return Err(GenesisConfigError::UnsupportedProtocolVersion(version));
        }
        if blocks_per_epoch == 0 {
            return Err(GenesisConfigError::BlocksPerEpochZero);
        }
        let block_maximum = u32::try_from(MAX_BLOCK_BODY_BYTES).expect("v1 block limit fits u32");
        if max_block_bytes == 0 || max_block_bytes > block_maximum {
            return Err(GenesisConfigError::InvalidMaxBlockBytes {
                value: max_block_bytes,
                maximum: block_maximum,
            });
        }
        let action_maximum =
            u32::try_from(MAX_ACTIONS_PER_BLOCK).expect("v1 action limit fits u32");
        if max_actions_per_block == 0 || max_actions_per_block > action_maximum {
            return Err(GenesisConfigError::InvalidMaxActionsPerBlock {
                value: max_actions_per_block,
                maximum: action_maximum,
            });
        }
        Ok(Self {
            version,
            blocks_per_epoch,
            max_block_bytes,
            max_actions_per_block,
        })
    }

    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    pub const fn blocks_per_epoch(self) -> u64 {
        self.blocks_per_epoch
    }

    pub const fn max_block_bytes(self) -> u32 {
        self.max_block_bytes
    }

    pub const fn max_actions_per_block(self) -> u32 {
        self.max_actions_per_block
    }
}

/// Complete genesis mechanism and protocol configuration.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GenesisConfig {
    protocol: GenesisProtocolConfig,
    mechanism_set: MechanismSetConfig,
}

impl GenesisConfig {
    pub fn new(
        protocol: GenesisProtocolConfig,
        mechanisms: Vec<MechanismSelection>,
    ) -> Result<Self, MechanismSetConfigError> {
        let mechanism_set = MechanismSetConfig::new(protocol.version(), mechanisms)?;
        Ok(Self {
            protocol,
            mechanism_set,
        })
    }

    pub const fn protocol(&self) -> GenesisProtocolConfig {
        self.protocol
    }

    pub const fn mechanism_set(&self) -> &MechanismSetConfig {
        &self.mechanism_set
    }

    pub fn mechanism_set_id(&self) -> MechanismSetId {
        self.mechanism_set.id()
    }
}

/// Invalid genesis protocol parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisConfigError {
    UnsupportedProtocolVersion(ProtocolVersion),
    BlocksPerEpochZero,
    InvalidMaxBlockBytes { value: u32, maximum: u32 },
    InvalidMaxActionsPerBlock { value: u32, maximum: u32 },
}

impl fmt::Display for GenesisConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid genesis protocol configuration: {self:?}"
        )
    }
}

impl std::error::Error for GenesisConfigError {}

impl Write for MechanismId {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl FixedSize for MechanismId {
    const SIZE: usize = <u16 as FixedSize>::SIZE;
}

impl Read for MechanismId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(u16::read(buf)?))
    }
}

impl Write for MechanismVersion {
    fn write(&self, buf: &mut impl BufMut) {
        self.major.write(buf);
        self.minor.write(buf);
        self.patch.write(buf);
    }
}

impl FixedSize for MechanismVersion {
    const SIZE: usize = 3 * <u16 as FixedSize>::SIZE;
}

impl Read for MechanismVersion {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(u16::read(buf)?, u16::read(buf)?, u16::read(buf)?))
    }
}

impl Write for MechanismExportId {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl FixedSize for MechanismExportId {
    const SIZE: usize = <u16 as FixedSize>::SIZE;
}

impl Read for MechanismExportId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(u16::read(buf)?))
    }
}

impl Write for MechanismStatus {
    fn write(&self, buf: &mut impl BufMut) {
        (*self as u8).write(buf);
    }
}

impl FixedSize for MechanismStatus {
    const SIZE: usize = <u8 as FixedSize>::SIZE;
}

impl Read for MechanismStatus {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Proposed),
            1 => Ok(Self::Implemented),
            2 => Ok(Self::Experimental),
            3 => Ok(Self::Accepted),
            4 => Ok(Self::Rejected),
            5 => Ok(Self::Superseded),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl Write for MechanismManifest {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.version.write(buf);
        self.status.write(buf);
        self.requires.write(buf);
        self.reads_exports.write(buf);
        self.state_namespace.get().write(buf);
        self.config_digest.write(buf);
    }
}

impl EncodeSize for MechanismManifest {
    fn encode_size(&self) -> usize {
        self.id.encode_size()
            + self.version.encode_size()
            + self.status.encode_size()
            + self.requires.encode_size()
            + self.reads_exports.encode_size()
            + <u16 as FixedSize>::SIZE
            + self.config_digest.encode_size()
    }
}

impl Read for MechanismManifest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            id: MechanismId::read(buf)?,
            version: MechanismVersion::read(buf)?,
            status: MechanismStatus::read(buf)?,
            requires: BoundedVec::read_cfg(buf, &())?,
            reads_exports: BoundedVec::read_cfg(buf, &())?,
            state_namespace: MechanismNamespace::new(u16::read(buf)?),
            config_digest: Sha256Digest::read(buf)?,
        })
    }
}

impl Write for CanonicalMechanismConfig {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl EncodeSize for CanonicalMechanismConfig {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Read for CanonicalMechanismConfig {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(BoundedBytes::read_cfg(buf, &())?))
    }
}

impl Write for MechanismSelection {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.version.write(buf);
        self.config.write(buf);
    }
}

impl EncodeSize for MechanismSelection {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.version.encode_size() + self.config.encode_size()
    }
}

impl Read for MechanismSelection {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(
            MechanismId::read(buf)?,
            MechanismVersion::read(buf)?,
            CanonicalMechanismConfig::read(buf)?,
        ))
    }
}

impl Write for MechanismSetConfig {
    fn write(&self, buf: &mut impl BufMut) {
        self.protocol_version.write(buf);
        self.mechanisms.write(buf);
    }
}

impl EncodeSize for MechanismSetConfig {
    fn encode_size(&self) -> usize {
        self.protocol_version.encode_size() + self.mechanisms.encode_size()
    }
}

impl Read for MechanismSetConfig {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let protocol_version = ProtocolVersion::read(buf)?;
        let mechanisms = BoundedVec::read_cfg(buf, &())?;
        Self::from_bounded(protocol_version, mechanisms)
            .map_err(|error| CodecError::Wrapped("MechanismSetConfig", Box::new(error)))
    }
}

impl Write for GenesisProtocolConfig {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.blocks_per_epoch.write(buf);
        self.max_block_bytes.write(buf);
        self.max_actions_per_block.write(buf);
    }
}

impl FixedSize for GenesisProtocolConfig {
    const SIZE: usize = <ProtocolVersion as FixedSize>::SIZE
        + <u64 as FixedSize>::SIZE
        + 2 * <u32 as FixedSize>::SIZE;
}

impl Read for GenesisProtocolConfig {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Self::new(
            ProtocolVersion::read(buf)?,
            u64::read(buf)?,
            u32::read(buf)?,
            u32::read(buf)?,
        )
        .map_err(|error| CodecError::Wrapped("GenesisProtocolConfig", Box::new(error)))
    }
}

impl Write for GenesisConfig {
    fn write(&self, buf: &mut impl BufMut) {
        self.protocol.write(buf);
        self.mechanism_set.mechanisms.write(buf);
    }
}

impl EncodeSize for GenesisConfig {
    fn encode_size(&self) -> usize {
        self.protocol.encode_size() + self.mechanism_set.mechanisms.encode_size()
    }
}

impl Read for GenesisConfig {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let protocol = GenesisProtocolConfig::read(buf)?;
        let mechanisms = BoundedVec::<MechanismSelection, MAX_MECHANISMS>::read_cfg(buf, &())?;
        let mechanism_set = MechanismSetConfig::from_bounded(protocol.version(), mechanisms)
            .map_err(|error| CodecError::Wrapped("GenesisConfig", Box::new(error)))?;
        Ok(Self {
            protocol,
            mechanism_set,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};

    fn selection(id: MechanismId, config: &[u8]) -> MechanismSelection {
        MechanismSelection::new(
            id,
            MechanismVersion::V1_0_0,
            CanonicalMechanismConfig::new(config.to_vec()).unwrap(),
        )
    }

    fn assert_codec<T>(value: T)
    where
        T: Encode + Read<Cfg = ()> + Eq + fmt::Debug,
    {
        let encoded = value.encode();
        assert_eq!(T::decode_cfg(encoded.clone(), &()).unwrap(), value);
        for length in 0..encoded.len() {
            assert!(T::decode_cfg(encoded.slice(..length), &()).is_err());
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0xff);
        assert!(matches!(
            T::decode_cfg(trailing.as_slice(), &()),
            Err(CodecError::ExtraData(1))
        ));
    }

    #[test]
    fn manifest_and_genesis_types_have_strict_canonical_codecs() {
        let config = CanonicalMechanismConfig::new(vec![1, 2, 3]).unwrap();
        assert_codec(MechanismManifest {
            id: MechanismId::M01,
            version: MechanismVersion::V1_0_0,
            status: MechanismStatus::Implemented,
            requires: BoundedVec::new(vec![MechanismId::M00]).unwrap(),
            reads_exports: BoundedVec::new(vec![MechanismExportId::new(7)]).unwrap(),
            state_namespace: MechanismNamespace::new(1),
            config_digest: config.digest(),
        });
        assert_codec(
            GenesisConfig::new(
                GenesisProtocolConfig::V1,
                vec![
                    selection(MechanismId::M00, &[]),
                    selection(MechanismId::M01, &[1, 2, 3]),
                ],
            )
            .unwrap(),
        );
    }

    #[test]
    fn mechanism_set_identity_commits_order_versions_and_configs() {
        let base = MechanismSetConfig::new(
            ProtocolVersion::V1,
            vec![
                selection(MechanismId::M00, &[]),
                selection(MechanismId::M01, &[1]),
            ],
        )
        .unwrap();
        let reordered = MechanismSetConfig::new(
            ProtocolVersion::V1,
            vec![
                selection(MechanismId::M01, &[1]),
                selection(MechanismId::M00, &[]),
            ],
        )
        .unwrap();
        let mut changed_version = selection(MechanismId::M01, &[1]);
        changed_version.version = MechanismVersion::new(1, 0, 1);
        let changed_version = MechanismSetConfig::new(
            ProtocolVersion::V1,
            vec![selection(MechanismId::M00, &[]), changed_version],
        )
        .unwrap();
        let changed_config = MechanismSetConfig::new(
            ProtocolVersion::V1,
            vec![
                selection(MechanismId::M00, &[]),
                selection(MechanismId::M01, &[2]),
            ],
        )
        .unwrap();

        assert_ne!(base.id(), reordered.id());
        assert_ne!(base.id(), changed_version.id());
        assert_ne!(base.id(), changed_config.id());
        assert_eq!(base.id(), base.id());
        assert_eq!(
            base.id().as_bytes(),
            [
                0xe3, 0x62, 0xcc, 0x58, 0x57, 0x22, 0xcf, 0xdc, 0x34, 0x46, 0xdb, 0x2c, 0xce, 0x84,
                0x3b, 0x3b, 0x00, 0xff, 0x0d, 0xc7, 0xf9, 0xbc, 0x46, 0xe4, 0x84, 0xa9, 0x7f, 0x3f,
                0xab, 0x92, 0xb5, 0x64,
            ]
        );
    }

    #[test]
    fn proposed_catalog_entries_are_not_selectable() {
        for number in 2..=12 {
            let id = MechanismId::new(number);
            let error =
                MechanismSetConfig::new(ProtocolVersion::V1, vec![selection(id, &[])]).unwrap_err();
            assert_eq!(error.code(), "MECHANISM_NOT_IMPLEMENTED");
            assert_eq!(error, MechanismSetConfigError::MechanismNotImplemented(id));
        }
    }

    #[test]
    fn genesis_protocol_parameters_are_bounded_and_nonzero() {
        assert_eq!(GenesisProtocolConfig::V1.blocks_per_epoch(), 100);
        assert_eq!(GenesisProtocolConfig::V1.max_block_bytes(), 4_194_304);
        assert_eq!(GenesisProtocolConfig::V1.max_actions_per_block(), 1_024);
        assert!(GenesisProtocolConfig::new(ProtocolVersion::V1, 0, 1, 1).is_err());
        assert!(GenesisProtocolConfig::new(ProtocolVersion::V1, 1, 4_194_305, 1).is_err());
        assert!(GenesisProtocolConfig::new(ProtocolVersion::V1, 1, 1, 1_025).is_err());
    }

    #[test]
    fn duplicate_mechanisms_and_oversized_configs_are_rejected() {
        let duplicate = MechanismSetConfig::new(
            ProtocolVersion::V1,
            vec![
                selection(MechanismId::M00, &[]),
                selection(MechanismId::M00, &[]),
            ],
        )
        .unwrap_err();
        assert_eq!(duplicate.code(), "MECHANISM_DUPLICATE");
        assert!(CanonicalMechanismConfig::new(vec![0; MAX_MECHANISM_CONFIG_BYTES + 1]).is_err());
    }
}
