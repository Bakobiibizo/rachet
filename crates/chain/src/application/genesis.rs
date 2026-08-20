//! Deterministic Stateful application genesis and its committed QMDB state.

use super::state::{QmdbStateBatch, QmdbStateDatabase};
use crate::observability::NodeMetrics;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Decode as _, Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable,
    simplex::{scheme::ed25519 as simplex_ed25519, types::Context as SimplexContext},
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digest as _, Digestible, ed25519, sha256::Digest};
use commonware_glue::stateful::{
    Application, Proposed,
    db::{DatabaseSet, Shared},
};
use commonware_parallel::Sequential;
use commonware_runtime::Spawner;
use commonware_storage::{
    Context as StorageContext,
    merkle::{Location, mmr},
    qmdb::sync::Target,
    translator::OneCap,
};
use commonware_utils::{non_empty_range, range::NonEmptyRange};
use futures::{Stream, StreamExt as _};
use rachet_core::{
    blocks::{
        Block as ProtocolBlock, BlockHeader, BlockValidationContext,
        ConsensusContext as ProtocolConsensusContext, ConsensusNodeId, action_root, receipt_root,
    },
    bounded::{BoundedBytes, BoundedVec, LengthExceeded},
    limits::{MAX_METADATA_BYTES, ProtocolLimits},
    mechanisms::{
        GenesisConfig, MechanismId, MechanismRegistryError, MechanismSet, MechanismVersion,
    },
    primitives::{ActorId, ChainId, HashDomain, Sha256Digest, hash_canonical},
    state::{StateBatch as _, StateKey, StateNamespace},
};
use rachet_mechanisms::{
    m00_record_only::{M00Config, M00RecordOnly},
    m01_naive_reputation::{M01Config, M01NaiveReputation},
    registry::MechanismInstance,
};
use std::{fmt, sync::Arc};

/// Maximum number of distinct resolution-authority keys fixed at genesis.
pub const MAX_RESOLUTION_AUTHORITIES: usize = 256;

/// Consensus-independent, bounded metadata committed by genesis.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GenesisMetadata {
    timestamp_ms: u64,
    data: BoundedBytes<MAX_METADATA_BYTES>,
}

impl GenesisMetadata {
    pub fn new(timestamp_ms: u64, data: Vec<u8>) -> Result<Self, LengthExceeded> {
        Ok(Self {
            timestamp_ms,
            data: BoundedBytes::new(data)?,
        })
    }

    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }
}

/// The complete consensus-independent configuration stored at `40/protocol/config`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GenesisState {
    chain_id: ChainId,
    protocol: GenesisConfig,
    limits: ProtocolLimits,
    metadata: GenesisMetadata,
    resolution_authorities: BoundedVec<ActorId, MAX_RESOLUTION_AUTHORITIES>,
}

impl GenesisState {
    pub fn new(
        chain_id: ChainId,
        protocol: GenesisConfig,
        limits: ProtocolLimits,
        metadata: GenesisMetadata,
        mut resolution_authorities: Vec<ActorId>,
    ) -> Result<Self, GenesisError> {
        resolution_authorities.sort_unstable();
        if resolution_authorities.is_empty() {
            return Err(GenesisError::NoResolutionAuthorities);
        }
        if resolution_authorities
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(GenesisError::DuplicateResolutionAuthority);
        }
        let resolution_authorities = BoundedVec::new(resolution_authorities)
            .map_err(GenesisError::TooManyResolutionAuthorities)?;
        Self::from_canonical(chain_id, protocol, limits, metadata, resolution_authorities)
    }

    fn from_canonical(
        chain_id: ChainId,
        protocol: GenesisConfig,
        limits: ProtocolLimits,
        metadata: GenesisMetadata,
        resolution_authorities: BoundedVec<ActorId, MAX_RESOLUTION_AUTHORITIES>,
    ) -> Result<Self, GenesisError> {
        let authorities = resolution_authorities.as_slice();
        if authorities.is_empty() {
            return Err(GenesisError::NoResolutionAuthorities);
        }
        if let Some(pair) = authorities.windows(2).find(|pair| pair[0] >= pair[1]) {
            return Err(if pair[0] == pair[1] {
                GenesisError::DuplicateResolutionAuthority
            } else {
                GenesisError::NonCanonicalAuthorityOrder
            });
        }

        let configured = protocol.protocol();
        let limits_config = limits.config();
        if configured.max_block_bytes() != limits_config.block_body_bytes
            || configured.max_actions_per_block() != limits_config.actions_per_block
        {
            return Err(GenesisError::ProtocolLimitMismatch);
        }
        validate_mechanisms(protocol.mechanism_set())?;

        Ok(Self {
            chain_id,
            protocol,
            limits,
            metadata,
            resolution_authorities,
        })
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn protocol(&self) -> &GenesisConfig {
        &self.protocol
    }

    pub const fn limits(&self) -> ProtocolLimits {
        self.limits
    }

    pub const fn metadata(&self) -> &GenesisMetadata {
        &self.metadata
    }

    pub fn resolution_authorities(&self) -> &[ActorId] {
        self.resolution_authorities.as_slice()
    }
}

fn validate_mechanisms(
    config: &rachet_core::mechanisms::MechanismSetConfig,
) -> Result<(), GenesisError> {
    compile_mechanism_set(config).map(|_| ())
}

pub(crate) fn compile_mechanism_set(
    config: &rachet_core::mechanisms::MechanismSetConfig,
) -> Result<MechanismSet<MechanismInstance>, GenesisError> {
    let mut instances = Vec::with_capacity(config.mechanisms().len());
    for selected in config.mechanisms() {
        if selected.version != MechanismVersion::V1_0_0 {
            return Err(GenesisError::MechanismVersionUnsupported {
                mechanism: selected.id,
                version: selected.version,
            });
        }
        let instance = match selected.id {
            MechanismId::M00 => {
                let config = M00Config::decode(selected.config.as_slice())
                    .map_err(|error| GenesisError::MechanismConfig(error.code()))?;
                MechanismInstance::m00(M00RecordOnly::new(config))
            }
            MechanismId::M01 => {
                let config = M01Config::decode(selected.config.as_slice())
                    .map_err(|error| GenesisError::MechanismConfig(error.code()))?;
                MechanismInstance::m01(M01NaiveReputation::new(config))
            }
            id => return Err(GenesisError::MechanismNotImplemented(id)),
        }
        .map_err(|_| GenesisError::MechanismInstanceMismatch(selected.id))?;
        instances.push(instance);
    }
    MechanismSet::compile(config, instances)
        .map_err(|error| GenesisError::MechanismRegistry(Box::new(error)))
}

impl Write for GenesisMetadata {
    fn write(&self, buf: &mut impl BufMut) {
        self.timestamp_ms.write(buf);
        self.data.write(buf);
    }
}

impl EncodeSize for GenesisMetadata {
    fn encode_size(&self) -> usize {
        self.timestamp_ms.encode_size() + self.data.encode_size()
    }
}

impl Read for GenesisMetadata {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            timestamp_ms: u64::read(buf)?,
            data: BoundedBytes::read_cfg(buf, &())?,
        })
    }
}

impl Write for GenesisState {
    fn write(&self, buf: &mut impl BufMut) {
        self.chain_id.write(buf);
        self.protocol.write(buf);
        self.limits.write(buf);
        self.metadata.write(buf);
        self.resolution_authorities.write(buf);
    }
}

impl EncodeSize for GenesisState {
    fn encode_size(&self) -> usize {
        self.chain_id.encode_size()
            + self.protocol.encode_size()
            + self.limits.encode_size()
            + self.metadata.encode_size()
            + self.resolution_authorities.encode_size()
    }
}

impl Read for GenesisState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Self::from_canonical(
            ChainId::read(buf)?,
            GenesisConfig::read(buf)?,
            ProtocolLimits::read(buf)?,
            GenesisMetadata::read(buf)?,
            BoundedVec::read_cfg(buf, &())?,
        )
        .map_err(|error| CodecError::Wrapped("GenesisState", Box::new(error)))
    }
}

/// A protocol block plus the authenticated current-QMDB commitments needed by Stateful.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatefulBlock {
    protocol: ProtocolBlock,
    qmdb_state_root: Sha256Digest,
    qmdb_ops_root: Digest,
    qmdb_range: NonEmptyRange<Location<mmr::Family>>,
}

impl StatefulBlock {
    pub(crate) fn from_parts(
        protocol: ProtocolBlock,
        qmdb_state_root: Sha256Digest,
        qmdb_ops_root: Digest,
        qmdb_range: NonEmptyRange<Location<mmr::Family>>,
    ) -> Self {
        Self {
            protocol,
            qmdb_state_root,
            qmdb_ops_root,
            qmdb_range,
        }
    }

    pub const fn protocol(&self) -> &ProtocolBlock {
        &self.protocol
    }

    pub const fn qmdb_state_root(&self) -> Sha256Digest {
        self.qmdb_state_root
    }

    pub fn sync_target(&self) -> Target<mmr::Family, Digest> {
        Target::new(self.qmdb_ops_root, self.qmdb_range.clone())
    }
}

impl Write for StatefulBlock {
    fn write(&self, buf: &mut impl BufMut) {
        self.protocol.write(buf);
        self.qmdb_state_root.write(buf);
        self.qmdb_ops_root.write(buf);
        self.qmdb_range.write(buf);
    }
}

impl EncodeSize for StatefulBlock {
    fn encode_size(&self) -> usize {
        self.protocol.encode_size()
            + self.qmdb_state_root.encode_size()
            + self.qmdb_ops_root.encode_size()
            + self.qmdb_range.encode_size()
    }
}

impl Read for StatefulBlock {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            protocol: ProtocolBlock::read(buf)?,
            qmdb_state_root: Sha256Digest::read(buf)?,
            qmdb_ops_root: Digest::read(buf)?,
            qmdb_range: NonEmptyRange::read(buf)?,
        })
    }
}

impl Digestible for StatefulBlock {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        hash_canonical(HashDomain::Block, &self.encode())
    }
}

impl Heightable for StatefulBlock {
    fn height(&self) -> Height {
        Height::new(self.protocol.header.height)
    }
}

impl ConsensusBlock for StatefulBlock {
    fn parent(&self) -> Digest {
        self.protocol.header.parent_block
    }
}

impl CertifiableBlock for StatefulBlock {
    type Context = SimplexContext<Digest, ed25519::PublicKey>;

    fn context(&self) -> Self::Context {
        let context = &self.protocol.context;
        SimplexContext {
            round: Round::new(Epoch::new(context.consensus_epoch), View::new(context.view)),
            leader: context.leader.public_key().clone(),
            parent: (View::new(context.parent_view), context.parent_block),
        }
    }
}

/// Immutable application configuration; all mutable consensus state lives in supplied batches.
#[derive(Clone)]
pub struct StatefulApplication {
    genesis: StatefulBlock,
    genesis_state: Arc<GenesisState>,
    observability: Option<Arc<NodeMetrics>>,
}

impl StatefulApplication {
    /// Opens an existing finalized database using the genesis block retained by marshal.
    pub async fn open<E>(
        database: &QmdbStateDatabase<E>,
        genesis_state: GenesisState,
        genesis_leader: ed25519::PublicKey,
        genesis: StatefulBlock,
    ) -> Result<Self, GenesisError>
    where
        E: StorageContext,
    {
        validate_consensus_role(&genesis_state, &genesis_leader)?;
        let config_key = StateKey::protocol_config().as_bytes().to_vec();
        let existing = database
            .stream_range(config_key.clone())
            .await
            .map_err(|_| GenesisError::Storage)?;
        futures::pin_mut!(existing);
        let Some(entry) = existing.next().await else {
            return Err(GenesisError::DatabaseEmpty);
        };
        let (key, value) = entry.map_err(|_| GenesisError::Storage)?;
        if key != config_key
            || GenesisState::decode_cfg(value.as_slice(), &())
                .map_err(|_| GenesisError::StoredGenesisMismatch)?
                != genesis_state
        {
            return Err(GenesisError::StoredGenesisMismatch);
        }

        let mut initial = QmdbStateBatch::new();
        initial.put(
            StateKey::protocol_config(),
            genesis_state.encode().as_ref().into(),
        );
        initial.put(
            StateKey::protocol_epoch(),
            0_u64.to_be_bytes().as_slice().into(),
        );
        let logical_root = initial
            .finish()
            .map_err(|_| GenesisError::Storage)?
            .logical_root();
        let expected_context = ProtocolConsensusContext {
            consensus_epoch: 0,
            view: 0,
            leader: ConsensusNodeId::from(genesis_leader),
            parent_view: 0,
            parent_block: Digest::EMPTY,
        };
        let protocol = genesis.protocol();
        protocol
            .validate_structure(&BlockValidationContext {
                consensus_context: expected_context,
                protocol_version: genesis_state.protocol().protocol().version(),
                chain_id: genesis_state.chain_id(),
                height: 0,
                parent_block: Digest::EMPTY,
                parent_state_root: Digest::EMPTY,
                mechanism_set_id: genesis_state.protocol().mechanism_set_id(),
                blocks_per_epoch: genesis_state.protocol().protocol().blocks_per_epoch(),
                limits: genesis_state.limits(),
            })
            .map_err(|_| GenesisError::StoredGenesisMismatch)?;
        protocol
            .validate_execution(&[], logical_root)
            .map_err(|_| GenesisError::StoredGenesisMismatch)?;
        if protocol.header.timestamp_ms != genesis_state.metadata().timestamp_ms() {
            return Err(GenesisError::StoredGenesisMismatch);
        }

        Ok(Self {
            genesis,
            genesis_state: Arc::new(genesis_state),
            observability: None,
        })
    }

    /// Validates configuration and writes the exact initial snapshot to a fresh real QMDB.
    pub async fn bootstrap<E>(
        database: &mut QmdbStateDatabase<E>,
        genesis_state: GenesisState,
        genesis_leader: ed25519::PublicKey,
    ) -> Result<Self, GenesisError>
    where
        E: StorageContext,
    {
        validate_consensus_role(&genesis_state, &genesis_leader)?;

        let database_is_empty = {
            let existing = database
                .stream_range(Vec::new())
                .await
                .map_err(|_| GenesisError::Storage)?;
            futures::pin_mut!(existing);
            existing.next().await.is_none()
        };
        if !database_is_empty {
            return Err(GenesisError::DatabaseNotEmpty);
        }

        let mut state = QmdbStateBatch::new();
        state.put(
            StateKey::protocol_config(),
            genesis_state.encode().as_ref().into(),
        );
        state.put(
            StateKey::protocol_epoch(),
            0_u64.to_be_bytes().as_slice().into(),
        );
        let commit = state.finish().map_err(|_| GenesisError::Storage)?;
        let logical_root = commit.logical_root();
        let (batch, _) = commit.write_to(database.new_batch());
        let merkleized = batch
            .merkleize(database, None)
            .await
            .map_err(|_| GenesisError::Storage)?;
        let qmdb_state_root = merkleized.root();
        let qmdb_ops_root = merkleized.ops_root();
        let bounds = merkleized.bounds();
        let qmdb_range =
            non_empty_range!(merkleized.sync_boundary(), Location::new(bounds.total_size));
        database
            .apply_batch(merkleized)
            .await
            .map_err(|_| GenesisError::Storage)?;
        database.commit().await.map_err(|_| GenesisError::Storage)?;

        let context = ProtocolConsensusContext {
            consensus_epoch: 0,
            view: 0,
            leader: ConsensusNodeId::from(genesis_leader),
            parent_view: 0,
            parent_block: Digest::EMPTY,
        };
        let header = BlockHeader {
            protocol_version: genesis_state.protocol().protocol().version(),
            chain_id: genesis_state.chain_id(),
            height: 0,
            epoch: 0,
            parent_block: Digest::EMPTY,
            parent_state_root: Digest::EMPTY,
            action_root: action_root(&[]),
            receipt_root: receipt_root(&[]),
            post_state_root: logical_root,
            mechanism_set_id: genesis_state.protocol().mechanism_set_id(),
            timestamp_ms: genesis_state.metadata().timestamp_ms(),
        };
        let protocol = ProtocolBlock::new(context, header, Vec::new())
            .map_err(|_| GenesisError::BlockConstruction)?;
        Ok(Self {
            genesis: StatefulBlock {
                protocol,
                qmdb_state_root,
                qmdb_ops_root,
                qmdb_range,
            },
            genesis_state: Arc::new(genesis_state),
            observability: None,
        })
    }

    pub const fn genesis_block(&self) -> &StatefulBlock {
        &self.genesis
    }

    pub fn genesis_state(&self) -> &GenesisState {
        &self.genesis_state
    }

    /// Attaches diagnostic counters that cannot influence application results.
    pub fn set_observability(&mut self, observability: Arc<NodeMetrics>) {
        self.observability = Some(observability);
    }
}

fn validate_consensus_role(
    genesis_state: &GenesisState,
    genesis_leader: &ed25519::PublicKey,
) -> Result<(), GenesisError> {
    if genesis_state
        .resolution_authorities()
        .iter()
        .any(|authority| authority.as_ref() == genesis_leader.as_ref())
    {
        return Err(GenesisError::ConsensusAuthorityRoleConflict);
    }
    Ok(())
}

impl<E> Application<E> for StatefulApplication
where
    E: StorageContext + Spawner + rand_core::Rng + Send + Sync + 'static,
{
    type SigningScheme = simplex_ed25519::Scheme;
    type Context = SimplexContext<Digest, ed25519::PublicKey>;
    type Block = StatefulBlock;
    type Databases = Shared<QmdbStateDatabase<E, OneCap, Sequential>>;
    type InputProvider = Box<dyn super::ProposalActionSource>;

    fn sync_targets(block: &Self::Block) -> Target<mmr::Family, Digest> {
        block.sync_target()
    }

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let proposed = super::proposal::propose(self, context, ancestry, batches, input).await;
        if proposed.is_some()
            && let Some(observability) = &self.observability
        {
            observability.observe_block_proposed();
        }
        proposed
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let verified = super::verification::verify(self, context.1, ancestry, batches).await;
        if let Some(observability) = &self.observability {
            observability.observe_block_verification(verified.is_some());
        }
        verified
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        super::replay::apply(self, block, batches).await
    }
}

/// Invalid input or storage state encountered before node startup.
#[derive(Debug)]
pub enum GenesisError {
    NoResolutionAuthorities,
    TooManyResolutionAuthorities(LengthExceeded),
    DuplicateResolutionAuthority,
    NonCanonicalAuthorityOrder,
    ConsensusAuthorityRoleConflict,
    ProtocolLimitMismatch,
    MechanismNotImplemented(MechanismId),
    MechanismVersionUnsupported {
        mechanism: MechanismId,
        version: MechanismVersion,
    },
    MechanismConfig(&'static str),
    MechanismInstanceMismatch(MechanismId),
    MechanismRegistry(Box<MechanismRegistryError>),
    DatabaseNotEmpty,
    DatabaseEmpty,
    StoredGenesisMismatch,
    Storage,
    BlockConstruction,
}

impl GenesisError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoResolutionAuthorities => "GENESIS_AUTHORITY_EMPTY",
            Self::TooManyResolutionAuthorities(_) => "GENESIS_AUTHORITY_LIMIT",
            Self::DuplicateResolutionAuthority => "GENESIS_AUTHORITY_DUPLICATE",
            Self::NonCanonicalAuthorityOrder => "GENESIS_AUTHORITY_ORDER_INVALID",
            Self::ConsensusAuthorityRoleConflict => "GENESIS_AUTHORITY_ROLE_CONFLICT",
            Self::ProtocolLimitMismatch => "GENESIS_PROTOCOL_LIMIT_MISMATCH",
            Self::MechanismNotImplemented(_) => "MECHANISM_NOT_IMPLEMENTED",
            Self::MechanismVersionUnsupported { .. } => "MECHANISM_VERSION_UNSUPPORTED",
            Self::MechanismConfig(code) => code,
            Self::MechanismInstanceMismatch(_) => "MECHANISM_INSTANCE_MISMATCH",
            Self::MechanismRegistry(error) => error.code(),
            Self::DatabaseNotEmpty => "GENESIS_DATABASE_NOT_EMPTY",
            Self::DatabaseEmpty => "GENESIS_DATABASE_EMPTY",
            Self::StoredGenesisMismatch => "GENESIS_STORED_MISMATCH",
            Self::Storage => "GENESIS_STORAGE_FAILED",
            Self::BlockConstruction => "GENESIS_BLOCK_INVALID",
        }
    }
}

impl fmt::Display for GenesisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for GenesisError {}

/// Returns whether an entry belongs to one of the namespaces that genesis must leave empty.
pub const fn is_empty_genesis_namespace(namespace: StateNamespace) -> bool {
    !matches!(
        namespace,
        StateNamespace::ProtocolConfig | StateNamespace::ProtocolEpoch
    )
}
