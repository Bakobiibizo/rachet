//! Live section 19 node assembly on Commonware's Tokio runtime.
//!
//! This module is the release wiring boundary. Every critical-path actor is a
//! concrete Commonware component; the only application-owned adapters are the
//! deterministic Stateful application, the bounded pending provider, and the
//! finalization hook that removes committed actions from that provider.

use super::variable_resolver::VariableQmdbResolverActor;
use super::{
    AuthenticatedCommitteeNetwork, CommitteeChannels, CommitteeNetworkConfigurationError,
    CommitteeNetworkGenesis, ConsensusConfigurationError, ConsensusNodeKey, FixedCommittee,
    MARSHAL_MAX_PENDING_ACKS, MARSHAL_MAX_REPAIR, STANDARD_MARSHAL_MAILBOX_SIZE,
    SimplexEngineConfig, new_block_broadcast, new_deferred_application, new_marshal_resolver,
    new_simplex_engine, state_sync_engine_config,
};
use crate::{
    application::{
        GenesisError, GenesisState, ProposalActionSource, StatefulApplication, StatefulBlock,
        state::QmdbStateDatabase,
    },
    ingress::{ActionIngress, PeerIngressError},
    mempool::{PendingActionPool, PendingPoolLimits},
    observability::{NodeMetrics, RuntimeMetricsExporter},
    persistence::{
        FinalizationActor, FinalizationPersistenceError, FinalizationStorageConfig,
        FinalizedQueryIndex,
    },
    rpc::{RpcService, serve as serve_rpc},
};
use commonware_actor::Feedback;
use commonware_codec::RangeCfg;
use commonware_consensus::{
    Reporter, Reporters,
    marshal::{self, Update, core::Actor as MarshalActor, standard::Standard},
    simplex::{self, config::Floor},
    types::{Epoch, FixedEpocher, ViewDelta},
};
use commonware_cryptography::{
    Digestible as _,
    certificate::{ConstantProvider, Verifier as _},
    sha256::Digest,
};
use commonware_glue::stateful::{Config as StatefulConfig, Stateful, SyncPlan};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, Metrics as _, Runner as _, Spawner as _, Supervisor as _,
    buffer::paged::CacheRef, tokio,
};
use commonware_storage::{
    archive::{Archive as _, Identifier as ArchiveIdentifier, immutable},
    journal::contiguous::variable::Config as VariableJournalConfig,
    merkle::full::Config as MerkleConfig,
    qmdb::current::VariableConfig,
    translator::OneCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use futures::{FutureExt as _, select};
use std::{fmt, future::Future, net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Duration};

const CONSENSUS_NAMESPACE: &[u8] = b"rachet/chain/simplex-ed25519/v1/";
const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(4_096);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(64);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(8 * 1024 * 1024);
const EPOCH_LENGTH: std::num::NonZeroU64 = NZU64!(u64::MAX);
const ARCHIVE_ITEMS_PER_SECTION: std::num::NonZeroU64 = NZU64!(1_024);
const MARSHAL_VIEW_RETENTION: u64 = 1_024;
const SIMPLEX_MAILBOX_SIZE: NonZeroUsize = NZUsize!(1_024);
const SIMPLEX_REPLAY_BUFFER: NonZeroUsize = NZUsize!(8 * 1024 * 1024);
const SIMPLEX_WRITE_BUFFER: NonZeroUsize = NZUsize!(8 * 1024 * 1024);
const SIMPLEX_LEADER_TIMEOUT: Duration = Duration::from_secs(2);
const SIMPLEX_CERTIFICATION_TIMEOUT: Duration = Duration::from_secs(4);
const SIMPLEX_TIMEOUT_RETRY: Duration = Duration::from_secs(2);
const SIMPLEX_ACTIVITY_TIMEOUT: u64 = 32;
const SIMPLEX_SKIP_TIMEOUT: u64 = 16;
const SIMPLEX_FETCH_TIMEOUT: Duration = Duration::from_secs(2);
const SIMPLEX_FETCH_CONCURRENT: NonZeroUsize = NZUsize!(8);
const MINIMUM_RUNTIME_BUFFER_SIZE: usize = 16 * 1024 * 1024;
const SHUTDOWN_DRAIN_POLLS: usize = 1_000;
const SHUTDOWN_DRAIN_INTERVAL: Duration = Duration::from_millis(10);

/// Configuration consumed exactly once to start one live consensus node.
pub struct LiveNodeConfig {
    pub network_genesis: CommitteeNetworkGenesis,
    pub genesis_state: GenesisState,
    pub consensus_key: ConsensusNodeKey,
    pub pending_limits: PendingPoolLimits,
    /// Prefix for all partitions owned by this node inside the runtime storage directory.
    pub storage_prefix: String,
    /// Validated external HTTP listen address, when this assembly owns RPC.
    pub rpc_listen: Option<SocketAddr>,
}

impl LiveNodeConfig {
    pub fn new(
        network_genesis: CommitteeNetworkGenesis,
        genesis_state: GenesisState,
        consensus_key: ConsensusNodeKey,
        pending_limits: PendingPoolLimits,
        storage_prefix: impl Into<String>,
    ) -> Result<Self, LiveNodeError> {
        if network_genesis.chain_id() != genesis_state.chain_id() {
            return Err(LiveNodeError::ChainIdMismatch);
        }
        if !genesis_state
            .resolution_authorities()
            .iter()
            .all(|authority| network_genesis.actor_identities().contains(authority))
        {
            return Err(LiveNodeError::ResolutionAuthorityMissingFromNetworkGenesis);
        }
        let storage_prefix = storage_prefix.into();
        if storage_prefix.is_empty() {
            return Err(LiveNodeError::EmptyStoragePrefix);
        }
        Ok(Self {
            network_genesis,
            genesis_state,
            consensus_key,
            pending_limits,
            storage_prefix,
            rpc_listen: None,
        })
    }

    /// Enables the external HTTP boundary at the already-validated address.
    pub const fn with_rpc_listen(mut self, rpc_listen: SocketAddr) -> Self {
        self.rpc_listen = Some(rpc_listen);
        self
    }
}

/// A started live actor tree with shared ingress and finalized query state.
pub struct LiveNode {
    pending: Arc<PendingActionPool>,
    finalized: FinalizedQueryIndex,
    deferred_task_prefix: String,
    actors: Vec<(&'static str, Handle<()>)>,
}

impl LiveNode {
    /// Builds storage and starts P2P, broadcast, resolver, marshal, Stateful, and Simplex actors.
    pub async fn start(
        context: tokio::Context,
        config: LiveNodeConfig,
    ) -> Result<Self, LiveNodeError> {
        let LiveNodeConfig {
            network_genesis,
            genesis_state,
            consensus_key,
            pending_limits,
            storage_prefix,
            rpc_listen,
        } = config;
        let observability = Arc::new(NodeMetrics::default());
        let committee = FixedCommittee::new(
            network_genesis
                .peers()
                .iter()
                .map(|peer| peer.node_id().clone())
                .collect(),
        )?;
        let participants = committee.public_keys();
        let local_public_key = consensus_key.node_id().public_key().clone();
        let namespace = consensus_namespace(network_genesis.chain_id());
        let scheme = committee.signer(&namespace, consensus_key.clone())?;
        let network = AuthenticatedCommitteeNetwork::new(
            context.child("authenticated_network"),
            &network_genesis,
            consensus_key,
        )?;

        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut finalized_blocks: immutable::Archive<_, Digest, StatefulBlock> =
            immutable::Archive::init(
                context.child("block_archive"),
                archive_config(page_cache.clone(), &storage_prefix, "blocks", ()),
            )
            .await
            .map_err(|_| LiveNodeError::BlockArchiveInitialization)?;
        let stored_genesis = finalized_blocks
            .get(ArchiveIdentifier::Index(0))
            .await
            .map_err(|_| LiveNodeError::BlockArchiveInitialization)?;

        let qmdb_config = || state_database_config(page_cache.clone(), &storage_prefix);
        let mut bootstrap_database =
            QmdbStateDatabase::<tokio::Context>::init(context.child("genesis_qmdb"), qmdb_config())
                .await
                .map_err(|_| LiveNodeError::QmdbInitialization)?;
        let mut application = if let Some(stored_genesis) = stored_genesis {
            StatefulApplication::open(
                &bootstrap_database,
                genesis_state,
                participants[0].clone(),
                stored_genesis,
            )
            .await?
        } else {
            let application = StatefulApplication::bootstrap(
                &mut bootstrap_database,
                genesis_state,
                participants[0].clone(),
            )
            .await?;
            let genesis = application.genesis_block().clone();
            finalized_blocks
                .put_sync(0, genesis.digest(), genesis)
                .await
                .map_err(|_| LiveNodeError::BlockArchiveInitialization)?;
            application
        };
        application.set_observability(Arc::clone(&observability));
        drop(bootstrap_database);
        let genesis = application.genesis_block().clone();
        let archived_ranges = finalized_blocks.ranges().collect::<Vec<_>>();
        let mut archived_blocks = Vec::new();
        for (start, end) in archived_ranges {
            for height in start..=end {
                let block = finalized_blocks
                    .get(ArchiveIdentifier::Index(height))
                    .await
                    .map_err(|_| LiveNodeError::BlockArchiveInitialization)?
                    .ok_or(LiveNodeError::BlockArchiveInitialization)?;
                archived_blocks.push(block);
            }
        }

        let finalizations = immutable::Archive::init(
            context.child("finalization_archive"),
            archive_config(
                page_cache.clone(),
                &storage_prefix,
                "finalizations",
                scheme.certificate_codec_config(),
            ),
        )
        .await
        .map_err(|_| LiveNodeError::FinalizationArchiveInitialization)?;
        let plan = SyncPlan::init(&context.child("startup_plan"), storage_prefix.clone()).await;
        let (marshal_actor, marshal_mailbox, _) =
            MarshalActor::<_, Standard<StatefulBlock>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations,
                finalized_blocks,
                marshal::Config {
                    provider: ConstantProvider::new(scheme.clone()),
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: plan.marshal_start(genesis.clone()),
                    partition_prefix: storage_prefix.clone(),
                    mailbox_size: STANDARD_MARSHAL_MAILBOX_SIZE,
                    view_retention_timeout: ViewDelta::new(MARSHAL_VIEW_RETENTION),
                    prunable_items_per_section: ARCHIVE_ITEMS_PER_SECTION,
                    page_cache: page_cache.clone(),
                    replay_buffer: IO_BUFFER_SIZE,
                    key_write_buffer: IO_BUFFER_SIZE,
                    value_write_buffer: IO_BUFFER_SIZE,
                    block_codec_config: (),
                    max_repair: MARSHAL_MAX_REPAIR,
                    max_pending_acks: MARSHAL_MAX_PENDING_ACKS,
                    strategy: Sequential,
                },
            )
            .await;

        let (channels, oracle, network_handle) = network.start();
        let CommitteeChannels {
            actions,
            blocks,
            marshal_resolution,
            state_resolution,
            simplex_votes,
            simplex_certificates,
            simplex_resolution,
        } = channels;

        let marshal_resolver = new_marshal_resolver(
            context.child("marshal_resolver"),
            local_public_key.clone(),
            oracle.clone(),
            oracle.clone(),
            (marshal_resolution.sender, marshal_resolution.receiver),
        );
        let (broadcast_actor, broadcast_mailbox) = new_block_broadcast(
            context.child("block_broadcast"),
            local_public_key.clone(),
            oracle.clone(),
        );
        let broadcast_handle = broadcast_actor.start((blocks.sender, blocks.receiver));

        let (state_resolver_actor, state_resolver) = VariableQmdbResolverActor::new(
            context.child("state_resolver"),
            local_public_key.clone(),
            state_resolution.sender,
            state_resolution.receiver,
            Arc::clone(&observability),
        );
        let state_resolver_handle = state_resolver_actor.start();

        let pending = Arc::new(PendingActionPool::new(pending_limits));
        let finalization_config = FinalizationStorageConfig::new(
            storage_prefix.clone(),
            ARCHIVE_ITEMS_PER_SECTION,
            page_cache.clone(),
            IO_BUFFER_SIZE,
        )?;
        let (finalization_actor, finalization_reporter, finalized) =
            FinalizationActor::init_with_archive(
                context.child("finalization_reporter"),
                finalization_config,
                application.genesis_state().clone(),
                &genesis,
                archived_blocks,
            )
            .await?;
        let finalization_handle = finalization_actor.start();
        let input_provider: Box<dyn ProposalActionSource> =
            Box::new(SharedPendingProvider(Arc::clone(&pending)));
        let (stateful_actor, stateful_mailbox) = Stateful::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config: qmdb_config(),
                input_provider,
                marshal: marshal_mailbox.clone(),
                mailbox_size: STANDARD_MARSHAL_MAILBOX_SIZE,
                plan,
                resolvers: state_resolver,
                sync_config: state_sync_engine_config(),
                prune_config: None,
            },
        );
        let stateful_handle = stateful_actor.start();
        let deferred_context = context.child("deferred");
        let deferred_task_prefix = deferred_context.name().label;
        let deferred = new_deferred_application(
            deferred_context,
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );
        let marshal_handle = marshal_actor.start(
            PendingFinalizationReporter {
                inner: Reporters::from((stateful_mailbox, finalization_reporter)),
                pending: Arc::clone(&pending),
            },
            broadcast_mailbox,
            marshal_resolver,
        );

        let simplex = new_simplex_engine(
            context.child("simplex"),
            SimplexEngineConfig {
                scheme,
                blocker: oracle,
                automaton: deferred.clone(),
                relay: deferred,
                reporter: marshal_mailbox,
                strategy: Sequential,
                partition: format!("{storage_prefix}-simplex"),
                mailbox_size: SIMPLEX_MAILBOX_SIZE,
                epoch: Epoch::zero(),
                floor: Floor::Genesis(genesis.digest()),
                replay_buffer: SIMPLEX_REPLAY_BUFFER,
                write_buffer: SIMPLEX_WRITE_BUFFER,
                page_cache,
                leader_timeout: SIMPLEX_LEADER_TIMEOUT,
                certification_timeout: SIMPLEX_CERTIFICATION_TIMEOUT,
                timeout_retry: SIMPLEX_TIMEOUT_RETRY,
                activity_timeout: ViewDelta::new(SIMPLEX_ACTIVITY_TIMEOUT),
                skip_timeout: ViewDelta::new(SIMPLEX_SKIP_TIMEOUT),
                fetch_timeout: SIMPLEX_FETCH_TIMEOUT,
                fetch_concurrent: SIMPLEX_FETCH_CONCURRENT,
                forwarding: simplex::config::ForwardingPolicy::Disabled,
            },
        );
        let simplex_handle = simplex.start(
            (simplex_votes.sender, simplex_votes.receiver),
            (simplex_certificates.sender, simplex_certificates.receiver),
            (simplex_resolution.sender, simplex_resolution.receiver),
        );

        let peer_ingress = ActionIngress::new(Arc::clone(&pending), finalized.clone())
            .with_observability(Arc::clone(&observability));
        let mut action_receiver = actions.receiver;
        let action_receiver_handle =
            context
                .child("action_ingress")
                .spawn(move |peer_context| async move {
                    let mut stopped = peer_context.stopped().fuse();
                    loop {
                        let receive = peer_ingress.receive_one(&mut action_receiver).fuse();
                        futures::pin_mut!(receive);
                        select! {
                            result = receive => match result {
                                Ok(_) | Err(PeerIngressError::Rejected { .. }) => {}
                                Err(PeerIngressError::Network(_)) => return,
                            },
                            _ = stopped => return,
                        }
                    }
                });

        let mut actors = vec![
            ("authenticated_network", network_handle),
            ("block_broadcast", broadcast_handle),
            ("state_resolver", state_resolver_handle),
            ("stateful", stateful_handle),
            ("finalization_reporter", finalization_handle),
            ("marshal", marshal_handle),
            ("simplex", simplex_handle),
            ("action_ingress", action_receiver_handle),
        ];
        if let Some(address) = rpc_listen {
            let listener = ::tokio::net::TcpListener::bind(address)
                .await
                .map_err(|_| LiveNodeError::RpcInitialization)?;
            let metrics_context = context.child("metrics_exporter");
            let runtime_metrics = RuntimeMetricsExporter::new(move || metrics_context.encode());
            let service = RpcService::with_observability(
                Arc::clone(&pending),
                finalized.clone(),
                actions.sender,
                Arc::clone(&observability),
                runtime_metrics,
            );
            let rpc_handle = context.child("rpc").spawn(move |rpc_context| async move {
                serve_rpc(listener, service, async move {
                    let _ = rpc_context.stopped().await;
                })
                .await
                .unwrap_or_else(|error| panic!("RPC server failed: {error}"));
            });
            actors.push(("rpc", rpc_handle));
        }

        Ok(Self {
            pending,
            finalized,
            deferred_task_prefix,
            actors,
        })
    }

    pub fn pending_pool(&self) -> &Arc<PendingActionPool> {
        &self.pending
    }

    pub const fn finalized_index(&self) -> &FinalizedQueryIndex {
        &self.finalized
    }

    /// Stops proposal verification before the storage actors receive the global
    /// shutdown signal. Deferred verification and certification run as sibling
    /// supervised tasks, so the task metrics must also reach zero before
    /// Stateful can be stopped safely.
    async fn quiesce_consensus(&mut self, context: &tokio::Context) -> Result<(), LiveNodeError> {
        if let Some(index) = self.actors.iter().position(|(name, _)| *name == "simplex") {
            let (_, handle) = self.actors.remove(index);
            handle.abort();
            let _ = handle.await;
        }
        for _ in 0..SHUTDOWN_DRAIN_POLLS {
            if running_tasks_with_prefix(&context.encode(), &self.deferred_task_prefix) == 0 {
                return Ok(());
            }
            context.sleep(SHUTDOWN_DRAIN_INTERVAL).await;
        }
        Err(LiveNodeError::ShutdownDrainTimeout)
    }

    /// Awaits every top-level actor after runtime shutdown has been requested.
    pub async fn stopped(self) -> Result<(), LiveNodeError> {
        for (name, handle) in self.actors {
            handle
                .await
                .map_err(|_| LiveNodeError::ActorTerminated(name))?;
        }
        Ok(())
    }
}

/// Runs one live node under the required Tokio runner until `shutdown` resolves.
pub fn run_live_node<F>(
    runtime_config: tokio::Config,
    node_config: LiveNodeConfig,
    shutdown: F,
) -> Result<(), LiveNodeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::Runner::new(runtime_config).start(move |context| async move {
        let mut node = LiveNode::start(context.child("node"), node_config).await?;
        shutdown.await;
        node.quiesce_consensus(&context).await?;
        context
            .child("shutdown")
            .stop(0, None)
            .await
            .map_err(|_| LiveNodeError::ShutdownSignal)?;
        context
            .stopped()
            .await
            .map_err(|_| LiveNodeError::ShutdownSignal)?;
        node.stopped().await
    })
}

/// Runtime settings large enough for the fixed 4 MiB canonical block boundary.
pub fn live_runtime_config(storage_directory: impl Into<std::path::PathBuf>) -> tokio::Config {
    tokio::Config::default()
        .with_worker_threads(4)
        .with_maximum_buffer_size(MINIMUM_RUNTIME_BUFFER_SIZE)
        .with_storage_directory(storage_directory)
}

#[derive(Clone)]
struct SharedPendingProvider(Arc<PendingActionPool>);

impl ProposalActionSource for SharedPendingProvider {
    fn candidates(&self) -> Vec<rachet_core::actions::SignedAction<rachet_core::actions::Action>> {
        self.0.candidates()
    }
}

#[derive(Clone)]
struct PendingFinalizationReporter<R> {
    inner: R,
    pending: Arc<PendingActionPool>,
}

impl<R> Reporter for PendingFinalizationReporter<R>
where
    R: Reporter<Activity = Update<StatefulBlock>>,
{
    type Activity = Update<StatefulBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(block, _) = &activity {
            self.pending
                .remove_finalized(block.protocol().actions.as_slice());
        }
        self.inner.report(activity)
    }
}

type StateCodecConfig = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()));

fn state_database_config(
    page_cache: CacheRef,
    prefix: &str,
) -> VariableConfig<OneCap, StateCodecConfig, Sequential> {
    VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-qmdb-merkle-journal"),
            metadata_partition: format!("{prefix}-qmdb-merkle-metadata"),
            items_per_blob: NZU64!(1_024),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: VariableJournalConfig {
            partition: format!("{prefix}-qmdb-operations"),
            items_per_section: ARCHIVE_ITEMS_PER_SECTION,
            compression: None,
            codec_config: ((RangeCfg::new(1..), ()), (RangeCfg::new(..), ())),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: format!("{prefix}-qmdb-grafted-metadata"),
        translator: OneCap,
        init_cache_size: Some(NZUsize!(16_384)),
    }
}

fn archive_config<C>(
    page_cache: CacheRef,
    prefix: &str,
    name: &str,
    codec_config: C,
) -> immutable::Config<C> {
    let partition = format!("{prefix}-{name}");
    immutable::Config {
        metadata_partition: format!("{partition}-metadata"),
        freezer_table_partition: format!("{partition}-freezer-table"),
        freezer_table_initial_size: 1_024,
        freezer_table_resize_frequency: 64,
        freezer_table_resize_chunk_size: 1_024,
        freezer_key_partition: format!("{partition}-freezer-key"),
        freezer_key_page_cache: page_cache,
        freezer_value_partition: format!("{partition}-freezer-value"),
        freezer_value_target_size: MINIMUM_RUNTIME_BUFFER_SIZE as u64,
        freezer_value_compression: None,
        ordinal_partition: format!("{partition}-ordinal"),
        items_per_section: ARCHIVE_ITEMS_PER_SECTION,
        codec_config,
        replay_buffer: IO_BUFFER_SIZE,
        freezer_key_write_buffer: IO_BUFFER_SIZE,
        freezer_value_write_buffer: IO_BUFFER_SIZE,
        ordinal_write_buffer: IO_BUFFER_SIZE,
    }
}

fn running_tasks_with_prefix(metrics: &str, prefix: &str) -> usize {
    metrics
        .lines()
        .filter_map(|line| {
            if !line.starts_with("runtime_tasks_running{") || !line.contains("kind=\"Task\"") {
                return None;
            }
            let name = line.split("name=\"").nth(1)?.split('"').next()?;
            if !name.starts_with(prefix) {
                return None;
            }
            line.rsplit(' ').next()?.parse::<usize>().ok()
        })
        .sum()
}

fn consensus_namespace(chain_id: rachet_core::primitives::ChainId) -> Vec<u8> {
    let mut namespace = Vec::with_capacity(CONSENSUS_NAMESPACE.len() + 32);
    namespace.extend_from_slice(CONSENSUS_NAMESPACE);
    namespace.extend_from_slice(chain_id.as_bytes());
    namespace
}

/// Startup or supervised actor failure.
#[derive(Debug)]
pub enum LiveNodeError {
    ChainIdMismatch,
    ResolutionAuthorityMissingFromNetworkGenesis,
    EmptyStoragePrefix,
    Consensus(ConsensusConfigurationError),
    Network(CommitteeNetworkConfigurationError),
    Genesis(GenesisError),
    QmdbInitialization,
    FinalizationArchiveInitialization,
    BlockArchiveInitialization,
    RpcInitialization,
    FinalizationPersistence(FinalizationPersistenceError),
    ShutdownSignal,
    ShutdownDrainTimeout,
    ActorTerminated(&'static str),
}

impl LiveNodeError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ChainIdMismatch => "NODE_CHAIN_ID_MISMATCH",
            Self::ResolutionAuthorityMissingFromNetworkGenesis => {
                "NODE_RESOLUTION_AUTHORITY_MISSING"
            }
            Self::EmptyStoragePrefix => "NODE_STORAGE_PREFIX_EMPTY",
            Self::Consensus(error) => error.code(),
            Self::Network(error) => error.code(),
            Self::Genesis(error) => error.code(),
            Self::QmdbInitialization => "NODE_QMDB_INIT_FAILED",
            Self::FinalizationArchiveInitialization => "NODE_FINALIZATION_ARCHIVE_INIT_FAILED",
            Self::BlockArchiveInitialization => "NODE_BLOCK_ARCHIVE_INIT_FAILED",
            Self::RpcInitialization => "NODE_RPC_INIT_FAILED",
            Self::FinalizationPersistence(_) => "NODE_FINALIZATION_PERSISTENCE_FAILED",
            Self::ShutdownSignal => "NODE_SHUTDOWN_SIGNAL_FAILED",
            Self::ShutdownDrainTimeout => "NODE_SHUTDOWN_DRAIN_TIMEOUT",
            Self::ActorTerminated(_) => "NODE_ACTOR_TERMINATED",
        }
    }
}

impl fmt::Display for LiveNodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActorTerminated(name) => write!(formatter, "node actor {name} terminated"),
            _ => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for LiveNodeError {}

impl From<ConsensusConfigurationError> for LiveNodeError {
    fn from(error: ConsensusConfigurationError) -> Self {
        Self::Consensus(error)
    }
}

impl From<CommitteeNetworkConfigurationError> for LiveNodeError {
    fn from(error: CommitteeNetworkConfigurationError) -> Self {
        Self::Network(error)
    }
}

impl From<GenesisError> for LiveNodeError {
    fn from(error: GenesisError) -> Self {
        Self::Genesis(error)
    }
}

impl From<FinalizationPersistenceError> for LiveNodeError {
    fn from(error: FinalizationPersistenceError) -> Self {
        Self::FinalizationPersistence(error)
    }
}
