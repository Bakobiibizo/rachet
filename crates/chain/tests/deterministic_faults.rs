use commonware_actor::Feedback;
use commonware_codec::RangeCfg;
use commonware_consensus::{
    Reporter,
    marshal::{self, Update, core::Actor as MarshalActor, standard::Standard},
    simplex::{self, config::ForwardingPolicy},
    types::{Epoch, FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::{
    Digestible as _, Signer as _,
    certificate::{ConstantProvider, Verifier as _},
    ed25519,
    sha256::Digest,
};
use commonware_glue::{
    simulate::{
        action::{Action as SimulationAction, Crash, Schedule},
        engine::{EngineDefinition, InitContext},
        exit::ProcessedHeightAtLeast,
        plan::PlanBuilder,
        processed::ProcessedHeight,
        reporter::MonitorReporter,
    },
    stateful::{
        Application, Config as StatefulConfig, Proposed, Stateful, SyncPlan,
        db::{DatabaseSet, Shared},
    },
};
use commonware_p2p::simulated::Link;
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, Quota, Spawner as _, Supervisor as _, buffer::paged::CacheRef,
    deterministic,
};
use commonware_storage::{
    archive::{Archive as _, Identifier as ArchiveIdentifier, immutable},
    journal::contiguous::variable::Config as VariableJournalConfig,
    merkle::{full::Config as MerkleConfig, mmr},
    qmdb::{current::VariableConfig, sync::Target},
    translator::OneCap,
};
use commonware_utils::{NZU16, NZU32, NZU64, NZUsize, ordered::Set, sync::Mutex};
use futures::Stream;
use rachet_chain::{
    application::{
        GenesisMetadata, GenesisState, ProposalActionSource, StatefulApplication, StatefulBlock,
        state::QmdbStateDatabase,
    },
    engine::{
        BLOCK_BROADCAST_CHANNEL, BLOCK_BROADCAST_MAX_MESSAGE_SIZE, MARSHAL_MAX_PENDING_ACKS,
        MARSHAL_MAX_REPAIR, MARSHAL_RESOLVER_CHANNEL, SIMPLEX_CERTIFICATE_CHANNEL,
        SIMPLEX_RESOLVER_CHANNEL, SIMPLEX_VOTE_CHANNEL, STANDARD_MARSHAL_MAILBOX_SIZE,
        STATE_SYNC_RESOLVER_CHANNEL, SimplexEngineConfig, VariableQmdbResolverActor,
        new_block_broadcast, new_deferred_application, new_marshal_resolver, new_simplex_engine,
        state_sync_engine_config,
    },
    observability::NodeMetrics,
};
use rachet_core::{
    actions::Action,
    limits::ProtocolLimits,
    mechanisms::{
        CanonicalMechanismConfig, GenesisConfig, GenesisProtocolConfig, MechanismId,
        MechanismSelection, MechanismVersion,
    },
    primitives::{ActorId, ChainId},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

const NAMESPACE: &[u8] = b"rachet/chain/deterministic-faults/v1";
const COMMITTEE_SIZE: usize = 4;
const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1_024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(24);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(8 * 1_024);
const EPOCH_LENGTH: std::num::NonZeroU64 = NZU64!(u64::MAX);
const NETWORK_QUOTA: Quota = Quota::per_second(NZU32!(10_000));
const HEALTHY_LINK: Link = Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(2),
    success_rate: 1.0,
};
type TestDatabases = Shared<QmdbStateDatabase<deterministic::Context>>;
type MarshalMailbox =
    marshal::core::Mailbox<simplex::scheme::ed25519::Scheme, Standard<StatefulBlock>>;
type StateCodecConfig = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Healthy,
    Crash,
    Delay,
    DisconnectRecovery,
    Drops,
    Partition,
    RestartStorage,
    LazyRecovery,
    MissingBlockBackfill,
}

impl Scenario {
    const fn target_height(self) -> u64 {
        match self {
            Self::Healthy => 16,
            Self::Crash => 24,
            Self::Delay | Self::Drops => 20,
            Self::DisconnectRecovery | Self::Partition => 32,
            Self::RestartStorage | Self::LazyRecovery => 36,
            Self::MissingBlockBackfill => 60,
        }
    }

    const fn expected_nodes_at_target(self) -> usize {
        COMMITTEE_SIZE
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BlockObservation {
    height: u64,
    digest: Vec<u8>,
    state_root: Vec<u8>,
    action_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RestartObservation {
    persisted_height: u64,
    peer_height: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Evidence {
    starts: BTreeMap<ed25519::PublicKey, u32>,
    tips: BTreeMap<ed25519::PublicKey, (u64, Vec<u8>)>,
    delivered: BTreeMap<ed25519::PublicKey, Vec<BlockObservation>>,
    replays: BTreeMap<ed25519::PublicKey, u64>,
    restarts: Vec<RestartObservation>,
    network_events: Vec<&'static str>,
}

type SharedEvidence = Arc<Mutex<Evidence>>;

#[derive(Clone)]
struct ObservedApplication {
    inner: StatefulApplication,
    public_key: ed25519::PublicKey,
    evidence: SharedEvidence,
}

impl Application<deterministic::Context> for ObservedApplication {
    type SigningScheme = simplex::scheme::ed25519::Scheme;
    type Context = simplex::types::Context<Digest, ed25519::PublicKey>;
    type Block = StatefulBlock;
    type Databases = TestDatabases;
    type InputProvider = Box<dyn ProposalActionSource>;

    fn sync_targets(block: &Self::Block) -> Target<mmr::Family, Digest> {
        <StatefulApplication as Application<deterministic::Context>>::sync_targets(block)
    }

    async fn genesis(&mut self) -> Self::Block {
        <StatefulApplication as Application<deterministic::Context>>::genesis(&mut self.inner).await
    }

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
        batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, deterministic::Context>> {
        let proposed = <StatefulApplication as Application<deterministic::Context>>::propose(
            &mut self.inner,
            context,
            ancestry,
            batches,
            input,
        )
        .await?;
        Some(Proposed {
            block: proposed.block,
            merkleized: proposed.merkleized,
        })
    }

    async fn verify(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
        batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
        <StatefulApplication as Application<deterministic::Context>>::verify(
            &mut self.inner,
            context,
            ancestry,
            batches,
        )
        .await
    }

    async fn apply(
        &mut self,
        context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
        *self
            .evidence
            .lock()
            .replays
            .entry(self.public_key.clone())
            .or_default() += 1;
        <StatefulApplication as Application<deterministic::Context>>::apply(
            &mut self.inner,
            context,
            block,
            batches,
        )
        .await
    }
}

#[derive(Clone)]
struct RecordingReporter<R> {
    inner: R,
    public_key: ed25519::PublicKey,
    evidence: SharedEvidence,
}

impl<R> Reporter for RecordingReporter<R>
where
    R: Reporter<Activity = Update<StatefulBlock>>,
{
    type Activity = Update<StatefulBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match &activity {
            Update::Tip(_, height, digest) => {
                self.evidence.lock().tips.insert(
                    self.public_key.clone(),
                    (height.get(), digest.as_ref().to_vec()),
                );
            }
            Update::Block(block, _) => {
                self.evidence
                    .lock()
                    .delivered
                    .entry(self.public_key.clone())
                    .or_default()
                    .push(BlockObservation {
                        height: block.protocol().header.height,
                        digest: block.digest().as_ref().to_vec(),
                        state_root: block.protocol().header.post_state_root.as_ref().to_vec(),
                        action_count: block.protocol().actions.len(),
                    });
            }
        }
        self.inner.report(activity)
    }
}

#[derive(Clone)]
struct ValidatorState {
    marshal: MarshalMailbox,
}

impl ProcessedHeight for ValidatorState {
    async fn processed_height(&self) -> u64 {
        self.marshal
            .get_processed_height()
            .await
            .map_or(0, Height::get)
    }
}

#[derive(Clone)]
struct ApplicationEngine {
    scenario: Scenario,
    participants: Vec<ed25519::PublicKey>,
    schemes: Vec<simplex::scheme::ed25519::Scheme>,
    genesis_state: GenesisState,
    evidence: SharedEvidence,
}

impl ApplicationEngine {
    fn new(scenario: Scenario) -> Self {
        let private_keys = (0..COMMITTEE_SIZE)
            .map(|index| ed25519::PrivateKey::from_seed(0xD37E_0000 + index as u64))
            .collect::<Vec<_>>();
        let participants = private_keys
            .iter()
            .map(|private_key| private_key.public_key())
            .collect::<Vec<_>>();
        let participant_set = Set::try_from(participants.clone())
            .expect("the deterministic committee must contain four unique identities");
        let schemes = private_keys
            .into_iter()
            .map(|private_key| {
                simplex::scheme::ed25519::Scheme::signer(
                    NAMESPACE,
                    participant_set.clone(),
                    private_key,
                )
                .expect("every deterministic signer must belong to the committee")
            })
            .collect();
        Self {
            scenario,
            participants,
            schemes,
            genesis_state: genesis_state(),
            evidence: Arc::new(Mutex::new(Evidence::default())),
        }
    }

    fn start_network_faults(
        &self,
        context: deterministic::Context,
        oracle: commonware_p2p::simulated::Oracle<ed25519::PublicKey, deterministic::Context>,
    ) {
        let scenario = self.scenario;
        if !matches!(scenario, Scenario::DisconnectRecovery | Scenario::Partition) {
            return;
        }
        let participants = self.participants.clone();
        let evidence = self.evidence.clone();
        context.spawn(move |context| async move {
            context.sleep(Duration::from_millis(1_500)).await;
            match scenario {
                Scenario::DisconnectRecovery => {
                    let isolated = participants[3].clone();
                    for peer in participants.iter().take(3) {
                        oracle
                            .remove_link(isolated.clone(), peer.clone())
                            .await
                            .expect("outbound disconnect must remove a real simulated link");
                        oracle
                            .remove_link(peer.clone(), isolated.clone())
                            .await
                            .expect("inbound disconnect must remove a real simulated link");
                    }
                    evidence.lock().network_events.push("disconnect");
                    context.sleep(Duration::from_millis(2_000)).await;
                    for peer in participants.iter().take(3) {
                        oracle
                            .add_link(isolated.clone(), peer.clone(), HEALTHY_LINK)
                            .await
                            .expect("outbound recovery must restore a real simulated link");
                        oracle
                            .add_link(peer.clone(), isolated.clone(), HEALTHY_LINK)
                            .await
                            .expect("inbound recovery must restore a real simulated link");
                    }
                    evidence.lock().network_events.push("reconnect");
                }
                Scenario::Partition => {
                    for left in participants.iter().take(2) {
                        for right in participants.iter().skip(2) {
                            oracle
                                .remove_link(left.clone(), right.clone())
                                .await
                                .expect("partition must remove a real cross-group link");
                            oracle
                                .remove_link(right.clone(), left.clone())
                                .await
                                .expect("partition must remove the reverse cross-group link");
                        }
                    }
                    evidence.lock().network_events.push("partition");
                    context.sleep(Duration::from_millis(2_000)).await;
                    for left in participants.iter().take(2) {
                        for right in participants.iter().skip(2) {
                            oracle
                                .add_link(left.clone(), right.clone(), HEALTHY_LINK)
                                .await
                                .expect("partition heal must restore a cross-group link");
                            oracle
                                .add_link(right.clone(), left.clone(), HEALTHY_LINK)
                                .await
                                .expect("partition heal must restore the reverse link");
                        }
                    }
                    evidence.lock().network_events.push("heal");
                }
                _ => unreachable!(),
            }
        });
    }
}

impl EngineDefinition for ApplicationEngine {
    type PublicKey = ed25519::PublicKey;
    type Engine = Handle<()>;
    type State = ValidatorState;

    fn participants(&self) -> Vec<Self::PublicKey> {
        self.participants.clone()
    }

    fn channels(&self) -> Vec<(u64, Quota)> {
        vec![
            (SIMPLEX_VOTE_CHANNEL, NETWORK_QUOTA),
            (SIMPLEX_CERTIFICATE_CHANNEL, NETWORK_QUOTA),
            (SIMPLEX_RESOLVER_CHANNEL, NETWORK_QUOTA),
            (MARSHAL_RESOLVER_CHANNEL, NETWORK_QUOTA),
            (BLOCK_BROADCAST_CHANNEL, NETWORK_QUOTA),
            (STATE_SYNC_RESOLVER_CHANNEL, NETWORK_QUOTA),
        ]
    }

    async fn init(&self, init: InitContext<'_, Self::PublicKey>) -> (Self::Engine, Self::State) {
        let InitContext {
            context,
            index,
            public_key,
            oracle,
            channels,
            monitor,
            ..
        } = init;
        if index == 0 {
            self.start_network_faults(context.child("network_faults"), oracle.clone());
        }
        let scheme = self.schemes[index].clone();
        let partition_prefix = format!("deterministic-application-validator-{index}");
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut channels = channels.into_iter();
        let vote_network = channels.next().expect("vote channel");
        let certificate_network = channels.next().expect("certificate channel");
        let simplex_resolver_network = channels.next().expect("Simplex resolver channel");
        let backfill_network = channels.next().expect("marshal backfill channel");
        let broadcast_network = channels.next().expect("block broadcast channel");
        let state_network = channels.next().expect("QMDB state resolver channel");

        let marshal_resolver = new_marshal_resolver(
            context.child("marshal_resolver"),
            public_key.clone(),
            oracle.manager(),
            oracle.control(public_key.clone()),
            backfill_network,
        );
        let (broadcast_actor, broadcast_mailbox) = new_block_broadcast(
            context.child("block_broadcast"),
            public_key.clone(),
            oracle.manager(),
        );
        broadcast_actor.start(broadcast_network);

        let finalizations = immutable::Archive::init(
            context.child("finalizations"),
            archive_config(
                page_cache.clone(),
                &partition_prefix,
                "finalizations",
                scheme.certificate_codec_config(),
            ),
        )
        .await
        .expect("the finalization archive must initialize or reopen");
        let mut finalized_blocks = immutable::Archive::init(
            context.child("blocks"),
            archive_config(page_cache.clone(), &partition_prefix, "blocks", ()),
        )
        .await
        .expect("the finalized block archive must initialize or reopen");
        let stored_genesis = finalized_blocks
            .get(ArchiveIdentifier::Index(0))
            .await
            .expect("the genesis archive must remain readable");

        let mut database = QmdbStateDatabase::<deterministic::Context>::init(
            context.child("application_database"),
            database_config(page_cache.clone(), &partition_prefix),
        )
        .await
        .expect("the application QMDB must initialize or reopen");
        let application = if let Some(genesis) = stored_genesis {
            StatefulApplication::open(
                &database,
                self.genesis_state.clone(),
                self.participants[0].clone(),
                genesis,
            )
            .await
            .expect("a restarted node must open its finalized application state")
        } else {
            let application = StatefulApplication::bootstrap(
                &mut database,
                self.genesis_state.clone(),
                self.participants[0].clone(),
            )
            .await
            .expect("a fresh node must bootstrap the real Rachet application");
            let genesis = application.genesis_block().clone();
            finalized_blocks
                .put_sync(0, genesis.digest(), genesis)
                .await
                .expect("the application genesis must be archived");
            application
        };
        drop(database);
        let genesis = application.genesis_block().clone();
        let plan = SyncPlan::init(&context.child("startup"), partition_prefix.clone()).await;
        let (marshal_actor, marshal_mailbox, persisted_height) =
            MarshalActor::<_, Standard<StatefulBlock>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations,
                finalized_blocks,
                marshal::Config {
                    provider: ConstantProvider::new(scheme.clone()),
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: plan.marshal_start(genesis.clone()),
                    partition_prefix: partition_prefix.clone(),
                    mailbox_size: STANDARD_MARSHAL_MAILBOX_SIZE,
                    view_retention_timeout: ViewDelta::new(128),
                    prunable_items_per_section: NZU64!(16),
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

        {
            let mut evidence = self.evidence.lock();
            let starts = evidence.starts.entry(public_key.clone()).or_default();
            let restarting = *starts > 0;
            *starts += 1;
            if restarting {
                let peer_height = evidence
                    .tips
                    .iter()
                    .filter(|(peer, _)| *peer != public_key)
                    .map(|(_, (height, _))| *height)
                    .max()
                    .unwrap_or(0);
                evidence.restarts.push(RestartObservation {
                    persisted_height: persisted_height.map_or(0, Height::get),
                    peer_height,
                });
            }
        }

        let metrics = Arc::new(NodeMetrics::default());
        let (state_resolver_actor, state_resolver) = VariableQmdbResolverActor::new(
            context.child("state_resolver"),
            public_key.clone(),
            state_network.0,
            state_network.1,
            metrics,
        );
        state_resolver_actor.start();

        let observed_application = ObservedApplication {
            inner: application,
            public_key: public_key.clone(),
            evidence: self.evidence.clone(),
        };
        let input_provider: Box<dyn ProposalActionSource> =
            Box::new(Vec::<rachet_core::actions::SignedAction<Action>>::new());
        let (stateful_actor, stateful_mailbox) = Stateful::init(
            context.child("stateful"),
            StatefulConfig {
                application: observed_application,
                db_config: database_config(page_cache.clone(), &partition_prefix),
                input_provider,
                marshal: marshal_mailbox.clone(),
                mailbox_size: STANDARD_MARSHAL_MAILBOX_SIZE,
                plan,
                resolvers: state_resolver,
                sync_config: state_sync_engine_config(),
                prune_config: None,
            },
        );
        let deferred = new_deferred_application(
            context.child("deferred"),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );
        let reporter = MonitorReporter::new(
            public_key.clone(),
            monitor,
            RecordingReporter {
                inner: stateful_mailbox.clone(),
                public_key: public_key.clone(),
                evidence: self.evidence.clone(),
            },
        );
        marshal_actor.start(reporter, broadcast_mailbox, marshal_resolver);
        stateful_actor.start();

        let simplex = new_simplex_engine(
            context.child("simplex"),
            SimplexEngineConfig {
                scheme,
                blocker: oracle.control(public_key.clone()),
                automaton: deferred.clone(),
                relay: deferred,
                reporter: marshal_mailbox.clone(),
                strategy: Sequential,
                partition: format!("{partition_prefix}-simplex"),
                mailbox_size: STANDARD_MARSHAL_MAILBOX_SIZE,
                epoch: Epoch::zero(),
                floor: simplex::config::Floor::Genesis(genesis.digest()),
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                page_cache,
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_millis(500),
                activity_timeout: ViewDelta::new(32),
                skip_timeout: ViewDelta::new(16),
                fetch_timeout: Duration::from_secs(1),
                fetch_concurrent: NZUsize!(4),
                forwarding: ForwardingPolicy::Disabled,
            },
        );
        let handle = simplex.start(vote_network, certificate_network, simplex_resolver_network);
        (
            handle,
            ValidatorState {
                marshal: marshal_mailbox,
            },
        )
    }

    fn start(engine: Self::Engine) -> Handle<()> {
        engine
    }
}

fn genesis_state() -> GenesisState {
    let mechanism = MechanismSelection::new(
        MechanismId::M00,
        MechanismVersion::V1_0_0,
        CanonicalMechanismConfig::empty(),
    );
    let protocol = GenesisConfig::new(GenesisProtocolConfig::V1, vec![mechanism]).unwrap();
    let authority = ActorId::from(ed25519::PrivateKey::from_seed(0xA07A_0001).public_key());
    GenesisState::new(
        ChainId::new([0xD7; 32]),
        protocol,
        ProtocolLimits::V1,
        GenesisMetadata::new(1_725_000_000_123, b"deterministic fault genesis".to_vec()).unwrap(),
        vec![authority],
    )
    .unwrap()
}

fn database_config(
    page_cache: CacheRef,
    prefix: &str,
) -> VariableConfig<OneCap, StateCodecConfig, Sequential> {
    VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-qmdb-merkle-journal"),
            metadata_partition: format!("{prefix}-qmdb-merkle-metadata"),
            items_per_blob: NZU64!(16),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: VariableJournalConfig {
            partition: format!("{prefix}-qmdb-operations"),
            items_per_section: NZU64!(16),
            compression: None,
            codec_config: ((RangeCfg::new(1..), ()), (RangeCfg::new(..), ())),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: format!("{prefix}-qmdb-grafted-metadata"),
        translator: OneCap,
        init_cache_size: Some(NZUsize!(4_096)),
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
        freezer_table_initial_size: 32,
        freezer_table_resize_frequency: 8,
        freezer_table_resize_chunk_size: 16,
        freezer_key_partition: format!("{partition}-freezer-key"),
        freezer_key_page_cache: page_cache,
        freezer_value_partition: format!("{partition}-freezer-value"),
        freezer_value_target_size: 4_096,
        freezer_value_compression: None,
        ordinal_partition: format!("{partition}-ordinal"),
        items_per_section: NZU64!(16),
        codec_config,
        replay_buffer: IO_BUFFER_SIZE,
        freezer_key_write_buffer: IO_BUFFER_SIZE,
        freezer_value_write_buffer: IO_BUFFER_SIZE,
        ordinal_write_buffer: IO_BUFFER_SIZE,
    }
}

fn plan_for(engine: ApplicationEngine) -> PlanBuilder<ApplicationEngine> {
    let scenario = engine.scenario;
    let target = scenario.target_height();
    let faulted = engine.participants[3].clone();
    let mut plan = PlanBuilder::new(engine)
        .seed(0xD37E_5241_4348_4554)
        .link(if matches!(scenario, Scenario::Drops) {
            Link {
                latency: Duration::from_millis(35),
                jitter: Duration::from_millis(15),
                success_rate: 0.72,
            }
        } else {
            HEALTHY_LINK
        })
        .max_message_size(BLOCK_BROADCAST_MAX_MESSAGE_SIZE)
        .exit_condition(ProcessedHeightAtLeast::new(target))
        .timeout(Duration::from_secs(60));
    plan = match scenario {
        Scenario::Crash => plan.crash(Crash::Schedule(
            Schedule::new()
                .at(
                    Duration::from_millis(800),
                    SimulationAction::Crash(faulted.clone()),
                )
                .at(
                    Duration::from_millis(1_200),
                    SimulationAction::Restart(faulted),
                ),
        )),
        Scenario::Delay => plan.crash(Crash::Delay { count: 1, after: 5 }),
        Scenario::RestartStorage | Scenario::LazyRecovery => plan.crash(Crash::Schedule(
            Schedule::new()
                .at(
                    Duration::from_millis(1_500),
                    SimulationAction::Crash(faulted.clone()),
                )
                .at(
                    Duration::from_millis(3_000),
                    SimulationAction::Restart(faulted),
                ),
        )),
        Scenario::MissingBlockBackfill => plan.crash(Crash::Schedule(
            Schedule::new()
                .at(
                    Duration::from_millis(1_500),
                    SimulationAction::Crash(faulted.clone()),
                )
                .at(
                    Duration::from_millis(5_000),
                    SimulationAction::Restart(faulted),
                ),
        )),
        _ => plan,
    };
    plan
}

fn run_once(scenario: Scenario) -> (String, Evidence) {
    let engine = ApplicationEngine::new(scenario);
    let evidence = engine.evidence.clone();
    let participants = engine.participants.clone();
    let target = scenario.target_height();
    let result = plan_for(engine)
        .run()
        .unwrap_or_else(|error| {
            panic!("{scenario:?} must finalize through the real stack: {error}")
        })
        .into_iter()
        .next()
        .expect("one deterministic seed must produce one result");

    if matches!(scenario, Scenario::Delay) {
        assert!(
            result.delayed_started,
            "the delayed node must eventually start"
        );
    }
    if matches!(
        scenario,
        Scenario::Crash
            | Scenario::RestartStorage
            | Scenario::LazyRecovery
            | Scenario::MissingBlockBackfill
    ) {
        assert_eq!(result.crashes, 1, "the declared crash must execute once");
    }

    let evidence = evidence.lock().clone();
    let target_blocks = evidence
        .delivered
        .values()
        .filter_map(|blocks| blocks.iter().find(|block| block.height == target))
        .collect::<Vec<_>>();
    assert!(
        target_blocks.len() >= scenario.expected_nodes_at_target(),
        "{scenario:?} must preserve expected application liveness at height {target}"
    );
    assert_eq!(
        target_blocks
            .iter()
            .map(|block| block.digest.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        1,
        "{scenario:?} must preserve finalized application safety at height {target}"
    );
    for blocks in evidence.delivered.values() {
        assert!(
            blocks.windows(2).all(|pair| {
                pair[1].height == pair[0].height || pair[1].height == pair[0].height + 1
            }),
            "marshal delivery must remain ordered and at-least-once"
        );
        assert!(
            blocks.iter().all(|block| block.action_count == 0),
            "the empty deterministic workload must execute as canonical empty application blocks"
        );
    }
    for height in 1..=target {
        let roots = evidence
            .delivered
            .values()
            .filter_map(|blocks| blocks.iter().find(|block| block.height == height))
            .map(|block| block.state_root.clone())
            .collect::<BTreeSet<_>>();
        assert!(
            roots.len() <= 1,
            "application state roots must agree at finalized height {height}"
        );
    }

    match scenario {
        Scenario::DisconnectRecovery => {
            assert_eq!(evidence.network_events, ["disconnect", "reconnect"]);
        }
        Scenario::Partition => {
            assert_eq!(evidence.network_events, ["partition", "heal"]);
        }
        Scenario::RestartStorage | Scenario::LazyRecovery | Scenario::MissingBlockBackfill => {
            assert_eq!(evidence.starts.get(&participants[3]), Some(&2));
            assert_eq!(evidence.restarts.len(), 1);
            assert!(
                evidence.restarts[0].persisted_height > 0,
                "restart must reopen a non-genesis finalized frontier"
            );
        }
        _ => {}
    }
    if matches!(scenario, Scenario::LazyRecovery) {
        assert!(
            evidence.replays.get(&participants[3]).copied().unwrap_or(0) > 0,
            "the restarted Stateful application must lazily replay missing ancestry"
        );
    }
    if matches!(scenario, Scenario::MissingBlockBackfill) {
        let restart = &evidence.restarts[0];
        assert!(
            restart.peer_height > restart.persisted_height + MARSHAL_MAX_REPAIR.get() as u64,
            "the missing-block gap must exceed one bounded repair batch: {restart:?}"
        );
        let restarted_blocks = evidence
            .delivered
            .get(&participants[3])
            .expect("the restarted node must receive finalized blocks");
        for height in 1..=target {
            assert!(
                restarted_blocks.iter().any(|block| block.height == height),
                "backfill must cover finalized height {height}"
            );
        }
    }

    (result.state, evidence)
}

fn assert_replayable(scenario: Scenario) {
    let first = run_once(scenario);
    let second = run_once(scenario);
    assert_eq!(
        first, second,
        "{scenario:?} must replay to identical runtime and application evidence"
    );
}

#[test]
fn four_healthy_nodes_execute_and_finalize_deterministically() {
    assert_replayable(Scenario::Healthy);
}

#[test]
fn one_crashed_node_restarts_and_preserves_safety_and_liveness() {
    assert_replayable(Scenario::Crash);
}

#[test]
fn one_delayed_node_starts_and_recovers_deterministically() {
    assert_replayable(Scenario::Delay);
}

#[test]
fn disconnected_node_reconnects_and_catches_up() {
    assert_replayable(Scenario::DisconnectRecovery);
}

#[test]
fn deterministic_message_drops_preserve_safety_and_liveness() {
    assert_replayable(Scenario::Drops);
}

#[test]
fn temporary_partition_heals_without_application_divergence() {
    assert_replayable(Scenario::Partition);
}

#[test]
fn restart_reopens_finalized_application_storage() {
    assert_replayable(Scenario::RestartStorage);
}

#[test]
fn restart_lazily_recovers_speculative_application_ancestry() {
    assert_replayable(Scenario::LazyRecovery);
}

#[test]
fn missing_blocks_are_backfilled_beyond_one_bounded_repair_batch() {
    assert_replayable(Scenario::MissingBlockBackfill);
}
