use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable, Reporter,
    marshal::{self, Update, core::Actor as MarshalActor, standard::Standard},
    simplex::{
        self, config::ForwardingPolicy, elector::RoundRobin, scheme::ed25519 as simplex_ed25519,
        types::Context as SimplexContext,
    },
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_cryptography::{
    Digest as _, Digestible, Hasher as _, Sha256, Signer as _,
    certificate::{ConstantProvider, Verifier as _},
    ed25519,
    sha256::Digest,
};
use commonware_glue::{
    simulate::{
        action::{Action, Crash, Schedule},
        engine::{EngineDefinition, InitContext},
        exit::ProcessedHeightAtLeast,
        plan::PlanBuilder,
        processed::ProcessedHeight,
        reporter::MonitorReporter,
    },
    stateful::{
        Application, Config as StatefulConfig, Proposed, Stateful, SyncPlan,
        db::p2p::standard as qmdb_resolver,
        db::{DatabaseSet, Merkleized as _, Unmerkleized as _},
    },
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Buf, BufMut, Handle, Quota, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    archive::immutable,
    journal::contiguous::fixed::Config as FixedLogConfig,
    merkle::{Location, full::Config as MerkleConfig, mmr},
    qmdb::{
        current::{FixedConfig, unordered::fixed},
        sync::Target,
    },
    translator::TwoCap,
};
use commonware_utils::{
    NZU16, NZU32, NZU64, NZUsize, non_empty_range,
    ordered::Set,
    range::NonEmptyRange,
    sync::{Mutex, TracedAsyncRwLock},
};
use futures::{Stream, StreamExt as _};
use rachet_chain::engine::{
    MARSHAL_MAX_PENDING_ACKS, MARSHAL_MAX_REPAIR, STANDARD_MARSHAL_MAILBOX_SIZE,
    STATE_SYNC_MAX_SERVE_OPS, new_deferred_application, new_marshal_resolver,
    state_sync_engine_config, state_sync_resolver_config,
};
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc, time::Duration};

const NAMESPACE: &[u8] = b"rachet/commonware-spike/restart-catchup/v1";
const COMMITTEE_SIZE: usize = 4;
const BITMAP_CHUNK_BYTES: usize = 32;
const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1_024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(12);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2_048);
const EPOCH_LENGTH: std::num::NonZeroU64 = NZU64!(u64::MAX);
const NETWORK_QUOTA: Quota = Quota::per_second(NZU32!(1_000));
const TARGET_HEIGHT: u64 = 60;

type CurrentQmdb = fixed::Db<
    mmr::Family,
    deterministic::Context,
    Digest,
    Digest,
    Sha256,
    TwoCap,
    BITMAP_CHUNK_BYTES,
    Sequential,
>;
type CurrentDatabaseSet = Arc<TracedAsyncRwLock<CurrentQmdb>>;
type ConsensusContext = SimplexContext<Digest, ed25519::PublicKey>;
type MarshalMailbox = marshal::core::Mailbox<simplex_ed25519::Scheme, Standard<Block>>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Block {
    context: ConsensusContext,
    parent: Digest,
    height: Height,
    value: Digest,
    state_root: Digest,
    ops_root: Digest,
    range: NonEmptyRange<Location<mmr::Family>>,
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.value.write(buf);
        self.state_root.write(buf);
        self.ops_root.write(buf);
        self.range.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.value.encode_size()
            + self.state_root.encode_size()
            + self.ops_root.encode_size()
            + self.range.encode_size()
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            context: ConsensusContext::read(buf)?,
            parent: Digest::read(buf)?,
            height: Height::read(buf)?,
            value: Digest::read(buf)?,
            state_root: Digest::read(buf)?,
            ops_root: Digest::read(buf)?,
            range: NonEmptyRange::read(buf)?,
        })
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&self.encode())
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for Block {
    fn parent(&self) -> Digest {
        self.parent
    }
}

impl CertifiableBlock for Block {
    type Context = ConsensusContext;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl Block {
    fn genesis(sync_target: Target<mmr::Family, Digest>, leader: ed25519::PublicKey) -> Self {
        Self {
            context: ConsensusContext {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), Digest::EMPTY),
            },
            parent: Digest::EMPTY,
            height: Height::zero(),
            value: Digest::EMPTY,
            state_root: Digest::EMPTY,
            ops_root: sync_target.root,
            range: sync_target.range,
        }
    }
}

#[derive(Clone)]
struct CatchupApplication {
    genesis: Block,
}

impl CatchupApplication {
    async fn execute(
        value: Digest,
        batches: <CurrentDatabaseSet as DatabaseSet<deterministic::Context>>::Unmerkleized,
    ) -> <CurrentDatabaseSet as DatabaseSet<deterministic::Context>>::Merkleized {
        batches
            .write(Sha256::hash(b"restart-catchup-tip"), Some(value))
            .merkleize()
            .await
            .expect("the current-QMDB catch-up batch must merkleize")
    }

    fn block(
        context: ConsensusContext,
        parent: &Block,
        value: Digest,
        merkleized: &<CurrentDatabaseSet as DatabaseSet<deterministic::Context>>::Merkleized,
    ) -> Block {
        let bounds = merkleized.bounds();
        Block {
            context,
            parent: parent.digest(),
            height: parent.height().next(),
            value,
            state_root: merkleized.root(),
            ops_root: merkleized.ops_root(),
            range: non_empty_range!(merkleized.sync_boundary(), Location::new(bounds.total_size)),
        }
    }
}

impl Application<deterministic::Context> for CatchupApplication {
    type SigningScheme = simplex_ed25519::Scheme;
    type Context = ConsensusContext;
    type Block = Block;
    type Databases = CurrentDatabaseSet;
    type InputProvider = ();

    fn sync_targets(block: &Self::Block) -> Target<mmr::Family, Digest> {
        Target::new(block.ops_root, block.range.clone())
    }

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (deterministic::Context, Self::Context),
        ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
        batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        _input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, deterministic::Context>> {
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let value = Sha256::hash(&context.1.encode());
        let merkleized = Self::execute(value, batches).await;
        let block = Self::block(context.1, &parent, value, &merkleized);
        Some(Proposed { block, merkleized })
    }

    async fn verify(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
        batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
        let mut ancestry = Box::pin(ancestry);
        let block = ancestry.next().await?;
        let parent = ancestry.next().await?;
        if block.parent != parent.digest() || block.height != parent.height().next() {
            return None;
        }
        let merkleized = Self::execute(block.value, batches).await;
        let expected = Self::block(block.context.clone(), &parent, block.value, &merkleized);
        (block.as_ref() == &expected).then_some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (deterministic::Context, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
        Self::execute(block.value, batches).await
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
        freezer_table_initial_size: 4,
        freezer_table_resize_frequency: 2,
        freezer_table_resize_chunk_size: 2,
        freezer_key_partition: format!("{partition}-freezer-key"),
        freezer_key_page_cache: page_cache,
        freezer_value_partition: format!("{partition}-freezer-value"),
        freezer_value_target_size: 128,
        freezer_value_compression: None,
        ordinal_partition: format!("{partition}-ordinal"),
        items_per_section: NZU64!(8),
        codec_config,
        replay_buffer: IO_BUFFER_SIZE,
        freezer_key_write_buffer: IO_BUFFER_SIZE,
        freezer_value_write_buffer: IO_BUFFER_SIZE,
        ordinal_write_buffer: IO_BUFFER_SIZE,
    }
}

fn qmdb_config(page_cache: CacheRef, prefix: &str) -> FixedConfig<TwoCap, Sequential> {
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-qmdb-merkle-journal"),
            metadata_partition: format!("{prefix}-qmdb-merkle-metadata"),
            items_per_blob: NZU64!(11),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedLogConfig {
            partition: format!("{prefix}-qmdb-operations"),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: format!("{prefix}-qmdb-grafted-metadata"),
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(1_024)),
    }
}

#[derive(Clone, Debug)]
struct RestartObservation {
    persisted_height: u64,
    peer_height: u64,
}

#[derive(Default)]
struct Evidence {
    starts: BTreeMap<ed25519::PublicKey, u32>,
    finalized: BTreeMap<ed25519::PublicKey, u64>,
    delivered: BTreeMap<ed25519::PublicKey, Vec<u64>>,
    restarts: Vec<RestartObservation>,
}

type SharedEvidence = Arc<Mutex<Evidence>>;

#[derive(Clone)]
struct TipRecorder<R> {
    inner: R,
    public_key: ed25519::PublicKey,
    evidence: SharedEvidence,
}

impl<R> Reporter for TipRecorder<R>
where
    R: Reporter<Activity = Update<Block>>,
{
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match &activity {
            Update::Tip(_, height, _) => {
                self.evidence
                    .lock()
                    .finalized
                    .insert(self.public_key.clone(), height.get());
            }
            Update::Block(block, _) => {
                self.evidence
                    .lock()
                    .delivered
                    .entry(self.public_key.clone())
                    .or_default()
                    .push(block.height().get());
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
            .map_or(0, |height| height.get())
    }
}

#[derive(Clone)]
struct CatchupEngine {
    participants: Vec<ed25519::PublicKey>,
    schemes: Vec<simplex_ed25519::Scheme>,
    evidence: SharedEvidence,
}

impl CatchupEngine {
    fn new() -> Self {
        let private_keys = (0..COMMITTEE_SIZE)
            .map(|index| ed25519::PrivateKey::from_seed(0x5241_4348_4554 + index as u64))
            .collect::<Vec<_>>();
        let participants = private_keys
            .iter()
            .map(|private_key| private_key.public_key())
            .collect::<Vec<_>>();
        let participant_set = Set::try_from(participants.clone())
            .expect("the restart committee must contain unique identities");
        let schemes = private_keys
            .into_iter()
            .map(|private_key| {
                simplex_ed25519::Scheme::signer(NAMESPACE, participant_set.clone(), private_key)
                    .expect("each restart identity must belong to the committee")
            })
            .collect();
        Self {
            participants,
            schemes,
            evidence: Arc::new(Mutex::new(Evidence::default())),
        }
    }
}

impl EngineDefinition for CatchupEngine {
    type PublicKey = ed25519::PublicKey;
    type Engine = Handle<()>;
    type State = ValidatorState;

    fn participants(&self) -> Vec<Self::PublicKey> {
        self.participants.clone()
    }

    fn channels(&self) -> Vec<(u64, Quota)> {
        vec![
            (0, NETWORK_QUOTA),
            (1, NETWORK_QUOTA),
            (2, NETWORK_QUOTA),
            (3, NETWORK_QUOTA),
            (4, NETWORK_QUOTA),
            (5, NETWORK_QUOTA),
        ]
    }

    async fn init(&self, context: InitContext<'_, Self::PublicKey>) -> (Self::Engine, Self::State) {
        let InitContext {
            context,
            index,
            public_key,
            oracle,
            channels,
            monitor,
            ..
        } = context;
        let scheme = self.schemes[index].clone();
        let partition_prefix = format!("restart-validator-{index}");
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut channels = channels.into_iter();
        let vote_network = channels.next().expect("vote channel");
        let certificate_network = channels.next().expect("certificate channel");
        let simplex_resolver_network = channels.next().expect("Simplex resolver channel");
        let backfill_network = channels.next().expect("marshal backfill channel");
        let broadcast_network = channels.next().expect("broadcast channel");
        let qmdb_network = channels.next().expect("QMDB resolver channel");

        let marshal_resolver = new_marshal_resolver(
            context.child("marshal_resolver"),
            public_key.clone(),
            oracle.manager(),
            oracle.control(public_key.clone()),
            backfill_network,
        );

        let (broadcast_actor, broadcast_buffer) = buffered::Engine::new(
            context.child("broadcast"),
            buffered::Config {
                public_key: public_key.clone(),
                mailbox_size: NZUsize!(64),
                deque_size: 2,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
            },
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
        .expect("the finalization archive must reopen");
        let finalized_blocks = immutable::Archive::init(
            context.child("blocks"),
            archive_config(page_cache.clone(), &partition_prefix, "blocks", ()),
        )
        .await
        .expect("the finalized block archive must reopen");

        let initial_target =
            <CurrentDatabaseSet as DatabaseSet<deterministic::Context>>::initial_sync_targets();
        let genesis = Block::genesis(initial_target, self.participants[0].clone());
        let plan = SyncPlan::init(&context.child("startup"), partition_prefix.clone()).await;
        let (marshal_actor, marshal_mailbox, persisted_height) =
            MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations,
                finalized_blocks,
                marshal::Config {
                    provider: ConstantProvider::new(scheme.clone()),
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: plan.marshal_start(genesis.clone()),
                    partition_prefix: partition_prefix.clone(),
                    mailbox_size: STANDARD_MARSHAL_MAILBOX_SIZE,
                    view_retention_timeout: ViewDelta::new(16),
                    prunable_items_per_section: NZU64!(8),
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
                    .finalized
                    .iter()
                    .filter(|(peer, _)| *peer != public_key)
                    .map(|(_, height)| *height)
                    .max()
                    .unwrap_or(0);
                evidence.restarts.push(RestartObservation {
                    persisted_height: persisted_height.map_or(0, Height::get),
                    peer_height,
                });
            }
        }

        let (qmdb_resolver_actor, qmdb_sync_resolver) =
            qmdb_resolver::Actor::<_, ed25519::PublicKey, _, _, mmr::Family, CurrentQmdb>::new(
                context.child("qmdb_resolver"),
                state_sync_resolver_config(
                    oracle.manager(),
                    oracle.control(public_key.clone()),
                    None,
                    Some(public_key.clone()),
                ),
            );
        qmdb_resolver_actor.start(qmdb_network);

        let (stateful_actor, stateful_mailbox) = Stateful::init(
            context.child("stateful"),
            StatefulConfig {
                application: CatchupApplication {
                    genesis: genesis.clone(),
                },
                db_config: qmdb_config(page_cache.clone(), &partition_prefix),
                input_provider: (),
                marshal: marshal_mailbox.clone(),
                mailbox_size: STANDARD_MARSHAL_MAILBOX_SIZE,
                plan,
                resolvers: qmdb_sync_resolver,
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
            TipRecorder {
                inner: stateful_mailbox,
                public_key: public_key.clone(),
                evidence: self.evidence.clone(),
            },
        );
        marshal_actor.start(reporter, broadcast_buffer, marshal_resolver);
        stateful_actor.start();

        let simplex = simplex::Engine::new(
            context,
            simplex::Config {
                scheme,
                elector: RoundRobin::<Sha256>::default(),
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
                activity_timeout: ViewDelta::new(16),
                skip_timeout: ViewDelta::new(8),
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

#[test]
fn stopped_node_reopens_persisted_storage_and_backfills_missing_ancestry() {
    let engine = CatchupEngine::new();
    let stopped = engine.participants[0].clone();
    let results = PlanBuilder::new(engine.clone())
        .seed(0x5241_4348_4554)
        .crash(Crash::Schedule(
            Schedule::new()
                .at(Duration::from_millis(1_500), Action::Crash(stopped.clone()))
                .at(Duration::from_millis(5_000), Action::Restart(stopped)),
        ))
        .exit_condition(ProcessedHeightAtLeast::new(TARGET_HEIGHT))
        .timeout(Duration::from_secs(45))
        .run()
        .expect("the real Commonware stack must restart and catch up");

    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert_eq!(result.crashes, 1, "the schedule must stop exactly one node");
    assert_eq!(result.scheduled_actions, 2);
    assert!(
        result.tracker.all_reached(COMMITTEE_SIZE, TARGET_HEIGHT),
        "the restarted node must rejoin the finalized chain"
    );
    assert_eq!(
        result.tracker.unique_digests_at(TARGET_HEIGHT),
        1,
        "all nodes must agree after catch-up"
    );

    let evidence = engine.evidence.lock();
    assert_eq!(evidence.restarts.len(), 1);
    let restart = &evidence.restarts[0];
    assert!(
        restart.persisted_height > 0,
        "shutdown must leave a reusable, non-genesis marshal frontier"
    );
    assert!(
        restart.peer_height > restart.persisted_height + MARSHAL_MAX_REPAIR.get() as u64,
        "the recovery gap must exceed both the two-block broadcast cache and one bounded marshal repair batch: {restart:?}"
    );

    for participant in &engine.participants {
        let delivered = evidence
            .delivered
            .get(participant)
            .expect("every validator must receive finalized blocks");
        assert!(
            delivered
                .windows(2)
                .all(|pair| pair[1] == pair[0] || pair[1] == pair[0] + 1),
            "marshal delivery must remain ordered while permitting at-least-once duplicates: {delivered:?}"
        );
        for height in 1..=TARGET_HEIGHT {
            assert!(
                delivered.contains(&height),
                "ordered delivery must cover finalized height {height}: {delivered:?}"
            );
        }
    }
    assert_eq!(STATE_SYNC_MAX_SERVE_OPS.get(), 16);
    println!(
        "restart_catchup persisted_height={} peer_height={} target_height={TARGET_HEIGHT}",
        restart.persisted_height, restart.peer_height
    );
}
