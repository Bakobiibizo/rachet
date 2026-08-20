use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::{
    Application as ConsensusApplication, Automaton, Block as ConsensusBlock, CertifiableAutomaton,
    CertifiableBlock, Heightable, Reporter,
    marshal::{
        self, Update, ancestry,
        core::Actor as MarshalActor,
        standard::{Deferred, Standard},
    },
    simplex::{scheme::ed25519 as simplex_ed25519, types::Context as SimplexContext},
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_cryptography::{
    Digest as _, Digestible, Hasher as _, Sha256, Signer as _,
    certificate::{ConstantProvider, Verifier as _},
    ed25519,
    sha256::Digest,
};
use commonware_glue::stateful::{
    Application, Config as StatefulConfig, Proposed, Stateful, SyncPlan,
    db::p2p::standard as qmdb_resolver,
    db::{DatabaseSet, Merkleized as _, Unmerkleized as _},
};
use commonware_p2p::simulated::{Config as NetworkConfig, Network};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Buf, BufMut, Quota, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
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
    Acknowledgement as _, NZU16, NZU64, NZUsize, non_empty_range, ordered::Set,
    range::NonEmptyRange, sync::TracedAsyncRwLock,
};
use futures::{Stream, StreamExt as _};
use rachet_chain::engine::{
    MARSHAL_MAX_PENDING_ACKS, MARSHAL_MAX_REPAIR, STANDARD_MARSHAL_MAILBOX_SIZE,
    new_deferred_application, new_marshal_resolver, state_sync_engine_config,
    state_sync_resolver_config,
};
use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc, time::Duration};

const NAMESPACE: &[u8] = b"rachet/commonware-spike/stateful-qmdb-deferred/v1";
const BITMAP_CHUNK_BYTES: usize = 32;

fn state_key() -> Digest {
    Digest::from([0x52; 32])
}

fn winner_value() -> Digest {
    Digest::from([0x11; 32])
}

fn loser_value() -> Digest {
    Digest::from([0x22; 32])
}

fn loser_child_value() -> Digest {
    Digest::from([0x33; 32])
}

fn post_finalize_value() -> Digest {
    Digest::from([0x44; 32])
}
const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1_024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2_048);
const EPOCH_LENGTH: std::num::NonZeroU64 = NZU64!(u64::MAX);
const NETWORK_QUOTA: Quota = Quota::per_second(std::num::NonZeroU32::MAX);

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
            context: consensus_context(View::zero(), View::zero(), Digest::EMPTY, leader),
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
struct BranchingApplication {
    genesis: Block,
}

impl BranchingApplication {
    async fn execute(
        value: Digest,
        batches: <CurrentDatabaseSet as DatabaseSet<deterministic::Context>>::Unmerkleized,
    ) -> <CurrentDatabaseSet as DatabaseSet<deterministic::Context>>::Merkleized {
        batches
            .write(state_key(), Some(value))
            .merkleize()
            .await
            .expect("the speculative current-QMDB batch must merkleize")
    }

    fn block_from_batch(
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

impl Application<deterministic::Context> for BranchingApplication {
    type SigningScheme = simplex_ed25519::Scheme;
    type Context = ConsensusContext;
    type Block = Block;
    type Databases = CurrentDatabaseSet;
    type InputProvider = VecDeque<Digest>;

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
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, deterministic::Context>> {
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let value = input.pop_front()?;
        let merkleized = Self::execute(value, batches).await;
        let block = Self::block_from_batch(context.1, &parent, value, &merkleized);
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
        let _parent = ancestry.next().await?;
        let merkleized = Self::execute(block.value, batches).await;
        let bounds = merkleized.bounds();
        let expected_range =
            non_empty_range!(merkleized.sync_boundary(), Location::new(bounds.total_size));
        (block.state_root == merkleized.root()
            && block.ops_root == merkleized.ops_root()
            && block.range == expected_range)
            .then_some(merkleized)
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

fn consensus_context(
    view: View,
    parent_view: View,
    parent: Digest,
    leader: ed25519::PublicKey,
) -> ConsensusContext {
    ConsensusContext {
        round: Round::new(Epoch::zero(), view),
        leader,
        parent: (parent_view, parent),
    }
}

fn archive_config<C>(
    page_cache: CacheRef,
    partition: &str,
    codec_config: C,
) -> immutable::Config<C> {
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
        items_per_section: NZU64!(4),
        codec_config,
        replay_buffer: IO_BUFFER_SIZE,
        freezer_key_write_buffer: IO_BUFFER_SIZE,
        freezer_value_write_buffer: IO_BUFFER_SIZE,
        ordinal_write_buffer: IO_BUFFER_SIZE,
    }
}

fn qmdb_config(page_cache: CacheRef) -> FixedConfig<TwoCap, Sequential> {
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: "stateful-current-merkle-journal".to_string(),
            metadata_partition: "stateful-current-merkle-metadata".to_string(),
            items_per_blob: NZU64!(11),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedLogConfig {
            partition: "stateful-current-operations".to_string(),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: "stateful-current-grafted-metadata".to_string(),
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(1_024)),
    }
}

async fn verify_through_deferred(
    deferred: &mut Deferred<
        deterministic::Context,
        simplex_ed25519::Scheme,
        commonware_glue::stateful::Mailbox<deterministic::Context, BranchingApplication>,
        Block,
        FixedEpocher,
    >,
    context: ConsensusContext,
    block: &Block,
) {
    let optimistic = deferred.verify(context.clone(), block.digest()).await;
    assert!(
        optimistic
            .await
            .expect("Deferred optimistic verdict must arrive"),
        "Deferred must accept the embedded consensus context"
    );
    let certified = deferred.certify(context.round, block.digest()).await;
    assert!(
        certified
            .await
            .expect("Deferred certified verdict must arrive"),
        "Deferred must wait for Stateful application verification"
    );
}

#[test]
fn stateful_deferred_commits_winner_and_prunes_dead_current_qmdb_fork() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let private_key = ed25519::PrivateKey::from_seed(0x5241_4348_4554);
        let public_key = private_key.public_key();
        let participants = Set::try_from(vec![public_key.clone()])
            .expect("the one-node spike committee must be unique");
        let scheme = simplex_ed25519::Scheme::signer(NAMESPACE, participants, private_key)
            .expect("the local Ed25519 key must belong to the committee");
        let provider = ConstantProvider::new(scheme.clone());

        let (network, oracle) = Network::new_with_peers(
            context.child("stateful_network"),
            NetworkConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            vec![public_key.clone()],
        )
        .await;
        network.start();
        let control = oracle.control(public_key.clone());
        let backfill_network = control
            .register(0, NETWORK_QUOTA)
            .await
            .expect("marshal resolver channel registration must succeed");
        let qmdb_network = control
            .register(1, NETWORK_QUOTA)
            .await
            .expect("QMDB resolver channel registration must succeed");

        let marshal_resolver = new_marshal_resolver(
            context.child("marshal_resolver"),
            public_key.clone(),
            oracle.manager(),
            oracle.control(public_key.clone()),
            backfill_network,
        );

        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let finalizations = immutable::Archive::init(
            context.child("finalizations"),
            archive_config(
                page_cache.clone(),
                "stateful-finalizations",
                scheme.certificate_codec_config(),
            ),
        )
        .await
        .expect("finalization archive must initialize");
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(page_cache.clone(), "stateful-blocks", ()),
        )
        .await
        .expect("finalized-block archive must initialize");

        let initial_target =
            <CurrentDatabaseSet as DatabaseSet<deterministic::Context>>::initial_sync_targets();
        let genesis = Block::genesis(initial_target, public_key.clone());
        let partition_prefix = "stateful-current-spike".to_string();
        let plan =
            SyncPlan::init(&context.child("stateful_startup"), partition_prefix.clone()).await;
        let marshal_start = plan.marshal_start(genesis.clone());
        let (marshal_actor, marshal_mailbox, _) =
            MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations,
                finalized_blocks,
                marshal::Config {
                    provider,
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: marshal_start,
                    partition_prefix,
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

        let application = BranchingApplication {
            genesis: genesis.clone(),
        };
        let (stateful_actor, mut stateful_mailbox) = Stateful::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config: qmdb_config(page_cache),
                input_provider: VecDeque::from([
                    winner_value(),
                    loser_value(),
                    loser_child_value(),
                    post_finalize_value(),
                ]),
                marshal: marshal_mailbox.clone(),
                mailbox_size: STANDARD_MARSHAL_MAILBOX_SIZE,
                plan,
                resolvers: qmdb_sync_resolver,
                sync_config: state_sync_engine_config(),
                prune_config: None,
            },
        );

        marshal_actor.start_unbuffered(stateful_mailbox.clone(), marshal_resolver);
        stateful_actor.start();
        let mut deferred = new_deferred_application(
            context.child("deferred"),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );

        let winner_context = consensus_context(
            View::new(1),
            View::zero(),
            genesis.digest(),
            public_key.clone(),
        );
        let winner = stateful_mailbox
            .propose(
                (context.child("winner_proposal"), winner_context.clone()),
                ancestry::from_iter([Arc::new(genesis.clone())]),
            )
            .await
            .expect("the winning speculative branch must be proposed");

        let loser_context = consensus_context(
            View::new(2),
            View::zero(),
            genesis.digest(),
            public_key.clone(),
        );
        let loser = stateful_mailbox
            .propose(
                (context.child("loser_proposal"), loser_context.clone()),
                ancestry::from_iter([Arc::new(genesis.clone())]),
            )
            .await
            .expect("the competing speculative branch must be proposed");
        assert_ne!(
            winner.state_root, loser.state_root,
            "competing current-QMDB mutations must merkleize to different canonical roots"
        );

        let loser_child_context = consensus_context(
            View::new(3),
            View::new(2),
            loser.digest(),
            public_key.clone(),
        );
        let loser_child = stateful_mailbox
            .propose(
                (
                    context.child("loser_child_proposal"),
                    loser_child_context.clone(),
                ),
                ancestry::from_iter([Arc::new(loser.clone()), Arc::new(genesis.clone())]),
            )
            .await
            .expect("Stateful must fork a child batch from the losing pending tip");
        assert_eq!(loser_child.parent(), loser.digest());

        assert!(
            marshal_mailbox
                .verified(winner_context.round, winner.clone())
                .await,
            "marshal must persist the winning candidate"
        );
        assert!(
            marshal_mailbox
                .verified(loser_context.round, loser.clone())
                .await,
            "marshal must persist the losing candidate for Deferred verification"
        );
        verify_through_deferred(&mut deferred, winner_context.clone(), &winner).await;
        verify_through_deferred(&mut deferred, loser_context.clone(), &loser).await;

        let (acknowledgement, acknowledged) = commonware_utils::acknowledgement::Exact::handle();
        assert!(
            deferred
                .report(Update::Block(Arc::new(winner.clone()), acknowledgement))
                .accepted(),
            "the winning finalization must traverse Deferred into Stateful"
        );
        acknowledged
            .await
            .expect("Stateful must acknowledge after durable QMDB finalization");

        let (duplicate_acknowledgement, duplicate_acknowledged) =
            commonware_utils::acknowledgement::Exact::handle();
        assert!(
            deferred
                .report(Update::Block(
                    Arc::new(winner.clone()),
                    duplicate_acknowledgement,
                ))
                .accepted(),
            "at-least-once duplicate delivery must be accepted"
        );
        duplicate_acknowledged
            .await
            .expect("duplicate finalization must be acknowledged without reapplying state");

        let databases = stateful_mailbox.subscribe_databases().await;
        let committed = databases
            .read()
            .await
            .get(&state_key())
            .await
            .expect("committed current-QMDB state must be readable");
        assert_eq!(
            committed,
            Some(winner_value()),
            "only the winning branch mutation may reach committed QMDB state"
        );
        assert_eq!(
            databases.read().await.root(),
            winner.state_root,
            "the committed current-QMDB canonical root must match the winning block"
        );

        let post_finalize_context =
            consensus_context(View::new(4), View::new(2), loser.digest(), public_key);
        let post_finalize = stateful_mailbox
            .propose(
                (context.child("post_finalize_loser"), post_finalize_context),
                ancestry::from_iter([Arc::new(loser), Arc::new(genesis)]),
            )
            .await;
        assert!(
            post_finalize.is_none(),
            "a child of the finalized-away branch must fail after Stateful prunes its pending batch"
        );
    });
}
