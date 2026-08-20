use commonware_codec::RangeCfg;
use commonware_consensus::{
    CertifiableBlock as _,
    simplex::types::Context as ConsensusContext,
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Digestible as _, Signer as _, ed25519};
use commonware_glue::stateful::{
    Application,
    db::{DatabaseSet, Merkleized as _, Shared},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::variable::Config as VariableJournalConfig,
    merkle::full::Config as MerkleConfig, qmdb::current::VariableConfig, translator::OneCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, sync::TracedAsyncRwLock};
use futures::{StreamExt as _, stream};
use rachet_chain::application::{
    GenesisMetadata, GenesisState, ProposalActionSource, StatefulApplication, StatefulBlock,
    state::QmdbStateDatabase,
};
use rachet_core::{
    actions::{Action, CommitmentSubject, CreateCommitment, SignedAction},
    limits::ProtocolLimits,
    mechanisms::{
        CanonicalMechanismConfig, GenesisConfig, GenesisProtocolConfig, MechanismId,
        MechanismSelection, MechanismVersion,
    },
    primitives::{ActorId, ChainId, ClaimId, ProtocolVersion, Sha256Digest},
    state::StateKey,
};
use std::{num::NonZeroU16, num::NonZeroUsize, sync::Arc};

const PAGE_SIZE: NonZeroU16 = NZU16!(1_024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2_048);
const CHAIN_ID: ChainId = ChainId::new([0x52; 32]);
const PARTITION: &str = "stateful_apply_recovery";

type TestDb = QmdbStateDatabase<deterministic::Context>;
type TestDatabases = Shared<TestDb>;
type CodecConfig = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()));

fn database_config(page_cache: CacheRef) -> VariableConfig<OneCap, CodecConfig, Sequential> {
    VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{PARTITION}_merkle_journal"),
            metadata_partition: format!("{PARTITION}_merkle_metadata"),
            items_per_blob: NZU64!(11),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: VariableJournalConfig {
            partition: format!("{PARTITION}_operations"),
            items_per_section: NZU64!(7),
            compression: None,
            codec_config: ((RangeCfg::new(1..), ()), (RangeCfg::new(..), ())),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: format!("{PARTITION}_grafted_metadata"),
        translator: OneCap,
        init_cache_size: Some(NZUsize!(1_024)),
    }
}

fn actor(seed: u64) -> ActorId {
    ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
}

fn genesis_state() -> GenesisState {
    let mechanism = MechanismSelection::new(
        MechanismId::M00,
        MechanismVersion::V1_0_0,
        CanonicalMechanismConfig::empty(),
    );
    let protocol = GenesisConfig::new(GenesisProtocolConfig::V1, vec![mechanism]).unwrap();
    GenesisState::new(
        CHAIN_ID,
        protocol,
        ProtocolLimits::V1,
        GenesisMetadata::new(1_725_000_000_123, b"recovery genesis".to_vec()).unwrap(),
        vec![actor(900)],
    )
    .unwrap()
}

fn signed_commitment(seed: u64, nonce: u64, subject: u8) -> SignedAction<Action> {
    SignedAction::sign(
        &ed25519::PrivateKey::from_seed(seed),
        ProtocolVersion::V1,
        CHAIN_ID,
        nonce,
        100,
        Action::CreateCommitment(CreateCommitment {
            subject: CommitmentSubject::Claim(ClaimId::derive(&[subject])),
            digest: Sha256Digest::from([subject; 32]),
            reveal_after_height: 10,
            reveal_before_height: 20,
        }),
    )
    .unwrap()
}

fn commitment_key(action: &SignedAction<Action>) -> StateKey {
    let Action::CreateCommitment(commitment) = &action.payload else {
        panic!("recovery fixture must contain commitment actions");
    };
    StateKey::commitment(&commitment.commitment_id(&action.actor))
}

fn consensus_context(
    view: u64,
    parent: &StatefulBlock,
    leader: ed25519::PublicKey,
) -> ConsensusContext<Sha256Digest, ed25519::PublicKey> {
    ConsensusContext {
        round: Round::new(Epoch::zero(), View::new(view)),
        leader,
        parent: (parent.context().round.view(), parent.digest()),
    }
}

#[test]
fn restart_replays_missing_fork_ancestry_and_finalizes_only_the_winner() {
    deterministic::Runner::default().start(|context| async move {
        let cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut database = TestDb::init(
            context.child("initial_database"),
            database_config(cache.clone()),
        )
        .await
        .unwrap();
        let leader = ed25519::PrivateKey::from_seed(901).public_key();
        let mut application =
            StatefulApplication::bootstrap(&mut database, genesis_state(), leader.clone())
                .await
                .unwrap();
        let genesis = Arc::new(application.genesis_block().clone());
        let genesis_root = database.root();
        let databases = Arc::new(TracedAsyncRwLock::new("recovery-initial", database));

        let winner_action = signed_commitment(1, 0, 1);
        let loser_action = signed_commitment(2, 0, 2);
        let child_action = signed_commitment(1, 1, 3);
        let first_context = consensus_context(1, &genesis, leader.clone());

        let mut winner_input: Box<dyn ProposalActionSource> = Box::new(vec![winner_action.clone()]);
        let winner = <StatefulApplication as Application<deterministic::Context>>::propose(
            &mut application,
            (context.child("propose_winner"), first_context.clone()),
            stream::iter([genesis.clone()]),
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases).await,
            &mut winner_input,
        )
        .await
        .unwrap();
        let winner_block = Arc::new(winner.block.clone());

        let mut loser_input: Box<dyn ProposalActionSource> = Box::new(vec![loser_action.clone()]);
        let loser = <StatefulApplication as Application<deterministic::Context>>::propose(
            &mut application,
            (context.child("propose_loser"), first_context.clone()),
            stream::iter([genesis.clone()]),
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases).await,
            &mut loser_input,
        )
        .await
        .unwrap();
        let loser_block = Arc::new(loser.block.clone());

        let child_context = consensus_context(2, &winner_block, leader.clone());
        let mut child_input: Box<dyn ProposalActionSource> = Box::new(vec![child_action.clone()]);
        let child = <StatefulApplication as Application<deterministic::Context>>::propose(
            &mut application,
            (context.child("propose_child"), child_context.clone()),
            stream::iter([winner_block.clone()]),
            <TestDatabases as DatabaseSet<deterministic::Context>>::fork_batches(
                &winner.merkleized,
            ),
            &mut child_input,
        )
        .await
        .unwrap();
        let child_block = Arc::new(child.block.clone());

        let verified_winner = <StatefulApplication as Application<deterministic::Context>>::verify(
            &mut application,
            (context.child("verify_winner"), first_context.clone()),
            stream::iter([winner_block.clone(), genesis.clone()]),
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases).await,
        )
        .await
        .unwrap();
        let verified_loser = <StatefulApplication as Application<deterministic::Context>>::verify(
            &mut application,
            (context.child("verify_loser"), first_context),
            stream::iter([loser_block.clone(), genesis.clone()]),
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases).await,
        )
        .await
        .unwrap();
        let verified_child = <StatefulApplication as Application<deterministic::Context>>::verify(
            &mut application,
            (context.child("verify_child"), child_context.clone()),
            stream::iter([child_block.clone(), winner_block.clone()]),
            <TestDatabases as DatabaseSet<deterministic::Context>>::fork_batches(&verified_winner),
        )
        .await
        .unwrap();
        let winner_root = verified_winner.root();
        let loser_root = verified_loser.root();
        let child_root = verified_child.root();
        assert_ne!(winner_root, loser_root);
        assert_ne!(child_root, loser_root);
        assert_eq!(databases.read().await.root(), genesis_root);

        // Simulate process loss: no proposed or verified merkleized batch survives.
        drop(winner);
        drop(loser);
        drop(child);
        drop(verified_winner);
        drop(verified_loser);
        drop(verified_child);
        drop(databases);

        let reopened = TestDb::init(context.child("reopened_database"), database_config(cache))
            .await
            .unwrap();
        assert_eq!(reopened.root(), genesis_root);
        let reopened = Arc::new(TracedAsyncRwLock::new("recovery-reopened", reopened));
        let mut restarted_application = application.clone();
        drop(application);

        // Stateful's lazy-recovery order is oldest missing ancestor first. Rebuild both
        // competing height-one tips, then rebuild the winning tip's missing child.
        let replayed_winner = <StatefulApplication as Application<deterministic::Context>>::apply(
            &mut restarted_application,
            (context.child("replay_winner"), winner_block.context()),
            &winner_block,
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&reopened).await,
        )
        .await;
        let replayed_loser = <StatefulApplication as Application<deterministic::Context>>::apply(
            &mut restarted_application,
            (context.child("replay_loser"), loser_block.context()),
            &loser_block,
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&reopened).await,
        )
        .await;
        let replayed_child = <StatefulApplication as Application<deterministic::Context>>::apply(
            &mut restarted_application,
            (context.child("replay_child"), child_block.context()),
            &child_block,
            <TestDatabases as DatabaseSet<deterministic::Context>>::fork_batches(&replayed_winner),
        )
        .await;

        assert_eq!(replayed_winner.root(), winner_root);
        assert_eq!(replayed_loser.root(), loser_root);
        assert_eq!(replayed_child.root(), child_root);
        assert!(
            <TestDatabases as DatabaseSet<deterministic::Context>>::matches_sync_targets(
                &replayed_winner,
                &winner_block.sync_target(),
            )
        );
        assert!(
            <TestDatabases as DatabaseSet<deterministic::Context>>::matches_sync_targets(
                &replayed_loser,
                &loser_block.sync_target(),
            )
        );
        assert!(
            <TestDatabases as DatabaseSet<deterministic::Context>>::matches_sync_targets(
                &replayed_child,
                &child_block.sync_target(),
            )
        );

        // Finalization selects the winner and its descendant. Dropping the incompatible
        // pending batch models Stateful's losing-fork prune: it never reaches durable QMDB.
        drop(replayed_loser);
        <TestDatabases as DatabaseSet<deterministic::Context>>::finalize(
            &reopened,
            replayed_winner,
        )
        .await;
        assert_eq!(reopened.read().await.root(), winner_root);
        <TestDatabases as DatabaseSet<deterministic::Context>>::finalize(&reopened, replayed_child)
            .await;
        assert_eq!(reopened.read().await.root(), child_root);
        assert_eq!(
            <TestDatabases as DatabaseSet<deterministic::Context>>::committed_targets(&reopened)
                .await,
            child_block.sync_target()
        );

        let database = reopened.read().await;
        let stored = database.stream_range(Vec::new()).await.unwrap();
        futures::pin_mut!(stored);
        let mut keys = Vec::new();
        while let Some(entry) = stored.next().await {
            keys.push(entry.unwrap().0);
        }
        assert!(keys.contains(&commitment_key(&winner_action).as_bytes().to_vec()));
        assert!(keys.contains(&commitment_key(&child_action).as_bytes().to_vec()));
        assert!(!keys.contains(&commitment_key(&loser_action).as_bytes().to_vec()));
    });
}
