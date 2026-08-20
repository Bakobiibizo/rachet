use commonware_codec::{DecodeExt as _, Encode as _, EncodeSize as _, RangeCfg};
use commonware_consensus::{
    simplex::types::Context as ConsensusContext,
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Digestible as _, Signer as _, ed25519};
use commonware_glue::stateful::{
    Application,
    db::{DatabaseSet, Shared},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::variable::Config as VariableJournalConfig,
    merkle::full::Config as MerkleConfig, qmdb::current::VariableConfig, translator::OneCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, sync::TracedAsyncRwLock};
use futures::stream;
use rachet_chain::{
    application::{
        GenesisMetadata, GenesisState, ProposalActionSource, StatefulApplication,
        state::QmdbStateDatabase,
    },
    persistence::{FinalizationStorageConfig, FinalizationStore, PersistOutcome},
};
use rachet_core::{
    actions::{Action, CommitmentSubject, CreateCommitment, SignedAction},
    limits::ProtocolLimits,
    mechanisms::{
        CanonicalMechanismConfig, GenesisConfig, GenesisProtocolConfig, MechanismId,
        MechanismSelection, MechanismVersion,
    },
    primitives::{ActorId, ChainId, ClaimId, ProtocolVersion, Sha256Digest},
};
use std::{num::NonZeroU16, num::NonZeroUsize, sync::Arc};

const PAGE_SIZE: NonZeroU16 = NZU16!(1_024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(16);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(4_096);
const CHAIN_ID: ChainId = ChainId::new([0x46; 32]);

type TestDb = QmdbStateDatabase<deterministic::Context>;
type TestDatabases = Shared<TestDb>;
type CodecConfig = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()));

fn database_config(page_cache: CacheRef) -> VariableConfig<OneCap, CodecConfig, Sequential> {
    VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: "finalization_test_qmdb_merkle_journal".into(),
            metadata_partition: "finalization_test_qmdb_merkle_metadata".into(),
            items_per_blob: NZU64!(11),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: VariableJournalConfig {
            partition: "finalization_test_qmdb_operations".into(),
            items_per_section: NZU64!(7),
            compression: None,
            codec_config: ((RangeCfg::new(1..), ()), (RangeCfg::new(..), ())),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: "finalization_test_qmdb_grafted_metadata".into(),
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
    GenesisState::new(
        CHAIN_ID,
        GenesisConfig::new(GenesisProtocolConfig::V1, vec![mechanism]).unwrap(),
        ProtocolLimits::V1,
        GenesisMetadata::new(1_725_000_000_123, b"finalization persistence".to_vec()).unwrap(),
        vec![actor(900)],
    )
    .unwrap()
}

fn signed_commitment() -> SignedAction<Action> {
    SignedAction::sign(
        &ed25519::PrivateKey::from_seed(1),
        ProtocolVersion::V1,
        CHAIN_ID,
        0,
        100,
        Action::CreateCommitment(CreateCommitment {
            subject: CommitmentSubject::Claim(ClaimId::derive(b"finalized-claim")),
            digest: Sha256Digest::from([0x63; 32]),
            reveal_after_height: 10,
            reveal_before_height: 20,
        }),
    )
    .unwrap()
}

#[test]
fn finalized_receipts_are_idempotent_restart_durable_and_qmdb_indexed() {
    deterministic::Runner::default().start(|context| async move {
        let cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut database = TestDb::init(context.child("qmdb"), database_config(cache.clone()))
            .await
            .unwrap();
        let leader = ed25519::PrivateKey::from_seed(901).public_key();
        let genesis_state = genesis_state();
        let mut application =
            StatefulApplication::bootstrap(&mut database, genesis_state.clone(), leader.clone())
                .await
                .unwrap();
        let genesis = Arc::new(application.genesis_block().clone());
        let databases = Arc::new(TracedAsyncRwLock::new("finalization-test", database));
        let batches =
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases).await;
        let action = signed_commitment();
        let action_id = action.action_id();
        let mut input: Box<dyn ProposalActionSource> = Box::new(vec![action]);
        let proposed = application
            .propose(
                (
                    context.child("proposal"),
                    ConsensusContext {
                        round: Round::new(Epoch::zero(), View::new(1)),
                        leader,
                        parent: (View::zero(), genesis.digest()),
                    },
                ),
                stream::once(async { Arc::clone(&genesis) }),
                batches,
                &mut input,
            )
            .await
            .unwrap();
        let block = proposed.block;
        assert_eq!(block.protocol().header.height, 1);

        let config =
            FinalizationStorageConfig::new("finalization_test", NZU64!(8), cache, IO_BUFFER_SIZE)
                .unwrap();
        let mut first = FinalizationStore::init(
            context.child("first_open"),
            config.clone(),
            genesis_state.clone(),
            &genesis,
        )
        .await
        .unwrap();
        assert_eq!(
            first.persist(&block, 1_725_000_000_500).await.unwrap(),
            PersistOutcome::Stored
        );
        assert_eq!(
            first.persist(&block, 1_725_000_000_501).await.unwrap(),
            PersistOutcome::Duplicate
        );
        let first_index = first.index();
        let snapshot = first_index.snapshot();
        assert_eq!(snapshot.finalized_height, 1);
        assert_eq!(
            snapshot.finalized_state_root,
            block.protocol().header.post_state_root
        );
        assert_eq!(snapshot.finalized_qmdb_root, block.qmdb_state_root());
        assert_eq!(snapshot.receipt_count, 1);
        assert_eq!(first_index.receipt(&action_id).unwrap().0, 1);
        drop(first);

        let mut reopened = FinalizationStore::init_with_archive(
            context.child("second_open"),
            config.clone(),
            genesis_state.clone(),
            &genesis,
            vec![genesis.as_ref().clone(), block.clone()],
        )
        .await
        .unwrap();
        let recovered = reopened.index();
        assert_eq!(recovered.snapshot(), snapshot);
        assert_eq!(recovered.receipt(&action_id).unwrap().0, 1);
        let replay = recovered.verify_replay().unwrap();
        assert_eq!(replay.finalized_height, 1);
        assert_eq!(replay.blocks_verified, 2);
        assert_eq!(replay.state_root, snapshot.finalized_state_root);
        assert_eq!(
            reopened.persist(&block, 1_725_000_000_999).await.unwrap(),
            PersistOutcome::Duplicate
        );
        drop(reopened);

        let mut tampered_bytes = block.encode().to_vec();
        tampered_bytes[block.protocol().encode_size()] ^= 1;
        let tampered =
            rachet_chain::application::StatefulBlock::decode(tampered_bytes.as_slice()).unwrap();
        let tampered_store = FinalizationStore::init_with_archive(
            context.child("tampered_open"),
            config,
            genesis_state,
            &genesis,
            vec![genesis.as_ref().clone(), tampered],
        )
        .await
        .unwrap();
        let mismatch = tampered_store.index().verify_replay().unwrap_err();
        assert_eq!(mismatch.height, 1);
        assert_eq!(mismatch.field, "block_id");
        assert_ne!(mismatch.expected, mismatch.actual);
    });
}
