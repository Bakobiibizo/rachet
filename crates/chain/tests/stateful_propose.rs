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
use futures::stream;
use rachet_chain::application::{
    GenesisMetadata, GenesisState, ProposalActionSource, StatefulApplication,
    state::QmdbStateDatabase,
};
use rachet_core::{
    actions::{Action, CommitmentSubject, CreateCommitment, SignedAction},
    blocks::action_root,
    limits::{ProtocolLimits, ProtocolLimitsConfig},
    mechanisms::{
        CanonicalMechanismConfig, GenesisConfig, GenesisProtocolConfig, MechanismId,
        MechanismSelection, MechanismVersion,
    },
    primitives::{ActorId, ChainId, ClaimId, ProtocolVersion, Sha256Digest},
};
use std::{num::NonZeroU16, num::NonZeroUsize, sync::Arc};

const PAGE_SIZE: NonZeroU16 = NZU16!(1_024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2_048);
const CHAIN_ID: ChainId = ChainId::new([0x52; 32]);

type TestDb = QmdbStateDatabase<deterministic::Context>;
type TestDatabases = Shared<TestDb>;
type CodecConfig = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()));

fn database_config(
    page_cache: CacheRef,
    prefix: &str,
) -> VariableConfig<OneCap, CodecConfig, Sequential> {
    VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}_merkle_journal"),
            metadata_partition: format!("{prefix}_merkle_metadata"),
            items_per_blob: NZU64!(11),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: VariableJournalConfig {
            partition: format!("{prefix}_operations"),
            items_per_section: NZU64!(7),
            compression: None,
            codec_config: ((RangeCfg::new(1..), ()), (RangeCfg::new(..), ())),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: format!("{prefix}_grafted_metadata"),
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
        GenesisMetadata::new(1_725_000_000_123, b"proposal genesis".to_vec()).unwrap(),
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

fn consensus_context(
    view: u64,
    parent_view: u64,
    parent: Sha256Digest,
    leader: ed25519::PublicKey,
) -> ConsensusContext<Sha256Digest, ed25519::PublicKey> {
    ConsensusContext {
        round: Round::new(Epoch::zero(), View::new(view)),
        leader,
        parent: (View::new(parent_view), parent),
    }
}

#[test]
fn proposals_are_ordered_reproducible_committed_and_stateful_across_children() {
    deterministic::Runner::default().start(|context| async move {
        let cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut database = TestDb::init(
            context.child("stateful_propose"),
            database_config(cache, "stateful_propose"),
        )
        .await
        .unwrap();
        let leader = ed25519::PrivateKey::from_seed(901).public_key();
        let mut application =
            StatefulApplication::bootstrap(&mut database, genesis_state(), leader.clone())
                .await
                .unwrap();
        let genesis = Arc::new(application.genesis_block().clone());
        let genesis_digest = genesis.digest();
        let genesis_root = database.root();
        let databases = Arc::new(TracedAsyncRwLock::new("proposal-test", database));

        let low = signed_commitment(1, 0, 1);
        let high = signed_commitment(2, 0, 2);
        let mut canonical = vec![low.clone(), high.clone()];
        canonical.sort_unstable_by(|left, right| {
            (&left.actor, left.nonce, left.action_id()).cmp(&(
                &right.actor,
                right.nonce,
                right.action_id(),
            ))
        });
        let context_one = consensus_context(1, 0, genesis_digest, leader.clone());
        let first_batches =
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases).await;
        let second_batches =
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases).await;
        let mut first_input: Box<dyn ProposalActionSource> =
            Box::new(vec![high.clone(), low.clone()]);
        let mut second_input: Box<dyn ProposalActionSource> = Box::new(vec![low, high]);

        let first = <StatefulApplication as Application<deterministic::Context>>::propose(
            &mut application,
            (context.child("first"), context_one.clone()),
            stream::iter([genesis.clone()]),
            first_batches,
            &mut first_input,
        )
        .await
        .unwrap();
        let second = <StatefulApplication as Application<deterministic::Context>>::propose(
            &mut application,
            (context.child("second"), context_one),
            stream::iter([genesis.clone()]),
            second_batches,
            &mut second_input,
        )
        .await
        .unwrap();

        assert_eq!(first.block, second.block);
        assert_eq!(first.merkleized.root(), second.merkleized.root());
        assert_eq!(first.block.protocol().actions.as_slice(), canonical);
        assert_eq!(
            first.block.protocol().header.action_root,
            action_root(&canonical)
        );
        assert_ne!(
            first.block.protocol().header.receipt_root,
            genesis.protocol().header.receipt_root
        );
        assert_eq!(first.block.qmdb_state_root(), first.merkleized.root());
        assert_eq!(
            first.block.protocol().header.parent_state_root,
            genesis.protocol().header.post_state_root
        );
        assert_ne!(
            first.block.protocol().header.post_state_root,
            genesis.protocol().header.post_state_root
        );
        assert_eq!(databases.read().await.root(), genesis_root);

        let first_block = Arc::new(first.block.clone());
        let child_batches =
            <TestDatabases as DatabaseSet<deterministic::Context>>::fork_batches(&first.merkleized);
        let follow_up = signed_commitment(1, 1, 3);
        let mut child_input: Box<dyn ProposalActionSource> = Box::new(vec![follow_up.clone()]);
        let child_context = consensus_context(
            2,
            first_block.context().round.view().get(),
            first_block.digest(),
            leader.clone(),
        );
        let child = <StatefulApplication as Application<deterministic::Context>>::propose(
            &mut application,
            (context.child("child"), child_context),
            stream::iter([first_block]),
            child_batches,
            &mut child_input,
        )
        .await
        .expect("the child must reload nonce and canonical state from its supplied batch");
        assert_eq!(child.block.protocol().header.height, 2);
        assert_eq!(child.block.protocol().actions.as_slice(), &[follow_up]);

        let invalid_batches =
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases).await;
        let invalid = SignedAction::sign(
            &ed25519::PrivateKey::from_seed(7),
            ProtocolVersion::V1,
            ChainId::new([0xff; 32]),
            0,
            100,
            Action::CreateCommitment(CreateCommitment {
                subject: CommitmentSubject::Claim(ClaimId::derive(b"invalid")),
                digest: Sha256Digest::from([7; 32]),
                reveal_after_height: 10,
                reveal_before_height: 20,
            }),
        )
        .unwrap();
        let mut invalid_input: Box<dyn ProposalActionSource> = Box::new(vec![invalid]);
        let rejected = <StatefulApplication as Application<deterministic::Context>>::propose(
            &mut application,
            (
                context.child("invalid"),
                consensus_context(1, 0, genesis_digest, leader),
            ),
            stream::iter([genesis]),
            invalid_batches,
            &mut invalid_input,
        )
        .await;
        assert!(rejected.is_none());
        assert_eq!(databases.read().await.root(), genesis_root);
    });
}

#[test]
fn configured_action_limit_selects_only_the_canonical_prefix() {
    let first = signed_commitment(11, 0, 1);
    let second = signed_commitment(12, 0, 2);
    let mut config = ProtocolLimitsConfig::V1;
    config.actions_per_block = 1;
    let selected = rachet_chain::application::select_proposal_actions(
        vec![second, first],
        ProtocolLimits::new(config).unwrap(),
    );
    assert_eq!(selected.len(), 1);
}
