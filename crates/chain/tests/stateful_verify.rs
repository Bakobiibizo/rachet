use commonware_codec::{DecodeExt as _, Encode as _, EncodeSize as _, RangeCfg};
use commonware_consensus::{
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
    GenesisMetadata, GenesisState, ProposalActionSource, StatefulApplication, StatefulBlock,
    state::QmdbStateDatabase,
};
use rachet_core::{
    actions::{Action, CommitmentSubject, CreateCommitment, SignedAction},
    blocks::{Block as ProtocolBlock, BlockHeader},
    limits::ProtocolLimits,
    mechanisms::{
        CanonicalMechanismConfig, GenesisConfig, GenesisProtocolConfig, MechanismId,
        MechanismSelection, MechanismVersion,
    },
    primitives::{ActorId, ChainId, ClaimId, MechanismSetId, ProtocolVersion, Sha256Digest},
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
        GenesisMetadata::new(1_725_000_000_123, b"verification genesis".to_vec()).unwrap(),
        vec![actor(900)],
    )
    .unwrap()
}

fn signed_commitment(seed: u64, subject: u8) -> SignedAction<Action> {
    SignedAction::sign(
        &ed25519::PrivateKey::from_seed(seed),
        ProtocolVersion::V1,
        CHAIN_ID,
        0,
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
    parent: Sha256Digest,
    leader: ed25519::PublicKey,
) -> ConsensusContext<Sha256Digest, ed25519::PublicKey> {
    ConsensusContext {
        round: Round::new(Epoch::zero(), View::new(1)),
        leader,
        parent: (View::zero(), parent),
    }
}

fn replace_protocol(block: &StatefulBlock, protocol: ProtocolBlock) -> StatefulBlock {
    let encoded = block.encode();
    let mut replacement = protocol.encode().to_vec();
    replacement.extend_from_slice(&encoded[block.protocol().encode_size()..]);
    StatefulBlock::decode(replacement.as_slice()).unwrap()
}

fn with_header(block: &StatefulBlock, mutate: impl FnOnce(&mut BlockHeader)) -> StatefulBlock {
    let mut header = block.protocol().header.clone();
    mutate(&mut header);
    let protocol = ProtocolBlock::new(
        block.protocol().context.clone(),
        header,
        block.protocol().actions.as_slice().to_vec(),
    )
    .unwrap();
    replace_protocol(block, protocol)
}

fn corrupt_stateful_byte(block: &StatefulBlock, offset_after_protocol: usize) -> StatefulBlock {
    let mut encoded = block.encode().to_vec();
    let offset = block.protocol().encode_size() + offset_after_protocol;
    encoded[offset] ^= 1;
    StatefulBlock::decode(encoded.as_slice()).unwrap()
}

#[test]
fn verification_reexecutes_and_rejects_each_corrupted_commitment_without_committing() {
    deterministic::Runner::default().start(|context| async move {
        let cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut database = TestDb::init(
            context.child("stateful_verify"),
            database_config(cache, "stateful_verify"),
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
        let committed_root = database.root();
        let databases = Arc::new(TracedAsyncRwLock::new("verification-test", database));
        let consensus = consensus_context(genesis_digest, leader);

        let proposal_batches =
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases).await;
        let action = signed_commitment(1, 1);
        let mut input: Box<dyn ProposalActionSource> = Box::new(vec![action]);
        let proposed = <StatefulApplication as Application<deterministic::Context>>::propose(
            &mut application,
            (context.child("proposal"), consensus.clone()),
            stream::iter([genesis.clone()]),
            proposal_batches,
            &mut input,
        )
        .await
        .unwrap();
        let valid = Arc::new(proposed.block.clone());

        let verification_batches =
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases).await;
        let verified = <StatefulApplication as Application<deterministic::Context>>::verify(
            &mut application,
            (context.child("valid"), consensus.clone()),
            stream::iter([valid.clone(), genesis.clone()]),
            verification_batches,
        )
        .await
        .expect("a valid proposal must verify");
        assert_eq!(verified.root(), proposed.merkleized.root());
        assert_eq!(databases.read().await.root(), committed_root);

        let replacement_action = signed_commitment(2, 2);
        let corrupted_action = replace_protocol(
            &valid,
            ProtocolBlock::new(
                valid.protocol().context.clone(),
                valid.protocol().header.clone(),
                vec![replacement_action],
            )
            .unwrap(),
        );
        let mut corruptions = vec![
            ("action", corrupted_action),
            (
                "receipt root",
                with_header(&valid, |header| {
                    header.receipt_root = Sha256Digest::from([0x11; 32])
                }),
            ),
            (
                "parent block",
                with_header(&valid, |header| {
                    header.parent_block = Sha256Digest::from([0x12; 32])
                }),
            ),
            (
                "parent state root",
                with_header(&valid, |header| {
                    header.parent_state_root = Sha256Digest::from([0x13; 32])
                }),
            ),
            (
                "post-state root",
                with_header(&valid, |header| {
                    header.post_state_root = Sha256Digest::from([0x14; 32])
                }),
            ),
            (
                "action root",
                with_header(&valid, |header| {
                    header.action_root = Sha256Digest::from([0x15; 32])
                }),
            ),
            ("height", with_header(&valid, |header| header.height += 1)),
            ("epoch", with_header(&valid, |header| header.epoch += 1)),
            (
                "chain",
                with_header(&valid, |header| header.chain_id = ChainId::new([0x16; 32])),
            ),
            (
                "protocol version",
                with_header(&valid, |header| {
                    header.protocol_version = ProtocolVersion::new(2)
                }),
            ),
            (
                "mechanism set",
                with_header(&valid, |header| {
                    header.mechanism_set_id =
                        MechanismSetId::from_digest(Sha256Digest::from([0x17; 32]))
                }),
            ),
            ("QMDB state root", corrupt_stateful_byte(&valid, 0)),
            ("QMDB operations root", corrupt_stateful_byte(&valid, 32)),
        ];

        for (name, corrupted) in corruptions.drain(..) {
            let batches =
                <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases)
                    .await;
            let result = <StatefulApplication as Application<deterministic::Context>>::verify(
                &mut application,
                (context.child("invalid"), consensus.clone()),
                stream::iter([Arc::new(corrupted), genesis.clone()]),
                batches,
            )
            .await;
            assert!(result.is_none(), "corrupted {name} must be rejected");
            assert_eq!(
                databases.read().await.root(),
                committed_root,
                "rejecting corrupted {name} must not commit a batch"
            );
        }
    });
}
