use commonware_codec::{Decode as _, Encode as _, RangeCfg};
use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519};
use commonware_glue::stateful::Application;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::variable::Config as VariableJournalConfig,
    merkle::full::Config as MerkleConfig, qmdb::current::VariableConfig, translator::OneCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use futures::StreamExt as _;
use rachet_chain::application::{
    GenesisMetadata, GenesisState, StatefulApplication, state::QmdbStateDatabase,
};
use rachet_core::{
    limits::{ProtocolLimits, ProtocolLimitsConfig},
    mechanisms::{
        CanonicalMechanismConfig, GenesisConfig, GenesisProtocolConfig, MechanismId,
        MechanismSelection, MechanismVersion,
    },
    primitives::{ActorId, ChainId},
    state::{StateKey, StateNamespace},
};

const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1_024);
const PAGE_CACHE_SIZE: std::num::NonZeroUsize = NZUsize!(8);
const IO_BUFFER_SIZE: std::num::NonZeroUsize = NZUsize!(2_048);

type TestDb = QmdbStateDatabase<deterministic::Context>;
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

fn selection(id: MechanismId, config: &[u8]) -> MechanismSelection {
    MechanismSelection::new(
        id,
        MechanismVersion::V1_0_0,
        CanonicalMechanismConfig::new(config.to_vec()).unwrap(),
    )
}

fn genesis_state(authorities: Vec<ActorId>) -> GenesisState {
    let protocol = GenesisConfig::new(
        GenesisProtocolConfig::V1,
        vec![
            selection(MechanismId::M00, &[]),
            selection(MechanismId::M01, &[]),
        ],
    )
    .unwrap();
    GenesisState::new(
        ChainId::new([0x52; 32]),
        protocol,
        ProtocolLimits::V1,
        GenesisMetadata::new(1_725_000_000_123, b"rachet core v1 genesis".to_vec()).unwrap(),
        authorities,
    )
    .unwrap()
}

async fn entries(database: &TestDb) -> Vec<(Vec<u8>, Vec<u8>)> {
    let stream = database.stream_range(Vec::new()).await.unwrap();
    futures::pin_mut!(stream);
    let mut entries = Vec::new();
    while let Some(entry) = stream.next().await {
        entries.push(entry.unwrap());
    }
    entries
}

#[test]
fn genesis_is_deterministic_committed_and_conformance_locked() {
    deterministic::Runner::default().start(|context| async move {
        let cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut first = TestDb::init(
            context.child("genesis_first"),
            database_config(cache.clone(), "genesis_first"),
        )
        .await
        .unwrap();
        let mut second = TestDb::init(
            context.child("genesis_second"),
            database_config(cache, "genesis_second"),
        )
        .await
        .unwrap();
        let leader = ed25519::PrivateKey::from_seed(90).public_key();
        let authorities = vec![actor(12), actor(11)];

        let first_app = StatefulApplication::bootstrap(
            &mut first,
            genesis_state(authorities.clone()),
            leader.clone(),
        )
        .await
        .unwrap();
        let second_app =
            StatefulApplication::bootstrap(&mut second, genesis_state(authorities), leader)
                .await
                .unwrap();

        let first_bytes = first_app.genesis_block().encode();
        assert_eq!(first_bytes, second_app.genesis_block().encode());
        assert_eq!(first.root(), second.root());
        assert_eq!(first.root(), first_app.genesis_block().qmdb_state_root());
        assert_eq!(first_app.genesis_block().protocol().header.height, 0);
        assert_eq!(first_app.genesis_block().protocol().header.epoch, 0);
        assert_eq!(first_app.genesis_block().protocol().actions.len(), 0);

        let stored = entries(&first).await;
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].0, StateKey::protocol_config().as_bytes());
        assert_eq!(stored[1].0, StateKey::protocol_epoch().as_bytes());
        assert_eq!(stored[1].1, 0_u64.to_be_bytes());
        let decoded = GenesisState::decode_cfg(stored[0].1.as_slice(), &()).unwrap();
        assert_eq!(decoded, *first_app.genesis_state());
        assert!(stored.iter().all(|(key, _)| matches!(
            StateKey::from_canonical_bytes(key).unwrap().namespace(),
            StateNamespace::ProtocolConfig | StateNamespace::ProtocolEpoch
        )));

        let mut clone = first_app.clone();
        let trait_genesis =
            <StatefulApplication as Application<deterministic::Context>>::genesis(&mut clone).await;
        assert_eq!(trait_genesis, *first_app.genesis_block());

        let bytes_hash = Sha256::hash(&first_bytes);
        assert_eq!(
            bytes_hash.as_ref(),
            [
                0xe1, 0xb8, 0x3b, 0xd3, 0x43, 0x3f, 0x69, 0xe8, 0xc4, 0x1a, 0xe1, 0x32, 0x1b, 0x56,
                0xba, 0x6d, 0x9d, 0x93, 0x91, 0x2f, 0xab, 0xb6, 0xdb, 0x73, 0x25, 0x38, 0x8f, 0xeb,
                0x7d, 0xa5, 0x92, 0x76,
            ]
        );
        assert_eq!(
            first.root().as_ref(),
            [
                0xcb, 0xd6, 0xfa, 0x1f, 0x4b, 0xa5, 0x3f, 0x65, 0xa6, 0x9d, 0x37, 0xc5, 0xf6, 0x02,
                0x20, 0x2c, 0x67, 0x00, 0xd4, 0x56, 0x0c, 0x06, 0xd0, 0x1e, 0x3c, 0x65, 0x87, 0xeb,
                0xeb, 0x61, 0xbc, 0xfa,
            ]
        );
    });
}

#[test]
fn invalid_mechanism_protocol_and_authority_inputs_fail_before_startup() {
    let metadata = || GenesisMetadata::new(0, Vec::new()).unwrap();
    let chain = ChainId::new([7; 32]);

    let invalid_config = GenesisConfig::new(
        GenesisProtocolConfig::V1,
        vec![selection(MechanismId::M00, &[1])],
    )
    .unwrap();
    let error = GenesisState::new(
        chain,
        invalid_config,
        ProtocolLimits::V1,
        metadata(),
        vec![actor(1)],
    )
    .unwrap_err();
    assert_eq!(error.code(), "M00_CONFIG_NONEMPTY");

    let invalid_version = GenesisConfig::new(
        GenesisProtocolConfig::V1,
        vec![MechanismSelection::new(
            MechanismId::M01,
            MechanismVersion::new(1, 0, 1),
            CanonicalMechanismConfig::empty(),
        )],
    )
    .unwrap();
    let error = GenesisState::new(
        chain,
        invalid_version,
        ProtocolLimits::V1,
        metadata(),
        vec![actor(1)],
    )
    .unwrap_err();
    assert_eq!(error.code(), "MECHANISM_VERSION_UNSUPPORTED");

    let protocol = GenesisConfig::new(
        GenesisProtocolConfig::V1,
        vec![selection(MechanismId::M00, &[])],
    )
    .unwrap();
    assert_eq!(
        GenesisState::new(
            chain,
            protocol.clone(),
            ProtocolLimits::V1,
            metadata(),
            Vec::new(),
        )
        .unwrap_err()
        .code(),
        "GENESIS_AUTHORITY_EMPTY"
    );
    assert_eq!(
        GenesisState::new(
            chain,
            protocol.clone(),
            ProtocolLimits::V1,
            metadata(),
            vec![actor(2), actor(2)],
        )
        .unwrap_err()
        .code(),
        "GENESIS_AUTHORITY_DUPLICATE"
    );

    let mut limits = ProtocolLimitsConfig::V1;
    limits.actions_per_block = 1;
    assert_eq!(
        GenesisState::new(
            chain,
            protocol,
            ProtocolLimits::new(limits).unwrap(),
            metadata(),
            vec![actor(2)],
        )
        .unwrap_err()
        .code(),
        "GENESIS_PROTOCOL_LIMIT_MISMATCH"
    );
}

#[test]
fn consensus_key_conflicts_and_nonempty_databases_are_rejected() {
    deterministic::Runner::default().start(|context| async move {
        let cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut database = TestDb::init(
            context.child("genesis_rejections"),
            database_config(cache, "genesis_rejections"),
        )
        .await
        .unwrap();
        let leader = ed25519::PrivateKey::from_seed(40).public_key();
        let conflicting = genesis_state(vec![ActorId::from(leader.clone())]);
        let error = StatefulApplication::bootstrap(&mut database, conflicting, leader.clone())
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), "GENESIS_AUTHORITY_ROLE_CONFLICT");

        StatefulApplication::bootstrap(
            &mut database,
            genesis_state(vec![actor(41)]),
            leader.clone(),
        )
        .await
        .unwrap();
        let error =
            StatefulApplication::bootstrap(&mut database, genesis_state(vec![actor(41)]), leader)
                .await
                .err()
                .unwrap();
        assert_eq!(error.code(), "GENESIS_DATABASE_NOT_EMPTY");
    });
}
