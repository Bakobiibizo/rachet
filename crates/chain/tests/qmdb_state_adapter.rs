use commonware_codec::RangeCfg;
use commonware_cryptography::{Signer as _, ed25519, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::variable::Config as VariableJournalConfig,
    merkle::full::Config as MerkleConfig, qmdb::current::VariableConfig, translator::OneCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use futures::StreamExt as _;
use rachet_chain::application::state::{QmdbStateBatch, QmdbStateDatabase};
use rachet_core::{
    primitives::{
        ActorId, AttestationId, ChallengeId, ClaimId, CommitmentId, EvidenceId, JobId, Sha256Digest,
    },
    state::{InMemoryStateBatch, MechanismNamespace, StateBatch, StateKey},
};

const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1_024);
const PAGE_CACHE_SIZE: std::num::NonZeroUsize = NZUsize!(8);
const IO_BUFFER_SIZE: std::num::NonZeroUsize = NZUsize!(2_048);

type TestDb = QmdbStateDatabase<deterministic::Context>;

type CodecConfig = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()));

fn config(page_cache: CacheRef, prefix: &str) -> VariableConfig<OneCap, CodecConfig, Sequential> {
    VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-merkle-journal"),
            metadata_partition: format!("{prefix}-merkle-metadata"),
            items_per_blob: NZU64!(11),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: VariableJournalConfig {
            partition: format!("{prefix}-operations"),
            items_per_section: NZU64!(7),
            compression: None,
            codec_config: ((RangeCfg::new(1..), ()), (RangeCfg::new(..), ())),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: format!("{prefix}-grafted-metadata"),
        translator: OneCap,
        init_cache_size: Some(NZUsize!(1_024)),
    }
}

fn actor(seed: u64) -> ActorId {
    ActorId::from(ed25519::PrivateKey::from_seed(seed).public_key())
}

fn digest(byte: u8) -> Sha256Digest {
    Digest::from([byte; 32])
}

fn every_namespace_key() -> Vec<StateKey> {
    let actor = actor(7);
    let job = JobId::from_digest(digest(0x10));
    let claim = ClaimId::from_digest(digest(0x11));
    let attestation = AttestationId::from_digest(digest(0x13));
    vec![
        StateKey::account(&actor),
        StateKey::job(&job),
        StateKey::claim(&claim),
        StateKey::evidence(&EvidenceId::from_digest(digest(0x12))),
        StateKey::attestation(&attestation),
        StateKey::commitment(&CommitmentId::from_digest(digest(0x14))),
        StateKey::challenge(&ChallengeId::from_digest(digest(0x15))),
        StateKey::job_by_customer(&actor, &job),
        StateKey::attestation_by_operator(&actor, &attestation),
        StateKey::claim_by_job(&job, &claim),
        StateKey::mechanism(MechanismNamespace::new(0x1234), &[0x00, 0xff]),
        StateKey::protocol_config(),
        StateKey::protocol_epoch(),
    ]
}

fn transition(state: &mut dyn StateBatch, reverse: bool) {
    let mut keys = every_namespace_key();
    if reverse {
        keys.reverse();
    }
    for (index, key) in keys.into_iter().enumerate() {
        state.put(key, vec![index as u8; index + 1].into_boxed_slice());
    }

    state.fork();
    state.delete(&StateKey::protocol_config());
    state.put(StateKey::protocol_epoch(), b"rolled-back".as_slice().into());
    state.rollback().unwrap();

    state.fork();
    state.put(
        StateKey::protocol_epoch(),
        42_u64.to_be_bytes().as_slice().into(),
    );
    state.put(
        StateKey::mechanism(MechanismNamespace::new(0x1234), &[0x00, 0xff]),
        b"committed".as_slice().into(),
    );
    state.commit().unwrap();
}

async fn commit_adapter(db: &mut TestDb, adapter: QmdbStateBatch) -> (Sha256Digest, Sha256Digest) {
    let commit = adapter.finish().unwrap();
    let expected_logical_root = commit.logical_root();
    assert!(
        commit
            .updates()
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
    );

    let (batch, logical_root) = commit.write_to(db.new_batch());
    assert_eq!(logical_root, expected_logical_root);
    let merkleized = batch.merkleize(db, None).await.unwrap();
    let qmdb_root = merkleized.root();
    db.apply_batch(merkleized).await.unwrap();
    db.commit().await.unwrap();
    assert_eq!(db.root(), qmdb_root);
    (logical_root, qmdb_root)
}

async fn streamed_entries(db: &TestDb) -> Vec<(Vec<u8>, Vec<u8>)> {
    let stream = db.stream_range(Vec::new()).await.unwrap();
    futures::pin_mut!(stream);
    let mut entries = Vec::new();
    while let Some(entry) = stream.next().await {
        entries.push(entry.unwrap());
    }
    entries
}

#[test]
fn pure_state_semantics_and_qmdb_roots_are_equivalent() {
    deterministic::Runner::default().start(|context| async move {
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut first = TestDb::init(
            context.child("first_db"),
            config(page_cache.clone(), "qmdb-state-first"),
        )
        .await
        .unwrap();
        let mut second = TestDb::init(
            context.child("second_db"),
            config(page_cache, "qmdb-state-second"),
        )
        .await
        .unwrap();

        let mut memory = InMemoryStateBatch::new();
        let mut adapter = QmdbStateBatch::new();
        transition(&mut memory, false);
        transition(&mut adapter, false);
        assert_eq!(adapter.entries(), memory.entries());
        assert_eq!(adapter.root(), memory.root());

        let (logical_root, first_qmdb_root) = commit_adapter(&mut first, adapter).await;
        assert_eq!(logical_root, memory.root());

        let stored = streamed_entries(&first).await;
        let expected: Vec<_> = memory
            .entries()
            .into_iter()
            .map(|(key, value)| (key.into_bytes().into_vec(), value.into_vec()))
            .collect();
        assert_eq!(stored, expected);
        assert_eq!(stored.len(), every_namespace_key().len());

        // QMDB mutation order cannot affect either root. Values differ by
        // insertion position unless the transition assigns before reversal,
        // so replay the exact final snapshot in reverse order here.
        let mut reverse = QmdbStateBatch::new();
        for (key, value) in memory.entries().into_iter().rev() {
            reverse.put(key, value);
        }
        let (second_logical_root, second_qmdb_root) = commit_adapter(&mut second, reverse).await;
        assert_eq!(second_logical_root, logical_root);
        assert_eq!(second_qmdb_root, first_qmdb_root);
    });
}

#[test]
fn streamed_parent_updates_and_rollbacks_preserve_exact_keys() {
    deterministic::Runner::default().start(|context| async move {
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut db = TestDb::init(
            context.child("database"),
            config(page_cache, "qmdb-state-parent"),
        )
        .await
        .unwrap();

        let mut initial = QmdbStateBatch::new();
        transition(&mut initial, false);
        commit_adapter(&mut db, initial).await;
        let parent_entries = streamed_entries(&db).await;

        let mut memory = InMemoryStateBatch::new();
        for (key, value) in &parent_entries {
            memory.put(
                StateKey::from_canonical_bytes(key).unwrap(),
                value.clone().into_boxed_slice(),
            );
        }
        let mut adapter = QmdbStateBatch::from_qmdb_entries(parent_entries).unwrap();

        let deleted = StateKey::challenge(&ChallengeId::from_digest(digest(0x15)));
        adapter.fork();
        adapter.delete(&deleted);
        adapter.put(StateKey::protocol_config(), b"discarded".as_slice().into());
        adapter.rollback().unwrap();
        assert!(adapter.get(&deleted).is_some());

        adapter.fork();
        memory.fork();
        adapter.delete(&deleted);
        memory.delete(&deleted);
        adapter.put(StateKey::protocol_config(), b"v2".as_slice().into());
        memory.put(StateKey::protocol_config(), b"v2".as_slice().into());
        adapter.commit().unwrap();
        memory.commit().unwrap();

        let expected = memory.entries();
        let (logical_root, _) = commit_adapter(&mut db, adapter).await;
        assert_eq!(logical_root, memory.root());
        let stored = streamed_entries(&db).await;
        let expected: Vec<_> = expected
            .into_iter()
            .map(|(key, value)| (key.into_bytes().into_vec(), value.into_vec()))
            .collect();
        assert_eq!(stored, expected);
        assert!(!stored.iter().any(|(key, _)| key == deleted.as_bytes()));
    });
}

#[test]
fn malformed_qmdb_keys_and_open_transactions_are_rejected() {
    assert!(QmdbStateBatch::from_qmdb_entries([(vec![0xff], vec![])]).is_err());

    let key = StateKey::protocol_config();
    assert!(
        QmdbStateBatch::from_qmdb_entries([
            (key.as_bytes().to_vec(), vec![1]),
            (key.as_bytes().to_vec(), vec![2]),
        ])
        .is_err()
    );

    let mut adapter = QmdbStateBatch::new();
    adapter.fork();
    assert!(adapter.finish().is_err());
}
