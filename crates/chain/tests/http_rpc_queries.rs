use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use commonware_codec::{Encode as _, RangeCfg};
use commonware_consensus::{
    simplex::types::Context as ConsensusContext,
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Digestible as _, Signer as _, ed25519};
use commonware_glue::stateful::{
    Application,
    db::{DatabaseSet, Shared},
};
use commonware_p2p::utils::mocks::inert_channel;
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
    ingress::MAX_ACTION_JSON_BYTES,
    mempool::{PendingActionPool, PendingPoolLimits},
    persistence::{FinalizationStorageConfig, FinalizationStore},
    rpc::RpcService,
};
use rachet_core::{
    actions::{Action, ClaimDefinition, CloseJob, CreateJob, ResolutionPolicy, SignedAction},
    artifacts::{ContentRef, GitArtifact, GitHash},
    bounded::{BoundedBytes, BoundedVec},
    limits::{MAX_ACTION_BYTES, ProtocolLimits},
    mechanisms::{
        CanonicalMechanismConfig, GenesisConfig, GenesisProtocolConfig, MechanismId,
        MechanismSelection, MechanismVersion,
    },
    primitives::{ActorId, ChainId, ProtocolVersion, Sha256Digest},
};
use serde_json::{Value, json};
use std::{
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
};
use tower::ServiceExt as _;

const PAGE_SIZE: NonZeroU16 = NZU16!(1_024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(16);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(4_096);
const CHAIN_ID: ChainId = ChainId::new([0x72; 32]);
const SECRET: &[u8] = b"PRIVATE_KEY hidden-label operator-prompt evidence-body";

type TestDb = QmdbStateDatabase<deterministic::Context>;
type TestDatabases = Shared<TestDb>;
type CodecConfig = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()));

fn database_config(page_cache: CacheRef) -> VariableConfig<OneCap, CodecConfig, Sequential> {
    VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: "rpc_test_qmdb_merkle_journal".into(),
            metadata_partition: "rpc_test_qmdb_merkle_metadata".into(),
            items_per_blob: NZU64!(11),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: VariableJournalConfig {
            partition: "rpc_test_qmdb_operations".into(),
            items_per_section: NZU64!(7),
            compression: None,
            codec_config: ((RangeCfg::new(1..), ()), (RangeCfg::new(..), ())),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: "rpc_test_qmdb_grafted_metadata".into(),
        translator: OneCap,
        init_cache_size: Some(NZUsize!(1_024)),
    }
}

fn key(seed: u64) -> ed25519::PrivateKey {
    ed25519::PrivateKey::from_seed(seed)
}

fn actor(seed: u64) -> ActorId {
    ActorId::from(key(seed).public_key())
}

fn bounded<const MAX: usize>(bytes: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(bytes).unwrap()
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
        GenesisMetadata::new(1_725_000_000_123, b"RPC integration".to_vec()).unwrap(),
        vec![actor(900)],
    )
    .unwrap()
}

fn create_job() -> SignedAction<Action> {
    SignedAction::sign(
        &key(1),
        ProtocolVersion::V1,
        CHAIN_ID,
        0,
        100,
        Action::CreateJob(Box::new(CreateJob {
            artifact: GitArtifact::new(
                bounded(SECRET),
                GitHash::sha1([0x11; 20]),
                GitHash::sha256([0x22; 32]),
                ContentRef::new(
                    Sha256Digest::from([0x33; 32]),
                    bounded(SECRET),
                    bounded(b"text/private"),
                ),
            ),
            claims: BoundedVec::new(vec![ClaimDefinition::new(bounded(SECRET))]).unwrap(),
            resolution_policy: ResolutionPolicy::ExperimentAuthority {
                authority: actor(900),
            },
            validation_opens_at: 1,
            validation_closes_at: 10,
            reveal_closes_at: Some(12),
            challenge_closes_at: Some(14),
            supersedes: None,
            metadata: bounded(SECRET),
        })),
    )
    .unwrap()
}

fn pending_action(job_id: rachet_core::primitives::JobId) -> SignedAction<Action> {
    SignedAction::sign(
        &key(1),
        ProtocolVersion::V1,
        CHAIN_ID,
        1,
        100,
        Action::CloseJob(CloseJob::new(job_id)),
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn action_json(action: &SignedAction<Action>) -> Vec<u8> {
    serde_json::to_vec(&json!({"canonical_action": hex(action.encode().as_ref())})).unwrap()
}

async fn call_text(
    router: &Router,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn call(router: &Router, method: Method, path: &str, body: Vec<u8>) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[test]
fn section_20_1_endpoints_use_finalized_state_bound_ingress_and_redacted_json() {
    deterministic::Runner::default().start(|context| async move {
        let cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut database = TestDb::init(context.child("qmdb"), database_config(cache.clone()))
            .await
            .unwrap();
        let leader = key(901).public_key();
        let genesis_state = genesis_state();
        let mut application =
            StatefulApplication::bootstrap(&mut database, genesis_state.clone(), leader.clone())
                .await
                .unwrap();
        let genesis = Arc::new(application.genesis_block().clone());
        let databases = Arc::new(TracedAsyncRwLock::new("rpc-test", database));
        let batches =
            <TestDatabases as DatabaseSet<deterministic::Context>>::new_batches(&databases).await;
        let finalized_action = create_job();
        let finalized_action_id = finalized_action.action_id();
        let job_id = match &finalized_action.payload {
            Action::CreateJob(action) => action.job_id(),
            _ => unreachable!(),
        };
        let mut input: Box<dyn ProposalActionSource> = Box::new(vec![finalized_action.clone()]);
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
        let config =
            FinalizationStorageConfig::new("rpc_test", NZU64!(8), cache, IO_BUFFER_SIZE).unwrap();
        let mut store = FinalizationStore::init(
            context.child("finalization"),
            config,
            genesis_state,
            &genesis,
        )
        .await
        .unwrap();
        store
            .persist(&proposed.block, 1_725_000_000_500)
            .await
            .unwrap();

        let index = store.index();
        let pool = Arc::new(PendingActionPool::new(PendingPoolLimits::new(
            16,
            8,
            MAX_ACTION_BYTES * 4,
            2,
        )));
        let (sender, _) = inert_channel::<ed25519::PublicKey>([]);
        let router = RpcService::new(Arc::clone(&pool), index.clone(), sender).router();

        let pending = pending_action(job_id);
        let pending_id = pending.action_id();
        let (status, submitted) =
            call(&router, Method::POST, "/v1/actions", action_json(&pending)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(submitted["result"]["action_id"], hex(pending_id.as_bytes()));
        assert!(pool.contains(&pending_id));

        let mut query_bodies = Vec::new();
        for path in [
            format!("/v1/actions/{}", hex(finalized_action_id.as_bytes())),
            format!("/v1/actions/{}", hex(pending_id.as_bytes())),
            "/v1/jobs".to_owned(),
            format!("/v1/jobs/{}", hex(job_id.as_bytes())),
            format!("/v1/actors/{}", hex(actor(1).as_bytes())),
            "/v1/blocks/1".to_owned(),
            "/v1/state/root".to_owned(),
            "/v1/state/mechanisms/M00".to_owned(),
            "/v1/replay/verify".to_owned(),
            "/v1/health".to_owned(),
        ] {
            let (status, body) = call(&router, Method::GET, &path, Vec::new()).await;
            assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
            query_bodies.push(body.to_string());
        }
        assert!(query_bodies[0].contains("finalized"));
        assert!(query_bodies[1].contains("pending"));
        assert!(query_bodies[4].contains("\"next_nonce\":1"));
        assert!(query_bodies[5].contains("action_root"));
        assert!(query_bodies[7].contains("\"mechanism_id\":\"M00\""));
        assert!(query_bodies[8].contains("\"verified\":true"));
        assert!(query_bodies[9].contains("\"connected_peers\":0"));
        for body in query_bodies {
            assert!(!body.contains(std::str::from_utf8(SECRET).unwrap()));
            assert!(!body.contains("consensus_private_key"));
            assert!(!body.contains("operator_private_key"));
        }

        let (status, metrics) = call_text(&router, Method::GET, "/metrics", Vec::new()).await;
        assert_eq!(status, StatusCode::OK);
        for metric in [
            "rachet_finalized_height 1",
            "rachet_current_epoch 0",
            "rachet_finalized_state_root_info{digest=\"",
            "rachet_pending_actions 1",
            "rachet_pending_action_bytes ",
            "rachet_actions_accepted_total 1",
            "rachet_actions_rejected_total 0",
            "rachet_blocks_proposed_total 0",
            "rachet_blocks_verified_total 0",
            "rachet_blocks_rejected_total 0",
            "rachet_consensus_current_view 0",
            "rachet_consensus_timeouts_total 0",
            "rachet_connected_peers 0",
            "rachet_resolver_requests_total 0",
            "rachet_stateful_pending_branches 0",
            "rachet_qmdb_commit_duration_observations_total 0",
            "rachet_finalization_latency_milliseconds ",
            "rachet_rpc_latency_microseconds_total ",
        ] {
            assert!(metrics.contains(metric), "missing node metric {metric}");
        }
        assert!(!metrics.contains(std::str::from_utf8(SECRET).unwrap()));
        assert!(!metrics.contains("private_key"));

        let missing = "00".repeat(32);
        for (path, code) in [
            (format!("/v1/actions/{missing}"), "RPC_ACTION_NOT_FOUND"),
            (format!("/v1/jobs/{missing}"), "RPC_JOB_NOT_FOUND"),
            ("/v1/blocks/99".to_owned(), "RPC_BLOCK_NOT_FOUND"),
        ] {
            let (status, body) = call(&router, Method::GET, &path, Vec::new()).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(body["error"]["code"], code);
        }

        let (status, body) = call(&router, Method::GET, "/v1/jobs/not-hex", Vec::new()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "RPC_IDENTIFIER_MALFORMED");

        let (status, body) = call(
            &router,
            Method::POST,
            "/v1/actions",
            br#"{"canonical_action":"00","unknown":true}"#.to_vec(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "ACTION_JSON_MALFORMED");

        let (status, body) = call(
            &router,
            Method::POST,
            "/v1/actions",
            vec![b' '; MAX_ACTION_JSON_BYTES + 1],
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["error"]["code"], "ACTION_JSON_TOO_LARGE");

        let mut unauthorized = pending.clone();
        unauthorized.signature = SignedAction::sign(
            &key(2),
            ProtocolVersion::V1,
            CHAIN_ID,
            1,
            100,
            unauthorized.payload.clone(),
        )
        .unwrap()
        .signature;
        let (status, body) = call(
            &router,
            Method::POST,
            "/v1/actions",
            action_json(&unauthorized),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "ACTION_SIGNATURE_INVALID");
        assert_eq!(pool.len(), 1);

        let (status, body) = call(&router, Method::DELETE, "/v1/health", Vec::new()).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(body["error"]["code"], "RPC_METHOD_NOT_ALLOWED");
    });
}
