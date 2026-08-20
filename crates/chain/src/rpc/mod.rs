//! Bounded HTTP/JSON action ingress and finalized-state queries.
//!
//! JSON values are explicit transport projections. Canonical bytes remain the
//! only consensus encoding, and responses whitelist public fields rather than
//! serializing consensus records or local node configuration.

use crate::{
    ingress::{ActionIngress, IngressError, MAX_ACTION_JSON_BYTES},
    mempool::{InsertOutcome, PendingActionPool},
    observability::{NodeMetrics, RuntimeMetricsExporter},
    persistence::{FinalizedBlockSummary, FinalizedQueryIndex},
};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Path, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
};
use commonware_codec::Decode as _;
use commonware_cryptography::{ed25519, sha256::Digest};
use commonware_p2p::Sender;
use rachet_core::{
    actions::ResolutionPolicy,
    artifacts::GitHash,
    events::CanonicalEvent,
    mechanisms::MechanismId,
    primitives::{ActionId, ActorId, JobId},
    state::{JobRecord, JobStatus, StateKey, StateNamespace},
};
use serde_json::{Value, json};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Instant,
};

/// An HTTP request body may contain exactly one bounded action JSON wrapper.
pub const MAX_RPC_REQUEST_BYTES: usize = MAX_ACTION_JSON_BYTES;

/// Shared RPC surface over one real pending pool, finalized index, and action sender.
pub struct RpcService<N> {
    pool: Arc<PendingActionPool>,
    finalized: FinalizedQueryIndex,
    ingress: ActionIngress<FinalizedQueryIndex>,
    sender: Mutex<N>,
    observability: Arc<NodeMetrics>,
    runtime_metrics: RuntimeMetricsExporter,
}

impl<N> RpcService<N>
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    /// Binds HTTP admission and every query to the same node-local state surfaces.
    pub fn new(pool: Arc<PendingActionPool>, finalized: FinalizedQueryIndex, sender: N) -> Self {
        Self::with_observability(
            pool,
            finalized,
            sender,
            Arc::new(NodeMetrics::default()),
            RuntimeMetricsExporter::default(),
        )
    }

    /// Binds the live node's shared counters and Commonware registry exporter.
    pub fn with_observability(
        pool: Arc<PendingActionPool>,
        finalized: FinalizedQueryIndex,
        sender: N,
        observability: Arc<NodeMetrics>,
        runtime_metrics: RuntimeMetricsExporter,
    ) -> Self {
        Self {
            ingress: ActionIngress::new(Arc::clone(&pool), finalized.clone())
                .with_observability(Arc::clone(&observability)),
            pool,
            finalized,
            sender: Mutex::new(sender),
            observability,
            runtime_metrics,
        }
    }

    /// Builds the section 20.1 routes plus the standard Prometheus scrape endpoint.
    pub fn router(self) -> Router {
        let state = Arc::new(self);
        let request_metrics = Arc::clone(&state.observability);
        Router::new()
            .route("/metrics", get(get_metrics::<N>))
            .route("/v1/actions", post(post_action::<N>))
            .route("/v1/actions/{action_id}", get(get_action::<N>))
            .route("/v1/jobs", get(get_jobs::<N>))
            .route("/v1/jobs/{job_id}", get(get_job::<N>))
            .route("/v1/actors/{actor_id}", get(get_actor::<N>))
            .route("/v1/blocks/{height}", get(get_block::<N>))
            .route("/v1/state/root", get(get_state_root::<N>))
            .route(
                "/v1/state/mechanisms/{mechanism_id}",
                get(get_mechanism_state::<N>),
            )
            .route("/v1/replay/verify", get(get_replay_verify::<N>))
            .route("/v1/health", get(get_health::<N>))
            .method_not_allowed_fallback(method_not_allowed)
            .fallback(endpoint_not_found)
            .with_state(state)
            .layer(middleware::from_fn(move |request: Request, next: Next| {
                let metrics = Arc::clone(&request_metrics);
                async move {
                    let started = Instant::now();
                    let response = next.run(request).await;
                    metrics.observe_rpc(started.elapsed());
                    response
                }
            }))
    }
}

/// Serves one RPC router on an already-bound Tokio listener.
pub async fn serve<N, F>(
    listener: tokio::net::TcpListener,
    service: RpcService<N>,
    shutdown: F,
) -> std::io::Result<()>
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, service.router())
        .with_graceful_shutdown(shutdown)
        .await
}

async fn post_action<N>(
    State(state): State<Arc<RpcService<N>>>,
    request: Request,
) -> impl IntoResponse
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    let body = match to_bytes(request.into_body(), MAX_RPC_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return rpc_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "ACTION_JSON_TOO_LARGE",
                "action JSON exceeds the RPC request boundary",
            );
        }
    };
    let mut sender = state
        .sender
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match state.ingress.submit_json(&body, &mut *sender) {
        Ok(outcome) => {
            let (action_id, insertion, replaced_action_id) = match outcome.insertion {
                InsertOutcome::Inserted { action_id } => (action_id, "inserted", None),
                InsertOutcome::Duplicate { action_id } => (action_id, "duplicate", None),
                InsertOutcome::Replaced {
                    action_id,
                    replaced_action_id,
                } => (action_id, "replaced", Some(replaced_action_id)),
            };
            let mut result = json!({
                "action_id": hex(action_id.as_bytes()),
                "status": "pending",
                "insertion": insertion,
                "forwarded_to": outcome.forwarded_to.len(),
            });
            if let Some(replaced) = replaced_action_id {
                result["replaced_action_id"] = Value::String(hex(replaced.as_bytes()));
            }
            rpc_success(StatusCode::ACCEPTED, result)
        }
        Err(error) => ingress_error(error),
    }
}

async fn get_action<N>(
    State(state): State<Arc<RpcService<N>>>,
    Path(encoded): Path<String>,
) -> impl IntoResponse
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    let action_id = match parse_action_id(&encoded) {
        Ok(action_id) => action_id,
        Err(response) => return response,
    };
    if let Some((height, receipt)) = state.finalized.receipt(&action_id) {
        return rpc_success(
            StatusCode::OK,
            json!({
                "action_id": encoded.to_ascii_lowercase(),
                "status": "finalized",
                "block_height": height,
                "actor_id": hex(receipt.actor.as_bytes()),
                "nonce": receipt.nonce,
                "events": receipt.events.iter().copied().map(event_json).collect::<Vec<_>>(),
            }),
        );
    }
    if let Some(action) = state.pool.get(&action_id) {
        return rpc_success(
            StatusCode::OK,
            json!({
                "action_id": encoded.to_ascii_lowercase(),
                "status": "pending",
                "actor_id": hex(action.actor.as_bytes()),
                "nonce": action.nonce,
                "valid_until_height": action.valid_until_height,
            }),
        );
    }
    rpc_error(
        StatusCode::NOT_FOUND,
        "RPC_ACTION_NOT_FOUND",
        "action was not found",
    )
}

async fn get_jobs<N>(State(state): State<Arc<RpcService<N>>>) -> impl IntoResponse
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    match all_jobs(&state.finalized) {
        Ok(jobs) => rpc_success(StatusCode::OK, json!({"count": jobs.len(), "jobs": jobs})),
        Err(response) => response,
    }
}

async fn get_job<N>(
    State(state): State<Arc<RpcService<N>>>,
    Path(encoded): Path<String>,
) -> impl IntoResponse
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    let job_id = match parse_job_id(&encoded) {
        Ok(job_id) => job_id,
        Err(response) => return response,
    };
    let Some(value) = state.finalized.state_value(&StateKey::job(&job_id)) else {
        return rpc_error(
            StatusCode::NOT_FOUND,
            "RPC_JOB_NOT_FOUND",
            "job was not found",
        );
    };
    match JobRecord::decode_cfg(value.as_ref(), &()) {
        Ok(record) if record.job_id() == job_id => {
            rpc_success(StatusCode::OK, job_json(job_id, &record))
        }
        _ => malformed_state(),
    }
}

async fn get_actor<N>(
    State(state): State<Arc<RpcService<N>>>,
    Path(encoded): Path<String>,
) -> impl IntoResponse
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    let actor = match parse_actor_id(&encoded) {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let Some(nonce) = state.finalized.state_value(&StateKey::account(&actor)) else {
        return rpc_error(
            StatusCode::NOT_FOUND,
            "RPC_ACTOR_NOT_FOUND",
            "actor was not found",
        );
    };
    let bytes: [u8; 8] = match nonce.as_ref().try_into() {
        Ok(bytes) => bytes,
        Err(_) => return malformed_state(),
    };
    rpc_success(
        StatusCode::OK,
        json!({
            "actor_id": encoded.to_ascii_lowercase(),
            "next_nonce": u64::from_be_bytes(bytes),
            "finalized_action_count": state.finalized.actor_receipt_count(&actor),
            "pending_action_count": state.pool.actor_len(&actor),
        }),
    )
}

async fn get_block<N>(
    State(state): State<Arc<RpcService<N>>>,
    Path(encoded): Path<String>,
) -> impl IntoResponse
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    let height = match encoded.parse::<u64>() {
        Ok(height) => height,
        Err(_) => {
            return rpc_error(
                StatusCode::BAD_REQUEST,
                "RPC_HEIGHT_MALFORMED",
                "block height must be an unsigned decimal integer",
            );
        }
    };
    match state.finalized.block(height) {
        Some(block) => rpc_success(StatusCode::OK, block_json(&block)),
        None => rpc_error(
            StatusCode::NOT_FOUND,
            "RPC_BLOCK_NOT_FOUND",
            "finalized block was not found",
        ),
    }
}

async fn get_state_root<N>(State(state): State<Arc<RpcService<N>>>) -> impl IntoResponse
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    let snapshot = state.finalized.snapshot();
    rpc_success(
        StatusCode::OK,
        json!({
            "height": snapshot.finalized_height,
            "state_root": hex(snapshot.finalized_state_root.as_ref()),
            "qmdb_state_root": hex(snapshot.finalized_qmdb_root.as_ref()),
        }),
    )
}

async fn get_mechanism_state<N>(
    State(state): State<Arc<RpcService<N>>>,
    Path(encoded): Path<String>,
) -> impl IntoResponse
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    let Some(id) = parse_mechanism_id(&encoded) else {
        return rpc_error(
            StatusCode::BAD_REQUEST,
            "RPC_MECHANISM_ID_MALFORMED",
            "mechanism ID must have the form M00 through M65535",
        );
    };
    let Some(mechanism) = state.finalized.mechanism_state(id) else {
        return rpc_error(
            StatusCode::NOT_FOUND,
            "RPC_MECHANISM_NOT_SELECTED",
            "mechanism is not selected by finalized genesis state",
        );
    };
    rpc_success(
        StatusCode::OK,
        json!({
            "mechanism_id": mechanism.id.to_string(),
            "version": mechanism.version.to_string(),
            "state_namespace": mechanism.namespace,
            "config_digest": hex(mechanism.config_digest.as_ref()),
            "entry_count": mechanism.entries.len(),
            "entries": mechanism.entries.into_iter().map(|(key, value)| json!({
                "key": hex(key.as_bytes()),
                "value": hex(value.as_ref()),
            })).collect::<Vec<_>>(),
        }),
    )
}

async fn get_replay_verify<N>(State(state): State<Arc<RpcService<N>>>) -> impl IntoResponse
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    match state.finalized.verify_replay() {
        Ok(report) => rpc_success(
            StatusCode::OK,
            json!({
                "verified": true,
                "first_height": report.first_height,
                "finalized_height": report.finalized_height,
                "blocks_verified": report.blocks_verified,
                "state_root": hex(report.state_root.as_ref()),
                "executor": "rachet_core::transition::execute_block",
                "archive": "commonware_storage::archive::immutable",
            }),
        ),
        Err(mismatch) => rpc_error_details(
            StatusCode::CONFLICT,
            "REPLAY_MISMATCH",
            "finalized archive diverges from pure execution",
            json!({
                "height": mismatch.height,
                "field": mismatch.field,
                "expected": mismatch.expected,
                "actual": mismatch.actual,
            }),
        ),
    }
}

async fn get_metrics<N>(State(state): State<Arc<RpcService<N>>>) -> impl IntoResponse
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state
            .observability
            .encode(&state.pool, &state.finalized, &state.runtime_metrics),
    )
}

async fn get_health<N>(State(state): State<Arc<RpcService<N>>>) -> impl IntoResponse
where
    N: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    let snapshot = state.finalized.snapshot();
    rpc_success(
        StatusCode::OK,
        json!({
            "status": "ok",
            "finalized_height": snapshot.finalized_height,
            "observed_tip_height": snapshot.observed_tip_height,
            "current_epoch": snapshot.current_epoch,
            "connected_peers": state.runtime_metrics.connected_peers(),
            "pending_actions": state.pool.len(),
            "pending_bytes": state.pool.total_bytes(),
        }),
    )
}

async fn endpoint_not_found() -> impl IntoResponse {
    rpc_error(
        StatusCode::NOT_FOUND,
        "RPC_ENDPOINT_NOT_FOUND",
        "RPC endpoint was not found",
    )
}

async fn method_not_allowed() -> impl IntoResponse {
    rpc_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "RPC_METHOD_NOT_ALLOWED",
        "HTTP method is not allowed for this endpoint",
    )
}

fn all_jobs(index: &FinalizedQueryIndex) -> Result<Vec<Value>, RpcResponse> {
    index
        .state_namespace(StateNamespace::Job)
        .into_iter()
        .map(|(key, value)| {
            let id_bytes: [u8; 32] = key
                .as_bytes()
                .get(1..)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(malformed_state)?;
            let job_id = JobId::from_digest(Digest::from(id_bytes));
            let record =
                JobRecord::decode_cfg(value.as_ref(), &()).map_err(|_| malformed_state())?;
            if record.job_id() != job_id {
                return Err(malformed_state());
            }
            Ok(job_json(job_id, &record))
        })
        .collect()
}

fn job_json(job_id: JobId, record: &JobRecord) -> Value {
    let (resolution_kind, authority, verifier_id) = match &record.resolution_policy {
        ResolutionPolicy::ExperimentAuthority { authority } => (
            "experiment_authority",
            Some(hex(authority.as_bytes())),
            None,
        ),
        ResolutionPolicy::DeterministicVerifier { verifier_id, .. } => (
            "deterministic_verifier",
            None,
            Some(hex(verifier_id.as_ref())),
        ),
    };
    json!({
        "job_id": hex(job_id.as_bytes()),
        "customer_actor_id": hex(record.customer.as_bytes()),
        "status": job_status(record.status),
        "claim_ids": record.claim_ids.iter().map(|id| hex(id.as_bytes())).collect::<Vec<_>>(),
        "resolution_policy": {
            "kind": resolution_kind,
            "authority_actor_id": authority,
            "verifier_id": verifier_id,
        },
        "lifecycle": {
            "validation_opens_at": record.lifecycle.validation_opens_at,
            "validation_closes_at": record.lifecycle.validation_closes_at,
            "reveal_closes_at": record.lifecycle.reveal_closes_at,
            "challenge_closes_at": record.lifecycle.challenge_closes_at,
        },
        "supersedes": record.supersedes.map(|id| hex(id.as_bytes())),
        "artifact": {
            "base_commit": git_hash_json(&record.artifact.base_commit),
            "candidate_commit": git_hash_json(&record.artifact.candidate_commit),
            "specification_digest": hex(record.artifact.specification.digest.as_ref()),
        },
    })
}

fn block_json(block: &FinalizedBlockSummary) -> Value {
    json!({
        "height": block.height,
        "epoch": block.epoch,
        "block_id": hex(block.block_digest.as_ref()),
        "parent_block_id": hex(block.parent_block.as_ref()),
        "parent_state_root": hex(block.parent_state_root.as_ref()),
        "action_root": hex(block.action_root.as_ref()),
        "receipt_root": hex(block.receipt_root.as_ref()),
        "state_root": hex(block.state_root.as_ref()),
        "qmdb_state_root": hex(block.qmdb_state_root.as_ref()),
        "action_count": block.action_count,
        "receipt_count": block.receipt_count,
    })
}

fn git_hash_json(hash: &GitHash) -> Value {
    json!({
        "algorithm": if hash.is_sha1() { "sha1" } else { "sha256" },
        "digest": hex(hash.as_bytes()),
    })
}

const fn job_status(status: JobStatus) -> &'static str {
    match status {
        JobStatus::Open => "open",
        JobStatus::Resolved => "resolved",
        JobStatus::Closed => "closed",
    }
}

fn event_json(event: CanonicalEvent) -> Value {
    match event {
        CanonicalEvent::JobCreated { job_id } => {
            json!({"type": "job_created", "job_id": hex(job_id.as_bytes())})
        }
        CanonicalEvent::ClaimCreated { job_id, claim_id } => json!({
            "type": "claim_created",
            "job_id": hex(job_id.as_bytes()),
            "claim_id": hex(claim_id.as_bytes()),
        }),
        CanonicalEvent::EvidenceRegistered { evidence_id } => json!({
            "type": "evidence_registered",
            "evidence_id": hex(evidence_id.as_bytes()),
        }),
        CanonicalEvent::AttestationSubmitted { attestation_id } => json!({
            "type": "attestation_submitted",
            "attestation_id": hex(attestation_id.as_bytes()),
        }),
        CanonicalEvent::CommitmentCreated { commitment_id } => json!({
            "type": "commitment_created",
            "commitment_id": hex(commitment_id.as_bytes()),
        }),
        CanonicalEvent::CommitmentRevealed { commitment_id } => json!({
            "type": "commitment_revealed",
            "commitment_id": hex(commitment_id.as_bytes()),
        }),
        CanonicalEvent::CommitmentExpired { commitment_id } => json!({
            "type": "commitment_expired",
            "commitment_id": hex(commitment_id.as_bytes()),
        }),
        CanonicalEvent::ChallengeCreated { challenge_id } => json!({
            "type": "challenge_created",
            "challenge_id": hex(challenge_id.as_bytes()),
        }),
        CanonicalEvent::ClaimResolved { claim_id, verdict } => json!({
            "type": "claim_resolved",
            "claim_id": hex(claim_id.as_bytes()),
            "verdict": resolution_verdict(verdict),
        }),
        CanonicalEvent::ClaimReopened { claim_id } => json!({
            "type": "claim_reopened",
            "claim_id": hex(claim_id.as_bytes()),
        }),
        CanonicalEvent::ChallengeResolved {
            challenge_id,
            upheld,
        } => json!({
            "type": "challenge_resolved",
            "challenge_id": hex(challenge_id.as_bytes()),
            "upheld": upheld,
        }),
        CanonicalEvent::JobResolved { job_id } => {
            json!({"type": "job_resolved", "job_id": hex(job_id.as_bytes())})
        }
        CanonicalEvent::JobClosed { job_id } => {
            json!({"type": "job_closed", "job_id": hex(job_id.as_bytes())})
        }
        CanonicalEvent::EpochChanged { previous, current } => json!({
            "type": "epoch_changed",
            "previous": previous,
            "current": current,
        }),
    }
}

const fn resolution_verdict(verdict: rachet_core::actions::ResolutionVerdict) -> &'static str {
    match verdict {
        rachet_core::actions::ResolutionVerdict::Pass => "pass",
        rachet_core::actions::ResolutionVerdict::Fail => "fail",
        rachet_core::actions::ResolutionVerdict::Unresolved => "unresolved",
    }
}

fn parse_mechanism_id(encoded: &str) -> Option<MechanismId> {
    let numeric = encoded.strip_prefix('M')?;
    if numeric.len() < 2 || numeric.len() > 5 || !numeric.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    numeric.parse::<u16>().ok().map(MechanismId::new)
}

fn parse_action_id(encoded: &str) -> Result<ActionId, RpcResponse> {
    parse_digest(encoded).map(ActionId::from_digest)
}

fn parse_job_id(encoded: &str) -> Result<JobId, RpcResponse> {
    parse_digest(encoded).map(JobId::from_digest)
}

fn parse_digest(encoded: &str) -> Result<Digest, RpcResponse> {
    let bytes = decode_fixed_hex::<32>(encoded)?;
    Ok(Digest::from(bytes))
}

fn parse_actor_id(encoded: &str) -> Result<ActorId, RpcResponse> {
    let bytes = decode_fixed_hex::<32>(encoded)?;
    ed25519::PublicKey::decode_cfg(bytes.as_slice(), &())
        .map(ActorId::from)
        .map_err(|_| malformed_identifier())
}

fn decode_fixed_hex<const N: usize>(encoded: &str) -> Result<[u8; N], RpcResponse> {
    if encoded.len() != N * 2 {
        return Err(malformed_identifier());
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(malformed_identifier)?;
        let low = hex_nibble(pair[1]).ok_or_else(malformed_identifier)?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

type RpcResponse = (StatusCode, Json<Value>);

fn rpc_success(status: StatusCode, result: Value) -> RpcResponse {
    (status, Json(json!({"ok": true, "result": result})))
}

fn rpc_error(status: StatusCode, code: &'static str, message: &'static str) -> RpcResponse {
    rpc_error_details(status, code, message, json!({}))
}

fn rpc_error_details(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    details: Value,
) -> RpcResponse {
    (
        status,
        Json(json!({"error": {"code": code, "message": message, "details": details}})),
    )
}

fn malformed_identifier() -> RpcResponse {
    rpc_error(
        StatusCode::BAD_REQUEST,
        "RPC_IDENTIFIER_MALFORMED",
        "identifier must be 32 lowercase or uppercase hexadecimal bytes",
    )
}

fn malformed_state() -> RpcResponse {
    rpc_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "RPC_STATE_MALFORMED",
        "finalized query state is malformed",
    )
}

fn ingress_error(error: IngressError) -> RpcResponse {
    let status = match error {
        IngressError::JsonTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        IngressError::MalformedJson | IngressError::MalformedCanonicalHex => {
            StatusCode::BAD_REQUEST
        }
        IngressError::Action(rachet_core::actions::ActionValidationError::InvalidSignature) => {
            StatusCode::UNAUTHORIZED
        }
        IngressError::Action(_) => StatusCode::UNPROCESSABLE_ENTITY,
        IngressError::State(_) => StatusCode::SERVICE_UNAVAILABLE,
        IngressError::Pending(_) => StatusCode::TOO_MANY_REQUESTS,
    };
    rpc_error(status, error.code(), "action submission was rejected")
}
