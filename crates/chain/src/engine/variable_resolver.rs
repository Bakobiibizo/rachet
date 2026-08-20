//! Authenticated state-sync transport for the ordered variable QMDB schema.
//!
//! Commonware 2026.7.0's packaged QMDB P2P actor constrains operation codecs to
//! `Cfg = ()`, while ordered variable operations require bounded key/value
//! range configuration. This small transport preserves those bounds and uses
//! the real QMDB proof producer/consumer interfaces over the authenticated
//! committee channel.

use super::STATE_SYNC_MAX_SERVE_OPS;
use crate::{
    application::state::{QmdbStateDatabase, QmdbStateOperation},
    observability::NodeMetrics,
};
use bytes::BufMut;
use commonware_actor::mailbox;
use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt as _, ReadRangeExt as _, Write};
use commonware_cryptography::sha256::Digest;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Handle, Spawner, Supervisor};
use commonware_storage::{
    Context as StorageContext,
    merkle::{Location, MAX_PINNED_NODES, MAX_PROOF_DIGESTS_PER_ELEMENT, Proof, mmr},
    qmdb::sync::resolver::{FetchResult, Resolver as SyncResolver},
};
use commonware_utils::{NZUsize, channel::oneshot, sync::TracedAsyncRwLock};
use futures::{FutureExt as _, select};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    future::Future,
    num::NonZeroU64,
    sync::Arc,
};

use commonware_glue::stateful::db::AttachableResolver;

const MAILBOX_SIZE: std::num::NonZeroUsize = NZUsize!(64);
const REQUEST_TAG: u8 = 0;
const RESPONSE_TAG: u8 = 1;

type Operation = QmdbStateOperation<mmr::Family>;
type Database<E> = QmdbStateDatabase<E>;
type SharedDatabase<E> = Arc<TracedAsyncRwLock<Database<E>>>;
type StateCodecConfig = ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()));

struct Request {
    id: u64,
    op_count: Location<mmr::Family>,
    start_loc: Location<mmr::Family>,
    max_ops: NonZeroU64,
    include_pinned_nodes: bool,
}

impl Write for Request {
    fn write(&self, buf: &mut impl BufMut) {
        REQUEST_TAG.write(buf);
        self.id.write(buf);
        self.op_count.write(buf);
        self.start_loc.write(buf);
        self.max_ops.write(buf);
        self.include_pinned_nodes.write(buf);
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        REQUEST_TAG.encode_size()
            + self.id.encode_size()
            + self.op_count.encode_size()
            + self.start_loc.encode_size()
            + self.max_ops.encode_size()
            + self.include_pinned_nodes.encode_size()
    }
}

impl Request {
    fn decode(mut bytes: &[u8]) -> Option<Self> {
        if u8::read(&mut bytes).ok()? != REQUEST_TAG {
            return None;
        }
        let request = Self {
            id: u64::read(&mut bytes).ok()?,
            op_count: Location::read(&mut bytes).ok()?,
            start_loc: Location::read(&mut bytes).ok()?,
            max_ops: NonZeroU64::read(&mut bytes).ok()?,
            include_pinned_nodes: bool::read(&mut bytes).ok()?,
        };
        (request.max_ops <= STATE_SYNC_MAX_SERVE_OPS && bytes.is_empty()).then_some(request)
    }
}

fn encode_response(id: u64, result: FetchResult<mmr::Family, Operation, Digest>) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(
        1 + id.encode_size()
            + result.proof.encode_size()
            + result.operations.encode_size()
            + result.pinned_nodes.encode_size(),
    );
    RESPONSE_TAG.write(&mut encoded);
    id.write(&mut encoded);
    result.proof.write(&mut encoded);
    result.operations.write(&mut encoded);
    result.pinned_nodes.write(&mut encoded);
    encoded
}

fn decode_response(
    mut bytes: &[u8],
    maximum_operations: usize,
) -> Option<(u64, FetchResult<mmr::Family, Operation, Digest>)> {
    if maximum_operations > usize::try_from(STATE_SYNC_MAX_SERVE_OPS.get()).ok()?
        || u8::read(&mut bytes).ok()? != RESPONSE_TAG
    {
        return None;
    }
    let id = u64::read(&mut bytes).ok()?;
    let proof = Proof::read_cfg(
        &mut bytes,
        &maximum_operations.saturating_mul(MAX_PROOF_DIGESTS_PER_ELEMENT),
    )
    .ok()?;
    let operations = Vec::<Operation>::read_cfg(
        &mut bytes,
        &(
            RangeCfg::new(..=maximum_operations),
            state_operation_codec_config(),
        ),
    )
    .ok()?;
    let pinned_nodes = Option::<Vec<Digest>>::read_range(&mut bytes, ..=MAX_PINNED_NODES).ok()?;
    if !bytes.is_empty() {
        return None;
    }
    Some((id, FetchResult::new(proof, operations, pinned_nodes)))
}

fn state_operation_codec_config() -> StateCodecConfig {
    ((RangeCfg::new(1..), ()), (RangeCfg::new(..), ()))
}

enum Command<E: StorageContext> {
    Attach(SharedDatabase<E>),
    Fetch {
        op_count: Location<mmr::Family>,
        start_loc: Location<mmr::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
        response:
            oneshot::Sender<Result<FetchResult<mmr::Family, Operation, Digest>, ResolverError>>,
    },
}

impl<E: StorageContext> mailbox::Policy for Command<E> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// Cloneable QMDB resolver passed directly to Stateful.
pub struct VariableQmdbResolver<E: StorageContext> {
    commands: mailbox::Sender<Command<E>>,
}

impl<E: StorageContext> Clone for VariableQmdbResolver<E> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
        }
    }
}

impl<E: StorageContext + 'static> SyncResolver for VariableQmdbResolver<E> {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = Operation;
    type Error = ResolverError;

    async fn get_operations(
        &self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
        cancel_rx: oneshot::Receiver<()>,
    ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        let (response, receiver) = oneshot::channel();
        if !self
            .commands
            .enqueue(Command::Fetch {
                op_count,
                start_loc,
                max_ops,
                include_pinned_nodes,
                response,
            })
            .accepted()
        {
            return Err(ResolverError::Unavailable);
        }
        futures::pin_mut!(receiver);
        futures::pin_mut!(cancel_rx);
        select! {
            result = receiver.as_mut().fuse() => result.map_err(|_| ResolverError::Unavailable)?,
            _ = cancel_rx.as_mut().fuse() => Err(ResolverError::Canceled),
        }
    }
}

impl<E: StorageContext + 'static> AttachableResolver<Database<E>> for VariableQmdbResolver<E> {
    fn attach_database(&self, database: SharedDatabase<E>) -> impl Future<Output = ()> + Send {
        let accepted = self.commands.enqueue(Command::Attach(database)).accepted();
        async move {
            assert!(accepted, "variable QMDB resolver must remain available");
        }
    }
}

/// Authenticated request/response actor for variable-QMDB operations and proofs.
pub struct VariableQmdbResolverActor<E: StorageContext, S, R> {
    context: E,
    _public_key: ed25519::PublicKey,
    commands: mailbox::Receiver<Command<E>>,
    sender: S,
    receiver: R,
    observability: Arc<NodeMetrics>,
}

use commonware_cryptography::ed25519;

impl<E, S, R> VariableQmdbResolverActor<E, S, R>
where
    E: StorageContext + Spawner + Supervisor + Send + 'static,
    S: Sender<PublicKey = ed25519::PublicKey> + Send + 'static,
    R: Receiver<PublicKey = ed25519::PublicKey> + Send + 'static,
{
    pub fn new(
        context: E,
        public_key: ed25519::PublicKey,
        sender: S,
        receiver: R,
        observability: Arc<NodeMetrics>,
    ) -> (Self, VariableQmdbResolver<E>) {
        let (commands, command_receiver) = mailbox::new(context.child("mailbox"), MAILBOX_SIZE);
        (
            Self {
                context,
                _public_key: public_key,
                commands: command_receiver,
                sender,
                receiver,
                observability,
            },
            VariableQmdbResolver { commands },
        )
    }

    pub fn start(self) -> Handle<()> {
        self.context
            .child("actor")
            .spawn(move |_| async move { self.run().await })
    }

    async fn run(mut self) {
        let mut database: Option<SharedDatabase<E>> = None;
        let mut next_id = 0_u64;
        let mut pending = BTreeMap::<
            u64,
            (
                usize,
                oneshot::Sender<Result<FetchResult<mmr::Family, Operation, Digest>, ResolverError>>,
            ),
        >::new();
        let mut stopped = self.context.stopped().fuse();
        loop {
            let command = self.commands.recv().fuse();
            let received = self.receiver.recv().fuse();
            futures::pin_mut!(command, received);
            select! {
                _ = stopped => break,
                command = command => {
                    let Some(command) = command else { break };
                    match command {
                        Command::Attach(attached) => database = Some(attached),
                        Command::Fetch { op_count, start_loc, max_ops, include_pinned_nodes, response } => {
                            if max_ops > STATE_SYNC_MAX_SERVE_OPS {
                                let _ = response.send(Err(ResolverError::RequestTooLarge));
                                continue;
                            }
                            self.observability.observe_resolver_request();
                            let id = next_id;
                            next_id = next_id.wrapping_add(1);
                            let request = Request { id, op_count, start_loc, max_ops, include_pinned_nodes };
                            let mut encoded = Vec::with_capacity(request.encode_size());
                            request.write(&mut encoded);
                            if self.sender.send(Recipients::All, encoded, false).is_empty() {
                                let _ = response.send(Err(ResolverError::NoConnectedPeer));
                            } else {
                                let maximum = usize::try_from(max_ops.get()).unwrap_or(usize::MAX);
                                pending.insert(id, (maximum, response));
                            }
                        }
                    }
                },
                received = received => {
                    let Ok((peer, message)) = received else { break };
                    let bytes: &[u8] = message.as_ref();
                    if bytes.first() == Some(&REQUEST_TAG) {
                        let Some(request) = Request::decode(bytes) else { continue };
                        let Some(database) = database.clone() else { continue };
                        let (cancel, cancel_rx) = oneshot::channel();
                        let result = SyncResolver::get_operations(
                            &database,
                            request.op_count,
                            request.start_loc,
                            request.max_ops,
                            request.include_pinned_nodes,
                            cancel_rx,
                        ).await;
                        if let Ok(result) = result {
                            let encoded = encode_response(request.id, result);
                            let _ = self.sender.send(Recipients::One(peer), encoded, false);
                        }
                        drop(cancel);
                    } else if bytes.first() == Some(&RESPONSE_TAG) {
                        if bytes.len() < 9 { continue; }
                        let mut id_bytes = &bytes[1..];
                        let Some(id) = u64::read(&mut id_bytes).ok() else { continue };
                        let Some((maximum, response)) = pending.remove(&id) else { continue };
                        let result = decode_response(bytes, maximum)
                            .map(|(_, result)| result)
                            .ok_or(ResolverError::MalformedResponse);
                        let _ = response.send(result);
                    }
                },
            }
        }
        for (_, (_, response)) in pending {
            let _ = response.send(Err(ResolverError::Unavailable));
        }
    }
}

/// Bounded state resolver failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolverError {
    Unavailable,
    Canceled,
    NoConnectedPeer,
    RequestTooLarge,
    MalformedResponse,
}

impl fmt::Display for ResolverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "variable QMDB resolver unavailable",
            Self::Canceled => "variable QMDB resolver request canceled",
            Self::NoConnectedPeer => "variable QMDB resolver has no connected peer",
            Self::RequestTooLarge => "variable QMDB resolver request exceeds the operation bound",
            Self::MalformedResponse => "variable QMDB resolver received malformed response",
        })
    }
}

impl std::error::Error for ResolverError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(max_ops: u64) -> Vec<u8> {
        let request = Request {
            id: 7,
            op_count: Location::<mmr::Family>::new(9),
            start_loc: Location::<mmr::Family>::new(3),
            max_ops: NonZeroU64::new(max_ops).unwrap(),
            include_pinned_nodes: true,
        };
        let mut encoded = Vec::with_capacity(request.encode_size());
        request.write(&mut encoded);
        encoded
    }

    #[test]
    fn request_decoder_rejects_truncation_tags_trailing_bytes_and_oversized_work() {
        let encoded = request(STATE_SYNC_MAX_SERVE_OPS.get());
        assert!(Request::decode(&encoded).is_some());
        for length in 0..encoded.len() {
            assert!(Request::decode(&encoded[..length]).is_none());
        }

        let mut invalid_tag = encoded.clone();
        invalid_tag[0] = RESPONSE_TAG;
        assert!(Request::decode(&invalid_tag).is_none());

        let mut invalid_bool = encoded.clone();
        *invalid_bool.last_mut().unwrap() = 2;
        assert!(Request::decode(&invalid_bool).is_none());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(Request::decode(&trailing).is_none());
        assert!(Request::decode(&request(STATE_SYNC_MAX_SERVE_OPS.get() + 1)).is_none());
    }

    #[test]
    fn response_decoder_rejects_an_unbounded_allocation_configuration_before_reading() {
        let oversized = usize::try_from(STATE_SYNC_MAX_SERVE_OPS.get()).unwrap() + 1;
        assert!(decode_response(&[], oversized).is_none());
    }
}
