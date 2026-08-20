//! Bounded full-block dissemination for the standard marshal pipeline.
//!
//! The returned mailbox is the concrete buffer expected by
//! `marshal::standard::Standard`; no substitute broadcaster sits on the
//! release-critical path. Older blocks outside the small per-sender cache are
//! recovered by marshal's targeted resolver rather than retained without bound.

use crate::application::StatefulBlock;
use commonware_broadcast::buffered;
use commonware_cryptography::ed25519;
use commonware_p2p::Provider;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner};
use commonware_utils::NZUsize;
use rachet_core::blocks::Block as ProtocolBlock;

/// Dedicated Commonware channel for full canonical block broadcast.
pub const BLOCK_BROADCAST_CHANNEL: u64 = 0x5241_4348_4554_0002;

/// Maximum buffered blocks retained for each current primary peer.
///
/// Marshal resolver/backfill owns recovery outside this recent window.
pub const BLOCK_CACHE_PER_PEER: usize = 16;

/// Maximum backlog of local broadcast, lookup, and subscription requests.
pub const BLOCK_BROADCAST_MAILBOX_SIZE: std::num::NonZeroUsize = NZUsize!(128);

// A StatefulBlock adds two SHA-256 digests and a pair of canonically encoded
// u64 QMDB locations. Ten bytes is the maximum canonical u64 varint width.
const STATEFUL_WRAPPER_MAX_BYTES: usize = 32 + 32 + 10 + 10;
const BLOCK_BROADCAST_MAX_MESSAGE_SIZE_USIZE: usize =
    ProtocolBlock::MAX_ENCODED_BYTES + STATEFUL_WRAPPER_MAX_BYTES;
const _: () = assert!(BLOCK_BROADCAST_MAX_MESSAGE_SIZE_USIZE <= u32::MAX as usize);

/// Maximum authenticated channel payload for one encoded [`StatefulBlock`].
///
/// Live and simulated P2P configurations must apply this value as their
/// channel/network message limit so oversized packets are rejected before
/// canonical decoding or cache insertion.
pub const BLOCK_BROADCAST_MAX_MESSAGE_SIZE: u32 = BLOCK_BROADCAST_MAX_MESSAGE_SIZE_USIZE as u32;

/// Concrete buffered mailbox consumed by standard marshal.
pub type BlockBroadcastMailbox = buffered::Mailbox<ed25519::PublicKey, StatefulBlock>;

/// Concrete Commonware buffered engine for canonical Stateful blocks.
pub type BlockBroadcastEngine<E, D> = buffered::Engine<E, ed25519::PublicKey, StatefulBlock, D>;

/// Creates one bounded Commonware full-block broadcast engine and mailbox.
///
/// The caller starts the returned engine on [`BLOCK_BROADCAST_CHANNEL`] and
/// passes the mailbox directly to standard marshal.
pub fn new_block_broadcast<E, D>(
    context: E,
    public_key: ed25519::PublicKey,
    peer_provider: D,
) -> (BlockBroadcastEngine<E, D>, BlockBroadcastMailbox)
where
    E: BufferPooler + Clock + Spawner + Metrics,
    D: Provider<PublicKey = ed25519::PublicKey>,
{
    buffered::Engine::new(
        context,
        buffered::Config {
            public_key,
            mailbox_size: BLOCK_BROADCAST_MAILBOX_SIZE,
            deque_size: BLOCK_CACHE_PER_PEER,
            priority: false,
            codec_config: (),
            peer_provider,
        },
    )
}
