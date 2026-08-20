//! Ordered standard-marshal, block-backfill, and state-sync wiring.
//!
//! The release path deliberately exposes only [`Deferred`]-based application
//! adaptation. Standard marshal receives the real P2P resolver mailbox, whose
//! type implements [`TargetedResolver`], and all repair/sync queues have fixed
//! non-zero bounds.

use commonware_consensus::{
    Application, CertifiableBlock,
    marshal::{
        core,
        resolver::{handler, p2p as marshal_resolver},
        standard::{Deferred, Standard},
    },
    simplex::types::Context as SimplexContext,
    types::FixedEpocher,
};
use commonware_cryptography::{ed25519, sha256::Digest as Sha256Digest};
use commonware_glue::stateful::db::{SyncEngineConfig, p2p::standard as state_sync_resolver};
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::TargetedResolver;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner};
use commonware_utils::{NZU64, NZUsize, sync::TracedAsyncRwLock};
use rand_core::Rng;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use super::ConsensusScheme;

/// Dedicated authenticated channel for marshal block/finalization backfill.
pub const MARSHAL_RESOLVER_CHANNEL: u64 = 0x5241_4348_4554_0003;
/// Dedicated authenticated channel for current-QMDB operation resolution.
pub const STATE_SYNC_RESOLVER_CHANNEL: u64 = 0x5241_4348_4554_0004;

/// Bounded standard-marshal command and subscription backlog.
pub const STANDARD_MARSHAL_MAILBOX_SIZE: NonZeroUsize = NZUsize!(128);
/// Bounded resolver request and delivery backlog.
pub const RESOLVER_MAILBOX_SIZE: NonZeroUsize = NZUsize!(64);
/// Initial latency estimate used by both targeted resolver paths.
pub const RESOLVER_INITIAL_LATENCY: Duration = Duration::from_millis(100);
/// Bound for one targeted network request attempt.
pub const RESOLVER_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
/// Delay before retrying unresolved targeted data.
pub const RESOLVER_RETRY_TIMEOUT: Duration = Duration::from_millis(100);

/// Maximum number of missing marshal items repaired in one actor turn.
pub const MARSHAL_MAX_REPAIR: NonZeroUsize = NZUsize!(16);
/// Maximum unacknowledged finalized blocks dispatched to Stateful.
///
/// Keeping this at one makes application delivery strictly sequential while
/// retaining Commonware marshal's at-least-once restart semantics.
pub const MARSHAL_MAX_PENDING_ACKS: NonZeroUsize = NZUsize!(1);

/// Maximum QMDB operations served in one state-sync response.
pub const STATE_SYNC_MAX_SERVE_OPS: std::num::NonZeroU64 = NZU64!(16);
/// Maximum QMDB operations requested in one state-sync fetch.
pub const STATE_SYNC_FETCH_BATCH_SIZE: std::num::NonZeroU64 = NZU64!(16);
/// Maximum QMDB operations applied in one state-sync turn.
pub const STATE_SYNC_APPLY_BATCH_SIZE: usize = 16;
/// Maximum concurrent state-sync fetch requests.
pub const STATE_SYNC_MAX_OUTSTANDING_REQUESTS: usize = 4;
/// Bounded state-sync update backlog.
pub const STATE_SYNC_UPDATE_CHANNEL_SIZE: NonZeroUsize = NZUsize!(64);
/// Maximum recent state roots retained while syncing.
pub const STATE_SYNC_MAX_RETAINED_ROOTS: usize = 8;

/// Standard marshal's concrete mailbox for an application block.
pub type StandardMarshalMailbox<B> = core::Mailbox<ConsensusScheme, Standard<B>>;

/// The only consensus application adapter exposed by the chain engine.
///
/// This alias intentionally fixes standard marshal to [`Deferred`].
pub type DeferredApplication<E, A, B> = Deferred<E, ConsensusScheme, A, B, FixedEpocher>;

/// Constructs the Deferred automaton/relay used by Simplex.
///
/// The same returned value is cloned into the Simplex automaton and relay
/// fields. Finalized updates are delivered through standard marshal rather
/// than directly from consensus to the application.
pub fn new_deferred_application<E, A, B>(
    context: E,
    application: A,
    marshal: StandardMarshalMailbox<B>,
    epocher: FixedEpocher,
) -> DeferredApplication<E, A, B>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<
            E,
            SigningScheme = ConsensusScheme,
            Context = SimplexContext<Sha256Digest, ed25519::PublicKey>,
            Block = B,
        >,
    B: CertifiableBlock<Context = A::Context, Digest = Sha256Digest>,
{
    Deferred::new(context, application, marshal, epocher)
}

/// Concrete targeted P2P mailbox used by standard marshal.
pub type MarshalResolverMailbox = marshal_resolver::Mailbox<Sha256Digest, ed25519::PublicKey>;

/// Initializes the real P2P resolver consumed by standard marshal.
///
/// The return type is intentionally concrete: the mailbox is a
/// [`TargetedResolver`], so substituting a non-targeted resolver cannot compile
/// at the marshal actor's `start` boundary.
pub fn new_marshal_resolver<E, C, B, S, R>(
    context: E,
    public_key: ed25519::PublicKey,
    peer_provider: C,
    blocker: B,
    backfill: (S, R),
) -> (handler::Receiver<Sha256Digest>, MarshalResolverMailbox)
where
    E: BufferPooler + Rng + Spawner + Clock + Metrics,
    C: Provider<PublicKey = ed25519::PublicKey>,
    B: Blocker<PublicKey = ed25519::PublicKey>,
    S: Sender<PublicKey = ed25519::PublicKey>,
    R: Receiver<PublicKey = ed25519::PublicKey>,
{
    let resolver = marshal_resolver::init(
        context,
        marshal_resolver::Config {
            public_key,
            peer_provider,
            blocker,
            mailbox_size: RESOLVER_MAILBOX_SIZE,
            initial: RESOLVER_INITIAL_LATENCY,
            timeout: RESOLVER_REQUEST_TIMEOUT,
            fetch_retry_timeout: RESOLVER_RETRY_TIMEOUT,
            priority_requests: false,
            priority_responses: false,
        },
        backfill,
    );
    assert_targeted_resolver(&resolver.1);
    resolver
}

fn assert_targeted_resolver<R>(_: &R)
where
    R: TargetedResolver<PublicKey = ed25519::PublicKey>,
{
}

/// Builds the bounded QMDB state-sync engine configuration.
pub const fn state_sync_engine_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: STATE_SYNC_FETCH_BATCH_SIZE,
        apply_batch_size: STATE_SYNC_APPLY_BATCH_SIZE,
        max_outstanding_requests: STATE_SYNC_MAX_OUTSTANDING_REQUESTS,
        update_channel_size: STATE_SYNC_UPDATE_CHANNEL_SIZE,
        max_retained_roots: STATE_SYNC_MAX_RETAINED_ROOTS,
    }
}

/// Builds the real P2P QMDB resolver configuration used by Stateful.
///
/// The database may be attached later by Stateful during initialization.
pub fn state_sync_resolver_config<P, D, B, DB>(
    peer_provider: D,
    blocker: B,
    database: Option<Arc<TracedAsyncRwLock<DB>>>,
    me: Option<P>,
) -> state_sync_resolver::Config<P, D, B, DB>
where
    P: commonware_cryptography::PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
{
    state_sync_resolver::Config {
        peer_provider,
        blocker,
        database,
        mailbox_size: RESOLVER_MAILBOX_SIZE,
        me,
        initial: RESOLVER_INITIAL_LATENCY,
        timeout: RESOLVER_REQUEST_TIMEOUT,
        fetch_retry_timeout: RESOLVER_RETRY_TIMEOUT,
        max_serve_ops: STATE_SYNC_MAX_SERVE_OPS,
        priority_requests: false,
        priority_responses: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::marshal::resolver::{handler::Annotation, handler::Key};

    fn requires_targeted<R>(_: &R)
    where
        R: TargetedResolver<
                Key = Key<Sha256Digest>,
                Subscriber = Annotation,
                PublicKey = ed25519::PublicKey,
            >,
    {
    }

    #[test]
    fn repair_and_state_sync_limits_are_finite_and_nonzero() {
        assert_eq!(MARSHAL_MAX_PENDING_ACKS.get(), 1);
        assert!(MARSHAL_MAX_REPAIR.get() < usize::MAX);
        assert!(STATE_SYNC_MAX_SERVE_OPS.get() > 0);
        assert!(STATE_SYNC_FETCH_BATCH_SIZE.get() > 0);
        let sync = state_sync_engine_config();
        assert_eq!(sync.max_outstanding_requests, 4);
        assert_eq!(sync.max_retained_roots, 8);
    }

    #[allow(dead_code)]
    fn marshal_mailbox_is_targeted(mailbox: &MarshalResolverMailbox) {
        requires_targeted(mailbox);
    }
}
