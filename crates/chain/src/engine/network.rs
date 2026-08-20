//! Live authenticated networking for the fixed genesis committee.
//!
//! Every connection is authenticated with the same typed consensus-node key
//! used by Simplex. The peer directory is immutable, addressable, and installed
//! at peer-set index zero before the Commonware lookup actors start. Unknown
//! identities therefore never become providers, blockers, or channel senders.

use super::{
    BLOCK_BROADCAST_CHANNEL, BLOCK_BROADCAST_MAX_MESSAGE_SIZE, ConsensusNodeKey, FixedCommittee,
    MARSHAL_RESOLVER_CHANNEL, RESOLVER_MAILBOX_SIZE, STATE_SYNC_RESOLVER_CHANNEL,
};
use crate::ingress::{ACTION_CHANNEL, ACTION_CHANNEL_MAX_MESSAGE_SIZE};
use commonware_cryptography::ed25519;
use commonware_p2p::{Address, AddressableManager as _, authenticated::lookup};
use commonware_runtime::{
    BufferPooler, Clock, Handle, Metrics, Network as RuntimeNetwork, Quota, Resolver, Spawner,
};
use commonware_utils::{NZU32, ordered::Map};
use rachet_core::{
    blocks::ConsensusNodeId,
    primitives::{ActorId, ChainId},
};
use rand_core::CryptoRng;
use std::{fmt, net::SocketAddr};

/// Peer-set index reserved for the immutable v1 genesis committee.
pub const GENESIS_COMMITTEE_INDEX: u64 = 0;
/// Domain prefix for authenticated stream handshakes.
///
/// The chain ID is appended by [`authenticated_network_namespace`] so a valid
/// peer handshake cannot be replayed onto another genesis.
pub const AUTHENTICATED_NETWORK_NAMESPACE: &[u8] = b"rachet/authenticated-committee/v1/";

/// Network receive backlog for canonical signed actions.
pub const ACTION_CHANNEL_BACKLOG: usize = 256;
/// Network receive backlog for complete canonical blocks.
pub const BLOCK_CHANNEL_BACKLOG: usize = 128;
/// Network receive backlog for Simplex votes, certificates, and resolution.
pub const CONSENSUS_CHANNEL_BACKLOG: usize = 256;
/// Network receive backlog for marshal and QMDB resolution traffic.
pub const RESOLUTION_CHANNEL_BACKLOG: usize = 64;

/// Dedicated authenticated channel for Simplex votes.
pub const SIMPLEX_VOTE_CHANNEL: u64 = 0x5241_4348_4554_0005;
/// Dedicated authenticated channel for Simplex certificates.
pub const SIMPLEX_CERTIFICATE_CHANNEL: u64 = 0x5241_4348_4554_0006;
/// Dedicated authenticated channel for Simplex certificate resolution.
pub const SIMPLEX_RESOLVER_CHANNEL: u64 = 0x5241_4348_4554_0007;

const CHANNEL_MESSAGES_PER_SECOND: u32 = 256;

const _: () = assert!(ACTION_CHANNEL_MAX_MESSAGE_SIZE <= BLOCK_BROADCAST_MAX_MESSAGE_SIZE);

/// Maximum payload admitted by the shared multiplexed transport.
///
/// Individual action and block consumers still enforce their narrower
/// canonical bounds. Resolver batches are also capped by this transport bound.
pub const AUTHENTICATED_NETWORK_MAX_MESSAGE_SIZE: u32 = BLOCK_BROADCAST_MAX_MESSAGE_SIZE;

/// One fixed consensus peer and its genesis-declared ingress address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitteePeer {
    node_id: ConsensusNodeId,
    address: SocketAddr,
}

impl CommitteePeer {
    pub const fn new(node_id: ConsensusNodeId, address: SocketAddr) -> Self {
        Self { node_id, address }
    }

    pub const fn node_id(&self) -> &ConsensusNodeId {
        &self.node_id
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

/// Immutable network portion of genesis.
///
/// `actor_identities` contains actor-role keys known at genesis (including
/// resolution authorities). Keeping them here makes a byte-identical actor and
/// consensus identity a startup error in addition to preserving distinct Rust
/// types at every public constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitteeNetworkGenesis {
    chain_id: ChainId,
    peers: Vec<CommitteePeer>,
    actor_identities: Vec<ActorId>,
}

impl CommitteeNetworkGenesis {
    /// Validates and canonically orders the exact four-peer committee.
    pub fn new(
        chain_id: ChainId,
        mut peers: Vec<CommitteePeer>,
        mut actor_identities: Vec<ActorId>,
    ) -> Result<Self, CommitteeNetworkConfigurationError> {
        FixedCommittee::new(peers.iter().map(|peer| peer.node_id.clone()).collect())
            .map_err(CommitteeNetworkConfigurationError::Committee)?;

        peers.sort_unstable_by(|left, right| left.node_id.cmp(&right.node_id));
        if peers
            .iter()
            .any(|peer| peer.address.port() == 0 || peer.address.ip().is_unspecified())
        {
            return Err(CommitteeNetworkConfigurationError::InvalidPeerAddress);
        }
        let mut addresses = peers.iter().map(|peer| peer.address).collect::<Vec<_>>();
        addresses.sort_unstable();
        if addresses.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CommitteeNetworkConfigurationError::DuplicatePeerAddress);
        }

        actor_identities.sort_unstable();
        if actor_identities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CommitteeNetworkConfigurationError::DuplicateActorIdentity);
        }
        if peers.iter().any(|peer| {
            actor_identities
                .iter()
                .any(|actor| actor.as_ref() == peer.node_id.as_ref())
        }) {
            return Err(CommitteeNetworkConfigurationError::ActorConsensusKeyConflict);
        }

        Ok(Self {
            chain_id,
            peers,
            actor_identities,
        })
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub fn peers(&self) -> &[CommitteePeer] {
        &self.peers
    }

    pub fn actor_identities(&self) -> &[ActorId] {
        &self.actor_identities
    }

    fn local_address(&self, node_id: &ConsensusNodeId) -> Option<SocketAddr> {
        self.peers
            .binary_search_by(|peer| peer.node_id.cmp(node_id))
            .ok()
            .map(|index| self.peers[index].address)
    }

    fn address_map(
        &self,
    ) -> Result<Map<ed25519::PublicKey, Address>, CommitteeNetworkConfigurationError> {
        Map::try_from(
            self.peers
                .iter()
                .map(|peer| (peer.node_id.public_key().clone(), peer.address.into()))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| CommitteeNetworkConfigurationError::DuplicateCommitteeIdentity)
    }
}

/// Returns the chain-bound authenticated handshake namespace.
pub fn authenticated_network_namespace(chain_id: ChainId) -> Vec<u8> {
    let mut namespace = Vec::with_capacity(AUTHENTICATED_NETWORK_NAMESPACE.len() + 32);
    namespace.extend_from_slice(AUTHENTICATED_NETWORK_NAMESPACE);
    namespace.extend_from_slice(chain_id.as_bytes());
    namespace
}

/// Invalid immutable committee-network configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitteeNetworkConfigurationError {
    Committee(super::ConsensusConfigurationError),
    DuplicateCommitteeIdentity,
    DuplicatePeerAddress,
    InvalidPeerAddress,
    DuplicateActorIdentity,
    ActorConsensusKeyConflict,
    LocalKeyOutsideCommittee,
}

impl CommitteeNetworkConfigurationError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Committee(_) => "NETWORK_COMMITTEE_INVALID",
            Self::DuplicateCommitteeIdentity => "NETWORK_COMMITTEE_IDENTITY_DUPLICATE",
            Self::DuplicatePeerAddress => "NETWORK_COMMITTEE_ADDRESS_DUPLICATE",
            Self::InvalidPeerAddress => "NETWORK_COMMITTEE_ADDRESS_INVALID",
            Self::DuplicateActorIdentity => "NETWORK_ACTOR_IDENTITY_DUPLICATE",
            Self::ActorConsensusKeyConflict => "NETWORK_ACTOR_CONSENSUS_KEY_CONFLICT",
            Self::LocalKeyOutsideCommittee => "NETWORK_LOCAL_KEY_OUTSIDE_COMMITTEE",
        }
    }
}

impl fmt::Display for CommitteeNetworkConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CommitteeNetworkConfigurationError {}

/// A registered authenticated channel with an independently bounded receive queue.
pub struct CommitteeChannel<E: Clock> {
    pub sender: lookup::Sender<ed25519::PublicKey, E>,
    pub receiver: lookup::Receiver<ed25519::PublicKey>,
}

/// All channels required by the v1 chain pipeline.
pub struct CommitteeChannels<E: Clock> {
    pub actions: CommitteeChannel<E>,
    pub blocks: CommitteeChannel<E>,
    pub marshal_resolution: CommitteeChannel<E>,
    pub state_resolution: CommitteeChannel<E>,
    pub simplex_votes: CommitteeChannel<E>,
    pub simplex_certificates: CommitteeChannel<E>,
    pub simplex_resolution: CommitteeChannel<E>,
}

/// The fixed peer provider and blocker shared by broadcast, consensus, marshal,
/// and state resolution.
pub type CommitteePeerOracle = lookup::Oracle<ed25519::PublicKey>;

/// A configured network before its supervised lookup actors are started.
pub struct AuthenticatedCommitteeNetwork<E>
where
    E: Spawner + BufferPooler + Clock + CryptoRng + RuntimeNetwork + Metrics,
{
    network: lookup::Network<E, ed25519::PrivateKey>,
    oracle: CommitteePeerOracle,
    channels: CommitteeChannels<E>,
}

impl<E> AuthenticatedCommitteeNetwork<E>
where
    E: Spawner + BufferPooler + Clock + CryptoRng + RuntimeNetwork + Resolver + Metrics,
{
    /// Builds the real Commonware lookup network and installs peer set zero.
    ///
    /// The local key is consumed and must identify one of the four configured
    /// peers. A network actor key or any other wrong key fails before a listen
    /// socket or actor is started.
    pub fn new(
        context: E,
        genesis: &CommitteeNetworkGenesis,
        local_key: ConsensusNodeKey,
    ) -> Result<Self, CommitteeNetworkConfigurationError> {
        let local_node = local_key.node_id();
        let listen = genesis
            .local_address(&local_node)
            .ok_or(CommitteeNetworkConfigurationError::LocalKeyOutsideCommittee)?;
        let namespace = authenticated_network_namespace(genesis.chain_id);
        let mut config = lookup::Config::local(
            local_key.into_private_key(),
            &namespace,
            listen,
            AUTHENTICATED_NETWORK_MAX_MESSAGE_SIZE,
        );
        // v1 never tracks previous, future, or reconfigured committees.
        config.tracked_peer_sets = commonware_utils::NZUsize!(1);

        let (mut network, mut oracle) = lookup::Network::new(context, config);
        let _ = oracle.track(GENESIS_COMMITTEE_INDEX, genesis.address_map()?);
        let channel_rate = || Quota::per_second(NZU32!(CHANNEL_MESSAGES_PER_SECOND));
        let (action_sender, action_receiver) =
            network.register(ACTION_CHANNEL, channel_rate(), ACTION_CHANNEL_BACKLOG);
        let (block_sender, block_receiver) = network.register(
            BLOCK_BROADCAST_CHANNEL,
            channel_rate(),
            BLOCK_CHANNEL_BACKLOG,
        );
        let (marshal_sender, marshal_receiver) = network.register(
            MARSHAL_RESOLVER_CHANNEL,
            channel_rate(),
            RESOLUTION_CHANNEL_BACKLOG,
        );
        let (state_sender, state_receiver) = network.register(
            STATE_SYNC_RESOLVER_CHANNEL,
            channel_rate(),
            RESOLUTION_CHANNEL_BACKLOG,
        );
        let (vote_sender, vote_receiver) = network.register(
            SIMPLEX_VOTE_CHANNEL,
            channel_rate(),
            CONSENSUS_CHANNEL_BACKLOG,
        );
        let (certificate_sender, certificate_receiver) = network.register(
            SIMPLEX_CERTIFICATE_CHANNEL,
            channel_rate(),
            CONSENSUS_CHANNEL_BACKLOG,
        );
        let (simplex_resolver_sender, simplex_resolver_receiver) = network.register(
            SIMPLEX_RESOLVER_CHANNEL,
            channel_rate(),
            CONSENSUS_CHANNEL_BACKLOG,
        );

        debug_assert_eq!(RESOLUTION_CHANNEL_BACKLOG, RESOLVER_MAILBOX_SIZE.get());
        Ok(Self {
            network,
            oracle,
            channels: CommitteeChannels {
                actions: CommitteeChannel {
                    sender: action_sender,
                    receiver: action_receiver,
                },
                blocks: CommitteeChannel {
                    sender: block_sender,
                    receiver: block_receiver,
                },
                marshal_resolution: CommitteeChannel {
                    sender: marshal_sender,
                    receiver: marshal_receiver,
                },
                state_resolution: CommitteeChannel {
                    sender: state_sender,
                    receiver: state_receiver,
                },
                simplex_votes: CommitteeChannel {
                    sender: vote_sender,
                    receiver: vote_receiver,
                },
                simplex_certificates: CommitteeChannel {
                    sender: certificate_sender,
                    receiver: certificate_receiver,
                },
                simplex_resolution: CommitteeChannel {
                    sender: simplex_resolver_sender,
                    receiver: simplex_resolver_receiver,
                },
            },
        })
    }

    /// Clones the authoritative provider/blocker before startup wiring.
    pub fn peer_oracle(&self) -> CommitteePeerOracle {
        self.oracle.clone()
    }

    /// Starts all supervised lookup actors.
    ///
    /// Dropping channel handles does not stop unrelated channels. Runtime
    /// shutdown stops the network, and awaiting the returned handle proves all
    /// listener, dialer, tracker, router, and peer actors exited.
    pub fn start(self) -> (CommitteeChannels<E>, CommitteePeerOracle, Handle<()>) {
        let handle = self.network.start();
        (self.channels, self.oracle, handle)
    }
}

#[cfg(test)]
mod tests {
    use super::super::FIXED_COMMITTEE_SIZE;
    use super::*;
    use commonware_cryptography::Signer as _;

    fn peer(seed: u64, port: u16) -> CommitteePeer {
        CommitteePeer::new(
            ConsensusNodeId::from(ed25519::PrivateKey::from_seed(seed).public_key()),
            SocketAddr::from(([127, 0, 0, 1], port)),
        )
    }

    #[test]
    fn genesis_requires_exact_unique_role_separated_peers() {
        let peers = (0..FIXED_COMMITTEE_SIZE)
            .map(|index| peer(index as u64, 31_000 + index as u16))
            .collect::<Vec<_>>();
        let genesis = CommitteeNetworkGenesis::new(ChainId::new([7; 32]), peers.clone(), vec![])
            .expect("four unique consensus peers are valid");
        assert_eq!(genesis.peers().len(), FIXED_COMMITTEE_SIZE);
        assert_eq!(
            authenticated_network_namespace(genesis.chain_id()).len(),
            AUTHENTICATED_NETWORK_NAMESPACE.len() + 32
        );

        let mut duplicate_address = peers.clone();
        duplicate_address[1].address = duplicate_address[0].address;
        assert_eq!(
            CommitteeNetworkGenesis::new(ChainId::new([7; 32]), duplicate_address, vec![]),
            Err(CommitteeNetworkConfigurationError::DuplicatePeerAddress)
        );

        let actor = ActorId::from(peers[0].node_id.public_key().clone());
        assert_eq!(
            CommitteeNetworkGenesis::new(ChainId::new([7; 32]), peers, vec![actor]),
            Err(CommitteeNetworkConfigurationError::ActorConsensusKeyConflict)
        );
    }
}
