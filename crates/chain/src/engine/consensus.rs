//! Fixed-committee Simplex consensus wiring.
//!
//! This boundary deliberately admits only Commonware's attributable Ed25519
//! certificate scheme and deterministic round-robin election. Consensus key
//! material is wrapped in a chain-specific type and committee membership uses
//! [`ConsensusNodeId`], never the protocol's network-actor identities.

use commonware_consensus::{
    CertifiableAutomaton, Relay, Reporter,
    simplex::{
        self, Engine,
        config::Floor,
        elector::RoundRobin,
        scheme::ed25519 as simplex_ed25519,
        types::{Activity, Context},
    },
    types::{Epoch, ViewDelta},
};
use commonware_cryptography::{Digest, Sha256, Signer as _, ed25519};
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_utils::ordered::Set;
use rachet_core::blocks::ConsensusNodeId;
use rand_core::CryptoRng;
use std::{fmt, num::NonZeroUsize, time::Duration};

/// The exact number of consensus nodes fixed by v1 genesis configuration.
pub const FIXED_COMMITTEE_SIZE: usize = 4;

/// The attributable Ed25519 certificate scheme fixed by section 19.1.
pub type ConsensusScheme = simplex_ed25519::Scheme;

/// The deterministic, unshuffled election configuration fixed by section 19.2.
pub type ConsensusElector = RoundRobin<Sha256>;

/// A consensus private key, intentionally not interchangeable with actor keys.
#[derive(Clone)]
pub struct ConsensusNodeKey {
    private_key: ed25519::PrivateKey,
}

impl ConsensusNodeKey {
    /// Wraps key material loaded from the consensus-node key configuration.
    pub const fn new(private_key: ed25519::PrivateKey) -> Self {
        Self { private_key }
    }

    /// Returns the corresponding typed consensus-node identity.
    pub fn node_id(&self) -> ConsensusNodeId {
        ConsensusNodeId::from(self.private_key.public_key())
    }

    /// Transfers the key to the authenticated committee transport.
    ///
    /// This remains crate-private so callers cannot erase the consensus-key
    /// role at the public chain boundary.
    pub(crate) fn into_private_key(self) -> ed25519::PrivateKey {
        self.private_key
    }
}

/// The immutable four-node v1 consensus committee.
#[derive(Clone, Debug)]
pub struct FixedCommittee {
    participants: Set<ed25519::PublicKey>,
}

impl FixedCommittee {
    /// Validates an exact, duplicate-free four-node committee.
    pub fn new(nodes: Vec<ConsensusNodeId>) -> Result<Self, ConsensusConfigurationError> {
        if nodes.len() != FIXED_COMMITTEE_SIZE {
            return Err(ConsensusConfigurationError::CommitteeSize {
                actual: nodes.len(),
            });
        }
        let participants = Set::try_from(
            nodes
                .into_iter()
                .map(|node| node.public_key().clone())
                .collect::<Vec<_>>(),
        )
        .map_err(|_| ConsensusConfigurationError::DuplicateCommitteeNode)?;
        Ok(Self { participants })
    }

    /// Returns public keys in the canonical ordering used by certificates and election.
    pub fn public_keys(&self) -> Vec<ed25519::PublicKey> {
        self.participants.iter().cloned().collect()
    }

    /// Creates the node's attributable signer, rejecting keys outside the fixed committee.
    pub fn signer(
        &self,
        namespace: &[u8],
        key: ConsensusNodeKey,
    ) -> Result<ConsensusScheme, ConsensusConfigurationError> {
        ConsensusScheme::signer(namespace, self.participants.clone(), key.private_key)
            .ok_or(ConsensusConfigurationError::KeyOutsideCommittee)
    }
}

/// Invalid fixed-committee consensus configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsensusConfigurationError {
    /// The committee did not contain exactly four entries.
    CommitteeSize { actual: usize },
    /// At least two committee entries identified the same consensus node.
    DuplicateCommitteeNode,
    /// The configured private key did not identify a committee member.
    KeyOutsideCommittee,
}

impl ConsensusConfigurationError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::CommitteeSize { .. } => "CONSENSUS_COMMITTEE_SIZE_INVALID",
            Self::DuplicateCommitteeNode => "CONSENSUS_COMMITTEE_NODE_DUPLICATE",
            Self::KeyOutsideCommittee => "CONSENSUS_LOCAL_KEY_OUTSIDE_COMMITTEE",
        }
    }
}

impl fmt::Display for ConsensusConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommitteeSize { actual } => write!(
                formatter,
                "consensus committee must contain {FIXED_COMMITTEE_SIZE} nodes, got {actual}"
            ),
            Self::DuplicateCommitteeNode => {
                formatter.write_str("consensus committee contains a duplicate node")
            }
            Self::KeyOutsideCommittee => {
                formatter.write_str("consensus key does not belong to the fixed committee")
            }
        }
    }
}

impl std::error::Error for ConsensusConfigurationError {}

/// Rachet's constrained Simplex configuration.
///
/// Unlike Commonware's general configuration this has no election field:
/// [`new_simplex_engine`] always installs unshuffled [`RoundRobin<Sha256>`].
pub struct SimplexEngineConfig<B, D: Digest, A, R, F, T> {
    pub scheme: ConsensusScheme,
    pub blocker: B,
    pub automaton: A,
    pub relay: R,
    pub reporter: F,
    pub strategy: T,
    pub partition: String,
    pub mailbox_size: NonZeroUsize,
    pub epoch: Epoch,
    pub floor: Floor<ConsensusScheme, D>,
    pub replay_buffer: NonZeroUsize,
    pub write_buffer: NonZeroUsize,
    pub page_cache: CacheRef,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub timeout_retry: Duration,
    pub activity_timeout: ViewDelta,
    pub skip_timeout: ViewDelta,
    pub fetch_timeout: Duration,
    pub fetch_concurrent: NonZeroUsize,
    pub forwarding: simplex::config::ForwardingPolicy,
}

/// The only Simplex engine type constructed by the chain adapter.
pub type SimplexConsensusEngine<E, B, D, A, R, F, T> =
    Engine<E, ConsensusScheme, ConsensusElector, B, D, A, R, F, T>;

/// Constructs real Commonware Simplex with Ed25519 certificates and round-robin election.
pub fn new_simplex_engine<E, B, D, A, R, F, T>(
    context: E,
    config: SimplexEngineConfig<B, D, A, R, F, T>,
) -> SimplexConsensusEngine<E, B, D, A, R, F, T>
where
    E: BufferPooler + Clock + CryptoRng + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = ed25519::PublicKey>,
    D: Digest,
    A: CertifiableAutomaton<Context = Context<D, ed25519::PublicKey>, Digest = D>,
    R: Relay<Digest = D, PublicKey = ed25519::PublicKey, Plan = simplex::Plan<ed25519::PublicKey>>,
    F: Reporter<Activity = Activity<ConsensusScheme, D>>,
    T: Strategy,
{
    Engine::new(
        context,
        simplex::Config {
            scheme: config.scheme,
            elector: ConsensusElector::default(),
            blocker: config.blocker,
            automaton: config.automaton,
            relay: config.relay,
            reporter: config.reporter,
            strategy: config.strategy,
            partition: config.partition,
            mailbox_size: config.mailbox_size,
            epoch: config.epoch,
            floor: config.floor,
            replay_buffer: config.replay_buffer,
            write_buffer: config.write_buffer,
            page_cache: config.page_cache,
            leader_timeout: config.leader_timeout,
            certification_timeout: config.certification_timeout,
            timeout_retry: config.timeout_retry,
            activity_timeout: config.activity_timeout,
            skip_timeout: config.skip_timeout,
            fetch_timeout: config.fetch_timeout,
            fetch_concurrent: config.fetch_concurrent,
            forwarding: config.forwarding,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u64) -> ConsensusNodeKey {
        ConsensusNodeKey::new(ed25519::PrivateKey::from_seed(seed))
    }

    #[test]
    fn committee_is_exact_unique_and_uses_typed_consensus_keys() {
        let keys = (0..FIXED_COMMITTEE_SIZE as u64)
            .map(key)
            .collect::<Vec<_>>();
        let committee = FixedCommittee::new(keys.iter().map(ConsensusNodeKey::node_id).collect())
            .expect("four unique consensus nodes form the fixed committee");
        assert_eq!(committee.public_keys().len(), FIXED_COMMITTEE_SIZE);
        assert!(committee.signer(b"rachet/test", key(0)).is_ok());
        assert_eq!(
            committee.signer(b"rachet/test", key(99)).unwrap_err(),
            ConsensusConfigurationError::KeyOutsideCommittee
        );

        let duplicate = vec![
            key(0).node_id(),
            key(0).node_id(),
            key(1).node_id(),
            key(2).node_id(),
        ];
        assert_eq!(
            FixedCommittee::new(duplicate).unwrap_err(),
            ConsensusConfigurationError::DuplicateCommitteeNode
        );
        assert_eq!(
            FixedCommittee::new(vec![key(0).node_id()]).unwrap_err(),
            ConsensusConfigurationError::CommitteeSize { actual: 1 }
        );
    }
}
