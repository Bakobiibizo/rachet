use commonware_actor::Feedback;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay, Reporter, Viewable as _,
    simplex::{self, config::Floor, types::Activity},
    types::{Epoch, View, ViewDelta},
};
use commonware_cryptography::{
    Digest as _, Hasher as _, Sha256, Signer as _, ed25519, sha256::Digest,
};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
use commonware_runtime::{
    Clock as _, Quota, Runner as _, Strategizer as _, Supervisor as _, buffer::paged::CacheRef,
    deterministic,
};
use commonware_utils::{
    NZU16, NZU32, NZUsize,
    channel::{fallible::OneshotExt as _, oneshot},
};
use rachet_chain::engine::{
    ConsensusNodeKey, FIXED_COMMITTEE_SIZE, FixedCommittee, SimplexEngineConfig, new_simplex_engine,
};
use rachet_core::{
    blocks::{Block, BlockHeader, ConsensusContext, ConsensusNodeId, action_root, receipt_root},
    primitives::{ChainId, MechanismSetId, ProtocolVersion},
};
use std::{
    collections::{BTreeMap, HashMap},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

const NAMESPACE: &[u8] = b"rachet/chain/simplex-ed25519/v1";
const TARGET_BLOCKS: usize = 32;
const CONSENSUS_QUOTA: Quota = Quota::per_second(NZU32!(1_000));
const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1_024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

type SimplexContext = simplex::types::Context<Digest, ed25519::PublicKey>;
type BlockStore = Arc<Mutex<HashMap<Digest, Block>>>;
type FinalizedHistory = Arc<Mutex<BTreeMap<View, (Digest, usize)>>>;

fn state_root(parent: Digest, context: &SimplexContext) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(NAMESPACE);
    hasher.update(parent.as_ref());
    hasher.update(&context.encode());
    hasher.finalize()
}

fn application_block(context: &SimplexContext, parent: &Block) -> Block {
    let actions = Vec::new();
    let parent_digest = parent.digest();
    Block::new(
        ConsensusContext {
            consensus_epoch: context.round.epoch().get(),
            view: context.round.view().get(),
            leader: ConsensusNodeId::from(context.leader.clone()),
            parent_view: context.parent.0.get(),
            parent_block: context.parent.1,
        },
        BlockHeader {
            protocol_version: ProtocolVersion::V1,
            chain_id: ChainId::new([0x53; 32]),
            height: parent.header.height + 1,
            epoch: 0,
            parent_block: parent_digest,
            parent_state_root: parent.header.post_state_root,
            action_root: action_root(&actions),
            receipt_root: receipt_root(&[]),
            post_state_root: state_root(parent.header.post_state_root, context),
            mechanism_set_id: MechanismSetId::from_digest(Sha256::hash(b"m00@1.0.0")),
            timestamp_ms: context.round.view().get(),
        },
        actions,
    )
    .expect("the deterministic application proposal is canonically bounded")
}

fn genesis(leader: ed25519::PublicKey) -> Block {
    let actions = Vec::new();
    Block::new(
        ConsensusContext {
            consensus_epoch: 0,
            view: 0,
            leader: ConsensusNodeId::from(leader),
            parent_view: 0,
            parent_block: Digest::EMPTY,
        },
        BlockHeader {
            protocol_version: ProtocolVersion::V1,
            chain_id: ChainId::new([0x53; 32]),
            height: 0,
            epoch: 0,
            parent_block: Digest::EMPTY,
            parent_state_root: Digest::EMPTY,
            action_root: action_root(&actions),
            receipt_root: receipt_root(&[]),
            post_state_root: Sha256::hash(b"rachet/chain/simplex-ed25519/genesis-state/v1"),
            mechanism_set_id: MechanismSetId::from_digest(Sha256::hash(b"m00@1.0.0")),
            timestamp_ms: 0,
        },
        actions,
    )
    .expect("the application genesis block is canonically bounded")
}

#[derive(Clone)]
struct ApplicationAutomaton {
    blocks: BlockStore,
}

impl Automaton for ApplicationAutomaton {
    type Context = SimplexContext;
    type Digest = Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();
        let proposed = {
            let mut blocks = self
                .blocks
                .lock()
                .expect("application block store lock is not poisoned");
            blocks.get(&context.parent.1).cloned().map(|parent| {
                let block = application_block(&context, &parent);
                let digest = block.digest();
                blocks.insert(digest, block);
                digest
            })
        };
        if let Some(digest) = proposed {
            sender.send_lossy(digest);
        }
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        let valid = {
            let blocks = self
                .blocks
                .lock()
                .expect("application block store lock is not poisoned");
            blocks.get(&context.parent.1).and_then(|parent| {
                blocks
                    .get(&payload)
                    .map(|candidate| candidate == &application_block(&context, parent))
            }) == Some(true)
        };
        sender.send_lossy(valid);
        receiver
    }
}

impl CertifiableAutomaton for ApplicationAutomaton {}

#[derive(Clone, Default)]
struct ApplicationRelay;

impl Relay for ApplicationRelay {
    type Digest = Digest;
    type PublicKey = ed25519::PublicKey;
    type Plan = simplex::Plan<Self::PublicKey>;

    fn broadcast(&mut self, _payload: Self::Digest, _plan: Self::Plan) -> Feedback {
        // The preceding buffered-broadcast work item owns full-block transport.
        // This test's shared store isolates the real Simplex ordering path.
        Feedback::Ok
    }
}

#[derive(Clone)]
struct ApplicationReporter {
    history: FinalizedHistory,
}

impl Reporter for ApplicationReporter {
    type Activity = Activity<rachet_chain::engine::ConsensusScheme, Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Activity::Finalization(finalization) = activity {
            let signer_count = finalization.certificate.signers.count();
            assert_eq!(
                signer_count,
                finalization.certificate.signatures.len(),
                "an attributable certificate carries one Ed25519 signature per signer"
            );
            self.history
                .lock()
                .expect("finalized history lock is not poisoned")
                .insert(
                    finalization.proposal.view(),
                    (finalization.proposal.payload, signer_count),
                );
        }
        Feedback::Ok
    }
}

#[test]
fn four_node_ed25519_round_robin_agrees_on_application_blocks() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let mut keys = (0..FIXED_COMMITTEE_SIZE as u64)
            .map(|index| {
                ConsensusNodeKey::new(ed25519::PrivateKey::from_seed(0x5349_4d50_4c45 + index))
            })
            .collect::<Vec<_>>();
        keys.sort_unstable_by_key(ConsensusNodeKey::node_id);
        let committee = FixedCommittee::new(keys.iter().map(ConsensusNodeKey::node_id).collect())
            .expect("the four consensus identities form the fixed committee");
        let participants = committee.public_keys();
        let schemes = keys
            .into_iter()
            .map(|key| {
                committee
                    .signer(NAMESPACE, key)
                    .expect("every node key belongs to the fixed committee")
            })
            .collect::<Vec<_>>();

        let genesis = genesis(participants[0].clone());
        let genesis_digest = genesis.digest();
        let blocks = Arc::new(Mutex::new(HashMap::from([(genesis_digest, genesis)])));
        let (network, oracle) = Network::new_with_peers(
            context.child("simplex_network"),
            NetworkConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            participants.clone(),
        )
        .await;
        network.start();

        let mut registrations = HashMap::with_capacity(FIXED_COMMITTEE_SIZE);
        for participant in &participants {
            let control = oracle.control(participant.clone());
            let votes = control
                .register(0, CONSENSUS_QUOTA)
                .await
                .expect("vote channel registration must succeed");
            let certificates = control
                .register(1, CONSENSUS_QUOTA)
                .await
                .expect("certificate channel registration must succeed");
            let resolver = control
                .register(2, CONSENSUS_QUOTA)
                .await
                .expect("resolver channel registration must succeed");
            registrations.insert(participant.clone(), (votes, certificates, resolver));
        }
        for sender in &participants {
            for receiver in &participants {
                if sender != receiver {
                    oracle
                        .add_link(
                            sender.clone(),
                            receiver.clone(),
                            Link {
                                latency: Duration::from_millis(5),
                                jitter: Duration::from_millis(1),
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .expect("the fixed committee must be fully connected");
                }
            }
        }

        let mut histories = Vec::with_capacity(FIXED_COMMITTEE_SIZE);
        for (index, participant) in participants.iter().enumerate() {
            let node_context = context.child("simplex_node").with_attribute("index", index);
            let history = Arc::new(Mutex::new(BTreeMap::new()));
            histories.push(Arc::clone(&history));
            let engine_config = SimplexEngineConfig {
                scheme: schemes[index].clone(),
                blocker: oracle.control(participant.clone()),
                automaton: ApplicationAutomaton {
                    blocks: Arc::clone(&blocks),
                },
                relay: ApplicationRelay,
                reporter: ApplicationReporter { history },
                strategy: node_context.strategy(NZUsize!(1)),
                partition: format!("simplex-node-{index}"),
                mailbox_size: NZUsize!(1_024),
                epoch: Epoch::zero(),
                floor: Floor::Genesis(genesis_digest),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&node_context, PAGE_SIZE, PAGE_CACHE_SIZE),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                fetch_timeout: Duration::from_secs(1),
                fetch_concurrent: NZUsize!(4),
                forwarding: simplex::config::ForwardingPolicy::Disabled,
            };
            let engine = new_simplex_engine(node_context, engine_config);
            let (votes, certificates, resolver) = registrations
                .remove(participant)
                .expect("every consensus node has registered channels");
            engine.start(votes, certificates, resolver);
        }

        for poll in 0..2_000 {
            if histories.iter().all(|history| {
                history
                    .lock()
                    .expect("finalized history lock is not poisoned")
                    .len()
                    >= TARGET_BLOCKS
            }) {
                break;
            }
            assert!(
                poll < 1_999,
                "Simplex stalled: finalized={:?}, known_blocks={}",
                histories
                    .iter()
                    .map(|history| history.lock().expect("history lock").len())
                    .collect::<Vec<_>>(),
                blocks.lock().expect("block store lock").len()
            );
            context.sleep(Duration::from_millis(10)).await;
        }

        let canonical = histories[0]
            .lock()
            .expect("finalized history lock is not poisoned")
            .iter()
            .take(TARGET_BLOCKS)
            .map(|(view, (digest, _))| (*view, *digest))
            .collect::<Vec<_>>();
        assert_eq!(canonical.len(), TARGET_BLOCKS);
        for history in &histories {
            let history = history
                .lock()
                .expect("finalized history lock is not poisoned");
            let finalized = history
                .iter()
                .take(TARGET_BLOCKS)
                .map(|(view, (digest, _))| (*view, *digest))
                .collect::<Vec<_>>();
            assert_eq!(finalized, canonical, "all four nodes must agree");
            assert!(
                history
                    .values()
                    .take(TARGET_BLOCKS)
                    .all(|(_, signers)| *signers >= 3),
                "every finalization needs an attributable three-of-four Ed25519 quorum"
            );
        }

        let blocks = blocks
            .lock()
            .expect("application block store lock is not poisoned");
        let mut parent = genesis_digest;
        for (view, digest) in canonical {
            let block = &blocks[&digest];
            assert_eq!(block.header.parent_block, parent);
            assert_eq!(block.header.height, view.get());
            assert_eq!(
                block.context.leader.public_key(),
                &participants[(view.get() as usize) % FIXED_COMMITTEE_SIZE],
                "unshuffled round-robin must choose the application-block leader"
            );
            parent = digest;
        }
    });
}
