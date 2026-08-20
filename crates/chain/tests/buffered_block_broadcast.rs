use commonware_broadcast::Broadcaster as _;
use commonware_codec::{DecodeExt as _, Encode as _, Write as _};
use commonware_cryptography::{Digestible as _, Signer as _, ed25519, sha256::Digest};
use commonware_p2p::{
    Manager as _, Recipients, Sender as _,
    simulated::{Link, Network},
};
use commonware_runtime::{Clock as _, IoBuf, Quota, Runner as _, Supervisor as _, deterministic};
use commonware_storage::merkle::{Location, mmr};
use commonware_utils::{NZUsize, non_empty_range, ordered::Set};
use rachet_chain::{
    application::StatefulBlock,
    engine::{
        BLOCK_BROADCAST_CHANNEL, BLOCK_BROADCAST_MAX_MESSAGE_SIZE, BLOCK_CACHE_PER_PEER,
        BlockBroadcastMailbox, new_block_broadcast,
    },
};
use rachet_core::{
    blocks::{Block, BlockHeader, ConsensusContext, ConsensusNodeId, action_root, receipt_root},
    primitives::{ChainId, MechanismSetId, ProtocolVersion, Sha256Digest},
};
use std::{collections::BTreeMap, num::NonZeroU32, time::Duration};

const VALIDATOR_COUNT: usize = 4;
const LINK_LATENCY: Duration = Duration::from_millis(10);
const PROPAGATION_DELAY: Duration = Duration::from_millis(50);
const NETWORK_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

type Registration = (
    commonware_p2p::simulated::Sender<ed25519::PublicKey, deterministic::Context>,
    commonware_p2p::simulated::Receiver<ed25519::PublicKey>,
);

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from([byte; 32])
}

fn block(height: u64, leader: ed25519::PublicKey) -> StatefulBlock {
    let parent = digest(height.wrapping_sub(1) as u8);
    let context = ConsensusContext {
        consensus_epoch: 0,
        view: height,
        leader: ConsensusNodeId::from(leader),
        parent_view: height.saturating_sub(1),
        parent_block: parent,
    };
    let actions = Vec::new();
    let protocol = Block::new(
        context,
        BlockHeader {
            protocol_version: ProtocolVersion::V1,
            chain_id: ChainId::new([0x52; 32]),
            height,
            epoch: 0,
            parent_block: parent,
            parent_state_root: digest(height as u8),
            action_root: action_root(&actions),
            receipt_root: receipt_root(&[]),
            post_state_root: digest(height.wrapping_add(1) as u8),
            mechanism_set_id: MechanismSetId::from_digest(digest(0x10)),
            timestamp_ms: height,
        },
        actions,
    )
    .expect("test protocol block must satisfy canonical bounds");

    // StatefulBlock deliberately has no public unchecked constructor. Assemble
    // its canonical fields and decode through the production boundary instead.
    let mut encoded = protocol.encode().to_vec();
    digest(height.wrapping_add(2) as u8).write(&mut encoded);
    Digest::from([height.wrapping_add(3) as u8; 32]).write(&mut encoded);
    non_empty_range!(
        Location::<mmr::Family>::new(height),
        Location::<mmr::Family>::new(height + 1)
    )
    .write(&mut encoded);
    StatefulBlock::decode(encoded.as_slice()).expect("test Stateful block must decode")
}

#[test]
fn canonical_blocks_disseminate_to_four_peers_with_bounded_cache_and_hardened_decode() {
    let runner = deterministic::Runner::timed(Duration::from_secs(15));
    runner.start(|context| async move {
        // A fifth authenticated identity remains a raw sender so malformed
        // traffic exercises the same receiver without replacing any validator.
        let private_keys = (0..=VALIDATOR_COUNT)
            .map(|index| ed25519::PrivateKey::from_seed(0x4252_4f41_4443 + index as u64))
            .collect::<Vec<_>>();
        let peers = private_keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>();
        let validators = peers[..VALIDATOR_COUNT].to_vec();
        let attacker = peers[VALIDATOR_COUNT].clone();

        let (network, oracle) = Network::<deterministic::Context, ed25519::PublicKey>::new(
            context.child("network"),
            commonware_p2p::simulated::Config {
                max_size: BLOCK_BROADCAST_MAX_MESSAGE_SIZE,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
        );
        network.start();

        let mut registrations = BTreeMap::<_, Registration>::new();
        for peer in &peers {
            let registration = oracle
                .control(peer.clone())
                .register(BLOCK_BROADCAST_CHANNEL, NETWORK_QUOTA)
                .await
                .expect("broadcast channel registration must succeed");
            registrations.insert(peer.clone(), registration);
        }

        let link = Link {
            latency: LINK_LATENCY,
            jitter: Duration::ZERO,
            success_rate: 1.0,
        };
        for source in &peers {
            for target in &peers {
                if source != target {
                    oracle
                        .add_link(source.clone(), target.clone(), link.clone())
                        .await
                        .expect("full-mesh broadcast link must be configured");
                }
            }
        }
        oracle.manager().track(
            0,
            Set::try_from(peers.clone()).expect("test identities are unique"),
        );

        let (mut attacker_sender, _) = registrations
            .remove(&attacker)
            .expect("attacker registration must exist");
        let mut mailboxes = BTreeMap::<ed25519::PublicKey, BlockBroadcastMailbox>::new();
        for peer in &validators {
            let channel = registrations
                .remove(peer)
                .expect("validator registration must exist");
            let (engine, mailbox) = new_block_broadcast(
                context.child("broadcast").with_attribute("peer", peer),
                peer.clone(),
                oracle.manager(),
            );
            engine.start(channel);
            mailboxes.insert(peer.clone(), mailbox);
        }

        // Let every engine observe latest.primary before local or remote cache insertion.
        context.sleep(PROPAGATION_DELAY).await;

        let proposer = &validators[0];
        let observer = &validators[1];
        let first = block(1, proposer.clone());
        let first_digest = first.digest();
        assert!(
            mailboxes[proposer]
                .broadcast(Recipients::All, first.clone())
                .accepted()
        );
        context.sleep(PROPAGATION_DELAY).await;
        for peer in &validators {
            assert_eq!(
                mailboxes[peer].get(first_digest).await.as_deref(),
                Some(&first),
                "canonical block must reach validator {peer:?}"
            );
        }

        // Repeated copies share one digest/cache entry. Filling the remaining
        // unique slots must retain it; one more unique block must evict it.
        for _ in 0..3 {
            assert!(
                mailboxes[proposer]
                    .broadcast(Recipients::All, first.clone())
                    .accepted()
            );
        }
        for height in 2..=BLOCK_CACHE_PER_PEER as u64 {
            assert!(
                mailboxes[proposer]
                    .broadcast(Recipients::All, block(height, proposer.clone()))
                    .accepted()
            );
        }
        context.sleep(PROPAGATION_DELAY).await;
        assert!(mailboxes[observer].get(first_digest).await.is_some());

        let overflow = block(BLOCK_CACHE_PER_PEER as u64 + 1, proposer.clone());
        let overflow_digest = overflow.digest();
        assert!(
            mailboxes[proposer]
                .broadcast(Recipients::All, overflow.clone())
                .accepted()
        );
        context.sleep(PROPAGATION_DELAY).await;
        assert!(
            mailboxes[observer].get(first_digest).await.is_none(),
            "per-sender cache must evict beyond its fixed bound"
        );
        assert_eq!(
            mailboxes[observer].get(overflow_digest).await.as_deref(),
            Some(&overflow)
        );

        // Invalid enum/truncated bytes are dropped by buffered's production
        // codec receiver and never prevent a later canonical block.
        let victim = validators[2].clone();
        for malformed in [vec![0xff], vec![0; 64]] {
            assert_eq!(
                attacker_sender.send(
                    Recipients::One(victim.clone()),
                    IoBuf::from(malformed),
                    false,
                ),
                vec![victim.clone()]
            );
        }
        context.sleep(PROPAGATION_DELAY).await;

        let recovered = block(10_000, validators[3].clone());
        let recovered_digest = recovered.digest();
        assert!(
            mailboxes[&validators[3]]
                .broadcast(Recipients::One(victim.clone()), recovered.clone())
                .accepted()
        );
        context.sleep(PROPAGATION_DELAY).await;
        assert_eq!(
            mailboxes[&victim].get(recovered_digest).await.as_deref(),
            Some(&recovered)
        );
    });
}
