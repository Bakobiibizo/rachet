use commonware_cryptography::{Signer as _, ed25519};
use commonware_p2p::{
    Address, AddressableManager as _, Receiver as _, Recipients, Sender as _, authenticated::lookup,
};
use commonware_runtime::{Clock as _, Quota, Runner as _, Spawner as _, Supervisor as _};
use commonware_utils::{NZU32, ordered::Map};
use futures::{FutureExt as _, select};
use rachet_chain::engine::{
    ACTION_CHANNEL_BACKLOG, AUTHENTICATED_NETWORK_MAX_MESSAGE_SIZE, AuthenticatedCommitteeNetwork,
    CommitteeChannel, CommitteeChannels, CommitteeNetworkConfigurationError,
    CommitteeNetworkGenesis, CommitteePeer, ConsensusNodeKey, FIXED_COMMITTEE_SIZE,
    authenticated_network_namespace,
};
use rachet_chain::ingress::ACTION_CHANNEL;
use rachet_core::{
    blocks::ConsensusNodeId,
    primitives::{ActorId, ChainId},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    time::Duration,
};

const CONNECT_ATTEMPTS: usize = 200;
const CONNECT_STABLE_ROUNDS: usize = 3;
const DELIVERY_ATTEMPTS: usize = 200;
const UNKNOWN_ATTEMPTS: usize = 30;
const RETRY_DELAY: Duration = Duration::from_millis(50);
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

fn reserve_loopback_addresses(count: usize) -> Vec<SocketAddr> {
    // Keep listener ports out of Linux's normal ephemeral client-port range.
    // Back-to-back real-network tests otherwise risk recycling a predecessor's
    // just-closed client tuple as this test's listener endpoint.
    let mut listeners = Vec::with_capacity(count);
    for port in 20_000..30_000 {
        if let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
            listeners.push(listener);
            if listeners.len() == count {
                break;
            }
        }
    }
    assert_eq!(
        listeners.len(),
        count,
        "enough non-ephemeral loopback ports must be available"
    );
    listeners
        .iter()
        .map(|listener| listener.local_addr().expect("reserved local address"))
        .collect()
}

fn payload(tag: u8, public_key: &ed25519::PublicKey) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + public_key.as_ref().len());
    payload.push(tag);
    payload.extend_from_slice(public_key.as_ref());
    payload
}

async fn exchange_channel<E>(
    context: &E,
    mut channels: Vec<CommitteeChannel<E>>,
    public_keys: &[ed25519::PublicKey],
    tag: u8,
) where
    E: commonware_runtime::Clock + Send + 'static,
{
    let mut stable_rounds = 0;
    for _ in 0..CONNECT_ATTEMPTS {
        let connected_senders =
            channels
                .iter_mut()
                .enumerate()
                .fold(0usize, |connected, (index, channel)| {
                    connected
                        + usize::from(
                            channel
                                .sender
                                .send(Recipients::All, payload(tag, &public_keys[index]), true)
                                .len()
                                == FIXED_COMMITTEE_SIZE - 1,
                        )
                });
        let fully_connected = connected_senders == FIXED_COMMITTEE_SIZE;
        stable_rounds = if fully_connected {
            stable_rounds + 1
        } else {
            0
        };
        if stable_rounds == CONNECT_STABLE_ROUNDS {
            break;
        }
        context.sleep(RETRY_DELAY).await;
    }
    assert_eq!(
        stable_rounds, CONNECT_STABLE_ROUNDS,
        "every authenticated sender must observe a stable full committee before traffic assertions"
    );
    let (mut senders, receivers): (Vec<_>, Vec<_>) = channels
        .into_iter()
        .map(|channel| (channel.sender, channel.receiver))
        .unzip();
    let expected = public_keys
        .iter()
        .map(|public_key| (public_key.clone(), payload(tag, public_key)))
        .collect::<BTreeMap<_, _>>();
    for (index, mut receiver) in receivers.into_iter().enumerate() {
        let local_key = public_keys[index].clone();
        let mut received = BTreeSet::new();
        for _ in 0..DELIVERY_ATTEMPTS {
            if received.len() == FIXED_COMMITTEE_SIZE - 1 {
                break;
            }
            // Commonware's authenticated sender is intentionally unreliable:
            // local acceptance does not guarantee remote delivery. Retry only
            // the still-missing peer messages while retaining the same bounded
            // deadline and requiring complete authenticated receipt.
            for (sender_index, sender) in senders.iter_mut().enumerate() {
                let sender_key = &public_keys[sender_index];
                if sender_index != index && !received.contains(sender_key) {
                    let _ = sender.send(
                        Recipients::One(local_key.clone()),
                        payload(tag, sender_key),
                        true,
                    );
                }
            }
            let receive = receiver.recv().fuse();
            let retry = context.sleep(RETRY_DELAY).fuse();
            futures::pin_mut!(receive, retry);
            select! {
                result = receive => match result {
                    Ok((sender, message)) => {
                    assert_ne!(sender, local_key);
                    assert_eq!(message, expected[&sender].as_slice());
                    assert_eq!(expected[&sender][0], tag);
                    received.insert(sender);
                    }
                    Err(error) => panic!("authenticated committee channel closed: {error:?}"),
                },
                _ = retry => {}
            }
        }
        assert_eq!(
            received.len(),
            FIXED_COMMITTEE_SIZE - 1,
            "typed committee traffic for channel tag {tag} at receiver {index} did not arrive from every remote peer"
        );
    }
}

#[test]
fn four_genesis_peers_exchange_all_bounded_channels_and_reject_actor_and_unknown_keys() {
    let addresses = reserve_loopback_addresses(FIXED_COMMITTEE_SIZE + 1);
    let addresses_after_shutdown = addresses.clone();
    let committee_keys = (0..FIXED_COMMITTEE_SIZE)
        .map(|index| ed25519::PrivateKey::from_seed(0xC011_0000 + index as u64))
        .collect::<Vec<_>>();
    let public_keys = committee_keys
        .iter()
        .map(|key| key.public_key())
        .collect::<Vec<_>>();
    let actor_key = ed25519::PrivateKey::from_seed(0xAC70_0001);
    let actor_id = ActorId::from(actor_key.public_key());
    let chain_id = ChainId::new([0xC1; 32]);
    let peers = public_keys
        .iter()
        .cloned()
        .zip(addresses.iter().copied())
        .map(|(public_key, address)| CommitteePeer::new(ConsensusNodeId::from(public_key), address))
        .collect::<Vec<_>>();
    let genesis = CommitteeNetworkGenesis::new(chain_id, peers, vec![actor_id])
        .expect("fixed role-separated network genesis");

    let runner = commonware_runtime::tokio::Runner::new(
        commonware_runtime::tokio::Config::default()
            .with_worker_threads(FIXED_COMMITTEE_SIZE + 1)
            .with_read_write_timeout(RECEIVE_TIMEOUT),
    );
    runner.start(move |context| async move {
        let wrong_key = AuthenticatedCommitteeNetwork::new(
            context.child("wrong_key"),
            &genesis,
            ConsensusNodeKey::new(actor_key.clone()),
        );
        assert!(matches!(
            wrong_key.err(),
            Some(CommitteeNetworkConfigurationError::LocalKeyOutsideCommittee)
        ));

        let mut action_channels = Vec::with_capacity(FIXED_COMMITTEE_SIZE);
        let mut block_channels = Vec::with_capacity(FIXED_COMMITTEE_SIZE);
        let mut marshal_channels = Vec::with_capacity(FIXED_COMMITTEE_SIZE);
        let mut state_channels = Vec::with_capacity(FIXED_COMMITTEE_SIZE);
        let mut vote_channels = Vec::with_capacity(FIXED_COMMITTEE_SIZE);
        let mut certificate_channels = Vec::with_capacity(FIXED_COMMITTEE_SIZE);
        let mut simplex_resolver_channels = Vec::with_capacity(FIXED_COMMITTEE_SIZE);
        let mut handles = Vec::with_capacity(FIXED_COMMITTEE_SIZE + 1);
        for (index, private_key) in committee_keys.into_iter().enumerate() {
            let network = AuthenticatedCommitteeNetwork::new(
                context
                    .child("committee_peer")
                    .with_attribute("index", index),
                &genesis,
                ConsensusNodeKey::new(private_key),
            )
            .expect("each genesis consensus key configures its declared address");
            let (node_channels, _oracle, handle) = network.start();
            let CommitteeChannels {
                actions,
                blocks,
                marshal_resolution,
                state_resolution,
                simplex_votes,
                simplex_certificates,
                simplex_resolution,
            } = node_channels;
            action_channels.push(actions);
            block_channels.push(blocks);
            marshal_channels.push(marshal_resolution);
            state_channels.push(state_resolution);
            vote_channels.push(simplex_votes);
            certificate_channels.push(simplex_certificates);
            simplex_resolver_channels.push(simplex_resolution);
            handles.push(handle);
        }

        // These markers exercise four separately registered typed surfaces:
        // canonical actions, full blocks, marshal repair, and QMDB resolution.
        exchange_channel(&context, action_channels, &public_keys, 1).await;
        exchange_channel(&context, block_channels, &public_keys, 2).await;
        exchange_channel(&context, marshal_channels, &public_keys, 3).await;
        exchange_channel(&context, state_channels, &public_keys, 4).await;
        exchange_channel(&context, vote_channels, &public_keys, 5).await;
        exchange_channel(&context, certificate_channels, &public_keys, 6).await;
        exchange_channel(&context, simplex_resolver_channels, &public_keys, 7).await;

        // A valid Ed25519 actor knows every address and uses the exact chain
        // namespace, but it is absent from genesis peer set zero. Committee
        // listeners must reject its authenticated handshakes.
        let outsider_address = addresses[FIXED_COMMITTEE_SIZE];
        let outsider_public = actor_key.public_key();
        let outsider_view = Map::try_from(
            public_keys
                .iter()
                .cloned()
                .zip(addresses.iter().copied().map(Address::from))
                .chain(std::iter::once((
                    outsider_public.clone(),
                    Address::from(outsider_address),
                )))
                .collect::<Vec<_>>(),
        )
        .expect("outsider directory identities are unique");
        let namespace = authenticated_network_namespace(chain_id);
        let mut outsider_config = lookup::Config::local(
            actor_key,
            &namespace,
            outsider_address,
            AUTHENTICATED_NETWORK_MAX_MESSAGE_SIZE,
        );
        outsider_config.dial_frequency = Duration::from_millis(25);
        outsider_config.peer_connection_cooldown = Duration::from_millis(50);
        let (mut outsider_network, mut outsider_oracle) =
            lookup::Network::new(context.child("unknown_actor_peer"), outsider_config);
        let _ = outsider_oracle.track(0, outsider_view);
        let (mut outsider_sender, outsider_receiver) = outsider_network.register(
            ACTION_CHANNEL,
            Quota::per_second(NZU32!(256)),
            ACTION_CHANNEL_BACKLOG,
        );
        handles.push(outsider_network.start());

        for _ in 0..UNKNOWN_ATTEMPTS {
            assert!(
                outsider_sender
                    .send(Recipients::All, payload(1, &outsider_public), true)
                    .is_empty(),
                "an actor/unknown identity must never establish a consensus peer path"
            );
            context.sleep(RETRY_DELAY).await;
        }

        drop(outsider_sender);
        drop(outsider_receiver);
        context
            .child("shutdown")
            .spawn(|shutdown_context| async move {
                shutdown_context
                    .stop(0, Some(SHUTDOWN_TIMEOUT))
                    .await
                    .expect("authenticated network must stop cleanly");
            });
        context.stopped().await.expect("shutdown signal");
        for handle in handles {
            context
                .timeout(SHUTDOWN_TIMEOUT, handle)
                .await
                .expect("network actors must stop before deadline")
                .expect("network actor tree must exit cleanly");
        }
        // Lookup peer actors are supervised below the top-level network handle.
        // Give their cancellation destructors one scheduler turn before proving
        // that every operating-system listener has been released.
        context.sleep(Duration::from_millis(100)).await;
    });

    for address in addresses_after_shutdown {
        TcpListener::bind(address).expect("shutdown must release every genesis listen address");
    }
}
