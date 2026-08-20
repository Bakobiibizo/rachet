use commonware_codec::Encode as _;
use commonware_cryptography::{Signer as _, ed25519};
use commonware_p2p::{
    Address, AddressableManager as _, Recipients, Sender as _, authenticated::lookup,
};
use commonware_runtime::{Clock as _, Quota, Runner as _, Spawner as _, Supervisor as _};
use commonware_utils::{NZU32, ordered::Map};
use rachet_chain::{
    ingress::{
        ACTION_CHANNEL, ACTION_CHANNEL_MAX_MESSAGE_SIZE, ActionIngress, ActionStateSnapshot,
        IngressError, IngressState, IngressStateError, PeerIngressError,
    },
    mempool::{PendingActionPool, PendingPoolLimits},
};
use rachet_core::{
    actions::{Action, ActionVerificationContext, CloseJob, SignedAction},
    limits::MAX_ACTION_BYTES,
    primitives::{ActorId, ChainId, JobId, ProtocolVersion},
};
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener},
    sync::Arc,
    time::Duration,
};

const COMMITTEE_SIZE: usize = 3;
const MESSAGE_BACKLOG: usize = 64;
const CONNECT_ATTEMPTS: usize = 100;
const RETRY_DELAY: Duration = Duration::from_millis(50);
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const NAMESPACE: &[u8] = b"rachet/action-forwarding/v1";

#[derive(Clone, Copy)]
struct FixedState;

impl IngressState for FixedState {
    fn snapshot(&self, _: &ActorId) -> Result<ActionStateSnapshot, IngressStateError> {
        Ok(ActionStateSnapshot::new(
            ActionVerificationContext::current(ChainId::new([0x51; 32]), 1),
            0,
        ))
    }
}

fn reserve_loopback_addresses(count: usize) -> Vec<SocketAddr> {
    let listeners = (0..count)
        .map(|_| {
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("the ingress test must reserve a loopback port")
        })
        .collect::<Vec<_>>();
    listeners
        .iter()
        .map(|listener| listener.local_addr().expect("reserved local address"))
        .collect()
}

fn signed(seed: u64, nonce: u64) -> SignedAction<Action> {
    SignedAction::sign(
        &ed25519::PrivateKey::from_seed(seed),
        ProtocolVersion::V1,
        ChainId::new([0x51; 32]),
        nonce,
        10,
        Action::CloseJob(CloseJob::new(JobId::derive(&seed.to_be_bytes()))),
    )
    .expect("the test action must be bounded")
}

fn ingress() -> ActionIngress<FixedState> {
    ActionIngress::new(
        Arc::new(PendingActionPool::new(PendingPoolLimits::new(
            16,
            8,
            MAX_ACTION_BYTES * 4,
            2,
        ))),
        FixedState,
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn valid_json_action_reaches_authenticated_committee_and_invalid_inputs_never_forward() {
    let addresses = reserve_loopback_addresses(COMMITTEE_SIZE);
    let identities = (0..COMMITTEE_SIZE)
        .map(|index| ed25519::PrivateKey::from_seed(0x5100 + index as u64))
        .collect::<Vec<_>>();
    let public_keys = identities
        .iter()
        .map(|identity| identity.public_key())
        .collect::<Vec<_>>();
    let committee = Map::try_from(
        public_keys
            .iter()
            .cloned()
            .zip(addresses.iter().copied().map(Address::from))
            .collect::<Vec<_>>(),
    )
    .expect("the ingress committee must contain unique identities");

    let runner = commonware_runtime::tokio::Runner::new(
        commonware_runtime::tokio::Config::default()
            .with_worker_threads(COMMITTEE_SIZE)
            .with_read_write_timeout(RECEIVE_TIMEOUT),
    );
    runner.start(move |context| async move {
        let mut senders = Vec::with_capacity(COMMITTEE_SIZE);
        let mut receivers = Vec::with_capacity(COMMITTEE_SIZE);
        let mut handles = Vec::with_capacity(COMMITTEE_SIZE);

        for (index, identity) in identities.into_iter().enumerate() {
            let peer_context = context.child("action_peer").with_attribute("index", index);
            let mut config = lookup::Config::local(
                identity,
                NAMESPACE,
                addresses[index],
                ACTION_CHANNEL_MAX_MESSAGE_SIZE,
            );
            config.dial_frequency = Duration::from_millis(25);
            config.peer_connection_cooldown = Duration::from_millis(50);
            let (mut network, mut oracle) =
                lookup::Network::new(peer_context.child("network"), config);
            oracle.track(0, committee.clone());
            let (sender, receiver) = network.register(
                ACTION_CHANNEL,
                Quota::per_second(NZU32!(100)),
                MESSAGE_BACKLOG,
            );
            senders.push(sender);
            receivers.push(receiver);
            handles.push(network.start());
        }

        // A malformed bounded probe establishes that the real authenticated
        // lookup sender has connected to every other committee member. Peers
        // must reject every such probe before observing the valid action.
        let mut connected = false;
        for _ in 0..CONNECT_ATTEMPTS {
            if senders[0].send(Recipients::All, vec![0xff], false).len() == COMMITTEE_SIZE - 1 {
                connected = true;
                break;
            }
            context.sleep(RETRY_DELAY).await;
        }
        assert!(connected, "action sender must connect to the committee");

        let source = ingress();
        let valid = signed(70, 0);
        let mut invalid_signature = valid.clone();
        invalid_signature.signature = signed(71, 0).signature;
        let mut wrong_chain = valid.clone();
        wrong_chain.chain_id = ChainId::new([0x52; 32]);
        let mut wrong_version = valid.clone();
        wrong_version.version = ProtocolVersion::new(2);
        let invalid_cases = [
            (vec![0xfe], "ACTION_MALFORMED"),
            (vec![0; MAX_ACTION_BYTES + 1], "ACTION_TOO_LARGE"),
            (
                invalid_signature.encode().to_vec(),
                "ACTION_SIGNATURE_INVALID",
            ),
            (wrong_chain.encode().to_vec(), "ACTION_CHAIN_ID_INVALID"),
            (
                wrong_version.encode().to_vec(),
                "ACTION_VERSION_UNSUPPORTED",
            ),
            (signed(70, 3).encode().to_vec(), "PENDING_NONCE_GAP"),
        ];
        for (canonical, expected_code) in invalid_cases {
            let error = source
                .submit_canonical(&canonical, &mut senders[0])
                .expect_err("invalid external action must be rejected");
            assert_eq!(error.code(), expected_code);
            assert!(source.pool().is_empty());
        }
        let malformed_json = source
            .submit_json(
                br#"{"canonical_action":"00","unknown":true}"#,
                &mut senders[0],
            )
            .expect_err("unknown JSON fields must be rejected");
        assert_eq!(malformed_json, IngressError::MalformedJson);
        assert!(source.pool().is_empty());

        let request = format!(
            r#"{{"canonical_action":"{}"}}"#,
            encode_hex(valid.encode().as_ref())
        );
        let submitted = source
            .submit_json(request.as_bytes(), &mut senders[0])
            .expect("valid RPC JSON must admit and forward");
        assert_eq!(submitted.forwarded_to.len(), COMMITTEE_SIZE - 1);
        assert!(source.pool().contains(&valid.action_id()));
        let duplicate = source
            .submit_json(request.as_bytes(), &mut senders[0])
            .expect("duplicate action admission must be idempotent");
        assert!(duplicate.forwarded_to.is_empty());
        assert_eq!(source.pool().len(), 1);

        let valid_id = valid.action_id();
        let source_identity = public_keys[0].clone();
        for (index, mut receiver) in receivers.into_iter().enumerate().skip(1) {
            let peer_ingress = ingress();
            let expected_source = source_identity.clone();
            context
                .timeout(RECEIVE_TIMEOUT, async move {
                    loop {
                        match peer_ingress.receive_one(&mut receiver).await {
                            Ok(outcome) => {
                                assert_eq!(outcome.peer, expected_source);
                                assert!(peer_ingress.pool().contains(&valid_id));
                                assert_eq!(peer_ingress.pool().len(), 1);
                                break;
                            }
                            Err(PeerIngressError::Rejected { error, .. }) => {
                                assert_eq!(
                                    error.code(),
                                    "ACTION_MALFORMED",
                                    "externally rejected actions must never reach peer {index}"
                                );
                            }
                            Err(PeerIngressError::Network(error)) => {
                                panic!("authenticated action channel failed: {error:?}")
                            }
                        }
                    }
                })
                .await
                .expect("peer must receive the forwarded valid action");
        }

        drop(senders);
        context
            .child("shutdown")
            .spawn(|shutdown_context| async move {
                shutdown_context
                    .stop(0, Some(SHUTDOWN_TIMEOUT))
                    .await
                    .expect("the runtime must stop cleanly");
            });
        context
            .stopped()
            .await
            .expect("the shutdown signal must be delivered");
        for handle in handles {
            context
                .timeout(SHUTDOWN_TIMEOUT, handle)
                .await
                .expect("lookup network must stop before deadline")
                .expect("lookup network must exit cleanly");
        }
    });
}
