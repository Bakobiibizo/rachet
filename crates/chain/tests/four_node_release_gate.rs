use commonware_codec::Encode as _;
use commonware_cryptography::{Signer as _, ed25519};
use futures::channel::oneshot;
use rachet_chain::{
    application::{GenesisMetadata, GenesisState},
    engine::{
        CommitteeNetworkGenesis, CommitteePeer, ConsensusNodeKey, FIXED_COMMITTEE_SIZE,
        LiveNodeConfig, live_runtime_config, run_live_node,
    },
    mempool::PendingPoolLimits,
};
use rachet_client::transport::NodeClient;
use rachet_core::{
    actions::{Action, ClaimDefinition, CreateJob, ResolutionPolicy, SignedAction},
    artifacts::{ContentRef, GitArtifact, GitHash},
    blocks::ConsensusNodeId,
    bounded::{BoundedBytes, BoundedVec},
    limits::ProtocolLimits,
    mechanisms::{
        CanonicalMechanismConfig, GenesisConfig, GenesisProtocolConfig, MechanismId,
        MechanismSelection, MechanismVersion,
    },
    primitives::{ActorId, ChainId, ProtocolVersion, Sha256Digest},
};
use serde_json::Value;
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    thread,
    time::{Duration, Instant, SystemTime},
};

const CHAIN_ID: ChainId = ChainId::new([0x67; 32]);
const TARGET_HEIGHT: u64 = 1_000;
const CRASH_HEIGHT: u64 = 250;
const RECOVERY_GAP_HEIGHT: u64 = 350;
const GATE_TIMEOUT: Duration = Duration::from_secs(240);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const PEER_READINESS_ROUNDS: usize = 3;
const AUTHORITY_SEED: u64 = 0x6700_0001;
const ACTOR_SEED: u64 = 0x6700_0002;

fn reserve_addresses(count: usize) -> Vec<SocketAddr> {
    let listeners = (0..count)
        .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve loopback address"))
        .collect::<Vec<_>>();
    listeners
        .iter()
        .map(|listener| listener.local_addr().expect("reserved address"))
        .collect()
}

fn temporary_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rachet-four-node-release-gate-{}-{nonce}",
        std::process::id()
    ))
}

fn authority() -> ActorId {
    ActorId::from(ed25519::PrivateKey::from_seed(AUTHORITY_SEED).public_key())
}

fn genesis_state() -> GenesisState {
    let mechanism = MechanismSelection::new(
        MechanismId::M00,
        MechanismVersion::V1_0_0,
        CanonicalMechanismConfig::empty(),
    );
    GenesisState::new(
        CHAIN_ID,
        GenesisConfig::new(GenesisProtocolConfig::V1, vec![mechanism]).unwrap(),
        ProtocolLimits::V1,
        GenesisMetadata::new(1_725_000_000_123, b"run 67 four-node release gate".to_vec()).unwrap(),
        vec![authority()],
    )
    .unwrap()
}

fn node_config(
    index: usize,
    network_addresses: &[SocketAddr],
    rpc_addresses: &[SocketAddr],
    keys: &[ed25519::PrivateKey],
) -> LiveNodeConfig {
    let peers = keys
        .iter()
        .zip(network_addresses.iter().copied())
        .map(|(key, address)| CommitteePeer::new(ConsensusNodeId::from(key.public_key()), address))
        .collect();
    let network = CommitteeNetworkGenesis::new(CHAIN_ID, peers, vec![authority()]).unwrap();
    LiveNodeConfig::new(
        network,
        genesis_state(),
        ConsensusNodeKey::new(keys[index].clone()),
        PendingPoolLimits::new(1_024, 64, 16 * 1024 * 1024, 32),
        format!("release-node-{index}"),
    )
    .unwrap()
    .with_rpc_listen(rpc_addresses[index])
}

struct RunningNode {
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<(), rachet_chain::engine::LiveNodeError>>>,
}

impl RunningNode {
    fn start(config: LiveNodeConfig, storage: PathBuf) -> Self {
        let (shutdown, stopped) = oneshot::channel();
        let thread = thread::spawn(move || {
            run_live_node(
                live_runtime_config(storage).with_read_write_timeout(Duration::from_secs(5)),
                config,
                async move {
                    let _ = stopped.await;
                },
            )
        });
        Self {
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    fn stop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .expect("live node thread must not panic")
                .expect("live node must stop cleanly");
        }
    }
}

impl Drop for RunningNode {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn client(address: SocketAddr) -> NodeClient {
    NodeClient::new(&format!("http://{address}")).unwrap()
}

fn height(value: &Value) -> u64 {
    value["finalized_height"]
        .as_u64()
        .expect("health response has finalized height")
}

fn connected_peers(value: &Value) -> u64 {
    value["connected_peers"]
        .as_u64()
        .expect("health response has connected peer count")
}

fn wait_for_height(clients: &[NodeClient], indexes: &[usize], target: u64, label: &str) {
    let started = Instant::now();
    let mut observed = vec![0; indexes.len()];
    loop {
        let mut complete = true;
        for (position, index) in indexes.iter().copied().enumerate() {
            match clients[index].health() {
                Ok(health) => {
                    observed[position] = height(&health);
                    complete &= observed[position] >= target;
                }
                Err(_) => complete = false,
            }
        }
        if complete {
            return;
        }
        assert!(
            started.elapsed() < GATE_TIMEOUT,
            "{label} did not reach height {target}; observed {observed:?}"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_peer_readiness(client: &NodeClient, target: u64, label: &str) {
    let started = Instant::now();
    let mut stable_rounds = 0;
    let mut observed = 0;
    loop {
        match client.health() {
            Ok(health) => {
                observed = connected_peers(&health);
                stable_rounds = if observed == target {
                    stable_rounds + 1
                } else {
                    0
                };
                if stable_rounds == PEER_READINESS_ROUNDS {
                    return;
                }
            }
            Err(_) => stable_rounds = 0,
        }
        assert!(
            started.elapsed() < GATE_TIMEOUT,
            "{label} did not retain {target} connected peers; observed {observed}"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

fn bounded<const MAX: usize>(bytes: &[u8]) -> BoundedBytes<MAX> {
    BoundedBytes::try_from(bytes).unwrap()
}

fn release_action() -> (SignedAction<Action>, String) {
    let customer = ed25519::PrivateKey::from_seed(ACTOR_SEED);
    let create = CreateJob {
        artifact: GitArtifact::new(
            bounded(b"https://example.invalid/rachet-release-gate.git"),
            GitHash::sha1([0x11; 20]),
            GitHash::sha256([0x22; 32]),
            ContentRef::new(
                Sha256Digest::from([0x33; 32]),
                bounded(b"release-gate/spec"),
                bounded(b"text/plain"),
            ),
        ),
        claims: BoundedVec::new(vec![ClaimDefinition::new(bounded(
            b"one-node forwarding reaches every proposer",
        ))])
        .unwrap(),
        resolution_policy: ResolutionPolicy::ExperimentAuthority {
            authority: authority(),
        },
        validation_opens_at: 1_000_000,
        validation_closes_at: 1_000_100,
        reveal_closes_at: None,
        challenge_closes_at: None,
        supersedes: None,
        metadata: bounded(b"chain-018-four-node-release-gate"),
    };
    let job_id = create.job_id();
    let action = SignedAction::sign(
        &customer,
        ProtocolVersion::V1,
        CHAIN_ID,
        0,
        u64::MAX,
        Action::CreateJob(Box::new(create)),
    )
    .unwrap();
    (action, hex(job_id.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn real_four_node_stack_finalizes_one_thousand_blocks_forwards_recovers_and_replays() {
    assert_eq!(FIXED_COMMITTEE_SIZE, 4);
    let network_addresses = reserve_addresses(FIXED_COMMITTEE_SIZE);
    let rpc_addresses = reserve_addresses(FIXED_COMMITTEE_SIZE);
    let keys = (0..FIXED_COMMITTEE_SIZE)
        .map(|index| ed25519::PrivateKey::from_seed(0x6701_0000 + index as u64))
        .collect::<Vec<_>>();
    let storage_root = temporary_directory();
    let storage = (0..FIXED_COMMITTEE_SIZE)
        .map(|index| storage_root.join(format!("node-{index}")))
        .collect::<Vec<_>>();
    let mut nodes = (0..FIXED_COMMITTEE_SIZE)
        .map(|index| {
            RunningNode::start(
                node_config(index, &network_addresses, &rpc_addresses, &keys),
                storage[index].clone(),
            )
        })
        .collect::<Vec<_>>();
    let clients = rpc_addresses
        .iter()
        .copied()
        .map(client)
        .collect::<Vec<_>>();
    let all = (0..FIXED_COMMITTEE_SIZE).collect::<Vec<_>>();

    wait_for_height(&clients, &all, 10, "initial live network");
    wait_for_peer_readiness(
        &clients[1],
        u64::try_from(FIXED_COMMITTEE_SIZE - 1).unwrap(),
        "action-ingress node",
    );
    let (action, job_id) = release_action();
    let admitted = clients[1]
        .submit_action(&hex(action.encode().as_ref()))
        .expect("one node must admit and forward the signed action");
    assert_eq!(admitted["forwarded_to"], 3);

    let started = Instant::now();
    loop {
        let finalized_everywhere = clients.iter().all(|client| client.job(&job_id).is_ok());
        if finalized_everywhere {
            break;
        }
        assert!(
            started.elapsed() < GATE_TIMEOUT,
            "forwarded action did not finalize on every node"
        );
        thread::sleep(POLL_INTERVAL);
    }

    wait_for_height(&clients, &all, CRASH_HEIGHT, "pre-crash network");
    nodes[0].stop();
    wait_for_height(
        &clients,
        &[1, 2, 3],
        RECOVERY_GAP_HEIGHT,
        "three-node quorum while node zero is stopped",
    );
    nodes[0] = RunningNode::start(
        node_config(0, &network_addresses, &rpc_addresses, &keys),
        storage[0].clone(),
    );
    wait_for_height(
        &clients,
        &all,
        RECOVERY_GAP_HEIGHT + 25,
        "restarted node catch-up",
    );
    wait_for_height(&clients, &all, TARGET_HEIGHT, "release chain");

    let canonical_block = clients[0]
        .block(TARGET_HEIGHT)
        .expect("node zero retains release-height block");
    assert_eq!(canonical_block["height"], TARGET_HEIGHT);
    assert!(canonical_block["state_root"].as_str().is_some());
    assert!(canonical_block["qmdb_state_root"].as_str().is_some());
    for (index, client) in clients.iter().enumerate().skip(1) {
        assert_eq!(
            client
                .block(TARGET_HEIGHT)
                .unwrap_or_else(|error| panic!("node {index} release block: {error}")),
            canonical_block,
            "all nodes must archive the identical block and roots at height {TARGET_HEIGHT}"
        );
    }

    for (index, client) in clients.iter().enumerate() {
        let replay = client
            .verify_replay()
            .unwrap_or_else(|error| panic!("node {index} pure replay: {error}"));
        assert_eq!(replay["verified"], true);
        assert!(
            replay["finalized_height"].as_u64().unwrap() >= TARGET_HEIGHT,
            "node {index} replay must cover the release height"
        );
        assert_eq!(replay["archive"], "commonware_storage::archive::immutable");
        assert_eq!(replay["executor"], "rachet_core::transition::execute_block");
    }

    println!(
        "four_node_release_gate target_height={TARGET_HEIGHT} block_id={} state_root={} qmdb_state_root={} forwarded_to={} restart_gap={} pure_replay_nodes={}",
        canonical_block["block_id"],
        canonical_block["state_root"],
        canonical_block["qmdb_state_root"],
        admitted["forwarded_to"],
        RECOVERY_GAP_HEIGHT - CRASH_HEIGHT,
        clients.len(),
    );

    for node in &mut nodes {
        node.stop();
    }
    std::fs::remove_dir_all(&storage_root).expect("closed release storage must be removable");
}
