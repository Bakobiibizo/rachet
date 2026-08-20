use commonware_cryptography::{Signer as _, ed25519};
use commonware_runtime::{Clock as _, Metrics as _, Runner as _, Spawner as _, Supervisor as _};
use rachet_chain::{
    application::{GenesisMetadata, GenesisState},
    engine::{
        CommitteeNetworkGenesis, CommitteePeer, ConsensusNodeKey, FIXED_COMMITTEE_SIZE, LiveNode,
        LiveNodeConfig, live_runtime_config,
    },
    mempool::PendingPoolLimits,
};
use rachet_core::{
    blocks::ConsensusNodeId,
    limits::ProtocolLimits,
    mechanisms::{
        CanonicalMechanismConfig, GenesisConfig, GenesisProtocolConfig, MechanismId,
        MechanismSelection, MechanismVersion,
    },
    primitives::{ActorId, ChainId},
};
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    time::{Duration, SystemTime},
};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

fn reserve_addresses(count: usize) -> Vec<SocketAddr> {
    let listeners = (0..count)
        .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve loopback address"))
        .collect::<Vec<_>>();
    listeners
        .iter()
        .map(|listener| listener.local_addr().expect("reserved address"))
        .collect()
}

fn storage_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rachet-live-runtime-{}-{nonce}",
        std::process::id()
    ))
}

fn node_config(addresses: &[SocketAddr], keys: &[ed25519::PrivateKey]) -> LiveNodeConfig {
    let chain_id = ChainId::new([0x56; 32]);
    let authority = ActorId::from(ed25519::PrivateKey::from_seed(0xA0A0).public_key());
    let peers = keys
        .iter()
        .zip(addresses.iter().copied())
        .map(|(key, address)| CommitteePeer::new(ConsensusNodeId::from(key.public_key()), address))
        .collect();
    let network_genesis =
        CommitteeNetworkGenesis::new(chain_id, peers, vec![authority.clone()]).unwrap();
    let mechanism = MechanismSelection::new(
        MechanismId::M00,
        MechanismVersion::V1_0_0,
        CanonicalMechanismConfig::new(Vec::new()).unwrap(),
    );
    let genesis_state = GenesisState::new(
        chain_id,
        GenesisConfig::new(GenesisProtocolConfig::V1, vec![mechanism]).unwrap(),
        ProtocolLimits::V1,
        GenesisMetadata::new(1_725_000_000_123, b"live runtime test".to_vec()).unwrap(),
        vec![authority],
    )
    .unwrap();
    LiveNodeConfig::new(
        network_genesis,
        genesis_state,
        ConsensusNodeKey::new(keys[0].clone()),
        PendingPoolLimits::new(1_024, 64, 16 * 1024 * 1024, 32),
        "live-node-0",
    )
    .unwrap()
}

#[test]
fn one_tokio_process_restarts_and_stops_the_complete_live_actor_tree() {
    let addresses = reserve_addresses(FIXED_COMMITTEE_SIZE);
    let local_address = addresses[0];
    let keys = (0..FIXED_COMMITTEE_SIZE)
        .map(|index| ed25519::PrivateKey::from_seed(0x4c49_5645_0000 + index as u64))
        .collect::<Vec<_>>();
    let storage = storage_directory();

    for _ in 0..2 {
        let config = node_config(&addresses, &keys);
        let runner = commonware_runtime::tokio::Runner::new(
            live_runtime_config(&storage).with_read_write_timeout(Duration::from_secs(2)),
        );
        runner.start(move |context| async move {
            let node = LiveNode::start(context.child("node"), config)
                .await
                .expect("the complete live node must assemble or recover");
            assert!(node.pending_pool().is_empty());
            assert_eq!(node.finalized_index().snapshot().finalized_height, 0);

            context.sleep(Duration::from_millis(100)).await;
            let commonware_metrics = context.encode();
            for release_metric in [
                "current_view",
                "pending_blocks",
                "stateful_db_set_any_commit_duration",
            ] {
                assert!(
                    commonware_metrics.contains(release_metric),
                    "live Commonware registry is missing {release_metric}: {commonware_metrics}"
                );
            }

            context.child("shutdown").spawn(|shutdown| async move {
                shutdown.sleep(Duration::from_millis(500)).await;
                shutdown
                    .stop(0, Some(SHUTDOWN_TIMEOUT))
                    .await
                    .expect("all live actors must release their supervisor signals");
            });
            context.stopped().await.expect("runtime shutdown signal");
            node.stopped()
                .await
                .expect("every top-level live actor must exit cleanly");
        });

        TcpListener::bind(local_address).expect("authenticated P2P listener must be released");
    }
    std::fs::remove_dir_all(storage).expect("closed storage directory must be removable");
}
