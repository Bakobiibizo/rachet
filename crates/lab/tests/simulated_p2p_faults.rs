use rachet_lab::simulator::p2p::{
    FaultSchedule, LinkCondition, NetworkAction, P2pLabConfig, PeerId, ScheduledNetworkEvent,
    SimulatedP2pLab, UNSUPPORTED_CORRUPTION_MODES, UnsupportedCorruptionMode,
};

fn event(at_ms: u64, action: NetworkAction) -> ScheduledNetworkEvent {
    ScheduledNetworkEvent::new(at_ms, action)
}

fn config(seed: u64, peer_count: u16) -> P2pLabConfig {
    let mut config = P2pLabConfig::new(seed, peer_count, LinkCondition::lossless(1));
    config.settle_ms = 250;
    config
}

#[test]
fn declared_latency_schedule_replays_with_identical_trace_and_audit() {
    let schedule = FaultSchedule::new(vec![
        event(
            0,
            NetworkAction::SetLink {
                from: PeerId(0),
                to: PeerId(1),
                condition: LinkCondition::lossless(25),
            },
        ),
        event(
            10,
            NetworkAction::Send {
                from: PeerId(0),
                to: PeerId(1),
                payload: b"latency".to_vec(),
            },
        ),
    ])
    .unwrap();

    let first = SimulatedP2pLab::run(config(7, 2), schedule.clone()).unwrap();
    let second = SimulatedP2pLab::run(config(7, 2), schedule).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.deliveries.len(), 1);
    // Commonware adds the 8-byte channel frame's deterministic transport time
    // to the declared 10ms send offset and 25ms simulated link latency.
    assert_eq!(first.deliveries[0].received_at_ms, 43);
    assert_eq!(first.deliveries[0].payload, b"latency");
}

#[test]
fn jitter_is_seeded_and_replays_the_same_delivery_variation() {
    let mut events = vec![event(
        0,
        NetworkAction::SetLink {
            from: PeerId(0),
            to: PeerId(1),
            condition: LinkCondition::new(40, 15, 0).unwrap(),
        },
    )];
    for index in 0_u8..6 {
        events.push(event(
            10 + u64::from(index) * 60,
            NetworkAction::Send {
                from: PeerId(0),
                to: PeerId(1),
                payload: vec![index],
            },
        ));
    }
    let schedule = FaultSchedule::new(events).unwrap();

    let first = SimulatedP2pLab::run(config(19, 2), schedule.clone()).unwrap();
    let second = SimulatedP2pLab::run(config(19, 2), schedule).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.deliveries.len(), 6);
    let delays = first
        .deliveries
        .iter()
        .map(|delivery| {
            let sequence = u64::from(delivery.payload[0]);
            delivery.received_at_ms - (10 + sequence * 60)
        })
        .collect::<Vec<_>>();
    assert!(
        delays.windows(2).any(|pair| pair[0] != pair[1]),
        "nonzero jitter must vary at least one sampled delivery delay"
    );
}

#[test]
fn full_drop_rate_drops_locally_accepted_messages_deterministically() {
    let schedule = FaultSchedule::new(vec![
        event(
            0,
            NetworkAction::SetLink {
                from: PeerId(0),
                to: PeerId(1),
                condition: LinkCondition::new(1, 0, 10_000).unwrap(),
            },
        ),
        event(
            5,
            NetworkAction::Send {
                from: PeerId(0),
                to: PeerId(1),
                payload: b"drop-me".to_vec(),
            },
        ),
    ])
    .unwrap();

    let output = SimulatedP2pLab::run(config(23, 2), schedule).unwrap();

    assert!(output.submissions[0].accepted);
    assert!(output.deliveries.is_empty());
}

#[test]
fn disconnected_peer_drops_traffic_and_reconnect_restores_links() {
    let schedule = FaultSchedule::new(vec![
        event(0, NetworkAction::Disconnect { peer: PeerId(1) }),
        event(
            5,
            NetworkAction::Send {
                from: PeerId(0),
                to: PeerId(1),
                payload: b"while-offline".to_vec(),
            },
        ),
        event(10, NetworkAction::Reconnect { peer: PeerId(1) }),
        event(
            15,
            NetworkAction::Send {
                from: PeerId(0),
                to: PeerId(1),
                payload: b"after-reconnect".to_vec(),
            },
        ),
    ])
    .unwrap();

    let output = SimulatedP2pLab::run(config(29, 2), schedule).unwrap();

    assert_eq!(output.submissions.len(), 2);
    assert_eq!(output.deliveries.len(), 1);
    assert_eq!(output.deliveries[0].payload, b"after-reconnect");
}

#[test]
fn partition_preserves_in_group_delivery_and_heal_restores_cross_group_links() {
    let schedule = FaultSchedule::new(vec![
        event(
            0,
            NetworkAction::Partition {
                left: vec![PeerId(0), PeerId(1)],
                right: vec![PeerId(2), PeerId(3)],
            },
        ),
        event(
            5,
            NetworkAction::Send {
                from: PeerId(0),
                to: PeerId(2),
                payload: b"partitioned".to_vec(),
            },
        ),
        event(
            5,
            NetworkAction::Send {
                from: PeerId(0),
                to: PeerId(1),
                payload: b"same-side".to_vec(),
            },
        ),
        event(10, NetworkAction::HealPartition),
        event(
            15,
            NetworkAction::Send {
                from: PeerId(0),
                to: PeerId(2),
                payload: b"healed".to_vec(),
            },
        ),
    ])
    .unwrap();

    let output = SimulatedP2pLab::run(config(31, 4), schedule).unwrap();
    let payloads = output
        .deliveries
        .iter()
        .map(|delivery| delivery.payload.as_slice())
        .collect::<Vec<_>>();

    assert!(payloads.contains(&b"same-side".as_slice()));
    assert!(payloads.contains(&b"healed".as_slice()));
    assert!(!payloads.contains(&b"partitioned".as_slice()));
}

#[test]
fn corrupted_peer_sends_arbitrary_attributed_bytes_without_faking_unsupported_modes() {
    let malformed = vec![0xff, 0x00, 0x13, 0x37];
    let schedule = FaultSchedule::new(vec![event(
        5,
        NetworkAction::CorruptedPeerSend {
            from: PeerId(1),
            to: PeerId(0),
            payload: malformed.clone(),
        },
    )])
    .unwrap();

    let output = SimulatedP2pLab::run(config(37, 2), schedule).unwrap();

    assert!(output.submissions[0].corrupted_peer);
    assert_eq!(output.deliveries.len(), 1);
    assert_eq!(output.deliveries[0].from, PeerId(1));
    assert_eq!(output.deliveries[0].payload, malformed);
    assert_eq!(
        UNSUPPORTED_CORRUPTION_MODES,
        &[
            UnsupportedCorruptionMode::IdentitySpoofing,
            UnsupportedCorruptionMode::UnauthenticatedInjection,
            UnsupportedCorruptionMode::InFlightPayloadMutation,
        ]
    );
}
