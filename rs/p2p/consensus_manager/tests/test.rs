use std::{sync::Arc, time::Duration};

use ic_p2p_test_utils::{
    consensus::TestConsensus,
    turmoil::{
        add_peer_manager_to_sim, add_transport_to_sim, run_simulation_for, wait_for,
        wait_for_timeout, waiter_fut, PeerManagerAction,
    },
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types::RegistryVersion;
use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3};
use tokio::sync::Notify;
use turmoil::Builder;

const TIMEOUT_DURATION_TRIGGER: Duration = Duration::from_secs(5);

#[test]
fn test_artifact_sent_to_other_peer() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(20))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_2.clone()),
            waiter_fut(),
        );
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        processor_1.push_advert(1);

        wait_for(&mut sim, || processor_2.received_advert_once(1))
            .expect("NODE_2 did not receive the advert from NODE_1.");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

#[test]
fn test_artifact_in_validated_pool_is_sent_to_peer_joining_subnet() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(20))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_2.clone()),
            waiter_fut(),
        );
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        // Node_1 sends the advert
        processor_1.push_advert(1);

        // Node_2 has received the advert
        wait_for(&mut sim, || processor_2.received_advert_once(1)).unwrap();

        // Node 3 joins the subnet
        let processor_3 = TestConsensus::new(log.clone(), NODE_3);
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_3.clone()),
            waiter_fut(),
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_3, RegistryVersion::from(4))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        // Node 3 has received the advert
        wait_for(&mut sim, || processor_3.received_advert_once(1))
            .expect("NODE_3 did not receive the advert from NODE_1 after joining the subnet.");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

#[test]
fn test_flapping_connection_does_not_cause_duplicate_artifact_downloads() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(20))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_2.clone()),
            waiter_fut(),
        );
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        // Node_1 sends the advert
        processor_1.push_advert(1);

        // Node_2 has received the advert
        wait_for(&mut sim, || processor_2.received_advert_once(1)).unwrap();

        // Disconnect nodes, and run simulation for 5s.
        sim.partition(NODE_1.to_string(), NODE_2.to_string());
        processor_1.push_advert(2);
        wait_for_timeout(
            &mut sim,
            || processor_2.received_advert_once(2),
            Duration::from_secs(5),
        )
        .unwrap();

        sim.repair(NODE_1.to_string(), NODE_2.to_string());
        wait_for(&mut sim, || processor_2.received_advert_once(2)).unwrap();

        assert!(processor_2.received_advert_once(1));

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

/// Test that nodes retransmits adverts tp peers that reconnect.
/// Scenario
/// 1. Node_1 connects to Node_2 and Node_3.
/// 2. Node_1 produces an artifact.
/// 3. Node_2 and Node_3 receive the artifact.
/// 4. Node_2 disconnects and re-connects to Node_1.
/// 5. Assert that Node_2 receives the artifact again from Node_1.
#[test]
fn test_adverts_are_retransmitted_on_reconnection() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(20))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2);
        let processor_3 = TestConsensus::new(log.clone(), NODE_3);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_2.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_3.clone()),
            waiter_fut(),
        );
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_3, RegistryVersion::from(4))))
            .unwrap();

        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        processor_1.push_advert(1);

        wait_for(&mut sim, || processor_2.received_advert_once(1))
            .expect("NODE_2 should receive `advert 1` from `NODE_1`.");

        wait_for(&mut sim, || processor_3.received_advert_once(1))
            .expect("NODE_3 should receive `advert 1` from `NODE_1`.");

        // Crash `NODE_3` nodes, and run simulation for 5s for `NODE_1` to detect disconnection.
        sim.crash(NODE_3.to_string());
        run_simulation_for(&mut sim, TIMEOUT_DURATION_TRIGGER).unwrap();
        sim.bounce(NODE_3.to_string());

        wait_for(&mut sim, || processor_3.received_advert_count(1) == 2)
            .expect("NODE_3 should receive `advert 1` twice from `NODE_1` since it reconnected.");

        wait_for(&mut sim, || processor_2.received_advert_once(1))
            .expect("NODE_2 should receive `advert 1` from `NODE_1`.");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

/// Test that a node transmit adverts to its peers for adverts that were produced at a time
/// its peer was disconnected, but that eventually reconnect.
/// Scenario:
/// 1. Node_1 connects to Node_2.
/// 2. Node_1 and Node_2 disconnect.
/// 3. Node_1's processor produces an artifact to be sent.
/// 4. Node_1 and Node_2 reconnect.
/// 5. Node_2 receives the artifact.
#[test]
fn test_new_adverts_are_transmitted_on_reconnection() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(20))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2);
        let processor_3 = TestConsensus::new(log.clone(), NODE_3);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_2.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            None,
            Some(processor_3.clone()),
            waiter_fut(),
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_3, RegistryVersion::from(4))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        // ping pong advert
        processor_1.push_advert(1);
        wait_for(&mut sim, || processor_2.received_advert_once(1))
            .expect("`NODE_2` should receive the advert from `NODE_1`.");

        // Disconnect nodes, and run simulation for +5s to cause timeout in transport.
        // TODO: Adjust this timeout duration to be injected with a config struct.
        sim.partition(NODE_1.to_string(), NODE_2.to_string());
        run_simulation_for(&mut sim, TIMEOUT_DURATION_TRIGGER).unwrap();

        // Node_1 starts a send task while the link is broken.
        processor_1.push_advert(2);

        wait_for(&mut sim, || processor_3.received_advert_once(2)).expect(
            "`NODE_3` is connected to `NODE_1` and should receive the advert from `NODE_1`.",
        );

        sim.repair(NODE_1.to_string(), NODE_2.to_string());

        wait_for(&mut sim, || processor_2.received_advert_once(2))
            .expect("`NODE_2` should receive the advert from `NODE_1` after reconnecting.");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}
