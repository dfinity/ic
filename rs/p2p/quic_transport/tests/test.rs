use std::{sync::Arc, time::Duration};

use crate::common::{
    add_peer_manager_to_sim, add_transport_to_sim, wait_for, wait_for_timeout, ConnectivityChecker,
    PeerManagerAction, PeerRestrictedSevHandshake, PeerRestrictedTlsConfig,
};

use ic_logger::info;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types::RegistryVersion;
use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4, NODE_5};
use tokio::sync::Notify;
use turmoil::Builder;

mod common;

#[test]
fn ping_pong() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");

        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(10))
            .build();

        let exit_notify = Arc::new(Notify::new());

        let node_1_port = 8888;
        let node_2_port = 9999;

        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            node_1_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log,
            NODE_2,
            node_2_port,
            registry_handle.clone(),
            topology_watcher,
            conn_checker.clone(),
            None,
            None,
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_1,
                node_1_port,
                RegistryVersion::from(2),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_2,
                node_2_port,
                RegistryVersion::from(3),
            )))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || conn_checker.fully_connected())
            .expect("The network did not reach a fully connected state after startup");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    })
}

/// Test abrupt peer crashes and verify that dead connections are detected and repaired.
#[test]
fn test_peer_restart() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");

        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(20))
            .tick_duration(Duration::from_millis(100))
            .build();

        let exit_notify = Arc::new(Notify::new());

        let node_1_port = 8888;
        let node_2_port = 9999;

        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            node_1_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            node_2_port,
            registry_handle.clone(),
            topology_watcher,
            conn_checker.clone(),
            None,
            None,
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_1,
                node_1_port,
                RegistryVersion::from(2),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_2,
                node_2_port,
                RegistryVersion::from(3),
            )))
            .unwrap();

        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || conn_checker.fully_connected())
            .expect("The network did not reach a fully connected state after startup");

        info!(log, "Crashing node 1");
        sim.crash(NODE_1.to_string());
        conn_checker.reset(&NODE_1);

        wait_for(&mut sim, || conn_checker.unreachable(&NODE_1))
            .expect("Node 1 is still reachable from other nodes after crashing it.");

        info!(log, "Restarting node 1");
        sim.bounce(NODE_1.to_string());

        wait_for(&mut sim, || conn_checker.fully_connected())
            .expect("The network did not reach a fully connected state after restarting node 1");

        info!(log, "Crashing node 2");
        sim.crash(NODE_2.to_string());
        conn_checker.reset(&NODE_2);

        wait_for(&mut sim, || conn_checker.unreachable(&NODE_2))
            .expect("Node 2 is still reachable after crashing it.");

        info!(log, "Restarting node 2");
        sim.bounce(NODE_2.to_string());

        wait_for(&mut sim, || conn_checker.fully_connected())
            .expect("The network did not reach a fully connected state after restarting node 2.");

        // Finish test by exiting client.
        exit_notify.notify_waiters();
        sim.run().unwrap();
    })
}

/// Test changing subnet membership where nodes are added and removed.
#[test]
fn test_changing_subnet_membership() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");

        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(30))
            .tick_duration(Duration::from_millis(100))
            .build();

        let exit_notify = Arc::new(Notify::new());

        let node_1_port = 5555;
        let node_2_port = 6666;
        let node_3_port = 7777;
        let node_4_port = 8888;
        let node_5_port = 9999;

        let (peer_manager_cmd_sender, topology_watcher, mut registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2, NODE_3, NODE_4, NODE_5]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            node_1_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            node_2_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            node_3_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_4,
            node_4_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_5,
            node_5_port,
            registry_handle.clone(),
            topology_watcher,
            conn_checker.clone(),
            None,
            None,
        );

        // Add two starting nodes 1 and 2.
        info!(log, "Adding node 1 and 2");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_1,
                node_1_port,
                RegistryVersion::from(2),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_2,
                node_2_port,
                RegistryVersion::from(3),
            )))
            .unwrap();

        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || conn_checker.connected_pair(&NODE_1, &NODE_2)).unwrap();

        wait_for(&mut sim, || conn_checker.unreachable(&NODE_3)).unwrap();
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_4)).unwrap();
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_5)).unwrap();

        // Add Node 3
        info!(log, "Adding node 3");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_3,
                node_3_port,
                RegistryVersion::from(4),
            )))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || conn_checker.connected_pair(&NODE_1, &NODE_3)).unwrap();
        wait_for(&mut sim, || conn_checker.connected_pair(&NODE_2, &NODE_3)).unwrap();

        // Remove node 3 from registry. This should not actually remove the node since oldest registry version is lower.
        info!(log, "Removing node 3");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Remove((
                NODE_3,
                RegistryVersion::from(5),
            )))
            .unwrap();
        // Reset necessary to actually verify a new connection can still be established.
        conn_checker.reset(&NODE_1);
        conn_checker.reset(&NODE_2);
        conn_checker.reset(&NODE_3);
        wait_for(&mut sim, || {
            conn_checker.fully_connected_except(vec![NODE_4, NODE_5])
        })
        .unwrap();

        // Increase oldest registry version. This should actually remove the node.
        registry_handle.set_oldest_consensus_registry_version(RegistryVersion::from(5));
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || conn_checker.unreachable(&NODE_3)).unwrap();

        // Add node 4 and 5
        info!(log, "Adding node 4 and 5");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_4,
                node_4_port,
                RegistryVersion::from(7),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_5,
                node_5_port,
                RegistryVersion::from(8),
            )))
            .unwrap();
        registry_handle.registry_client.reload();
        wait_for(&mut sim, || {
            conn_checker.fully_connected_except(vec![NODE_3])
        })
        .unwrap();

        // Remove node 1 from registry. This should not actually remove the node since oldest registry version is lower.
        info!(log, "Removing node 1");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Remove((
                NODE_1,
                RegistryVersion::from(9),
            )))
            .unwrap();
        // Reset necessary to actually verify a new connection can still be established.
        conn_checker.reset(&NODE_1);
        conn_checker.reset(&NODE_2);
        conn_checker.reset(&NODE_4);
        conn_checker.reset(&NODE_5);
        wait_for(&mut sim, || {
            conn_checker.fully_connected_except(vec![NODE_1, NODE_3])
        })
        .unwrap();
        // Increase oldest registry version. This should actually remove the node.
        registry_handle.set_oldest_consensus_registry_version(RegistryVersion::from(9));
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_1)).unwrap();

        // Rejoin node 3
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_3)).unwrap();
        info!(log, "Rejoining node 3");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_3,
                node_3_port,
                RegistryVersion::from(10),
            )))
            .unwrap();
        wait_for(&mut sim, || {
            conn_checker.fully_connected_except(vec![NODE_1])
        })
        .unwrap();

        // Remove rest of nodes
        info!(log, "Removing all nodes");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Remove((
                NODE_2,
                RegistryVersion::from(11),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Remove((
                NODE_4,
                RegistryVersion::from(12),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Remove((
                NODE_5,
                RegistryVersion::from(13),
            )))
            .unwrap();
        registry_handle.set_oldest_consensus_registry_version(RegistryVersion::from(13));
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_1)).unwrap();
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_2)).unwrap();
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_3)).unwrap();
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_4)).unwrap();
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_5)).unwrap();

        exit_notify.notify_waiters();
        sim.run().unwrap();
    })
}

/// Test that we reconnect after AMD SEV-SNP handshake failures.
#[test]
fn test_transient_failing_sev() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");

        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(40))
            .tick_duration(Duration::from_millis(100))
            .build();

        let exit_notify = Arc::new(Notify::new());

        let node_1_port = 5555;
        let node_2_port = 6666;

        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2]);

        let sev = Arc::new(PeerRestrictedSevHandshake::new());
        sev.set_allowed_peers(vec![NODE_1, NODE_2]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            node_1_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            Some(sev.clone()),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            node_2_port,
            registry_handle.clone(),
            topology_watcher,
            conn_checker.clone(),
            None,
            Some(sev.clone()),
        );

        // Add two starting nodes 1 and 2.
        info!(log, "Adding node 1 and 2");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_1,
                node_1_port,
                RegistryVersion::from(2),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_2,
                node_2_port,
                RegistryVersion::from(3),
            )))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || conn_checker.fully_connected()).unwrap();

        // Node 1 will start to reject connections from node 2.
        sev.set_allowed_peers(vec![]);
        // Restart node 1 to reset connection
        sim.bounce(NODE_1.to_string());
        conn_checker.reset(&NODE_1);
        conn_checker.reset(&NODE_2);

        // Make sure we can't connect by trying to connect for a 7s.
        wait_for_timeout(
            &mut sim,
            || conn_checker.fully_connected(),
            Duration::from_secs(7),
        )
        .expect("Nodes should not connect");

        // Allow all nodes again
        sev.set_allowed_peers(vec![NODE_1, NODE_2]);
        wait_for(&mut sim, || conn_checker.fully_connected()).expect("Nodes failed to reconnect");

        // Do the inverse
        // Node 2 will start to reject connections from node 1.
        sev.set_allowed_peers(vec![]);
        // Restart node 1 to reset connection
        sim.bounce(NODE_2.to_string());
        conn_checker.reset(&NODE_1);
        conn_checker.reset(&NODE_2);

        // Try for 7s simulated time to connect
        wait_for_timeout(
            &mut sim,
            || conn_checker.fully_connected(),
            Duration::from_secs(7),
        )
        .expect("Nodes should not connect");

        // Allow all nodes again
        sev.set_allowed_peers(vec![NODE_1, NODE_2]);
        wait_for(&mut sim, || conn_checker.fully_connected()).expect("Nodes failed to reconnect");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    })
}

/// Test that we reconnect after TLS handshake failures.
#[test]
fn test_transient_failing_tls() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");

        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(20))
            .tick_duration(Duration::from_millis(100))
            .build();

        let exit_notify = Arc::new(Notify::new());

        let node_1_port = 5555;
        let node_2_port = 6666;

        let (peer_manager_cmd_sender, topology_watcher, mut registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2]);

        let tls_2 = Arc::new(PeerRestrictedTlsConfig::new(NODE_2, &registry_handle));
        tls_2.set_allowed_peers(vec![NODE_2]);

        // Client
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            node_1_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        // Server.
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            node_2_port,
            registry_handle.clone(),
            topology_watcher,
            conn_checker.clone(),
            Some(tls_2.clone()),
            None,
        );

        // Add two starting nodes 1 and 2.
        info!(log, "Adding node 1 and 2");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_1,
                node_1_port,
                RegistryVersion::from(2),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_2,
                node_2_port,
                RegistryVersion::from(3),
            )))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        // Make sure we can't connect by trying to connect for a 7s.
        wait_for_timeout(
            &mut sim,
            || conn_checker.fully_connected(),
            Duration::from_secs(7),
        )
        .expect("Nodes should not connect");

        // Node 2 is server here. Allow node 1 to connect again.
        tls_2.set_allowed_peers(vec![NODE_2, NODE_1]);
        // This triggers a tls reconfiguration because it is a topology change.
        registry_handle.set_oldest_consensus_registry_version(RegistryVersion::from(2));
        wait_for(&mut sim, || conn_checker.fully_connected()).expect("Nodes failed to reconnect");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    })
}

/// Test network where nodes get partitioned.

#[test]

fn test_bad_network() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");

        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(30))
            .tick_duration(Duration::from_millis(100))
            .build();

        let exit_notify = Arc::new(Notify::new());

        let node_1_port = 5555;
        let node_2_port = 6666;
        let node_3_port = 7777;
        let node_4_port = 8888;
        let node_5_port = 9999;

        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2, NODE_3, NODE_4, NODE_5]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            node_1_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            node_2_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            node_3_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_4,
            node_4_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_5,
            node_5_port,
            registry_handle.clone(),
            topology_watcher,
            conn_checker.clone(),
            None,
            None,
        );

        // Add all nodes
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_1,
                node_1_port,
                RegistryVersion::from(2),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_2,
                node_2_port,
                RegistryVersion::from(3),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_3,
                node_3_port,
                RegistryVersion::from(4),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_4,
                node_4_port,
                RegistryVersion::from(5),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_5,
                node_5_port,
                RegistryVersion::from(6),
            )))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || conn_checker.fully_connected()).unwrap();

        // Cause some turmoil
        sim.partition(NODE_1.to_string(), NODE_2.to_string());
        sim.partition(NODE_1.to_string(), NODE_3.to_string());
        sim.partition(NODE_4.to_string(), NODE_3.to_string());
        sim.partition(NODE_3.to_string(), NODE_5.to_string());
        conn_checker.reset(&NODE_1);
        conn_checker.reset(&NODE_2);
        conn_checker.reset(&NODE_3);
        conn_checker.reset(&NODE_4);
        conn_checker.reset(&NODE_5);
        info!(log, "Partitioned nodes");

        wait_for_timeout(
            &mut sim,
            || conn_checker.fully_connected(),
            Duration::from_secs(7),
        )
        .expect("Nodes are connected but they should be partitioned.");

        wait_for(&mut sim, || {
            conn_checker.disconnected_from(&NODE_1, &NODE_2)
                && conn_checker.disconnected_from(&NODE_1, &NODE_3)
                && conn_checker.disconnected_from(&NODE_4, &NODE_3)
                && conn_checker.disconnected_from(&NODE_3, &NODE_5)
        })
        .expect("Node should be disconnected due to partitioning.");

        info!(log, "Releasing nodes");
        sim.release(NODE_1.to_string(), NODE_2.to_string());
        sim.release(NODE_1.to_string(), NODE_3.to_string());
        sim.release(NODE_4.to_string(), NODE_3.to_string());
        sim.release(NODE_3.to_string(), NODE_5.to_string());

        wait_for(&mut sim, || conn_checker.fully_connected())
            .expect("Nodes should be fully connected again.");

        exit_notify.notify_waiters();

        sim.run().unwrap();
    })
}

/// Test network where nodes get partitioned and removed.
#[test]
fn test_bad_network_and_membership_change() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");

        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(30))
            .tick_duration(Duration::from_millis(100))
            .build();

        let exit_notify = Arc::new(Notify::new());

        let node_1_port = 5555;
        let node_2_port = 6666;
        let node_3_port = 7777;
        let node_4_port = 8888;
        let node_5_port = 9999;

        let (peer_manager_cmd_sender, topology_watcher, mut registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2, NODE_3, NODE_4, NODE_5]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            node_1_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            node_2_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            node_3_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_4,
            node_4_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
            None,
            None,
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_5,
            node_5_port,
            registry_handle.clone(),
            topology_watcher,
            conn_checker.clone(),
            None,
            None,
        );

        // Add all 5 nodes.
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_1,
                node_1_port,
                RegistryVersion::from(2),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_2,
                node_2_port,
                RegistryVersion::from(3),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_3,
                node_3_port,
                RegistryVersion::from(4),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_4,
                node_4_port,
                RegistryVersion::from(5),
            )))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((
                NODE_5,
                node_5_port,
                RegistryVersion::from(6),
            )))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || conn_checker.fully_connected()).unwrap();

        // Cause some turmoil for node 1.
        sim.partition(NODE_1.to_string(), NODE_2.to_string());
        sim.partition(NODE_1.to_string(), NODE_3.to_string());
        conn_checker.reset(&NODE_1);
        conn_checker.reset(&NODE_2);
        conn_checker.reset(&NODE_3);
        info!(log, "Partitioned nodes");

        wait_for_timeout(
            &mut sim,
            || conn_checker.fully_connected(),
            Duration::from_secs(7),
        )
        .expect("Nodes are connected but they should be partitioned.");

        wait_for(&mut sim, || {
            conn_checker.disconnected_from(&NODE_1, &NODE_2)
                && conn_checker.disconnected_from(&NODE_1, &NODE_3)
        })
        .expect("Node1 <-> Node2 and Node1 <-> Node3 should be disconnected.");

        info!(log, "Removing node 1");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Remove((
                NODE_1,
                RegistryVersion::from(7),
            )))
            .unwrap();

        registry_handle.set_oldest_consensus_registry_version(RegistryVersion::from(7));

        wait_for(&mut sim, || conn_checker.unreachable(&NODE_1))
            .expect("Node1 is reachable after removing it from the topology.");

        info!(log, "Releasing nodes {}", NODE_1);
        sim.release(NODE_1.to_string(), NODE_2.to_string());
        sim.release(NODE_1.to_string(), NODE_3.to_string());

        wait_for(&mut sim, || {
            conn_checker.fully_connected_except(vec![NODE_1])
        })
        .expect("Nodes are fully connected except node1 which was removed.");

        exit_notify.notify_waiters();

        sim.run().unwrap();
    })
}
