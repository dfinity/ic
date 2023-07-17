use std::{sync::Arc, time::Duration};

use crate::common::{
    add_peer_manager_to_sim, add_transport_to_sim, wait_for, ConnectivityChecker, PeerManagerAction,
};

use ic_logger::info;
use ic_test_utilities_logger::with_test_replica_logger;
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
        );

        add_transport_to_sim(
            &mut sim,
            log,
            NODE_2,
            node_2_port,
            registry_handle.clone(),
            topology_watcher,
            conn_checker.clone(),
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, node_1_port, 2.into())))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, node_2_port, 3.into())))
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
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            node_2_port,
            registry_handle.clone(),
            topology_watcher,
            conn_checker.clone(),
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, node_1_port, 2.into())))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, node_2_port, 3.into())))
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
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            node_2_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            node_3_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_4,
            node_4_port,
            registry_handle.clone(),
            topology_watcher.clone(),
            conn_checker.clone(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_5,
            node_5_port,
            registry_handle.clone(),
            topology_watcher,
            conn_checker.clone(),
        );

        // Add two starting nodes 1 and 2.
        info!(log, "Adding node 1 and 2");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, node_1_port, 2.into())))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, node_2_port, 3.into())))
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
            .send(PeerManagerAction::Add((NODE_3, node_3_port, 4.into())))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || conn_checker.connected_pair(&NODE_1, &NODE_3)).unwrap();
        wait_for(&mut sim, || conn_checker.connected_pair(&NODE_2, &NODE_3)).unwrap();

        // Remove node 3 from registry. This should not actually remove the node since oldest registry version is lower.
        info!(log, "Removing node 3");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Remove((NODE_3, 5.into())))
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
        registry_handle.set_oldest_consensus_registry_version(5.into());
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || conn_checker.unreachable(&NODE_3)).unwrap();

        // Add node 4 and 5
        info!(log, "Adding node 4 and 5");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_4, node_4_port, 7.into())))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_5, node_5_port, 8.into())))
            .unwrap();
        registry_handle.registry_client.reload();
        wait_for(&mut sim, || {
            conn_checker.fully_connected_except(vec![NODE_3])
        })
        .unwrap();

        // Remove node 1 from registry. This should not actually remove the node since oldest registry version is lower.
        info!(log, "Removing node 1");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Remove((NODE_1, 9.into())))
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
        registry_handle.set_oldest_consensus_registry_version(9.into());
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_1)).unwrap();

        // Rejoin node 3
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_3)).unwrap();
        info!(log, "Rejoining node 3");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_3, node_3_port, 10.into())))
            .unwrap();
        wait_for(&mut sim, || {
            conn_checker.fully_connected_except(vec![NODE_1])
        })
        .unwrap();

        // Remove rest of nodes
        info!(log, "Removing all nodes");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Remove((NODE_2, 11.into())))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Remove((NODE_4, 12.into())))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Remove((NODE_5, 13.into())))
            .unwrap();
        registry_handle.set_oldest_consensus_registry_version(13.into());
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_1)).unwrap();
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_2)).unwrap();
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_3)).unwrap();
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_4)).unwrap();
        wait_for(&mut sim, || conn_checker.unreachable(&NODE_5)).unwrap();

        exit_notify.notify_waiters();
        sim.run().unwrap();
    })
}
