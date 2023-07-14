use std::{sync::Arc, time::Duration};

use crate::common::{
    add_peer_manager_to_sim, add_transport_to_sim, wait_for, ConnectivityChecker, PeerManagerAction,
};

use ic_logger::info;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types_test_utils::ids::{NODE_1, NODE_2};
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
