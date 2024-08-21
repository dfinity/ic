use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::common::PeerRestrictedTlsConfig;
use axum::{http::Request, Router};
use bytes::Bytes;
use futures::FutureExt;
use ic_base_types::{NodeId, RegistryVersion};
use ic_logger::info;
use ic_metrics::MetricsRegistry;
use ic_p2p_test_utils::{
    create_peer_manager_and_registry_handle, temp_crypto_component_with_tls_keys,
    turmoil::{
        add_peer_manager_to_sim, add_transport_to_sim, wait_for, wait_for_timeout,
        PeerManagerAction,
    },
    ConnectivityChecker,
};
use ic_quic_transport::{create_udp_socket, QuicTransport, Transport};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4, NODE_5};
use tokio::{
    sync::{mpsc, Notify},
    time::timeout,
};
use turmoil::Builder;

mod common;
#[test]
fn test_ping_pong() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");

        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(10))
            .build();

        let exit_notify = Arc::new(Notify::new());

        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log,
            NODE_2,
            registry_handle.clone(),
            topology_watcher,
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || conn_checker.fully_connected())
            .expect("The network did not reach a fully connected state after startup");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    })
}

#[test]
fn test_graceful_shutdown() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (_jh, topology_watcher, mut registry_handler) =
            create_peer_manager_and_registry_handle(rt.handle(), log.clone());

        let node_crypto_1 = temp_crypto_component_with_tls_keys(&registry_handler, NODE_1);
        let node_crypto_2 = temp_crypto_component_with_tls_keys(&registry_handler, NODE_2);
        registry_handler.registry_client.update_to_latest_version();

        let socket_1: SocketAddr = "127.0.10.1:4100".parse().unwrap();
        let socket_2: SocketAddr = "127.0.11.1:4100".parse().unwrap();

        let transport_1 = Arc::new(QuicTransport::start(
            &log,
            &MetricsRegistry::default(),
            rt.handle(),
            node_crypto_1,
            registry_handler.registry_client.clone(),
            NODE_1,
            topology_watcher.clone(),
            create_udp_socket(rt.handle(), socket_1),
            ConnectivityChecker::router(),
        ));

        let mut transport_2 = Arc::new(QuicTransport::start(
            &log,
            &MetricsRegistry::default(),
            rt.handle(),
            node_crypto_2,
            registry_handler.registry_client.clone(),
            NODE_2,
            topology_watcher,
            create_udp_socket(rt.handle(), socket_2),
            ConnectivityChecker::router(),
        ));

        registry_handler.add_node(
            RegistryVersion::from(2),
            NODE_1,
            Some(&socket_1.ip().to_string()),
        );
        registry_handler.add_node(
            RegistryVersion::from(3),
            NODE_2,
            Some(&socket_2.ip().to_string()),
        );
        registry_handler.registry_client.reload();
        registry_handler.registry_client.update_to_latest_version();

        let succesful_ping_pong_fut = async {
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;

                let request = Request::builder().uri("/Ping").body(Bytes::new()).unwrap();
                let node_1_reachable_from_node_2 = transport_2.push(&NODE_1, request).await.is_ok();
                let request = Request::builder().uri("/Ping").body(Bytes::new()).unwrap();
                let node_2_reachable_from_node_1 = transport_1.push(&NODE_2, request).await.is_ok();
                if node_2_reachable_from_node_1 && node_1_reachable_from_node_2 {
                    break;
                }
            }
        };
        rt.block_on(async move { timeout(Duration::from_secs(10), succesful_ping_pong_fut).await })
            .unwrap();

        rt.block_on(async move {
            Arc::get_mut(&mut transport_2).unwrap().shutdown().await;
            let request = Request::builder().uri("/Ping").body(Bytes::new()).unwrap();
            assert!(transport_2.push(&NODE_1, request).await.is_err());
        });
    })
}

#[test]
fn test_real_socket() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (_jh, topology_watcher, mut registry_handler) =
            create_peer_manager_and_registry_handle(rt.handle(), log.clone());

        let node_crypto_1 = temp_crypto_component_with_tls_keys(&registry_handler, NODE_1);
        let node_crypto_2 = temp_crypto_component_with_tls_keys(&registry_handler, NODE_2);
        registry_handler.registry_client.update_to_latest_version();

        let socket_1: SocketAddr = "127.0.1.1:4100".parse().unwrap();
        let socket_2: SocketAddr = "127.0.2.1:4100".parse().unwrap();

        let transport_1 = Arc::new(QuicTransport::start(
            &log,
            &MetricsRegistry::default(),
            rt.handle(),
            node_crypto_1,
            registry_handler.registry_client.clone(),
            NODE_1,
            topology_watcher.clone(),
            create_udp_socket(rt.handle(), socket_1),
            ConnectivityChecker::router(),
        ));

        let transport_2 = Arc::new(QuicTransport::start(
            &log,
            &MetricsRegistry::default(),
            rt.handle(),
            node_crypto_2,
            registry_handler.registry_client.clone(),
            NODE_2,
            topology_watcher,
            create_udp_socket(rt.handle(), socket_2),
            ConnectivityChecker::router(),
        ));

        registry_handler.add_node(
            RegistryVersion::from(2),
            NODE_1,
            Some(&socket_1.ip().to_string()),
        );
        registry_handler.add_node(
            RegistryVersion::from(3),
            NODE_2,
            Some(&socket_2.ip().to_string()),
        );
        registry_handler.registry_client.reload();
        registry_handler.registry_client.update_to_latest_version();

        rt.block_on(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;

                let request = Request::builder().uri("/Ping").body(Bytes::new()).unwrap();
                let node_1_reachable_from_node_2 = transport_2.push(&NODE_1, request).await.is_ok();
                let request = Request::builder().uri("/Ping").body(Bytes::new()).unwrap();
                let node_2_reachable_from_node_1 = transport_1.push(&NODE_2, request).await.is_ok();
                if node_2_reachable_from_node_1 && node_1_reachable_from_node_2 {
                    break;
                }
            }
        });
    })
}

#[test]
fn test_real_socket_large_msg() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (_jh, topology_watcher, mut registry_handler) =
            create_peer_manager_and_registry_handle(rt.handle(), log.clone());

        let node_crypto_1 = temp_crypto_component_with_tls_keys(&registry_handler, NODE_1);
        let node_crypto_2 = temp_crypto_component_with_tls_keys(&registry_handler, NODE_2);
        registry_handler.registry_client.update_to_latest_version();

        let socket_1: SocketAddr = "127.0.3.1:4100".parse().unwrap();
        let socket_2: SocketAddr = "127.0.4.1:4100".parse().unwrap();

        let transport_1 = Arc::new(QuicTransport::start(
            &log,
            &MetricsRegistry::default(),
            rt.handle(),
            node_crypto_1,
            registry_handler.registry_client.clone(),
            NODE_1,
            topology_watcher.clone(),
            create_udp_socket(rt.handle(), socket_1),
            ConnectivityChecker::router(),
        ));

        let transport_2 = Arc::new(QuicTransport::start(
            &log,
            &MetricsRegistry::default(),
            rt.handle(),
            node_crypto_2,
            registry_handler.registry_client.clone(),
            NODE_2,
            topology_watcher,
            create_udp_socket(rt.handle(), socket_2),
            ConnectivityChecker::router(),
        ));

        registry_handler.add_node(
            RegistryVersion::from(2),
            NODE_1,
            Some(&socket_1.ip().to_string()),
        );
        registry_handler.add_node(
            RegistryVersion::from(3),
            NODE_2,
            Some(&socket_2.ip().to_string()),
        );
        registry_handler.registry_client.reload();
        registry_handler.registry_client.update_to_latest_version();

        rt.block_on(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;

                let request = Request::builder()
                    .uri("/Ping")
                    .body(Bytes::from(vec![0; 100_000_000]))
                    .unwrap();
                let node_1_reachable_from_node_2 = transport_2.push(&NODE_1, request).await.is_ok();
                let request = Request::builder().uri("/Ping").body(Bytes::new()).unwrap();
                let node_2_reachable_from_node_1 = transport_1.push(&NODE_2, request).await.is_ok();
                if node_2_reachable_from_node_1 && node_1_reachable_from_node_2 {
                    break;
                }
            }
        });
    })
}

/// Test sending large message works fine.
#[test]
fn test_sending_large_message() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");

        let mut sim = Builder::new()
            .max_message_latency(Duration::from_millis(0))
            .udp_capacity(1024 * 1024)
            .simulation_duration(Duration::from_secs(30))
            .build();

        let exit_notify = Arc::new(Notify::new());

        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let (received_large_msg1_tx, mut received_large_msg1_rx) = mpsc::channel(1);
        let router_1: Router<()> = Router::new().route(
            "/",
            axum::routing::any(|| async move {
                received_large_msg1_tx.send(()).await.unwrap();
            }),
        );

        let (received_large_msg2_tx, mut received_large_msg2_rx) = mpsc::channel(1);
        let router_2: Router<()> = Router::new().route(
            "/",
            axum::routing::any(|| async move {
                received_large_msg2_tx.send(()).await.unwrap();
            }),
        );

        // Send large message that should be reject and verify connectivity.
        let send_large_msg_to_node_2 = |_node_id: NodeId, transport: Arc<dyn Transport>| {
            async move {
                loop {
                    let _ = transport
                        .push(&NODE_2, Request::new(Bytes::from(vec![0; 50_000_000])))
                        .await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            .boxed()
        };
        let send_large_msg_to_node_1 = |_node_id: NodeId, transport: Arc<dyn Transport>| {
            async move {
                loop {
                    let _ = transport
                        .push(&NODE_1, Request::new(Bytes::from(vec![0; 50_000_000])))
                        .await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            .boxed()
        };

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(router_1),
            None,
            None,
            None,
            send_large_msg_to_node_2,
        );

        add_transport_to_sim(
            &mut sim,
            log,
            NODE_2,
            registry_handle.clone(),
            topology_watcher,
            Some(router_2),
            None,
            None,
            None,
            send_large_msg_to_node_1,
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        wait_for(&mut sim, || received_large_msg1_rx.try_recv().is_ok())
            .expect("Node 1 is still reachable from other nodes after crashing it.");
        wait_for(&mut sim, || received_large_msg2_rx.try_recv().is_ok())
            .expect("Node 1 is still reachable from other nodes after crashing it.");

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

        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher,
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
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

        wait_for(&mut sim, || {
            conn_checker.fully_connected()
                && conn_checker.connected_with_min_id(&NODE_2, &NODE_1, 1)
                && conn_checker.connected_with_min_id(&NODE_1, &NODE_2, 0)
        })
        .expect("Node 2 reconnected to Node 1 and should now use connection id 2 and all nodes should be connected");

        info!(log, "Crashing node 2");
        sim.crash(NODE_2.to_string());
        conn_checker.reset(&NODE_2);

        wait_for(&mut sim, || conn_checker.unreachable(&NODE_2))
            .expect("Node 2 is still reachable after crashing it.");

        info!(log, "Restarting node 2");
        sim.bounce(NODE_2.to_string());

        wait_for(&mut sim, || {
            conn_checker.fully_connected()
                && conn_checker.connected_with_min_id(&NODE_1, &NODE_2, 1)
                && conn_checker.connected_with_min_id(&NODE_2, &NODE_1, 0)
        })
        .expect("The network did not reach a fully connected state after restarting node 2 and all nodes should be connected.");

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

        let (peer_manager_cmd_sender, topology_watcher, mut registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2, NODE_3, NODE_4, NODE_5]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_4,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_5,
            registry_handle.clone(),
            topology_watcher,
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        // Add two starting nodes 1 and 2.
        info!(log, "Adding node 1 and 2");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
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
            .send(PeerManagerAction::Add((NODE_3, RegistryVersion::from(4))))
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
            .send(PeerManagerAction::Add((NODE_4, RegistryVersion::from(7))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_5, RegistryVersion::from(8))))
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
            .send(PeerManagerAction::Add((NODE_3, RegistryVersion::from(10))))
            .unwrap();
        wait_for(&mut sim, || {
            conn_checker.fully_connected_except(vec![NODE_1])
                && conn_checker.connected_with_min_id(&NODE_2, &NODE_3, 1)
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
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        // Server.
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher,
            Some(ConnectivityChecker::router()),
            Some(tls_2.clone()),
            None,
            None,
            conn_checker.check_fut(),
        );

        // Add two starting nodes 1 and 2.
        info!(log, "Adding node 1 and 2");
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
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

        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2, NODE_3, NODE_4, NODE_5]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_4,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_5,
            registry_handle.clone(),
            topology_watcher,
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        // Add all nodes
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_3, RegistryVersion::from(4))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_4, RegistryVersion::from(5))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_5, RegistryVersion::from(6))))
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

        wait_for(&mut sim, || {
            conn_checker.fully_connected()
                && conn_checker.connected_with_min_id(&NODE_1, &NODE_2, 1)
                && conn_checker.connected_with_min_id(&NODE_2, &NODE_1, 1)
                && conn_checker.connected_with_min_id(&NODE_1, &NODE_3, 1)
                && conn_checker.connected_with_min_id(&NODE_3, &NODE_1, 1)
                && conn_checker.connected_with_min_id(&NODE_4, &NODE_3, 1)
                && conn_checker.connected_with_min_id(&NODE_3, &NODE_4, 1)
                && conn_checker.connected_with_min_id(&NODE_3, &NODE_5, 1)
                && conn_checker.connected_with_min_id(&NODE_5, &NODE_3, 1)
        })
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

        let (peer_manager_cmd_sender, topology_watcher, mut registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2, NODE_3, NODE_4, NODE_5]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_4,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_5,
            registry_handle.clone(),
            topology_watcher,
            Some(ConnectivityChecker::router()),
            None,
            None,
            None,
            conn_checker.check_fut(),
        );

        // Add all 5 nodes.
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_3, RegistryVersion::from(4))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_4, RegistryVersion::from(5))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_5, RegistryVersion::from(6))))
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
