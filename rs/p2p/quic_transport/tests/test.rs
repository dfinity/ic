use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use crate::common::{
    mock_registry_client, wait_for, ConnectivityChecker, CustomUdp, DummyTlsConfig,
};

use axum::{routing::get, Router};
use bytes::Bytes;
use either::Either;
use http::Request;
use ic_icos_sev::Sev;
use ic_logger::info;
use ic_metrics::MetricsRegistry;
use ic_peer_manager::SubnetTopology;
use ic_quic_transport::{QuicTransport, Transport};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types_test_utils::ids::{NODE_1, NODE_2};
use tokio::sync::{watch::channel, Barrier, Notify};
use turmoil::{self, net, Builder};

mod common;

#[test]
fn ping_pong() {
    with_test_replica_logger(|log| {
        info!(log, "Starting test");

        let mut sim = Builder::new()
            .simulation_duration(Duration::from_secs(10))
            .build();

        let barrier = Arc::new(Barrier::new(3));

        let node_1_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, 8888).into();
        let node_2_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, 9999).into();

        let (topology_sender, topology_watcher) = channel(SubnetTopology::default());
        let registry_client = mock_registry_client();

        let topology_watcher_clone = topology_watcher.clone();
        let logger_clone = log.clone();
        let registry_client_clone = registry_client.clone();
        let barrier_clone = barrier.clone();

        sim.host(NODE_1.to_string(), move || {
            let topology_watcher = topology_watcher_clone.clone();
            let logger = logger_clone.clone();
            let registry_client = registry_client_clone.clone();
            let barrier = barrier_clone.clone();

            async move {
                let udp_listener = net::UdpSocket::bind(node_1_addr).await.unwrap();
                let this_ip = turmoil::lookup(NODE_1.to_string());
                let custom_udp = CustomUdp::new(this_ip, udp_listener);

                let router = Router::new().route("/Ping", get(|| async { "Pong" }));

                let tls_config = Arc::new(DummyTlsConfig::new(NODE_1));

                let sev_handshake = Sev::new(NODE_1, registry_client.clone());

                let _transport = QuicTransport::build(
                    tokio::runtime::Handle::current(),
                    logger,
                    tls_config,
                    registry_client,
                    Arc::new(sev_handshake),
                    NODE_1,
                    topology_watcher,
                    Either::Right(custom_udp),
                    &MetricsRegistry::default(),
                    router,
                );

                barrier.wait().await;

                Ok(())
            }
        });

        let barrier_clone = barrier.clone();
        sim.host(NODE_2.to_string(), move || {
            let topology_watcher = topology_watcher.clone();
            let logger = log.clone();
            let registry_client = registry_client.clone();
            let barrier = barrier_clone.clone();

            async move {
                let udp_listener = net::UdpSocket::bind(node_2_addr).await.unwrap();
                let custom_udp = CustomUdp::new(turmoil::lookup(NODE_2.to_string()), udp_listener);

                let router = Router::new();

                let tls_config = Arc::new(DummyTlsConfig::new(NODE_2));

                let sev_handshake = Sev::new(NODE_2, registry_client.clone());

                let transport = QuicTransport::build(
                    tokio::runtime::Handle::current(),
                    logger.clone(),
                    tls_config,
                    registry_client,
                    Arc::new(sev_handshake),
                    NODE_2,
                    topology_watcher,
                    Either::Right(custom_udp),
                    &MetricsRegistry::default(),
                    router,
                );

                loop {
                    let request = Request::builder().uri("/Ping").body(Bytes::new()).unwrap();
                    let response = transport.rpc(&NODE_1, request).await;

                    match response {
                        Err(e) => {
                            info!(logger, "Node 2 received an error: {:?}", e);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                        Ok(response) => {
                            assert_eq!(
                                response.body(),
                                "Pong",
                                "Unexpected response: {:?}",
                                response
                            );
                            break;
                        }
                    }
                }

                barrier.wait().await;
                Ok(())
            }
        });

        sim.client("sender", async move {
            let subnet_nodes = [
                (NODE_1, (turmoil::lookup(NODE_1.to_string()), 8888).into()),
                (NODE_2, (turmoil::lookup(NODE_2.to_string()), 9999).into()),
            ];

            let subnet_topology = SubnetTopology::new(subnet_nodes);

            topology_sender
                .send(subnet_topology)
                .expect("Failed to send topology");
            barrier.wait().await;
            Ok(())
        });

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

        let node_1_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, 8888).into();
        let node_2_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, 9999).into();

        let (topology_sender, topology_watcher) = channel(SubnetTopology::default());
        let registry_client = mock_registry_client();

        let topology_watcher_clone = topology_watcher.clone();
        let logger_c = log.clone();
        let registry_client_clone = registry_client.clone();

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2]);

        let conn_checker1 = conn_checker.clone();
        sim.host(NODE_1.to_string(), move || {
            let topology_watcher = topology_watcher_clone.clone();
            let logger = logger_c.clone();
            let registry_client = registry_client_clone.clone();
            let conn_checker1 = conn_checker1.clone();

            async move {
                let udp_listener = net::UdpSocket::bind(node_1_addr).await.unwrap();
                let this_ip = turmoil::lookup(NODE_1.to_string());
                let custom_udp = CustomUdp::new(this_ip, udp_listener);

                let router = Router::new().merge(ConnectivityChecker::router());

                let tls_config = Arc::new(DummyTlsConfig::new(NODE_1));

                let sev_handshake = Sev::new(NODE_1, registry_client.clone());

                let transport = QuicTransport::build(
                    tokio::runtime::Handle::current(),
                    logger,
                    tls_config,
                    registry_client,
                    Arc::new(sev_handshake),
                    NODE_1,
                    topology_watcher,
                    Either::Right(custom_udp),
                    &MetricsRegistry::default(),
                    router,
                );

                loop {
                    conn_checker1.check(NODE_1, &transport).await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        });

        let conn_checker2 = conn_checker.clone();
        let logger_c = log.clone();
        sim.host(NODE_2.to_string(), move || {
            let topology_watcher = topology_watcher.clone();
            let logger = logger_c.clone();
            let registry_client = registry_client.clone();
            let conn_checker2 = conn_checker2.clone();

            async move {
                let udp_listener = net::UdpSocket::bind(node_2_addr).await.unwrap();
                let custom_udp = CustomUdp::new(turmoil::lookup(NODE_2.to_string()), udp_listener);

                let router = Router::new().merge(ConnectivityChecker::router());

                let tls_config = Arc::new(DummyTlsConfig::new(NODE_2));

                let sev_handshake = Sev::new(NODE_2, registry_client.clone());

                let transport = QuicTransport::build(
                    tokio::runtime::Handle::current(),
                    logger.clone(),
                    tls_config,
                    registry_client,
                    Arc::new(sev_handshake),
                    NODE_2,
                    topology_watcher,
                    Either::Right(custom_udp),
                    &MetricsRegistry::default(),
                    router,
                );

                loop {
                    conn_checker2.check(NODE_2, &transport).await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        });

        let notify = Arc::new(Notify::new());
        let notify_c = notify.clone();
        sim.client("sender", async move {
            let subnet_nodes = [
                (NODE_1, (turmoil::lookup(NODE_1.to_string()), 8888).into()),
                (NODE_2, (turmoil::lookup(NODE_2.to_string()), 9999).into()),
            ];

            let subnet_topology = SubnetTopology::new(subnet_nodes);

            topology_sender
                .send(subnet_topology)
                .expect("Failed to send topology");
            notify_c.notified().await;
            Ok(())
        });

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
        notify.notify_waiters();
        sim.run().unwrap();
    })
}
