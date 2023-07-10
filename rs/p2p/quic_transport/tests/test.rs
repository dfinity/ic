use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use crate::common::{mock_registry_client, CustomUdp, DummyTlsConfig};

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
use tokio::sync::{watch::channel, Barrier};
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
