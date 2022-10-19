mod common;

use common::{
    create_mock_event_handler, get_free_localhost_port,
    temp_crypto_component_with_tls_keys_in_registry, RegistryAndDataProvider, REG_V1,
};
use ic_base_types::{NodeId, RegistryVersion};
use ic_config::transport::TransportConfig;
use ic_crypto_tls_interfaces::{
    AllowedClients, TlsClientHandshakeError, TlsHandshake, TlsServerHandshakeError,
};
use ic_crypto_tls_interfaces_mocks::MockTlsHandshake;
use ic_interfaces_transport::{Transport, TransportEvent};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_transport::transport::create_transport;
use ic_types_test_utils::ids::{NODE_1, NODE_2};
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tokio::{net::TcpStream, sync::mpsc::channel};
use tower_test::mock::Handle;

const TRANSPORT_CHANNEL_ID: u32 = 1234;

fn setup_test_peer<F>(
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    node_id: NodeId,
    port: u16,
    registry_version: RegistryVersion,
    registry_and_data: &mut RegistryAndDataProvider,
    mut crypto_factory: F,
    use_h2: bool,
) -> (Arc<dyn Transport>, Handle<TransportEvent, ()>, SocketAddr)
where
    F: FnMut(&mut RegistryAndDataProvider, NodeId) -> Arc<dyn TlsHandshake + Send + Sync>,
{
    let crypto = crypto_factory(registry_and_data, node_id);
    let config = TransportConfig {
        node_ip: "0.0.0.0".to_string(),
        legacy_flow_tag: TRANSPORT_CHANNEL_ID,
        listening_port: port,
        send_queue_size: 10,
    };
    let peer = create_transport(
        node_id,
        config,
        registry_version,
        MetricsRegistry::new(),
        crypto,
        rt_handle,
        log,
        use_h2,
    );
    let addr = SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap();
    let (event_handler, mock_handle) = create_mock_event_handler();
    peer.set_event_handler(event_handler);
    (peer, mock_handle, addr)
}

#[test]
fn test_single_transient_failure_of_tls_client_handshake() {
    test_single_transient_failure_of_tls_client_handshake_impl(false);
    test_single_transient_failure_of_tls_client_handshake_impl(true);
}

fn test_single_transient_failure_of_tls_client_handshake_impl(use_h2: bool) {
    with_test_replica_logger(|log| {
        let mut registry_and_data = RegistryAndDataProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let rt_handle = rt.handle().clone();

        let crypto_factory_with_single_tls_handshake_client_failures =
            |registry_and_data: &mut RegistryAndDataProvider, node_id: NodeId| {
                let mut mock_client_tls_handshake = MockTlsHandshake::new();
                let rt_handle = rt_handle.clone();

                let crypto = Arc::new(temp_crypto_component_with_tls_keys_in_registry(
                    registry_and_data,
                    node_id,
                ));

                mock_client_tls_handshake
                    .expect_perform_tls_client_handshake()
                    .times(1)
                    .returning({
                        move |_tcp_stream: TcpStream,
                              _server: NodeId,
                              _registry_version: RegistryVersion| {
                            Err(TlsClientHandshakeError::HandshakeError {
                                internal_error: "transient".to_string(),
                            })
                        }
                    });

                mock_client_tls_handshake
                    .expect_perform_tls_client_handshake()
                    .times(1)
                    .returning(
                        move |tcp_stream: TcpStream,
                              server: NodeId,
                              registry_version: RegistryVersion| {
                            let rt_handle = rt_handle.clone();
                            let crypto = crypto.clone();

                            tokio::task::block_in_place(move || {
                                let rt_handle = rt_handle.clone();

                                rt_handle.block_on(async move {
                                    crypto
                                        .perform_tls_client_handshake(
                                            tcp_stream,
                                            server,
                                            registry_version,
                                        )
                                        .await
                                })
                            })
                        },
                    );

                Arc::new(mock_client_tls_handshake) as Arc<dyn TlsHandshake + Send + Sync>
            };

        let crypto_factory = |registry_and_data: &mut RegistryAndDataProvider, node_id: NodeId| {
            Arc::new(temp_crypto_component_with_tls_keys_in_registry(
                registry_and_data,
                node_id,
            )) as Arc<dyn TlsHandshake + Send + Sync>
        };

        let peer1_port = get_free_localhost_port().expect("Failed to get free localhost port");
        let (peer_1, mut mock_handle_peer_1, peer_1_addr) = setup_test_peer(
            log.clone(),
            rt.handle().clone(),
            NODE_1,
            peer1_port,
            REG_V1,
            &mut registry_and_data,
            crypto_factory_with_single_tls_handshake_client_failures,
            use_h2,
        );
        let peer2_port = get_free_localhost_port().expect("Failed to get free localhost port");
        let (peer_2, mut mock_handle_peer_2, peer_2_addr) = setup_test_peer(
            log,
            rt.handle().clone(),
            NODE_2,
            peer2_port,
            REG_V1,
            &mut registry_and_data,
            crypto_factory,
            use_h2,
        );
        registry_and_data.registry.update_to_latest_version();

        let (connected_1, mut done_1) = channel(1);
        let (connected_2, mut done_2) = channel(1);
        rt.spawn(async move {
            let (event, rsp) = mock_handle_peer_1.next_request().await.unwrap();
            if let TransportEvent::PeerUp(_) = event {
                connected_1.try_send(true).unwrap()
            }
            rsp.send_response(());
        });
        rt.spawn(async move {
            let (event, rsp) = mock_handle_peer_2.next_request().await.unwrap();
            if let TransportEvent::PeerUp(_) = event {
                connected_2.try_send(true).unwrap()
            }
            rsp.send_response(());
        });
        assert!(peer_1
            .start_connection(&NODE_2, peer_2_addr, REG_V1)
            .is_ok());

        assert!(peer_2
            .start_connection(&NODE_1, peer_1_addr, REG_V1)
            .is_ok());
        assert_eq!(done_1.blocking_recv(), Some(true));
        assert_eq!(done_2.blocking_recv(), Some(true));
    });
}

#[test]
fn test_single_transient_failure_of_tls_server_handshake() {
    test_single_transient_failure_of_tls_server_handshake_impl(false);
    test_single_transient_failure_of_tls_server_handshake_impl(true);
}

fn test_single_transient_failure_of_tls_server_handshake_impl(use_h2: bool) {
    with_test_replica_logger(|log| {
        let mut registry_and_data = RegistryAndDataProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let rt_handle = rt.handle().clone();

        let crypto_factory_with_single_tls_handshake_server_failures =
            |registry_and_data: &mut RegistryAndDataProvider, node_id: NodeId| {
                let mut mock_server_tls_handshake = MockTlsHandshake::new();
                let rt_handle = rt_handle.clone();

                let crypto = Arc::new(temp_crypto_component_with_tls_keys_in_registry(
                    registry_and_data,
                    node_id,
                ));

                mock_server_tls_handshake
                    .expect_perform_tls_server_handshake()
                    .times(1)
                    .returning({
                        move |_tcp_stream: TcpStream,
                              _allowed_clients: AllowedClients,
                              _registry_version: RegistryVersion| {
                            Err(TlsServerHandshakeError::HandshakeError {
                                internal_error: "transient".to_string(),
                            })
                        }
                    });

                mock_server_tls_handshake
                    .expect_perform_tls_server_handshake()
                    .times(1)
                    .returning(
                        move |tcp_stream: TcpStream,
                              allowed_clients: AllowedClients,
                              registry_version: RegistryVersion| {
                            let rt_handle = rt_handle.clone();
                            let crypto = crypto.clone();

                            tokio::task::block_in_place(move || {
                                let rt_handle = rt_handle.clone();

                                rt_handle.block_on(async move {
                                    crypto
                                        .perform_tls_server_handshake(
                                            tcp_stream,
                                            allowed_clients,
                                            registry_version,
                                        )
                                        .await
                                })
                            })
                        },
                    );

                Arc::new(mock_server_tls_handshake) as Arc<dyn TlsHandshake + Send + Sync>
            };

        let crypto_factory = |registry_and_data: &mut RegistryAndDataProvider, node_id: NodeId| {
            Arc::new(temp_crypto_component_with_tls_keys_in_registry(
                registry_and_data,
                node_id,
            )) as Arc<dyn TlsHandshake + Send + Sync>
        };

        let peer1_port = get_free_localhost_port().expect("Failed to get free localhost port");
        let (peer_1, mut mock_handle_peer_1, peer_1_addr) = setup_test_peer(
            log.clone(),
            rt.handle().clone(),
            NODE_1,
            peer1_port,
            REG_V1,
            &mut registry_and_data,
            crypto_factory,
            use_h2,
        );
        let peer2_port = get_free_localhost_port().expect("Failed to get free localhost port");
        let (peer_2, mut mock_handle_peer_2, peer_2_addr) = setup_test_peer(
            log,
            rt.handle().clone(),
            NODE_2,
            peer2_port,
            REG_V1,
            &mut registry_and_data,
            crypto_factory_with_single_tls_handshake_server_failures,
            use_h2,
        );
        registry_and_data.registry.update_to_latest_version();

        let (connected_1, mut done_1) = channel(1);
        let (connected_2, mut done_2) = channel(1);
        rt.spawn(async move {
            let (event, rsp) = mock_handle_peer_1.next_request().await.unwrap();
            if let TransportEvent::PeerUp(_) = event {
                connected_1.try_send(true).unwrap()
            }
            rsp.send_response(());
        });
        rt.spawn(async move {
            let (event, rsp) = mock_handle_peer_2.next_request().await.unwrap();
            if let TransportEvent::PeerUp(_) = event {
                connected_2.try_send(true).unwrap()
            }
            rsp.send_response(());
        });
        assert!(peer_1
            .start_connection(&NODE_2, peer_2_addr, REG_V1)
            .is_ok());

        assert!(peer_2
            .start_connection(&NODE_1, peer_1_addr, REG_V1)
            .is_ok());
        assert_eq!(done_1.blocking_recv(), Some(true));
        assert_eq!(done_2.blocking_recv(), Some(true));
    });
}
