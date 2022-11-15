mod common;

use common::{
    get_free_localhost_port, setup_peer_up_ack_event_handler, setup_test_peer,
    temp_crypto_component_with_tls_keys_in_registry, RegistryAndDataProvider, REG_V1,
};
use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_tls_interfaces::{
    AllowedClients, TlsClientHandshakeError, TlsHandshake, TlsServerHandshakeError,
};
use ic_crypto_tls_interfaces_mocks::MockTlsHandshake;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types_test_utils::ids::{NODE_1, NODE_2};
use std::sync::Arc;
use tokio::{net::TcpStream, sync::mpsc::channel};

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
        let (peer_1_sender, mut peer_1_receiver) = channel(1);
        let event_handler_1 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_1_sender);

        let (peer_1, peer_1_addr) = setup_test_peer(
            log.clone(),
            rt.handle().clone(),
            NODE_1,
            peer1_port,
            REG_V1,
            &mut registry_and_data,
            crypto_factory_with_single_tls_handshake_client_failures,
            event_handler_1,
            use_h2,
        );
        let peer2_port = get_free_localhost_port().expect("Failed to get free localhost port");
        let (peer_2_sender, mut peer_2_receiver) = channel(1);
        let event_handler_2 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_2_sender);

        let (peer_2, peer_2_addr) = setup_test_peer(
            log,
            rt.handle().clone(),
            NODE_2,
            peer2_port,
            REG_V1,
            &mut registry_and_data,
            crypto_factory,
            event_handler_2,
            use_h2,
        );
        registry_and_data.registry.update_to_latest_version();

        assert!(peer_1
            .start_connection(&NODE_2, peer_2_addr, REG_V1)
            .is_ok());

        assert!(peer_2
            .start_connection(&NODE_1, peer_1_addr, REG_V1)
            .is_ok());
        assert_eq!(peer_1_receiver.blocking_recv(), Some(true));
        assert_eq!(peer_2_receiver.blocking_recv(), Some(true));
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
        let (peer_1_sender, mut peer_1_receiver) = channel(1);
        let event_handler_1 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_1_sender);
        let (peer_1, peer_1_addr) = setup_test_peer(
            log.clone(),
            rt.handle().clone(),
            NODE_1,
            peer1_port,
            REG_V1,
            &mut registry_and_data,
            crypto_factory,
            event_handler_1,
            use_h2,
        );
        let peer2_port = get_free_localhost_port().expect("Failed to get free localhost port");
        let (peer_2_sender, mut peer_2_receiver) = channel(1);
        let event_handler_2 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_2_sender);
        let (peer_2, peer_2_addr) = setup_test_peer(
            log,
            rt.handle().clone(),
            NODE_2,
            peer2_port,
            REG_V1,
            &mut registry_and_data,
            crypto_factory_with_single_tls_handshake_server_failures,
            event_handler_2,
            use_h2,
        );
        registry_and_data.registry.update_to_latest_version();

        assert!(peer_1
            .start_connection(&NODE_2, peer_2_addr, REG_V1)
            .is_ok());

        assert!(peer_2
            .start_connection(&NODE_1, peer_1_addr, REG_V1)
            .is_ok());
        assert_eq!(peer_1_receiver.blocking_recv(), Some(true));
        assert_eq!(peer_2_receiver.blocking_recv(), Some(true));
    });
}
