use ic_base_types::{NodeId, RegistryVersion};
use ic_config::transport::TransportConfig;
use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces_transport::{Transport, TransportEvent, TransportEventHandler, TransportPayload};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_tls_cert_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_transport::transport::create_transport;
use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4};
use std::{convert::Infallible, net::SocketAddr, str::FromStr, sync::Arc};
use tokio::net::TcpSocket;
use tower::{util::BoxCloneService, Service, ServiceExt};
use tower_test::mock::Handle;

pub const NODE_ID_1: NodeId = NODE_1;
pub const NODE_ID_2: NodeId = NODE_2;
pub const NODE_ID_3: NodeId = NODE_3;
pub const NODE_ID_4: NodeId = NODE_4;

pub const TRANSPORT_CHANNEL_ID: usize = 0;

pub fn basic_transport_message() -> TransportPayload {
    TransportPayload(vec![0xb; 1_000_000])
}

pub fn basic_transport_message_v2() -> TransportPayload {
    TransportPayload(vec![0xb; 1_000_001])
}

pub fn blocking_transport_message() -> TransportPayload {
    TransportPayload(vec![0xb; 1_000_002])
}

pub fn large_transport_message() -> TransportPayload {
    // Currently largest use case (StateSync) may send up to 100MB
    TransportPayload(vec![0xb; 100_000_000])
}

pub const REG_V1: RegistryVersion = RegistryVersion::new(1);

// Get a free port on this host to which we can connect transport to.
pub fn get_free_localhost_port() -> std::io::Result<u16> {
    let socket = TcpSocket::new_v4()?;
    // This allows transport to bind to this address,
    //  even though the socket is already bound.
    socket.set_reuseport(false)?;
    socket.set_reuseaddr(false)?;
    socket.bind("127.0.0.1:0".parse().unwrap())?;
    Ok(socket.local_addr()?.port())
}

pub struct RegistryAndDataProvider {
    pub data_provider: Arc<ProtoRegistryDataProvider>,
    pub registry: Arc<FakeRegistryClient>,
}

impl RegistryAndDataProvider {
    pub fn new() -> Self {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));
        Self {
            data_provider,
            registry,
        }
    }
}

impl Default for RegistryAndDataProvider {
    fn default() -> Self {
        Self::new()
    }
}

pub fn setup_test_peer<F>(
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    node_id: NodeId,
    port: u16,
    registry_version: RegistryVersion,
    registry_and_data: &mut RegistryAndDataProvider,
    mut crypto_factory: F,
    event_handler: TransportEventHandler,
    use_h2: bool,
) -> (Arc<dyn Transport>, SocketAddr)
where
    F: FnMut(&mut RegistryAndDataProvider, NodeId) -> Arc<dyn TlsHandshake + Send + Sync>,
{
    let crypto = crypto_factory(registry_and_data, node_id);
    let config = TransportConfig {
        node_ip: "0.0.0.0".to_string(),
        listening_port: port,
        send_queue_size: 10,
        ..Default::default()
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
    peer.set_event_handler(event_handler);
    (peer, addr)
}

pub fn temp_crypto_component_with_tls_keys_in_registry(
    registry_and_data: &RegistryAndDataProvider,
    node_id: NodeId,
) -> TempCryptoComponent {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(Arc::clone(&registry_and_data.registry) as Arc<_>)
        .with_node_id(node_id)
        .with_keys(NodeKeysToGenerate::only_tls_key_and_cert())
        .build();
    let tls_pubkey_cert = temp_crypto.node_tls_public_key_certificate();
    registry_and_data
        .data_provider
        .add(
            &make_crypto_tls_cert_key(node_id),
            REG_V1,
            Some(tls_pubkey_cert.to_proto()),
        )
        .expect("failed to add TLS cert to registry");
    temp_crypto
}

pub fn create_mock_event_handler() -> (TransportEventHandler, Handle<TransportEvent, ()>) {
    let (service, handle) = tower_test::mock::pair::<TransportEvent, ()>();

    let infallible_service = tower::service_fn(move |request: TransportEvent| {
        let mut service_clone = service.clone();
        async move {
            service_clone
                .ready()
                .await
                .expect("Mocking Infallible service. Waiting for readiness failed.")
                .call(request)
                .await
                .expect("Mocking Infallible service and can therefore not return an error.");
            Ok::<(), Infallible>(())
        }
    });
    (BoxCloneService::new(infallible_service), handle)
}

pub fn start_connection_between_two_peers(
    rt_handle: tokio::runtime::Handle,
    logger: ReplicaLogger,
    registry_version: RegistryVersion,
    send_queue_size: usize,
    event_handler_1: TransportEventHandler,
    event_handler_2: TransportEventHandler,
    node_1: NodeId,
    node_2: NodeId,
    use_h2: bool,
) -> (Arc<dyn Transport>, Arc<dyn Transport>) {
    // Setup registry and crypto component
    let registry_and_data = RegistryAndDataProvider::new();
    let crypto_1 = temp_crypto_component_with_tls_keys_in_registry(&registry_and_data, node_1);
    let crypto_2 = temp_crypto_component_with_tls_keys_in_registry(&registry_and_data, node_2);
    registry_and_data.registry.update_to_latest_version();

    let peer1_port = get_free_localhost_port().expect("Failed to get free localhost port");
    let peer_a_config = TransportConfig {
        node_ip: "127.0.0.1".to_string(),
        listening_port: peer1_port,
        send_queue_size,
        ..Default::default()
    };

    let peer_a = create_transport(
        node_1,
        peer_a_config,
        registry_version,
        MetricsRegistry::new(),
        Arc::new(crypto_1),
        rt_handle.clone(),
        logger.clone(),
        use_h2,
    );

    peer_a.set_event_handler(event_handler_1);

    let peer2_port = get_free_localhost_port().expect("Failed to get free localhost port");
    let peer_b_config = TransportConfig {
        node_ip: "127.0.0.1".to_string(),
        listening_port: peer2_port,
        send_queue_size,
        ..Default::default()
    };

    let peer_b = create_transport(
        node_2,
        peer_b_config,
        registry_version,
        MetricsRegistry::new(),
        Arc::new(crypto_2),
        rt_handle,
        logger,
        use_h2,
    );
    peer_b.set_event_handler(event_handler_2);
    let peer_2_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", peer2_port)).unwrap();

    peer_a
        .start_connection(&node_2, peer_2_addr, REG_V1)
        .expect("start_connection");

    let peer_1_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", peer1_port)).unwrap();
    peer_b
        .start_connection(&node_1, peer_1_addr, REG_V1)
        .expect("start_connection");

    (peer_a, peer_b)
}
