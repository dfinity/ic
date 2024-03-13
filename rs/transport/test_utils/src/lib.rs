use futures::future::BoxFuture;
use ic_base_types::{NodeId, RegistryVersion, SubnetId};
use ic_config::transport::TransportConfig;
use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces_transport::{
    Transport, TransportChannelId, TransportError, TransportEvent, TransportEventHandler,
    TransportPayload,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{
    make_crypto_tls_cert_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities_registry::test_subnet_record;
use ic_transport::transport::create_transport;
use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4, SUBNET_1};
use std::{collections::HashMap, convert::Infallible, net::SocketAddr, str::FromStr, sync::Arc};
use tokio::{net::TcpSocket, task::JoinHandle};
use tower::{util::BoxCloneService, Service, ServiceExt};
use tower_test::mock::Handle;

pub const NODE_ID_1: NodeId = NODE_1;
pub const NODE_ID_2: NodeId = NODE_2;
pub const NODE_ID_3: NodeId = NODE_3;
pub const NODE_ID_4: NodeId = NODE_4;
pub const SUBNET_ID_1: SubnetId = SUBNET_1;

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

pub fn peer_down_message() -> TransportPayload {
    // For send channels of TransportPayload type, we need some payload representing peer down event
    TransportPayload(vec![0xc; 1])
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

#[derive(Clone)]
pub struct RegistryAndDataProvider {
    pub data_provider: Arc<ProtoRegistryDataProvider>,
    pub registry: Arc<FakeRegistryClient>,
}

impl RegistryAndDataProvider {
    pub fn new() -> Self {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let subnet_list_record = SubnetListRecord {
            subnets: vec![SUBNET_ID_1.get().to_vec()],
        };
        data_provider
            .add(
                make_subnet_list_record_key().as_str(),
                REG_V1,
                Some(subnet_list_record),
            )
            .expect("Could not add subnet list");
        let mut subnet_record = test_subnet_record();
        subnet_record.membership = vec![
            NODE_ID_1.get().to_vec(),
            NODE_ID_2.get().to_vec(),
            NODE_ID_3.get().to_vec(),
            NODE_ID_4.get().to_vec(),
        ];
        data_provider
            .add(
                &make_subnet_record_key(SUBNET_ID_1),
                REG_V1,
                Some(subnet_record),
            )
            .expect("Could not add subnet record.");
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

pub struct TestPeerBuilder {
    node_id: NodeId,
    rt_handle: tokio::runtime::Handle,
    registry_data: RegistryAndDataProvider,
    log: ReplicaLogger,
    send_queue_size: usize,
    crypto: Option<Arc<dyn TlsHandshake + Send + Sync>>,
    h2: bool,
    registry_version: RegistryVersion,
}

pub struct TestPeer {
    node_id: NodeId,
    addr: SocketAddr,
    transport: Arc<dyn Transport>,
    handle: Handle<TransportEvent, ()>,
}

impl TestPeerBuilder {
    pub fn new(
        node_id: NodeId,
        rt_handle: tokio::runtime::Handle,
        registry_data: RegistryAndDataProvider,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            rt_handle,
            registry_data,
            log,
            send_queue_size: 51200,
            crypto: None,
            h2: false,
            registry_version: REG_V1,
        }
    }
    pub fn h2(mut self, use_h2: bool) -> Self {
        self.h2 = use_h2;
        self
    }
    pub fn send_queue_size(mut self, n: usize) -> Self {
        self.send_queue_size = n;
        self
    }
    pub fn registry_version(mut self, rv: RegistryVersion) -> Self {
        self.registry_version = rv;
        self
    }
    pub fn crypto(mut self, c: Arc<dyn TlsHandshake + Send + Sync>) -> Self {
        self.crypto = Some(c);
        self
    }
    pub fn build(self) -> TestPeer {
        let crypto = self.crypto.unwrap_or_else(|| {
            let crypto =
                temp_crypto_component_with_tls_keys_in_registry(&self.registry_data, self.node_id);
            Arc::new(crypto)
        });

        let (event_handler, handle) = create_mock_event_handler();

        let listening_port = get_free_localhost_port().expect("Failed to get free localhost port");
        let node_config = TransportConfig {
            node_ip: "127.0.0.1".to_string(),
            listening_port,
            send_queue_size: self.send_queue_size,
            ..Default::default()
        };

        let transport = create_transport(
            self.node_id,
            node_config,
            self.registry_version,
            self.registry_version,
            MetricsRegistry::new(),
            crypto,
            self.rt_handle,
            self.log,
            self.h2,
        );
        transport.set_event_handler(event_handler);

        TestPeer {
            node_id: self.node_id,
            addr: SocketAddr::from_str(&format!("127.0.0.1:{}", listening_port)).unwrap(),
            transport,
            handle,
        }
    }
}

pub struct TestTopology {
    peer_handles: HashMap<NodeId, TestPeerHandle>,
}

impl TestTopology {
    /// Blocks until:
    /// Reference count of control plane == 1
    /// Make sure that event handler is down.
    pub fn verify_all_peers_down(&mut self) {
        for (_, peer) in self.peer_handles.iter() {
            while Arc::strong_count(&peer.transport) != 1 {}
            while !peer.event_handler_jh.is_finished() {}
        }
    }
    pub fn stop_peer_connection(&self, src_node: NodeId, dst_node: NodeId) {
        self.peer_handles
            .get(&src_node)
            .unwrap()
            .transport
            .stop_connection(&dst_node);
    }
    pub fn send_payload(
        &self,
        src_node: NodeId,
        dst_node: NodeId,
        channel_id: TransportChannelId,
        msg: TransportPayload,
    ) -> Result<(), TransportError> {
        self.peer_handles
            .get(&src_node)
            .unwrap()
            .transport
            .send(&dst_node, channel_id, msg)
    }
}

struct TestPeerHandle {
    addr: SocketAddr,
    transport: Arc<dyn Transport>,
    event_handler_jh: JoinHandle<()>,
}

pub struct TestTopologyBuilder {
    rt_handle: tokio::runtime::Handle,
    registry_data: RegistryAndDataProvider,
    peers: HashMap<NodeId, TestPeerHandle>,
}

impl TestTopologyBuilder {
    pub fn new(registry_data: RegistryAndDataProvider, rt_handle: tokio::runtime::Handle) -> Self {
        Self {
            rt_handle,
            registry_data,
            peers: HashMap::new(),
        }
    }
    pub fn add_node(
        mut self,
        peer: TestPeer,
        expectation_event_handler: impl FnOnce(Handle<TransportEvent, ()>) -> BoxFuture<'static, ()>
            + Send,
    ) -> Self {
        let TestPeer {
            node_id: _,
            addr,
            transport,
            handle,
        } = peer;

        let event_handler_jh = self.rt_handle.spawn((expectation_event_handler)(handle));

        self.peers.insert(
            peer.node_id,
            TestPeerHandle {
                addr,
                transport,
                event_handler_jh,
            },
        );
        self
    }
    pub fn full_mesh(self) -> TestTopology {
        // Make sure registry contains all peers.
        self.registry_data.registry.update_to_latest_version();

        // Create full mesh network.
        for (id_1, peer_1) in self.peers.iter() {
            for (id_2, peer_2) in self.peers.iter() {
                if id_1 != id_2 {
                    peer_1.transport.start_connection(
                        id_2,
                        peer_2.addr,
                        self.registry_data.data_provider.latest_version(),
                        self.registry_data.data_provider.latest_version(),
                    )
                }
            }
        }
        TestTopology {
            peer_handles: self.peers,
        }
    }
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
        registry_version,
        MetricsRegistry::new(),
        Arc::new(crypto_2),
        rt_handle,
        logger,
        use_h2,
    );
    peer_b.set_event_handler(event_handler_2);
    let peer_2_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", peer2_port)).unwrap();

    peer_a.start_connection(&node_2, peer_2_addr, REG_V1, REG_V1);
    let peer_1_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", peer1_port)).unwrap();
    peer_b.start_connection(&node_1, peer_1_addr, REG_V1, REG_V1);
    (peer_a, peer_b)
}
