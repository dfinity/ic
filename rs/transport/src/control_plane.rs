//! Control plane - Transport connection management.
//!
//! The control plane handles tokio/TLS related details of connection
//! management. This component establishes/accepts connections to/from subnet
//! peers. The component also manages re-establishment of severed connections.

use crate::{
    data_plane::create_connected_state,
    metrics::{IntGaugeResource, STATUS_ERROR, STATUS_SUCCESS},
    types::{
        Connecting, ConnectionRole, ConnectionState, PeerState, QueueSize, ServerPortState,
        TransportImpl,
    },
    utils::get_flow_label,
};
use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_tls_interfaces::{AllowedClients, AuthenticatedPeer, TlsStream};
use ic_interfaces_transport::{FlowTag, TransportError, TransportEvent, TransportEventHandler};
use ic_logger::{error, warn};
use std::{net::SocketAddr, time::Duration};
use strum::AsRefStr;
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream},
    sync::RwLock,
    task::JoinHandle,
    time::sleep,
};
use tower::Service;

#[derive(Debug, AsRefStr)]
#[strum(serialize_all = "snake_case")]
enum TransportTlsHandshakeError {
    DeadlineExceeded,
    Internal(String),
    NotFound,
    InvalidArgument,
}

/// Time to wait before retrying an unsuccessful connection attempt
const CONNECT_RETRY_SECONDS: u64 = 3;

/// Time to wait for the TLS handshake (for both client/server sides)
const TLS_HANDSHAKE_TIMEOUT_SECONDS: u64 = 30;

const CONNECT_TASK_NAME: &str = "connect";
const ACCEPT_TASK_NAME: &str = "accept";
const TRANSITION_FROM_ACCEPT_TASK_NAME: &str = "transition_from_accept";

/// Implementation for the transport control plane
impl TransportImpl {
    /// Stops connection to a peer
    pub(crate) fn stop_peer_connection(&self, peer_id: &NodeId) {
        self.allowed_clients.blocking_write().remove(peer_id);
        self.peer_map.blocking_write().remove(peer_id);
    }

    /// Starts connection(s) to a peer and initializes the corresponding data
    /// structures and tasks
    pub(crate) fn start_peer_connection(
        &self,
        peer_id: &NodeId,
        peer_addr: SocketAddr,
        registry_version: RegistryVersion,
    ) -> Result<(), TransportError> {
        let role = connection_role(&self.node_id, peer_id);
        // If we are the server, we should add the peer to the allowed_clients.
        if role == ConnectionRole::Server {
            self.allowed_clients.blocking_write().insert(*peer_id);
        }
        *self.registry_version.blocking_write() = registry_version;
        let mut peer_map = self.peer_map.blocking_write();
        if peer_map.get(peer_id).is_some() {
            return Err(TransportError::AlreadyExists);
        }

        // TODO: P2P-514
        let flow_tag = FlowTag::from(self.config.legacy_flow_tag);
        if role == ConnectionRole::Server {
            let flow_label = get_flow_label(&peer_addr.ip().to_string(), peer_id);
            let peer_state = PeerState::new(
                self.log.clone(),
                flow_tag,
                flow_label,
                ConnectionState::Listening,
                QueueSize::from(self.config.send_queue_size),
                self.send_queue_metrics.clone(),
                self.control_plane_metrics.clone(),
            );
            peer_map.insert(*peer_id, RwLock::new(peer_state));
            return Ok(());
        }

        let flow_label = get_flow_label(&peer_addr.ip().to_string(), peer_id);
        let connecting_task = self.spawn_connect_task(flow_tag, *peer_id, peer_addr);
        let connecting_state = Connecting {
            peer_addr,
            connecting_task,
        };
        let peer_state = PeerState::new(
            self.log.clone(),
            flow_tag,
            flow_label,
            ConnectionState::Connecting(connecting_state),
            QueueSize::from(self.config.send_queue_size),
            self.send_queue_metrics.clone(),
            self.control_plane_metrics.clone(),
        );

        peer_map.insert(*peer_id, RwLock::new(peer_state));
        Ok(())
    }

    /// Starts the async task to accept the incoming TcpStreams in server mode.
    fn spawn_accept_task(&self, flow_tag: FlowTag, tcp_listener: TcpListener) -> JoinHandle<()> {
        let weak_self = self.weak_self.read().unwrap().clone();
        let rt_handle = self.rt_handle.clone();
        let async_tasks_gauge_vec = self.control_plane_metrics.async_tasks.clone();
        self.rt_handle.spawn(async move {
            let task_gauge = async_tasks_gauge_vec.with_label_values(&[ACCEPT_TASK_NAME]);
            let _gauge_guard = IntGaugeResource::new(task_gauge);
            loop {
                // If the TransportImpl has been deleted, abort.
                let arc_self = match weak_self.upgrade() {
                    Some(arc_self) => arc_self,
                    _ => return,
                };
                match tcp_listener.accept().await {
                    Ok((stream, _)) => {
                        arc_self.control_plane_metrics
                            .tcp_accepts
                            .with_label_values(&[STATUS_SUCCESS])
                            .inc();

                        let (local_addr, peer_addr) = match (stream.local_addr(), stream.peer_addr()) {
                            (Ok(local_addr), Ok(peer_addr)) => (local_addr, peer_addr),
                            _ => {
                                error!(
                                    arc_self.log,
                                    "ControlPlane::spawn_accept_task(): local_addr() and/or peer_addr() failed."
                                );
                                continue;
                            }
                        };

                        if let Err(err) = stream.set_nodelay(true) {
                            error!(
                                arc_self.log,
                                "ControlPlane::spawn_accept_task(): set_nodelay(true) failed: \
                                error = {:?}, local_addr = {:?}, peer_addr = {:?}",
                                err,
                                local_addr,
                                peer_addr,
                            );
                            continue;
                        }

                        rt_handle.spawn(async move {
                            let task_gauge = arc_self.control_plane_metrics.async_tasks.with_label_values(&[TRANSITION_FROM_ACCEPT_TASK_NAME]);
                            let _gauge_guard = IntGaugeResource::new(task_gauge);
                            let (peer_id, tls_stream) = match arc_self.tls_server_handshake(stream).await {
                                Ok((peer_id, tls_stream)) => {
                                    arc_self.control_plane_metrics
                                        .tls_handshakes
                                        .with_label_values(&[ConnectionRole::Server.as_ref(), STATUS_SUCCESS])
                                        .inc();
                                    (peer_id, tls_stream)
                                },
                                Err(err) => {
                                    arc_self.control_plane_metrics
                                        .tls_handshakes
                                        .with_label_values(&[ConnectionRole::Server.as_ref(), err.as_ref()])
                                       .inc();
                                    warn!(
                                        arc_self.log,
                                        "ControlPlane::spawn_accept_task(): tls_server_handshake failed: error = {:?},
                                        local_addr = {:?}, peer_addr = {:?}",
                                        err,
                                        local_addr,
                                        peer_addr,
                                    );
                                    return;
                                }
                            };

                            let peer_map = arc_self.peer_map.read().await;
                            let peer_state_mu = match peer_map.get(&peer_id) {
                                Some(peer_state) => peer_state,
                                None => return,
                            };
                            let mut peer_state = peer_state_mu.write().await;
                            if peer_state.get_connected().is_some() {
                                // TODO: P2P-516
                                return;
                            }
                            let mut event_handler = match arc_self.event_handler.lock().await.as_ref() {
                                Some(event_handler) => event_handler.clone(),
                                None => return,
                            };
                            let connected_state = create_connected_state(
                                peer_id,
                                flow_tag,
                                peer_state.flow_label.clone(),
                                peer_state.send_queue.get_reader(),
                                ConnectionRole::Server,
                                peer_addr,
                                tls_stream,
                                event_handler.clone(),
                                arc_self.data_plane_metrics.clone(),
                                arc_self.weak_self.read().unwrap().clone(),
                                arc_self.rt_handle.clone(),
                            );

                            event_handler
                                .call(TransportEvent::PeerUp(peer_id))
                                .await
                                .expect("Can't panic on infallible");
                            peer_state.update(ConnectionState::Connected(connected_state));
                            arc_self.control_plane_metrics
                                .tcp_accept_conn_success
                                .with_label_values(&[&flow_tag.to_string()])
                                    .inc()
                        });
                    }
                    Err(err) => {
                        arc_self.control_plane_metrics
                            .tcp_accepts
                            .with_label_values(&[STATUS_ERROR])
                            .inc();
                        error!(arc_self.log, "ControlPlane::spawn_accept_task(): accept failed: error = {:?}", err);
                    }
                }
            }
        })
    }

    /// Spawn a task that tries to connect to a peer (forever, or until
    /// connection is established or peer is removed)
    fn spawn_connect_task(
        &self,
        flow_tag: FlowTag,
        peer_id: NodeId,
        peer_addr: SocketAddr,
    ) -> JoinHandle<()> {
        let node_ip = self.node_ip;
        let weak_self = self.weak_self.read().unwrap().clone();
        let async_tasks_gauge_vec = self.control_plane_metrics.async_tasks.clone();
        self.rt_handle.spawn(async move {
            let gauge = async_tasks_gauge_vec.with_label_values(&[CONNECT_TASK_NAME]);
            let _raii_gauge_vec = IntGaugeResource::new(gauge);
            let local_addr = SocketAddr::new(node_ip, 0);

            // Loop till connection is established
            let mut retries: u32 = 0;
            loop {
                retries += 1;
                // If the TransportImpl has been deleted, abort.
                let arc_self = match weak_self.upgrade() {
                    Some(arc_self) => arc_self,
                    _ => return,
                };
                // We currently retry forever, which is fine as we have per-connection
                // async task. This loop will terminate when the peer is removed from
                // valid set.
                match connect_to_server(local_addr, peer_addr).await {
                    Ok(stream) => {
                        arc_self.control_plane_metrics
                            .tcp_connects
                            .with_label_values(&[STATUS_SUCCESS])
                            .inc();

                        let peer_map = arc_self.peer_map.read().await;
                        let peer_state_mu = match peer_map.get(&peer_id) {
                            Some(peer_state) => peer_state,
                            None => continue,
                        };
                        let mut peer_state = peer_state_mu.write().await;
                        if peer_state.get_connected().is_some() {
                            // TODO: P2P-516
                            continue;
                        }
                        let tls_stream = match arc_self.tls_client_handshake(peer_id, stream).await {
                            Ok(tls_stream) => {
                                arc_self.control_plane_metrics
                                .tls_handshakes
                                    .with_label_values(&[ConnectionRole::Client.as_ref(), STATUS_SUCCESS])
                                    .inc();
                                tls_stream
                            }
                            Err(err) => {
                                arc_self.control_plane_metrics
                                    .tls_handshakes
                                    .with_label_values(&[ConnectionRole::Client.as_ref(), err.as_ref()])
                                    .inc();
                                warn!(
                                    arc_self.log,
                                    "ControlPlane::spawn_connect_task(): tls_client_handshake failed: error = {:?},
                                    local_addr = {:?}, peer_addr = {:?}",
                                    err,
                                    local_addr,
                                    peer_addr,
                                );
                                continue;
                            }
                        };

                        let mut event_handler = match arc_self.event_handler.lock().await.as_ref() {
                            Some(event_handler) => event_handler.clone(),
                            None => continue,
                        };
                        let connected_state = create_connected_state(
                            peer_id,
                            flow_tag,
                            peer_state.flow_label.clone(),
                            peer_state.send_queue.get_reader(),
                            ConnectionRole::Client,
                            peer_addr,
                            tls_stream,
                            event_handler.clone(),
                            arc_self.data_plane_metrics.clone(),
                            arc_self.weak_self.read().unwrap().clone(),
                            arc_self.rt_handle.clone(),

                        );
                        event_handler
                            .call(TransportEvent::PeerUp(peer_id))
                            .await
                            .expect("Can't panic on infallible");
                        peer_state.update(ConnectionState::Connected(connected_state));
                        arc_self.control_plane_metrics
                            .tcp_conn_to_server_success
                            .with_label_values(&[
                                &peer_id.to_string(),
                                &flow_tag.to_string(),
                            ])
                            .inc();
                        return;
                    }
                    Err(err) => {
                        arc_self.control_plane_metrics
                            .tcp_connects
                            .with_label_values(&[STATUS_ERROR])
                            .inc();
                        warn!(
                            arc_self.log,
                            "ControlPlane::spawn_connect_task(): connect_to_server failed: error = {:?}, \
                            local_addr = {:?}, peer = {:?}/{:?}, retries = {}",
                            err,
                            local_addr,
                            peer_id,
                            peer_addr,
                            retries,
                        );
                    }
                }
                sleep(Duration::from_secs(CONNECT_RETRY_SECONDS)).await;
            }
        })
    }

    /// Retries to establish a connection
    pub(crate) async fn on_disconnect(&self, peer_id: NodeId, flow_tag: FlowTag) {
        warn!(
            self.log,
            "ControlPlane::retry_connection(): node_id = {:?}, flow_tag = {:?}, peer_id = {:?}",
            self.node_id,
            flow_tag,
            peer_id
        );
        let peer_map = self.peer_map.read().await;
        let peer_state_mu = match peer_map.get(&peer_id) {
            Some(peer_state) => peer_state,
            None => return,
        };
        let mut peer_state = peer_state_mu.write().await;
        let connected = match peer_state.get_connected() {
            Some(connected) => connected,
            // Flow is already disconnected/reconnecting, skip reconnect processing
            None => return,
        };
        let mut event_handler = match self.event_handler.lock().await.as_ref() {
            Some(event_handler) => event_handler.clone(),
            None => return,
        };
        self.control_plane_metrics
            .retry_connection
            .with_label_values(&[&peer_id.to_string(), &flow_tag.to_string()])
            .inc();

        let socket_addr = connected.peer_addr;
        let connection_state = if connection_role(&self.node_id, &peer_id) == ConnectionRole::Server
        {
            // We are the server, wait for the peer to connect
            warn!(
                self.log,
                "ControlPlane::process_disconnect(): waiting for peer to reconnect: \
                 node_id = {:?}, flow_tag = {:?}, peer_id = {:?}",
                self.node_id,
                flow_tag,
                peer_id
            );
            ConnectionState::Listening
        } else {
            // reconnect if we have a listener
            let connecting_task = self.spawn_connect_task(flow_tag, peer_id, socket_addr);
            let connecting_state = Connecting {
                peer_addr: socket_addr,
                connecting_task,
            };
            warn!(
                self.log,
                "ControlPlane::process_disconnect(): spawning reconnect task: node = {:?}/{:?}, \
                    flow_tag = {:?}, peer = {:?}/{:?}, peer_port = {:?}",
                self.node_id,
                self.node_ip,
                flow_tag,
                peer_id,
                socket_addr.ip(),
                socket_addr.port(),
            );
            ConnectionState::Connecting(connecting_state)
        };
        event_handler
            .call(TransportEvent::PeerDown(peer_id))
            .await
            .expect("Can't panic on infallible");
        peer_state.update(connection_state);
    }

    /// Performs the server side TLS hand shake processing
    async fn tls_server_handshake(
        &self,
        stream: TcpStream,
    ) -> Result<(NodeId, TlsStream), TransportTlsHandshakeError> {
        let registry_version = *self.registry_version.read().await;
        let current_allowed_clients = self.allowed_clients.read().await.clone();
        let allowed_clients = AllowedClients::new_with_nodes(current_allowed_clients)
            .map_err(|_| TransportTlsHandshakeError::InvalidArgument)?;
        let (tls_stream, authenticated_peer) = match tokio::time::timeout(
            Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECONDS),
            self.crypto
                .perform_tls_server_handshake(stream, allowed_clients, registry_version),
        )
        .await
        {
            Err(_) => Err(TransportTlsHandshakeError::DeadlineExceeded),
            Ok(Ok((tls_stream, authenticated_peer))) => Ok((tls_stream, authenticated_peer)),
            Ok(Err(err)) => Err(TransportTlsHandshakeError::Internal(format!("{:?}", err))),
        }?;
        let peer_id = match authenticated_peer {
            AuthenticatedPeer::Node(node_id) => node_id,
            AuthenticatedPeer::Cert(_) => {
                return Err(TransportTlsHandshakeError::NotFound);
            }
        };
        Ok((peer_id, tls_stream))
    }

    /// Performs the client side TLS hand shake processing
    async fn tls_client_handshake(
        &self,
        peer_id: NodeId,
        stream: TcpStream,
    ) -> Result<TlsStream, TransportTlsHandshakeError> {
        let registry_version = *self.registry_version.read().await;
        match tokio::time::timeout(
            Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECONDS),
            self.crypto
                .perform_tls_client_handshake(stream, peer_id, registry_version),
        )
        .await
        {
            Err(_) => Err(TransportTlsHandshakeError::DeadlineExceeded),
            Ok(Ok(tls_stream)) => Ok(tls_stream),
            Ok(Err(err)) => Err(TransportTlsHandshakeError::Internal(format!("{:?}", err))),
        }
    }

    /// Initilizes a client
    pub(crate) fn init_client(&self, event_handler: TransportEventHandler) {
        // Creating the listeners requres that we are within a tokio runtime context.
        let _rt_enter_guard = self.rt_handle.enter();
        // Bind to the server ports.
        let server_addr = SocketAddr::new(self.node_ip, self.config.listening_port);
        let tcp_listener = start_listener(server_addr).unwrap_or_else(|err| {
            panic!(
                "Failed to init listener: local_addr = {:?}, error = {:?}",
                server_addr, err
            )
        });

        let flow_tag = FlowTag::from(self.config.legacy_flow_tag);
        let accept_task = self.spawn_accept_task(flow_tag, tcp_listener);
        *self.accept_port.blocking_lock() = Some(ServerPortState { accept_task });
        *self.event_handler.blocking_lock() = Some(event_handler);
    }
}

/// Set up the client socket, and connect to the specified server peer
async fn connect_to_server(
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> std::io::Result<TcpStream> {
    let socket = if local_addr.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    socket.bind(local_addr)?;
    let stream = socket.connect(peer_addr).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

// Sets up the server side socket with the node IP:port
// Panics in case of unrecoverable error.
fn start_listener(local_addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if local_addr.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.bind(local_addr)?;
    socket.listen(128)
}

/// Returns our role wrt the peer connection
fn connection_role(my_id: &NodeId, peer: &NodeId) -> ConnectionRole {
    assert!(*my_id != *peer);
    if *my_id > *peer {
        ConnectionRole::Server
    } else {
        ConnectionRole::Client
    }
}

#[cfg(test)]
mod tests {
    use crate::transport::create_transport;
    use ic_base_types::{NodeId, RegistryVersion};
    use ic_config::transport::TransportConfig;
    use ic_crypto::utils::TempCryptoComponent;
    use ic_crypto_tls_interfaces::{TlsClientHandshakeError, TlsHandshake};
    use ic_crypto_tls_interfaces_mocks::MockTlsHandshake;
    use ic_interfaces_transport::{Transport, TransportEvent, TransportEventHandler};
    use ic_logger::ReplicaLogger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::make_crypto_tls_cert_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types_test_utils::ids::{NODE_1, NODE_2};
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio::sync::mpsc::{channel, Sender};
    use tower::{util::BoxCloneService, Service, ServiceExt};
    use tower_test::mock::Handle;

    const NODE_ID_1: NodeId = NODE_1;
    const NODE_ID_2: NodeId = NODE_2;
    const REG_V1: RegistryVersion = RegistryVersion::new(1);
    const FLOW_TAG: u32 = 1234;

    const PORT_1: u16 = 65001;
    const PORT_2: u16 = 65002;

    fn setup_test_peer<F>(
        log: ReplicaLogger,
        rt_handle: tokio::runtime::Handle,
        node_id: NodeId,
        port: u16,
        registry_version: RegistryVersion,
        registry_and_data: &mut RegistryAndDataProvider,
        mut crypto_factory: F,
    ) -> (Arc<dyn Transport>, Handle<TransportEvent, ()>, SocketAddr)
    where
        F: FnMut(&mut RegistryAndDataProvider, NodeId) -> Arc<dyn TlsHandshake + Send + Sync>,
    {
        let crypto = crypto_factory(registry_and_data, node_id);
        let config = TransportConfig {
            node_ip: "0.0.0.0".to_string(),
            legacy_flow_tag: FLOW_TAG,
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
        );
        let addr = SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap();
        let (event_handler, mock_handle) = setup_mock_event_handler();
        peer.set_event_handler(event_handler);
        (peer, mock_handle, addr)
    }

    #[test]
    fn test_start_connection_between_two_peers() {
        with_test_replica_logger(|logger| {
            let registry_version = REG_V1;

            let rt = tokio::runtime::Runtime::new().unwrap();

            let (connected_1, mut done_1) = channel(1);
            let (event_handler_1, handle_1) = setup_mock_event_handler();
            create_peer_up_ack_event_handler(rt.handle().clone(), handle_1, connected_1);

            let (connected_2, mut done_2) = channel(1);
            let (event_handler_2, handle_2) = setup_mock_event_handler();
            create_peer_up_ack_event_handler(rt.handle().clone(), handle_2, connected_2);

            let (_control_plane_1, _control_plane_2) = start_connection_between_two_peers(
                rt.handle().clone(),
                logger,
                registry_version,
                10,
                event_handler_1,
                event_handler_2,
            );

            assert_eq!(done_1.blocking_recv(), Some(true));
            assert_eq!(done_2.blocking_recv(), Some(true));
        });
    }

    // helper functions

    fn create_peer_up_ack_event_handler(
        rt: tokio::runtime::Handle,
        mut handle: Handle<TransportEvent, ()>,
        connected: Sender<bool>,
    ) {
        rt.spawn(async move {
            let (event, rsp) = handle.next_request().await.unwrap();
            if let TransportEvent::PeerUp(_) = event {
                connected.try_send(true).unwrap()
            }
            rsp.send_response(());
        });
    }

    struct RegistryAndDataProvider {
        data_provider: Arc<ProtoRegistryDataProvider>,
        registry: Arc<FakeRegistryClient>,
    }

    impl RegistryAndDataProvider {
        fn new() -> Self {
            let data_provider = Arc::new(ProtoRegistryDataProvider::new());
            let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));
            Self {
                data_provider,
                registry,
            }
        }
    }

    fn temp_crypto_component_with_tls_keys_in_registry(
        registry_and_data: &RegistryAndDataProvider,
        node_id: NodeId,
    ) -> TempCryptoComponent {
        let (temp_crypto, tls_pubkey_cert) = TempCryptoComponent::new_with_tls_key_generation(
            Arc::clone(&registry_and_data.registry) as Arc<_>,
            node_id,
        );
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

    // TODO(NET-1182): this test hangs on CI sometimes
    #[ignore]
    #[test]
    fn test_single_transient_failure_of_tls_client_handshake() {
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
                        .returning(
                            move |_tcp_stream: TcpStream,
                                  _server: NodeId,
                                  _registry_version: RegistryVersion| {
                                Err(TlsClientHandshakeError::HandshakeError {
                                    internal_error: "transient".to_string(),
                                })
                            },
                        );

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

            let crypto_factory = |registry_and_data: &mut RegistryAndDataProvider,
                                  node_id: NodeId| {
                Arc::new(temp_crypto_component_with_tls_keys_in_registry(
                    registry_and_data,
                    node_id,
                )) as Arc<dyn TlsHandshake + Send + Sync>
            };

            let (peer_1, mut mock_handle_peer_1, peer_1_addr) = setup_test_peer(
                log.clone(),
                rt.handle().clone(),
                NODE_1,
                PORT_1,
                REG_V1,
                &mut registry_and_data,
                crypto_factory_with_single_tls_handshake_client_failures,
            );
            let (peer_2, mut mock_handle_peer_2, peer_2_addr) = setup_test_peer(
                log,
                rt.handle().clone(),
                NODE_2,
                PORT_2,
                REG_V1,
                &mut registry_and_data,
                crypto_factory,
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
                .start_connection(&NODE_ID_2, peer_2_addr, REG_V1)
                .is_ok());

            assert!(peer_2
                .start_connection(&NODE_ID_1, peer_1_addr, REG_V1)
                .is_ok());
            assert_eq!(done_1.blocking_recv(), Some(true));
            assert_eq!(done_2.blocking_recv(), Some(true));
        });
    }

    fn setup_mock_event_handler() -> (TransportEventHandler, Handle<TransportEvent, ()>) {
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

    fn start_connection_between_two_peers(
        rt_handle: tokio::runtime::Handle,
        logger: ReplicaLogger,
        registry_version: RegistryVersion,
        send_queue_size: usize,
        event_handler_1: TransportEventHandler,
        event_handler_2: TransportEventHandler,
    ) -> (Arc<dyn Transport>, Arc<dyn Transport>) {
        // Setup registry and crypto component
        let registry_and_data = RegistryAndDataProvider::new();
        let crypto_1 =
            temp_crypto_component_with_tls_keys_in_registry(&registry_and_data, NODE_ID_1);
        let crypto_2 =
            temp_crypto_component_with_tls_keys_in_registry(&registry_and_data, NODE_ID_2);
        registry_and_data.registry.update_to_latest_version();

        let peer_a_config = TransportConfig {
            node_ip: "0.0.0.0".to_string(),
            listening_port: PORT_1,
            legacy_flow_tag: FLOW_TAG,
            send_queue_size,
        };

        let peer_a = create_transport(
            NODE_ID_1,
            peer_a_config,
            registry_version,
            MetricsRegistry::new(),
            Arc::new(crypto_1),
            rt_handle.clone(),
            logger.clone(),
        );
        peer_a.set_event_handler(event_handler_1);

        let peer_b_config = TransportConfig {
            node_ip: "0.0.0.0".to_string(),
            listening_port: PORT_2,
            legacy_flow_tag: FLOW_TAG,
            send_queue_size,
        };

        let peer_b = create_transport(
            NODE_ID_2,
            peer_b_config,
            registry_version,
            MetricsRegistry::new(),
            Arc::new(crypto_2),
            rt_handle,
            logger,
        );
        peer_b.set_event_handler(event_handler_2);
        let peer_2_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", PORT_2)).unwrap();

        peer_a
            .start_connection(&NODE_ID_2, peer_2_addr, REG_V1)
            .expect("start_connection");

        let peer_1_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", PORT_1)).unwrap();
        peer_b
            .start_connection(&NODE_ID_1, peer_1_addr, REG_V1)
            .expect("start_connection");

        (peer_a, peer_b)
    }
}
