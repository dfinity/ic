//! Control plane - Transport connection management.
//!
//! The control plane handles tokio/TLS related details of connection
//! management. This component establishes/accepts connections to/from subnet
//! peers. The component also manages re-establishment of severed connections.

use crate::{
    data_plane::create_connected_state,
    metrics::{IntGaugeResource, STATUS_ERROR, STATUS_SUCCESS},
    types::{
        Connecting, ConnectionRole, ConnectionState, FlowState, PeerState, QueueSize,
        ServerPortState, TransportImpl,
    },
    utils::get_flow_label,
};
use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_tls_interfaces::{AllowedClients, AuthenticatedPeer, TlsStream};
use ic_interfaces_transport::{
    FlowTag, TransportErrorCode, TransportEvent, TransportEventHandler, TransportStateChange,
};
use ic_logger::{error, warn};
use std::{collections::HashMap, net::SocketAddr, time::Duration};
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
    ) -> Result<(), TransportErrorCode> {
        let role = connection_role(&self.node_id, peer_id);
        // If we are the server, we should add the peer to the allowed_clients.
        if role == ConnectionRole::Server {
            self.allowed_clients.blocking_write().insert(*peer_id);
        }
        *self.registry_version.blocking_write() = registry_version;
        let mut peer_map = self.peer_map.blocking_write();
        if peer_map.get(peer_id).is_some() {
            return Err(TransportErrorCode::PeerAlreadyRegistered);
        }
        let mut peer_state = PeerState {
            flow_map: HashMap::new(),
        };

        // TODO: P2P-514
        let flow_tag = FlowTag::from(self.config.legacy_flow_tag);
        if role == ConnectionRole::Server {
            let flow_label = get_flow_label(&peer_addr.ip().to_string(), peer_id);
            let flow_state = FlowState::new(
                self.log.clone(),
                flow_tag,
                flow_label,
                ConnectionState::Listening,
                QueueSize::from(self.config.send_queue_size),
                self.send_queue_metrics.clone(),
                self.control_plane_metrics.clone(),
            );
            peer_state
                .flow_map
                .insert(flow_tag, RwLock::new(flow_state));
        }
        if role == ConnectionRole::Server {
            peer_map.insert(*peer_id, peer_state);
            return Ok(());
        }

        let flow_label = get_flow_label(&peer_addr.ip().to_string(), peer_id);
        let connecting_task = self.spawn_connect_task(flow_tag, *peer_id, peer_addr);
        let connecting_state = Connecting {
            peer_addr,
            connecting_task,
        };
        let flow_state = FlowState::new(
            self.log.clone(),
            flow_tag,
            flow_label,
            ConnectionState::Connecting(connecting_state),
            QueueSize::from(self.config.send_queue_size),
            self.send_queue_metrics.clone(),
            self.control_plane_metrics.clone(),
        );
        peer_state
            .flow_map
            .insert(flow_tag, RwLock::new(flow_state));

        peer_map.insert(*peer_id, peer_state);
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
                            let peer_state = match peer_map.get(&peer_id) {
                                Some(peer_state) => peer_state,
                                None => return,
                            };
                            let flow_state_mu = match peer_state.flow_map.get(&flow_tag) {
                                Some(flow_state) => flow_state,
                                None => return,
                            };
                            let mut flow_state = flow_state_mu.write().await;
                            if flow_state.get_connected().is_some() {
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
                                flow_state.flow_label.clone(),
                                flow_state.send_queue.get_reader(),
                                ConnectionRole::Server,
                                peer_addr,
                                tls_stream,
                                event_handler.clone(),
                                arc_self.data_plane_metrics.clone(),
                                arc_self.weak_self.read().unwrap().clone(),
                                arc_self.rt_handle.clone(),
                            );

                            event_handler
                                // Notify the client that peer flow is up.
                                .call(TransportEvent::StateChange(
                                    TransportStateChange::PeerFlowUp(peer_id),
                                ))
                                .await
                                .expect("Can't panic on infallible");
                            flow_state.update(ConnectionState::Connected(connected_state));
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
                        let peer_state = match peer_map.get(&peer_id) {
                            Some(peer_state) => peer_state,
                            None => continue,
                        };
                        let flow_state_mu = match peer_state.flow_map.get(&flow_tag) {
                            Some(flow_state) => flow_state,
                            None => continue,
                        };
                        let mut flow_state = flow_state_mu.write().await;
                        if flow_state.get_connected().is_some() {
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
                            flow_state.flow_label.clone(),
                            flow_state.send_queue.get_reader(),
                            ConnectionRole::Client,
                            peer_addr,
                            tls_stream,
                            event_handler.clone(),
                            arc_self.data_plane_metrics.clone(),
                            arc_self.weak_self.read().unwrap().clone(),
                            arc_self.rt_handle.clone(),

                        );
                        event_handler
                            // Notify the client that peer flow is up.
                            .call(TransportEvent::StateChange(
                                TransportStateChange::PeerFlowUp(peer_id),
                            ))
                            .await
                            .expect("Can't panic on infallible");
                        flow_state.update(ConnectionState::Connected(connected_state));
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
        let peer_state = match peer_map.get(&peer_id) {
            Some(peer_state) => peer_state,
            None => return,
        };
        let flow_state_mu = match peer_state.flow_map.get(&flow_tag) {
            Some(flow_state) => flow_state,
            None => return,
        };
        let mut flow_state = flow_state_mu.write().await;
        let connected = match flow_state.get_connected() {
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
            .call(TransportEvent::StateChange(
                TransportStateChange::PeerFlowDown(peer_id),
            ))
            .await
            .expect("Can't panic on infallible");
        flow_state.update(connection_state);
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
        let mut listeners = Vec::new();

        let server_addr = SocketAddr::new(self.node_ip, self.config.listening_port);
        listeners.push((
            self.config.legacy_flow_tag,
            self.config.listening_port,
            start_listener(server_addr).unwrap_or_else(|err| {
                panic!(
                    "Failed to init listener: local_addr = {:?}, error = {:?}",
                    server_addr, err
                )
            }),
        ));

        let mut accept_ports = HashMap::new();
        for (config_flow_tag, _, tcp_listener) in listeners {
            let flow_tag = FlowTag::from(config_flow_tag);
            let accept_task = self.spawn_accept_task(flow_tag, tcp_listener);
            accept_ports.insert(flow_tag, ServerPortState { accept_task });
        }
        *self.accept_ports.blocking_lock() = accept_ports;
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
    use async_trait::async_trait;
    use ic_base_types::{NodeId, RegistryVersion};
    use ic_config::transport::TransportConfig;
    use ic_crypto::utils::TempCryptoComponent;
    use ic_interfaces_transport::{TransportEvent, TransportStateChange};
    use ic_metrics::MetricsRegistry;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::make_crypto_tls_cert_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types_test_utils::ids::{NODE_1, NODE_2};
    use std::convert::Infallible;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::sync::mpsc::{channel, Sender};
    use tower::{util::BoxCloneService, Service};

    const NODE_ID_1: NodeId = NODE_1;
    const NODE_ID_2: NodeId = NODE_2;
    const REG_V1: RegistryVersion = RegistryVersion::new(1);
    const FLOW_TAG_1: u32 = 1234;
    const FLOW_TAG_2: u32 = 1235;

    const PORT_1: u16 = 65001;
    const PORT_2: u16 = 65002;

    #[derive(Clone)]
    struct FakeEventHandler {
        connected: Sender<bool>,
    }

    #[async_trait]
    impl Service<TransportEvent> for FakeEventHandler {
        type Response = ();
        type Error = Infallible;
        #[allow(clippy::type_complexity)]
        type Future =
            Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, event: TransportEvent) -> Self::Future {
            if let TransportEvent::StateChange(TransportStateChange::PeerFlowUp(_)) = event {
                self.connected.try_send(true).unwrap()
            }
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn test_start_connection_between_two_peers() {
        with_test_replica_logger(|logger| {
            let registry_version = REG_V1;
            // Setup registry and crypto component
            let registry_and_data = RegistryAndDataProvider::new();
            let crypto_1 =
                temp_crypto_component_with_tls_keys_in_registry(&registry_and_data, NODE_ID_1);
            let crypto_2 =
                temp_crypto_component_with_tls_keys_in_registry(&registry_and_data, NODE_ID_2);
            registry_and_data.registry.update_to_latest_version();
            let rt = tokio::runtime::Runtime::new().unwrap();

            let client_config_1 = TransportConfig {
                node_ip: "0.0.0.0".to_string(),
                legacy_flow_tag: FLOW_TAG_1,
                listening_port: PORT_1,
                send_queue_size: 10,
            };
            let control_plane_1 = create_transport(
                NODE_ID_1,
                client_config_1,
                registry_version,
                MetricsRegistry::new(),
                Arc::new(crypto_1),
                rt.handle().clone(),
                logger.clone(),
            );

            let client_config_2 = TransportConfig {
                node_ip: "0.0.0.0".to_string(),
                legacy_flow_tag: FLOW_TAG_2,
                listening_port: PORT_2,
                send_queue_size: 10,
            };
            let control_plane_2 = create_transport(
                NODE_ID_2,
                client_config_2,
                registry_version,
                MetricsRegistry::new(),
                Arc::new(crypto_2),
                rt.handle().clone(),
                logger,
            );

            let (connected_1, mut done_1) = channel(1);
            let fake_event_handler_1 = BoxCloneService::new(FakeEventHandler {
                connected: connected_1,
            });
            control_plane_1.set_event_handler(fake_event_handler_1);
            let peer_2_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", PORT_2)).unwrap();
            assert!(control_plane_1
                .start_connection(&NODE_ID_2, peer_2_addr, REG_V1)
                .is_ok());
            let (connected_2, mut done_2) = channel(1);
            let fake_event_handler_2 = BoxCloneService::new(FakeEventHandler {
                connected: connected_2,
            });
            control_plane_2.set_event_handler(fake_event_handler_2);
            let peer_1_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", PORT_1)).unwrap();
            assert!(control_plane_2
                .start_connection(&NODE_ID_1, peer_1_addr, REG_V1)
                .is_ok());
            assert_eq!(done_1.blocking_recv(), Some(true));
            assert_eq!(done_2.blocking_recv(), Some(true));
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
}
