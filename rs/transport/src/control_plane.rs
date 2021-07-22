//! Control plane - Transport connection management.
//!
//! The control plane handles tokio/TLS related details of connection
//! management.  This component establishes/accepts connections
//! to/from subnet peers. The component also manages re-establishment
//! of severed connections.
//!
//! The control plane module implements control plane functionality for
//! [`TransportImpl`](../types/struct.TransportImpl.html).

use crate::types::{
    ClientState, Connecting, ConnectionRole, ConnectionState, FlowState, PeerState, QueueSize,
    ServerPort, ServerPortState, TransportImpl,
};
use crate::utils::{get_flow_ips, get_flow_label, SendQueueImpl};
use futures::future::{AbortHandle, Abortable, Aborted};
use ic_crypto_tls_interfaces::{AllowedClients, AuthenticatedPeer, TlsReadHalf, TlsWriteHalf};
use ic_interfaces::transport::AsyncTransportEventHandler;
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_types::{
    transport::{FlowId, FlowTag, TransportClientType, TransportErrorCode},
    NodeId, RegistryVersion,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::sleep;

/// Time to wait before retrying an unsuccessful connection attempt
const CONNECT_RETRY_SECONDS: u64 = 3;

/// Time to wait for the TLS handshake (for both client/server sides)
const TLS_HANDSHAKE_TIMEOUT_SECONDS: u64 = 30;

/// Connection status values
#[derive(Debug)]
enum ConnectStatus {
    Success(TcpStream),
    ServerDown,
    Error(nix::errno::Errno),
}

/// Implementation for the transport control plane
impl TransportImpl {
    /// Starts connection to a peer
    pub fn start_peer_connections(
        &self,
        peer_id: &NodeId,
        peer_record: &NodeRecord,
        client_type: TransportClientType,
        registry_version: RegistryVersion,
    ) -> Result<(), TransportErrorCode> {
        let mut client_map = self.client_map.write().unwrap();
        let client_state = client_map
            .get_mut(&client_type)
            .ok_or(TransportErrorCode::TransportClientNotFound)?;
        let role = Self::connection_role(&self.node_id, &peer_id);
        // If we are the server, we should add the peer to the allowed_clients.
        if role == ConnectionRole::Server {
            self.allowed_clients.write().unwrap().insert(*peer_id);
        }
        *self.registry_version.write().unwrap() = registry_version;
        info!(
            self.log,
            "ControlPlane::start_peer_connections(): client_type = {:?}, node_id = {:?} peer_id = {:?}",
            client_type,
            self.node_id,
            peer_id
        );
        self.start_peer(client_type, peer_id, peer_record, client_state, role)
    }

    /// Stops connection to a peer
    pub fn stop_peer_connections(
        &self,
        client_type: TransportClientType,
        peer_id: &NodeId,
        registry_version: RegistryVersion,
    ) -> Result<(), TransportErrorCode> {
        self.allowed_clients.write().unwrap().remove(peer_id);
        *self.registry_version.write().unwrap() = registry_version;
        let mut client_map = self.client_map.write().unwrap();
        let client_state = client_map
            .get_mut(&client_type)
            .ok_or(TransportErrorCode::TransportClientNotFound)?;
        let peer_state = client_state
            .peer_map
            .get(&peer_id)
            .ok_or(TransportErrorCode::PeerNotFound)?;

        // Remove flow from metrics.
        for flow_state in peer_state.flow_map.values() {
            if self
                .control_plane_metrics
                .flow_state
                .remove_label_values(&[&flow_state.flow_label, &flow_state.flow_tag_label])
                .is_err()
            {
                warn!(
                    self.log,
                    "ControlPlane::stop_peer_connections(): Could not remove flow metric {:?}",
                    flow_state.flow_label
                )
            }
        }
        client_state.peer_map.remove(&peer_id);

        info!(
            self.log,
            "ControlPlane::stop_peer_connections(): client_type = {:?}, peer_id = {:?}",
            client_type,
            peer_id
        );
        Ok(())
    }

    /// Starts all connections to a peer and initializes the corresponding data
    /// structures and tasks
    fn start_peer(
        &self,
        client_type: TransportClientType,
        peer_id: &NodeId,
        peer_record: &NodeRecord,
        client_state: &mut ClientState,
        role: ConnectionRole,
    ) -> Result<(), TransportErrorCode> {
        if client_state.peer_map.get(&peer_id).is_some() {
            return Err(TransportErrorCode::PeerAlreadyRegistered);
        }

        let mut peer_state = PeerState {
            flow_map: HashMap::new(),
        };

        // TODO: P2P-514
        let mut queue_size_map = HashMap::new();
        let flow_ips = get_flow_ips(peer_record)?;
        for flow_config in &self.config.p2p_flows {
            let flow_tag = FlowTag::from(flow_config.flow_tag);
            queue_size_map.insert(flow_tag, QueueSize::from(flow_config.queue_size));
            if role == ConnectionRole::Server {
                let peer_ip = flow_ips
                    .get(&flow_tag)
                    .map_or("Unknown Peer IP".to_string(), |x| x.to_string());
                let flow_label = get_flow_label(&peer_ip, peer_id);
                let flow_id = FlowId {
                    client_type,
                    peer_id: *peer_id,
                    flow_tag,
                };
                let flow_state = FlowState::new(
                    flow_id,
                    flow_config.flow_tag.to_string(),
                    flow_label.clone(),
                    ConnectionState::Listening,
                    Box::new(SendQueueImpl::new(
                        flow_label,
                        &flow_tag,
                        QueueSize::from(flow_config.queue_size),
                        self.send_queue_metrics.clone(),
                    )),
                    self.control_plane_metrics.clone(),
                );
                peer_state.flow_map.insert(flow_tag, flow_state);
            }
        }
        if role == ConnectionRole::Server {
            client_state.peer_map.insert(*peer_id, peer_state);
            return Ok(());
        }

        for flow_endpoint in &peer_record.p2p_flow_endpoints {
            let endpoint = match &flow_endpoint.endpoint {
                Some(x) => x,
                None => {
                    warn!(
                        self.log,
                        "ControlPlane::start_peer(): missing endpoint flow = {:?}",
                        flow_endpoint.flow_tag
                    );
                    continue;
                }
            };

            let flow_tag = FlowTag::from(flow_endpoint.flow_tag);
            let queue_size = match queue_size_map.get(&flow_tag) {
                Some(queue_size) => queue_size,
                None => {
                    error!(
                        self.log,
                        "ControlPlane::start_peer(): TransportConfig NodeRecord mismatch = {:?}",
                        flow_endpoint.flow_tag
                    );
                    continue;
                }
            };

            let peer_ip = IpAddr::from_str(endpoint.ip_addr.as_str())
                .unwrap_or_else(|_| panic!("Invalid node IP: {}", endpoint.ip_addr));
            let flow_label = get_flow_label(&endpoint.ip_addr.as_str(), peer_id);
            let server_port = endpoint.port as u16;
            let connecting_task = self.spawn_connect_task(
                client_type,
                flow_endpoint.flow_tag.into(),
                *peer_id,
                peer_ip,
                ServerPort::from(server_port),
            );
            let connecting_state = Connecting {
                peer_addr: SocketAddr::new(peer_ip, server_port),
                connecting_task,
            };
            let flow_id = FlowId {
                client_type,
                peer_id: *peer_id,
                flow_tag,
            };
            let flow_state = FlowState::new(
                flow_id,
                flow_endpoint.flow_tag.to_string(),
                flow_label.clone(),
                ConnectionState::Connecting(connecting_state),
                Box::new(SendQueueImpl::new(
                    flow_label.clone(),
                    &flow_tag,
                    *queue_size,
                    self.send_queue_metrics.clone(),
                )),
                self.control_plane_metrics.clone(),
            );
            peer_state
                .flow_map
                .insert(flow_endpoint.flow_tag.into(), flow_state);
        }

        client_state.peer_map.insert(*peer_id, peer_state);
        Ok(())
    }

    /// Starts the async task to accept the incoming TcpStreams in server mode.
    fn spawn_accept_task(
        &self,
        client_type: TransportClientType,
        flow_tag: FlowTag,
        tcp_listener: TcpListener,
    ) -> AbortHandle {
        let weak_self = self.weak_self.read().unwrap().clone();
        let tokio_runtime = self.tokio_runtime.clone();
        let metrics = self.control_plane_metrics.clone();
        let accept_task = async move {
            let local_addr = match tcp_listener.local_addr() {
                Ok(addr) => addr,
                _ => return,
            };
            loop {
                // If the TransportImpl has been deleted, abort.
                let arc_self = match weak_self.upgrade() {
                    Some(arc_self) => arc_self,
                    _ => return,
                };
                match tcp_listener.accept().await {
                    Ok((stream, _)) => {
                        let metrics = metrics.clone();
                        metrics
                            .tcp_accepts
                            .with_label_values(&[&flow_tag.to_string()])
                            .inc();
                        tokio_runtime.spawn(async move {
                            // Errors are reported in set_sockopts
                            let stream = match Self::set_send_sockopts(stream, &arc_self.log) {
                                Ok(stream) => stream,
                                Err(_) => return,
                            };
                            // Errors are reported in tls_server_handshake
                            if let Ok(()) = arc_self
                                .tls_server_handshake(client_type, flow_tag, stream)
                                .await
                            {
                                metrics
                                    .tcp_accept_conn_success
                                    .with_label_values(&[&flow_tag.to_string()])
                                    .inc();
                            }
                        });
                    }
                    Err(e) => {
                        metrics
                            .tcp_accept_conn_err
                            .with_label_values(&[&flow_tag.to_string()])
                            .inc();
                        warn!(
                            arc_self.log,
                            "ControlPlane::accept(): local_addr = {:?} flow = {:?}, err = {:?}",
                            local_addr,
                            flow_tag,
                            e,
                        );
                    }
                }
            }
        };

        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let log_cl = self.log.clone();
        self.tokio_runtime.spawn(async move {
            if let Err(Aborted) = Abortable::new(accept_task, abort_registration).await {
                warn!(log_cl, "ControlPlane: accept task aborted");
            }
        });
        abort_handle
    }

    /// Spawn a task that tries to connect to a peer (forever, or until
    /// connection is established or peer is removed)
    #[allow(clippy::too_many_arguments)]
    fn spawn_connect_task(
        &self,
        client_type: TransportClientType,
        flow_tag: FlowTag,
        peer_id: NodeId,
        peer_ip: IpAddr,
        server_port: ServerPort,
    ) -> AbortHandle {
        let node_ip = self.node_ip;
        let weak_self = self.weak_self.read().unwrap().clone();
        let metrics = self.control_plane_metrics.clone();
        let connect_task = async move {
            let local_addr = SocketAddr::new(node_ip, 0);
            let peer_addr = SocketAddr::new(peer_ip, server_port.get());

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
                metrics
                    .tcp_connects
                    .with_label_values(&[&peer_id.to_string(), &flow_tag.to_string()])
                    .inc();
                match Self::connect_to_server(&local_addr, &peer_addr, &arc_self.log).await {
                    Ok(stream) => {
                        match arc_self
                            .tls_client_handshake(peer_id, client_type, flow_tag, stream)
                            .await
                        {
                            Ok(()) => {
                                metrics
                                    .tcp_conn_to_server_success
                                    .with_label_values(&[
                                        &peer_id.to_string(),
                                        &flow_tag.to_string(),
                                    ])
                                    .inc();
                                info!(
                                    arc_self.log,
                                    "ControlPlane::connect_to_server(): Successful TLS handshake. local_addr = {:?} peer = {:?}/{:?}, \
                                    flow = {:?}, retries = {}",
                                    local_addr,
                                    peer_id,
                                    peer_addr,
                                    flow_tag,
                                    retries,
                                );
                                return;
                            }
                            Err(e) => {
                                metrics
                                    .tcp_conn_to_server_err
                                    .with_label_values(&[
                                        &peer_id.to_string(),
                                        &flow_tag.to_string(),
                                    ])
                                    .inc();
                                info!(
                                    every_n_seconds => 300,
                                    arc_self.log,
                                    "ControlPlane::connect_to_server(): TLS handshake failed. local_addr = {:?} peer = {:?}/{:?}, \
                                    flow = {:?}, err = {:?}, retries = {}",
                                    local_addr,
                                    peer_id,
                                    peer_addr,
                                    flow_tag,
                                    e,
                                    retries
                                );
                                sleep(Duration::from_secs(CONNECT_RETRY_SECONDS)).await;
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        metrics
                            .tcp_conn_to_server_err
                            .with_label_values(&[&peer_id.to_string(), &flow_tag.to_string()])
                            .inc();
                        warn!(
                            arc_self.log,
                            "ControlPlane::connect_to_server(): local_addr = {:?} peer = {:?}/{:?}, \
                             flow = {:?}, err = {:?}, retries = {}",
                            local_addr,
                            peer_id,
                            peer_addr,
                            flow_tag,
                            e,
                            retries,
                        );
                        sleep(Duration::from_secs(CONNECT_RETRY_SECONDS)).await;
                    }
                }
            }
        };

        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let log_cl = self.log.clone();
        self.tokio_runtime.spawn(async move {
            if let Err(Aborted) = Abortable::new(connect_task, abort_registration).await {
                warn!(log_cl, "ControlPlane: connect task aborted");
            }
        });
        abort_handle
    }

    /// Handles the handshake completion during connection establishment (both
    /// server/client sides). Does the validation, sets up the connection state
    /// and spawns the read task for the connection.
    #[allow(clippy::too_many_arguments)]
    async fn process_handshake_result(
        &self,
        peer_id: NodeId,
        role: ConnectionRole,
        client_type: TransportClientType,
        flow_tag: FlowTag,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        tls_reader: TlsReadHalf,
        tls_writer: TlsWriteHalf,
    ) -> Result<(), TransportErrorCode> {
        // Pass the established connection to the data plane to start IOs.
        let flow_id = FlowId {
            client_type,
            peer_id,
            flow_tag,
        };
        self.on_connect(
            flow_id,
            role,
            peer_addr,
            Box::new(tls_reader),
            Box::new(tls_writer),
        )
        .await
        .map_err(|e| {
            warn!(
                every_n_seconds => 30,
                self.log,
                "ControlPlane::handshake_result(): failed to add flow: \
                 node_id = {:?}, local_addr = {:?}, peer_addr = {:?}, role = {:?}, \
                 flow = {:?}, error = {:?}",
                self.node_id,
                local_addr,
                peer_addr,
                Self::connection_role(&self.node_id, &peer_id),
                flow_tag,
                e
            );
            e
        })
    }

    /// Retries to establish a connection
    pub fn retry_connection(&self, flow_id: &FlowId) -> Result<(), TransportErrorCode> {
        warn!(
            self.log,
            "ControlPlane::retry_connection(): node_id = {:?}, flow = {:?}", self.node_id, flow_id,
        );
        self.control_plane_metrics
            .retry_connection
            .with_label_values(&[&flow_id.peer_id.to_string(), &flow_id.flow_tag.to_string()])
            .inc();

        let socket_addr: SocketAddr;
        {
            // Don't hold the lock across await points
            let mut client_map = self.client_map.write().unwrap();
            let client_state = client_map
                .get_mut(&flow_id.client_type)
                .ok_or(TransportErrorCode::TransportClientNotFound)?;
            let peer_state = client_state
                .peer_map
                .get_mut(&flow_id.peer_id)
                .ok_or(TransportErrorCode::PeerNotFound)?;
            let flow_state = peer_state
                .flow_map
                .get_mut(&flow_id.flow_tag)
                .ok_or(TransportErrorCode::FlowNotFound)?;

            if Self::connection_role(&self.node_id, &flow_id.peer_id) == ConnectionRole::Server {
                // We are the server, wait for the peer to connect
                flow_state.update(ConnectionState::Listening);
                warn!(
                    self.log,
                    "ControlPlane::process_disconnect(): node_id = {:?}, flow = {:?}, \
                        waiting for peer to reconnect",
                    self.node_id,
                    flow_id,
                );
                return Ok(());
            }

            // reconnect if we have a listener
            if let ConnectionState::Connected(sa) = &flow_state.connection_state {
                if client_state.accept_ports.contains_key(&flow_id.flow_tag) {
                    socket_addr = sa.peer_addr;
                    let connecting_task = self.spawn_connect_task(
                        flow_id.client_type,
                        flow_id.flow_tag,
                        flow_id.peer_id,
                        socket_addr.ip(),
                        ServerPort::from(socket_addr.port()),
                    );
                    let connecting_state = Connecting {
                        peer_addr: socket_addr,
                        connecting_task,
                    };
                    flow_state.update(ConnectionState::Connecting(connecting_state));

                    warn!(
                        self.log,
                        "ControlPlane::process_disconnect(): spawning reconnect task: node_id = {:?}, \
                        flow = {:?}, local_addr = {:?}, peer_addr = {:?}, peer_port = {:?}",
                        self.node_id,
                        flow_id,
                        self.node_ip,
                        socket_addr.ip(),
                        socket_addr.port(),
                    );
                }
            }
        }

        Ok(())
    }

    /// Set up the client socket, and connect to the specified server peer
    async fn connect_to_server(
        local_addr: &SocketAddr,
        peer_addr: &SocketAddr,
        log: &ReplicaLogger,
    ) -> Result<TcpStream, TransportErrorCode> {
        let client_socket = Self::init_client_socket(local_addr, log)?;
        match Self::connect_status(client_socket.connect(*peer_addr).await) {
            ConnectStatus::Success(stream) => Self::set_send_sockopts(stream, log),
            ConnectStatus::ServerDown => Err(TransportErrorCode::ServerDown),
            ConnectStatus::Error(err_code) => {
                warn!(
                    log,
                    "ControlPlane::connect_to_server(): local_addr = {:?} peer_addr = {:?}, error {:?}",
                    local_addr,
                    peer_addr,
                    err_code,
                );
                Err(TransportErrorCode::ConnectOsError)
            }
        }
    }

    /// Set socket options on a socket
    fn set_send_sockopts(
        stream: TcpStream,
        log: &ReplicaLogger,
    ) -> Result<TcpStream, TransportErrorCode> {
        if let Err(e) = stream.set_nodelay(true) {
            warn!(
                log,
                "ControlPlane::set_send_sockopts(): set_nodelay() failed: \
                 local_addr = {:?}, peer_addr = {:?}, err = {:?}",
                stream
                    .local_addr()
                    .map_err(|e| format!("Unknown IP: {:?}", e)),
                stream
                    .peer_addr()
                    .map_err(|e| format!("Unknown IP: {:?}", e)),
                e,
            );
            Err(TransportErrorCode::SocketNoDelayFailed)
        } else {
            Ok(stream)
        }
    }

    /// Performs the server side TLS hand shake processing
    async fn tls_server_handshake(
        &self,
        client_type: TransportClientType,
        flow_tag: FlowTag,
        stream: TcpStream,
    ) -> Result<(), TransportErrorCode> {
        let local_addr = Self::sock_addr(stream.local_addr())?;
        let peer_addr = Self::sock_addr(stream.peer_addr())?;
        let allowed_clients = {
            let allowed_clients = self.allowed_clients.read().unwrap().clone();
            match AllowedClients::new_with_nodes(allowed_clients) {
                Err(e) => {
                    self.control_plane_metrics
                        .tcp_server_handshake_failed
                        .with_label_values(&[&flow_tag.to_string()])
                        .inc();
                    warn!(
                        every_n_seconds => 30,
                        self.log,
                        "ControlPlane::tls_server_handshake() no allowed clients: failed local_addr = {:?} node_id = {:?}, peer_addr = {:?}, error = {:?}",
                     local_addr,
                     self.node_id,
                     peer_addr,
                     e);
                    return Err(TransportErrorCode::PeerTlsInfoNotFound);
                }
                Ok(allowed_clients) => allowed_clients,
            }
        };
        let registry_version = *self.registry_version.read().unwrap();
        let ret = tokio::time::timeout(
            Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECONDS),
            self.crypto
                .perform_tls_server_handshake(stream, allowed_clients, registry_version),
        )
        .await;
        if ret.is_err() {
            self.control_plane_metrics
                .tcp_server_handshake_failed
                .with_label_values(&[&flow_tag.to_string()])
                .inc();
            warn!(
                every_n_seconds => 30,
                self.log,
                    "ControlPlane::tls_server_handshake() timed out: \
                      local_addr = {:?}, node_id = {:?}, peer_addr = {:?}",
                     local_addr,
                     self.node_id,
                     peer_addr);
            return Err(TransportErrorCode::TimeoutExpired);
        }

        let (tls_stream, authenticated_peer) = match ret.unwrap() {
            Ok((tls_stream, peer_id)) => (tls_stream.split(), peer_id),
            Err(e) => {
                self.control_plane_metrics
                    .tcp_server_handshake_failed
                    .with_label_values(&[&flow_tag.to_string()])
                    .inc();
                warn!(
                    every_n_seconds => 30,
                    self.log,
                    "ControlPlane::tls_server_handshake(): failed local_addr = {:?} \
                     node_id = {:?}, peer_addr = {:?}, error = {:?}",
                    local_addr,
                    self.node_id,
                    peer_addr,
                    e
                );
                return Err(TransportErrorCode::PeerTlsInfoNotFound);
            }
        };
        let (tls_reader, tls_writer) = tls_stream;
        let peer_id = match authenticated_peer {
            AuthenticatedPeer::Node(node_id) => node_id,
            AuthenticatedPeer::Cert(_) => {
                warn!(
                    every_n_seconds => 10,
                    self.log,
                    "ControlPlane::tls_server_handshake(): failed local_addr = {:?} \
                        node_id = {:?}, peer_addr = {:?}, error = cert instead of node id",
                    local_addr,
                    self.node_id,
                    peer_addr
                );
                return Err(TransportErrorCode::PeerTlsInfoNotFound);
            }
        };
        self.process_handshake_result(
            peer_id,
            ConnectionRole::Server,
            client_type,
            flow_tag,
            local_addr,
            peer_addr,
            tls_reader,
            tls_writer,
        )
        .await
        .map(|_| {
            self.control_plane_metrics
                .tcp_server_handshake_success
                .with_label_values(&[&flow_tag.to_string()])
                .inc()
        })
    }

    /// Performs the client side TLS hand shake processing
    async fn tls_client_handshake(
        &self,
        peer_id: NodeId,
        client_type: TransportClientType,
        flow_tag: FlowTag,
        stream: TcpStream,
    ) -> Result<(), TransportErrorCode> {
        let registry_version = *self.registry_version.read().unwrap();
        let local_addr = Self::sock_addr(stream.local_addr())?;
        let peer_addr = Self::sock_addr(stream.peer_addr())?;

        let ret = tokio::time::timeout(
            Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECONDS),
            self.crypto
                .perform_tls_client_handshake(stream, peer_id, registry_version),
        )
        .await;
        if ret.is_err() {
            warn!(
                every_n_seconds => 30,
                self.log,
                "ControlPlane::tls_client_handshake(): timed out \
                 node_id = {:?} local_addr = {:?} peer_addr = {:?}, flow = {:?}",
                self.node_id,
                local_addr,
                peer_addr,
                flow_tag
            );
            return Err(TransportErrorCode::TimeoutExpired);
        }

        let (tls_reader, tls_writer) = ret.unwrap().map(|tls_stream| tls_stream.split()).map_err(
            |e| {
                self.control_plane_metrics
                    .tcp_client_handshake_failed
                    .with_label_values(&[&flow_tag.to_string()])
                    .inc();
                warn!(
                    every_n_seconds => 30,
                    self.log,
                    "ControlPlane::tls_client_handshake(): failed \
                     node_id = {:?} local_addr = {:?} peer_addr = {:?}, flow = {:?} error = {:?}",
                    self.node_id,
                    local_addr,
                    peer_addr,
                    flow_tag,
                    e
                );
                TransportErrorCode::PeerTlsInfoNotFound
            },
        )?;

        self.process_handshake_result(
            peer_id,
            ConnectionRole::Client,
            client_type,
            flow_tag,
            local_addr,
            peer_addr,
            tls_reader,
            tls_writer,
        )
        .await
        .map(|_| {
            self.control_plane_metrics
                .tcp_client_handshake_success
                .with_label_values(&[&flow_tag.to_string()])
                .inc()
        })
    }

    // Sets up the server side socket with the node IP:port
    fn init_listener(&self, local_addr: &SocketAddr) -> Result<TcpListener, TransportErrorCode> {
        let socket = if local_addr.is_ipv6() {
            TcpSocket::new_v6()
        } else {
            TcpSocket::new_v4()
        };
        let socket = match socket {
            Ok(socket) => socket,
            Err(e) => {
                warn!(
                    every_n_seconds => 30,
                    self.log,
                    "ControlPlane::listen(): Failed to create socket: local_addr = {:?} {:?}",
                    local_addr,
                    e
                );
                return Err(TransportErrorCode::ServerSocketCreateFailed);
            }
        };

        // TODO: set reuse flags only for tests if needed
        if socket.set_reuseaddr(true).is_err() {
            return Err(TransportErrorCode::ServerSocketAddrReuseFailed);
        }

        if socket.set_reuseport(true).is_err() {
            return Err(TransportErrorCode::ServerSocketPortReuseFailed);
        }

        if let Err(e) = socket.bind(*local_addr) {
            warn!(
                every_n_seconds => 30,
                self.log,
                "ControlPlane::listen(): Failed to bind: local_addr = {:?} {:?}", local_addr, e
            );
            return Err(TransportErrorCode::ServerSocketBindFailed);
        }

        match socket.listen(128) {
            Ok(listener) => Ok(listener),
            Err(e) => {
                warn!(
                    self.log,
                    "ControlPlane::listen(): Failed to listen: local_addr = {:?} {:?}",
                    local_addr,
                    e
                );
                Err(TransportErrorCode::ServerSocketListenFailed)
            }
        }
    }

    /// Sets up the client side socket with the node IP address
    fn init_client_socket(
        local_addr: &SocketAddr,
        log: &ReplicaLogger,
    ) -> Result<TcpSocket, TransportErrorCode> {
        let socket = if local_addr.is_ipv6() {
            TcpSocket::new_v6()
        } else {
            TcpSocket::new_v4()
        };
        let socket = match socket {
            Ok(socket) => socket,
            Err(e) => {
                warn!(
                    every_n_seconds => 30,
                    log,
                    "ControlPlane::connect(): Failed to create socket: local_addr = {:?} {:?}",
                    local_addr,
                    e
                );
                return Err(TransportErrorCode::ClientSocketCreateFailed);
            }
        };
        match socket.bind(*local_addr) {
            Ok(()) => Ok(socket),
            Err(e) => {
                warn!(
                    every_n_seconds => 30,
                    log,
                    "ControlPlane::connect(): Failed to bind(): local_addr = {:?} {:?}",
                    local_addr,
                    e
                );
                Err(TransportErrorCode::ClientSocketBindFailed)
            }
        }
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

    /// Parses the `connect()` result and returns the status
    fn connect_status(connect_result: std::io::Result<TcpStream>) -> ConnectStatus {
        if let Ok(stream) = connect_result {
            return ConnectStatus::Success(stream);
        }
        match connect_result.as_ref().err().unwrap().raw_os_error() {
            Some(err_code) => match nix::errno::from_i32(err_code) {
                nix::errno::Errno::ECONNREFUSED => ConnectStatus::ServerDown,
                nix::errno::Errno::EHOSTUNREACH => ConnectStatus::ServerDown,
                _ => ConnectStatus::Error(nix::errno::from_i32(err_code)),
            },
            _ => ConnectStatus::Error(nix::errno::Errno::EINTR),
        }
    }

    /// Extract the socket address from the result
    fn sock_addr(result: std::io::Result<SocketAddr>) -> Result<SocketAddr, TransportErrorCode> {
        result.map_err(|_| TransportErrorCode::InvalidSockAddr)
    }

    /// Initilizes a client
    pub fn init_client(
        &self,
        client_type: TransportClientType,
        event_handler: Arc<dyn AsyncTransportEventHandler>,
    ) -> Result<(), TransportErrorCode> {
        let mut client_map = self.client_map.write().unwrap();
        if client_map.contains_key(&client_type) {
            return Err(TransportErrorCode::TransportClientAlreadyRegistered);
        }

        // Bind to the server ports.
        let mut listeners = Vec::new();
        for flow_config in &self.config.p2p_flows {
            let server_addr = SocketAddr::new(self.node_ip, flow_config.server_port);
            listeners.push((
                flow_config.flow_tag,
                flow_config.server_port,
                self.init_listener(&server_addr)?,
            ));
        }

        let mut accept_ports = HashMap::new();
        for (config_flow_tag, config_server_port, tcp_listener) in listeners {
            let flow_tag = FlowTag::from(config_flow_tag);
            let accept_task = self.spawn_accept_task(client_type, flow_tag, tcp_listener);
            accept_ports.insert(
                flow_tag,
                ServerPortState {
                    port: ServerPort::from(config_server_port),
                    accept_task,
                },
            );
        }
        client_map.insert(
            client_type,
            ClientState {
                accept_ports,
                peer_map: HashMap::new(),
                event_handler,
            },
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::transport::create_transport;
    use async_trait::async_trait;
    use crossbeam_channel::{bounded, Sender};
    use ic_crypto::utils::TempCryptoComponent;
    use ic_interfaces::transport::{AsyncTransportEventHandler, SendError};
    use ic_logger::warn;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::node::v1::{
        connection_endpoint::Protocol, ConnectionEndpoint, FlowEndpoint, NodeRecord,
    };
    use ic_registry_client::fake::FakeRegistryClient;
    use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
    use ic_registry_keys::make_crypto_tls_cert_key;
    use ic_test_utilities::types::ids::{NODE_1, NODE_2};
    use ic_test_utilities::with_test_replica_logger;
    use ic_types::transport::TransportErrorCode;
    use ic_types::{
        transport::{
            FlowId, TransportClientType, TransportConfig, TransportFlowConfig, TransportPayload,
            TransportStateChange,
        },
        NodeId, RegistryVersion,
    };
    use std::sync::Arc;

    const NODE_ID_1: NodeId = NODE_1;
    const NODE_ID_2: NodeId = NODE_2;
    const REG_V1: RegistryVersion = RegistryVersion::new(1);
    const FLOW_TAG_1: u32 = 1234;
    const FLOW_TAG_2: u32 = 1235;

    const PORT_1: u16 = 65001;
    const PORT_2: u16 = 65002;

    struct FakeEventHandler {
        connected: Sender<bool>,
    }

    impl FakeEventHandler {
        fn on_message(
            &self,
            _flow: FlowId,
            _message: TransportPayload,
        ) -> Option<TransportPayload> {
            None
        }

        fn on_state_change(&self, state_change: TransportStateChange) {
            if let TransportStateChange::PeerFlowUp(_) = state_change {
                self.connected.send(true).unwrap();
            }
        }

        fn on_error(&self, _flow: FlowId, _error: TransportErrorCode) {}
    }

    #[async_trait]
    impl AsyncTransportEventHandler for FakeEventHandler {
        async fn send_message(
            &self,
            flow: FlowId,
            message: TransportPayload,
        ) -> Result<(), SendError> {
            self.on_message(flow, message);
            Ok(())
        }

        async fn state_changed(&self, state_change: TransportStateChange) {
            self.on_state_change(state_change);
        }

        async fn error(&self, flow: FlowId, error: TransportErrorCode) {
            self.on_error(flow, error);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn should_handshake() {
        let registry_version = REG_V1;
        let (connected_1, done_1) = bounded(0);
        let (connected_2, done_2) = bounded(0);
        with_test_replica_logger(|logger| {
            // Setup registry and crypto component
            let registry_and_data = empty_registry();
            let crypto_1 =
                temp_crypto_component_with_tls_keys_in_registry(&registry_and_data, NODE_ID_1);
            let crypto_2 =
                temp_crypto_component_with_tls_keys_in_registry(&registry_and_data, NODE_ID_2);
            registry_and_data.registry.update_to_latest_version();

            let mut client_config_1 = TransportConfig {
                node_ip: "0.0.0.0".to_string(),
                p2p_flows: Vec::new(),
            };
            let flow_internal_1 = TransportFlowConfig {
                flow_tag: FLOW_TAG_1,
                server_port: PORT_1,
                queue_size: 10,
            };
            client_config_1.p2p_flows.push(flow_internal_1);
            let control_plane_1 = create_transport(
                NODE_ID_1,
                client_config_1,
                registry_version,
                MetricsRegistry::new(),
                Arc::new(crypto_1),
                tokio::runtime::Handle::current(),
                logger.clone(),
            );

            let mut client_config_2 = TransportConfig {
                node_ip: "0.0.0.0".to_string(),
                p2p_flows: Vec::new(),
            };
            let flow_internal_2 = TransportFlowConfig {
                flow_tag: FLOW_TAG_2,
                server_port: PORT_2,
                queue_size: 10,
            };
            client_config_2.p2p_flows.push(flow_internal_2);
            let control_plane_2 = create_transport(
                NODE_ID_2,
                client_config_2,
                registry_version,
                MetricsRegistry::new(),
                Arc::new(crypto_2),
                tokio::runtime::Handle::current(),
                logger.clone(),
            );

            let fake_event_handler_1 = Arc::new(FakeEventHandler {
                connected: connected_1,
            });
            control_plane_1
                .register_client(TransportClientType::P2P, fake_event_handler_1)
                .expect("register_client");
            let mut node_record_1: NodeRecord = Default::default();
            node_record_1.p2p_flow_endpoints.push(FlowEndpoint {
                flow_tag: FLOW_TAG_1,
                endpoint: Some(ConnectionEndpoint {
                    ip_addr: "127.0.0.1".to_string(),
                    port: PORT_2 as u32,
                    protocol: Protocol::P2p1Tls13 as i32,
                }),
            });
            control_plane_1
                .start_connections(TransportClientType::P2P, &NODE_ID_2, &node_record_1, REG_V1)
                .expect("start_connections");

            let fake_event_handler_2 = Arc::new(FakeEventHandler {
                connected: connected_2,
            });
            control_plane_2
                .register_client(TransportClientType::P2P, fake_event_handler_2)
                .expect("register_client");
            let mut node_record_2: NodeRecord = Default::default();
            node_record_2.p2p_flow_endpoints.push(FlowEndpoint {
                flow_tag: FLOW_TAG_2,
                endpoint: Some(ConnectionEndpoint {
                    ip_addr: "127.0.0.1".to_string(),
                    port: PORT_1 as u32,
                    protocol: Protocol::P2p1Tls13 as i32,
                }),
            });
            control_plane_2
                .start_connections(TransportClientType::P2P, &NODE_ID_1, &node_record_2, REG_V1)
                .expect("start_connections");
            assert_eq!(done_1.recv(), Ok(true));
            assert_eq!(done_2.recv(), Ok(true));
            warn!(logger, "done");
        });
    }

    struct RegistryAndDataProvider {
        pub data_provider: Arc<ProtoRegistryDataProvider>,
        pub registry: Arc<FakeRegistryClient>,
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

    fn empty_registry() -> RegistryAndDataProvider {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));
        RegistryAndDataProvider {
            data_provider,
            registry,
        }
    }
}
