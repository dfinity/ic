//! Quic Transport connection manager.
//!
//! Responsible for managing the peer connections according to the subnet topology.
//! The active connections (PeerMap) are shared with the Transport object and
//! updated to newest connection by this component.
//!
//! Connection manager is an eventloop with the following events:
//!     - Periodic heartbeat. During which we collect metrics, adjust the toplogy
//!       and check for dead connection.
//!     - Accept incoming connections.
//!     - Process negotiated connections. If a connection setup successfully completes
//!       we add it to shared PeerMap.
//!
//! Authentication:
//!     - The endpoints tls configuration gets updated (periodically) to match
//!       the subnet topology. -> Only accept connections from peers in topology.
//!     - When dialing a peer TLS is configured to only accept a specific peer.
//!     - After the connection is established (with TLS) we do the SEV attestation
//!       handshake.
//!     - Since currently the attestation handshake is a noop we also do a small "gruezi"
//!       handshake to verify that the connection is active from both sides. This adds
//!       latency during the setup but we are not worried about this since connections are
//!       long lived in our case.
//!     - Only if all these steps successfully complete do we add the connection to the active set.
//!
//! Connection reconciliation:
//!     - Since transport guarantees eventual connectivity to peers in the topology
//!       it needs to repair broken connections.
//!     - Currently there is a periodic check that checks the status of the connection
//!       and reconnects if necessary.
use std::{collections::HashMap, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use axum::Router;
use either::Either;
use futures::StreamExt;
use ic_async_utils::JoinMap;
use ic_crypto_tls_interfaces::{
    AllowedClients, MalformedPeerCertificateError, SomeOrAllNodes, TlsConfig, TlsConfigError,
    TlsStream,
};
use ic_crypto_utils_tls::{
    node_id_from_cert_subject_common_name, tls_pubkey_cert_from_rustls_certs,
};
use ic_icos_sev_interfaces::ValidateAttestedStream;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_peer_manager::SubnetTopology;
use ic_types::{NodeId, RegistryVersion};
use quinn::{
    AsyncUdpSocket, ConnectError, Connecting, Connection, ConnectionError, Endpoint,
    EndpointConfig, RecvStream, SendStream, VarInt,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    runtime::Handle,
    select,
    sync::mpsc::{channel, Receiver},
    task::JoinSet,
};
use tokio_util::time::DelayQueue;

use crate::{metrics::QuicTransportMetrics, request_handler::start_request_handler};
use crate::{
    metrics::{CONNECTION_RESULT_FAILED_LABEL, CONNECTION_RESULT_SUCCESS_LABEL},
    ConnCmd, ConnectionHandle, MngCmd, QuicConnWithPeerId,
};

/// Interval of quic heartbeats. They are only sent if the connection is idle for more than 200ms.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_millis(200);
/// Timeout after which quic marks connections as broken. This timeout is used to detect connections
/// that were not explicitly closed. I.e replica crash
const IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_secs(3);
const GRUEZI_HANDSHAKE: &str = "gruezi";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Direction {
    Inbound,
    Outbound,
}

/// Connection manager is responsible for making sure that
/// there always exists a healthy connection to each peer
/// currently in the subnet topology.
struct ConnectionManager {
    log: ReplicaLogger,
    node_id: NodeId,
    rt: Handle,
    metrics: QuicTransportMetrics,

    /// Current topology
    topology: SubnetTopology,
    /// All outgoing connection requests should go through this queue.
    /// It is ok to add the same node multiple times here since we only dial
    /// if we don't have an outstanding dial.
    /// If we want to immediately connect add to this queue with Duration 0.
    connect_queue: DelayQueue<NodeId>,

    // Authentication
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
    sev_handshake: Arc<dyn ValidateAttestedStream<Box<dyn TlsStream>> + Send + Sync>,

    // Shared state
    watcher: tokio::sync::watch::Receiver<SubnetTopology>,
    peer_map: HashMap<NodeId, ConnectionHandle>,

    // Local state.
    /// Task joinmap that holds stores a connecting tasks keys by peer id.
    outbound_connecting: JoinMap<NodeId, Result<QuicConnWithPeerId, ConnectionEstablishError>>,
    /// Task joinset on which incoming connection requests are spawned. This is not a JoinMap
    /// because the peerId is not available until the TLS handshake succeeded.
    inbound_connecting: JoinSet<Result<QuicConnWithPeerId, ConnectionEstablishError>>,
    /// JoinMap that stores active connection handlers keyed by peer id.
    active_connections: JoinMap<NodeId, ()>,

    /// Endpoint config
    endpoint: Endpoint,
    transport_config: Arc<quinn::TransportConfig>,
    router: Router,
}

#[derive(Debug)]
enum ConnectionEstablishError {
    Timeout,
    SevAttestation(String),
    Gruezi(String),
    TlsClientConfigError {
        peer_id: NodeId,
        cause: TlsConfigError,
    },
    ConnectError {
        peer_id: NodeId,
        cause: ConnectError,
    },
    ConnectionError {
        peer_id: Option<NodeId>,
        cause: ConnectionError,
    },
    MissingPeerIdentity,
    MalformedPeerIdentity(MalformedPeerCertificateError),
    PeerIdMismatch {
        client: NodeId,
        server: NodeId,
    },
}

impl std::fmt::Display for ConnectionEstablishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "Timeout during connection establishment."),
            Self::SevAttestation(e) => write!(f, "Sev attestation handshake failed. {e}"),
            Self::Gruezi(e) => write!(f, "Gruezi handshake failed. {e}"),
            Self::TlsClientConfigError { peer_id, cause } => {
                write!(
                    f,
                    "Failed to get rustls client config for peer {peer_id}. {cause}"
                )
            }
            Self::ConnectError { peer_id, cause } => {
                write!(f, "Failed to connect to peer {peer_id}. {cause}")
            }
            Self::ConnectionError { peer_id, cause } => match peer_id {
                Some(peer_id) => write!(f, "Outgoing connection to peer {peer_id}. {cause}"),
                None => write!(f, "Incoming connection failed. {cause}"),
            },
            Self::MissingPeerIdentity => write!(f, "No peer identity available."),
            Self::MalformedPeerIdentity(MalformedPeerCertificateError { internal_error }) => {
                write!(f, "Malformed peer identity. {internal_error}")
            }
            Self::PeerIdMismatch { client, server } => {
                write!(f, "Received peer ids didn't match {client} and {server}.")
            }
        }
    }
}

pub(crate) fn start_connection_manager(
    log: &ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt: Handle,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    sev_handshake: Arc<dyn ValidateAttestedStream<Box<dyn TlsStream>> + Send + Sync>,
    node_id: NodeId,
    mng_rx: Receiver<MngCmd>,
    watcher: tokio::sync::watch::Receiver<SubnetTopology>,
    socket: Either<SocketAddr, impl AsyncUdpSocket>,
    router: Router,
) {
    let topology = watcher.borrow().clone();

    let metrics = QuicTransportMetrics::new(metrics_registry);
    // We use a random reset key here. The downside of this is that
    // during a crash and restart the peer will not recognize our
    // CONNECTION_RESETS.Not recognizing the reset might lead
    // the other side to keep sending data. To solve this we would
    // need to persist our reset key or derive it from the secret key.
    // In our case the other side will reset the connection after a few
    // seconds because we are not able to respond to keep-alives.
    // Maybe in the future we could derive a key from our tls key.
    let endpoint_config = EndpointConfig::default();
    // TODO: Restrict this to current subnet. What do if it fails?
    let rustls_server_config = tls_config
        .server_config(
            AllowedClients::new(ic_crypto_tls_interfaces::SomeOrAllNodes::All).unwrap(),
            registry_client.get_latest_version(),
        )
        .unwrap();

    let mut transport_config = quinn::TransportConfig::default();

    transport_config.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    transport_config.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().unwrap()));
    // defaults:
    // STREAM_RWN 1_250_000
    // stream_receive_window: STREAM_RWND.into(),
    // send_window: (8 * STREAM_RWND).into()
    transport_config.send_window(100_000_000);
    // Upper bound on receive memory consumption.
    transport_config.receive_window(VarInt::from_u32(200_000_000));
    transport_config.stream_receive_window(VarInt::from_u32(4_000_000));
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(1_000));
    transport_config.max_concurrent_uni_streams(VarInt::from_u32(1_000));
    let transport_config = Arc::new(transport_config);
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(rustls_server_config));
    server_config.transport_config(transport_config.clone());

    // Start endpoint
    let endpoint = match socket {
        Either::Left(addr) => {
            let socket2 = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
                .expect("Failed to create udp socket");

            // Set socket send/recv buffer size. Setting these explicitly makes sure that a
            // sufficently large value is used. Increasing these buffers can help with high packetloss.
            // The value of 25MB isch chosen from experiments and the BDP product shown below to support
            // around 2Gb/s.
            // Bandwidth-Delay Product
            // 2Gb/s * 100ms ~ 200M bits = 25MB
            socket2
                .set_recv_buffer_size(25_000_000)
                .expect("Failed to set receive buffer size");
            socket2
                .set_send_buffer_size(25_000_000)
                .expect("Failed to set send buffer size");
            socket2
                .bind(&SockAddr::from(addr))
                .expect("Failed to bind to UDP socket");

            let _enter_guard = rt.enter();
            Endpoint::new(
                endpoint_config,
                Some(server_config),
                socket2.into(),
                Arc::new(quinn::TokioRuntime),
            )
            .expect("Failed to create endpoint")
        }
        Either::Right(async_udp_socket) => Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            async_udp_socket,
            Arc::new(quinn::TokioRuntime),
        )
        .expect("Failed to create endpoint"),
    };

    let manager = ConnectionManager {
        log: log.clone(),
        rt: rt.clone(),
        tls_config,
        metrics,
        sev_handshake,
        node_id,
        topology,
        connect_queue: DelayQueue::new(),
        peer_map: HashMap::new(),
        watcher,
        endpoint,
        transport_config,
        outbound_connecting: JoinMap::new(),
        inbound_connecting: JoinSet::new(),
        active_connections: JoinMap::new(),
        router,
    };

    rt.spawn(manager.run(mng_rx));
}

impl ConnectionManager {
    pub async fn run(mut self, mut mng_rx: Receiver<MngCmd>) {
        loop {
            select! {
                Some(mng_cmd) = mng_rx.recv() => {
                    match mng_cmd {
                        MngCmd::Peers(peers_tx) => {
                            info!(self.log, "{:?}",self.peer_map.keys().cloned().collect::<Vec<_>>());

                            let _ = peers_tx.send(Ok(self.peer_map.keys().cloned().collect()));
                        }
                        MngCmd::ConnCmd((peer_id, conn_cmd)) => {
                            if let Some(conn_handle) = self.peer_map.get(&peer_id) {
                                let _ = match conn_cmd {
                                    ConnCmd::Push(req, push_tx) => conn_handle.0.send(ConnCmd::Push(req, push_tx)).await,
                                    ConnCmd::Rpc(req, rpc_tx) => conn_handle.0.send(ConnCmd::Rpc(req, rpc_tx)).await,
                                };
                            }
                        }
                    }
                }
                Some(reconnect) = self.connect_queue.next() => {
                    self.handle_dial(reconnect.into_inner())
                }
                topology = self.watcher.changed() => {
                    match topology {
                        Ok(_) => {
                            self.handle_topology_change().await;
                        },
                        Err(_) => {
                            error!(self.log, "Transport disconnected from peer manager. Shutting down.");
                            break
                        }
                    }
                },
                connecting = self.endpoint.accept() => {
                    if let Some(connecting) = connecting {
                        self.handle_inbound(connecting);
                    } else {
                        info!(self.log, "Quic endpoint closed. Stopping transport.");
                        // Endpoint is closed. This indicates a shutdown.
                        break;
                    }
                },
                Some(conn_res) = self.outbound_connecting.join_next() => {
                    match conn_res {
                        Ok((conn_out, peer_id)) => self.handle_connecting_result(conn_out, Some(peer_id)).await,
                        Err(err) => {
                            // Cancelling tasks is ok. Panicking tasks are not.
                            if err.is_panic() {
                                std::panic::resume_unwind(err.into_panic());
                            }
                        }
                    }
                },
                Some(conn_res) = self.inbound_connecting.join_next() => {
                    match conn_res {
                        Ok(conn_out) => self.handle_connecting_result(conn_out, None).await,
                        Err(err) => {
                            // Cancelling tasks is ok. Panicking tasks are not.
                            if err.is_panic() {
                                std::panic::resume_unwind(err.into_panic());
                            }
                        }
                    }
                },
                Some(active_result) = self.active_connections.join_next() => {
                    match active_result {
                        Ok((_, peer_id)) => self.handled_closed_conn(peer_id).await,
                        Err(err) => {
                            // Cancelling tasks is ok. Panicking tasks are not.
                            if err.is_panic() {
                                std::panic::resume_unwind(err.into_panic());
                            }
                        }
                    }
                },
            }
            // Collect metrics
            self.metrics
                .active_connections
                .set(self.active_connections.len() as i64);
            self.metrics
                .connecting_connections
                .set(self.inbound_connecting.len() as i64 + self.outbound_connecting.len() as i64);
            self.metrics
                .delay_queue_size
                .set(self.connect_queue.len() as i64);
        }
        // This point is reached only in two cases - replica gracefully shutting down or
        // bug which makes the peer manager unavaible.
        // If the peer manager is unavailable, the replica needs must exist that's why
        // the endpoint is closed proactively.
        self.endpoint.close(0u8.into(), b"shutting down");

        self.endpoint.wait_idle().await;
    }

    // Removes connection and sets peer status to disconnected
    async fn handled_closed_conn(&mut self, peer_id: NodeId) {
        self.peer_map.remove(&peer_id);
        self.connect_queue.insert(peer_id, Duration::from_secs(0));
        self.metrics.peer_map_size.dec();
        self.metrics.closed_request_handlers_total.inc();
    }

    async fn handle_topology_change(&mut self) {
        self.metrics.topology_changes_total.inc();
        self.topology = self.watcher.borrow_and_update().clone();

        let subnet_node_set = self.topology.get_subnet_nodes();
        self.metrics.topology_size.set(subnet_node_set.len() as i64);
        let subnet_nodes = SomeOrAllNodes::Some(subnet_node_set);

        // Set new server config to only accept connections from the current set.
        match self.tls_config.server_config(
            AllowedClients::new(subnet_nodes)
                .unwrap_or_else(|_| AllowedClients::new(SomeOrAllNodes::All).unwrap()),
            self.topology.latest_registry_version(),
        ) {
            Ok(rustls_server_config) => {
                let mut server_config =
                    quinn::ServerConfig::with_crypto(Arc::new(rustls_server_config));
                server_config.transport_config(self.transport_config.clone());
                self.endpoint.set_server_config(Some(server_config));
            }
            Err(e) => {
                error!(self.log, "Failed to get certificate from crypto {}", e)
            }
        }

        // Connect/Disconnect from peers according to new topology
        for (peer_id, _) in self.topology.iter() {
            let dialer = self.node_id < *peer_id;
            let no_active_connection_attempt = !self.outbound_connecting.contains(peer_id);
            let no_active_connection = !self.active_connections.contains(peer_id);
            let node_in_subnet = self.topology.is_member(&self.node_id);
            // Add to delayqueue for connecting iff
            // - Not currently trying to connect
            // - No active connection to this peer
            // - Our node id is lower -> This node is dialer.
            // - This node is part of the subnet. This can happen when a node is removed from the subnet.
            if no_active_connection_attempt && no_active_connection && dialer && node_in_subnet {
                self.connect_queue.insert(*peer_id, Duration::from_secs(0));
            }
        }

        // Remove peer connections that are not part of subnet anymore.
        // Also remove peer connections that have closed connections.
        self.peer_map.retain(|peer_id, _| {
            let peer_left_topology = !self.topology.is_member(peer_id);
            let node_left_topology = !self.topology.is_member(&self.node_id);
            // If peer is not member anymore or this node not part of subnet close connection.
            let should_close_connection = peer_left_topology || node_left_topology;

            if should_close_connection {
                self.metrics.peers_removed_total.inc();
                false
            } else {
                true
            }
        });
        self.metrics.peer_map_size.set(self.peer_map.len() as i64);
    }

    fn handle_dial(&mut self, peer_id: NodeId) {
        let not_dialer = self.node_id >= peer_id;
        let peer_not_in_subnet = self.topology.get_addr(&peer_id).is_none();
        let active_connection_attempt = self.outbound_connecting.contains(&peer_id);
        let active_connection = self.active_connections.contains(&peer_id);
        let node_not_in_subnet = !self.topology.is_member(&self.node_id);

        // Conditions under which we do NOT connect
        // - prefer lower node id / dialing ourself
        // - peer not in subnet
        // - currently trying to connect
        // - already connected
        // - this node is not part of subnet. This can happen when a node is removed from the subnet.
        if not_dialer
            || peer_not_in_subnet
            || active_connection_attempt
            || active_connection
            || node_not_in_subnet
        {
            return;
        }

        info!(self.log, "Connecting to node {}", peer_id);
        self.metrics.outbound_connection_total.inc();
        let addr = self
            .topology
            .get_addr(&peer_id)
            .expect("Just checked this conditions");
        let handshaker = self.sev_handshake.clone();
        let endpoint = self.endpoint.clone();
        let client_config = self
            .tls_config
            .client_config(peer_id, self.topology.latest_registry_version())
            .map_err(|cause| ConnectionEstablishError::TlsClientConfigError { peer_id, cause });
        let transport_config = self.transport_config.clone();
        let earliest_registry_version = self.topology.earliest_registry_version();
        let last_registry_version = self.topology.latest_registry_version();
        let conn_fut = async move {
            let mut quinn_client_config = quinn::ClientConfig::new(Arc::new(client_config?));
            quinn_client_config.transport_config(transport_config);
            let connecting = endpoint.connect_with(quinn_client_config, addr, "irrelevant");
            let established = connecting
                .map_err(|cause| ConnectionEstablishError::ConnectError { peer_id, cause })?
                .await
                .map_err(|cause| ConnectionEstablishError::ConnectionError {
                    peer_id: Some(peer_id),
                    cause,
                })?;

            // Authentication handshakes
            let connection = Self::attestation_handshake(
                handshaker,
                peer_id,
                earliest_registry_version,
                last_registry_version,
                established,
                Direction::Outbound,
            )
            .await?;
            let connection = Self::gruezi(connection, Direction::Outbound).await?;

            Ok::<_, ConnectionEstablishError>(QuicConnWithPeerId {
                peer_id,
                connection,
            })
        };

        let timeout_conn_fut = async move {
            tokio::time::timeout(CONNECT_TIMEOUT, conn_fut)
                .await
                .map_err(|_| ConnectionEstablishError::Timeout)
                .and_then(|x| x)
        };

        self.outbound_connecting
            .spawn_on(peer_id, timeout_conn_fut, &self.rt);
    }

    /// Process connection attempt result. If successfull connection is
    /// added to peer map. If unsuccessful and this node is dialer the
    /// connection will be retried. `peer` is `Some` if this node was
    /// the dialer. I.e lower node id.
    async fn handle_connecting_result(
        &mut self,
        conn_res: Result<QuicConnWithPeerId, ConnectionEstablishError>,
        peer_id: Option<NodeId>,
    ) {
        match conn_res {
            Ok(connection) => {
                self.metrics
                    .connection_results_total
                    .with_label_values(&[CONNECTION_RESULT_SUCCESS_LABEL])
                    .inc();

                let peer_id = connection.peer_id;

                let (cmd_tx, cmd_rx) = channel(10);
                let new_conn_handle = ConnectionHandle(cmd_tx);
                self.peer_map.insert(peer_id, new_conn_handle);

                info!(
                    self.log,
                    "Spawning request handler for peer : {:?}", peer_id
                );
                self.active_connections.spawn_on(
                    peer_id,
                    start_request_handler(
                        connection.peer_id,
                        connection.connection,
                        cmd_rx,
                        self.metrics.clone(),
                        self.log.clone(),
                        self.router.clone(),
                    ),
                    &self.rt,
                );
            }
            Err(err) => {
                self.metrics
                    .connection_results_total
                    .with_label_values(&[CONNECTION_RESULT_FAILED_LABEL])
                    .inc();
                // The peer is only present in connections that this node initiated. This node should therefore retry connecting to the peer.
                if let Some(peer_id) = peer_id {
                    self.connect_queue.insert(peer_id, CONNECT_RETRY_BACKOFF);
                }
                info!(self.log, "Failed to connect {}", err);
            }
        };
    }

    fn handle_inbound(&mut self, connecting: Connecting) {
        self.metrics.inbound_connection_total.inc();
        let handshaker = self.sev_handshake.clone();
        let node_id = self.node_id;
        let earliest_registry_version = self.topology.earliest_registry_version();
        let last_registry_version = self.topology.latest_registry_version();
        let conn_fut = async move {
            let established =
                connecting
                    .await
                    .map_err(|cause| ConnectionEstablishError::ConnectionError {
                        peer_id: None,
                        cause,
                    })?;

            let tls_pub_key = tls_pubkey_cert_from_rustls_certs(
                &established
                    .peer_identity()
                    .ok_or(ConnectionEstablishError::MissingPeerIdentity)?
                    .downcast::<Vec<tokio_rustls::rustls::Certificate>>()
                    .unwrap(),
            )
            .map_err(|e| {
                ConnectionEstablishError::MalformedPeerIdentity(MalformedPeerCertificateError {
                    internal_error: e.to_string(),
                })
            })?;
            let peer_id = node_id_from_cert_subject_common_name(&tls_pub_key)
                .map_err(|e| ConnectionEstablishError::MalformedPeerIdentity(e))?;

            // Lower ID is dialer. So we reject if this nodes id is higher.
            if peer_id > node_id {
                return Err(ConnectionEstablishError::PeerIdMismatch {
                    client: peer_id,
                    server: node_id,
                });
            }

            // Authentication handshakes
            let connection = Self::attestation_handshake(
                handshaker,
                peer_id,
                earliest_registry_version,
                last_registry_version,
                established,
                Direction::Inbound,
            )
            .await?;
            let connection = Self::gruezi(connection, Direction::Inbound).await?;

            Ok::<_, ConnectionEstablishError>(QuicConnWithPeerId {
                peer_id,
                connection,
            })
        };

        let timeout_conn_fut = async move {
            match tokio::time::timeout(CONNECT_TIMEOUT, conn_fut).await {
                Ok(connection_res) => connection_res,
                Err(_) => Err(ConnectionEstablishError::Timeout),
            }
        };

        self.inbound_connecting.spawn(timeout_conn_fut);
    }

    async fn attestation_handshake(
        sev_handshake: Arc<dyn ValidateAttestedStream<Box<dyn TlsStream>> + Send + Sync>,
        peer_id: NodeId,
        earliest_registry_version: RegistryVersion,
        latest_registry_version: RegistryVersion,
        conn: Connection,
        direction: Direction,
    ) -> Result<Connection, ConnectionEstablishError> {
        let read_write = match direction {
            Direction::Inbound => HandshakeReadWrite::new(
                conn.open_bi()
                    .await
                    .map_err(|e| ConnectionEstablishError::SevAttestation(e.to_string()))?,
            ),
            Direction::Outbound => HandshakeReadWrite::new(
                conn.accept_bi()
                    .await
                    .map_err(|e| ConnectionEstablishError::SevAttestation(e.to_string()))?,
            ),
        };

        sev_handshake
            .perform_attestation_validation(
                Box::new(read_write),
                peer_id,
                latest_registry_version,
                earliest_registry_version,
            )
            .await
            .map_err(|e| ConnectionEstablishError::SevAttestation(e.to_string()))?;
        Ok(conn)
    }

    // To authenticate peers we do mutual TLS. Both peers therefore know the identity
    // of the other peer. It can can happen that one side assumes that the connection
    // is fully established when the other peer may still reject the connection. This
    // handshake makes sure that connection is fully functional.
    async fn gruezi(
        conn: Connection,
        direction: Direction,
    ) -> Result<Connection, ConnectionEstablishError> {
        match direction {
            Direction::Inbound => {
                let (mut send, mut recv) = conn
                    .open_bi()
                    .await
                    .map_err(|e| ConnectionEstablishError::Gruezi(e.to_string()))?;
                send.write_all(GRUEZI_HANDSHAKE.as_bytes())
                    .await
                    .map_err(|e| ConnectionEstablishError::Gruezi(e.to_string()))?;
                send.finish()
                    .await
                    .map_err(|e| ConnectionEstablishError::Gruezi(e.to_string()))?;
                let data = recv
                    .read_to_end(GRUEZI_HANDSHAKE.len())
                    .await
                    .map_err(|e| ConnectionEstablishError::Gruezi(e.to_string()))?;
                if data != GRUEZI_HANDSHAKE.as_bytes() {
                    return Err(ConnectionEstablishError::Gruezi(format!(
                        "Handshake failed unexpected response: {}",
                        String::from_utf8_lossy(&data)
                    )));
                }
            }
            Direction::Outbound => {
                let (mut send, mut recv) = conn
                    .accept_bi()
                    .await
                    .map_err(|e| ConnectionEstablishError::Gruezi(e.to_string()))?;
                let data = recv
                    .read_to_end(GRUEZI_HANDSHAKE.len())
                    .await
                    .map_err(|e| ConnectionEstablishError::Gruezi(e.to_string()))?;
                if data != GRUEZI_HANDSHAKE.as_bytes() {
                    return Err(ConnectionEstablishError::Gruezi(format!(
                        "Handshake failed unexpected response: {}",
                        String::from_utf8_lossy(&data)
                    )));
                }
                send.write_all(GRUEZI_HANDSHAKE.as_bytes())
                    .await
                    .map_err(|e| ConnectionEstablishError::Gruezi(e.to_string()))?;
                send.finish()
                    .await
                    .map_err(|e| ConnectionEstablishError::Gruezi(e.to_string()))?;
            }
        };
        Ok(conn)
    }
}

struct HandshakeReadWrite {
    recv: RecvStream,
    send: SendStream,
}

impl HandshakeReadWrite {
    pub fn new(read_write: (SendStream, RecvStream)) -> Self {
        Self {
            recv: read_write.1,
            send: read_write.0,
        }
    }
}

impl TlsStream for HandshakeReadWrite {}

impl AsyncRead for HandshakeReadWrite {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for HandshakeReadWrite {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
