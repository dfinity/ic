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
//!     - Only if all these steps successfully complete do we add the connection to the active set.
//!
//! Connection reconciliation:
//!     - Since transport guarantees eventual connectivity to peers in the topology
//!       it needs to repair broken connections.
//!     - Currently there is a periodic check that checks the status of the connection
//!       and reconnects if necessary.
use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    Router, body::Body, body::HttpBody, extract::Request, extract::State, middleware::Next,
    middleware::from_fn_with_state,
};
use futures::StreamExt;
use ic_base_types::NodeId;
use ic_crypto_tls_interfaces::{SomeOrAllNodes, TlsConfig};
use ic_crypto_utils_tls::node_id_from_certificate_der;
use ic_http_endpoints_async_utils::JoinMap;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, error, info};
use ic_metrics::MetricsRegistry;
use quinn::{
    AsyncUdpSocket, ConnectError, Connection, ConnectionError, Endpoint, EndpointConfig, Incoming,
    Runtime, TokioRuntime, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::pki_types::CertificateDer;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use static_assertions::const_assert;
use thiserror::Error;
use tokio::{runtime::Handle, select, task::JoinSet};
use tokio_util::{sync::CancellationToken, time::DelayQueue};

use crate::{
    Shutdown, SubnetTopology,
    connection_handle::ConnectionHandle,
    metrics::{CONNECTION_RESULT_FAILED_LABEL, CONNECTION_RESULT_SUCCESS_LABEL},
};
use crate::{metrics::QuicTransportMetrics, request_handler::start_stream_acceptor};

/// The value of 25MB is chosen from experiments and the BDP product shown below to support
/// around 2Gb/s.
/// Bandwidth-Delay Product
/// 2Gb/s * 100ms ≈ 200M bits = 25MB
/// To this only on to avoid unnecessary error in dfx on MacOS
#[cfg(target_os = "linux")]
const UDP_BUFFER_SIZE: usize = 25_000_000; // 25MB

const RECEIVE_WINDOW: VarInt = VarInt::from_u32(200_000_000);
const SEND_WINDOW: u64 = 100_000_000;
const STREAM_RECEIVE_WINDOW: VarInt = VarInt::from_u32(4_000_000);
const MAX_CONCURRENT_BIDI_STREAMS: VarInt = VarInt::from_u32(1_000);
const MAX_CONCURRENT_UNI_STREAMS: VarInt = VarInt::from_u32(1_000);

/// Interval of quic heartbeats. They are only sent if the connection is idle for more than 1sec.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(1);
/// Timeout after which quic marks connections as broken. This timeout is used to detect connections
/// that were not explicitly closed. I.e replica crash
const IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_secs(5);

// There should be least two probes before timing out a connection.
const_assert!(KEEP_ALIVE_INTERVAL.as_nanos() < IDLE_TIMEOUT.as_nanos());
// The application level timeout should no less than the QUIC idle timeout.
const_assert!(IDLE_TIMEOUT.as_nanos() <= CONNECT_TIMEOUT.as_nanos());
// The waiting time before re-trying to connect should be no less than the IDLE_TIMEOUT.
const_assert!(IDLE_TIMEOUT.as_nanos() <= CONNECT_RETRY_BACKOFF.as_nanos());

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
    tls_config: Arc<dyn TlsConfig>,

    // Shared state
    watcher: tokio::sync::watch::Receiver<SubnetTopology>,
    peer_map: Arc<RwLock<HashMap<NodeId, ConnectionHandle>>>,

    // Local state.
    /// Task joinmap that holds stores a connecting tasks keys by peer id.
    outbound_connecting: JoinMap<NodeId, Result<Connection, ConnectionEstablishError>>,
    /// Task joinset on which incoming connection requests are spawned. This is not a JoinMap
    /// because the peerId is not available until the TLS handshake succeeded.
    inbound_connecting: JoinSet<Result<ConnectionWithPeerId, ConnectionEstablishError>>,
    /// JoinMap that stores active connection handlers keyed by peer id.
    active_connections: JoinMap<NodeId, ()>,

    /// Endpoint config
    endpoint: Endpoint,
    transport_config: Arc<quinn::TransportConfig>,
    router: Router,
}

#[derive(Debug, Error)]
enum ConnectionEstablishError {
    #[error(
        "Timeout during connection establishment. Took longer than {:?} to establish a connection",
        CONNECT_TIMEOUT
    )]
    Timeout,
    #[error("Incoming connection failed. {cause:?}")]
    ConnectionError {
        peer_id: Option<NodeId>,
        cause: ConnectionError,
    },
    // The following errors should be infallible/internal.
    #[error(
        "Failed to establish outbound connection to peer {peer_id:?} due to errors in the parameters being used. {cause:?}"
    )]
    BadConnectParameters {
        peer_id: NodeId,
        cause: ConnectError,
    },
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("Incoming connection from {client:?}, which is > than {server:?}")]
    InvalidIncomingPeerId { client: NodeId, server: NodeId },
}

struct ConnectionWithPeerId {
    peer_id: NodeId,
    connection: Connection,
}

pub fn create_udp_socket(rt: &Handle, addr: SocketAddr) -> Arc<dyn AsyncUdpSocket> {
    let _guard = rt.enter();
    let socket2 = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
        .expect("Failed to create udp socket");

    // Set socket send/recv buffer size. Setting these explicitly makes sure that a
    // sufficiently large value is used. Increasing these buffers can help with high packet loss.
    #[cfg(target_os = "linux")]
    let _ = socket2.set_recv_buffer_size(UDP_BUFFER_SIZE);
    #[cfg(target_os = "linux")]
    let _ = socket2.set_send_buffer_size(UDP_BUFFER_SIZE);

    socket2
        .bind(&SockAddr::from(addr))
        .expect("Failed to bind to UDP socket");

    TokioRuntime::wrap_udp_socket(&TokioRuntime, socket2.into()).unwrap()
}

pub(crate) fn start_connection_manager(
    log: &ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt: &Handle,
    tls_config: Arc<dyn TlsConfig>,
    registry_client: Arc<dyn RegistryClient>,
    node_id: NodeId,
    peer_map: Arc<RwLock<HashMap<NodeId, ConnectionHandle>>>,
    watcher: tokio::sync::watch::Receiver<SubnetTopology>,
    socket: Arc<dyn AsyncUdpSocket>,
    router: Router,
) -> Shutdown {
    let topology = watcher.borrow().clone();

    let metrics = QuicTransportMetrics::new(metrics_registry);

    let router = router.route_layer(from_fn_with_state(metrics.clone(), collect_metrics));

    // We use a random reset key here. The downside of this is that
    // during a crash and restart the peer will not recognize our
    // CONNECTION_RESETS.Not recognizing the reset might lead
    // the other side to keep sending data. To solve this we would
    // need to persist our reset key or derive it from the secret key.
    // In our case the other side will reset the connection after a few
    // seconds because we are not able to respond to keep-alives.
    // Maybe in the future we could derive a key from our tls key.
    let endpoint_config = EndpointConfig::default();
    let rustls_server_config = tls_config
        .server_config(
            SomeOrAllNodes::Some(BTreeSet::new()),
            registry_client.get_latest_version(),
        )
        .expect(
            "The rustls server config must be locally available, otherwise transport can't start.",
        );

    let mut transport_config = quinn::TransportConfig::default();

    transport_config
        .max_idle_timeout(Some(IDLE_TIMEOUT.try_into().unwrap()))
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
        .send_window(SEND_WINDOW)
        .receive_window(RECEIVE_WINDOW)
        .stream_receive_window(STREAM_RECEIVE_WINDOW)
        .max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS)
        .max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS);

    let transport_config = Arc::new(transport_config);
    let quinn_server_config = QuicServerConfig::try_from(rustls_server_config).expect("Conversion from RustTls config to Quinn config must succeed as long as this library and quinn use the same RustTls versions.");
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_server_config));
    server_config.transport_config(transport_config.clone());

    let endpoint = {
        let _guard = rt.enter();
        Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .expect("Failed to create endpoint")
    };
    let manager = ConnectionManager {
        log: log.clone(),
        rt: rt.clone(),
        tls_config,
        metrics,
        node_id,
        topology,
        connect_queue: DelayQueue::new(),
        peer_map,
        watcher,
        endpoint,
        transport_config,
        outbound_connecting: JoinMap::new(),
        inbound_connecting: JoinSet::new(),
        active_connections: JoinMap::new(),
        router,
    };
    Shutdown::spawn_on_with_cancellation(
        |cancellation: CancellationToken| manager.run(cancellation),
        rt,
    )
}

impl ConnectionManager {
    fn am_i_dialer(&self, dst: &NodeId) -> bool {
        self.node_id < *dst
    }

    /// Conditions under which the node can start outbound connecting attempt
    /// - the node is a designated dialer
    /// - peer is in the subnet
    /// - this node is part of the subnet (can happen when a node is removed from the subnet)
    /// - there is no connect attempted
    /// - there is no established connection
    fn can_i_dial_to(&self, dst: &NodeId) -> bool {
        let dialer = self.am_i_dialer(dst);
        let peer_in_subnet = self.topology.is_member(dst);
        let node_in_subnet = self.topology.is_member(&self.node_id);
        let no_active_connection_attempt = !self.outbound_connecting.contains(dst);
        let no_active_connection = !self.active_connections.contains(dst);
        no_active_connection_attempt
            && no_active_connection
            && dialer
            && node_in_subnet
            && peer_in_subnet
    }

    pub async fn run(mut self, cancellation: CancellationToken) {
        loop {
            select! {
                () = cancellation.cancelled() => {
                    break;
                },
                Some(conn_res) = self.outbound_connecting.join_next() => {
                    match conn_res {
                        Ok((Ok(conn), peer_id)) => self.handle_established_connection(conn, peer_id),
                        // retry
                        Ok((Err(err), peer_id)) =>  {
                            self.metrics
                                .connection_results_total
                                .with_label_values(&[CONNECTION_RESULT_FAILED_LABEL])
                                .inc();
                            info!(self.log, "Failed to establish outbound connection {:?}.", err);
                            self.connect_queue.insert(peer_id, CONNECT_RETRY_BACKOFF);
                        }
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
                        Ok(Ok(conn)) => self.handle_established_connection(conn.connection, conn.peer_id),
                        Ok(Err(err)) => {
                            self.metrics
                                .connection_results_total
                                .with_label_values(&[CONNECTION_RESULT_FAILED_LABEL])
                                .inc();
                            info!(self.log, "Failed to establish inbound connection {:?}.", err);
                        }
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
                        Ok(((), peer_id)) => {
                            self.peer_map.write().unwrap().remove(&peer_id);
                            self.metrics.peers_removed_total.inc();
                            self.connect_queue.insert(peer_id, Duration::ZERO);
                            self.metrics.peer_map_size.dec();
                            self.metrics.closed_request_handlers_total.inc();
                        }
                        Err(err) => {
                            // Cancelling tasks is ok. Panicking tasks are not.
                            if err.is_panic() {
                                std::panic::resume_unwind(err.into_panic());
                            }
                        }
                    }
                },
                Some(reconnect) = self.connect_queue.next() => {
                    self.handle_outbound_conn_attemp(reconnect.into_inner())
                },
                incoming = self.endpoint.accept() => {
                    if let Some(incoming) = incoming {
                        self.handle_inbound_conn_attemp(incoming);
                    } else {
                        error!(self.log, "Quic endpoint closed. Stopping transport.");
                        // Endpoint is closed. This indicates NOT graceful shutdown.
                        break;
                    }
                },
                // Ignore the case if the sender is dropped. It is not transport's responsibility to make
                // sure topology senders are up and running.
                Ok(()) = self.watcher.changed() => {
                    self.handle_topology_change();
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
        self.reset().await;
    }

    // TODO: maybe unbind the port so we can start another transport on the same port after shutdown.
    async fn reset(mut self) {
        self.peer_map.write().unwrap().clear();
        self.endpoint
            .close(VarInt::from_u32(0), b"graceful shutdown of endpoint");
        self.connect_queue.clear();
        self.inbound_connecting.shutdown().await;
        self.outbound_connecting.shutdown().await;
        self.active_connections.shutdown().await;
        self.endpoint.wait_idle().await;
    }

    fn handle_topology_change(&mut self) {
        self.metrics.topology_changes_total.inc();
        self.topology = self.watcher.borrow_and_update().clone();

        let subnet_node_set = self.topology.get_subnet_nodes();
        self.metrics.topology_size.set(subnet_node_set.len() as i64);
        let subnet_nodes = SomeOrAllNodes::Some(subnet_node_set);

        // Set new server config to only accept connections from the current set.
        let rustls_server_config = self.tls_config
            .server_config(subnet_nodes, self.topology.latest_registry_version())
            .expect("The rustls server config must be locally available, otherwise transport can't run.");

        let quic_server_config = QuicServerConfig::try_from(rustls_server_config).expect("Conversion from RustTls config to Quinn config must succeed as long as this library and quinn use the same RustTls versions.");
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        server_config.transport_config(self.transport_config.clone());
        self.endpoint.set_server_config(Some(server_config));

        // Connect/Disconnect from peers according to new topology
        for (peer_id, _) in self.topology.iter() {
            if self.can_i_dial_to(peer_id) {
                self.connect_queue.insert(*peer_id, Duration::from_secs(0));
            }
        }

        // Remove peer connections that are not part of subnet anymore.
        // Also remove peer connections that have closed connections.
        let peer_map = self.peer_map.read().unwrap();
        peer_map.iter().for_each(|(peer_id, conn_handle)| {
            let peer_left_topology = !self.topology.is_member(peer_id);
            let node_left_topology = !self.topology.is_member(&self.node_id);
            // If peer is not member anymore or this node not part of subnet close connection.
            let should_close_connection = peer_left_topology || node_left_topology;
            if should_close_connection {
                conn_handle
                    .conn()
                    .close(VarInt::from_u32(0), b"node not part of subnet anymore");
            }
        });

        self.metrics.peer_map_size.set(peer_map.len() as i64);
    }

    /// Inserts a task into `outbound_connecting`` that handles an outbound connection attempt. (The function can also be called `handle_outbound`).
    fn handle_outbound_conn_attemp(&mut self, peer_id: NodeId) {
        if !self.can_i_dial_to(&peer_id) {
            return;
        }

        info!(self.log, "Connecting to node {:?}", peer_id);
        self.metrics.outbound_connection_total.inc();
        let addr = self
            .topology
            .get_addr(&peer_id)
            .expect("Just checked this conditions.");
        let endpoint = self.endpoint.clone();
        let rustls_client_config = self
            .tls_config
            .client_config(peer_id, self.topology.latest_registry_version())
            .expect("The rustls client config must be locally available, otherwise transport can't start.");
        let transport_config = self.transport_config.clone();
        let quinn_client_config = QuicClientConfig::try_from(rustls_client_config).expect("Conversion from RustTls config to Quinn config must succeed as long as this library and quinn use the same RustTls versions.");
        let mut client_config = quinn::ClientConfig::new(Arc::new(quinn_client_config));
        client_config.transport_config(transport_config);
        let logger = self.log.clone();
        let conn_fut = async move {
            // 'connect_with' is placed inside the async block so the event loop retries on failure.
            let connecting = endpoint
                .connect_with(client_config, addr, "irrelevant")
                .map_err(|cause| ConnectionEstablishError::BadConnectParameters {
                    peer_id,
                    cause,
                })?;
            let established =
                connecting
                    .await
                    .map_err(|cause| ConnectionEstablishError::ConnectionError {
                        peer_id: Some(peer_id),
                        cause,
                    })?;

            info!(logger, "Connected to node {:?}", peer_id);
            Ok::<_, ConnectionEstablishError>(established)
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

    /// Process connection attempt result. If successful connection is
    /// added to peer map. If unsuccessful and this node is dialer the
    /// connection will be retried. `peer` is `Some` if this node was
    /// the dialer. I.e lower node id.
    fn handle_established_connection(&mut self, connection: Connection, peer_id: NodeId) {
        self.metrics
            .connection_results_total
            .with_label_values(&[CONNECTION_RESULT_SUCCESS_LABEL])
            .inc();
        let mut peer_map_mut = self.peer_map.write().unwrap();
        // Increase the connection ID for the newly connected peer.
        // This should be done while holding a write lock to the peer map
        // such that the next read call sees the new id.

        let connection_handle = ConnectionHandle::new(connection, self.metrics.clone());

        // dropping the old connection will result in closing it
        if let Some(old_conn) = peer_map_mut.insert(peer_id, connection_handle.clone()) {
            old_conn
                .conn()
                .close(VarInt::from_u32(0), b"using newer connection");
            info!(
                self.log,
                "Replacing old connection to {:?} with newer", peer_id
            );
        } else {
            self.metrics.peer_map_size.inc();
        }

        info!(
            self.log,
            "Spawning request handler for peer : {:?}", peer_id
        );
        self.active_connections.spawn_on(
            peer_id,
            start_stream_acceptor(
                self.log.clone(),
                peer_id,
                connection_handle,
                self.metrics.clone(),
                self.router.clone(),
            ),
            &self.rt,
        );
    }

    /// Inserts a task into 'inbound_connecting' that handles an inbound connection attempt.
    fn handle_inbound_conn_attemp(&mut self, incoming: Incoming) {
        self.metrics.inbound_connection_total.inc();
        let node_id = self.node_id;
        let conn_fut = async move {
            let established =
                incoming
                    .await
                    .map_err(|cause| ConnectionEstablishError::ConnectionError {
                        peer_id: None,
                        cause,
                    })?;

            let rustls_certs = established
                .peer_identity()
                .ok_or(ConnectionEstablishError::AuthenticationFailed(
                    "missing peer identity".to_string(),
                ))?
                .downcast::<Vec<CertificateDer>>()
                .unwrap();
            let rustls_cert =
                rustls_certs
                    .first()
                    .ok_or(ConnectionEstablishError::AuthenticationFailed(
                        "a single cert must be present".to_string(),
                    ))?;
            let peer_id = node_id_from_certificate_der(rustls_cert.as_ref())
                .map_err(|err| ConnectionEstablishError::AuthenticationFailed(err.to_string()))?;

            // Lower ID is dialer. So we reject if this nodes id is higher.
            if peer_id > node_id {
                return Err(ConnectionEstablishError::InvalidIncomingPeerId {
                    client: peer_id,
                    server: node_id,
                });
            }

            Ok::<_, ConnectionEstablishError>(ConnectionWithPeerId {
                peer_id,
                connection: established,
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
}

/// Axum middleware to collect metrics
async fn collect_metrics(
    State(state): State<QuicTransportMetrics>,
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    state
        .request_handle_bytes_received_total
        .with_label_values(&[request.uri().path()])
        .inc_by(request.body().size_hint().lower());
    let _timer = state
        .request_handle_duration_seconds
        .with_label_values(&[request.uri().path()])
        .start_timer();
    let out_counter = state
        .request_handle_bytes_sent_total
        .with_label_values(&[request.uri().path()]);
    let response = next.run(request).await;
    out_counter.inc_by(response.body().size_hint().lower());
    response
}
