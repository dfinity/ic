//! Quic Transport.
//!
//! Transport layer based on QUIC. Provides connectivity to all peers in a subnet and
//! the ability to do rpc's to any peer in the subnet. RPC's are routed to the corresponding
//! handlers. Each RPC occurs on a different substream and are therefore fully decoupled from
//! each other.
//!
//! COMPONENTS:
//!  - Connection Manager (connection_manager.rs): Main logic that keeps peers connected.
//!  - Request Handler (request_handler.rs): Accepts streams on a active connection.
//!    spawned by the connection manager for each connection.
//!  - Connection Handle (connection_handle.rs): Provides an rpc interface to a peer.
//!
//! API:
//!  - Constructor takes a topology watcher. The topology defines the
//!    set of peers, to which transport tries to keep an active connection.
//!  - Constructor also takes an Router. Incoming requests are routed to a handler
//!    based on the URI specified in the request.
//!  - `get_peer_handle`: Can be used to get a `ConnectionHandle` to a peer.
//!     A connection handle is small wrapper around the actual quic connection
//!     with an rpc interface. Rpc's need to specify an URI to get routed to
//!     the correct handler.
//!
//! GUARANTEES:
//!  - If a peer is reachable, part of the topology and well-behaving
//!    transport will eventually open a connection.
//!  - The connection handle returned by `get_peer_handle` can be broken.
//!    It is responsibility of the transport user to have an adequate retry logic.
//!    Note: Currently the `TransportClient` which is a small wrapper around transport
//!          calls `get_peer_handle` for each rpc and therefore always has the latest
//!          possible handle to a peer.

use std::{collections::HashMap, fmt::Debug, io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use axum::Router;
use bytes::Bytes;
use either::Either;
use http::{Request, Response};
use ic_crypto_tls_interfaces::{TlsConfig, TlsStream};
use ic_icos_sev_interfaces::ValidateAttestedStream;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_peer_manager::SubnetTopology;
use ic_types::NodeId;
use quinn::{AsyncUdpSocket, Connection};
use tokio::sync::mpsc::Sender;
use tokio::sync::{oneshot, RwLock};

use crate::connection_manager::start_connection_manager;

mod connection_manager;
mod metrics;
mod request_handler;
mod utils;

#[derive(Clone)]
pub struct QuicTransport(Arc<RwLock<HashMap<NodeId, ConnectionHandle>>>);

impl QuicTransport {
    pub fn build(
        log: &ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        rt: tokio::runtime::Handle,
        tls_config: Arc<dyn TlsConfig + Send + Sync>,
        registry_client: Arc<dyn RegistryClient>,
        sev_handshake: Arc<dyn ValidateAttestedStream<Box<dyn TlsStream>> + Send + Sync>,
        node_id: NodeId,
        topology_watcher: tokio::sync::watch::Receiver<SubnetTopology>,
        udp_socket: Either<SocketAddr, impl AsyncUdpSocket>,
        // Make sure this is respected https://docs.rs/axum/latest/axum/struct.Router.html#a-note-about-performance
        router: Router,
    ) -> QuicTransport {
        info!(log, "Starting Quic transport.");

        let peer_map = Arc::new(RwLock::new(HashMap::new()));

        start_connection_manager(
            log,
            metrics_registry,
            rt,
            tls_config.clone(),
            registry_client,
            sev_handshake,
            node_id,
            peer_map.clone(),
            topology_watcher,
            udp_socket,
            router,
        );

        QuicTransport(peer_map)
    }
}

enum ConnCmd {
    Push(Request<Bytes>, oneshot::Sender<Result<(), TransportError>>),
    Rpc(
        Request<Bytes>,
        oneshot::Sender<Result<Response<Bytes>, TransportError>>,
    ),
}

#[async_trait]
impl Transport for QuicTransport {
    async fn rpc(
        &self,
        peer_id: &NodeId,
        mut request: Request<Bytes>,
    ) -> Result<Response<Bytes>, TransportError> {
        let rpc_rx = {
            let peers_guard = self.0.read().await;

            let peer = peers_guard
                .get(peer_id)
                .ok_or(TransportError::Disconnected {
                    reason: String::from("Currently not connected to this peer"),
                })?;

            // Propagate PeerId from this connection to lower layers.
            request.extensions_mut().insert(peer_id.clone());

            let (rpc_tx, rpc_rx) = oneshot::channel();
            peer.0
                .send(ConnCmd::Rpc(request, rpc_tx))
                .await
                .map_err(|_err| TransportError::Disconnected {
                    reason: "no existing connection event loop".to_string(),
                })?;
            rpc_rx
        };
        let mut response = rpc_rx.await.map_err(|_err| TransportError::Disconnected {
            reason: "no existing connection event loop".to_string(),
        })??;

        // Propagate PeerId from this request to upper layers.
        response.extensions_mut().insert(peer_id.clone());

        Ok(response)
    }

    async fn push(
        &self,
        peer_id: &NodeId,
        mut request: Request<Bytes>,
    ) -> Result<(), TransportError> {
        let push_rx = {
            let peers_guard = self.0.read().await;
            let peer = peers_guard
                .get(peer_id)
                .ok_or(TransportError::Disconnected {
                    reason: String::from("Currently not connected to this peer"),
                })?;

            // Propagate PeerId from this connection to lower layers.
            request.extensions_mut().insert(peer_id.clone());

            let (push_tx, push_rx) = oneshot::channel();
            peer.0
                .send(ConnCmd::Push(request, push_tx))
                .await
                .map_err(|_err| TransportError::Disconnected {
                    reason: "no existing connection event loop".to_string(),
                })?;
            push_rx
        };

        push_rx.await.map_err(|_err| TransportError::Disconnected {
            reason: "no existing connection event loop".to_string(),
        })?
    }

    async fn peers(&self) -> Vec<NodeId> {
        self.0.read().await.keys().cloned().collect()
    }
}

impl From<quinn::WriteError> for TransportError {
    fn from(value: quinn::WriteError) -> Self {
        match value {
            quinn::WriteError::Stopped(e) => TransportError::Io {
                error: io::Error::new(io::ErrorKind::ConnectionReset, e.to_string()),
            },
            quinn::WriteError::ConnectionLost(cause) => TransportError::Disconnected {
                reason: cause.to_string(),
            },
            quinn::WriteError::UnknownStream => TransportError::Io {
                error: io::Error::new(io::ErrorKind::ConnectionReset, "unknown quic stream"),
            },
            quinn::WriteError::ZeroRttRejected => TransportError::Io {
                error: io::Error::new(io::ErrorKind::ConnectionRefused, "zero rtt rejected"),
            },
        }
    }
}

impl From<quinn::ConnectionError> for TransportError {
    fn from(value: quinn::ConnectionError) -> Self {
        match value {
            quinn::ConnectionError::VersionMismatch => TransportError::Io {
                error: io::Error::new(io::ErrorKind::Unsupported, "Quic version mismatch"),
            },
            quinn::ConnectionError::TransportError(e) => TransportError::Io {
                error: io::Error::new(io::ErrorKind::Unsupported, e.to_string()),
            },
            quinn::ConnectionError::Reset => TransportError::Io {
                error: io::Error::from(io::ErrorKind::ConnectionReset),
            },
            quinn::ConnectionError::TimedOut => TransportError::Io {
                error: io::Error::from(io::ErrorKind::TimedOut),
            },
            quinn::ConnectionError::ConnectionClosed(e) => TransportError::Disconnected {
                reason: e.to_string(),
            },
            quinn::ConnectionError::ApplicationClosed(e) => TransportError::Disconnected {
                reason: e.to_string(),
            },
            quinn::ConnectionError::LocallyClosed => TransportError::Disconnected {
                reason: "Connection closed locally".to_string(),
            },
        }
    }
}

impl From<io::Error> for TransportError {
    fn from(value: io::Error) -> Self {
        TransportError::Io { error: value }
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionHandle(Sender<ConnCmd>);

#[derive(Debug)]
pub(crate) struct QuicConnWithPeerId {
    pub peer_id: NodeId,
    pub connection: Connection,
}

#[derive(Debug)]
pub enum TransportError {
    Disconnected {
        // Potential reason for not being connected
        reason: String,
    },
    Io {
        error: std::io::Error,
    },
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected { reason: e } => {
                write!(f, "Disconnected/No connection to peer: {}", e)
            }
            Self::Io { error } => {
                write!(f, "Io error: {}", error)
            }
        }
    }
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn rpc(
        &self,
        peer_id: &NodeId,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, TransportError>;

    async fn push(&self, peer_id: &NodeId, request: Request<Bytes>) -> Result<(), TransportError>;

    async fn peers(&self) -> Vec<NodeId>;
}
