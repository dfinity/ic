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

use std::{
    collections::HashMap,
    fmt::Debug,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use axum::Router;
use bytes::Bytes;
use connection_handle::ConnectionHandle;
use either::Either;
use http::{Request, Response};
use ic_crypto_tls_interfaces::{TlsConfig, TlsStream};
use ic_icos_sev_interfaces::ValidateAttestedStream;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_peer_manager::SubnetTopology;
use ic_types::NodeId;
use quinn::AsyncUdpSocket;

use crate::connection_manager::start_connection_manager;

mod connection_handle;
mod connection_manager;
mod metrics;
mod request_handler;
mod utils;

#[derive(Clone)]
pub struct QuicTransport(Arc<RwLock<HashMap<NodeId, ConnectionHandle>>>);

impl QuicTransport {
    pub fn build(
        rt: tokio::runtime::Handle,
        log: ReplicaLogger,
        tls_config: Arc<dyn TlsConfig + Send + Sync>,
        registry_client: Arc<dyn RegistryClient>,
        sev_handshake: Arc<dyn ValidateAttestedStream<Box<dyn TlsStream>> + Send + Sync>,
        node_id: NodeId,
        topology_watcher: tokio::sync::watch::Receiver<SubnetTopology>,
        udp_socket: Either<SocketAddr, impl AsyncUdpSocket>,
        metrics_registry: &MetricsRegistry,
        state_sync_router: Router,
    ) -> QuicTransport {
        info!(log, "Building Quic transport.");

        let peer_map = Arc::new(RwLock::new(HashMap::new()));

        // If we have multiple services we need to combine the routers here.
        // Make sure this is respected https://docs.rs/axum/latest/axum/struct.Router.html#a-note-about-performance
        let router = state_sync_router;

        start_connection_manager(
            log,
            rt,
            metrics_registry,
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

    pub(crate) fn get_peer_handle(
        &self,
        peer_id: &NodeId,
    ) -> Result<ConnectionHandle, TransportError> {
        let conn = self
            .0
            .read()
            .unwrap()
            .get(peer_id)
            .ok_or(TransportError::Disconnected {
                connection_error: Some(String::from("Currently not connected to this peer")),
            })?
            .clone();
        Ok(conn)
    }

    pub(crate) fn get_peer_handles(&self) -> Vec<ConnectionHandle> {
        self.0.read().unwrap().values().cloned().collect()
    }
}
#[async_trait]
impl Transport for QuicTransport {
    async fn rpc(
        &self,
        peer: &NodeId,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, TransportError> {
        let peer = self.get_peer_handle(peer)?;
        peer.rpc(request).await
    }

    fn broadcast(&self, request: Request<Bytes>) {
        for peer_handle in self.get_peer_handles() {
            let mut new_request = Request::builder()
                .method(request.method().clone())
                .uri(request.uri().clone())
                .version(request.version());
            new_request
                .headers_mut()
                .replace(&mut request.headers().clone());
            let new_request = new_request
                .body(request.body().clone())
                .expect("Clone of valid request");

            let _ = tokio::spawn(async move {
                let _ = peer_handle.rpc(new_request).await;
            });
        }
    }
}

#[derive(Debug)]
pub enum TransportError {
    Disconnected {
        // Potential reason for not being connected
        connection_error: Option<String>,
    },
    Io {
        error: std::io::Error,
    },
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected {
                connection_error: Some(e),
            } => {
                write!(f, "Disconnected/No connection to peer: {}", e)
            }
            Self::Disconnected {
                connection_error: None,
            } => {
                write!(f, "Disconnected/No connection to peer")
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
        peer: &NodeId,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, TransportError>;

    fn broadcast(&self, request: Request<Bytes>);
}
