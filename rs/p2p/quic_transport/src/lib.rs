//! Quic Transport.
//!
//! Transport layer based on QUIC. Provides connectivity to all peers in a subnet and
//! the ability to do rpc's to any peer in the subnet. RPC's are routed to the corresponding
//! handlers. Each RPC occurs on a different substream and are therefore fully decoupled from
//! each other.
//!
//! COMPONENTS:
//!  - Connection Manager (connection_manager.rs): Keeps peers connected.
//!  - Request Handler (request_handler.rs): Accepts streams on an active connection.
//!    Spawned by the connection manager for each connection.
//!  - Connection Handle (connection_handle.rs): Provides rpc and push interfaces to a peer.
//!
//! API:
//!  - Constructor takes a topology watcher. The topology defines the
//!    set of peers, to which transport tries to keep active connections.
//!  - Constructor also takes a Router. Incoming requests are routed to a handler
//!    based on the URI specified in the request.
//!  - `get_conn_handle`: Can be used to get a `ConnectionHandle` to a peer.
//!     The connection handle is small wrapper around the actual quic connection
//!     with an rpc/push interface. Passed in requests need to specify an URI to get
//!     routed to the correct handler.
//!
//! GUARANTEES:
//!  - If a peer is reachable, part of the topology and well-behaving transport will eventually
//!    open a connection.
//!  - The connection handle returned by `get_conn_handle` can be broken.
//!    It is responsibility of the transport user to have an adequate retry logic.
//!
//!
use std::{
    collections::HashMap,
    fmt::Debug,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use axum::Router;
use bytes::Bytes;
use either::Either;
use http::{Request, Response};
use ic_base_types::NodeId;
use ic_crypto_tls_interfaces::{TlsConfig, TlsStream};
use ic_icos_sev_interfaces::ValidateAttestedStream;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_peer_manager::SubnetTopology;
use phantom_newtype::AmountOf;
use quinn::AsyncUdpSocket;

use crate::connection_handle::ConnectionHandle;
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
        router: Option<Router>,
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
            router.unwrap_or_default(),
        );

        QuicTransport(peer_map)
    }

    pub(crate) fn get_conn_handle(&self, peer_id: &NodeId) -> Result<ConnectionHandle, SendError> {
        let conn = self
            .0
            .read()
            .unwrap()
            .get(peer_id)
            .ok_or(SendError::ConnectionNotFound {
                reason: "Currently not connected to this peer".to_string(),
            })?
            .clone();
        Ok(conn)
    }
}

#[async_trait]
impl Transport for QuicTransport {
    async fn rpc(
        &self,
        peer_id: &NodeId,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, SendError> {
        let peer = self.get_conn_handle(peer_id)?;
        peer.rpc(request).await
    }

    async fn push(&self, peer_id: &NodeId, request: Request<Bytes>) -> Result<(), SendError> {
        let peer = self.get_conn_handle(peer_id)?;
        peer.push(request).await
    }

    fn peers(&self) -> Vec<(NodeId, ConnId)> {
        self.0
            .read()
            .unwrap()
            .iter()
            .map(|(n, c)| (*n, c.conn_id()))
            .collect()
    }
}

#[derive(Debug)]
pub enum SendError {
    ConnectionNotFound { reason: String },
    // Error for the outbound QUIC message.
    SendRequestFailed { reason: String },
    // Error for the inbound QUIC message.
    RecvResponseFailed { reason: String },
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionNotFound { reason: e } => {
                write!(f, "No connection to peer: {}", e)
            }
            Self::SendRequestFailed { reason } => {
                write!(f, "Sending a request failed: {}", reason)
            }
            Self::RecvResponseFailed { reason } => {
                write!(f, "Receiving a response failed: {}", reason)
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
    ) -> Result<Response<Bytes>, SendError>;

    async fn push(&self, peer_id: &NodeId, request: Request<Bytes>) -> Result<(), SendError>;

    fn peers(&self) -> Vec<(NodeId, ConnId)>;
}

pub struct ConnIdTag {}
pub type ConnId = AmountOf<ConnIdTag, u64>;

/// This is a workaround for being able to initiate quic transport
/// with both a real and virtual udp socket. This is needed due
/// to an inconsistency with the quinn API. This is fixed upstream
/// and can be removed with quinn 0.11.0.
/// https://github.com/quinn-rs/quinn/pull/1595
#[derive(Debug)]
pub struct DummyUdpSocket;

impl AsyncUdpSocket for DummyUdpSocket {
    fn poll_send(
        &self,
        _state: &quinn::udp::UdpState,
        _cx: &mut std::task::Context,
        _transmits: &[quinn::udp::Transmit],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        todo!()
    }
    fn poll_recv(
        &self,
        _cx: &mut std::task::Context,
        _bufs: &mut [std::io::IoSliceMut<'_>],
        _meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        todo!()
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        todo!()
    }
    fn may_fragment(&self) -> bool {
        todo!()
    }
}
