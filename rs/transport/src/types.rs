//! Shared types internal to transport crate

use crate::metrics::{ControlPlaneMetrics, DataPlaneMetrics, SendQueueMetrics};
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces::transport::AsyncTransportEventHandler;
use ic_logger::ReplicaLogger;
use ic_types::transport::{
    FlowId, FlowTag, TransportClientType, TransportConfig, TransportPayload,
};
use ic_types::{NodeId, RegistryVersion};
use phantom_newtype::{AmountOf, Id};

use async_trait::async_trait;
use futures::future::AbortHandle;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock, Weak};
use tokio::runtime::Handle;
use tokio::time::Duration;

/// A tag for the server port
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerPortTag;
/// Type definition for a server port
pub type ServerPort = Id<ServerPortTag, u16>;

/// A tag for the queue size
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueueSizeTag;
/// Type definition for a queue's size
pub type QueueSize = AmountOf<QueueSizeTag, usize>;

/// The size (in bytes) of the transport header
pub const TRANSPORT_HEADER_SIZE: usize = 8;

/// Flag: sender-indicated error
///
/// When a message has this flag on, it means that the sender of this message
/// has experienced an error sending some messages and may have dropped messages
/// (e.g., due to congestion). The message may still contain some payload.
pub const TRANSPORT_FLAGS_SENDER_ERROR: u8 = 1;
/// Flag: message is a heartbeat
///
/// When a message has this flag on, it means that the message contains no
/// payload, and that it was sent by the heartbeats mechanism to keep the
/// connection alive.
pub const TRANSPORT_FLAGS_IS_HEARTBEAT: u8 = 2;

/// The transport header format.
///
/// A message is sent on the wire as two writes:
///
///   1. The TransportHeader
///   2. The payload (client message, which is an opaque byte array)
///
/// Note:
///
/// For message framing the transport header must serialize to the
/// same size irrespective of its contents. Fields like NodeId can
/// result violation of the same requirement as it can get serialized
/// to different lengths.
///
/// To maintain the size invariant the header is manually serialized.
/// This struct is ephemeral hence the lack of derivations or tagging.
pub(crate) struct TransportHeader {
    /// The version of the Transport being used (currently 0)
    pub(crate) version: u8, // Currently 0
    /// Transport flags: defined by the constants named `TRANSPORT_FLAGS_*` in
    /// this module
    pub(crate) flags: u8,
    /// Reserved space (currently 0)
    pub(crate) reserved: u16, // Currently 0, serialized little endian.
    /// The length of the byte payload that follows next
    pub(crate) payload_length: u32, // Serialized little endian.
}

/// Transport implementation state struct. The control and data planes provide
/// implementations for this struct.
pub(crate) struct TransportImpl {
    /// The node ID of this replica
    pub node_id: NodeId,
    /// The IP address of this node
    pub node_ip: IpAddr,
    /// Configuration
    pub config: TransportConfig,
    /// Map of clients to their corresponding state
    pub client_map: RwLock<HashMap<TransportClientType, ClientState>>,

    // Crypto and data required for TLS handshakes
    /// Clients that are allowed to connect to this node
    pub allowed_clients: Arc<RwLock<BTreeSet<NodeId>>>,
    /// The registry version that is used
    pub registry_version: Arc<RwLock<RegistryVersion>>,
    /// Reference to the crypto component
    pub crypto: Arc<dyn TlsHandshake + Send + Sync>,

    /// Data plane metrics
    pub data_plane_metrics: DataPlaneMetrics,
    /// Control plane metrics
    pub control_plane_metrics: ControlPlaneMetrics,
    /// Send queue metrics
    pub send_queue_metrics: SendQueueMetrics,

    /// The tokio runtime
    pub tokio_runtime: Handle,
    /// Logger
    pub log: ReplicaLogger,
    /// Guarded self weak-reference
    pub weak_self: RwLock<Weak<TransportImpl>>,
}

/// Per transport-client state
pub(crate) struct ClientState {
    /// Ports used to accept connections for this transport-client
    pub accept_ports: HashMap<FlowTag, ServerPort>,
    /// Hooks to cancel the accept() tasks on the server side
    pub accept_cancelers: Vec<Arc<AtomicBool>>,
    /// Mapping of peers to their corresponding state
    pub peer_map: HashMap<NodeId, PeerState>,
    /// Event handler to report back to the transport client
    pub event_handler: Arc<dyn AsyncTransportEventHandler>,
}

/// Per-peer state, specific to a transport client
pub(crate) struct PeerState {
    /// State of the flows with the peer
    pub flow_map: HashMap<FlowTag, FlowState>,
    /// If the peer is the server, hooks to cancel the connect() tasks in
    /// progress
    pub connect_cancelers: Vec<Arc<AtomicBool>>,
}

/// Per-flow state, specific to a transport-client and a peer.
pub(crate) struct FlowState {
    /// Flow identifier
    pub flow_id: FlowId,
    /// Flow tag as a metrics label
    pub flow_tag_label: String,
    /// Flow label, used for metrics
    pub flow_label: String,
    /// Connection state
    pub connection_state: ConnectionState,
    /// Handles to stop the send/receive tasks for this flow
    pub abort_handles: Option<(AbortHandle, AbortHandle)>,
    /// The send queue of this flow
    pub send_queue: Box<dyn SendQueue + Send + Sync>,
}

/// Current state of the connection for a flow with a peer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionState {
    /// We are the server, waiting for peer to connect
    Listening,
    /// We are the client, connection in progress
    Connecting(SocketAddr),
    /// Connection established
    Connected(SocketAddr),
}

/// Per-flow: send queue
///
/// Single producer, single consumer queues for sending data over
/// sockets. There could be multiple sender threads sending into the
/// queue, but the Impl would guarantee mutually exclusive access to
/// the send queue.
#[async_trait]
pub(crate) trait SendQueue {
    /// Gets the read end to be passed to the write task.
    /// Returns None if the reader is already in use by a previously created
    /// write task.
    fn get_reader(&self) -> Box<dyn SendQueueReader + Send + Sync>;

    /// Submits a client message for sending to a peer. If the message
    /// cannot be enqueued, the message is returned back to the caller.
    fn enqueue(&self, message: TransportPayload) -> Option<TransportPayload>;

    /// Discards enqueued messages and clears the queue.
    fn clear(&self);
}

/// Per-flow: send queue read end
#[async_trait]
pub(crate) trait SendQueueReader {
    /// Called by the scheduler to get the next enqueued message, if any.
    async fn dequeue(&mut self, bytes_limit: usize, timeout: Duration) -> Vec<DequeuedMessage>;
}

/// A wrapper for messages that also encloses any related errors
pub(crate) struct DequeuedMessage {
    /// Message payload
    pub(crate) payload: TransportPayload,

    /// Error: the sender indicated an error on its end
    pub(crate) sender_error: bool,
}
