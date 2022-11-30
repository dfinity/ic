//! Shared types internal to transport crate

use crate::metrics::{ControlPlaneMetrics, DataPlaneMetrics, SendQueueMetrics};
use crate::utils::SendQueueImpl;
use async_trait::async_trait;
use bytes::Bytes;
use futures::future::poll_fn;
use h2::{RecvStream, SendStream};
use ic_base_types::{NodeId, RegistryVersion};
use ic_config::transport::TransportConfig;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_crypto_tls_interfaces::TlsStream;
use ic_interfaces_transport::{TransportChannelId, TransportEventHandler, TransportPayload};
use ic_logger::{warn, ReplicaLogger};
use phantom_newtype::AmountOf;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt::{self, Debug, Formatter};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use strum::AsRefStr;
use strum::IntoStaticStr;
use tokio::{
    io::{ReadHalf, WriteHalf},
    runtime::Handle,
    sync::{Mutex, RwLock},
    task::JoinHandle,
    time::Duration,
};

/// A tag for the queue size
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueueSizeTag;
/// Type definition for a queue's size
pub type QueueSize = AmountOf<QueueSizeTag, usize>;

/// The size (in bytes) of the transport header
pub const TRANSPORT_HEADER_SIZE: usize = 8;

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

/// This is the max frame size that H2 supports
pub const H2_FRAME_SIZE: u32 = 16_777_215;

/// This value was chosen empirically and can be raised if needed
pub const H2_WINDOW_SIZE: u32 = 1_000_000;

pub(crate) enum ChannelReader {
    Legacy(ReadHalf<Box<dyn TlsStream>>),
    H2RecvStream(H2Reader),
}

impl ChannelReader {
    pub fn new_with_legacy(tls_reader: ReadHalf<Box<dyn TlsStream>>) -> Self {
        ChannelReader::Legacy(tls_reader)
    }

    pub fn new_with_h2_recv_stream(recv_stream: RecvStream) -> Self {
        ChannelReader::H2RecvStream(H2Reader::new(recv_stream))
    }
}

pub(crate) enum ChannelWriter {
    Legacy(WriteHalf<Box<dyn TlsStream>>),
    H2SendStream(H2Writer),
}

impl ChannelWriter {
    pub fn new_with_legacy(tls_writer: WriteHalf<Box<dyn TlsStream>>) -> Self {
        ChannelWriter::Legacy(tls_writer)
    }

    pub fn new_with_h2_send_stream(send_stream: SendStream<Bytes>) -> Self {
        ChannelWriter::H2SendStream(H2Writer::new(send_stream))
    }
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

    /// Port used to accept connections for this transport-client
    pub accept_port: Mutex<Option<ServerPortState>>,
    /// Mapping of peers to their corresponding state
    pub peer_map: RwLock<HashMap<NodeId, RwLock<PeerState>>>,
    /// Event handler to report back to the transport client
    pub event_handler: Mutex<Option<TransportEventHandler>>,

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
    pub rt_handle: Handle,
    /// Logger
    pub log: ReplicaLogger,
    /// Guarded self weak-reference
    pub weak_self: std::sync::RwLock<Weak<TransportImpl>>,
    /// If true, uses http/2 protocol
    pub use_h2: bool,
}

/// Error type for read errors
#[derive(Debug, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum StreamReadError {
    Failed(std::io::Error),
    TimeOut,
    H2ReceiveStreamFailure(String),
}

// Wrapper around SendStream to ensure that we only send data if there is available capacity,
// since send stream uses an unbounded buffer to handle data.
pub(crate) struct H2Writer {
    send_stream: SendStream<Bytes>,
}

impl H2Writer {
    pub fn new(send_stream: SendStream<Bytes>) -> Self {
        Self { send_stream }
    }

    // This is invoked to send data via sendstream. As a prerequisite, it checks available capacity
    // and waits until non-zero capacity is available before calling send to avoid overloading memory
    pub async fn send_data(&mut self, mut data: Bytes) -> Result<(), std::io::Error> {
        while !data.is_empty() {
            let len = data.len();
            self.send_stream.reserve_capacity(len);

            match poll_fn(|cx| self.send_stream.poll_capacity(cx)).await {
                None | Some(Err(_)) => {
                    let e = std::io::Error::new(std::io::ErrorKind::Other, "poll capacity failure");
                    return Err(e);
                }
                Some(Ok(0)) => continue,
                Some(Ok(cap)) => {
                    let to_send = data.split_to(std::cmp::min(cap, len));
                    self.send_stream.send_data(to_send, false).map_err(|err| {
                        err.into_io().unwrap_or_else(|| {
                            std::io::Error::new(std::io::ErrorKind::Other, "failed to send header")
                        })
                    })?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct H2Reader {
    receive_stream: RecvStream,
    buffer: Vec<u8>,
}

impl H2Reader {
    pub fn new(receive_stream: RecvStream) -> Self {
        Self {
            receive_stream,
            buffer: vec![],
        }
    }

    /// Reads frames until target length is reached.
    /// After each frame is read, capacity is released.
    /// Timeout is applied to each frame read.
    /// If more bytes are read than the target, return that as an 'excess'
    pub async fn get_message(
        &mut self,
        target_len: usize,
        msg_type: String,
        timeout: Duration,
    ) -> Result<Vec<u8>, StreamReadError> {
        while self.buffer.len() < target_len {
            let read_future = self.receive_stream.data();
            match tokio::time::timeout(timeout, read_future).await {
                Err(_) => return Err(StreamReadError::TimeOut),
                Ok(Some(Ok(chunk))) => {
                    self.buffer.append(&mut chunk.to_vec());
                    let _ = self
                        .receive_stream
                        .flow_control()
                        .release_capacity(chunk.len());
                }
                // If stream returns empty frame, continue polling
                Ok(None) => {}
                Ok(Some(Err(h2_error))) => {
                    return Err(StreamReadError::H2ReceiveStreamFailure(format!(
                        "{:?} for {:?}",
                        h2_error.to_string(),
                        msg_type
                    )));
                }
            }
        }
        let extra_buffer = self.buffer.split_off(target_len);

        let message = self.buffer.to_vec();
        self.buffer = extra_buffer;
        Ok(message)
    }
}

pub(crate) struct TransportImplH2 {
    /// The node ID of this replica
    pub _node_id: NodeId,
    /// The IP address of this node
    pub node_ip: IpAddr,
    /// Configuration
    pub config: TransportConfig,

    /// Port used to accept connections for this transport-client
    pub accept_port: Mutex<Option<ServerPortState>>,
    /// Mapping of peers to their corresponding state
    pub peer_map: RwLock<HashMap<NodeId, RwLock<PeerStateH2>>>,
    /// Event handler to report back to the transport client
    pub event_handler: Mutex<Option<TransportEventHandler>>,

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
    pub rt_handle: Handle,
    /// Logger
    pub log: ReplicaLogger,
    /// Guarded self weak-reference
    pub weak_self: std::sync::RwLock<Weak<TransportImplH2>>,
}

/// Our role in a connection
#[derive(Debug, PartialEq, Eq, Copy, Clone, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum ConnectionRole {
    /// We connect to the peer as a client
    Client,

    /// We are the server
    Server,
}

/// State about the server ports we are listening on
pub(crate) struct ServerPortState {
    /// Handle to the accept task for this port
    pub accept_task: JoinHandle<()>,
}

impl Drop for ServerPortState {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

/// Per-peer state, specific to a transport client
pub(crate) struct PeerState {
    log: ReplicaLogger,
    /// Transport channel label, used for metrics
    pub channel_id_label: String,
    /// Peer label, used for metrics
    pub peer_label: String,
    /// Connection state
    connection_state: ConnectionState,
    /// The send queue of this flow
    pub send_queue: Box<dyn SendQueue + Send + Sync>,
    /// Metrics
    control_plane_metrics: ControlPlaneMetrics,
}

impl PeerState {
    pub(crate) fn new(
        log: ReplicaLogger,
        channel_id: TransportChannelId,
        peer_label: String,
        connection_state: ConnectionState,
        queue_size: QueueSize,
        send_queue_metrics: SendQueueMetrics,
        control_plane_metrics: ControlPlaneMetrics,
    ) -> Self {
        let send_queue = Box::new(SendQueueImpl::new(
            peer_label.clone(),
            channel_id,
            queue_size,
            send_queue_metrics,
        ));
        let ret = Self {
            log,
            channel_id_label: channel_id.to_string(),
            peer_label,
            connection_state,
            send_queue,
            control_plane_metrics,
        };
        ret.report_connection_state();
        ret
    }

    /// Updates the state of the connection
    pub(crate) fn update(&mut self, connection_state: ConnectionState) {
        self.connection_state.update(connection_state);
        self.report_connection_state();
    }

    /// Reports the state of a flow to metrics
    fn report_connection_state(&self) {
        self.control_plane_metrics
            .flow_state
            .with_label_values(&[&self.peer_label, &self.channel_id_label])
            .set(self.connection_state.idx());
    }

    pub(crate) fn get_connected(&self) -> Option<&Connected> {
        if let ConnectionState::Connected(connected) = &self.connection_state {
            return Some(connected);
        }
        None
    }
}

impl Drop for PeerState {
    fn drop(&mut self) {
        if self
            .control_plane_metrics
            .flow_state
            .remove_label_values(&[&self.peer_label, &self.channel_id_label])
            .is_err()
        {
            warn!(
                self.log,
                "Transport:PeerState drop: Could not remove peer metric {:?}", self.peer_label
            )
        }
    }
}

pub(crate) struct PeerStateH2 {
    _log: ReplicaLogger,
    /// Transport channel label, used for metrics
    pub _channel_id_label: String,
    /// Peer label, used for metrics
    pub peer_label: String,
    /// Connection state where peer is server
    connection_state_write_path: ConnectionState,
    /// Connection state where peer is client
    connection_state_read_path: ConnectionState,
    /// The send queue of this flow
    pub send_queue: Box<dyn SendQueue + Send + Sync>,
    /// Metrics
    _control_plane_metrics: ControlPlaneMetrics,
}

impl PeerStateH2 {
    pub(crate) fn new(
        _log: ReplicaLogger,
        channel_id: TransportChannelId,
        peer_label: String,
        connection_state_write_path: ConnectionState,
        connection_state_read_path: ConnectionState,
        queue_size: QueueSize,
        send_queue_metrics: SendQueueMetrics,
        _control_plane_metrics: ControlPlaneMetrics,
    ) -> Self {
        let send_queue = Box::new(SendQueueImpl::new(
            peer_label.clone(),
            channel_id,
            queue_size,
            send_queue_metrics,
        ));
        let ret = Self {
            _log,
            _channel_id_label: channel_id.to_string(),
            peer_label,
            connection_state_write_path,
            connection_state_read_path,
            send_queue,
            _control_plane_metrics,
        };
        ret.report_connection_state(ConnectionRole::Client);
        ret.report_connection_state(ConnectionRole::Server);
        ret
    }

    // Connection role represents role of calling node, not the peer
    pub(crate) fn update(
        &mut self,
        connection_state: ConnectionState,
        connection_role: ConnectionRole,
    ) {
        match connection_role {
            ConnectionRole::Client => self.connection_state_write_path.update(connection_state),
            ConnectionRole::Server => self.connection_state_read_path.update(connection_state),
        }
        self.report_connection_state(connection_role);
    }

    /// Reports the state of a flow to metrics
    fn report_connection_state(&self, _connection_role: ConnectionRole) {
        //TODO - metrics
    }

    pub(crate) fn get_connected(&self, connection_role: ConnectionRole) -> Option<&Connected> {
        match connection_role {
            ConnectionRole::Client => {
                if let ConnectionState::Connected(connected) = &self.connection_state_write_path {
                    return Some(connected);
                }
            }
            ConnectionRole::Server => {
                if let ConnectionState::Connected(connected) = &self.connection_state_read_path {
                    return Some(connected);
                }
            }
        }
        None
    }
}

impl Drop for PeerStateH2 {
    fn drop(&mut self) {
        // TODO: Metrics
    }
}

/// The connection state machine for a flow with a peer
pub(crate) enum ConnectionState {
    /// We are the server, waiting for peer to connect
    Listening,
    /// We are the client, connection in progress
    Connecting(Connecting),
    /// Connection established
    Connected(Connected),
    /// Connection established (H2)
    ConnectedH2(ConnectedH2),
}

/// Info about a flow in ConnectionState::Connecting
pub(crate) struct Connecting {
    /// Server node we are connecting to
    pub peer_addr: SocketAddr,

    /// The connecting task handle
    pub connecting_task: JoinHandle<()>,
}

/// Info about a flow in ConnectionState::Connected
pub(crate) struct Connected {
    /// Peer node
    pub peer_addr: SocketAddr,

    /// The read task handle
    pub read_task: JoinHandle<()>,

    /// The write task handle
    pub write_task: JoinHandle<()>,

    /// Our role
    pub role: ConnectionRole,
}

/// Info about a flow in ConnectionState::Connected
pub(crate) struct ConnectedH2 {
    /// Peer node
    pub peer_addr: SocketAddr,

    /// The read or write task handle
    pub _task: JoinHandle<()>,

    /// Our role
    pub role: ConnectionRole,
}

impl ConnectionState {
    /// Validates/updates the state transition
    fn update(&mut self, next_state: Self) {
        if self.is_valid_transition(&next_state) {
            *self = next_state;
        } else {
            panic!(
                "Invalid connection state change: {:?} -> {:?}",
                *self, next_state
            );
        }
    }

    /// Verifies if it the state transition is allowed according to the state
    /// machine
    fn is_valid_transition(&self, next_state: &Self) -> bool {
        let mut valid = false;
        match self {
            Self::Listening => {
                if let Self::Connected(s) = next_state {
                    if s.role == ConnectionRole::Server {
                        valid = true;
                    }
                }
                if let Self::ConnectedH2(s) = next_state {
                    if s.role == ConnectionRole::Server {
                        valid = true;
                    }
                }
            }
            Self::Connecting(_) => {
                if let Self::Connected(s) = next_state {
                    if s.role == ConnectionRole::Client {
                        valid = true;
                    }
                }
                if let Self::ConnectedH2(s) = next_state {
                    if s.role == ConnectionRole::Client {
                        valid = true;
                    }
                }
            }
            Self::Connected(s) => match next_state {
                Self::Listening => {
                    if s.role == ConnectionRole::Server {
                        valid = true;
                    }
                }
                Self::Connecting(_) => {
                    if s.role == ConnectionRole::Client {
                        valid = true;
                    }
                }
                _ => (),
            },
            Self::ConnectedH2(s) => match next_state {
                Self::Listening => {
                    if s.role == ConnectionRole::Server {
                        valid = true;
                    }
                }
                Self::Connecting(_) => {
                    if s.role == ConnectionRole::Client {
                        valid = true;
                    }
                }
                _ => (),
            },
        }
        valid
    }

    fn idx(&self) -> i64 {
        match self {
            Self::Listening => 1,
            Self::Connecting(_) => 2,
            Self::Connected(_) => 3,
            Self::ConnectedH2(_) => 4,
        }
    }
}

impl Debug for ConnectionState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Listening => {
                write!(f, "ConnectionState::Listening")
            }
            Self::Connecting(state) => {
                write!(
                    f,
                    "ConnectionState::Connecting(peer = {:?})",
                    state.peer_addr
                )
            }
            Self::Connected(state) => {
                write!(
                    f,
                    "ConnectionState::Connected(peer = {:?}, role = {:?})",
                    state.peer_addr, state.role
                )
            }
            Self::ConnectedH2(state) => {
                write!(
                    f,
                    "ConnectionState::ConnectedH2(peer = {:?}, role = {:?})",
                    state.peer_addr, state.role
                )
            }
        }
    }
}

impl Drop for ConnectionState {
    fn drop(&mut self) {
        match &self {
            Self::Connecting(state) => state.connecting_task.abort(),
            Self::Connected(state) => {
                state.read_task.abort();
                state.write_task.abort();
            }
            _ => (),
        }
    }
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
    fn get_reader(&mut self) -> Box<dyn SendQueueReader + Send + Sync>;

    /// Submits a client message for sending to a peer. If the message
    /// cannot be enqueued, the message is returned back to the caller.
    fn enqueue(&self, message: TransportPayload) -> Option<TransportPayload>;

    /// Discards enqueued messages and clears the queue.
    fn clear(&mut self);
}

/// Per-flow: send queue read end
#[async_trait]
pub(crate) trait SendQueueReader {
    /// Called by the scheduler to get the next enqueued message, if any.
    async fn dequeue(&mut self, bytes_limit: usize, timeout: Duration) -> Vec<TransportPayload>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connecting_state() -> ConnectionState {
        let connecting_task = tokio::task::spawn(async {});
        ConnectionState::Connecting(Connecting {
            peer_addr: "127.0.0.1:8080".parse().unwrap(),
            connecting_task,
        })
    }

    fn connected_state(role: ConnectionRole) -> ConnectionState {
        let read_task = tokio::task::spawn(async {});
        let write_task = tokio::task::spawn(async {});
        ConnectionState::Connected(Connected {
            peer_addr: "127.0.0.1:8080".parse().unwrap(),
            read_task,
            write_task,
            role,
        })
    }

    fn verify_state_transitions(
        current_state: ConnectionState,
        results: Vec<(ConnectionState, bool)>,
    ) {
        for (next_state, expected_result) in results {
            assert_eq!(
                current_state.is_valid_transition(&next_state),
                expected_result
            );
        }
    }

    #[tokio::test]
    async fn test_connection_state_machine_listening() {
        let state = ConnectionState::Listening;
        let expected = vec![
            (ConnectionState::Listening, false),
            (connecting_state(), false),
            (connected_state(ConnectionRole::Server), true),
            (connected_state(ConnectionRole::Client), false),
        ];
        verify_state_transitions(state, expected);
    }

    #[tokio::test]
    async fn test_connection_state_machine_connecting() {
        let state = connecting_state();
        let expected = vec![
            (ConnectionState::Listening, false),
            (connecting_state(), false),
            (connected_state(ConnectionRole::Server), false),
            (connected_state(ConnectionRole::Client), true),
        ];
        verify_state_transitions(state, expected);
    }

    #[tokio::test]
    async fn test_connection_state_machine_connected() {
        let state = connected_state(ConnectionRole::Server);
        let expected = vec![
            (ConnectionState::Listening, true),
            (connecting_state(), false),
            (connected_state(ConnectionRole::Server), false),
            (connected_state(ConnectionRole::Client), false),
        ];
        verify_state_transitions(state, expected);

        let state = connected_state(ConnectionRole::Client);
        let expected = vec![
            (ConnectionState::Listening, false),
            (connecting_state(), true),
            (connected_state(ConnectionRole::Server), false),
            (connected_state(ConnectionRole::Client), false),
        ];
        verify_state_transitions(state, expected);
    }
}
