//! Shared types internal to transport crate

use crate::metrics::{ControlPlaneMetrics, DataPlaneMetrics, SendQueueMetrics};
use ic_config::transport::TransportConfig;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces_transport::AsyncTransportEventHandler;
use ic_logger::ReplicaLogger;
use ic_types::transport::{FlowId, FlowTag, TransportPayload};
use ic_types::{NodeId, RegistryVersion};
use phantom_newtype::{AmountOf, Id};

use async_trait::async_trait;
use futures::future::AbortHandle;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt::{self, Debug, Formatter};
use std::net::IpAddr;
use std::net::SocketAddr;
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
    pub client_map: RwLock<Option<ClientState>>,

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

/// Our role in a connection
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConnectionRole {
    /// We connect to the peer as a client
    Client,

    /// We are the server
    Server,
}

/// Per transport-client state
pub(crate) struct ClientState {
    /// Ports used to accept connections for this transport-client
    pub accept_ports: HashMap<FlowTag, ServerPortState>,
    /// Mapping of peers to their corresponding state
    pub peer_map: HashMap<NodeId, PeerState>,
    /// Event handler to report back to the transport client
    pub event_handler: Arc<dyn AsyncTransportEventHandler>,
}

/// State about the server ports we are listening on
pub(crate) struct ServerPortState {
    /// Handle to the accept task for this port
    pub accept_task: AbortHandle,
}

impl Drop for ServerPortState {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

/// Per-peer state, specific to a transport client
pub(crate) struct PeerState {
    /// State of the flows with the peer
    pub flow_map: HashMap<FlowTag, FlowState>,
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
    /// The send queue of this flow
    pub send_queue: Box<dyn SendQueue + Send + Sync>,
    /// Metrics
    pub control_plane_metrics: ControlPlaneMetrics,
}

impl FlowState {
    pub(crate) fn new(
        flow_id: FlowId,
        flow_tag_label: String,
        flow_label: String,
        connection_state: ConnectionState,
        send_queue: Box<dyn SendQueue + Send + Sync>,
        control_plane_metrics: ControlPlaneMetrics,
    ) -> Self {
        let ret = Self {
            flow_id,
            flow_tag_label,
            flow_label,
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
            .with_label_values(&[&self.flow_label, &self.flow_tag_label])
            .set(self.connection_state.idx());
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
}

/// Info about a flow in ConnectionState::Connecting
pub(crate) struct Connecting {
    /// Server node we are connecting to
    pub peer_addr: SocketAddr,

    /// The connecting task handle
    pub connecting_task: AbortHandle,
}

/// Info about a flow in ConnectionState::Connected
pub(crate) struct Connected {
    /// Peer node
    pub peer_addr: SocketAddr,

    /// The read task handle
    pub read_task: AbortHandle,

    /// The write task handle
    pub write_task: AbortHandle,

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
            }
            Self::Connecting(_) => {
                if let Self::Connected(s) = next_state {
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
        }
        valid
    }

    fn idx(&self) -> i64 {
        match self {
            Self::Listening => 1,
            Self::Connecting(_) => 2,
            Self::Connected(_) => 3,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn connecting_state() -> ConnectionState {
        let (connecting_task, _) = AbortHandle::new_pair();
        ConnectionState::Connecting(Connecting {
            peer_addr: "127.0.0.1:8080".parse().unwrap(),
            connecting_task,
        })
    }

    fn connected_state(role: ConnectionRole) -> ConnectionState {
        let (read_task, _) = AbortHandle::new_pair();
        let (write_task, _) = AbortHandle::new_pair();
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

    #[test]
    fn test_connection_state_machine_listening() {
        let state = ConnectionState::Listening;
        let expected = vec![
            (ConnectionState::Listening, false),
            (connecting_state(), false),
            (connected_state(ConnectionRole::Server), true),
            (connected_state(ConnectionRole::Client), false),
        ];
        verify_state_transitions(state, expected);
    }

    #[test]
    fn test_connection_state_machine_connecting() {
        let state = connecting_state();
        let expected = vec![
            (ConnectionState::Listening, false),
            (connecting_state(), false),
            (connected_state(ConnectionRole::Server), false),
            (connected_state(ConnectionRole::Client), true),
        ];
        verify_state_transitions(state, expected);
    }

    #[test]
    fn test_connection_state_machine_connected() {
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
