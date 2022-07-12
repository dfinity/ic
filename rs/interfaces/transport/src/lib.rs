//! Transport layer public interface.
use ic_base_types::{NodeId, RegistryVersion};
use ic_protobuf::registry::node::v1::NodeRecord;
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, fmt::Debug};
use tower::util::BoxCloneService;

/// Transport component API
/// The Transport component provides peer-to-peer connectivity with other peers.
/// It exposes an interface for sending and receiving messages from peers, as well
/// as for tracking the state of connections.
/// The provided interface does not have the notion of clients and servers, as
/// in peer to peer networks, there is no such definition of clients and servers.
/// Therefore, Transport hides these semantics from the components above it
/// (which are called 'Transport clients').
pub trait Transport: Send + Sync {
    /// Sets an event handler object that is called when a new message is received.
    /// It is important to call this method before `start_connections`, otherwise,
    /// a panic may occur due to the missing `event_handler`.
    ///
    /// Alternatives considered:
    ///     1. Event handler instance per connection instead per Transport object.
    ///        Having different event handlers per connection/peer implies peers are not equal.
    ///     2. Use a pull model for delivering message to the Transport `client`.
    ///        In this context the Transport `client` is the service/library that consumes the
    ///        received messages.
    ///        One way to implement this is to return channel receiver(s) when a connection
    ///        is established. Then the client can pull the receiver(s) to consume messages.
    ///        Using a pull model gives us less flexibility:
    ///             a) can't have custom logic like filtering, load shedding, queueing,
    ///                rate-limitting, etc. before messages are deliver to the client
    ///             b) complicated concurrent processing, because messages are fanned in into
    ///                a single channel that the client uses to receive them
    ///                (channel receivers require exclusive access to receive a message)
    fn set_event_handler(&self, event_handler: TransportEventHandler);

    /// Mark the peer as valid neighbor, and set up the transport layer to
    /// exchange messages with the peer. This call would create the
    /// necessary wiring in the transport layer for the peer:
    /// - 1. Set up the Tx/Rx queueing, based on TransportQueueConfig.
    /// - 2. If the peer is the server, initiate connection requests to the peer
    ///   server ports.
    /// - 3. If the peer is the client, set up the connection state to accept
    ///   connection requests from the peer.
    /// These are all implementation details that should not bother the
    /// components that are using Transport (the Transport clients).
    fn start_connections(
        &self,
        peer: &NodeId,
        node_record: &NodeRecord,
        registry_version: RegistryVersion,
    ) -> Result<(), TransportErrorCode>;

    /// Remove the peer from the set of valid neighbors, and tear down the
    /// queues and connections for the peer. Any messages in the Tx and Rx
    /// queues for the peer will be discarded.
    /// It is fine to call the function on non-existing connection(s).
    fn stop_connections(&self, peer_id: &NodeId);

    /// Send the message to the specified peer. The message will be enqueued
    /// into the appropriate TxQ based on the TransportQueueConfig.
    fn send(
        &self,
        peer_id: &NodeId,
        flow_tag: FlowTag,
        message: TransportPayload,
    ) -> Result<(), TransportErrorCode>;

    /// Clear any unsent messages in all the send queues for the peer.
    fn clear_send_queues(&self, peer_id: &NodeId);
}

#[derive(Debug)]
pub enum SendError {
    DeserializationFailed,
    EndpointClosed,
    EndpointNotFound,
}

pub type TransportEventHandler = BoxCloneService<TransportEvent, Result<(), SendError>, Infallible>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowTagType;
/// A tag attached to a flow.
pub type FlowTag = Id<FlowTagType, u32>;

/// The payload for the transport layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportPayload(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Debug)]
pub enum TransportEvent {
    StateChange(TransportStateChange),
    Message(TransportMessage),
}

#[derive(Debug)]
pub struct TransportMessage {
    pub peer_id: NodeId,
    pub payload: TransportPayload,
}

/// State changes that can happen in the transport layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportStateChange {
    /// Peer flow was established
    PeerFlowUp(NodeId),

    /// Peer flow went down
    PeerFlowDown(NodeId),
}

/// Error codes returned by transport manager functions.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportErrorCode {
    /// Found an active client of the same type.
    TransportClientAlreadyRegistered,

    /// Unable to find a registered client for the given client context.
    TransportClientNotFound,

    /// Found an active client of the same type.
    PeerAlreadyRegistered,

    /// Unable to find the peer specified by the API.
    PeerNotFound,

    /// Flow already enabled
    FlowAlreadyEnabled,

    /// Flow not found
    FlowNotFound,

    /// Flow is already in connected state
    FlowConnectionUp,

    /// Flow is already in disconnected state
    FlowConnectionDown,

    /// Unable to find config for the client type.
    TransportClientConfigNotFound,

    /// Failed to enqueue/submit a message/request. The error code contains the
    /// entry that could not be submitted.
    TransportBusy(TransportPayload),

    /// Write to connection failed due to OS error. The string has the
    /// human readable error string.
    ConnectionWriteFailed(String),

    /// Read from connection failed due to OS error. The string has the
    /// human readable error string.
    ConnectionReadFailed(String),

    /// Failed to serialize
    SerializationFailed,

    /// Failed to deserialize
    DeserializationFailed,

    /// Registry has missing entries for one of advert/request/artifact types
    RegistryMissingConfig,

    /// Registry has multiple IPs across advert/request/artifact types
    RegistryMultiIP,

    /// Registry has invalid port number
    RegistryInvalidPortNumber,

    /// Unable to route the message -> queue, based on the config.
    MessageQueueRoutingFailed,

    /// Transport queue is full.
    TransportQueueFull,

    /// The queue is being shut down.
    TransportQueueStopped,

    /// Connection event handler not registered.
    ConnectionEventHandlerNotFound,

    /// Failed to serialize the message for send.
    MessageSerializationFailed,

    /// Unable to route the message -> connection, based on the config.
    MessageConnectionRoutingFailed,

    /// Unable to find a connection to send the message.
    ConnectionNotFound,

    /// Failed to write to socket.
    SocketWriteFailed,

    /// Failed to convert server listener.
    ServerSocketConversionFailed,

    /// Failed to set the NO_DELAY option
    SocketNoDelayFailed,

    /// Duplicate node Ids in node registry.
    RegistryDuplicateNodeId,

    /// Duplicate node IPs in node registry.
    RegistryDuplicateNodeIP,

    /// Duplicate <node IP, port> in node registry.
    RegistryDuplicateEndpoint,

    /// Invalid IP address in node registry.
    RegistryInvalidNodeIP,

    /// NodeId -> IP resolution failed.
    NodeIpResolutionFailed,

    /// NodeId -> server endpoint resolution failed.
    NodeServerEndpointResolutionFailed,

    /// Failed to parse the PEM certificate
    WrapperCertParsingFailed,

    /// NodeId missing from the certificate
    NodeIdMissing,

    /// Failed to parse the NodeId from the certificate
    NodeIdParsingFailed,

    /// NodeId in the certificate was not in the expected format
    NodeIdMalformed,

    /// Domain name missing from the certificate
    DomainNameMissing,

    /// Too many domain names in the certificate
    DomainNameTooMany,

    /// Domain name in the certificate was not in the expected format
    DomainNameMalformed,

    /// Failed to get the public key from the certificate
    PublicKeyParsingFailed,

    /// TLS is not uniformly configured across all the registry nodes
    RegistryTlsConfigNotUniform,

    /// The NodeId in the certificate is incorrect
    InvalidNodeIdInCertificate,

    /// Failed to find peer TLS info
    PeerTlsInfoNotFound,

    /// Peer cert did not match the expected value in the registry
    PeerTlsInfoMismatch,

    /// The private key file specified in the config could not be parsed
    ConfigPrivateKeyParsingFailed,

    /// The private key file specified in the config could not be read
    ConfigPrivateKeyFileReadFailed,

    /// The private key file specified in the config could not be parsed
    ConfigCertParsingFailed,

    /// The private key file specified in the config could not be read
    ConfigCertFileReadFailed,

    /// Failed to initialize the node key prior to the TLS handshake
    SetNodeKeyFailed,

    /// Failed to initialize the certificate prior to the TLS handshake
    SetNodeCertFailed,

    /// Failed to add peer certificate prior to the TLS handshake
    AddPeerCertFailed,

    /// Failed to initialize the acceptor
    AcceptorInitFailed,

    /// Failed to initialize the connector
    ConnectorInitFailed,

    /// Failed to configure the client side TLS connector
    ConnectorConfigFailed,

    /// Received an error from sender
    SenderErrorIndicated,

    /// Failed to get socket address
    InvalidSockAddr,

    /// Duplicate flow tags in NodeRecord
    NodeRecordDuplicateFlowTag,

    /// Missing connection endpoint in NodeRecord
    NodeRecordMissingConnectionEndpoint,

    /// Timeout expired
    TimeoutExpired,
}
