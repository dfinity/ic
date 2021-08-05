//! Transport layer public types.

use crate::NodeId;
use phantom_newtype::Id;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowTagType;
/// A tag attached to a flow.
pub type FlowTag = Id<FlowTagType, u32>;

/// The payload for the transport layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportPayload(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// A transport notification.
#[derive(Debug)]
pub enum TransportNotification {
    TransportStateChange(TransportStateChange),
    TransportError(TransportError),
}

/// Represents a blob.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Bytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// The type of a transport client.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportClientType {
    /// P2P/Gossip module.
    P2P,

    /// Cross net module.
    XnetCom,
}

/// FlowId is the unique key for the flows being managed
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowId {
    /// Client type
    pub client_type: TransportClientType,

    /// Peer Id
    pub peer_id: NodeId,

    /// Per-peer flow tag
    pub flow_tag: FlowTag,
}

/// The transport format specified in the ic.json
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportConfig {
    pub node_ip: String,

    /// P2P specific config. In future, this will be made more generic.
    pub p2p_flows: Vec<TransportFlowConfig>,
}

/// Per-flow config
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportFlowConfig {
    /// The flow tag. This should be unique per transport client.
    pub flow_tag: u32,

    /// Server port for the flow connection. This should be unique across
    /// all transport clients.
    pub server_port: u16,

    /// Flow queue size
    pub queue_size: usize,
}

/// State changes that can happen in the transport layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportStateChange {
    /// Peer flow was established
    PeerFlowUp(TransportFlowInfo),

    /// Peer flow went down
    PeerFlowDown(TransportFlowInfo),
}

/// Errors that are returned by the transport layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportError {
    TransportSendError(TransportFlowInfo),
}

/// Information that can be used to identify a transport flow.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportFlowInfo {
    /// The peer for the connection
    pub peer_id: NodeId,

    /// The flow tag for the connection
    pub flow_tag: FlowTag,
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

    /// Server socket creation failed.
    ServerSocketCreateFailed,

    /// Failed to set the address reuse flag on the server socket.
    ServerSocketAddrReuseFailed,

    /// Failed to set the port reuse flag on the server socket.
    ServerSocketPortReuseFailed,

    /// Failed to bind to server port.
    ServerSocketBindFailed,

    /// Failed to listen on the server socket.
    ServerSocketListenFailed,

    /// Failed to convert server listener.
    ServerSocketConversionFailed,

    /// Client socket creation failed.
    ClientSocketCreateFailed,

    /// Client socket bind failed.
    ClientSocketBindFailed,

    /// Failed to set the NO_DELAY option
    SocketNoDelayFailed,

    /// Server not accepting connections on the specified port.
    ServerDown,

    /// connect() failed with unhandled OS error.
    ConnectOsError,

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

impl FlowId {
    pub fn new(client_type: TransportClientType, peer_id: NodeId, flow_tag: FlowTag) -> Self {
        Self {
            client_type,
            peer_id,
            flow_tag,
        }
    }
}
