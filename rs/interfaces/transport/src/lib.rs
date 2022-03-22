//! Transport layer public interface.

use async_trait::async_trait;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_types::transport::{
    FlowId, FlowTag, TransportErrorCode, TransportPayload, TransportStateChange,
};
use ic_types::{NodeId, RegistryVersion};
use std::{fmt::Debug, sync::Arc};

/// Transport component API
/// The Transport component provides peer-to-peer connectivity with other peers.
/// It exposes an interface for sending and receiving messages from peers, as well
/// as for tracking the state of connections.
/// The provided interface does not have the notion of clients and servers, as
/// in peer to peer networks, there is no such definition of clients and servers.
/// Therefore, Transport hides these semantics from the components above it
/// (which are called 'Transport clients').
pub trait Transport: Send + Sync {
    /// Register the given Transport client, providing an event handler with the
    /// corresponding implementation of the required callbacks for Transport to
    /// call the client on events.
    /// Note that a Transport client is another component (e.g., p2p). It should
    /// not be confused with the notion of a client in a client-server communication.
    fn register_client(
        &self,
        async_event_handler: Arc<dyn AsyncTransportEventHandler>,
    ) -> Result<(), TransportErrorCode>;

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
    fn stop_connections(&self, peer_id: &NodeId) -> Result<(), TransportErrorCode>;

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

    /// Clear any unsent messages in the send queue for the given peer and flow
    /// tag.
    fn clear_send_queue(&self, peer_id: &NodeId, flow_tag: FlowTag);
}

#[derive(Debug)]
pub enum SendError {
    DeserializationFailed,
    EndpointClosed,
    EndpointNotFound,
}

/// An event handler for Transport clients. The event handler defines a set
/// of callback functions to be used by Transport for notifications to the
/// client.
#[async_trait]
pub trait AsyncTransportEventHandler: Send + Sync {
    /// Send a received message to the client
    async fn send_message(&self, flow: FlowId, message: TransportPayload) -> Result<(), SendError>;

    /// Notify the client of a change in a connection state
    async fn state_changed(&self, state_change: TransportStateChange);

    /// Notify the client of an error that occurred while a connection is active
    async fn error(&self, flow: FlowId, error: TransportErrorCode);
}
