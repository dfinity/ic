//! Transport layer public interface.

use async_trait::async_trait;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_types::transport::{
    FlowId, FlowTag, TransportClientType, TransportErrorCode, TransportPayload,
    TransportStateChange,
};
use ic_types::{NodeId, RegistryVersion};
use std::{fmt::Debug, sync::Arc};

/// Transport layer APIs.
pub trait Transport: Send + Sync {
    /// Register the transport client of the specified type. No more than one
    /// module can register against a particular client type. This returns a
    /// handle to the client's context, which should be supplied in all the
    /// future interactions with the transport layer.
    fn register_client(
        &self,
        client_type: TransportClientType,
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
    fn start_connections(
        &self,
        client_type: TransportClientType,
        peer: &NodeId,
        node_record: &NodeRecord,
        registry_version: RegistryVersion,
    ) -> Result<(), TransportErrorCode>;

    /// Remove the peer from the set of valid neighbors, and tear down the
    /// queues and connections for the peer. Any messages in the Tx and Rx
    /// queues for the peer will be discarded.
    fn stop_connections(
        &self,
        client_type: TransportClientType,
        peer_id: &NodeId,
        registry_version: RegistryVersion,
    ) -> Result<(), TransportErrorCode>;

    /// Send the message to the specified peer. The message will be enqueued
    /// into the appropriate TxQ based on the TransportQueueConfig.
    fn send(
        &self,
        client_type: TransportClientType,
        peer_id: &NodeId,
        flow_tag: FlowTag,
        message: TransportPayload,
    ) -> Result<(), TransportErrorCode>;

    /// Clear any unsent messages in all the send queues for the peer.
    fn clear_send_queues(&self, client_type: TransportClientType, peer_id: &NodeId);

    /// Clear any unsent messages in the send queue for the given peer and flow
    /// tag.
    fn clear_send_queue(
        &self,
        client_type: TransportClientType,
        peer_id: &NodeId,
        flow_tag: FlowTag,
    );
}

#[derive(Debug)]
pub enum SendError {
    DeserializationFailed,
    EndpointClosed,
    EndpointNotFound,
}

/// API for handling transport events.
pub trait TransportEventHandler: Send + Sync {
    /// Invoked by the transport layer when a message is received from the
    /// network. This is implemented by the transport clients to
    /// receive/process the messages.
    /// Returns the message back if it was not accepted.
    fn on_message(&self, flow: FlowId, message: TransportPayload) -> Option<TransportPayload>;

    fn on_error(&self, flow: FlowId, error: TransportErrorCode);

    /// Invoked by the transport layer to notify of any changes in the state.
    fn on_state_change(&self, state_change: TransportStateChange);
}

/// Async version of the transport event handler
#[async_trait]
pub trait AsyncTransportEventHandler: Send + Sync {
    async fn send_message(&self, flow: FlowId, message: TransportPayload) -> Result<(), SendError>;
    async fn state_changed(&self, state_change: TransportStateChange);

    async fn error(&self, flow: FlowId, error: TransportErrorCode);
}
