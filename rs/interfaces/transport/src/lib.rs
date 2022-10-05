//! Transport layer public interface.
use ic_base_types::{NodeId, RegistryVersion};
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, fmt::Debug, net::SocketAddr};
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
    /// It is important to call this method before `start_connection`, otherwise,
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
    ///        Using a pull model leads to:
    ///             a) can't have custom logic like filtering, load shedding, queueing,
    ///                rate-limitting, etc. before messages are deliver to the client
    ///             b) complicated concurrent processing, because messages are fanned in into
    ///                a single channel that the client uses to receive them
    ///                (channel receivers require exclusive access to receive a message).
    ///                If one day we need a custom scheduler this is the abstraction we need to
    ///                consider.
    fn set_event_handler(&self, event_handler: TransportEventHandler);

    /// Initiates a connection to the corresponding peer. This method should be non-blocking
    /// because the success of establishing the connection depends on the internal state of
    /// both peers. This is different than the client-server model where a server starts up
    /// waiting for connection and it can be acceptable for the client to block until a
    /// connection is established.
    /// Since this method is non-blocking, the callee can send messages to the peer
    /// once it received the PeerUp event.
    fn start_connection(
        &self,
        peer_id: &NodeId,
        peer_addr: SocketAddr,
        registry_version: RegistryVersion,
    ) -> Result<(), TransportError>;

    /// Terminates the connection with the peer.
    fn stop_connection(&self, peer_id: &NodeId);

    /// Send the message to the specified peer. The message will be enqueued
    /// into the corresponding 'TransportChannelId' send queue.
    fn send(
        &self,
        peer_id: &NodeId,
        channel_id: TransportChannelId,
        message: TransportPayload,
    ) -> Result<(), TransportError>;

    /// Clear any queued messages in all the send queues for the peer.
    fn clear_send_queues(&self, peer_id: &NodeId);
}

/// The transport layer has the responsibility of passing the payload to the caller.
/// If the event handler can't process the payload for some reason it is the caller's
/// responsibility to handle the error.
/// Currently there are no caller errors that make sense to be handled by the lower level
/// transport implementation.
pub type TransportEventHandler = BoxCloneService<TransportEvent, (), Infallible>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportChannel;
/// Identifier associated with a peer connection.
pub type TransportChannelId = Id<TransportChannel, u32>;

/// The payload for the transport layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct TransportPayload(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Debug)]
pub enum TransportEvent {
    /// Peer flow was established
    PeerUp(NodeId),

    /// Peer flow went down
    PeerDown(NodeId),

    /// Message received
    Message(TransportMessage),
}

#[derive(Debug)]
pub struct TransportMessage {
    pub peer_id: NodeId,
    pub payload: TransportPayload,
}

/// Error codes returned by transport manager functions.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportError {
    /// E.g. the the peer connection already is initiated,
    /// the event handler is already set, etc.
    AlreadyExists,

    /// E.g. the peer is missing, the peer connection is missing, etc.
    NotFound,

    /// Failed to add a message to the send queue because the queue is full.
    SendQueueFull(TransportPayload),
}
