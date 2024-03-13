//! Transport client interface.
//!
//! Transport processes different types of messages classified into flows by
//! their QoS requirements.  The same flow id and weight is used for both
//! incoming (RX)  and outgoing (TX) messages of the same type.
//!
//! Example: Gossip(one of Transport's clients) uses separate flows for control
//! messages (adverts, requests) and data messages (artifact chunks for ingress
//! manager, consensus (incl DKG and certification) and state sync). Thus,
//! Transport has to handle 3 x 3 flows per peer.
//!
//! The diagram below shows the flow/connect set up sequence:
//!
//! Transport clients invoke add_peer(peer_id) to set up the
//! connections with a valid peer. Control plane then looks up the
//! client config and sets up the peer state. If we are the TCP/TLS
//! client, the control plane initiates the connections for all the
//! flows with the peer. If we are the server, we wait for peers to
//! initiate the flow connections. When a connection is established,
//! the ownership is passed from control plane to the data plane via
//! on_connect(flow_id, socket_read_half, socket_write_half)
//! callback. The read/write halves are passed to the receive/send
//! tasks respectively. At this point, data plane can start performing
//! IOs on the peer connection.  If the data plane tasks detect a
//! connection error, IOs are paused on the connection, and control
//! plane is notified via on_disconnect(flow_id) callback. Control
//! plane then initiates re-connection with the peer.  Successfully
//! re-connections are handled according via the on_connect() described
//! earlier.
//!
//! The send data path has two hops:
//!
//! Transport client calls send(flow_id, message). The message is
//! en-queued to the per-flow send queue. The send data plane task then
//! dequeues the messages and sends it over the socket.
//!
//! The receive data path has one hop:
//!
//! The receive data plane task scans the read half of the
//! connections. Once a complete message is read from the socket, the
//! client's on_message(flow_id, message) callback is invoked for
//! messages delivery.
//!
//! ```text
//! +-----------------------------------------------------+
//! |    Transport Client (Gossip)                        |
//! +-----------------------------------------------------+
//!      |                                 |           ^
//!      | start_connection()      send()  |           |
//!      v                                 |           |
//! +----------+                 +-------------------------------+
//! |          |                 |         |           |         |
//! | Control  | on_connect()    |   Send Queues       |         |
//! | Plane    |---------------->|         |           |         |
//! |          |                 |  +------v----+  +----------+  |
//! |          | on_disconnect() |  | Send Task |  | Receive  |  |
//! |          |<----------------|  +-----------+  | Task     |  |
//! +----------+                 |         |       +----------+  |
//!                              |         |           |         |
//!                              |         v           |         |
//!                              |  +------------+ +------------+|
//!                              |  | Connection | | Connection ||
//!                              |  | Write Half | | Read Half  ||
//!                              |  +------------+ +------------+|
//!                              |     Data Plane                |
//!                              +-------------------------------+
//! ```

use crate::metrics::{ControlPlaneMetrics, DataPlaneMetrics, SendQueueMetrics};
use crate::types::TransportImpl;
use ic_base_types::{NodeId, RegistryVersion};
use ic_config::transport::TransportConfig;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces_transport::{
    Transport, TransportChannelId, TransportError, TransportEventHandler, TransportPayload,
};
use ic_logger::{info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Weak};
use tokio::{
    runtime::Handle,
    sync::{Mutex, RwLock},
};

impl TransportImpl {
    /// Creates a new Transport instance
    fn new(
        node_id: NodeId,
        config: TransportConfig,
        latest_registry_version: RegistryVersion,
        earliest_registry_version: RegistryVersion,
        metrics_registry: MetricsRegistry,
        crypto: Arc<dyn TlsHandshake + Send + Sync>,
        rt_handle: Handle,
        log: ReplicaLogger,
        use_h2: bool,
    ) -> Arc<Self> {
        let node_ip = IpAddr::from_str(&config.node_ip)
            .unwrap_or_else(|_| panic!("Invalid node IP: {}", &config.node_ip));
        let arc = Arc::new(Self {
            node_id,
            node_ip,
            config,
            allowed_clients: RwLock::new(BTreeSet::<NodeId>::new()),
            crypto,
            latest_registry_version: RwLock::new(latest_registry_version),
            earliest_registry_version: RwLock::new(earliest_registry_version),
            rt_handle,
            data_plane_metrics: DataPlaneMetrics::new(metrics_registry.clone()),
            control_plane_metrics: ControlPlaneMetrics::new(metrics_registry.clone()),
            send_queue_metrics: SendQueueMetrics::new(metrics_registry),
            log,
            peer_map: tokio::sync::RwLock::new(HashMap::new()),
            accept_port: Mutex::new(None),
            event_handler: Mutex::new(None),
            weak_self: std::sync::RwLock::new(Weak::new()),
            use_h2,
        });
        *arc.weak_self.write().unwrap() = Arc::downgrade(&arc);
        arc
    }
}

/// Returns the production implementation of the `Transport` interfaces.
pub fn create_transport(
    node_id: NodeId,
    transport_config: TransportConfig,
    latest_registry_version: RegistryVersion,
    earliest_registry_version: RegistryVersion,
    metrics_registry: MetricsRegistry,
    crypto: Arc<dyn TlsHandshake + Send + Sync>,
    rt_handle: Handle,
    log: ReplicaLogger,
    use_h2: bool,
) -> Arc<dyn Transport> {
    TransportImpl::new(
        node_id,
        transport_config,
        latest_registry_version,
        earliest_registry_version,
        metrics_registry,
        crypto,
        rt_handle,
        log,
        use_h2,
    )
}

/// Trait implementation for
/// [`Transport`](../../ic_interfaces/transport/trait.Transport.html).
impl Transport for TransportImpl {
    fn set_event_handler(&self, event_handler: TransportEventHandler) {
        self.init_client(event_handler)
    }

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
    fn start_connection(
        &self,
        peer_id: &NodeId,
        peer_addr: SocketAddr,
        latest_registry_version: RegistryVersion,
        earliest_registry_version: RegistryVersion,
    ) {
        info!(
            self.log,
            "Transport::start_connection(): peer_id = {:?}", peer_id
        );
        self.start_peer_connection(
            peer_id,
            peer_addr,
            latest_registry_version,
            earliest_registry_version,
        );
    }

    /// Remove the peer from the set of valid neighbors, and tear down the
    /// queues and connections for the peer. Any messages in the Tx and Rx
    /// queues for the peer will be discarded.
    /// It is fine to call the function on non-existing connection(s).
    fn stop_connection(&self, peer_id: &NodeId) {
        info!(
            self.log,
            "Transport::stop_connection(): peer_id = {:?}", peer_id,
        );
        self.stop_peer_connection(peer_id);
    }

    fn send(
        &self,
        peer_id: &NodeId,
        _channel_id: TransportChannelId,
        message: TransportPayload,
    ) -> Result<(), TransportError> {
        let peer_map = self.peer_map.blocking_read();
        let peer_state_mu = match peer_map.get(peer_id) {
            Some(peer_state) => peer_state,
            None => return Err(TransportError::NotFound),
        };
        let peer_state = peer_state_mu.blocking_read();
        match peer_state.send_queue.enqueue(message) {
            Some(unsent) => Err(TransportError::SendQueueFull(unsent)),
            None => Ok(()),
        }
    }

    fn clear_send_queues(&self, peer_id: &NodeId) {
        let mut peer_map = self.peer_map.blocking_write();
        let peer_state = peer_map
            .get_mut(peer_id)
            .expect("Transport client not found");
        peer_state.blocking_write().send_queue.clear();
    }
}
