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
//! on_connnect(flow_id, socket_read_half, socket_write_half)
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
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces::transport::{AsyncTransportEventHandler, Transport};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_types::transport::{FlowTag, TransportConfig, TransportErrorCode, TransportPayload};
use ic_types::{NodeId, RegistryVersion};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock, Weak};
use tokio::runtime::Handle;

impl TransportImpl {
    /// Creates a new Transport instance
    fn new(
        node_id: NodeId,
        config: TransportConfig,
        registry_version: RegistryVersion,
        metrics_registry: MetricsRegistry,
        crypto: Arc<dyn TlsHandshake + Send + Sync>,
        tokio_runtime: Handle,
        log: ReplicaLogger,
    ) -> Arc<Self> {
        let node_ip = IpAddr::from_str(&config.node_ip)
            .unwrap_or_else(|_| panic!("Invalid node IP: {}", &config.node_ip));
        let arc = Arc::new(Self {
            node_id,
            node_ip,
            config,
            allowed_clients: Arc::new(RwLock::new(BTreeSet::<NodeId>::new())),
            crypto,
            registry_version: Arc::new(RwLock::new(registry_version)),
            tokio_runtime,
            data_plane_metrics: DataPlaneMetrics::new(metrics_registry.clone()),
            control_plane_metrics: ControlPlaneMetrics::new(metrics_registry.clone()),
            send_queue_metrics: SendQueueMetrics::new(metrics_registry),
            log,
            client_map: RwLock::new(None),
            weak_self: RwLock::new(Weak::new()),
        });
        *arc.weak_self.write().unwrap() = Arc::downgrade(&arc);
        arc
    }
}

/// Returns the production implementation of the `Transport` interfaces.
pub fn create_transport(
    node_id: NodeId,
    transport_config: TransportConfig,
    registry_version: RegistryVersion,
    metrics_registry: MetricsRegistry,
    crypto: Arc<dyn TlsHandshake + Send + Sync>,
    tokio_runtime: Handle,
    log: ReplicaLogger,
) -> Arc<dyn Transport> {
    TransportImpl::new(
        node_id,
        transport_config,
        registry_version,
        metrics_registry,
        crypto,
        tokio_runtime,
        log,
    )
}

/// Trait implementation for
/// [`Transport`](../../ic_interfaces/transport/trait.Transport.html).
impl Transport for TransportImpl {
    fn register_client(
        &self,
        event_handler: Arc<dyn AsyncTransportEventHandler>,
    ) -> Result<(), TransportErrorCode> {
        self.init_client(event_handler)
    }

    fn start_connections(
        &self,
        peer_id: &NodeId,
        node_record: &NodeRecord,
        registry_version: RegistryVersion,
    ) -> Result<(), TransportErrorCode> {
        self.start_peer_connections(peer_id, node_record, registry_version)
    }

    fn stop_connections(&self, peer_id: &NodeId) -> Result<(), TransportErrorCode> {
        self.stop_peer_connections(peer_id)
    }

    fn send(
        &self,
        peer_id: &NodeId,
        flow_tag: FlowTag,
        message: TransportPayload,
    ) -> Result<(), TransportErrorCode> {
        let client_map = self.client_map.read().unwrap();
        let client_state = match client_map.as_ref() {
            Some(client_state) => client_state,
            None => return Err(TransportErrorCode::TransportClientNotFound),
        };
        let peer_state = match client_state.peer_map.get(peer_id) {
            Some(peer_state) => peer_state,
            None => return Err(TransportErrorCode::TransportClientNotFound),
        };
        let flow_state = match peer_state.flow_map.get(&flow_tag) {
            Some(flow_state) => flow_state,
            None => return Err(TransportErrorCode::FlowNotFound),
        };
        match flow_state.send_queue.enqueue(message) {
            Some(unsent) => Err(TransportErrorCode::TransportBusy(unsent)),
            None => Ok(()),
        }
    }

    fn clear_send_queues(&self, peer_id: &NodeId) {
        let client_map = self.client_map.read().unwrap();
        let client_state = client_map.as_ref().expect("Transport client not found");
        let peer_state = client_state
            .peer_map
            .get(peer_id)
            .expect("Transport client not found");
        peer_state
            .flow_map
            .iter()
            .for_each(|(_flow_id, flow_state)| {
                flow_state.send_queue.clear();
            });
    }

    fn clear_send_queue(&self, peer_id: &NodeId, flow_tag: FlowTag) {
        let client_map = self.client_map.read().unwrap();
        let client_state = client_map.as_ref().expect("Transport client not found");
        let peer_state = client_state
            .peer_map
            .get(peer_id)
            .expect("Transport client not found");
        peer_state
            .flow_map
            .iter()
            .for_each(|(flow_id, flow_state)| {
                if flow_id.eq(&flow_tag) {
                    flow_state.send_queue.clear();
                }
            });
    }
}
