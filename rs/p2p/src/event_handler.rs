//! An asynchronous event handler for interacting with the Gossip
//! layer.
//!
//! P2P receives events as network messages from the Transport layer (delivering
//! IC internal messages) and the HttpHandler (delivering ingress messages)
//! layer.
//!
//!```text
//!                +-----------------------------+
//!                |     HttpHandler(Ingress)    |
//!                +-----------------------------+
//!                |    IngressEventHandler{}    |
//!                +------------v----------------+
//!                |       P2P/Gossip            |
//!                +----^----------------^-------+
//!                | AsyncTranportEventHandler{} |
//!                +-----------------------------+
//!                |        Transport            |
//!                +-----------------------------+
//! ```
//!
//! Internally, P2P treats event streams as flows. Each flow is
//! represented as a message queue implemented over an asynchronous
//! channel. The channel implements back pressure by having a bounded
//! number of buffers. There are 5 flows: advert, request,
//! re-transmission, chunk, and ingress. The first four flows are
//! received from the *Gossip* peer network and ingress flow is received
//! from the http handler.
//!
//! Flow control/back pressure for transport throttles/suspends the
//! inflow of messages to match the p2p flow consumption rate.
//! Receiver-side back pressure throttles/suspends the drainage of
//! messages from the transport socket buffers. If the sender-side transport
//! queue becomes full, messages are dropped in the *Gossip* layer.
//! i.e., there are no retries/wait for transport queues to free up.
//! Receiver-side flow channels and sender-side transport queues have sufficient
//! backlog/buffer capacity to ensure that nodes communicating as per the
//! protocol specification will not experience any message drops due to
//! back pressure under favorable network conditions.
//!
//! Flow control for ingress messages is based on admission control in
//! the ingress pool. The ingress pool is fixed in size. This fixed size ensures
//! that the available bandwidth is shared between the user-ingress flow and
//! *Gossip* network flows.
//!
//! There is a flow control message queue per peer and per flow. Thus, each flow
//! from a peer can be independently controlled. The P2P event handler
//! employs 1 synchronous thread to serve each flow type across
//! peers. The flow thread goes through all connected peers in a round-robin
//! fashion.
//!
//! Note that the ingress flow is emulated as a flow originating from the node
//! itself.
//!
//!```text
//! +------+---------+                          +------+----+-------------+
//! |Arc<Mutex<<Map>>|                          | Arc<Mutex<<Map>>        |
//! +------+---------+                          +------+----+-------------+
//! |NodeId|Send     |                          |NodeId|Rcv |             |
//! +------+---------+                          +------+----+ Thread      |
//! |1     |Send     |<--Queues(Size:Backlog)-->|1     |Rcv | Process     |
//! +------+---------+                          +------+----+ Message(T)  |
//! |2     |...      |                          |2     |... |             |
//! +------+---------+                          +------+----+             |
//! |3..   |Send     |                          |3..   |Rcv |             |
//! +------+---------+                          +------+----+-------------+
//!
//!      PeerFlowQueueMap: A single flow being addressed by 1 thread.
//! ```
use crate::{
    advert_utils::AdvertRequestBuilder,
    gossip_protocol::{
        Gossip, GossipAdvertSendRequest, GossipChunk, GossipChunkRequest, GossipMessage,
        GossipRetransmissionRequest,
    },
    metrics::EventHandlerMetrics,
};
use async_trait::async_trait;
use futures::future::select_all;
use futures::future::FutureExt;
use ic_interfaces::{
    ingress_pool::IngressPoolThrottler,
    registry::RegistryClient,
    transport::{AsyncTransportEventHandler, SendError},
};
use ic_logger::{info, replica_logger::ReplicaLogger, trace};
use ic_metrics::MetricsRegistry;
use ic_protobuf::{p2p::v1 as pb, proxy::ProtoProxy, registry::subnet::v1::GossipConfig};
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_types::transport::{TransportError, TransportErrorCode, TransportFlowInfo};
use ic_types::{
    artifact::AdvertClass,
    canonical_error::{unavailable_error, CanonicalError},
    messages::SignedIngress,
    p2p::GossipAdvert,
    transport::{FlowId, TransportNotification, TransportPayload, TransportStateChange},
    NodeId, SubnetId,
};
use std::{
    cmp::max,
    collections::BTreeMap,
    convert::{Infallible, TryInto},
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    task::{Context, Poll},
    thread::JoinHandle,
    vec::Vec,
};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use tokio::{
    sync::mpsc::{
        channel, error::TrySendError, unbounded_channel, Receiver, Sender, UnboundedReceiver,
        UnboundedSender,
    },
    time::timeout,
};
use tower_service::Service;

/// The trait for P2P event handler control, exposing methods to start and stop
/// control, as well as add nodes.
#[async_trait]
pub(crate) trait P2PEventHandlerControl: Send + Sync {
    /// The method adds/registers a peer node with the event handler.
    ///
    /// The P2P event handler implementation maintains per-peer-per-flow queues
    /// to process messages. Each flow type is backed by a dedicated
    /// processing thread. Messages from nodes that have not been registered
    /// are dropped. Thus, valid nodes must be added to the event handler
    /// before any network processing starts.
    fn add_node(&self, node_id: NodeId);
}

/// Fetch the Gossip configuration from the registry.
pub fn fetch_gossip_config(
    registry_client: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
) -> GossipConfig {
    if let Ok(Some(Some(gossip_config))) =
        registry_client.get_gossip_config(subnet_id, registry_client.get_latest_version())
    {
        gossip_config
    } else {
        ic_types::p2p::build_default_gossip_config()
    }
}

/// The different flow types.
#[derive(EnumIter, PartialOrd, Ord, Eq, PartialEq)]
enum FlowType {
    /// Advert variant.
    Advert,
    /// Advert request variant.
    Request,
    /// Advert request variant.
    Chunk,
    /// Retransmission request variant.
    Retransmission,
    /// *Transport* state change variant.
    Transport,
    /// Send advert variant.
    SendAdvert,
}

/// This type contains the (node ID, receiver) pairs.
type ReceiveMap<T> = Vec<(NodeId, Receiver<T>)>; // Exclusive ownership
/// This type contains the (node ID, sender) pairs. Since access is shared, it
/// uses a read-write lock.
type SendMap<T> = Arc<RwLock<BTreeMap<NodeId, Sender<T>>>>; // Shared

// We use tokio channel for adding peers because the sender can running
// either in async or sync.
type AddPeer<T> = (NodeId, Receiver<T>);
type AddPeerSender<T> = UnboundedSender<AddPeer<T>>;
type AddPeerReceiver<T> = UnboundedReceiver<AddPeer<T>>;

/// A *Gossip* type with atomic reference counting.
pub type GossipArc = Arc<
    dyn Gossip<
            GossipAdvert = GossipAdvert,
            GossipChunkRequest = GossipChunkRequest,
            GossipChunk = GossipChunk,
            NodeId = NodeId,
            TransportNotification = TransportNotification,
            Ingress = SignedIngress,
        > + Send
        + Sync,
>;

/// The struct maps from node IDs to bounded flows.
/// It also encapsulates the processing of received messages.
struct PeerFlowQueueMap<T: Send + 'static + Debug> {
    rt_handle: tokio::runtime::Handle,
    /// Flow End-points need to be thread-safe to support concurrent node
    /// addition and polling.
    send_map: SendMap<T>,
    /// The sender of management commands.
    add_peer_sender: AddPeerSender<T>,
    /// The receive task handle, in a Mutex for interior mutability.
    receive_task_handle: Mutex<Option<JoinHandle<()>>>,
    /// The management command receiver, in a Mutex for interior mutability.
    add_peer_receiver: Mutex<Option<AddPeerReceiver<T>>>,
    cancelled: Arc<AtomicBool>,
}

impl<T: Send + 'static + Debug> PeerFlowQueueMap<T> {
    fn new(rt_handle: tokio::runtime::Handle) -> Self {
        let (add_peer_sender, add_peer_receiver) = unbounded_channel();
        Self {
            rt_handle,
            send_map: Arc::new(RwLock::new(BTreeMap::new())),
            add_peer_sender,
            add_peer_receiver: Mutex::new(Some(add_peer_receiver)),
            receive_task_handle: Mutex::new(None),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl<T: Send + 'static + Debug> PeerFlowQueueMap<T> {
    /// The method starts the processing of messages in the `PeerFlowQueueMap`.
    fn start<F>(&self, fn_consume_message: F)
    where
        F: Fn(T, NodeId) + Clone + Send + 'static,
    {
        let mgmt_cmd_receive = self.add_peer_receiver.lock().unwrap().take().unwrap();
        let rt_handle = self.rt_handle.clone();
        let cancelled = Arc::clone(&self.cancelled);
        let recv_task_handle = std::thread::Builder::new()
            .name("PeerFlow".to_string())
            .spawn(move || {
                rt_handle.block_on(async move {
                    Self::process_messages(mgmt_cmd_receive, fn_consume_message, cancelled).await;
                });
            })
            .unwrap();

        self.receive_task_handle
            .lock()
            .unwrap()
            .replace(recv_task_handle)
            .ok_or(0)
            .expect_err("Handler already started");
    }

    /// The function processes received messages.
    ///
    /// The event handler loop calls `select()` on receivers and dispatch.
    async fn process_messages<F>(
        mut add_peer_receiver: AddPeerReceiver<T>,
        fn_consume_message: F,
        cancelled: Arc<AtomicBool>,
    ) where
        F: Fn(T, NodeId) + Clone + 'static + Send,
    {
        let mut receive_map: ReceiveMap<T> = Vec::with_capacity(MAX_PEERS_HINT);
        let receive_duration = tokio::time::Duration::from_millis(500);
        while !cancelled.load(Ordering::Relaxed) {
            if let Ok((node_id, receiver)) = add_peer_receiver.try_recv() {
                receive_map.push((node_id, receiver));
                continue;
            }

            let receive_futures = receive_map
                .iter_mut()
                .map(|(_, receiver)| receiver.recv().boxed())
                .collect::<Vec<_>>();
            let received_item = match timeout(receive_duration, select_all(receive_futures)).await {
                Ok((item, idx, _rem)) => Some((item, idx)),
                _ => None,
            };

            // Process the ready channel up to `BATCH_LIMIT`.
            if let Some((Some(item), idx)) = received_item {
                let mut batch = Vec::with_capacity(BATCH_LIMIT);
                batch.push(item);

                while let Ok(item) = receive_map[idx].1.try_recv() {
                    batch.push(item);
                    if batch.len() >= BATCH_LIMIT {
                        break;
                    }
                }

                let node_id = receive_map[idx].0;
                for item in batch.into_iter() {
                    fn_consume_message(item, node_id);
                }

                // Reorder the receive map recv_map.
                let t = receive_map.remove(idx);
                receive_map.push(t);
            }
        }
    }

    /// The method adds the node with the given node ID.
    fn add_node(&self, node_id: NodeId, buffer: usize) {
        let mut send_map = self.send_map.write().unwrap();
        if let std::collections::btree_map::Entry::Vacant(e) = send_map.entry(node_id) {
            let (send, recv) = channel(max(1, buffer));
            e.insert(send);

            self.add_peer_sender
                .send((node_id, recv))
                .expect("Failed to send ManagementCommands::AddPeer command");
        }
    }

    fn stop(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
        if let Some(handle) = self.receive_task_handle.lock().unwrap().take() {
            handle.join().unwrap();
        }
    }
}

/// The peer flow struct, which contains a flow for each flow type.
struct PeerFlows {
    // A struct is used instead of an enum to allocate only the required memory.
    // Otherwise, space for the largest variant (artifact chunk) would be used.
    /// The current flows of received adverts.
    advert: PeerFlowQueueMap<GossipAdvert>,
    /// The current flows of received chunk requests.
    request: PeerFlowQueueMap<GossipChunkRequest>,
    /// The current flows of received chunk requests.
    chunk: PeerFlowQueueMap<GossipChunk>,
    /// The current flows of retransmission requests.
    retransmission: PeerFlowQueueMap<GossipRetransmissionRequest>,
    /// The current flows of adverts being sent.
    send_advert: PeerFlowQueueMap<GossipAdvertSendRequest>,
    /// The current flows of transport notifications.
    transport: PeerFlowQueueMap<TransportNotification>,
}

impl PeerFlows {
    fn new(rt_handle: tokio::runtime::Handle) -> Self {
        Self {
            advert: PeerFlowQueueMap::<GossipAdvert>::new(rt_handle.clone()),
            request: PeerFlowQueueMap::<GossipChunkRequest>::new(rt_handle.clone()),
            chunk: PeerFlowQueueMap::<GossipChunk>::new(rt_handle.clone()),
            retransmission: PeerFlowQueueMap::<GossipRetransmissionRequest>::new(rt_handle.clone()),
            send_advert: PeerFlowQueueMap::<GossipAdvertSendRequest>::new(rt_handle.clone()),
            transport: PeerFlowQueueMap::<TransportNotification>::new(rt_handle),
        }
    }

    /// The method starts the P2P event handler loop for the individual flow
    /// types.
    pub fn start(&self, gossip: GossipArc) {
        for flow_type in FlowType::iter() {
            let c_gossip = gossip.clone();
            match flow_type {
                FlowType::Advert => {
                    self.advert.start(move |item, peer_id| {
                        c_gossip.on_advert(item, peer_id);
                    });
                }
                FlowType::Request => {
                    self.request.start(move |item, peer_id| {
                        c_gossip.on_chunk_request(item, peer_id);
                    });
                }
                FlowType::Chunk => {
                    self.chunk.start(move |item, peer_id| {
                        c_gossip.on_chunk(item, peer_id);
                    });
                }
                FlowType::Retransmission => {
                    self.retransmission.start(move |item, peer_id| {
                        c_gossip.on_retransmission_request(item, peer_id);
                    });
                }
                FlowType::Transport => {
                    self.transport.start(move |item, _peer_id| match item {
                        TransportNotification::TransportStateChange(state_change) => {
                            c_gossip.on_transport_state_change(state_change)
                        }
                        TransportNotification::TransportError(error) => {
                            c_gossip.on_transport_error(error)
                        }
                    });
                }
                FlowType::SendAdvert => {
                    self.send_advert
                        .start(move |item, _peer_id| c_gossip.broadcast_advert(item));
                }
            }
        }
    }

    /// The method adds a node with the given node ID and channel configuration.
    fn add_node(&self, node_id: NodeId, channel_config: &ChannelConfig) {
        for flow_type in FlowType::iter() {
            let flow_type = &flow_type;
            match flow_type {
                FlowType::Advert => self.advert.add_node(node_id, channel_config.map[flow_type]),
                FlowType::Request => self
                    .request
                    .add_node(node_id, channel_config.map[flow_type]),
                FlowType::Chunk => self.chunk.add_node(node_id, channel_config.map[flow_type]),
                FlowType::Retransmission => self
                    .retransmission
                    .add_node(node_id, channel_config.map[flow_type]),
                FlowType::Transport => self
                    .transport
                    .add_node(node_id, channel_config.map[flow_type]),
                FlowType::SendAdvert => self
                    .send_advert
                    .add_node(node_id, channel_config.map[flow_type]),
            };
        }
    }

    /// The method stops the flows for each flow type.
    fn stop(&self) {
        for flow_type in FlowType::iter() {
            let flow_type = &flow_type;
            match flow_type {
                FlowType::Advert => self.advert.stop(),
                FlowType::Request => self.request.stop(),
                FlowType::Chunk => self.chunk.stop(),
                FlowType::Retransmission => self.retransmission.stop(),
                FlowType::Transport => self.transport.stop(),
                FlowType::SendAdvert => self.send_advert.stop(),
            };
        }
    }
}

/// The ingress throttler is protected by a read-write lock for concurrent
/// access.
pub type IngressThrottler = Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>;
/// The struct implements the async event handler traits for consumption by
/// transport, ingress, artifact manager, and node addition/removal.
pub struct P2PEventHandlerImpl {
    /// The replica node ID.
    node_id: NodeId,
    /// The logger.
    log: ReplicaLogger,
    /// The event handler metrics.
    pub metrics: EventHandlerMetrics,
    /// The channel configuration.
    channel_config: ChannelConfig,
    /// The peer flows.
    peer_flows: PeerFlows,
    /// For advert send requests from artifact manager.
    advert_builder: AdvertRequestBuilder,
}

/// This constant specifies the expected maximum number of peers.
const MAX_PEERS_HINT: usize = 100;
/// Messages are processed in batches with a size of at most this constant.
const BATCH_LIMIT: usize = 100;

/// The maximum number of buffered adverts.
pub(crate) const MAX_ADVERT_BUFFER: usize = 100_000;
/// The maximum number of buffered *Transport* notification messages.
pub(crate) const MAX_TRANSPORT_BUFFER: usize = 1000;
/// The maximum number of buffered retransmission requests.
pub(crate) const MAX_RETRANSMISSION_BUFFER: usize = 1000;

/// The channel configuration, containing the maximum number of messages for
/// each flow type.
#[derive(Default)]
struct ChannelConfig {
    /// The map from flow type to the maximum number of buffered messages.
    map: BTreeMap<FlowType, usize>,
}

/// A `GossipConfig` can be converted into a `ChannelConfig`.
impl From<GossipConfig> for ChannelConfig {
    /// The function converts a `GossipConfig` to a `ChannelConfig`.
    fn from(gossip_config: GossipConfig) -> Self {
        let max_outstanding_buffer = gossip_config
            .max_artifact_streams_per_peer
            .try_into()
            .unwrap();
        Self {
            map: FlowType::iter()
                .map(|flow_type| match flow_type {
                    FlowType::Advert => (flow_type, MAX_ADVERT_BUFFER),
                    FlowType::Request => (flow_type, max_outstanding_buffer),
                    FlowType::Chunk => (flow_type, max_outstanding_buffer),
                    FlowType::Retransmission => (flow_type, MAX_RETRANSMISSION_BUFFER),
                    FlowType::Transport => (flow_type, MAX_TRANSPORT_BUFFER),
                    FlowType::SendAdvert => (flow_type, MAX_ADVERT_BUFFER),
                })
                .collect(),
        }
    }
}

impl P2PEventHandlerImpl {
    /// The function creates a `P2PEventHandlerImpl` instance.
    #[allow(dead_code, clippy::too_many_arguments)] // pending integration with P2P crate
    pub fn new(
        rt_handle: tokio::runtime::Handle,
        node_id: NodeId,
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        gossip_config: GossipConfig,
    ) -> Self {
        let handler = P2PEventHandlerImpl {
            node_id,
            log: log.clone(),
            metrics: EventHandlerMetrics::new(metrics_registry),
            advert_builder: AdvertRequestBuilder::new(
                gossip_config.advert_config.clone(),
                metrics_registry,
                log,
            ),
            channel_config: ChannelConfig::from(gossip_config),
            peer_flows: PeerFlows::new(rt_handle),
        };
        handler
            .peer_flows
            .add_node(node_id, &handler.channel_config);
        handler
    }

    /// The method starts the event processing loop, dispatching events to the
    /// *Gossip* component.
    pub fn start(&self, gossip_arc: GossipArc) {
        self.peer_flows.start(gossip_arc);
    }

    /// The method stops the event handler.
    ///
    /// This is a no-op call if the event handler has not been started.
    pub fn stop(&self) {
        self.peer_flows.stop();
    }

    async fn send_gossip_message<T>(
        &self,
        send_map: &SendMap<T>,
        peer_id: NodeId,
        msg: T,
    ) -> Result<(), SendError> {
        let sender = send_map
            .read()
            .unwrap()
            .get(&peer_id)
            .ok_or(SendError::EndpointNotFound)?
            .clone();
        let permit = match sender.try_reserve() {
            Err(_err) => {
                self.metrics.adverts_blocked.inc();
                match sender.reserve().await {
                    Ok(permit) => permit,
                    Err(_) => return Err(SendError::EndpointClosed),
                }
            }
            Ok(permit) => permit,
        };
        permit.send(msg);
        Ok(())
    }
}

impl P2PEventHandlerControl for P2PEventHandlerImpl {
    /// The method adds a node to the event handler. Messages from nodes that
    /// are not found in the peer flow maps are not processed.
    fn add_node(&self, node_id: NodeId) {
        self.peer_flows.add_node(node_id, &self.channel_config);
    }
}

/// `P2PEventHandlerImpl` implements the `AsyncTransportEventHandler` trait.
#[async_trait]
impl AsyncTransportEventHandler for P2PEventHandlerImpl {
    /// The method sends the given message on the flow associated with the given
    /// flow ID.
    async fn send_message(&self, flow: FlowId, message: TransportPayload) -> Result<(), SendError> {
        let gossip_message = <pb::GossipMessage as ProtoProxy<GossipMessage>>::proxy_decode(
            &message.0,
        )
        .map_err(|e| {
            trace!(self.log, "Deserialization failed {}", e);
            SendError::DeserializationFailed
        })?;
        let start_time = std::time::Instant::now();
        let (msg_type, ret) = match gossip_message {
            GossipMessage::Advert(msg) => {
                let send_map = &self.peer_flows.advert.send_map;
                (
                    "Advert",
                    self.send_gossip_message(send_map, flow.peer_id, msg).await,
                )
            }
            GossipMessage::ChunkRequest(msg) => {
                let send_map = &self.peer_flows.request.send_map;
                (
                    "Request",
                    self.send_gossip_message(send_map, flow.peer_id, msg).await,
                )
            }
            GossipMessage::Chunk(msg) => {
                let send_map = &self.peer_flows.chunk.send_map;
                (
                    "Chunk",
                    self.send_gossip_message(send_map, flow.peer_id, msg).await,
                )
            }
            GossipMessage::RetransmissionRequest(msg) => {
                let send_map = &self.peer_flows.retransmission.send_map;
                (
                    "Retransmission",
                    self.send_gossip_message(send_map, flow.peer_id, msg).await,
                )
            }
        };
        self.metrics
            .send_message_duration_ms
            .with_label_values(&[msg_type])
            .observe(start_time.elapsed().as_millis() as f64);
        ret
    }

    /// The method changes the state of the P2P event handler.
    async fn state_changed(&self, state_change: TransportStateChange) {
        let sender = {
            let send_map = self.peer_flows.transport.send_map.read().unwrap();
            send_map
                .get(&self.node_id)
                .expect("Self Node channel not setup")
                .clone()
        };
        sender
            .send(TransportNotification::TransportStateChange(state_change))
            .await
            .unwrap_or_else(|e| {
                // panic as we  will be blocking re-transmission requests at this point.
                panic!("Failed to dispatch transport state change {:?}", e)
            });
    }

    /// If there is a sender error, the method sends a transport error
    /// notification message on the flow associated with the given flow ID.
    async fn error(&self, flow: FlowId, error: TransportErrorCode) {
        if let TransportErrorCode::SenderErrorIndicated = error {
            let sender = {
                let send_map = self.peer_flows.transport.send_map.read().unwrap();
                send_map
                    .get(&self.node_id)
                    .expect("Self Node channel not setup")
                    .clone()
            };
            sender
                .send(TransportNotification::TransportError(
                    TransportError::TransportSendError(TransportFlowInfo {
                        peer_id: flow.peer_id,
                        flow_tag: flow.flow_tag,
                    }),
                ))
                .await
                .unwrap_or_else(|e| {
                    // Panic as we  will be blocking re-transmission requests at this point.
                    panic!("Failed to dispatch transport error {:?}", e)
                });
        }
    }
}

/// Interface between the ingress handler and P2P.
pub struct IngressEventHandler {
    /// Tokio runtime handle used for spawning ingestion tasks.
    rt_handle: tokio::runtime::Handle,
    /// The ingress throttler.
    ingress_throttler: IngressThrottler,
    /// The shared *Gossip* instance (using automatic reference counting).
    gossip: GossipArc,
    /// The node ID.
    node_id: NodeId,
}

impl IngressEventHandler {
    /// The function creates an `IngressEventHandler` instance.
    pub fn new(
        rt_handle: tokio::runtime::Handle,
        ingress_throttler: IngressThrottler,
        gossip: GossipArc,
        node_id: NodeId,
    ) -> Self {
        Self {
            rt_handle,
            ingress_throttler,
            gossip,
            node_id,
        }
    }
}

/// `IngressEventHandler` implements the `IngressEventHandler` trait.
impl Service<SignedIngress> for IngressEventHandler {
    type Response = Result<(), CanonicalError>;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// The method is called when an ingress message is received.
    fn call(&mut self, signed_ingress: SignedIngress) -> Self::Future {
        let gossip = Arc::clone(&self.gossip);
        let throttler = Arc::clone(&self.ingress_throttler);
        let node_id = self.node_id;
        let jh = self.rt_handle.spawn_blocking(move || {
            if throttler.read().unwrap().exceeds_threshold() {
                return Ok(Err(unavailable_error("Service Unavailable!".to_string())));
            }
            Ok(gossip.on_user_ingress(signed_ingress, node_id))
        });
        Box::pin(async move { jh.await.expect("Ingress ingestion task MUST NOT panic.") })
    }
}

/// This trait is used as the interface between Artifact Manager and P2P.
pub trait AdvertSubscriber {
    /// The method broadcasts the given advert.
    fn broadcast_advert(&self, advert: GossipAdvert, advert_class: AdvertClass);
}

/// `P2PEventHandlerImpl` implements the `AdvertSubscriber` trait.
impl AdvertSubscriber for P2PEventHandlerImpl {
    /// The method broadcasts the given advert.
    fn broadcast_advert(&self, advert: GossipAdvert, advert_class: AdvertClass) {
        // Translate the advert request to internal format
        let advert_request = match self.advert_builder.build(advert, advert_class) {
            Some(request) => request,
            None => return,
        };

        let sender = {
            let send_map = self.peer_flows.send_advert.send_map.read().unwrap();
            // channel for self.node_id is populated in the constructor
            send_map.get(&self.node_id).unwrap().clone()
        };
        sender
            .try_send(advert_request)
            .or_else::<TrySendError<GossipAdvert>, _>(|e| {
                if let TrySendError::Closed(_) = e {
                    info!(self.log, "Send advert channel closed");
                };
                Ok(())
            })
            .unwrap();
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub mod tests {
    use super::*;
    use crate::download_prioritization::test::make_gossip_advert;
    use ic_interfaces::ingress_pool::IngressPoolThrottler;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::{p2p::p2p_test_setup_logger, types::ids::node_test_id};
    use ic_types::artifact::AdvertClass;
    use ic_types::transport::{FlowTag, TransportClientType};
    use tokio::time::{sleep, Duration};

    struct TestThrottle();
    impl IngressPoolThrottler for TestThrottle {
        fn exceeds_threshold(&self) -> bool {
            false
        }
    }

    type ItemCountCollector = Mutex<BTreeMap<NodeId, usize>>;

    /// The test *Gossip* struct.
    struct TestGossip {
        /// The node ID.
        node_id: NodeId,
        /// The advert processing delay.
        advert_processing_delay: Duration,
        /// The item count collector, counting the number of adverts.
        num_adverts: ItemCountCollector,
        /// The item count collector, counting the number of chunks.
        num_chunks: ItemCountCollector,
        /// The item count collector, counting the number of chunk requests.
        num_reqs: ItemCountCollector,
        /// The item count collector, counting the number of ingress messages.
        num_ingress: ItemCountCollector,
        /// The item count collector, counting the number of *Transport* state
        /// changes.
        num_changes: ItemCountCollector,
        /// The item count collector, counting the number of advert broadcasts.
        num_advert_bcasts: ItemCountCollector,
    }

    impl TestGossip {
        /// The function creates a TestGossip instance.
        fn new(advert_processing_delay: Duration, node_id: NodeId) -> Self {
            TestGossip {
                node_id,
                advert_processing_delay,
                num_adverts: Default::default(),
                num_chunks: Default::default(),
                num_reqs: Default::default(),
                num_ingress: Default::default(),
                num_changes: Default::default(),
                num_advert_bcasts: Default::default(),
            }
        }

        /// The function performs an atomic increment-or-set operation.
        fn increment_or_set(map: &ItemCountCollector, peer_id: NodeId) {
            let map_i = &mut map.lock().unwrap();
            map_i.entry(peer_id).and_modify(|e| *e += 1).or_insert(1);
        }

        /// The function returns the number of flows of the node with the given
        /// node ID.
        fn get_node_flow_count(map: &ItemCountCollector, node_id: NodeId) -> usize {
            let map_i = &mut map.lock().unwrap();
            *map_i.get(&node_id).or(Some(&0)).unwrap()
        }
    }

    /// `TestGossip` implements the `Gossip` trait.
    impl Gossip for TestGossip {
        type GossipAdvert = GossipAdvert;
        type GossipChunkRequest = GossipChunkRequest;
        type GossipChunk = GossipChunk;
        type NodeId = NodeId;
        type TransportNotification = TransportNotification;
        type Ingress = SignedIngress;

        /// The method is called when an advert is received.
        fn on_advert(&self, _gossip_advert: Self::GossipAdvert, peer_id: Self::NodeId) {
            std::thread::sleep(self.advert_processing_delay);
            TestGossip::increment_or_set(&self.num_adverts, peer_id);
        }

        /// The method is called when a chunk request is received.
        fn on_chunk_request(&self, _gossip_request: GossipChunkRequest, peer_id: NodeId) {
            TestGossip::increment_or_set(&self.num_reqs, peer_id);
        }

        /// The method is called when a chunk is received.
        fn on_chunk(&self, _gossip_artifact: Self::GossipChunk, peer_id: Self::NodeId) {
            TestGossip::increment_or_set(&self.num_chunks, peer_id);
        }

        /// The method is called when a user ingress message is received.
        fn on_user_ingress(
            &self,
            _ingress: Self::Ingress,
            peer_id: Self::NodeId,
        ) -> Result<(), CanonicalError> {
            TestGossip::increment_or_set(&self.num_ingress, peer_id);
            Ok(())
        }

        /// The method broadcasts the given advert.
        fn broadcast_advert(&self, _advert: GossipAdvertSendRequest) {
            TestGossip::increment_or_set(&self.num_advert_bcasts, self.node_id);
        }

        /// The method is called when a re-transmission request is received.
        fn on_retransmission_request(
            &self,
            _gossip_request: GossipRetransmissionRequest,
            _node_id: NodeId,
        ) {
            unimplemented!()
        }

        /// The method is called when a transport state change is received.
        fn on_transport_state_change(&self, transport_state_change: TransportStateChange) {
            let peer_id = match transport_state_change {
                TransportStateChange::PeerFlowUp(x) => x,
                TransportStateChange::PeerFlowDown(x) => x,
            }
            .peer_id;
            TestGossip::increment_or_set(&self.num_changes, peer_id);
        }

        /// The method is called on a transport error.
        fn on_transport_error(&self, _transport_error: TransportError) {
            // Do nothing
        }
    }

    /// The function creates a new test event handler.
    pub(crate) fn new_test_event_handler(
        advert_max_depth: usize,
        node_id: NodeId,
    ) -> P2PEventHandlerImpl {
        let mut handler = P2PEventHandlerImpl::new(
            tokio::runtime::Handle::current(),
            node_id,
            p2p_test_setup_logger().root.clone().into(),
            &MetricsRegistry::new(),
            ic_types::p2p::build_default_gossip_config(),
        );
        handler
            .channel_config
            .map
            .insert(FlowType::Advert, advert_max_depth);
        handler
    }

    /// The function sends the given number of messages to the peer with the
    /// given node ID.
    async fn send_advert(count: usize, handler: &P2PEventHandlerImpl, peer_id: NodeId) {
        for i in 0..count {
            let message = GossipMessage::Advert(make_gossip_advert(i as u64));
            let message = TransportPayload(pb::GossipMessage::proxy_encode(message).unwrap());
            let _ = handler
                .send_message(
                    FlowId {
                        client_type: TransportClientType::P2P,
                        peer_id,
                        flow_tag: FlowTag::from(0),
                    },
                    message,
                )
                .await;
        }
    }

    /// The function broadcasts the given number of adverts.
    async fn broadcast_advert(count: usize, handler: &P2PEventHandlerImpl) {
        for i in 0..count {
            let message = make_gossip_advert(i as u64);
            handler.broadcast_advert(message, AdvertClass::Critical);
        }
    }

    /// Event handler tests.
    ///
    /// Test with the Tokio multi-threaded executor. Single-threaded
    /// execution is no longer possible as drop calls spawn and wait.
    ///
    /// This is a smoke test for starting and stopping the event handler.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_start_stop() {
        let node_test_id = node_test_id(0);
        let handler = new_test_event_handler(MAX_ADVERT_BUFFER, node_test_id);
        handler.start(Arc::new(TestGossip::new(
            Duration::from_secs(0),
            node_test_id,
        )));
        handler.stop();
    }

    /// Test the dispatching of adverts to the event handler.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_advert_dispatch() {
        let node_test_id = node_test_id(0);
        let handler = new_test_event_handler(MAX_ADVERT_BUFFER, node_test_id);
        handler.start(Arc::new(TestGossip::new(
            Duration::from_secs(0),
            node_test_id,
        )));
        send_advert(100, &handler, node_test_id).await;
        handler.stop();
    }

    /// Test slow/delayed consumption of events.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_slow_consumer() {
        let node_id = node_test_id(0);
        let handler = new_test_event_handler(1, node_id);
        handler.start(Arc::new(TestGossip::new(Duration::from_millis(3), node_id)));
        // send adverts
        send_advert(10, &handler, node_id).await;
        handler.stop();
    }

    /// Test the addition of nodes to the event handler.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_add_remove_nodes() {
        let node_id = node_test_id(0);
        let handler = Arc::new(new_test_event_handler(1, node_id));

        for node_idx in 0..64 {
            handler.add_node(node_test_id(node_idx));
        }
        handler.start(Arc::new(TestGossip::new(Duration::from_secs(0), node_id)));
        send_advert(100, &handler, node_id).await;
        handler.stop();
    }

    /// Test queuing up the maximum number of adverts.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_max_channel_capacity() {
        let node_id = node_test_id(0);
        let handler = Arc::new(new_test_event_handler(MAX_ADVERT_BUFFER, node_id));
        let node_test_id = node_test_id(0);
        let gossip_arc = Arc::new(TestGossip::new(Duration::from_secs(0), node_id));
        handler.start(gossip_arc.clone());

        send_advert(MAX_ADVERT_BUFFER, &handler, node_test_id).await;
        loop {
            let num_adverts = TestGossip::get_node_flow_count(&gossip_arc.num_adverts, node_id);
            assert!(num_adverts <= MAX_ADVERT_BUFFER);
            if num_adverts == MAX_ADVERT_BUFFER {
                break;
            }
            sleep(Duration::from_millis(1000)).await;
        }

        broadcast_advert(MAX_ADVERT_BUFFER, &handler).await;
        loop {
            let num_adverts =
                TestGossip::get_node_flow_count(&gossip_arc.num_advert_bcasts, node_id);
            assert!(num_adverts <= MAX_ADVERT_BUFFER);
            if num_adverts == MAX_ADVERT_BUFFER {
                break;
            }
            sleep(Duration::from_millis(1000)).await;
        }
    }
}
