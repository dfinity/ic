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
    metrics::FlowWorkerMetrics,
};
use async_trait::async_trait;
use ic_interfaces_transport::{
    AsyncTransportEventHandler, FlowId, SendError, TransportError, TransportErrorCode,
    TransportPayload, TransportStateChange,
};
use ic_logger::{debug, info, replica_logger::ReplicaLogger, trace};
use ic_metrics::MetricsRegistry;
use ic_protobuf::{p2p::v1 as pb, proxy::ProtoProxy, registry::subnet::v1::GossipConfig};
use ic_types::{artifact::AdvertClass, p2p::GossipAdvert, NodeId};
use parking_lot::RwLock;
use std::{
    cmp::max,
    collections::BTreeMap,
    convert::TryInto,
    fmt::Debug,
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Arc, Condvar, Mutex,
    },
    thread::JoinHandle,
    time::Duration,
};
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, IntoStaticStr};
use threadpool::ThreadPool;
use tokio::sync::{Semaphore, TryAcquireError};

// Each message for each flow is being executed on the same code path. Unless those codepaths are
// lock free (which is not the case because Gossip has locks) there is no point in having more
// than 1 thread processing messages per flow.
const P2P_PER_FLOW_THREADS: usize = 1;

/// A *Gossip* type with atomic reference counting.
type GossipArc = Arc<
    dyn Gossip<
            GossipAdvert = GossipAdvert,
            GossipChunkRequest = GossipChunkRequest,
            GossipChunk = GossipChunk,
            GossipRetransmissionRequest = GossipRetransmissionRequest,
            GossipAdvertSendRequest = GossipAdvertSendRequest,
            NodeId = NodeId,
        > + Send
        + Sync,
>;

/// Flows are reliable and bidirectional channels. They must support backpressure, which prevents receivers
/// from being flooded by data from eager senders.
///
/// The FlowType enum specifies which message is passed on each flow.
#[derive(EnumIter, PartialOrd, Ord, Eq, PartialEq, IntoStaticStr)]
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
}

/// We have a single worker for all flows with the same flow type.
struct FlowWorker {
    flow_type_name: &'static str,
    /// The flow type worker metrics.
    metrics: FlowWorkerMetrics,
    /// The threadpool is used for executing messages from all flows with the
    /// given flow type.
    threadpool: Arc<Mutex<ThreadPool>>,
    /// The semaphore map used to make sure not a single peer can
    /// flood the this peer.
    sem_map: Arc<RwLock<BTreeMap<NodeId, Arc<Semaphore>>>>,
    /// The max number of inflight request for each peer.
    max_inflight_requests: usize,
}

impl FlowWorker {
    fn new(
        flow_type_name: &'static str,
        metrics: FlowWorkerMetrics,
        max_inflight_requests: usize,
    ) -> Self {
        let threadpool = threadpool::Builder::new()
            .num_threads(P2P_PER_FLOW_THREADS)
            .thread_name(format!("P2P_{}_Thread", flow_type_name))
            .build();

        Self {
            flow_type_name,
            metrics,
            threadpool: Arc::new(Mutex::new(threadpool)),
            sem_map: Arc::new(RwLock::new(BTreeMap::new())),
            max_inflight_requests,
        }
    }

    async fn execute<T: Send + 'static + Debug, F>(
        &self,
        node_id: NodeId,
        msg: T,
        consume_message_fn: F,
    ) where
        F: Fn(T, NodeId) + Clone + Send + 'static,
    {
        let send_timer = self
            .metrics
            .execute_message_duration
            .with_label_values(&[self.flow_type_name])
            .start_timer();

        let sem = self.insert_peer_semaphore_if_missing(node_id);
        // Acquiring a permit must always succeed because we never close the semaphore.
        let permit = match sem.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.metrics
                    .waiting_for_peer_permit
                    .with_label_values(&[self.flow_type_name])
                    .inc();
                sem.acquire_owned()
                    .await
                    .expect("Acquiring a permit can't fail because we never close the semaphore.")
            }
        };
        self.threadpool.lock().unwrap().execute(move || {
            let _permit = permit;
            let _send_timer = send_timer;
            consume_message_fn(msg, node_id);
        });
    }

    fn insert_peer_semaphore_if_missing(&self, node_id: NodeId) -> Arc<Semaphore> {
        if let Some(sem) = self.sem_map.read().get(&node_id) {
            return sem.clone();
        }
        let mut sem_map = self.sem_map.write();
        match sem_map.entry(node_id) {
            std::collections::btree_map::Entry::Vacant(e) => {
                let sem = Arc::new(Semaphore::new(max(1, self.max_inflight_requests)));
                e.insert(sem.clone());
                sem
            }
            std::collections::btree_map::Entry::Occupied(e) => e.get().clone(),
        }
    }
}

/// The struct implements the async event handler traits for consumption by
/// transport, ingress, artifact manager, and node addition/removal.
pub(crate) struct AsyncTransportEventHandlerImpl {
    /// The replica node ID.
    node_id: NodeId,
    /// The logger.
    log: ReplicaLogger,
    /// The peer flows.
    gossip: Arc<RwLock<Option<GossipArc>>>,

    /// The current flows of received adverts.
    advert: FlowWorker,
    /// The current flows of received chunk requests.
    request: FlowWorker,
    /// The current flows of received chunk requests.
    chunk: FlowWorker,
    /// The current flows of retransmission requests.
    retransmission: FlowWorker,
    /// The current flows of transport notifications.
    transport: FlowWorker,
}

/// The maximum number of buffered adverts.
pub(crate) const MAX_ADVERT_BUFFER: usize = 100_000;
/// The maximum number of buffered *Transport* notification messages.
pub(crate) const MAX_TRANSPORT_BUFFER: usize = 1000;
/// The maximum number of buffered retransmission requests.
pub(crate) const MAX_RETRANSMISSION_BUFFER: usize = 1000;

/// The channel configuration, containing the maximum number of messages for
/// each flow type.
#[derive(Default)]
pub(crate) struct ChannelConfig {
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
                })
                .collect(),
        }
    }
}

impl AsyncTransportEventHandlerImpl {
    pub(crate) fn new(
        node_id: NodeId,
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        channel_config: ChannelConfig,
    ) -> Self {
        let flow_worker_metrics = FlowWorkerMetrics::new(metrics_registry);
        Self {
            node_id,
            log,
            gossip: Arc::new(RwLock::new(None)),

            advert: FlowWorker::new(
                FlowType::Advert.into(),
                flow_worker_metrics.clone(),
                channel_config.map[&FlowType::Advert],
            ),
            request: FlowWorker::new(
                FlowType::Request.into(),
                flow_worker_metrics.clone(),
                channel_config.map[&FlowType::Request],
            ),
            chunk: FlowWorker::new(
                FlowType::Chunk.into(),
                flow_worker_metrics.clone(),
                channel_config.map[&FlowType::Chunk],
            ),
            retransmission: FlowWorker::new(
                FlowType::Retransmission.into(),
                flow_worker_metrics.clone(),
                channel_config.map[&FlowType::Retransmission],
            ),
            transport: FlowWorker::new(
                FlowType::Transport.into(),
                flow_worker_metrics,
                channel_config.map[&FlowType::Transport],
            ),
        }
    }

    /// The method starts the event processing loop, dispatching events to the
    /// *Gossip* component.
    pub(crate) fn start(&self, gossip_arc: GossipArc) {
        self.gossip.write().replace(gossip_arc);
    }
}

#[async_trait]
impl AsyncTransportEventHandler for AsyncTransportEventHandlerImpl {
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

        let c_gossip = self.gossip.read().as_ref().unwrap().clone();
        match gossip_message {
            GossipMessage::Advert(msg) => {
                let consume_fn = move |item, peer_id| {
                    c_gossip.on_advert(item, peer_id);
                };
                self.advert.execute(flow.peer_id, msg, consume_fn).await;
            }
            GossipMessage::ChunkRequest(msg) => {
                let consume_fn = move |item, peer_id| {
                    c_gossip.on_chunk_request(item, peer_id);
                };
                self.request.execute(flow.peer_id, msg, consume_fn).await;
            }
            GossipMessage::Chunk(msg) => {
                let consume_fn = move |item, peer_id| {
                    c_gossip.on_chunk(item, peer_id);
                };
                self.chunk.execute(flow.peer_id, msg, consume_fn).await;
            }
            GossipMessage::RetransmissionRequest(msg) => {
                let consume_fn = move |item, peer_id| {
                    c_gossip.on_retransmission_request(item, peer_id);
                };
                self.retransmission
                    .execute(flow.peer_id, msg, consume_fn)
                    .await;
            }
        };
        Ok(())
    }

    /// The method changes the state of the P2P event handler.
    async fn state_changed(&self, state_change: TransportStateChange) {
        let c_gossip = self.gossip.read().as_ref().unwrap().clone();
        let consume_fn = move |item, _peer_id| {
            c_gossip.on_transport_state_change(item);
        };
        self.transport
            .execute(self.node_id, state_change, consume_fn)
            .await;
    }

    /// If there is a sender error, the method sends a transport error
    /// notification message on the flow associated with the given flow ID.
    async fn error(&self, flow: FlowId, error: TransportErrorCode) {
        if let TransportErrorCode::SenderErrorIndicated = error {
            let c_gossip = self.gossip.read().as_ref().unwrap().clone();
            let consume_fn = move |item, _peer_id| {
                c_gossip.on_transport_error(item);
            };
            self.transport
                .execute(
                    self.node_id,
                    TransportError::TransportSendError(FlowId {
                        peer_id: flow.peer_id,
                        flow_tag: flow.flow_tag,
                    }),
                    consume_fn,
                )
                .await;
        }
    }
}

/// The struct is a handle for running a P2P thread relevant for the protocol.
/// Once dropped expect the protocol to be aborted.
pub struct P2PThreadJoiner {
    /// The task handles.
    join_handle: Option<JoinHandle<()>>,
    /// Flag indicating if P2P has been terminated.
    killed: Arc<AtomicBool>,
}

/// Periodic timer duration in milliseconds between polling calls to the P2P
/// component.
const P2P_TIMER_DURATION_MS: u64 = 100;

impl P2PThreadJoiner {
    /// The method starts the P2P timer task in the background.
    pub(crate) fn new(log: ReplicaLogger, gossip: GossipArc) -> Self {
        let killed = Arc::new(AtomicBool::new(false));
        let killed_c = Arc::clone(&killed);
        let join_handle = std::thread::Builder::new()
            .name("P2P_OnTimer_Thread".into())
            .spawn(move || {
                debug!(log, "P2P::p2p_timer(): started processing",);

                let timer_duration = Duration::from_millis(P2P_TIMER_DURATION_MS);
                while !killed_c.load(SeqCst) {
                    std::thread::sleep(timer_duration);
                    gossip.on_timer();
                }
            })
            .unwrap();
        Self {
            killed,
            join_handle: Some(join_handle),
        }
    }
}

impl Drop for P2PThreadJoiner {
    /// The method signals the tasks to exit and waits for them to complete.
    fn drop(&mut self) {
        self.killed.store(true, SeqCst);
        self.join_handle.take().unwrap().join().unwrap();
    }
}

/// The struct is used by `Consensus` to broadcast adverts. After creation a mutable
/// references must be pass to `setup_p2p` in order to activate broadcasting.
/// The `broadcast_advert` call blocks until AdvertSubscriber is activated by
/// `setup_p2p`.
#[derive(Clone)]
pub struct AdvertSubscriber {
    log: ReplicaLogger,
    threadpool: ThreadPool,
    /// The shared *Gossip* instance (using automatic reference counting).
    gossip: Arc<RwLock<Option<GossipArc>>>,
    /// For advert send requests from artifact manager.
    advert_builder: AdvertRequestBuilder,
    sem: Arc<Semaphore>,
    started: Arc<(Mutex<bool>, Condvar)>,
}

#[allow(clippy::mutex_atomic)]
impl AdvertSubscriber {
    pub fn new(
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        gossip_config: GossipConfig,
    ) -> Self {
        let threadpool = threadpool::Builder::new()
            .num_threads(P2P_PER_FLOW_THREADS)
            .thread_name("P2P_Advert_Thread".into())
            .build();

        Self {
            log: log.clone(),
            threadpool,
            gossip: Arc::new(RwLock::new(None)),

            advert_builder: AdvertRequestBuilder::new(
                gossip_config.advert_config,
                metrics_registry,
                log,
            ),
            sem: Arc::new(Semaphore::new(MAX_ADVERT_BUFFER)),
            started: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    pub(crate) fn start(&self, gossip_arc: GossipArc) {
        self.gossip.write().replace(gossip_arc);
        let (lock, cvar) = &*self.started;
        *lock.lock().unwrap() = true;
        cvar.notify_one();
    }

    /// The method broadcasts the given advert.
    pub fn broadcast_advert(&self, advert: GossipAdvert, advert_class: AdvertClass) {
        let (lock, cvar) = &*self.started;
        let mut started = lock.lock().unwrap();
        while !*started {
            started = cvar.wait(started).unwrap();
        }

        // Translate the advert request to internal format
        let advert_request = match self.advert_builder.build(advert, advert_class) {
            Some(request) => request,
            None => return,
        };
        match self.sem.clone().try_acquire_owned() {
            Ok(permit) => {
                let c_gossip = self.gossip.read().as_ref().unwrap().clone();
                self.threadpool.execute(move || {
                    let _permit = permit;
                    c_gossip.broadcast_advert(advert_request);
                });
            }
            Err(TryAcquireError::Closed) => {
                info!(self.log, "Send advert channel closed");
            }
            _ => (),
        };
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub mod tests {
    use super::*;
    use crate::{
        download_prioritization::test::make_gossip_advert,
        gossip_protocol::{GossipAdvertSendRequest, GossipRetransmissionRequest},
    };
    use ic_interfaces::ingress_pool::IngressPoolThrottler;
    use ic_interfaces_transport::FlowTag;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::{p2p::p2p_test_setup_logger, types::ids::node_test_id};
    use ic_types::artifact::AdvertClass;
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
        type GossipRetransmissionRequest = GossipRetransmissionRequest;
        type GossipAdvertSendRequest = GossipAdvertSendRequest;
        type NodeId = NodeId;

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

        fn on_timer(&self) {
            // Do nothing
        }
    }

    /// The function creates a new test event handler.
    pub(crate) fn new_test_event_handler(
        advert_max_depth: usize,
        node_id: NodeId,
    ) -> (AsyncTransportEventHandlerImpl, AdvertSubscriber) {
        let mut channel_config = ChannelConfig::from(ic_types::p2p::build_default_gossip_config());
        channel_config
            .map
            .insert(FlowType::Advert, advert_max_depth);

        let handler = AsyncTransportEventHandlerImpl::new(
            node_id,
            p2p_test_setup_logger().root.clone().into(),
            &MetricsRegistry::new(),
            channel_config,
        );

        let advert_subscriber = AdvertSubscriber::new(
            p2p_test_setup_logger().root.clone().into(),
            &MetricsRegistry::new(),
            ic_types::p2p::build_default_gossip_config(),
        );

        (handler, advert_subscriber)
    }

    /// The function sends the given number of messages to the peer with the
    /// given node ID.
    async fn send_advert(count: usize, handler: &AsyncTransportEventHandlerImpl, peer_id: NodeId) {
        for i in 0..count {
            let message = GossipMessage::Advert(make_gossip_advert(i as u64));
            let message = TransportPayload(pb::GossipMessage::proxy_encode(message).unwrap());
            let _ = handler
                .send_message(
                    FlowId {
                        peer_id,
                        flow_tag: FlowTag::from(0),
                    },
                    message,
                )
                .await;
        }
    }

    /// The function broadcasts the given number of adverts.
    async fn broadcast_advert(count: usize, handler: &AdvertSubscriber) {
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
        let handler = new_test_event_handler(MAX_ADVERT_BUFFER, node_test_id).0;
        handler.start(Arc::new(TestGossip::new(
            Duration::from_secs(0),
            node_test_id,
        )));
    }

    /// Test the dispatching of adverts to the event handler.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_advert_dispatch() {
        let node_test_id = node_test_id(0);
        let handler = new_test_event_handler(MAX_ADVERT_BUFFER, node_test_id).0;
        handler.start(Arc::new(TestGossip::new(
            Duration::from_secs(0),
            node_test_id,
        )));
        send_advert(100, &handler, node_test_id).await;
    }

    /// Test slow/delayed consumption of events.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_slow_consumer() {
        let node_id = node_test_id(0);
        let handler = new_test_event_handler(1, node_id).0;
        handler.start(Arc::new(TestGossip::new(Duration::from_millis(3), node_id)));
        // send adverts
        send_advert(10, &handler, node_id).await;
    }

    /// Test the addition of nodes to the event handler.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_add_remove_nodes() {
        let node_id = node_test_id(0);
        let handler = Arc::new(new_test_event_handler(1, node_id).0);

        handler.start(Arc::new(TestGossip::new(Duration::from_secs(0), node_id)));
        send_advert(100, &handler, node_id).await;
    }

    /// Test queuing up the maximum number of adverts.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_max_channel_capacity() {
        let node_id = node_test_id(0);
        let (handler, subscriber) = new_test_event_handler(MAX_ADVERT_BUFFER, node_id);
        let handler = Arc::new(handler);
        let node_test_id = node_test_id(0);
        let gossip_arc = Arc::new(TestGossip::new(Duration::from_secs(0), node_id));
        handler.start(gossip_arc.clone());
        subscriber.start(gossip_arc.clone());

        send_advert(MAX_ADVERT_BUFFER, &handler, node_test_id).await;
        loop {
            let num_adverts = TestGossip::get_node_flow_count(&gossip_arc.num_adverts, node_id);
            assert!(num_adverts <= MAX_ADVERT_BUFFER);
            if num_adverts == MAX_ADVERT_BUFFER {
                break;
            }
            sleep(Duration::from_millis(1000)).await;
        }

        broadcast_advert(MAX_ADVERT_BUFFER, &subscriber).await;
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
