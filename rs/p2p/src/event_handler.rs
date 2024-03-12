//! An asynchronous event handler for interacting with the Gossip
//! layer.
//!
//! P2P receives events as network messages from the Transport layer (delivering
//! IC internal messages) and the HttpHandler (delivering ingress messages)
//! layer.
//!
//!```text
//!                +------------------------------+
//!                |      HttpHandler(Ingress)    |
//!                +------------------------------+
//!                |     IngressEventHandler{}    |
//!                +------------v-----------------+
//!                |        P2P/Gossip            |
//!                +-----^----------------^-------+
//!                | AsyncTransportEventHandler{} |
//!                +------------------------------+
//!                |         Transport            |
//!                +------------------------------+
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
    gossip_protocol::Gossip,
    gossip_types::{GossipChunk, GossipChunkRequest, GossipMessage},
    metrics::FlowWorkerMetrics,
};
use ic_interfaces_transport::{TransportEvent, TransportMessage};
use ic_logger::{replica_logger::ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_protobuf::{proxy::ProtoProxy, types::v1 as pb};
use ic_types::{artifact::ArtifactFilter, p2p::GossipAdvert, NodeId};
use parking_lot::Mutex;
use std::{
    cmp::max,
    collections::BTreeMap,
    convert::Infallible,
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, IntoStaticStr};
use threadpool::ThreadPool;
use tokio::sync::Semaphore;
use tower::Service;

// Each message for each flow is being executed on the same code path. Unless those codepaths are
// lock free (which is not the case because Gossip has locks) there is no point in having more
// than 1 thread processing messages per flow.
const P2P_PER_FLOW_THREADS: usize = 1;

/// A *Gossip* type with atomic reference counting.
pub(crate) type GossipArc = Arc<
    dyn Gossip<
            GossipAdvert = GossipAdvert,
            GossipChunkRequest = GossipChunkRequest,
            GossipChunk = GossipChunk,
            GossipRetransmissionRequest = ArtifactFilter,
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
#[derive(Clone)]
struct FlowWorker {
    flow_type_name: &'static str,
    /// The flow type worker metrics.
    metrics: FlowWorkerMetrics,
    /// The threadpool is used for executing messages from all flows with the
    /// given flow type.
    threadpool: Arc<Mutex<ThreadPool>>,
    /// The semaphore map used to make sure not a single peer can
    /// flood the this peer.
    sem: Arc<Semaphore>,
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
            sem: Arc::new(Semaphore::new(max(1, max_inflight_requests))),
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

        // Acquiring a permit must always succeed because we never close the semaphore.
        let sem = self.sem.clone();
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
        self.threadpool.lock().execute(move || {
            let _permit = permit;
            let _send_timer = send_timer;
            consume_message_fn(msg, node_id);
        });
    }
}

/// The struct implements the async event handler traits for consumption by
/// transport, ingress, artifact manager, and node addition/removal.
#[derive(Clone)]
pub(crate) struct AsyncTransportEventHandlerImpl {
    /// The replica node ID.
    node_id: NodeId,
    /// The logger.
    log: ReplicaLogger,
    /// The peer flows.
    gossip: GossipArc,

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
pub const MAX_ADVERT_BUFFER: usize = 100_000;

/// The channel configuration, containing the maximum number of messages for
/// each flow type.
pub(crate) struct ChannelConfig {
    /// The map from flow type to the maximum number of buffered messages.
    map: BTreeMap<FlowType, usize>,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            map: FlowType::iter()
                .map(|flow_type| match flow_type {
                    FlowType::Advert => (flow_type, MAX_ADVERT_BUFFER),
                    FlowType::Request => (flow_type, 100),
                    FlowType::Chunk => (flow_type, 100),
                    FlowType::Retransmission => (flow_type, 1000),
                    FlowType::Transport => (flow_type, 1000),
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
        gossip: GossipArc,
    ) -> Self {
        let flow_worker_metrics = FlowWorkerMetrics::new(metrics_registry);
        Self {
            node_id,
            log,
            gossip,

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
}

impl Service<TransportEvent> for AsyncTransportEventHandlerImpl {
    type Response = ();
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// The method sends the given message on the flow associated with the given
    /// flow ID.
    fn call(&mut self, event: TransportEvent) -> Self::Future {
        let c_gossip = self.gossip.clone();
        match event {
            TransportEvent::Message(raw) => {
                let TransportMessage { payload, peer_id } = raw;
                let gossip_message =
                    match <pb::GossipMessage as ProtoProxy<GossipMessage>>::proxy_decode(&payload.0)
                    {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(self.log, "Deserialization failed {}", err);
                            return Box::pin(async { Ok(()) });
                        }
                    };
                match gossip_message {
                    GossipMessage::Advert(msg) => {
                        let consume_fn = move |item, peer_id| {
                            c_gossip.on_gossip_advert(item, peer_id);
                        };
                        let advert = self.advert.clone();
                        Box::pin(async move {
                            advert.execute(peer_id, msg, consume_fn).await;
                            Ok(())
                        })
                    }
                    GossipMessage::ChunkRequest(msg) => {
                        let consume_fn = move |item, peer_id| {
                            c_gossip.on_chunk_request(item, peer_id);
                        };
                        let request = self.request.clone();
                        Box::pin(async move {
                            request.execute(peer_id, msg, consume_fn).await;
                            Ok(())
                        })
                    }
                    GossipMessage::Chunk(msg) => {
                        let consume_fn = move |item, peer_id| {
                            c_gossip.on_gossip_chunk(item, peer_id);
                        };
                        let chunk = self.chunk.clone();
                        Box::pin(async move {
                            chunk.execute(peer_id, msg, consume_fn).await;
                            Ok(())
                        })
                    }
                    GossipMessage::RetransmissionRequest(msg) => {
                        let consume_fn = move |item, peer_id| {
                            c_gossip.on_gossip_retransmission_request(item, peer_id);
                        };
                        let retransmission = self.retransmission.clone();
                        Box::pin(async move {
                            retransmission.execute(peer_id, msg, consume_fn).await;
                            Ok(())
                        })
                    }
                }
            }
            TransportEvent::PeerUp(peer_id) => {
                let consume_fn = move |item, _peer_id| {
                    c_gossip.on_peer_up(item);
                };
                let node_id = self.node_id;
                let transport = self.transport.clone();
                Box::pin(async move {
                    transport.execute(node_id, peer_id, consume_fn).await;
                    Ok(())
                })
            }
            TransportEvent::PeerDown(peer_id) => {
                let consume_fn = move |item, _peer_id| {
                    c_gossip.on_peer_down(item);
                };
                let node_id = self.node_id;
                let transport = self.transport.clone();
                Box::pin(async move {
                    transport.execute(node_id, peer_id, consume_fn).await;
                    Ok(())
                })
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::download_prioritization::test::make_gossip_advert;
    use crossbeam_channel::{bounded, Sender};
    use ic_interfaces::ingress_pool::IngressPoolThrottler;
    use ic_interfaces_transport::TransportPayload;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::p2p::p2p_test_setup_logger;
    use ic_test_utilities_types::ids::node_test_id;
    use tokio::time::{sleep, Duration};

    struct TestThrottle();
    impl IngressPoolThrottler for TestThrottle {
        fn exceeds_threshold(&self) -> bool {
            false
        }
    }

    type ItemCountCollector = Mutex<BTreeMap<NodeId, usize>>;

    /// The test *Gossip* struct.
    pub(crate) struct TestGossip {
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
        /// The item count collector, counting the number of *Transport* state
        /// changes.
        num_changes: ItemCountCollector,
        /// The item count collector, counting the number of advert broadcasts.
        num_advert_bcasts: ItemCountCollector,
    }

    impl TestGossip {
        /// The function creates a TestGossip instance.
        pub(crate) fn new(advert_processing_delay: Duration, node_id: NodeId) -> Self {
            TestGossip {
                node_id,
                advert_processing_delay,
                num_adverts: Default::default(),
                num_chunks: Default::default(),
                num_reqs: Default::default(),
                num_changes: Default::default(),
                num_advert_bcasts: Default::default(),
            }
        }

        /// The function performs an atomic increment-or-set operation.
        fn increment_or_set(map: &ItemCountCollector, peer_id: NodeId) {
            let map_i = &mut map.lock();
            map_i.entry(peer_id).and_modify(|e| *e += 1).or_insert(1);
        }

        /// The function returns the number of flows of the node with the given
        /// node ID.
        fn get_node_flow_count(map: &ItemCountCollector, node_id: NodeId) -> usize {
            let map_i = &mut map.lock();
            *map_i.get(&node_id).unwrap_or(&0)
        }
    }

    /// `TestGossip` implements the `Gossip` trait.
    impl Gossip for TestGossip {
        type GossipAdvert = GossipAdvert;
        type GossipChunkRequest = GossipChunkRequest;
        type GossipChunk = GossipChunk;
        type GossipRetransmissionRequest = ArtifactFilter;

        /// The method is called when an advert is received.
        fn on_gossip_advert(&self, _gossip_advert: Self::GossipAdvert, peer_id: NodeId) {
            std::thread::sleep(self.advert_processing_delay);
            TestGossip::increment_or_set(&self.num_adverts, peer_id);
        }

        /// The method is called when a chunk request is received.
        fn on_chunk_request(&self, _gossip_request: GossipChunkRequest, peer_id: NodeId) {
            TestGossip::increment_or_set(&self.num_reqs, peer_id);
        }

        /// The method is called when a chunk is received.
        fn on_gossip_chunk(&self, _gossip_artifact: Self::GossipChunk, peer_id: NodeId) {
            TestGossip::increment_or_set(&self.num_chunks, peer_id);
        }

        /// The method broadcasts the given advert.
        fn broadcast_advert(&self, _advert: Self::GossipAdvert) {
            TestGossip::increment_or_set(&self.num_advert_bcasts, self.node_id);
        }

        /// The method is called when a re-transmission request is received.
        fn on_gossip_retransmission_request(
            &self,
            _gossip_request: Self::GossipRetransmissionRequest,
            _node_id: NodeId,
        ) {
            unimplemented!()
        }

        fn on_peer_up(&self, peer_id: NodeId) {
            TestGossip::increment_or_set(&self.num_changes, peer_id);
        }

        fn on_peer_down(&self, peer_id: NodeId) {
            TestGossip::increment_or_set(&self.num_changes, peer_id);
        }

        fn on_gossip_timer(&self) {
            // Do nothing
        }
    }

    /// The function creates a new test event handler.
    pub(crate) fn new_test_event_handler(
        advert_max_depth: usize,
        node_id: NodeId,
        gossip: GossipArc,
    ) -> AsyncTransportEventHandlerImpl {
        let mut channel_config = ChannelConfig::default();
        channel_config
            .map
            .insert(FlowType::Advert, advert_max_depth);

        AsyncTransportEventHandlerImpl::new(
            node_id,
            p2p_test_setup_logger().root.clone().into(),
            &MetricsRegistry::new(),
            channel_config,
            gossip,
        )
    }

    /// The function sends the given number of messages to the peer with the
    /// given node ID.
    async fn send_advert(
        count: usize,
        handler: &mut AsyncTransportEventHandlerImpl,
        peer_id: NodeId,
    ) {
        for i in 0..count {
            let message = GossipMessage::Advert(make_gossip_advert(i as u64));
            let message = TransportPayload(pb::GossipMessage::proxy_encode(message));
            let _ = handler
                .call(TransportEvent::Message(TransportMessage {
                    peer_id,
                    payload: message,
                }))
                .await;
        }
    }

    /// The function broadcasts the given number of adverts.
    async fn broadcast_advert(count: usize, handler: &Sender<GossipAdvert>) {
        for i in 0..count {
            let message = make_gossip_advert(i as u64);
            handler.send(message).unwrap();
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
        let gossip_arc = Arc::new(TestGossip::new(Duration::from_secs(0), node_test_id));
        let _handler = new_test_event_handler(MAX_ADVERT_BUFFER, node_test_id, gossip_arc);
    }

    /// Test the dispatching of adverts to the event handler.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_advert_dispatch() {
        let node_test_id = node_test_id(0);
        let gossip_arc = Arc::new(TestGossip::new(Duration::from_secs(0), node_test_id));
        let mut handler = new_test_event_handler(MAX_ADVERT_BUFFER, node_test_id, gossip_arc);
        send_advert(100, &mut handler, node_test_id).await;
    }

    /// Test slow/delayed consumption of events.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_slow_consumer() {
        let node_id = node_test_id(0);
        let gossip_arc = Arc::new(TestGossip::new(Duration::from_millis(3), node_id));
        let mut handler = new_test_event_handler(1, node_id, gossip_arc);
        // send adverts
        send_advert(10, &mut handler, node_id).await;
    }

    /// Test the addition of nodes to the event handler.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_add_remove_peers() {
        let node_id = node_test_id(0);
        let gossip_arc = Arc::new(TestGossip::new(Duration::from_secs(0), node_id));
        let mut handler = new_test_event_handler(1, node_id, gossip_arc);
        send_advert(100, &mut handler, node_id).await;
    }

    /// Test queuing up the maximum number of adverts.
    #[tokio::test(flavor = "multi_thread")]
    async fn event_handler_max_channel_capacity() {
        let node_id = node_test_id(0);
        let node_test_id = node_test_id(0);
        let gossip_arc = Arc::new(TestGossip::new(Duration::from_secs(0), node_id));
        let mut handler = new_test_event_handler(MAX_ADVERT_BUFFER, node_id, gossip_arc.clone());
        let (subscriber, rx) = bounded(MAX_ADVERT_BUFFER);
        let _g = crate::start_p2p_event_loop(rx, gossip_arc.clone());

        send_advert(MAX_ADVERT_BUFFER, &mut handler, node_test_id).await;
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
