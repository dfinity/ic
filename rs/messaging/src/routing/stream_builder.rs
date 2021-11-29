use crate::message_routing::LatencyMetrics;
use ic_base_types::NumBytes;
use ic_logger::{error, warn, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_replicated_state::replicated_state::PeekableOutputIterator;
use ic_replicated_state::Stream;
use ic_replicated_state::{
    canister_state::QUEUE_INDEX_NONE, replicated_state::ReplicatedStateMessageRouting,
    ReplicatedState,
};
use ic_types::xnet::QueueId;
use ic_types::{
    messages::{Payload, RejectContext, Request, RequestOrResponse, Response},
    user_error::RejectCode,
    CountBytes, QueueIndex, SubnetId,
};
#[cfg(test)]
use mockall::automock;
use prometheus::{Histogram, IntCounter, IntCounterVec, IntGaugeVec};
use std::sync::{Arc, Mutex};

#[cfg(test)]
mod tests;

struct StreamBuilderMetrics {
    /// Messages currently enqueued in streams, by destination subnet.
    pub stream_messages: IntGaugeVec,
    /// Stream byte size, by destination subnet.
    pub stream_bytes: IntGaugeVec,
    /// Stream begin, by destination subnet.
    pub stream_begin: IntGaugeVec,
    /// Routed XNet messages, by type and status.
    pub routed_messages: IntCounterVec,
    /// Successfully routed XNet messages' total payload size.
    pub routed_payload_sizes: Histogram,
    /// Critical error counter for detected infinite loops while routing.
    pub error_infinite_loops: IntCounter,
}

/// Desired byte size of an outgoing stream. Messages are routed to a stream
/// until its `count_bytes()` is greater than or equal to this amount.
const TARGET_STREAM_SIZE_BYTES: usize = 10 * 1024 * 1024;

const METRIC_STREAM_MESSAGES: &str = "mr_stream_messages";
const METRIC_STREAM_BYTES: &str = "mr_stream_bytes";
const METRIC_STREAM_BEGIN: &str = "mr_stream_begin";
const METRIC_ROUTED_MESSAGES: &str = "mr_routed_message_count";
const METRIC_ROUTED_PAYLOAD_SIZES: &str = "mr_routed_payload_size_bytes";

const LABEL_TYPE: &str = "type";
const LABEL_STATUS: &str = "status";
const LABEL_REMOTE: &str = "remote";
const LABEL_INFINITE_LOOP: &str = "mr_stream_builder_infinite_loop";

const LABEL_VALUE_TYPE_REQUEST: &str = "request";
const LABEL_VALUE_TYPE_RESPONSE: &str = "response";
const LABEL_VALUE_STATUS_SUCCESS: &str = "success";
const LABEL_VALUE_STATUS_CANISTER_NOT_FOUND: &str = "canister_not_found";

impl StreamBuilderMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        let stream_messages = metrics_registry.int_gauge_vec(
            METRIC_STREAM_MESSAGES,
            "Messages currently enqueued in streams, by destination subnet.",
            &[LABEL_REMOTE],
        );
        let stream_bytes = metrics_registry.int_gauge_vec(
            METRIC_STREAM_BYTES,
            "Stream byte size including header, by destination subnet.",
            &[LABEL_REMOTE],
        );
        let stream_begin = metrics_registry.int_gauge_vec(
            METRIC_STREAM_BEGIN,
            "Stream begin, by destination subnet",
            &[LABEL_REMOTE],
        );
        let routed_messages = metrics_registry.int_counter_vec(
            METRIC_ROUTED_MESSAGES,
            "Routed XNet messages, by type and status.",
            &[LABEL_TYPE, LABEL_STATUS],
        );
        let routed_payload_sizes = metrics_registry.histogram(
            METRIC_ROUTED_PAYLOAD_SIZES,
            "Successfully routed XNet messages' total payload size.",
            // 10 B - 5 MB
            decimal_buckets(1, 6),
        );
        let error_infinite_loops = metrics_registry.error_counter(LABEL_INFINITE_LOOP);
        // Initialize all `routed_messages` counters with zero, so they are all exported
        // from process start (`IntCounterVec` is really a map).
        for (msg_type, status) in &[
            (LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_STATUS_SUCCESS),
            (
                LABEL_VALUE_TYPE_REQUEST,
                LABEL_VALUE_STATUS_CANISTER_NOT_FOUND,
            ),
            (LABEL_VALUE_TYPE_RESPONSE, LABEL_VALUE_STATUS_SUCCESS),
            (
                LABEL_VALUE_TYPE_RESPONSE,
                LABEL_VALUE_STATUS_CANISTER_NOT_FOUND,
            ),
        ] {
            routed_messages.with_label_values(&[msg_type, status]);
        }

        Self {
            stream_messages,
            stream_bytes,
            stream_begin,
            routed_messages,
            routed_payload_sizes,
            error_infinite_loops,
        }
    }
}

/// Interface for the StreamBuilder sub-component.  Invoked by the
/// Coordinator.
#[cfg_attr(test, automock)]
pub(crate) trait StreamBuilder: Send {
    /// Build all streams from the messages and signals that are pending (i.e.,
    /// have been added but not yet moved into a stream.
    fn build_streams(&self, state: ReplicatedState) -> ReplicatedState;
}

pub(crate) struct StreamBuilderImpl {
    subnet_id: SubnetId,
    metrics: StreamBuilderMetrics,
    time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
    log: ReplicaLogger,
}

impl StreamBuilderImpl {
    pub(crate) fn new(
        subnet_id: SubnetId,
        metrics_registry: &MetricsRegistry,
        time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            subnet_id,
            metrics: StreamBuilderMetrics::new(metrics_registry),
            time_in_stream_metrics,
            log,
        }
    }

    /// Enqueues a reject Response to a request from a local canister into the
    /// canister's input queue.
    fn reject_local_request(
        &self,
        state: &mut ReplicatedState,
        req: Request,
        reject_code: RejectCode,
        reject_message: String,
    ) {
        state
            .push_input(
                QUEUE_INDEX_NONE,
                Response {
                    originator: req.sender,
                    respondent: req.receiver,
                    originator_reply_callback: req.sender_reply_callback,
                    refund: req.payment,
                    response_payload: Payload::Reject(RejectContext {
                        code: reject_code,
                        message: reject_message,
                    }),
                }
                .into(),
                // Arbitrary large amounts, pushing a response always returns memory.
                NumBytes::new(i64::MAX as u64 / 2),
                &mut (i64::MAX / 2),
            )
            .unwrap();
    }

    /// Records the result of routing an XNet message.
    fn observe_message_status(&self, msg: &RequestOrResponse, status: &str) {
        let msg_type = match msg {
            RequestOrResponse::Request(_) => LABEL_VALUE_TYPE_REQUEST,
            RequestOrResponse::Response(_) => LABEL_VALUE_TYPE_RESPONSE,
        };
        self.metrics
            .routed_messages
            .with_label_values(&[msg_type, status])
            .inc();
    }

    /// Records the size of a successfully routed XNet message payload.
    fn observe_payload_size(&self, msg: &RequestOrResponse) {
        let payload_size = match msg {
            RequestOrResponse::Request(req) => req.method_payload.len() as u64,
            RequestOrResponse::Response(res) => res.response_payload.size_of().get(),
        };
        self.metrics
            .routed_payload_sizes
            .observe(payload_size as f64);
    }

    /// Implementation of `StreamBuilder::build_streams()` that takes a
    /// `target_stream_size_bytes` argument to limit how many messages will be
    /// routed into each stream.
    fn build_streams_impl(
        &self,
        mut state: ReplicatedState,
        target_stream_size_bytes: usize,
    ) -> ReplicatedState {
        /// Pops the previously peeked message.
        ///
        /// Panics:
        ///  * if there is no message to pop; or
        ///  * (in debug builds) if the popped message is not the same as the
        ///    peeked one.
        fn validated_next(
            iterator: &mut dyn PeekableOutputIterator,
            (expected_id, expected_index, expected_message): (
                QueueId,
                QueueIndex,
                Arc<RequestOrResponse>,
            ),
        ) -> RequestOrResponse {
            let (queue_id, queue_index, message) = iterator.next().unwrap();
            debug_assert_eq!(
                (queue_id, queue_index, &message),
                (expected_id, expected_index, expected_message.as_ref())
            );
            message
        }

        let mut streams = state.take_streams();
        let routing_table = state.routing_table();

        let mut requests_to_reject = Vec::new();

        {
            let mut output_iter = state.output_into_iter();
            let mut last_output_size = usize::MAX;

            // Route all messages into the appropriate stream or generate reject Responses
            // when unable to (no route to canister). When a stream's byte size reaches or
            // exceeds `target_stream_size_bytes`, any matching queues are skipped.
            while let Some((queue_id, queue_index, msg)) = output_iter.peek() {
                // Safeguard to guarantee that iteration always terminates. Will always loop at
                // least once, if messages are available.
                let output_size = output_iter.size_hint().0;
                debug_assert!(output_size < last_output_size);
                if output_size == last_output_size {
                    error!(
                        self.log,
                        "Infinite loop detected in StreamBuilder::build_streams @{}.", output_size
                    );
                    self.metrics.error_infinite_loops.inc();
                    break;
                }
                last_output_size = output_size;

                let src_canister_id = queue_id.src_canister;
                let dst_canister_id = queue_id.dst_canister;

                match routing_table.route(dst_canister_id.get()) {
                    // Destination subnet found.
                    Some(dst_net_id) => {
                        if streams
                            .get(&dst_net_id)
                            .map(Stream::count_bytes)
                            .unwrap_or_default()
                            >= target_stream_size_bytes
                        {
                            // Stream full, skip all other messagees to this destination.
                            output_iter.exclude_queue();
                            continue;
                        }

                        // Route the message into the stream.
                        self.observe_message_status(&msg, LABEL_VALUE_STATUS_SUCCESS);
                        self.observe_payload_size(&msg);
                        streams.push(
                            dst_net_id,
                            validated_next(&mut output_iter, (queue_id, queue_index, msg)),
                        );
                    }

                    // Destination subnet not found.
                    None => {
                        warn!(self.log, "No route to canister {}", dst_canister_id);
                        self.observe_message_status(&msg, LABEL_VALUE_STATUS_CANISTER_NOT_FOUND);
                        match validated_next(&mut output_iter, (queue_id, queue_index, msg)) {
                            // A Request: generate a reject Response.
                            RequestOrResponse::Request(req) => {
                                requests_to_reject.push(req);
                            }
                            RequestOrResponse::Response(_) => {
                                // A Response: discard it.
                                error!(
                                    self.log,
                                    "Discarding response from canister {}.", src_canister_id
                                );
                            }
                        }
                    }
                };
            }
        }

        for req in requests_to_reject {
            let dst_canister_id = req.receiver;
            self.reject_local_request(
                &mut state,
                req,
                RejectCode::DestinationInvalid,
                format!("No route to canister {}", dst_canister_id),
            );
        }

        // Export the total number of enqueued messages and byte size, per stream.
        streams
            .iter()
            .map(|(subnet, stream)| {
                (
                    subnet.to_string(),
                    stream.messages().len(),
                    stream.count_bytes(),
                    stream.messages_begin(),
                )
            })
            .for_each(|(subnet, len, size_bytes, begin)| {
                self.metrics
                    .stream_messages
                    .with_label_values(&[&subnet])
                    .set(len as i64);
                self.metrics
                    .stream_bytes
                    .with_label_values(&[&subnet])
                    .set(size_bytes as i64);
                self.metrics
                    .stream_begin
                    .with_label_values(&[&subnet])
                    .set(begin.get() as i64);
            });

        {
            // Record the enqueuing time of any messages newly enqueued into `streams`.
            let mut time_in_stream_metrics = self.time_in_stream_metrics.lock().unwrap();
            for (subnet_id, stream) in streams.iter() {
                if *subnet_id == self.subnet_id {
                    continue;
                }
                time_in_stream_metrics.record_header(*subnet_id, &stream.header());
            }
        }

        // Put the updated CanisterStates (outgoing messages removed) and Streams
        // (messages added) into the ReplicatedState to be returned.
        state.put_streams(streams);
        state
    }
}

impl StreamBuilder for StreamBuilderImpl {
    fn build_streams(&self, state: ReplicatedState) -> ReplicatedState {
        self.build_streams_impl(state, TARGET_STREAM_SIZE_BYTES)
    }
}
