use crate::message_routing::LatencyMetrics;
use ic_error_types::RejectCode;
use ic_limits::SYSTEM_SUBNET_STREAM_MSG_LIMIT;
use ic_logger::{error, warn, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    replicated_state::{
        PeekableOutputIterator, ReplicatedStateMessageRouting, MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
    },
    ReplicatedState, Stream,
};
use ic_types::{
    messages::{
        Payload, RejectContext, Request, RequestOrResponse, Response,
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, MAX_REJECT_MESSAGE_LEN_BYTES,
    },
    CountBytes, SubnetId,
};
#[cfg(test)]
use mockall::automock;
use prometheus::{Histogram, IntCounter, IntCounterVec, IntGaugeVec};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[cfg(test)]
mod tests;

struct StreamBuilderMetrics {
    /// Messages currently enqueued in streams, by remote subnet.
    pub stream_messages: IntGaugeVec,
    /// Stream byte size, by remote subnet.
    pub stream_bytes: IntGaugeVec,
    /// Stream begin, by remote subnet.
    pub stream_begin: IntGaugeVec,
    /// Signals end, by remote subnet.
    pub signals_end: IntGaugeVec,
    /// Routed XNet messages, by type and status.
    pub routed_messages: IntCounterVec,
    /// Successfully routed XNet messages' total payload size.
    pub routed_payload_sizes: Histogram,
    /// Critical error counter for detected infinite loops while routing.
    pub critical_error_infinite_loops: IntCounter,
    /// Critical error for payloads above the maximum supported size.
    pub critical_error_payload_too_large: IntCounter,
    /// Critical error for responses dropped due to destination not found.
    pub critical_error_response_destination_not_found: IntCounter,
}

/// Desired byte size of an outgoing stream.
///
/// At most `MAX_STREAM_MESSAGES` are enqueued into a stream; but only until its
/// `count_bytes()` is greater than or equal to `TARGET_STREAM_SIZE_BYTES`.
const TARGET_STREAM_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of messages in a stream.
///
/// At most `MAX_STREAM_MESSAGES` are enqueued into a stream; but only until its
/// `count_bytes()` is greater than or equal to `TARGET_STREAM_SIZE_BYTES`.
const MAX_STREAM_MESSAGES: usize = 50_000;

const METRIC_STREAM_MESSAGES: &str = "mr_stream_messages";
const METRIC_STREAM_BYTES: &str = "mr_stream_bytes";
const METRIC_STREAM_BEGIN: &str = "mr_stream_begin";
const METRIC_SIGNALS_END: &str = "mr_signals_end";
const METRIC_ROUTED_MESSAGES: &str = "mr_routed_message_count";
const METRIC_ROUTED_PAYLOAD_SIZES: &str = "mr_routed_payload_size_bytes";

const LABEL_TYPE: &str = "type";
const LABEL_STATUS: &str = "status";
const LABEL_REMOTE: &str = "remote";

const LABEL_VALUE_TYPE_REQUEST: &str = "request";
const LABEL_VALUE_TYPE_RESPONSE: &str = "response";
const LABEL_VALUE_STATUS_SUCCESS: &str = "success";
const LABEL_VALUE_STATUS_CANISTER_NOT_FOUND: &str = "canister_not_found";
const LABEL_VALUE_STATUS_PAYLOAD_TOO_LARGE: &str = "payload_too_large";

const CRITICAL_ERROR_INFINITE_LOOP: &str = "mr_stream_builder_infinite_loop";
const CRITICAL_ERROR_PAYLOAD_TOO_LARGE: &str = "mr_stream_builder_payload_too_large";
const CRITICAL_ERROR_RESPONSE_DESTINATION_NOT_FOUND: &str =
    "mr_stream_builder_response_destination_not_found";

impl StreamBuilderMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        let stream_messages = metrics_registry.int_gauge_vec(
            METRIC_STREAM_MESSAGES,
            "Messages currently enqueued in streams, by remote subnet.",
            &[LABEL_REMOTE],
        );
        let stream_bytes = metrics_registry.int_gauge_vec(
            METRIC_STREAM_BYTES,
            "Stream byte size including header, by remote subnet.",
            &[LABEL_REMOTE],
        );
        let stream_begin = metrics_registry.int_gauge_vec(
            METRIC_STREAM_BEGIN,
            "Stream begin, by remote subnet",
            &[LABEL_REMOTE],
        );
        let signals_end = metrics_registry.int_gauge_vec(
            METRIC_SIGNALS_END,
            "Signals end, by remote subnet",
            &[LABEL_REMOTE],
        );
        let routed_messages = metrics_registry.int_counter_vec(
            METRIC_ROUTED_MESSAGES,
            "Routed XNet messages, by type and status.",
            &[LABEL_TYPE, LABEL_STATUS],
        );
        let routed_payload_sizes = metrics_registry.histogram(
            METRIC_ROUTED_PAYLOAD_SIZES,
            "Successfully routed XNet messages' payload sizes.",
            // 10 B - 5 MB
            decimal_buckets(1, 6),
        );
        let critical_error_infinite_loops =
            metrics_registry.error_counter(CRITICAL_ERROR_INFINITE_LOOP);
        let critical_error_payload_too_large =
            metrics_registry.error_counter(CRITICAL_ERROR_PAYLOAD_TOO_LARGE);
        let critical_error_response_destination_not_found =
            metrics_registry.error_counter(CRITICAL_ERROR_RESPONSE_DESTINATION_NOT_FOUND);
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
            signals_end,
            routed_messages,
            routed_payload_sizes,
            critical_error_infinite_loops,
            critical_error_payload_too_large,
            critical_error_response_destination_not_found,
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
        req: &Request,
        reject_code: RejectCode,
        reject_message: String,
    ) {
        state
            .push_input(
                Response {
                    originator: req.sender,
                    respondent: req.receiver,
                    originator_reply_callback: req.sender_reply_callback,
                    refund: req.payment,
                    response_payload: Payload::Reject(
                        RejectContext::new_with_message_length_limit(
                            reject_code,
                            reject_message,
                            MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
                        ),
                    ),
                    deadline: req.deadline,
                }
                .into(),
                // Arbitrary large amount, pushing a response always returns memory.
                &mut (i64::MAX / 2),
            )
            // Enqueuing a response for a local request.
            // There should never be the case of getting `CanisterStopped` or `CanisterStopping`.
            .unwrap();
    }

    /// Records the result of routing an XNet message.
    fn observe_message_status(&self, msg: &RequestOrResponse, status: &str) {
        let msg_type = match msg {
            RequestOrResponse::Request(_) => LABEL_VALUE_TYPE_REQUEST,
            RequestOrResponse::Response(_) => LABEL_VALUE_TYPE_RESPONSE,
        };
        self.observe_message_type_status(msg_type, status)
    }

    /// Records the result of routing an XNet message.
    fn observe_message_type_status(&self, msg_type: &str, status: &str) {
        self.metrics
            .routed_messages
            .with_label_values(&[msg_type, status])
            .inc();
    }

    /// Records the size of a successfully routed XNet message payload.
    fn observe_payload_size(&self, msg: &RequestOrResponse) {
        self.metrics
            .routed_payload_sizes
            .observe(msg.payload_size_bytes().get() as f64);
    }

    /// Implementation of `StreamBuilder::build_streams()` that takes a
    /// `target_stream_size_bytes` argument to limit how many messages will be
    /// routed into each stream.
    fn build_streams_impl(
        &self,
        mut state: ReplicatedState,
        max_stream_messages: usize,
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
            expected_message: &RequestOrResponse,
        ) -> RequestOrResponse {
            let message = iterator.next().unwrap();
            debug_assert_eq!(&message, expected_message);
            message
        }

        /// Tests whether a stream is over the message count limit, byte limit or (if
        /// directed at a system subnet) over `2 * SYSTEM_SUBNET_STREAM_MSG_LIMIT`.
        fn is_at_limit(
            stream: Option<&Stream>,
            max_stream_messages: usize,
            target_stream_size_bytes: usize,
            is_local_message: bool,
            destination_subnet_type: SubnetType,
        ) -> bool {
            let stream = match stream {
                Some(stream) => stream,
                None => return false,
            };
            let stream_messages_len = stream.messages().len();

            if stream_messages_len >= max_stream_messages
                || stream.count_bytes() >= target_stream_size_bytes
            {
                // At limit if message count or byte size limits (enforced across all outgoing
                // streams) are hit.
                return true;
            }

            // At limit if system subnet limit is hit. This is only enforced for non-local
            // streams to system subnets (i.e., excluding the loopback stream on system
            // subnets).
            !is_local_message
                && destination_subnet_type == SubnetType::System
                && stream_messages_len >= 2 * SYSTEM_SUBNET_STREAM_MSG_LIMIT
        }

        let mut streams = state.take_streams();
        let routing_table = state.routing_table();
        let subnet_types: BTreeMap<_, _> = state
            .metadata
            .network_topology
            .subnets
            .iter()
            .map(|(subnet_id, topology)| (*subnet_id, topology.subnet_type))
            .collect();

        let mut requests_to_reject = Vec::new();
        let mut oversized_requests = Vec::new();

        let mut output_iter = state.output_into_iter();
        let mut last_output_size = usize::MAX;

        // Route all messages into the appropriate stream or generate reject Responses
        // when unable to (no route to canister). When a stream's byte size reaches or
        // exceeds `target_stream_size_bytes`, any matching queues are skipped.
        while let Some(msg) = output_iter.peek() {
            // Cheap to clone, `RequestOrResponse` wraps `Arcs`.
            let msg = msg.clone();
            // Safeguard to guarantee that iteration always terminates. Will always loop at
            // least once, if messages are available.
            let output_size = output_iter.size();
            debug_assert!(output_size < last_output_size);
            if output_size >= last_output_size {
                error!(
                    self.log,
                    "{}: Infinite loop detected in StreamBuilder::build_streams @{}.",
                    CRITICAL_ERROR_INFINITE_LOOP,
                    output_size
                );
                self.metrics.critical_error_infinite_loops.inc();
                break;
            }
            last_output_size = output_size;

            match routing_table.route(msg.receiver().get()) {
                // Destination subnet found.
                Some(dst_subnet_id) => {
                    if is_at_limit(
                        streams.get(&dst_subnet_id),
                        max_stream_messages,
                        target_stream_size_bytes,
                        self.subnet_id == dst_subnet_id,
                        *subnet_types
                            .get(&dst_subnet_id)
                            .unwrap_or(&SubnetType::Application),
                    ) {
                        // Stream full, skip all other messages to this destination.
                        output_iter.exclude_queue();
                        continue;
                    }

                    // We will route (or reject) the message, pop it.
                    let mut msg = validated_next(&mut output_iter, &msg);

                    // Reject messages with oversized payloads, as they may
                    // cause streams to permanently stall.
                    match msg {
                        // Remote request above the payload size limit.
                        RequestOrResponse::Request(req)
                            if dst_subnet_id != self.subnet_id
                                && req.payload_size_bytes()
                                    > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES =>
                        {
                            warn!(
                                self.log,
                                "Request payload size ({}) exceeds maximum allowed size: {:?}.",
                                req.payload_size_bytes(),
                                req
                            );
                            self.observe_message_type_status(
                                LABEL_VALUE_TYPE_REQUEST,
                                LABEL_VALUE_STATUS_PAYLOAD_TOO_LARGE,
                            );
                            oversized_requests.push(req);
                        }

                        // Response above the payload size limit.
                        RequestOrResponse::Response(ref mut rep)
                            if rep.payload_size_bytes() > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES =>
                        {
                            error!(
                                self.log,
                                "{}: Response payload size ({}) exceeds maximum allowed size: {:?}.",
                                CRITICAL_ERROR_PAYLOAD_TOO_LARGE,
                                rep.payload_size_bytes(),
                                rep
                            );
                            self.metrics.critical_error_payload_too_large.inc();
                            self.observe_message_type_status(
                                LABEL_VALUE_TYPE_RESPONSE,
                                LABEL_VALUE_STATUS_PAYLOAD_TOO_LARGE,
                            );

                            let rep = Arc::make_mut(rep);
                            match &mut rep.response_payload {
                                // Replace oversized data payloads with reject payloads.
                                Payload::Data(_) => {
                                    rep.response_payload = Payload::Reject(RejectContext::new(
                                        RejectCode::CanisterError,
                                        format!(
                                            "Canister {} violated contract: attempted to send a message of size {} exceeding the limit {}",
                                            rep.respondent, rep.payload_size_bytes(), MAX_INTER_CANISTER_PAYLOAD_IN_BYTES
                                        ),
                                    ))
                                }
                                // Truncate error messages of oversized reject payloads.
                                &mut Payload::Reject(ref mut context @ RejectContext { .. }) => {
                                    rep.response_payload = Payload::Reject(RejectContext::new_with_message_length_limit(context.code(), context.message(), MAX_REJECT_MESSAGE_LEN_BYTES));
                                }
                            }

                            streams.push(dst_subnet_id, msg);
                        }

                        _ => {
                            // Route the message into the stream.
                            self.observe_message_status(&msg, LABEL_VALUE_STATUS_SUCCESS);
                            self.observe_payload_size(&msg);
                            streams.push(dst_subnet_id, msg);
                        }
                    };
                }

                // Destination subnet not found.
                None => {
                    warn!(self.log, "No route to canister {}", msg.receiver());
                    self.observe_message_status(&msg, LABEL_VALUE_STATUS_CANISTER_NOT_FOUND);
                    match validated_next(&mut output_iter, &msg) {
                        // A Request: generate a reject Response.
                        RequestOrResponse::Request(req) => {
                            requests_to_reject.push(req);
                        }
                        RequestOrResponse::Response(rep) => {
                            // A Response: discard it.
                            error!(
                                self.log,
                                "{}: Discarding response, destination not found: {:?}",
                                CRITICAL_ERROR_RESPONSE_DESTINATION_NOT_FOUND,
                                rep
                            );
                            self.metrics
                                .critical_error_response_destination_not_found
                                .inc();
                        }
                    }
                }
            };
        }
        drop(output_iter);

        for req in requests_to_reject {
            let dst_canister_id = req.receiver;
            self.reject_local_request(
                &mut state,
                &req,
                RejectCode::DestinationInvalid,
                format!("No route to canister {}", dst_canister_id),
            );
        }

        for req in oversized_requests {
            let sender = req.sender;
            self.reject_local_request(
                &mut state,
                &req,
                RejectCode::CanisterError,
                format!(
                    "Canister {} violated contract: attempted to send a message of size {} exceeding the limit {}",
                    sender,
                    req.payload_size_bytes(),
                    MAX_INTER_CANISTER_PAYLOAD_IN_BYTES
                ),
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
                    stream.signals_end(),
                )
            })
            .for_each(|(subnet, len, size_bytes, begin, signals_end)| {
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
                self.metrics
                    .signals_end
                    .with_label_values(&[&subnet])
                    .set(signals_end.get() as i64);
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
        self.build_streams_impl(state, MAX_STREAM_MESSAGES, TARGET_STREAM_SIZE_BYTES)
    }
}
