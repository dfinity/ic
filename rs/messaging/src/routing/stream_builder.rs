use crate::message_routing::{
    CRITICAL_ERROR_ILLEGAL_ENGINE_MESSAGE, CRITICAL_ERROR_INDUCT_RESPONSE_FAILED, LatencyMetrics,
    MessageRoutingMetrics,
};
use ic_error_types::RejectCode;
use ic_logger::{ReplicaLogger, debug, error, warn};
use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::replicated_state::{
    MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN, PeekableOutputIterator, ReplicatedStateMessageRouting,
};
use ic_replicated_state::{ReplicatedState, StateError, Stream};
use ic_types::messages::{
    MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, MAX_REJECT_MESSAGE_LEN_BYTES, NO_DEADLINE, Payload,
    RejectContext, Request, RequestOrResponse, Response, StreamMessage,
};
use ic_types::{CountBytes, SubnetId};
use ic_types_cycles::{CompoundCycles, Cycles};
#[cfg(test)]
use mockall::automock;
use prometheus::{Histogram, IntCounter, IntCounterVec, IntGaugeVec};
use std::collections::{BTreeMap, BTreeSet, btree_map};
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
    /// Signals currently enqueued in streams, by remote subnet.
    pub stream_signals: IntGaugeVec,
    /// Signals end, by remote subnet.
    pub signals_end: IntGaugeVec,
    /// Routed XNet messages, by type and status.
    pub routed_messages: IntCounterVec,
    /// Successfully routed XNet messages' total payload size.
    pub routed_payload_sizes: Histogram,
    /// Misrouted messages currently in streams, by remote subnet.
    pub stream_misrouted_messages: IntGaugeVec,
    /// Critical error for payloads above the maximum supported size.
    pub critical_error_payload_too_large: IntCounter,
    /// Critical error for responses dropped due to destination not found.
    pub critical_error_response_destination_not_found: IntCounter,
    /// Critical error counter (see [`MetricsRegistry::error_counter`]) tracking
    /// failures to induct responses.
    pub critical_error_induct_response_failed: IntCounter,
    /// Critical error for messages that should never have reached an engine
    /// boundary (e.g. a refund or a guaranteed-response/cycle-bearing response),
    /// indicating that an earlier engine-boundary check failed.
    pub critical_error_engine_message: IntCounter,
}

const METRIC_STREAM_MESSAGES: &str = "mr_stream_messages";
const METRIC_STREAM_BYTES: &str = "mr_stream_bytes";
const METRIC_STREAM_BEGIN: &str = "mr_stream_begin";
const METRIC_STREAM_SIGNALS: &str = "mr_stream_signals";
const METRIC_SIGNALS_END: &str = "mr_signals_end";
const METRIC_ROUTED_MESSAGES: &str = "mr_routed_message_count";
const METRIC_ROUTED_PAYLOAD_SIZES: &str = "mr_routed_payload_size_bytes";
const METRIC_STREAM_MISROUTED_MESSAGES: &str = "mr_stream_misrouted_messages";

const LABEL_TYPE: &str = "type";
const LABEL_STATUS: &str = "status";
const LABEL_REMOTE: &str = "remote";

const LABEL_VALUE_TYPE_REQUEST: &str = "request";
const LABEL_VALUE_TYPE_RESPONSE: &str = "response";
const LABEL_VALUE_TYPE_REFUND: &str = "refund";
const LABEL_VALUE_STATUS_SUCCESS: &str = "success";
const LABEL_VALUE_STATUS_CANISTER_NOT_FOUND: &str = "canister_not_found";
const LABEL_VALUE_STATUS_PAYLOAD_TOO_LARGE: &str = "payload_too_large";
const LABEL_VALUE_STATUS_ENGINE_NOT_ALLOWED: &str = "engine_not_allowed";

const CRITICAL_ERROR_PAYLOAD_TOO_LARGE: &str = "mr_stream_builder_payload_too_large";
const CRITICAL_ERROR_RESPONSE_DESTINATION_NOT_FOUND: &str =
    "mr_stream_builder_response_destination_not_found";

impl StreamBuilderMetrics {
    pub fn new(
        metrics_registry: &MetricsRegistry,
        message_routing_metrics: &MessageRoutingMetrics,
    ) -> Self {
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
        let stream_signals = metrics_registry.int_gauge_vec(
            METRIC_STREAM_SIGNALS,
            "Signals currently enqueued in streams, by remote subnet.",
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
        let stream_misrouted_messages= metrics_registry.int_gauge_vec(
            METRIC_STREAM_MISROUTED_MESSAGES,
            "Count of misrouted messages in streams, by remote subnet. Only populated for subnets currently involved in a canister migration.",
            &[LABEL_REMOTE],
        );
        let critical_error_payload_too_large =
            metrics_registry.error_counter(CRITICAL_ERROR_PAYLOAD_TOO_LARGE);
        let critical_error_response_destination_not_found =
            metrics_registry.error_counter(CRITICAL_ERROR_RESPONSE_DESTINATION_NOT_FOUND);
        let critical_error_induct_response_failed = message_routing_metrics
            .critical_error_induct_response_failed
            .clone();
        let critical_error_engine_message = message_routing_metrics
            .critical_error_engine_message
            .clone();
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
            (LABEL_VALUE_TYPE_REFUND, LABEL_VALUE_STATUS_SUCCESS),
            (
                LABEL_VALUE_TYPE_REFUND,
                LABEL_VALUE_STATUS_CANISTER_NOT_FOUND,
            ),
        ] {
            routed_messages.with_label_values(&[msg_type, status]);
        }

        Self {
            stream_messages,
            stream_bytes,
            stream_begin,
            stream_signals,
            signals_end,
            routed_messages,
            routed_payload_sizes,
            stream_misrouted_messages,
            critical_error_payload_too_large,
            critical_error_response_destination_not_found,
            critical_error_induct_response_failed,
            critical_error_engine_message,
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

/// Routes messages from canister output queues into streams, up to the specified limits.
///
/// At most `max_stream_messages` are enqueued into a stream; but only until its
/// `count_bytes()` is greater than or equal to `target_stream_size_bytes`.
pub(crate) struct StreamBuilderImpl {
    subnet_id: SubnetId,
    max_stream_messages: usize,
    target_stream_size_bytes: usize,
    system_subnet_stream_msg_limit: usize,
    metrics: StreamBuilderMetrics,
    time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
    log: ReplicaLogger,
}

impl StreamBuilderImpl {
    pub(crate) fn new(
        subnet_id: SubnetId,
        max_stream_messages: usize,
        target_stream_size_bytes: usize,
        system_subnet_stream_msg_limit: usize,
        metrics_registry: &MetricsRegistry,
        message_routing_metrics: &MessageRoutingMetrics,
        time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            subnet_id,
            max_stream_messages,
            target_stream_size_bytes,
            system_subnet_stream_msg_limit,
            metrics: StreamBuilderMetrics::new(metrics_registry, message_routing_metrics),
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
        let own_cost_schedule = state.get_own_cost_schedule();
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
            .map(|_| ())
            .unwrap_or_else(|(err, response)| {
                // Local request, we should never get a `CanisterNotFound`, `CanisterStopped` or
                // `NonMatchingResponse` error.
                error!(
                    self.log,
                    "{}: Failed to enqueue reject response for local request: {}\n{:?}",
                    CRITICAL_ERROR_INDUCT_RESPONSE_FAILED,
                    err,
                    response
                );
                self.metrics.critical_error_induct_response_failed.inc();
                state.observe_lost_cycles_due_to_dropped_messages(CompoundCycles::new(
                    req.payment,
                    own_cost_schedule,
                ));
            });
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

    /// Iterates over all messages in potentially relevant streams and counts how
    /// many are misrouted (mismatched source or destination subnet according to the
    /// current routing table).
    ///
    /// Only streams to or from subnets involved in migrations may enqueue misrouted
    /// messages. If this subnet is involved in a migration, we scan all its
    /// streams. Otherwise, we only scan streams to subnets involved in migrations.
    fn observe_misrouted_messages(&self, state: &ReplicatedState) {
        // Reset all gauges to zero before recounting.
        //
        // This may lead to a race condition where some keys are temporarily missing,
        // but we already have a race condition between this metric and the registry
        // version metric. We work around both by (1) aggregating over all replicas on
        // the subnet and (2) requiring the condition (no misrouted messages) to hold
        // for a while before acting on it.
        self.metrics.stream_misrouted_messages.reset();

        let canister_migrations = state.metadata.network_topology.canister_migrations.as_ref();
        if canister_migrations.is_empty() {
            return;
        }

        // Collect all subnets involved in migrations (source or destination).
        //
        // It may be sufficient to only look at "source" subnets of migrations because
        // we are looking for messages stuck in streams to OLD host subnets. But, just
        // to be safe, we collect all subnets appearing in migration traces.
        let mut subnets_with_canister_migrations = BTreeSet::new();
        for (_, trace) in canister_migrations.iter() {
            for subnet in trace {
                subnets_with_canister_migrations.insert(*subnet);
            }
        }
        let relevant_subnets = if subnets_with_canister_migrations.contains(&self.subnet_id) {
            // This subnet is the source or target of a migration, scan all its streams.
            state
                .metadata
                .streams()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
        } else {
            // This is a third-party subnet, only scan streams to subnets involved in
            // canister migrations.
            subnets_with_canister_migrations
        };

        for remote_subnet in &relevant_subnets {
            let Some(stream) = state.metadata.streams().get(remote_subnet) else {
                continue;
            };

            let mut misrouted_messages = 0;
            // Iterate over all messages in the stream
            for (_, msg) in stream.messages().iter() {
                // Check for receiver subnet mismatch.
                let receiver_host_subnet =
                    state.metadata.network_topology.route(msg.receiver().get());
                if receiver_host_subnet != Some(*remote_subnet) {
                    misrouted_messages += 1;
                    continue;
                }

                // Check for sender subnet mismatch.
                let sender_host_subnet = match msg {
                    StreamMessage::Request(req) => {
                        state.metadata.network_topology.route(req.sender.get())
                    }
                    StreamMessage::Response(resp) => {
                        state.metadata.network_topology.route(resp.originator.get())
                    }
                    StreamMessage::Refund(_) => {
                        // Refunds don't have explicit senders. Always assume they are local.
                        Some(self.subnet_id)
                    }
                };
                if sender_host_subnet != Some(self.subnet_id) {
                    misrouted_messages += 1;
                }
            }

            self.metrics
                .stream_misrouted_messages
                .with_label_values(&[&remote_subnet.to_string()])
                .set(misrouted_messages);
        }
    }

    /// Implementation of `StreamBuilder::build_streams()`.
    fn build_streams_impl(&self, mut state: ReplicatedState) -> ReplicatedState {
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

        // Tests whether a stream is over the message count limit, byte limit or (if
        // directed at a system subnet) over `2 * system_subnet_stream_msg_limit`.
        let is_at_limit = |stream: &btree_map::Entry<SubnetId, Stream>,
                           destination_subnet_type: SubnetType|
         -> bool {
            let stream = match stream {
                btree_map::Entry::Occupied(occupied_entry) => occupied_entry.get(),
                btree_map::Entry::Vacant(_) => return false,
            };
            let stream_messages_len = stream.messages().len();

            if stream_messages_len >= self.max_stream_messages
                || stream.count_bytes() >= self.target_stream_size_bytes
            {
                // At limit if message count or byte size limits (enforced across all outgoing
                // streams) are hit.
                return true;
            }

            // At limit if system subnet limit is hit. This is only enforced for non-local
            // streams to system subnets (i.e., excluding the loopback stream on system
            // subnets). And only applies to canister messages, not refunds.
            destination_subnet_type == SubnetType::System
                && stream_messages_len - stream.refund_count()
                    >= 2 * self.system_subnet_stream_msg_limit
        };

        let mut streams = state.take_streams();
        let network_topology = state.metadata.network_topology.clone();
        let own_subnet_type = state.metadata.own_subnet_type;

        // First, have up to `max_stream_messages / 2` refunds in each stream (including
        // already routed ones) while respecting stream message and byte limits.
        //
        // Refunds are smaller than the smallest possible canister message, so it makes
        // sense to prioritize routing a bounded number of refunds, leaving most of the
        // stream capacity for canister messages (5k refunds are ~250 KB, so only around
        // 2.5% of the 10 MB target stream size).
        //
        // Note that there is no need to enforce `system_subnet_stream_msg_limit` for
        // anonymous refunds, as they get applied during induction, never enqueued.
        let refund_limit = self.max_stream_messages / 2;
        self.route_refunds(&mut state, refund_limit, &network_topology, &mut streams);

        let mut requests_to_reject = Vec::new();
        let mut oversized_requests = Vec::new();
        let mut engine_requests_to_reject: Vec<Arc<Request>> = Vec::new();
        let mut engine_response_dropped_cycles = Cycles::zero();
        let mut dropped_response_cycles = Cycles::zero();
        let own_cost_schedule = state.get_own_cost_schedule();

        let mut output_iter = state.output_into_iter();

        // Route all messages into the appropriate stream or generate reject Responses
        // when unable to (no route to canister). When a stream's byte size reaches or
        // exceeds `target_stream_size_bytes`, any matching queues are skipped.
        while let Some(msg) = output_iter.peek() {
            // Cheap to clone, `RequestOrResponse` wraps `Arcs`.
            let msg = msg.clone();

            match network_topology.route(msg.receiver().get()) {
                // Destination subnet found.
                Some(dst_subnet_id) => {
                    let dst_stream_entry = streams.entry(dst_subnet_id);
                    let is_loopback_stream = self.subnet_id == dst_subnet_id;
                    if !is_loopback_stream
                        && is_at_limit(
                            &dst_stream_entry,
                            network_topology
                                .subnets()
                                .get(&dst_subnet_id)
                                .map_or(SubnetType::Application, |topology| topology.subnet_type),
                        )
                    {
                        // Stream full, skip all other messages to this destination.
                        output_iter.exclude_queue();
                        continue;
                    }

                    // We will route (or reject) the message, pop it.
                    let mut msg = validated_next(&mut output_iter, &msg);

                    let is_engine_dst = !is_loopback_stream
                        && network_topology
                            .subnets()
                            .get(&dst_subnet_id)
                            .is_some_and(|t| t.subnet_type == SubnetType::CloudEngine);
                    let is_engine_src =
                        !is_loopback_stream && own_subnet_type == SubnetType::CloudEngine;

                    // Reject messages with oversized payloads, as they may
                    // cause streams to permanently stall.
                    match msg {
                        // Request at an engine boundary: reject if unbounded-wait or carries cycles.
                        RequestOrResponse::Request(req)
                            if (is_engine_dst || is_engine_src)
                                && (req.deadline == NO_DEADLINE
                                    || req.payment > Cycles::zero()) =>
                        {
                            self.observe_message_type_status(
                                LABEL_VALUE_TYPE_REQUEST,
                                LABEL_VALUE_STATUS_ENGINE_NOT_ALLOWED,
                            );
                            engine_requests_to_reject.push(req);
                        }

                        // A response that should not exist at an engine boundary: a
                        // guaranteed-response response, or one carrying cycles. A canister
                        // can only produce such a response in reply to a guaranteed-response
                        // or cycle-bearing request it received from across the boundary -- but
                        // that request would itself have been rejected at the boundary. So
                        // reaching here means an earlier engine-boundary check failed: a bug,
                        // not something a canister can trigger on its own. Raise a critical
                        // error and strip any attached cycles (so that none cross the boundary,
                        // not even as anonymous refunds on the receiving side; they are lost).
                        // A guaranteed response is then still routed, so the waiting caller is
                        // not stranded forever; a best-effort response is dropped (the caller
                        // will time out). Kept above the oversized-response arm so that the
                        // cycle stripping always happens first.
                        RequestOrResponse::Response(ref mut rep)
                            if (is_engine_dst || is_engine_src)
                                && (rep.deadline == NO_DEADLINE || rep.refund > Cycles::zero()) =>
                        {
                            error!(
                                self.log,
                                "{}: Illegal engine-boundary response (to {}): {:?}",
                                CRITICAL_ERROR_ILLEGAL_ENGINE_MESSAGE,
                                dst_subnet_id,
                                rep,
                            );
                            self.metrics.critical_error_engine_message.inc();
                            self.observe_message_type_status(
                                LABEL_VALUE_TYPE_RESPONSE,
                                LABEL_VALUE_STATUS_ENGINE_NOT_ALLOWED,
                            );
                            let is_guaranteed_response = rep.deadline == NO_DEADLINE;
                            // Strip any attached cycles; they are lost.
                            engine_response_dropped_cycles += rep.refund;
                            if rep.refund > Cycles::zero() {
                                Arc::make_mut(rep).refund = Cycles::zero();
                            }
                            if is_guaranteed_response {
                                // Still deliver the (now cycle-free) response so the caller is
                                // not left hanging forever on our bug.
                                dst_stream_entry.or_default().push(msg.into());
                            }
                            // Best-effort illegal responses are dropped (consumed here).
                        }

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
                                            rep.respondent,
                                            rep.payload_size_bytes(),
                                            MAX_INTER_CANISTER_PAYLOAD_IN_BYTES
                                        ),
                                    ))
                                }
                                // Truncate error messages of oversized reject payloads.
                                &mut Payload::Reject(ref mut context @ RejectContext { .. }) => {
                                    rep.response_payload = Payload::Reject(
                                        RejectContext::new_with_message_length_limit(
                                            context.code(),
                                            context.message(),
                                            MAX_REJECT_MESSAGE_LEN_BYTES,
                                        ),
                                    );
                                }
                            }

                            dst_stream_entry.or_default().push(msg.into());
                        }

                        _ => {
                            // Route the message into the stream.
                            self.observe_message_status(&msg, LABEL_VALUE_STATUS_SUCCESS);
                            self.observe_payload_size(&msg);
                            dst_stream_entry.or_default().push(msg.into());
                        }
                    };
                }

                // Destination subnet not found: process the message immediately.
                // It is important to process the message immediately so that
                // `generate_reject_responses_for_deleted_subnets` does not
                // produce a response that would trigger a critical error in a subsequent
                // `build_streams` that does not expect to deal with duplicate responses.
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
                            if rep.is_best_effort() {
                                // Bounded-wait responses can be discarded silently, e.g.,
                                // when the destination subnet has been deleted.
                                debug!(
                                    self.log,
                                    "Discarding bounded-wait response, destination not found: {:?}",
                                    rep
                                );
                            } else {
                                error!(
                                    self.log,
                                    "{}: Discarding unbounded-wait response, destination not found: {:?}",
                                    CRITICAL_ERROR_RESPONSE_DESTINATION_NOT_FOUND,
                                    rep
                                );
                                self.metrics
                                    .critical_error_response_destination_not_found
                                    .inc();
                            }
                            dropped_response_cycles += rep.refund;
                        }
                    }
                }
            };
        }
        drop(output_iter);

        if !dropped_response_cycles.is_zero() {
            state.observe_lost_cycles_due_to_dropped_messages(CompoundCycles::new(
                dropped_response_cycles,
                own_cost_schedule,
            ));
        }

        for req in requests_to_reject {
            let dst_canister_id = req.receiver;
            self.reject_local_request(
                &mut state,
                &req,
                RejectCode::DestinationInvalid,
                format!("No route to canister {dst_canister_id}"),
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

        for req in engine_requests_to_reject {
            self.reject_local_request(
                &mut state,
                &req,
                RejectCode::SysFatal,
                "Unbounded-wait calls and calls with cycles are not allowed to CloudEngine subnets"
                    .to_string(),
            );
        }

        if engine_response_dropped_cycles > Cycles::zero() {
            let own_cost_schedule = state.get_own_cost_schedule();
            state.observe_lost_cycles_due_to_dropped_messages(CompoundCycles::new(
                engine_response_dropped_cycles,
                own_cost_schedule,
            ));
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
                    stream.signals_begin(),
                    stream.signals_end(),
                )
            })
            .for_each(
                |(subnet, len, size_bytes, begin, signals_begin, signals_end)| {
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
                        .stream_signals
                        .with_label_values(&[&subnet])
                        .set((signals_end - signals_begin).get() as i64);
                    self.metrics
                        .signals_end
                        .with_label_values(&[&subnet])
                        .set(signals_end.get() as i64);
                },
            );
        self.observe_misrouted_messages(&state);

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

    /// Routes up to `refund_limit` refunds per stream from `state` into `streams`.
    ///
    /// Refunds that could not be routed due to reaching the per stream limit are
    /// retained in `state`.
    fn route_refunds(
        &self,
        state: &mut ReplicatedState,
        refund_limit: usize,
        network_topology: &ic_replicated_state::NetworkTopology,
        streams: &mut BTreeMap<SubnetId, Stream>,
    ) {
        let mut cycles_lost = Cycles::zero();
        let own_cost_schedule = state.get_own_cost_schedule();
        let own_is_engine = state.metadata.own_subnet_type == SubnetType::CloudEngine;
        state.take_refunds(|refund| {
            match network_topology.route(refund.recipient().get()) {
                Some(dst_subnet_id) => {
                    let is_loopback_stream = dst_subnet_id == self.subnet_id;
                    let is_engine_dst = !is_loopback_stream
                        && network_topology
                            .subnets()
                            .get(&dst_subnet_id)
                            .is_some_and(|t| t.subnet_type == SubnetType::CloudEngine);
                    let is_engine_src = !is_loopback_stream && own_is_engine;
                    if is_engine_dst || is_engine_src {
                        // A refund destined to cross the engine boundary should not exist: a
                        // refund is only produced for a dropped cycle-bearing message, but a
                        // cycle-bearing message would itself have been rejected at the
                        // boundary. So reaching here means an earlier engine-boundary check
                        // failed: a bug, not something a canister can trigger on its own. Drop
                        // the refund (cycles lost) and raise a critical error.
                        error!(
                            self.log,
                            "{}: Dropping engine-boundary refund (to {}): {:?}",
                            CRITICAL_ERROR_ILLEGAL_ENGINE_MESSAGE,
                            dst_subnet_id,
                            refund,
                        );
                        self.metrics.critical_error_engine_message.inc();
                        cycles_lost += refund.amount();
                        self.observe_message_type_status(
                            LABEL_VALUE_TYPE_REFUND,
                            LABEL_VALUE_STATUS_ENGINE_NOT_ALLOWED,
                        );
                        return true;
                    }
                    let stream = streams.entry(dst_subnet_id).or_default();
                    if is_loopback_stream
                        || (stream.refund_count() < refund_limit
                            && stream.messages().len() < self.max_stream_messages
                            && stream.count_bytes() < self.target_stream_size_bytes)
                    {
                        stream.push(StreamMessage::Refund((*refund).into()));
                        self.observe_message_type_status(
                            LABEL_VALUE_TYPE_REFUND,
                            LABEL_VALUE_STATUS_SUCCESS,
                        );
                        true
                    } else {
                        // No more space for this refund in the stream, hold on to it.
                        false
                    }
                }

                None => {
                    error!(
                        self.log,
                        "{}: Discarding refund, destination not found: {:?}",
                        CRITICAL_ERROR_RESPONSE_DESTINATION_NOT_FOUND,
                        refund
                    );
                    self.metrics
                        .critical_error_response_destination_not_found
                        .inc();
                    cycles_lost += refund.amount();
                    self.observe_message_type_status(
                        LABEL_VALUE_TYPE_REFUND,
                        LABEL_VALUE_STATUS_CANISTER_NOT_FOUND,
                    );
                    true
                }
            }
        });
        state.observe_lost_cycles_due_to_dropped_messages(CompoundCycles::new(
            cycles_lost,
            own_cost_schedule,
        ));
    }
}

impl StreamBuilder for StreamBuilderImpl {
    fn build_streams(&self, state: ReplicatedState) -> ReplicatedState {
        self.build_streams_impl(state)
    }
}

/// Generates synthetic reject responses for callbacks to deleted subnets.
///
/// Must be called after `build_streams()`: `build_streams()` unconditionally
/// rejects any request in an output queue with no route (e.g. destined for a
/// deleted subnet), never expecting to deal with duplicate responses. Producing
/// a reject response for an unbounded-wait callback before `build_streams()` has
/// had a chance to produce a reject response for the corresponding request would
/// trigger a critical error in `build_streams()`.
///
/// Skipped if the subnet list in the network topology is unchanged since the
/// last call that successfully inducted all of its reject responses (tracked via
/// `subnet_ids_at_last_reject_generation`). On error, the subnet list is left
/// unchanged, so generation is retried on the next call; already-enqueued
/// responses are filtered out by `has_enqueued_response`, so only the callbacks
/// that failed to be inducted are retried.
pub(crate) fn generate_reject_responses_for_deleted_subnets(
    state: &mut ReplicatedState,
) -> Vec<StateError> {
    let network_topology = &state.metadata.network_topology;
    let current_subnet_ids: Vec<SubnetId> = network_topology.subnets().keys().cloned().collect();
    if state.metadata.subnet_ids_at_last_reject_generation.as_ref() == Some(&current_subnet_ids) {
        return Vec::new();
    }

    // Collect reject responses for callbacks whose respondent has no route in
    // the current network topology (i.e. is on a deleted subnet, or is the
    // management canister of a deleted subnet) and has no response enqueued yet.
    let mut rejects = Vec::new();
    for (canister_id, canister) in state.canister_states().all_iter() {
        let Some(ccm) = canister.system_state.call_context_manager() else {
            continue;
        };
        for (callback_id, callback) in ccm.callbacks().iter() {
            let respondent = callback.respondent;
            if network_topology.route(respondent.get()).is_none()
                && !canister
                    .system_state
                    .queues()
                    .has_enqueued_response(callback_id)
            {
                rejects.push(RequestOrResponse::Response(Arc::new(Response {
                    originator: *canister_id,
                    respondent,
                    originator_reply_callback: *callback_id,
                    refund: Cycles::zero(),
                    // Use the same reject code and message as canister uninstallation, but do
                    // not refund cycles here: the deleted subnet may have partially executed
                    // the request and consumed some or all of the payment/refund cycles.
                    // `RejectCode::DestinationInvalid` (as used by `build_streams()`) would not
                    // be accurate: it implies that the request was never processed, whereas here
                    // the deleted subnet may have already pulled the request from the stream
                    // without yet signaling back.
                    response_payload: Payload::Reject(
                        RejectContext::new_with_message_length_limit(
                            RejectCode::CanisterReject,
                            "Canister has been uninstalled.",
                            MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
                        ),
                    ),
                    deadline: callback.deadline,
                })));
            }
        }
    }

    // Responses never consume guaranteed-response memory: guaranteed responses fill a slot
    // reserved when the corresponding request was enqueued, and best-effort responses don't
    // use guaranteed-response memory at all (see `can_push`). Since we only push responses
    // here, the available-memory budget is never consulted, so a value of zero is safe.
    let mut available_guaranteed_response_memory = 0;
    let mut errors = Vec::new();
    for response in rejects {
        if let Err((error, _)) =
            state.push_input(response, &mut available_guaranteed_response_memory)
        {
            errors.push(error);
        }
    }
    // Only update the subnet list if all responses were successfully inducted.
    if errors.is_empty() {
        state.metadata.subnet_ids_at_last_reject_generation = Some(current_subnet_ids);
    }
    errors
}
