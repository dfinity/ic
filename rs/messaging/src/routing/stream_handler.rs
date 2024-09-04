use crate::message_routing::LatencyMetrics;
use ic_base_types::NumBytes;
use ic_certification_version::CertificationVersion;
use ic_config::execution_environment::Config as HypervisorConfig;
use ic_error_types::RejectCode;
use ic_interfaces::messaging::{
    LABEL_VALUE_CANISTER_METHOD_NOT_FOUND, LABEL_VALUE_CANISTER_NOT_FOUND,
    LABEL_VALUE_CANISTER_OUT_OF_CYCLES, LABEL_VALUE_CANISTER_STOPPED,
    LABEL_VALUE_CANISTER_STOPPING, LABEL_VALUE_INVALID_MANAGEMENT_PAYLOAD,
};
use ic_logger::{debug, error, fatal, info, trace, ReplicaLogger};
use ic_metrics::{
    buckets::{add_bucket, decimal_buckets},
    MetricsRegistry,
};
use ic_replicated_state::{
    metadata_state::{StreamHandle, Streams},
    replicated_state::{
        ReplicatedStateMessageRouting, LABEL_VALUE_QUEUE_FULL, MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
    },
    ReplicatedState, StateError,
};
use ic_types::{
    messages::{
        Payload, RejectContext, Request, RequestOrResponse, Response,
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64, MAX_RESPONSE_COUNT_BYTES,
    },
    xnet::{RejectReason, RejectSignal, StreamIndex, StreamIndexedQueue, StreamSlice},
    CanisterId, SubnetId,
};
use prometheus::{Histogram, IntCounter, IntCounterVec, IntGaugeVec};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

#[cfg(test)]
mod tests;

struct StreamHandlerMetrics {
    /// Counts of XNet message induction attempts, by message type and status.
    pub inducted_xnet_messages: IntCounterVec,
    /// Successfully inducted XNet message payload sizes.
    pub inducted_xnet_payload_sizes: Histogram,
    /// Garbage collected XNet messages.
    pub gced_xnet_messages: IntCounter,
    /// Garbage collected XNet reject signals.
    pub gced_xnet_reject_signals: IntCounter,
    /// Change in stream flags observed.
    pub stream_flags_changes: IntCounter,
    /// Backlog of XNet messages based on end in stream header and last message
    /// in slice, per subnet.
    pub xnet_message_backlog: IntGaugeVec,
    /// Critical error counter (see [`MetricsRegistry::error_counter`]) tracking the
    /// receival of bad reject signals for responses.
    pub critical_error_bad_reject_signal_for_response: IntCounter,
    /// Critical error counter (see [`MetricsRegistry::error_counter`]) tracking
    /// failures to induct responses.
    pub critical_error_induct_response_failed: IntCounter,
    /// Critical error counter (see [`MetricsRegistry::error_counter`]) tracking
    /// messages received from a subnet that is not known to host (or to have hosted
    /// according to `canister_migrations`) the sender.
    pub critical_error_sender_subnet_mismatch: IntCounter,
    /// Critical error counter (see [`MetricsRegistry::error_counter`]) tracking
    /// messages for canisters not hosted (now, or previously, according to
    /// `canister_migrations`) by this subnet.
    pub critical_error_receiver_subnet_mismatch: IntCounter,
    /// Critical error counter (see [`MetricsRegistry::error_counter`]) tracking
    /// requests for canisters misrouted by this subnet due to a problem with the
    /// routing process or a prematurely completed canister migration.
    pub critical_error_request_misrouted: IntCounter,
}

const METRIC_INDUCTED_XNET_MESSAGES: &str = "mr_inducted_xnet_message_count";
const METRIC_INDUCTED_XNET_PAYLOAD_SIZES: &str = "mr_inducted_xnet_payload_size_bytes";
const METRIC_GCED_XNET_MESSAGES: &str = "mr_gced_xnet_message_count";
const METRIC_GCED_XNET_REJECT_SIGNALS: &str = "mr_gced_xnet_reject_signal_count";
const METRIC_STREAM_FLAGS_CHANGES: &str = "mr_stream_flags_changes_count";

const METRIC_XNET_MESSAGE_BACKLOG: &str = "mr_xnet_message_backlog";

const LABEL_STATUS: &str = "status";
const LABEL_VALUE_SUCCESS: &str = "success";
const LABEL_VALUE_SENDER_SUBNET_MISMATCH: &str = "SenderSubnetMismatch";
const LABEL_VALUE_RECEIVER_SUBNET_MISMATCH: &str = "ReceiverSubnetMismatch";
const LABEL_VALUE_REQUEST_MISROUTED: &str = "RequestMisrouted";
const LABEL_VALUE_CANISTER_MIGRATED: &str = "CanisterMigrated";
const LABEL_TYPE: &str = "type";
const LABEL_VALUE_TYPE_REQUEST: &str = "request";
const LABEL_VALUE_TYPE_RESPONSE: &str = "response";
const LABEL_REMOTE: &str = "remote";

const CRITICAL_ERROR_BAD_REJECT_SIGNAL_FOR_RESPONSE: &str = "mr_bad_reject_signal_for_response";
const CRITICAL_ERROR_INDUCT_RESPONSE_FAILED: &str = "mr_induct_response_failed";
const CRITICAL_ERROR_SENDER_SUBNET_MISMATCH: &str = "mr_sender_subnet_mismatch";
const CRITICAL_ERROR_RECEIVER_SUBNET_MISMATCH: &str = "mr_receiver_subnet_mismatch";
const CRITICAL_ERROR_REQUEST_MISROUTED: &str = "mr_request_misrouted";

impl StreamHandlerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        let inducted_xnet_messages = metrics_registry.int_counter_vec(
            METRIC_INDUCTED_XNET_MESSAGES,
            "Counts of XNet message induction attempts, by message type and status.",
            &[LABEL_TYPE, LABEL_STATUS],
        );
        let inducted_xnet_payload_sizes = metrics_registry.histogram(
            METRIC_INDUCTED_XNET_PAYLOAD_SIZES,
            "Successfully inducted XNet message payload sizes.",
            // 10 B - 5 MB, plus 2 MiB (limit for XNet payloads)
            add_bucket(
                MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as f64,
                decimal_buckets(1, 6),
            ),
        );
        let gced_xnet_messages = metrics_registry.int_counter(
            METRIC_GCED_XNET_MESSAGES,
            "Garbage collected XNet messages.",
        );
        let gced_xnet_reject_signals = metrics_registry.int_counter(
            METRIC_GCED_XNET_REJECT_SIGNALS,
            "Garbage collected XNet reject signals.",
        );
        let stream_flags_changes = metrics_registry.int_counter(
            METRIC_STREAM_FLAGS_CHANGES,
            "Change in stream flags observed.",
        );
        let xnet_message_backlog = metrics_registry.int_gauge_vec(
            METRIC_XNET_MESSAGE_BACKLOG,
            "Backlog of XNet messages, by sending subnet.",
            &[LABEL_REMOTE],
        );
        let critical_error_bad_reject_signal_for_response =
            metrics_registry.error_counter(CRITICAL_ERROR_BAD_REJECT_SIGNAL_FOR_RESPONSE);
        let critical_error_induct_response_failed =
            metrics_registry.error_counter(CRITICAL_ERROR_INDUCT_RESPONSE_FAILED);
        let critical_error_sender_subnet_mismatch =
            metrics_registry.error_counter(CRITICAL_ERROR_SENDER_SUBNET_MISMATCH);
        let critical_error_receiver_subnet_mismatch =
            metrics_registry.error_counter(CRITICAL_ERROR_RECEIVER_SUBNET_MISMATCH);
        let critical_error_request_misrouted =
            metrics_registry.error_counter(CRITICAL_ERROR_REQUEST_MISROUTED);

        // Initialize all `inducted_xnet_messages` counters with zero, so they are all
        // exported from process start (`IntCounterVec` is really a map).
        for msg_type in &[LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_TYPE_RESPONSE] {
            for status in &[
                LABEL_VALUE_SUCCESS,
                LABEL_VALUE_CANISTER_NOT_FOUND,
                LABEL_VALUE_CANISTER_OUT_OF_CYCLES,
                LABEL_VALUE_CANISTER_STOPPED,
                LABEL_VALUE_CANISTER_STOPPING,
                LABEL_VALUE_QUEUE_FULL,
                LABEL_VALUE_SENDER_SUBNET_MISMATCH,
                LABEL_VALUE_REQUEST_MISROUTED,
                LABEL_VALUE_RECEIVER_SUBNET_MISMATCH,
                LABEL_VALUE_CANISTER_MIGRATED,
                LABEL_VALUE_CANISTER_METHOD_NOT_FOUND,
                LABEL_VALUE_INVALID_MANAGEMENT_PAYLOAD,
            ] {
                inducted_xnet_messages.with_label_values(&[msg_type, status]);
            }
        }

        Self {
            inducted_xnet_messages,
            inducted_xnet_payload_sizes,
            gced_xnet_messages,
            gced_xnet_reject_signals,
            stream_flags_changes,
            xnet_message_backlog,
            critical_error_bad_reject_signal_for_response,
            critical_error_induct_response_failed,
            critical_error_sender_subnet_mismatch,
            critical_error_receiver_subnet_mismatch,
            critical_error_request_misrouted,
        }
    }
}

/// Interface for the `StreamHandler` sub-component.  Invoked by `Demux`.
pub(crate) trait StreamHandler: Send {
    /// Processes `StreamSlices`. The two stages of processing are to
    ///  1. clean up streams based on the received messages/signals; and
    ///  2. induct input messages (adding outgoing signals as appropriate).
    fn process_stream_slices(
        &self,
        state: ReplicatedState,
        stream_slices: BTreeMap<SubnetId, StreamSlice>,
    ) -> ReplicatedState;
}

pub(crate) struct StreamHandlerImpl {
    subnet_id: SubnetId,

    /// The memory allocated for guaranteed response messages on the subnet.
    guaranteed_response_message_memory_capacity: NumBytes,

    metrics: StreamHandlerMetrics,
    /// Per-destination-subnet histogram of wall time spent by messages in the
    /// stream before they are garbage collected.
    time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
    /// Per-source-subnet histogram of wall time between finding out about the
    /// existence of a message from an incoming stream header; and inducting it.
    time_in_backlog_metrics: RefCell<LatencyMetrics>,

    log: ReplicaLogger,
}

impl StreamHandlerImpl {
    pub(crate) fn new(
        subnet_id: SubnetId,
        hypervisor_config: HypervisorConfig,
        metrics_registry: &MetricsRegistry,
        time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            subnet_id,
            guaranteed_response_message_memory_capacity: hypervisor_config
                .subnet_message_memory_capacity,
            metrics: StreamHandlerMetrics::new(metrics_registry),
            time_in_stream_metrics,
            time_in_backlog_metrics: RefCell::new(LatencyMetrics::new_time_in_backlog(
                metrics_registry,
            )),
            log,
        }
    }
}

impl StreamHandler for StreamHandlerImpl {
    fn process_stream_slices(
        &self,
        mut state: ReplicatedState,
        stream_slices: BTreeMap<SubnetId, StreamSlice>,
    ) -> ReplicatedState {
        trace!(self.log, "Process certified stream slices");

        {
            // Record having learned about the existence of all messages "mentioned" in
            // `stream_slices` headers.
            let mut time_in_backlog_metrics = self.time_in_backlog_metrics.borrow_mut();
            stream_slices
                .iter()
                .for_each(|(remote_subnet, stream_slice)| {
                    time_in_backlog_metrics.record_header(*remote_subnet, stream_slice.header());
                });
        }

        // A lower bound running estimate of the subnet's available guaranteed response
        // message memory. It accurately reflects all memory allocated by inducted and
        // rejected messages and released by inducting responses; but not the changes to
        // `Streams::responses_size_bytes` (the size of responses already routed to
        // streams), as some of its entries may refer to deleted or migrated canisters.
        let mut available_guaranteed_response_memory =
            self.available_guaranteed_response_memory(&state);

        // Induct our own loopback stream first, if one exists and has any messages.
        state = self.induct_loopback_stream(state, &mut available_guaranteed_response_memory);
        debug_assert!(
            self.available_guaranteed_response_memory(&state)
                >= available_guaranteed_response_memory
        );

        // Garbage collect our stream state based on the contents of the slices.
        state = self.garbage_collect_local_state(
            state,
            &mut available_guaranteed_response_memory,
            &stream_slices,
        );
        debug_assert!(
            self.available_guaranteed_response_memory(&state)
                >= available_guaranteed_response_memory
        );
        self.observe_backlog_durations(&stream_slices);

        // Induct the messages in `stream_slices`, updating signals as appropriate.
        let state = self.induct_stream_slices(
            state,
            stream_slices,
            &mut available_guaranteed_response_memory,
        );
        debug_assert!(
            self.available_guaranteed_response_memory(&state)
                >= available_guaranteed_response_memory
        );

        state
    }
}

impl StreamHandlerImpl {
    /// Inducts and consumes all messages from the subnet's loopback stream.
    ///
    /// After the call completes, the loopback stream may only contain reject
    /// responses or rerouted responses and no signals. All initial messages and
    /// corresponding signals will have been garbage collected.
    ///
    /// Updates `available_guaranteed_response_memory` to reflect change in memory
    /// usage, in such a way that it remains a lower-bound estimate of the actual
    /// available guaranteed response memory.
    ///
    /// The sequence of steps is as follows:
    ///
    /// 1. All messages in the loopback stream ("initial messages"; cloned,
    ///    wrapped within a `StreamSlice`) are inducted. See
    ///    [`Self::induct_message`] for possible outcomes.
    /// 2. Initial messages only (not including any newly appended reject
    ///    responses) are garbage collected from the loopback stream. Any
    ///    rejected `Responses` are retained for rerouting at step (4).
    /// 3. Signals for the initial messages only are garbage collected from the
    ///    loopback stream.
    /// 4. Any rejected `Responses` collected at step (2) are rerouted into the
    ///    appropriate streams as per the routing table.
    fn induct_loopback_stream(
        &self,
        mut state: ReplicatedState,
        available_guaranteed_response_memory: &mut i64,
    ) -> ReplicatedState {
        let loopback_stream = state.get_stream(&self.subnet_id);

        // All done if the loopback stream does not exist or is empty.
        if loopback_stream.is_none() || loopback_stream.unwrap().messages().is_empty() {
            return state;
        }
        let loopback_stream = loopback_stream.unwrap();

        // Precondition: ensure that the loopback stream has had signals for all
        // earlier messages.
        assert_valid_slice_messages_for_stream(
            Some(loopback_stream.messages()),
            loopback_stream.signals_end(),
            self.subnet_id,
        );

        // Wrap it within a StreamSlice.
        let loopback_stream_slice: StreamSlice = loopback_stream.clone().into();

        // 1. Induct all messages. This will add signals to the loopback stream.
        let mut stream_slices = BTreeMap::new();
        stream_slices.insert(self.subnet_id, loopback_stream_slice);
        state =
            self.induct_stream_slices(state, stream_slices, available_guaranteed_response_memory);

        let mut streams = state.take_streams();
        // We know for sure that the loopback stream exists, so it is safe to unwrap.
        let mut loopback_stream = streams.get_mut(&self.subnet_id).unwrap();

        // 2. Garbage collect all initial messages and retain any rejected messages.
        let signals_end = loopback_stream.signals_end();
        let reject_signals = loopback_stream.reject_signals().clone();
        let rejected_messages = self.garbage_collect_messages(
            &mut loopback_stream,
            self.subnet_id,
            signals_end,
            &reject_signals,
        );

        // 3. Garbage collect signals for all initial messages.
        self.discard_signals_before(&mut loopback_stream, signals_end);

        // 4. Respond to rejected requests and reroute rejected responses.
        self.handle_rejected_messages(
            rejected_messages,
            self.subnet_id,
            &mut state,
            &mut streams,
            available_guaranteed_response_memory,
        );

        state.put_streams(streams);

        #[cfg(debug_assertions)]
        {
            let loopback_stream = state.get_stream(&self.subnet_id).unwrap();
            debug_assert!(loopback_stream.reject_signals().is_empty());
            debug_assert!(loopback_stream
                .messages()
                .iter()
                .all(|(_, msg)| matches!(msg, RequestOrResponse::Response(_))));
        }

        state
    }

    /// Garbage collects outgoing `Streams` based on the headers (signals and
    /// `begin` indices) of the provided stream slices.
    fn garbage_collect_local_state(
        &self,
        mut state: ReplicatedState,
        available_guaranteed_response_memory: &mut i64,
        stream_slices: &BTreeMap<SubnetId, StreamSlice>,
    ) -> ReplicatedState {
        let mut streams = state.take_streams();
        for (remote_subnet, stream_slice) in stream_slices {
            match streams.get_mut(remote_subnet) {
                Some(mut stream) => {
                    let rejected_messages = self.garbage_collect_messages(
                        &mut stream,
                        *remote_subnet,
                        stream_slice.header().signals_end(),
                        stream_slice.header().reject_signals(),
                    );
                    self.garbage_collect_signals(&mut stream, *remote_subnet, stream_slice);

                    if stream.reverse_stream_flags() != stream_slice.header().flags() {
                        stream.set_reverse_stream_flags(*stream_slice.header().flags());
                        self.metrics.stream_flags_changes.inc();
                    }

                    // Respond to rejected requests and reroute rejected responses.
                    self.handle_rejected_messages(
                        rejected_messages,
                        *remote_subnet,
                        &mut state,
                        &mut streams,
                        available_guaranteed_response_memory,
                    );
                }
                None => {
                    // New stream.
                    assert_eq!(
                        stream_slice.header().signals_end(),
                        StreamIndex::from(0),
                        "Cannot garbage collect a stream for subnet {} that does not exist",
                        remote_subnet
                    );
                    assert_eq!(
                        stream_slice.header().begin(), StreamIndex::from(0),
                        "Signals from subnet {} do not start from 0 in the first communication attempt",
                        remote_subnet
                    );
                }
            }
            let backlog = if let Some(messages) = stream_slice.messages() {
                stream_slice.header().end() - messages.end()
            } else {
                stream_slice.header().end() - stream_slice.header().begin()
            };
            self.metrics
                .xnet_message_backlog
                .with_label_values(&[&remote_subnet.to_string()])
                .set(backlog.get() as i64);
        }
        state.put_streams(streams);
        state
    }

    /// Garbage collects the messages of an outgoing `Stream` based on the
    /// signals in an incoming stream slice. Returns any rejected messages.
    ///
    /// Panics if the slice's `signals_end` refers to a nonexistent (already
    /// garbage collected or future) message; or if `reject_signals` plus
    /// `signals_end` are invalid (not strictly increasing).
    fn garbage_collect_messages(
        &self,
        stream: &mut StreamHandle,
        remote_subnet: SubnetId,
        signals_end: StreamIndex,
        reject_signals: &VecDeque<RejectSignal>,
    ) -> Vec<(RejectReason, RequestOrResponse)> {
        assert_valid_signals(
            signals_end,
            reject_signals,
            StreamComponent::SignalsFrom(remote_subnet),
        );
        assert_valid_signals_for_messages(
            signals_end,
            stream.messages_begin(),
            stream.messages_end(),
            StreamComponent::SignalsFrom(remote_subnet),
        );

        if remote_subnet != self.subnet_id {
            // Observe the enqueuing duration of all garbage collected messages.
            let mut time_in_stream_metrics = self.time_in_stream_metrics.lock().unwrap();
            time_in_stream_metrics
                .observe_message_durations(remote_subnet, stream.messages_begin()..signals_end);
        }

        // Remove the consumed messages from our outgoing stream.
        self.observe_gced_messages(stream.messages_begin(), signals_end);
        stream.discard_messages_before(signals_end, reject_signals)
    }

    /// Garbage collects the signals of an outgoing `Stream` based on the
    /// `header.begin` of an incoming stream slice (the index of the first
    /// message of (an earlier state of) the remote stream).
    ///
    /// For received `CertifiedStreamSlice` _s_:
    ///  * remove all outgoing signals at i <=_s.begin()_
    ///
    /// Panics if the outgoing `Signals` do not left overlap or touch the
    /// `[stream_slice.header.begin, stream_slice.messages.end)` range; or
    /// if `stream_slice.messages.begin != stream.signals_end`.
    fn garbage_collect_signals(
        &self,
        stream: &mut StreamHandle,
        remote_subnet: SubnetId,
        stream_slice: &StreamSlice,
    ) {
        assert_valid_signals(
            stream.signals_end(),
            stream.reject_signals(),
            StreamComponent::SignalsTo(remote_subnet),
        );
        assert_valid_signals_for_messages(
            stream.signals_end(),
            stream_slice.header().begin(),
            stream_slice
                .messages()
                .map(|q| q.end())
                .unwrap_or_else(|| stream_slice.header().end()),
            StreamComponent::MessagesFrom(remote_subnet),
        );
        assert_valid_slice_messages_for_stream(
            stream_slice.messages(),
            stream.signals_end(),
            remote_subnet,
        );

        self.discard_signals_before(stream, stream_slice.header().begin());
    }

    /// Wrapper around `Stream::discard_signals_before()` plus telemetry.
    fn discard_signals_before(&self, stream: &mut StreamHandle, header_begin: StreamIndex) {
        let signal_count_before = stream.reject_signals().len();
        stream.discard_signals_before(header_begin);
        self.observe_gced_reject_signals(signal_count_before - stream.reject_signals().len());
    }

    /// Handles messages for which a reject signal was received:
    /// - If the message is a request, a reject response is generated and inducted into `state`.
    ///   If the reject response can not be inducted due to a canister migration, it is treated
    ///   as a rejected response (see below).
    /// - If the message is a response, it is rerouted according to the routing table into the
    ///   correspoding stream.
    ///
    /// Error cases:
    /// - A response with a `RejectReason` other than `CanisterMigrating`: guaranteed response
    ///   delivery requires that the response be rerouted; an error counter is incremented.
    fn handle_rejected_messages(
        &self,
        rejected_messages: Vec<(RejectReason, RequestOrResponse)>,
        remote_subnet_id: SubnetId,
        state: &mut ReplicatedState,
        streams: &mut Streams,
        available_guaranteed_response_memory: &mut i64,
    ) {
        fn reroute_response(
            response: RequestOrResponse,
            state: &ReplicatedState,
            streams: &mut Streams,
            log: &ReplicaLogger,
        ) {
            let new_destination = state
                .metadata
                .network_topology
                .routing_table
                .route(response.receiver().get())
                .expect("Canister disappeared from registry. Registry in an inconsistent state.");
            info!(
                log,
                "Canister {} is being migrated, rerouting to subnet {} for {:?}",
                response.receiver(),
                new_destination,
                response,
            );
            streams.get_mut_or_insert(new_destination).push(response);
        }

        for (reason, msg) in rejected_messages {
            match msg {
                RequestOrResponse::Request(ref request) => {
                    // Generate a reject response and try to induct it.
                    debug!(
                        self.log,
                        "Received reject signal '{:?}', generating reject response for {:?}",
                        reason,
                        request
                    );

                    let reject_response = generate_reject_response_for(reason, request);
                    if !self.should_accept_message_from(&reject_response, remote_subnet_id, state) {
                        // `remote_subnet_id` is not known to be a valid host for `msg.sender()`.
                        //
                        // This can only happen if the initial request was misrouted or if a
                        // canister migration was completed with in-flight messages still in the
                        // system.
                        error!(
                            self.log,
                            "{}: Dropping reject reason '{:?}' from subnet {} for request {:?}",
                            CRITICAL_ERROR_REQUEST_MISROUTED,
                            reason,
                            remote_subnet_id,
                            msg
                        );
                        self.observe_inducted_message_status(
                            LABEL_VALUE_TYPE_REQUEST,
                            LABEL_VALUE_REQUEST_MISROUTED,
                        );
                        self.metrics.critical_error_request_misrouted.inc();
                    }

                    // Try to induct the reject response.
                    match self.induct_message_impl(
                        reject_response,
                        LABEL_VALUE_TYPE_RESPONSE,
                        state,
                        available_guaranteed_response_memory,
                    ) {
                        None => {
                            // Reject response successfully inducted or dropped.
                        }
                        Some((StateError::CanisterMigrating { .. }, reject_response)) => {
                            // Canister is being migrated, reroute reject response.
                            reroute_response(reject_response, state, streams, &self.log);
                        }
                        Some(_) => {
                            unreachable!(
                                "Errors other than `CanisterMigrating` shouldn't be possible."
                            );
                        }
                    }
                }
                RequestOrResponse::Response(_) => {
                    if reason != RejectReason::CanisterMigrating {
                        // Signals other than `CanisterMigrating` shouldn't be possible for
                        // responses.
                        error!(
                            self.log,
                            "{}: Received unsupported reject reason {:?} from {} for response: {:?}",
                            CRITICAL_ERROR_BAD_REJECT_SIGNAL_FOR_RESPONSE,
                            reason,
                            remote_subnet_id,
                            msg,
                        );
                        self.metrics
                            .critical_error_bad_reject_signal_for_response
                            .inc();
                    }
                    // The policy for guaranteed responses enforces rerouting all responses
                    // regardless of signal/response pairing.
                    reroute_response(msg, state, streams, &self.log);
                }
            }
        }
    }

    /// Inducts the messages in the provided stream slices into the
    /// `InductionPool`, generating a signal for each message.
    ///
    /// See [`Self::induct_message`] for the possible outcomes of inducting a
    /// message.
    ///
    /// Updates `available_guaranteed_response_memory` to reflect change in memory
    /// usage, in such a way that it remains a lower-bound estimate of the actual
    /// available guaranteed response memory.
    fn induct_stream_slices(
        &self,
        mut state: ReplicatedState,
        stream_slices: BTreeMap<SubnetId, StreamSlice>,
        available_guaranteed_response_memory: &mut i64,
    ) -> ReplicatedState {
        let mut streams = state.take_streams();

        for (remote_subnet_id, mut stream_slice) in stream_slices {
            // Output stream, for resulting signals and (in the initial iteration) reject
            // `Responses`.
            let mut stream = streams.get_mut_or_insert(remote_subnet_id);

            while let Some((stream_index, msg)) = stream_slice.pop_message() {
                assert_eq!(
                    stream.signals_end(),
                    stream_index,
                    "Expecting signal with stream index {}, got {}",
                    stream.signals_end(),
                    stream_index
                );
                self.induct_message(
                    msg,
                    remote_subnet_id,
                    &mut state,
                    &mut stream,
                    available_guaranteed_response_memory,
                );
            }
        }

        state.put_streams(streams);
        state
    }

    /// Attempts to induct the given message at `stream_index` in the incoming
    /// stream from `remote_subnet_id` into `state`, producing a signal onto the
    /// provided reverse `stream`. The induction attempt will result in one of
    /// the following outcomes:
    ///
    ///  * `Request` or `Response` successfully inducted: accept signal appended
    ///    to the reverse stream;
    ///  * `Request` not inducted (queue full, out of memory, canister not
    ///    found, canister migrated): accept signal and reject response appended
    ///    to the reverse stream;
    ///  * `Response` not inducted (canister migrated): reject signal appended
    ///    to loopback stream (canonical versions 9+ only).
    ///  * `Request` or `Response` silently dropped and accept signal appended
    ///    to loopback stream iff:
    ///     * the sender and source subnet do not match (according to the
    ///       routing table or canister migrations); or
    ///     * the receiver is not hosted by or being migrated off of this
    ///       subnet; or
    ///     * enqueuing a `Response` failed due to the canister having been
    ///       removed.
    ///
    /// Updates `available_guaranteed_response_memory` to reflect any change in
    /// guaranteed response memory usage.
    fn induct_message(
        &self,
        msg: RequestOrResponse,
        remote_subnet_id: SubnetId,
        state: &mut ReplicatedState,
        stream: &mut StreamHandle,
        available_guaranteed_response_memory: &mut i64,
    ) {
        let msg_type = match msg {
            RequestOrResponse::Request(_) => LABEL_VALUE_TYPE_REQUEST,
            RequestOrResponse::Response(_) => LABEL_VALUE_TYPE_RESPONSE,
        };
        if self.should_accept_message_from(&msg, remote_subnet_id, state) {
            // Sender subnet is valid.
            match self.induct_message_impl(
                msg,
                msg_type,
                state,
                available_guaranteed_response_memory,
            ) {
                None => {
                    // Message successfully inducted or dropped.
                    stream.push_accept_signal();
                }
                Some((err, RequestOrResponse::Request(request)))
                    if state.metadata.certification_version < CertificationVersion::V19 =>
                {
                    // Unable to induct a request, generate reject response and push it into `stream`.
                    let code = match err {
                        StateError::CanisterNotFound(_) => RejectCode::DestinationInvalid,
                        StateError::CanisterStopped(_) => RejectCode::CanisterError,
                        StateError::CanisterStopping(_) => RejectCode::CanisterError,
                        StateError::CanisterMigrating { .. } => RejectCode::SysTransient,
                        StateError::QueueFull { .. } => RejectCode::SysTransient,
                        StateError::OutOfMemory { .. } => RejectCode::CanisterError,
                        StateError::NonMatchingResponse { .. }
                        | StateError::BitcoinNonMatchingResponse { .. } => {
                            unreachable!("Not a user error: {}", err);
                        }
                    };
                    *available_guaranteed_response_memory -=
                        stream.push(generate_reject_response(&request, code, err.to_string()))
                            as i64;
                    stream.push_accept_signal();
                }
                Some((err, RequestOrResponse::Request(_))) => {
                    // Unable to induct a request, push a reject signal.
                    let reason = match err {
                        StateError::CanisterMigrating { .. } => RejectReason::CanisterMigrating,
                        StateError::CanisterNotFound(_) => RejectReason::CanisterNotFound,
                        StateError::CanisterStopped(_) => RejectReason::CanisterStopped,
                        StateError::CanisterStopping(_) => RejectReason::CanisterStopping,
                        StateError::QueueFull { .. } => RejectReason::QueueFull,
                        StateError::OutOfMemory { .. } => RejectReason::OutOfMemory,
                        StateError::NonMatchingResponse { .. }
                        | StateError::BitcoinNonMatchingResponse { .. } => RejectReason::Unknown,
                    };
                    stream.push_reject_signal(reason);
                }
                Some((StateError::CanisterMigrating { .. }, RequestOrResponse::Response(_))) => {
                    // Unable to deliver a response due to migrating canister, push reject signal.
                    stream.push_reject_signal(RejectReason::CanisterMigrating);
                }
                Some((_, RequestOrResponse::Response(_))) => {
                    unreachable!("No signals are generated for response induction failures except for CanisterMigrating");
                }
            }
        } else {
            // `remote_subnet_id` is not known to be a valid host for `msg.sender()`.
            //
            // Do not enqueue a reject response as remote subnet is likely malicious and
            // trying to cause a memory leak by sending bogus messages and never consuming
            // reject responses.
            error!(
                self.log,
                "{}: Dropping message from subnet {} claiming to be from sender {}: {:?}",
                CRITICAL_ERROR_SENDER_SUBNET_MISMATCH,
                remote_subnet_id,
                msg.sender(),
                msg
            );
            self.observe_inducted_message_status(msg_type, LABEL_VALUE_SENDER_SUBNET_MISMATCH);
            self.metrics.critical_error_sender_subnet_mismatch.inc();
            stream.push_accept_signal();
        }
    }

    fn induct_message_impl(
        &self,
        msg: RequestOrResponse,
        msg_type: &str,
        state: &mut ReplicatedState,
        available_guaranteed_response_memory: &mut i64,
    ) -> Option<(StateError, RequestOrResponse)> {
        // Subnet that should have received the message according to the routing table.
        let receiver_host_subnet = state
            .metadata
            .network_topology
            .routing_table
            .route(msg.receiver().get());

        let payload_size = msg.payload_size_bytes().get();
        match receiver_host_subnet {
            // Matching receiver subnet, try inducting message.
            Some(host_subnet) if host_subnet == self.subnet_id => {
                match state.push_input(msg, available_guaranteed_response_memory) {
                    // Message successfully inducted, all done.
                    Ok(()) => {
                        self.observe_inducted_message_status(msg_type, LABEL_VALUE_SUCCESS);
                        self.observe_inducted_payload_size(payload_size);
                    }

                    // Message not inducted.
                    Err((err, msg)) => {
                        self.observe_inducted_message_status(msg_type, err.to_label_value());

                        match msg {
                            RequestOrResponse::Request(ref request) => {
                                debug!(
                                    self.log,
                                    "Induction failed with error '{}', generating reject Response for {:?}",
                                    &err,
                                    &request
                                );
                                return Some((err, msg));
                            }
                            RequestOrResponse::Response(response) => {
                                // Critical error, responses should always be inducted successfully.
                                error!(
                                    self.log,
                                    "{}: Inducting response failed: {} {:?}",
                                    CRITICAL_ERROR_INDUCT_RESPONSE_FAILED,
                                    err,
                                    response
                                );
                                self.metrics.critical_error_induct_response_failed.inc();
                            }
                        }
                    }
                }
            }

            // Receiver canister is migrating to/from this subnet.
            Some(host_subnet) if self.should_reroute_message_to(&msg, host_subnet, state) => {
                self.observe_inducted_message_status(msg_type, LABEL_VALUE_CANISTER_MIGRATED);
                let err = StateError::CanisterMigrating {
                    canister_id: msg.receiver(),
                    host_subnet,
                };

                match &msg {
                    RequestOrResponse::Request(request) => {
                        debug!(
                            self.log,
                            "Canister {} is being migrated, generating reject response for {:?}",
                            request.receiver,
                            request
                        );
                        return Some((err, msg));
                    }
                    RequestOrResponse::Response(response) => {
                        if state.metadata.certification_version >= CertificationVersion::V9 {
                            debug!(
                                self.log,
                                "Canister {} is being migrated, generating reject signal for {:?}",
                                response.originator,
                                response
                            );
                            return Some((err, msg));
                        } else {
                            fatal!(
                                self.log,
                                "Canister {} is being migrated, but cannot produce reject signal for response {:?}",
                                response.originator,
                                response
                            );
                        }
                    }
                }
            }

            // Receiver is not and was not (according to `migrating_canisters`) recently
            // hosted by this subnet.
            host_subnet => {
                error!(
                    self.log,
                    "{}: Dropping misrouted message (receiver {} is hosted by {:?}): {:?}",
                    CRITICAL_ERROR_RECEIVER_SUBNET_MISMATCH,
                    msg.receiver(),
                    host_subnet,
                    msg
                );
                self.observe_inducted_message_status(
                    msg_type,
                    LABEL_VALUE_RECEIVER_SUBNET_MISMATCH,
                );
                self.metrics.critical_error_receiver_subnet_mismatch.inc();
            }
        }

        // Any reject signals generated were returned before this point.
        None
    }

    /// Checks whether `actual_subnet_id` is a valid host subnet for `msg.sender()`
    /// (i.e. whether it is its current host according to the routing table; or an
    /// exception applies due to a canister migrations).
    fn should_accept_message_from(
        &self,
        msg: &RequestOrResponse,
        actual_subnet_id: SubnetId,
        state: &ReplicatedState,
    ) -> bool {
        // Remote subnet that should have sent the message according to the routing table.
        let expected_subnet_id = state
            .metadata
            .network_topology
            .routing_table
            .route(msg.sender().get());

        match expected_subnet_id {
            // The actual originating subnet and the routing table entry for the sender are in agreement.
            Some(expected_subnet_id) if expected_subnet_id == actual_subnet_id => true,

            // If a message addressed to a canister on this subnet A comes from a remote subnet B,
            // but the routing table claims it should come from a different subnet C, it must be accepted
            // iff the sender of this message is undergoing a migration from subnet B to C or C to B.
            Some(expected_subnet_id)
                if migration_trace(state, msg.sender()).is_some_and(|trace| {
                    trace.contains(&actual_subnet_id) && trace.contains(&expected_subnet_id)
                }) =>
            {
                true
            }

            // A reject response addressed to a canister hosted on this subnet A, but coming from a
            // different subnet B must be accepted iff this canister is marked as undergoing a
            // migration process from subnet B to subnet A.
            //
            // Since this case arises only in terms of reject signals for requests, it is important
            // that this be applied to reject responses only.
            _ if matches!(
                msg,
                RequestOrResponse::Response(response) if matches!(response.response_payload, Payload::Reject(_))
            ) && migration_trace(state, msg.receiver()).is_some_and(|trace| {
                matches!(
                    (
                        trace.iter().position(|subnet_id| subnet_id == &actual_subnet_id),
                        trace.iter().position(|subnet_id| subnet_id == &state.metadata.own_subnet_id),
                    ),
                    (Some(index_1), Some(index_2)) if index_1 < index_2
                )
            }) =>
            {
                true
            }

            // The sender is not known to be hosted by the originating subnet now (according to the
            // routing table) or previously (according to canister migration traces).
            _ => false,
        }
    }

    /// Checks whether a message addressed to a canister known not to be hosted by
    /// `self.subnet_id` should be rejected (as opposed to silently dropped).
    ///
    /// Reject signals for `Responses` and reject responses for requests addressed
    /// to receivers not hosted by `self.subnet_id` are only produced if both the
    /// known host and `self.subnet_id` are on the path of a canister migration
    /// including `msg.receiver()`.
    fn should_reroute_message_to(
        &self,
        msg: &RequestOrResponse,
        actual_receiver_subnet_id: SubnetId,
        state: &ReplicatedState,
    ) -> bool {
        debug_assert_eq!(
            Some(actual_receiver_subnet_id),
            state
                .metadata
                .network_topology
                .routing_table
                .route(msg.receiver().get())
        );

        // Reroute if `msg.receiver()` is being migrated from `self.subnet_id` to
        // `actual_receiver_subnet_id` (possibly with extra steps).
        migration_trace(state, msg.receiver()).is_some_and(|trace| {
            trace.contains(&actual_receiver_subnet_id) && trace.contains(&self.subnet_id)
        })
    }

    /// Computes the subnet's available guaranteed response message memory, as the
    /// difference between the subnet's guaranteed response message memory capacity
    /// and its current usage.
    fn available_guaranteed_response_memory(&self, state: &ReplicatedState) -> i64 {
        self.guaranteed_response_message_memory_capacity.get() as i64
            - state.guaranteed_response_message_memory_taken().get() as i64
    }

    /// Observes "time in backlog" (since learning about their existence from
    /// the stream header) for each of the given inducted messages.
    fn observe_backlog_durations(&self, stream_slices: &BTreeMap<SubnetId, StreamSlice>) {
        let mut time_in_backlog_metrics = self.time_in_backlog_metrics.borrow_mut();
        for (remote_subnet_id, stream_slice) in stream_slices {
            if let Some(messages) = stream_slice.messages() {
                time_in_backlog_metrics
                    .observe_message_durations(*remote_subnet_id, messages.begin()..messages.end());
            }
        }
    }

    /// Records the result of inducting an XNet message.
    fn observe_inducted_message_status(&self, msg_type: &str, status: &str) {
        self.metrics
            .inducted_xnet_messages
            .with_label_values(&[msg_type, status])
            .inc();
    }

    /// Records the size of a successfully inducted XNet message payload.
    fn observe_inducted_payload_size(&self, bytes: u64) {
        self.metrics
            .inducted_xnet_payload_sizes
            .observe(bytes as f64);
    }

    /// Records the garbage collection of all messages between the two given
    /// stream indices.
    fn observe_gced_messages(&self, from: StreamIndex, to: StreamIndex) {
        assert!(from <= to);
        self.metrics.gced_xnet_messages.inc_by((to - from).get());
    }

    /// Records the garbage collection of all reject signals.
    fn observe_gced_reject_signals(&self, signal_count: usize) {
        self.metrics
            .gced_xnet_reject_signals
            .inc_by(signal_count as u64);
    }
}

/// Returns a migration trace for `canister_id` in the network topology in `state` (if any).
fn migration_trace(state: &ReplicatedState, canister_id: CanisterId) -> Option<Vec<SubnetId>> {
    state
        .metadata
        .network_topology
        .canister_migrations
        .lookup(canister_id)
}

/// Generates a reject `Response` for a pair of `RejectReason` and `Request`.
fn generate_reject_response_for(reason: RejectReason, request: &Request) -> RequestOrResponse {
    use ic_types::CountBytes;
    let (code, message) = match reason {
        RejectReason::CanisterMigrating => (
            RejectCode::SysTransient,
            format!("Canister {} is migrating", request.receiver),
        ),
        RejectReason::CanisterNotFound => (
            RejectCode::DestinationInvalid,
            format!("Canister {} not found", request.receiver),
        ),
        RejectReason::CanisterStopped => (
            RejectCode::CanisterError,
            format!("Canister {} is stopped", request.receiver),
        ),
        RejectReason::CanisterStopping => (
            RejectCode::CanisterError,
            format!("Canister {} is stopping", request.receiver),
        ),
        RejectReason::QueueFull => (
            RejectCode::SysTransient,
            format!("Canister {} input queue is full", request.receiver),
        ),
        RejectReason::OutOfMemory => (
            RejectCode::CanisterError,
            format!(
                "Cannot induct request. Out of memory: requested {}",
                request.count_bytes().max(MAX_RESPONSE_COUNT_BYTES),
            ),
        ),
        RejectReason::Unknown => (
            RejectCode::SysFatal,
            "Inducting request failed due to an unknown error".to_string(),
        ),
    };
    generate_reject_response(request, code, message)
}

/// Generates a reject `Response` for a `Request` message with the provided
/// `RejectCode` and error message.
fn generate_reject_response(
    request: &Request,
    reject_code: RejectCode,
    message: String,
) -> RequestOrResponse {
    Response {
        originator: request.sender,
        respondent: request.receiver,
        originator_reply_callback: request.sender_reply_callback,
        refund: request.payment,
        response_payload: Payload::Reject(RejectContext::new_with_message_length_limit(
            reject_code,
            message,
            MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
        )),
        deadline: request.deadline,
    }
    .into()
}

/// Ensures that the given signals are valid (strictly increasing, before
/// `signals_end`).
fn assert_valid_signals(
    signals_end: StreamIndex,
    reject_signals: &VecDeque<RejectSignal>,
    stream_component: StreamComponent,
) {
    let iter = reject_signals.iter().map(|signal| signal.index);
    assert!(
        // Check that signals are strictly monotonic and below signals_end.
        iter.clone()
            .zip(iter.skip(1).chain(std::iter::once(signals_end)))
            .all(|(x, y)| x < y),
        "Invalid {}: signals_end {}, signals {:?}",
        stream_component,
        signals_end,
        reject_signals
    );
}

/// Ensures that the given signals cover a prefix of messages.
fn assert_valid_signals_for_messages(
    signals_end: StreamIndex,
    messages_begin: StreamIndex,
    messages_end: StreamIndex,
    stream_component: StreamComponent,
) {
    assert!(
        messages_begin <= signals_end && signals_end <= messages_end,
        "Invalid {}: signals_end {}, messages [{}, {})",
        stream_component,
        signals_end,
        messages_begin,
        messages_end,
    );
}

/// Ensures that the given slice messages (if non-empty) begin where the reverse
/// stream's signals end.
fn assert_valid_slice_messages_for_stream(
    slice_messages: Option<&StreamIndexedQueue<RequestOrResponse>>,
    stream_signals_end: StreamIndex,
    subnet: SubnetId,
) {
    if let Some(messages) = slice_messages {
        assert!(
            messages.begin() == stream_signals_end,
            "Invalid message indices in stream slice from subnet {}: messages begin ({}) != stream signals_end ({})",
            subnet,
            messages.begin(),
            stream_signals_end
        );
    }
}

/// Identifies a part of a stream / stream slice and the remote subnet, for
/// logging purposes.
enum StreamComponent {
    SignalsFrom(SubnetId),
    SignalsTo(SubnetId),
    MessagesFrom(SubnetId),
}

impl std::fmt::Display for StreamComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamComponent::SignalsFrom(subnet) => {
                write!(f, "signal indices in stream slice from subnet {}", subnet)
            }
            StreamComponent::SignalsTo(subnet) => {
                write!(f, "signal indices in stream to subnet {}", subnet)
            }
            StreamComponent::MessagesFrom(subnet) => {
                write!(f, "message indices in stream slice from subnet {}", subnet)
            }
        }
    }
}
