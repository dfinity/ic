use crate::message_routing::{
    CRITICAL_ERROR_INDUCT_RESPONSE_FAILED, LatencyMetrics, MessageRoutingMetrics,
};
use ic_base_types::NumBytes;
use ic_config::execution_environment::Config as HypervisorConfig;
use ic_error_types::RejectCode;
use ic_interfaces::messaging::{
    LABEL_VALUE_CANISTER_METHOD_NOT_FOUND, LABEL_VALUE_CANISTER_NOT_FOUND,
    LABEL_VALUE_CANISTER_OUT_OF_CYCLES, LABEL_VALUE_CANISTER_STOPPED,
    LABEL_VALUE_CANISTER_STOPPING, LABEL_VALUE_INVALID_MANAGEMENT_PAYLOAD,
};
use ic_logger::{ReplicaLogger, debug, error, info, trace};
use ic_metrics::MetricsRegistry;
use ic_metrics::buckets::{add_bucket, decimal_buckets};
use ic_replicated_state::metadata_state::{Stream, StreamMap};
use ic_replicated_state::replicated_state::{
    LABEL_VALUE_QUEUE_FULL, MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN, ReplicatedStateMessageRouting,
};
use ic_replicated_state::{ReplicatedState, StateError};
use ic_types::messages::{
    MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64, MAX_RESPONSE_COUNT_BYTES, Payload, Refund,
    RejectContext, Request, RequestOrResponse, Response, StreamMessage,
};
use ic_types::xnet::{RejectReason, RejectSignal, StreamIndex, StreamIndexedQueue, StreamSlice};
use ic_types::{CanisterId, SubnetId};
use prometheus::{Histogram, IntCounter, IntCounterVec, IntGaugeVec};
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

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
}

const METRIC_INDUCTED_XNET_MESSAGES: &str = "mr_inducted_xnet_message_count";
const METRIC_INDUCTED_XNET_PAYLOAD_SIZES: &str = "mr_inducted_xnet_payload_size_bytes";
const METRIC_GCED_XNET_MESSAGES: &str = "mr_gced_xnet_message_count";
const METRIC_GCED_XNET_REJECT_SIGNALS: &str = "mr_gced_xnet_reject_signal_count";
const METRIC_STREAM_FLAGS_CHANGES: &str = "mr_stream_flags_changes_count";

const METRIC_XNET_MESSAGE_BACKLOG: &str = "mr_xnet_message_backlog";

const LABEL_STATUS: &str = "status";
const LABEL_VALUE_SUCCESS: &str = "success";
const LABEL_VALUE_DROPPED: &str = "dropped";
const LABEL_VALUE_SENDER_SUBNET_MISMATCH: &str = "SenderSubnetMismatch";
const LABEL_VALUE_SENDER_SUBNET_MISMATCH_MIGRATING: &str = "SenderSubnetMismatchMigrating";
const LABEL_VALUE_RECEIVER_SUBNET_MISMATCH: &str = "ReceiverSubnetMismatch";
const LABEL_VALUE_REQUEST_MISROUTED: &str = "RequestMisrouted";
const LABEL_VALUE_SENDER_MIGRATED: &str = "SenderMigrated";
const LABEL_VALUE_RECEIVER_MIGRATED: &str = "ReceiverMigrated";
const LABEL_VALUE_RECEIVER_LIKELY_MIGRATED: &str = "ReceiverLikelyMigrated";
const LABEL_TYPE: &str = "type";
const LABEL_VALUE_TYPE_REQUEST: &str = "request";
const LABEL_VALUE_TYPE_RESPONSE: &str = "response";
const LABEL_VALUE_TYPE_REFUND: &str = "refund";
const LABEL_REMOTE: &str = "remote";

const CRITICAL_ERROR_BAD_REJECT_SIGNAL_FOR_RESPONSE: &str = "mr_bad_reject_signal_for_response";
const CRITICAL_ERROR_SENDER_SUBNET_MISMATCH: &str = "mr_sender_subnet_mismatch";
const CRITICAL_ERROR_RECEIVER_SUBNET_MISMATCH: &str = "mr_receiver_subnet_mismatch";

impl StreamHandlerMetrics {
    pub fn new(
        metrics_registry: &MetricsRegistry,
        message_routing_metrics: &MessageRoutingMetrics,
    ) -> Self {
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
        let critical_error_induct_response_failed = message_routing_metrics
            .critical_error_induct_response_failed
            .clone();
        let critical_error_sender_subnet_mismatch =
            metrics_registry.error_counter(CRITICAL_ERROR_SENDER_SUBNET_MISMATCH);
        let critical_error_receiver_subnet_mismatch =
            metrics_registry.error_counter(CRITICAL_ERROR_RECEIVER_SUBNET_MISMATCH);

        // Initialize all `inducted_xnet_messages` counters with zero, so they are all
        // exported from process start (`IntCounterVec` is really a map).
        for msg_type in &[LABEL_VALUE_TYPE_REQUEST, LABEL_VALUE_TYPE_RESPONSE] {
            for status in &[
                LABEL_VALUE_SUCCESS,
                LABEL_VALUE_DROPPED,
                LABEL_VALUE_CANISTER_NOT_FOUND,
                LABEL_VALUE_CANISTER_OUT_OF_CYCLES,
                LABEL_VALUE_CANISTER_STOPPED,
                LABEL_VALUE_CANISTER_STOPPING,
                LABEL_VALUE_QUEUE_FULL,
                LABEL_VALUE_SENDER_SUBNET_MISMATCH,
                LABEL_VALUE_REQUEST_MISROUTED,
                LABEL_VALUE_RECEIVER_SUBNET_MISMATCH,
                LABEL_VALUE_SENDER_MIGRATED,
                LABEL_VALUE_RECEIVER_MIGRATED,
                LABEL_VALUE_RECEIVER_LIKELY_MIGRATED,
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
        message_routing_metrics: &MessageRoutingMetrics,
        time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            subnet_id,
            guaranteed_response_message_memory_capacity: hypervisor_config
                .guaranteed_response_message_memory_capacity,
            metrics: StreamHandlerMetrics::new(metrics_registry, message_routing_metrics),
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
        let loopback_stream = streams.get_mut(&self.subnet_id).unwrap();

        // 2. Garbage collect all initial messages and retain any rejected messages.
        let signals_end = loopback_stream.signals_end();
        let reject_signals = loopback_stream.reject_signals().clone();
        let rejected_messages = self.garbage_collect_messages(
            loopback_stream,
            self.subnet_id,
            signals_end,
            &reject_signals,
        );

        // 3. Garbage collect signals for all initial messages.
        self.discard_signals_before(loopback_stream, signals_end);

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
            debug_assert!(
                loopback_stream
                    .messages()
                    .iter()
                    .all(|(_, msg)| matches!(msg, StreamMessage::Response(_)))
            );
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
                Some(stream) => {
                    let rejected_messages = self.garbage_collect_messages(
                        stream,
                        *remote_subnet,
                        stream_slice.header().signals_end(),
                        stream_slice.header().reject_signals(),
                    );
                    self.garbage_collect_signals(stream, *remote_subnet, stream_slice);

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
                        "Cannot garbage collect a stream for subnet {remote_subnet} that does not exist"
                    );
                    assert_eq!(
                        stream_slice.header().begin(),
                        StreamIndex::from(0),
                        "Signals from subnet {remote_subnet} do not start from 0 in the first communication attempt"
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
        stream: &mut Stream,
        remote_subnet: SubnetId,
        signals_end: StreamIndex,
        reject_signals: &VecDeque<RejectSignal>,
    ) -> Vec<(RejectReason, StreamMessage)> {
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
        stream: &mut Stream,
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
                .map_or_else(|| stream_slice.header().end(), |q| q.end()),
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
    fn discard_signals_before(&self, stream: &mut Stream, header_begin: StreamIndex) {
        let signal_count_before = stream.reject_signals().len();
        stream.discard_signals_before(header_begin);
        self.observe_gced_reject_signals(signal_count_before - stream.reject_signals().len());
    }

    /// Handles messages for which a reject signal was received:
    /// - If the message is a request, a reject response is generated and inducted into `state`.
    ///   If the reject response can not be inducted due to a canister migration, it is treated
    ///   as a rejected response (see below).
    /// - If the message is a response or refund, it is rerouted according to the routing table
    ///   into the appropriate stream.
    ///
    /// Error cases:
    /// - A response or refund with a `RejectReason` other than `CanisterMigrating`: guaranteed
    ///   delivery requires rerouting; an error counter is incremented.
    fn handle_rejected_messages(
        &self,
        rejected_messages: Vec<(RejectReason, StreamMessage)>,
        remote_subnet_id: SubnetId,
        state: &mut ReplicatedState,
        streams: &mut StreamMap,
        available_guaranteed_response_memory: &mut i64,
    ) {
        fn reroute_message(
            response: StreamMessage,
            state: &ReplicatedState,
            streams: &mut StreamMap,
            log: &ReplicaLogger,
        ) {
            let new_destination = state
                .metadata
                .network_topology
                .route(response.receiver().get())
                .expect("Canister disappeared from registry. Registry in an inconsistent state.");
            info!(
                log,
                "Canister {} is being migrated, rerouting to subnet {} for {:?}",
                response.receiver(),
                new_destination,
                response,
            );
            streams.entry(new_destination).or_default().push(response);
        }

        for (reason, msg) in rejected_messages {
            match msg {
                StreamMessage::Request(ref request) => {
                    // Generate a reject response and try to induct it.
                    debug!(
                        self.log,
                        "Received reject signal '{:?}', generating reject response for {:?}",
                        reason,
                        request
                    );

                    let reject_response = generate_reject_response_for(reason, request);
                    if self.validate_sender_subnet(&reject_response, remote_subnet_id, state)
                        == SenderSubnet::Mismatch
                    {
                        // `remote_subnet_id` is not known to be a valid host for `msg.sender()`.
                        //
                        // This can happen during a canister migration. It's not an error, but we add this case
                        // to the metrics as its own status.
                        self.observe_inducted_message_status(
                            LABEL_VALUE_TYPE_REQUEST,
                            LABEL_VALUE_REQUEST_MISROUTED,
                        );
                    }

                    // Try to induct the reject response.
                    match self.induct_message_impl(
                        reject_response,
                        LABEL_VALUE_TYPE_RESPONSE,
                        state,
                        available_guaranteed_response_memory,
                    ) {
                        // Reject response successfully inducted or silently dropped (for being late).
                        Accept => {}
                        // Canister is being migrated, reroute reject response.
                        Reject(RejectReason::CanisterMigrating, reject_response) => {
                            reroute_message(reject_response.into(), state, streams, &self.log);
                        }
                        Reject(..) => {
                            unreachable!(
                                "Errors other than `CanisterMigrating` shouldn't be possible."
                            );
                        }
                    }
                }

                // Refunds are treated the same as responses for rerouting purposes.
                StreamMessage::Response(_) | StreamMessage::Refund(_) => {
                    if reason != RejectReason::CanisterMigrating {
                        // Signals other than `CanisterMigrating` shouldn't be possible for
                        // responses or refunds.
                        error!(
                            self.log,
                            "{}: Received unsupported reject reason {:?} from {} for {:?}",
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
                    reroute_message(msg, state, streams, &self.log);
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
            let stream = streams.entry(remote_subnet_id).or_default();

            while let Some((stream_index, msg)) = stream_slice.pop_message() {
                assert_eq!(
                    stream.signals_end(),
                    stream_index,
                    "Expecting signal with stream index {}, got {}",
                    stream.signals_end(),
                    stream_index
                );

                #[cfg(debug_assertions)]
                let (balance_before, msg_cycles, reject_signals_before) = (
                    state.balance_with_messages(),
                    msg.cycles(),
                    stream.reject_signals().len(),
                );

                self.induct_message(
                    msg,
                    remote_subnet_id,
                    &mut state,
                    stream,
                    available_guaranteed_response_memory,
                );

                #[cfg(debug_assertions)]
                {
                    let expected_balance = if stream.reject_signals().len() > reject_signals_before
                    {
                        // Message was rejected; balance should be unchanged.
                        balance_before
                    } else {
                        // Message was accepted; balance should increase by msg.cycles().
                        balance_before + msg_cycles
                    };
                    state.assert_balance_with_messages(expected_balance);
                }
            }
        }

        state.put_streams(streams);
        state
    }

    /// Attempts to induct the given message, at `stream_index` in the incoming
    /// stream from `remote_subnet_id` into `state`, producing a signal onto the
    /// provided reverse `stream`. The induction attempt will result in one of
    /// the following outcomes:
    ///
    ///  * Message successfully inducted: accept signal appended to the reverse
    ///    stream;
    ///  * `Request` not inducted (queue full, out of memory, canister not found,
    ///    canister migrated): reject signal appended to the reverse stream;
    ///  * `Response` or `Refund` not inducted (canister migrated): reject signal
    ///    appended to reverse stream.
    ///  * `Request` or `Refund` not inducted (potential manual canister migration):
    ///    reject signal appended to reverse stream.
    ///  * `Response` or `Refund` not inducted (canister deleted): accept signal
    ///    appended to reverse stream.
    ///  * `Response` silently dropped, critical error raised and accept signal
    ///    appended to reverse stream iff:
    ///     * the sender and source subnet do not match (according to the
    ///       routing table or canister migrations); or
    ///     * the receiver is not hosted by or being migrated off of this
    ///       subnet.
    ///
    /// Updates `available_guaranteed_response_memory` to reflect any change in
    /// guaranteed response memory usage.
    fn induct_message(
        &self,
        msg: StreamMessage,
        remote_subnet_id: SubnetId,
        state: &mut ReplicatedState,
        stream: &mut Stream,
        available_guaranteed_response_memory: &mut i64,
    ) {
        let (msg, msg_type) = match msg {
            StreamMessage::Request(req) => {
                (RequestOrResponse::Request(req), LABEL_VALUE_TYPE_REQUEST)
            }
            StreamMessage::Response(rep) => {
                (RequestOrResponse::Response(rep), LABEL_VALUE_TYPE_RESPONSE)
            }
            StreamMessage::Refund(refund) => {
                return self.induct_refund(&refund, state, stream);
            }
        };

        match (
            self.validate_sender_subnet(&msg, remote_subnet_id, state),
            &msg,
        ) {
            // Induct messages with a matching sender; and responses from any subnet
            // on a canister's migration path.
            (SenderSubnet::Match, _)
            | (SenderSubnet::OnMigrationPath, RequestOrResponse::Response(_)) => {
                match self.induct_message_impl(
                    msg,
                    msg_type,
                    state,
                    available_guaranteed_response_memory,
                ) {
                    // Message successfully inducted or dropped (late best-effort response).
                    Accept => stream.push_accept_signal(),

                    // Unable to induct a request, push a reject signal.
                    Reject(reason, RequestOrResponse::Request(_)) => {
                        stream.push_reject_signal(reason);
                    }
                    // Unable to deliver a response due to migrating canister, push reject signal.
                    Reject(RejectReason::CanisterMigrating, RequestOrResponse::Response(_)) => {
                        stream.push_reject_signal(RejectReason::CanisterMigrating);
                    }
                    Reject(_, RequestOrResponse::Response(_)) => {
                        unreachable!(
                            "No signals are generated for response induction failures except for CanisterMigrating"
                        );
                    }
                }
            }

            // Reject requests from migrating senders, if they do not originate
            // from the sender's known host subnet. This is to ensure request
            // ordering guarantees.
            (SenderSubnet::OnMigrationPath, RequestOrResponse::Request(_)) => {
                self.observe_inducted_message_status(msg_type, LABEL_VALUE_SENDER_MIGRATED);
                stream.push_reject_signal(RejectReason::CanisterMigrating);
            }

            // Reject requests not originating from their sender's known host
            // subnet. Their senders are likely manually migrated canisters.
            (SenderSubnet::Mismatch, RequestOrResponse::Request(_)) => {
                self.observe_inducted_message_status(
                    msg_type,
                    LABEL_VALUE_SENDER_SUBNET_MISMATCH_MIGRATING,
                );
                stream.push_reject_signal(RejectReason::CanisterMigrating);
            }

            // Responses that fail the routing check indicate a critical error.
            //
            // Do not push a reject signal as remote subnet is likely malicious.
            (SenderSubnet::Mismatch, RequestOrResponse::Response(rep)) => {
                error!(
                    self.log,
                    "{}: Dropping message from subnet {} claiming to be from sender {}: {:?}",
                    CRITICAL_ERROR_SENDER_SUBNET_MISMATCH,
                    remote_subnet_id,
                    rep.respondent,
                    msg
                );
                self.observe_inducted_message_status(msg_type, LABEL_VALUE_SENDER_SUBNET_MISMATCH);
                self.metrics.critical_error_sender_subnet_mismatch.inc();
                stream.push_accept_signal();
                // Cycles are lost.
                state.observe_lost_cycles_due_to_dropped_messages(rep.refund);
            }
        }
    }

    /// Inducts a message into `state`.
    ///
    /// There are 4 possible outcomes:
    ///  * `msg` successfully inducted: returns `Accept`.
    ///  * silently dropped late best-effort response: returns `Accept` (having
    ///    credited any refund).
    ///  * `msg` failed to be inducted (error or canister migrating), returns a
    ///    `Reject` wrapping a `RejectReason` and the original `msg`. The caller is
    ///    expected to produce a reject response or a reject signal.
    ///  * internal error when inducting a `Response`: returns `Accept` (`Response`
    ///    is consumed) and logs a critical error.
    fn induct_message_impl(
        &self,
        msg: RequestOrResponse,
        msg_type: &str,
        state: &mut ReplicatedState,
        available_guaranteed_response_memory: &mut i64,
    ) -> InductionResult {
        // Subnet that should have received the message according to the routing table.
        let receiver_host_subnet = state.metadata.network_topology.route(msg.receiver().get());

        let payload_size = msg.payload_size_bytes().get();
        match receiver_host_subnet {
            // Matching receiver subnet, try inducting message.
            Some(host_subnet) if host_subnet == self.subnet_id => {
                match state.push_input(msg, available_guaranteed_response_memory) {
                    // Message successfully inducted, all done.
                    Ok(true) => {
                        self.observe_inducted_message_status(msg_type, LABEL_VALUE_SUCCESS);
                        self.observe_inducted_payload_size(payload_size);
                        Accept
                    }

                    // Message silently dropped, any refund was already credited.
                    Ok(false) => {
                        self.observe_inducted_message_status(msg_type, LABEL_VALUE_DROPPED);
                        Accept
                    }

                    // Message not inducted.
                    Err((err, msg)) => {
                        self.observe_inducted_message_status(msg_type, err.to_label_value());

                        match msg {
                            RequestOrResponse::Request(ref request) => {
                                let reason = match err {
                                    // Receiver should be hosted by this subnet, but does not exist.
                                    StateError::CanisterNotFound(_) => {
                                        RejectReason::CanisterNotFound
                                    }
                                    StateError::CanisterStopped(_) => RejectReason::CanisterStopped,
                                    StateError::CanisterStopping(_) => {
                                        RejectReason::CanisterStopping
                                    }
                                    StateError::QueueFull { .. } => RejectReason::QueueFull,
                                    StateError::OutOfMemory { .. } => RejectReason::OutOfMemory,
                                    // Unreachable.
                                    StateError::NonMatchingResponse { .. }
                                    | StateError::BitcoinNonMatchingResponse { .. } => {
                                        RejectReason::Unknown
                                    }
                                };
                                debug!(
                                    self.log,
                                    "Inducting request failed: {}\n{:?}", &err, &request
                                );
                                Reject(reason, msg)
                            }
                            RequestOrResponse::Response(response) => {
                                // Responses should always be inducted successfully (or silently dropped,
                                // in the case of duplicate best-effort responses). But never produce an error.
                                error!(
                                    self.log,
                                    "{}: Inducting response failed: {}\n{:?}",
                                    CRITICAL_ERROR_INDUCT_RESPONSE_FAILED,
                                    err,
                                    response
                                );
                                self.metrics.critical_error_induct_response_failed.inc();
                                // Cycles are lost.
                                state.observe_lost_cycles_due_to_dropped_messages(response.refund);
                                Accept
                            }
                        }
                    }
                }
            }

            // Receiver canister is migrating to/from this subnet.
            Some(host_subnet) if self.is_canister_migrating(msg.receiver(), host_subnet, state) => {
                self.observe_inducted_message_status(msg_type, LABEL_VALUE_RECEIVER_MIGRATED);

                match &msg {
                    RequestOrResponse::Request(request) => {
                        debug!(
                            self.log,
                            "Inducting request failed: Canister {} is migrating\n{:?}",
                            request.receiver,
                            request
                        );
                    }
                    RequestOrResponse::Response(response) => {
                        debug!(
                            self.log,
                            "Inducting response failed: Canister {} is migrating\n{:?}",
                            response.originator,
                            response
                        );
                    }
                }
                Reject(RejectReason::CanisterMigrating, msg)
            }

            // Best-effort response to canister hosted by other subnet. May occur
            // legitimately if the canister was migrated after the matching callback had
            // timed out.
            Some(_) if msg.is_best_effort() && matches!(msg, RequestOrResponse::Response(_)) => {
                self.observe_inducted_message_status(
                    msg_type,
                    LABEL_VALUE_RECEIVER_LIKELY_MIGRATED,
                );
                Reject(RejectReason::CanisterMigrating, msg)
            }

            // Request to receiver not hosted by this subnet. May occur legitimately during
            // a manual canister migration.
            _ if matches!(msg, RequestOrResponse::Request(_)) => {
                self.observe_inducted_message_status(
                    msg_type,
                    LABEL_VALUE_RECEIVER_LIKELY_MIGRATED,
                );
                Reject(RejectReason::CanisterMigrating, msg)
            }

            // Guaranteed response to receiver not hosted by this subnet. Should never
            // happen, whether due to subnet splits (there would be a matching
            // `canister_migrations` entry) or due to a manual canister migration (the
            // canister would have been stopped).
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
                Reject(RejectReason::CanisterMigrating, msg)
            }
        }
    }

    /// Credits the cycles attached to a refund message to its respective receiver.
    fn induct_refund(&self, refund: &Refund, state: &mut ReplicatedState, stream: &mut Stream) {
        // Subnet that should have received the message according to the routing table.
        let receiver_host_subnet = state
            .metadata
            .network_topology
            .route(refund.recipient().get());

        match receiver_host_subnet {
            // Matching receiver subnet, try crediting the cycles.
            Some(host_subnet) if host_subnet == self.subnet_id => {
                stream.push_accept_signal();
                if state.credit_refund(refund) {
                    self.observe_inducted_message_status(
                        LABEL_VALUE_TYPE_REFUND,
                        LABEL_VALUE_SUCCESS,
                    );
                } else {
                    // Recipient canister not found, cycles are lost.
                    self.observe_inducted_message_status(
                        LABEL_VALUE_TYPE_REFUND,
                        LABEL_VALUE_DROPPED,
                    );
                    state.observe_lost_cycles_due_to_dropped_messages(refund.amount());
                }
            }

            // Receiver canister is migrating to/from this subnet.
            Some(host_subnet)
                if self.is_canister_migrating(refund.recipient(), host_subnet, state) =>
            {
                self.observe_inducted_message_status(
                    LABEL_VALUE_TYPE_REFUND,
                    LABEL_VALUE_RECEIVER_MIGRATED,
                );
                stream.push_reject_signal(RejectReason::CanisterMigrating);
            }

            // Refund to receiver not hosted by this subnet. May occur legitimately during
            // a manual canister migration.
            _ => {
                self.observe_inducted_message_status(
                    LABEL_VALUE_TYPE_REFUND,
                    LABEL_VALUE_RECEIVER_LIKELY_MIGRATED,
                );
                stream.push_reject_signal(RejectReason::CanisterMigrating);
            }
        }
    }

    /// Checks whether `actual_subnet_id` is a valid host subnet for `msg.sender()`
    /// (i.e. whether it is its current host according to the routing table; or an
    /// exception applies due to a canister migrations).
    fn validate_sender_subnet(
        &self,
        msg: &RequestOrResponse,
        actual_subnet_id: SubnetId,
        state: &ReplicatedState,
    ) -> SenderSubnet {
        // Remote subnet that should have sent the message according to the routing table.
        let expected_subnet_id = state.metadata.network_topology.route(msg.sender().get());

        match expected_subnet_id {
            // The actual originating subnet and the routing table entry for the sender are in agreement.
            Some(expected_subnet_id) if expected_subnet_id == actual_subnet_id => SenderSubnet::Match,

            // A message originating from a subnet B; with the routing table claiming it
            // should be coming from a subnet C; and there is a migration trace for the
            // sender from B to C or C to B.
            Some(expected_subnet_id)
                if migration_trace(state, msg.sender()).is_some_and(|trace| {
                    trace.contains(&actual_subnet_id) && trace.contains(&expected_subnet_id)
                }) =>
            {
                SenderSubnet::OnMigrationPath
            }

            // A reject response coming from a subnet B; with the routing table claiming it
            // should be coming from a subnet C; but there is a migration trace for the
            // receiver from subnet B to this subnet.
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
                SenderSubnet::OnMigrationPath
            }

            // The sender is not known to be hosted by the originating subnet now (according to the
            // routing table) or previously (according to canister migration traces).
            _ => SenderSubnet::Mismatch,
        }
    }

    /// Checks whether the given canister (known not to be hosted by
    /// `self.subnet_id`) is part of a canister migration between the known host
    /// subnet and this subnet (in any order).
    fn is_canister_migrating(
        &self,
        canister: CanisterId,
        known_host_subnet_id: SubnetId,
        state: &ReplicatedState,
    ) -> bool {
        debug_assert_eq!(
            Some(known_host_subnet_id),
            state.metadata.network_topology.route(canister.get())
        );

        // Reroute if `msg.receiver()` is being migrated between `self.subnet_id` and
        // `actual_receiver_subnet_id` (possibly with extra steps).
        migration_trace(state, canister).is_some_and(|trace| {
            trace.contains(&known_host_subnet_id) && trace.contains(&self.subnet_id)
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
            "Canister migration in progress".to_string(),
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
        "Invalid {stream_component}: signals_end {signals_end}, signals {reject_signals:?}"
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
        "Invalid {stream_component}: signals_end {signals_end}, messages [{messages_begin}, {messages_end})",
    );
}

/// Ensures that the given slice messages (if non-empty) begin where the reverse
/// stream's signals end.
fn assert_valid_slice_messages_for_stream(
    slice_messages: Option<&StreamIndexedQueue<StreamMessage>>,
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
                write!(f, "signal indices in stream slice from subnet {subnet}")
            }
            StreamComponent::SignalsTo(subnet) => {
                write!(f, "signal indices in stream to subnet {subnet}")
            }
            StreamComponent::MessagesFrom(subnet) => {
                write!(f, "message indices in stream slice from subnet {subnet}")
            }
        }
    }
}

/// The outcome of checking the subnet ID that a message originated from against
/// the sender's expected subnet ID.
#[derive(Eq, PartialEq)]
enum SenderSubnet {
    Match,
    OnMigrationPath,
    Mismatch,
}

/// The outcome of inducting a message.
#[must_use]
enum InductionResult {
    /// Message was either inducted or silently dropped (late best-effort response),
    /// with the caller expected to produce (the equivalent of) an accept signal.
    Accept,

    /// Message was rejected, with the caller expected to produce a reject response
    /// or a reject signal.
    ///
    /// Wraps the reject reason and the original message.
    Reject(RejectReason, RequestOrResponse),
}
use InductionResult::*;
