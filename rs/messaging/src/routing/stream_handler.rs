use crate::message_routing::LatencyMetrics;
use ic_base_types::NumBytes;
use ic_certification_version::CertificationVersion;
use ic_config::execution_environment::Config as HypervisorConfig;
use ic_error_types::RejectCode;
use ic_logger::{debug, error, fatal, trace, ReplicaLogger};
use ic_metrics::{
    buckets::{add_bucket, decimal_buckets},
    MetricsRegistry,
};
use ic_registry_routing_table::RoutingTable;
use ic_replicated_state::{
    canister_state::QUEUE_INDEX_NONE,
    metadata_state::{StreamHandle, Streams},
    replicated_state::{
        ReplicatedStateMessageRouting, LABEL_VALUE_CANISTER_NOT_FOUND,
        LABEL_VALUE_CANISTER_OUT_OF_CYCLES, LABEL_VALUE_CANISTER_STOPPED,
        LABEL_VALUE_CANISTER_STOPPING, LABEL_VALUE_INVALID_SUBNET_PAYLOAD, LABEL_VALUE_QUEUE_FULL,
        LABEL_VALUE_UNKNOWN_SUBNET_METHOD,
    },
    ReplicatedState, StateError,
};
use ic_types::{
    messages::{
        Payload, RejectContext, RequestOrResponse, Response,
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64,
    },
    xnet::{StreamIndex, StreamIndexedQueue, StreamSlice},
    SubnetId,
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
    /// Backlog of XNet messages based on end in stream header and last message
    /// in slice, per subnet.
    pub xnet_message_backlog: IntGaugeVec,
    /// Critical error counter (see [`MetricsRegistry::error_counter`]) tracking the
    /// receival of reject signals for requests.
    pub critical_error_reject_signals_for_request: IntCounter,
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

const METRIC_XNET_MESSAGE_BACKLOG: &str = "mr_xnet_message_backlog";

const LABEL_STATUS: &str = "status";
const LABEL_VALUE_SUCCESS: &str = "success";
const LABEL_VALUE_SENDER_SUBNET_MISMATCH: &str = "SenderSubnetMismatch";
const LABEL_VALUE_RECEIVER_SUBNET_MISMATCH: &str = "ReceiverSubnetMismatch";
const LABEL_VALUE_CANISTER_MIGRATED: &str = "CanisterMigrated";
const LABEL_TYPE: &str = "type";
const LABEL_VALUE_TYPE_REQUEST: &str = "request";
const LABEL_VALUE_TYPE_RESPONSE: &str = "response";
const LABEL_REMOTE: &str = "remote";

const CRITICAL_ERROR_REJECT_SIGNALS_FOR_REQUEST: &str = "mr_reject_signals_for_request";
const CRITICAL_ERROR_INDUCT_RESPONSE_FAILED: &str = "mr_induct_response_failed";
const CRITICAL_ERROR_SENDER_SUBNET_MISMATCH: &str = "mr_sender_subnet_mismatch";
const CRITICAL_ERROR_RECEIVER_SUBNET_MISMATCH: &str = "mr_receiver_subnet_mismatch";

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
        let xnet_message_backlog = metrics_registry.int_gauge_vec(
            METRIC_XNET_MESSAGE_BACKLOG,
            "Backlog of XNet messages, by sending subnet.",
            &[LABEL_REMOTE],
        );
        let critical_error_reject_signals_for_request =
            metrics_registry.error_counter(CRITICAL_ERROR_REJECT_SIGNALS_FOR_REQUEST);
        let critical_error_induct_response_failed =
            metrics_registry.error_counter(CRITICAL_ERROR_INDUCT_RESPONSE_FAILED);
        let critical_error_sender_subnet_mismatch =
            metrics_registry.error_counter(CRITICAL_ERROR_SENDER_SUBNET_MISMATCH);
        let critical_error_receiver_subnet_mismatch =
            metrics_registry.error_counter(CRITICAL_ERROR_RECEIVER_SUBNET_MISMATCH);

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
                LABEL_VALUE_RECEIVER_SUBNET_MISMATCH,
                LABEL_VALUE_CANISTER_MIGRATED,
                LABEL_VALUE_UNKNOWN_SUBNET_METHOD,
                LABEL_VALUE_INVALID_SUBNET_PAYLOAD,
            ] {
                inducted_xnet_messages.with_label_values(&[msg_type, status]);
            }
        }

        Self {
            inducted_xnet_messages,
            inducted_xnet_payload_sizes,
            gced_xnet_messages,
            gced_xnet_reject_signals,
            xnet_message_backlog,
            critical_error_reject_signals_for_request,
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

    max_canister_memory_size: NumBytes,
    subnet_memory_capacity: NumBytes,
    subnet_message_memory_capacity: NumBytes,

    metrics: StreamHandlerMetrics,
    /// Per-destination-subnet histogram of wall time spent by messages in the
    /// stream before they are garbage collected.
    time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
    /// Per-source-subnet histogram of wall time between finding out about the
    /// existence of a message from an incoming stream header; and inducting it.
    time_in_backlog_metrics: RefCell<LatencyMetrics>,
    log: ReplicaLogger,

    /// Testing-only flag that forces generation of reject signals even if
    /// `CURRENT_CERTIFICATION_VERSION` is less than 9.
    testing_flag_generate_reject_signals: bool,
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
            max_canister_memory_size: hypervisor_config.max_canister_memory_size,
            subnet_memory_capacity: hypervisor_config.subnet_memory_capacity,
            subnet_message_memory_capacity: hypervisor_config.subnet_message_memory_capacity,
            metrics: StreamHandlerMetrics::new(metrics_registry),
            time_in_stream_metrics,
            time_in_backlog_metrics: RefCell::new(LatencyMetrics::new_time_in_backlog(
                metrics_registry,
            )),
            log,
            testing_flag_generate_reject_signals: false,
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

        // Induct our own loopback stream first, if one exists and has any messages.
        state = self.induct_loopback_stream(state);

        // Garbage collect our stream state based on the contents of the slices.
        state = self.garbage_collect_local_state(state, &stream_slices);
        self.observe_backlog_durations(&stream_slices);

        // Induct the messages in `stream_slices`, updating signals as appropriate.
        self.induct_stream_slices(state, stream_slices)
    }
}

impl StreamHandlerImpl {
    /// Inducts and consumes all messages from the subnet's loopback stream.
    ///
    /// After the call completes, the loopback stream may only contain reject
    /// responses or rerouted responses and no signals. All initial messages and
    /// corresponding signals will have been garbage collected.
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
    fn induct_loopback_stream(&self, mut state: ReplicatedState) -> ReplicatedState {
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
        state = self.induct_stream_slices(state, stream_slices);

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

        // 4. Reroute any rejected responses.
        self.reroute_rejected_messages(
            rejected_messages,
            &mut streams,
            state.metadata.network_topology.routing_table.as_ref(),
            self.subnet_id,
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
        stream_slices: &BTreeMap<SubnetId, StreamSlice>,
    ) -> ReplicatedState {
        let mut streams = state.take_streams();
        for (remote_subnet, stream_slice) in stream_slices {
            match streams.get_mut(remote_subnet) {
                Some(mut stream) => {
                    let rejected_messages = self.garbage_collect_messages(
                        &mut stream,
                        *remote_subnet,
                        stream_slice.header().signals_end,
                        &stream_slice.header().reject_signals,
                    );
                    self.garbage_collect_signals(&mut stream, *remote_subnet, stream_slice);

                    // Reroute any rejected responses.
                    self.reroute_rejected_messages(
                        rejected_messages,
                        &mut streams,
                        state.metadata.network_topology.routing_table.as_ref(),
                        *remote_subnet,
                    );
                }
                None => {
                    // New stream.
                    assert_eq!(
                        stream_slice.header().signals_end,
                        StreamIndex::from(0),
                        "Cannot garbage collect a stream for subnet {} that does not exist",
                        remote_subnet
                    );
                    assert_eq!(
                        stream_slice.header().begin, StreamIndex::from(0),
                        "Signals from subnet {} do not start from 0 in the first communication attempt",
                        remote_subnet
                    );
                }
            }
            let backlog = if let Some(messages) = stream_slice.messages() {
                stream_slice.header().end - messages.end()
            } else {
                stream_slice.header().end - stream_slice.header().begin
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
        reject_signals: &VecDeque<StreamIndex>,
    ) -> Vec<RequestOrResponse> {
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
            stream_slice.header().begin,
            stream_slice
                .messages()
                .map(|q| q.end())
                .unwrap_or_else(|| stream_slice.header().end),
            StreamComponent::MessagesFrom(remote_subnet),
        );
        assert_valid_slice_messages_for_stream(
            stream_slice.messages(),
            stream.signals_end(),
            remote_subnet,
        );

        self.discard_signals_before(stream, stream_slice.header().begin);
    }

    /// Wrapper around `Stream::discard_signals_before()` plus telemetry.
    fn discard_signals_before(&self, stream: &mut StreamHandle, header_begin: StreamIndex) {
        let signal_count_before = stream.reject_signals().len();
        stream.discard_signals_before(header_begin);
        self.observe_gced_reject_signals(signal_count_before - stream.reject_signals().len());
    }

    /// Reroutes all `Responses` rejected by `remote_subnet` into `streams`,
    /// based on the provided routing table; drops all `Requests`, incrementing
    /// a critical error counter.
    fn reroute_rejected_messages(
        &self,
        rejected_messages: Vec<RequestOrResponse>,
        streams: &mut Streams,
        routing_table: &RoutingTable,
        remote_subnet: SubnetId,
    ) {
        for msg in rejected_messages {
            match msg {
                RequestOrResponse::Request(request) => {
                    // Critical error, honest subnets do not produce reject signals for requests.
                    // We do not want to re-route requests because this can break the message
                    // ordering guarantees once canisters start migrating.
                    // An honest subnet should send a reject response instead of a reject signal
                    // if the destination canister moved away.
                    error!(
                        self.log,
                        "{}: Received unsupported reject signal from {} for request: {:?}",
                        CRITICAL_ERROR_REJECT_SIGNALS_FOR_REQUEST,
                        remote_subnet,
                        request
                    );
                    self.metrics.critical_error_reject_signals_for_request.inc();
                }

                RequestOrResponse::Response(response) => {
                    // The signal corresponds to a response a local canister sent back
                    // to a remote canister. This can only happen if the remote canister
                    // is no longer hosted by the remote subnet. So we need to get it to
                    // the subnet that actually hosts the canister now.
                    let new_destination = routing_table.route(response.originator.get()).expect(
                        "Canister disappeared from registry. Registry in an inconsistent state.",
                    );
                    streams
                        .get_mut_or_insert(new_destination)
                        .push(response.into());
                }
            }
        }
    }

    /// Inducts the messages in the provided stream slices into the
    /// `InductionPool`, generating a signal for each message.
    ///
    /// See [`Self::induct_message`] for the possible outcomes of inducting a
    /// message.
    fn induct_stream_slices(
        &self,
        mut state: ReplicatedState,
        stream_slices: BTreeMap<SubnetId, StreamSlice>,
    ) -> ReplicatedState {
        let subnet_available_memory = self.subnet_memory_capacity.get() as i64
            - state.total_memory_taken_with_messages().get() as i64;
        let subnet_available_message_memory = self.subnet_message_memory_capacity.get() as i64
            - state.message_memory_taken().get() as i64;
        let mut subnet_available_memory =
            subnet_available_memory.min(subnet_available_message_memory);
        let mut streams = state.take_streams();

        for (remote_subnet_id, mut stream_slice) in stream_slices {
            // Output stream, for resulting signals and (in the initial iteration) reject
            // `Responses`.
            let mut stream = streams.get_mut_or_insert(remote_subnet_id);

            while let Some((stream_index, msg)) = stream_slice.pop_message() {
                self.induct_message(
                    msg,
                    remote_subnet_id,
                    stream_index,
                    &mut state,
                    &mut stream,
                    &mut subnet_available_memory,
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
    /// Updates `subnet_available_memory` to reflect any change in memory usage.
    fn induct_message(
        &self,
        msg: RequestOrResponse,
        remote_subnet_id: SubnetId,
        stream_index: StreamIndex,
        state: &mut ReplicatedState,
        stream: &mut StreamHandle,
        subnet_available_memory: &mut i64,
    ) {
        let msg_type = match msg {
            RequestOrResponse::Request(_) => LABEL_VALUE_TYPE_REQUEST,
            RequestOrResponse::Response(_) => LABEL_VALUE_TYPE_RESPONSE,
        };

        if self.should_accept_message_from(&msg, remote_subnet_id, state) {
            // Sender subnet is valid.

            // Subnet that should have received the message according to the routing table.
            let receiver_host_subnet = state
                .metadata
                .network_topology
                .routing_table
                .route(msg.receiver().get());

            let payload_size = msg.payload_size_bytes().get();
            match receiver_host_subnet {
                // Matching receiver subnet, try inducting message.
                Some(host_subnet) if host_subnet == self.subnet_id => match state.push_input(
                    QUEUE_INDEX_NONE,
                    msg,
                    self.max_canister_memory_size,
                    subnet_available_memory,
                ) {
                    // Message successfully inducted, all done.
                    Ok(()) => {
                        self.observe_inducted_message_status(msg_type, LABEL_VALUE_SUCCESS);
                        self.observe_inducted_payload_size(payload_size);
                    }

                    // Message not inducted.
                    Err((err, msg)) => {
                        self.observe_inducted_message_status(msg_type, err.to_label_value());

                        match msg {
                            RequestOrResponse::Request(_) => {
                                debug!(
                                    self.log,
                                    "Induction failed with error '{}', generating reject Response for {:?}",
                                    &err,
                                    &msg
                                );
                                let code = reject_code_for_state_error(&err);
                                let context = RejectContext::new(code, err.to_string());
                                stream.push(generate_reject_response(msg, context))
                            }
                            RequestOrResponse::Response(response) => {
                                // Critical error, responses should always be inducted successfully.
                                error!(
                                    self.log,
                                    "{}: Inducting response failed: {:?}",
                                    CRITICAL_ERROR_INDUCT_RESPONSE_FAILED,
                                    response
                                );
                                self.metrics.critical_error_induct_response_failed.inc()
                            }
                        }
                    }
                },

                // Receiver canister is migrating to/from this subnet.
                Some(host_subnet) if self.should_reroute_message_to(&msg, host_subnet, state) => {
                    self.observe_inducted_message_status(msg_type, LABEL_VALUE_CANISTER_MIGRATED);

                    match &msg {
                        RequestOrResponse::Request(_) => {
                            debug!(self.log, "Canister {} is being migrated, generating reject response for {:?}", msg.receiver(), msg);
                            let context = RejectContext::new(
                                RejectCode::SysTransient,
                                format!(
                                    "Canister {} is being migrated to/from {}",
                                    msg.receiver(),
                                    host_subnet
                                ),
                            );
                            stream.push(generate_reject_response(msg, context));
                        }

                        RequestOrResponse::Response(_) => {
                            if state.metadata.certification_version >= CertificationVersion::V9
                                || self.testing_flag_generate_reject_signals
                            {
                                debug!(self.log, "Canister {} is being migrated, generating reject signal for {:?}", msg.receiver(), msg);
                                stream.push_reject_signal(stream_index);
                            } else {
                                fatal!(self.log, "Canister {} is being migrated, but cannot produce reject signal for response {:?}", msg.receiver(), msg);
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
        }

        // Signals use the `StreamIndex` of the incoming message.
        assert_eq!(
            stream.signals_end(),
            stream_index,
            "Expecting signal with stream index {}, got {}",
            stream.signals_end(),
            stream_index
        );
        stream.increment_signals_end();
    }

    /// Checks whether `actual_subnet_id` is a valid host subnet for `msg.sender()`
    /// (i.e. whether it is its current host according to the routing table; or it
    /// and the known host subnet are both on the path of a canister migration
    /// including `msg.sender()`).
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
            // `actual_subnet_id` is the expected host according to the routing table.
            Some(expected_subnet_id) if expected_subnet_id == actual_subnet_id => true,

            // `actual_subnet_id` and `expected_subnet_id` are both on the path
            // of a canister migration that includes `msg.sender()`.
            Some(expected_subnet_id)
                if state
                    .metadata
                    .network_topology
                    .canister_migrations
                    .lookup(msg.sender())
                    .map(|trace| {
                        trace.contains(&actual_subnet_id) && trace.contains(&expected_subnet_id)
                    })
                    .unwrap_or(false) =>
            {
                true
            }

            // Sender is known not to be (or have been) hosted by `remote_subnet_id`.
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
        actual_receiver_subnet: SubnetId,
        state: &ReplicatedState,
    ) -> bool {
        debug_assert_eq!(
            Some(actual_receiver_subnet),
            state
                .metadata
                .network_topology
                .routing_table
                .route(msg.receiver().get())
        );

        // Reroute if `msg.receiver()` is being migrated from `self.subnet_id` to `actual_receiver_subnet` (possibly with extra steps).
        state
            .metadata
            .network_topology
            .canister_migrations
            .lookup(msg.receiver())
            .map(|trace| trace.contains(&actual_receiver_subnet) && trace.contains(&self.subnet_id))
            .unwrap_or(false)
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

/// Generates a reject `Response` for a `Request` message with the provided
/// `RejectContext`.
fn generate_reject_response(msg: RequestOrResponse, context: RejectContext) -> RequestOrResponse {
    if let RequestOrResponse::Request(msg) = msg {
        Response {
            originator: msg.sender,
            respondent: msg.receiver,
            originator_reply_callback: msg.sender_reply_callback,
            refund: msg.payment,
            response_payload: Payload::Reject(context),
        }
        .into()
    } else {
        unreachable!("Can't have a response to a response: {:?}", msg)
    }
}

/// Maps a `StateError` resulting from a failed induction to a `RejectCode`.
fn reject_code_for_state_error(err: &StateError) -> RejectCode {
    match err {
        StateError::QueueFull { .. } => RejectCode::SysTransient,
        StateError::CanisterOutOfCycles(_) => RejectCode::SysTransient,
        StateError::CanisterNotFound(_) => RejectCode::DestinationInvalid,
        StateError::CanisterStopped(_) => RejectCode::CanisterReject,
        StateError::CanisterStopping(_) => RejectCode::CanisterReject,
        StateError::InvariantBroken(_) => RejectCode::SysTransient,
        StateError::UnknownSubnetMethod(_) => RejectCode::CanisterReject,
        StateError::NonMatchingResponse { .. } => RejectCode::SysFatal,
        StateError::InvalidSubnetPayload => RejectCode::CanisterReject,
        StateError::OutOfMemory { .. } => RejectCode::SysTransient,
        StateError::BitcoinStateError(_) => RejectCode::SysTransient,
    }
}

/// Ensures that the given signals are vaild (strictly increasing, before
/// `signals_end`).
fn assert_valid_signals(
    signals_end: StreamIndex,
    reject_signals: &VecDeque<StreamIndex>,
    stream_component: StreamComponent,
) {
    use std::iter::once;
    let shifted = reject_signals.iter().skip(1).chain(once(&signals_end));
    assert!(
        // Check that signals are stricly monotonic and below signals_end.
        reject_signals.iter().zip(shifted).all(|(x, y)| x < y),
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
