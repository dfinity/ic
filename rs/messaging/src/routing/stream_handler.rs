use crate::message_routing::LatencyMetrics;
use ic_logger::{debug, trace, warn, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_replicated_state::{
    canister_state::QUEUE_INDEX_NONE,
    metadata_state::Stream,
    replicated_state::{
        LABEL_VALUE_CANISTER_NOT_FOUND, LABEL_VALUE_CANISTER_OUT_OF_CYCLES,
        LABEL_VALUE_CANISTER_STOPPED, LABEL_VALUE_CANISTER_STOPPING,
        LABEL_VALUE_INVALID_SUBNET_PAYLOAD, LABEL_VALUE_QUEUE_FULL,
        LABEL_VALUE_UNKNOWN_SUBNET_METHOD,
    },
    ReplicatedState, StateError,
};
use ic_types::{
    messages::{Payload, RejectContext, RequestOrResponse, Response},
    user_error::RejectCode,
    xnet::{StreamIndex, StreamSlice},
    SubnetId,
};
use prometheus::{Histogram, IntCounter, IntCounterVec, IntGaugeVec};
use std::cell::RefCell;
use std::collections::BTreeMap;
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
    /// Backlog of XNet messages based on end in stream header and last message
    /// in slice, per subnet.
    pub xnet_message_backlog: IntGaugeVec,
}

const METRIC_INDUCTED_XNET_MESSAGES: &str = "mr_inducted_xnet_message_count";
const METRIC_INDUCTED_XNET_PAYLOAD_SIZES: &str = "mr_inducted_xnet_payload_size_bytes";
const METRIC_GCED_XNET_MESSAGES: &str = "mr_gced_xnet_message_count";
const METRIC_XNET_MESSAGE_BACKLOG: &str = "mr_xnet_message_backlog";

const LABEL_STATUS: &str = "status";
const LABEL_VALUE_SUCCESS: &str = "success";
const LABEL_VALUE_SENDER_SUBNET_MISMATCH: &str = "SenderSubnetMismatch";
const LABEL_VALUE_SENDER_SUBNET_UNKNOWN: &str = "SenderSubnetUnknown";
const LABEL_TYPE: &str = "type";
const LABEL_VALUE_TYPE_REQUEST: &str = "request";
const LABEL_VALUE_TYPE_RESPONSE: &str = "response";
const LABEL_SUBNET: &str = "subnet";

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
            // 10 B - 5 MB
            decimal_buckets(1, 6),
        );
        let gced_xnet_messages = metrics_registry.int_counter(
            METRIC_GCED_XNET_MESSAGES,
            "Garbage collected XNet messages.",
        );
        let xnet_message_backlog = metrics_registry.int_gauge_vec(
            METRIC_XNET_MESSAGE_BACKLOG,
            "Backlog of XNet messages, pre sending subnet.",
            &[LABEL_SUBNET],
        );

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
                LABEL_VALUE_SENDER_SUBNET_UNKNOWN,
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
            xnet_message_backlog,
        }
    }
}

/// Interface for the `StreamHandler` sub-component.  Invoked by `Demux`.
pub(crate) trait StreamHandler: Send {
    /// Processes `StreamSlices`. The two stages of processing are to
    ///  1. clean up streams based on the received signals; and
    ///  2. induct input messages (adding outgoing signals as appropriate).
    fn process_stream_slices(
        &self,
        state: ReplicatedState,
        stream_slices: BTreeMap<SubnetId, StreamSlice>,
    ) -> ReplicatedState;
}

pub(crate) struct StreamHandlerImpl {
    subnet_id: SubnetId,
    metrics: StreamHandlerMetrics,
    time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
    time_in_backlog_metrics: RefCell<LatencyMetrics>,
    log: ReplicaLogger,
}

impl StreamHandlerImpl {
    pub(crate) fn new(
        subnet_id: SubnetId,
        metrics_registry: &MetricsRegistry,
        time_in_stream_metrics: Arc<Mutex<LatencyMetrics>>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            subnet_id,
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
            let mut time_in_backlog_metrics = self.time_in_backlog_metrics.borrow_mut();
            stream_slices
                .iter()
                .for_each(|(remote_subnet, stream_slice)| {
                    time_in_backlog_metrics.observe_header(*remote_subnet, stream_slice.header());
                });
        }

        // Induct our own loopback stream first, if one exists and has any messages.
        state = self.induct_loopback_stream(state);

        // Garbage collect our stream state based on the contents of the slices.
        state = self.garbage_collect_local_state(state, &stream_slices);

        // Induct messsages from the slices, adding signals as appropriate.
        self.observe_stream_slices(&stream_slices);
        self.induct_stream_slices(state, stream_slices)
    }
}

impl StreamHandlerImpl {
    /// Inducts and consumes all messages from the subnet's loopback stream.
    ///
    /// After the call completes, the loopback stream may only contain reject
    /// responses, with all initial messages garbage collected and signals
    /// generated for them.
    fn induct_loopback_stream(&self, mut state: ReplicatedState) -> ReplicatedState {
        let loopback_stream = state.get_stream(self.subnet_id);

        // All done if the loopback stream does not exist or is empty.
        if loopback_stream.is_none() || loopback_stream.unwrap().messages.is_empty() {
            return state;
        }
        let loopback_stream = loopback_stream.unwrap();

        // Precondition: ensure that the loopback stream has had signals for all
        // earlier messages.
        assert!(
            loopback_stream.signals_end == loopback_stream.messages.begin(),
            "Expecting loopback stream signals to end ({}) where messages begin ({})",
            loopback_stream.signals_end,
            loopback_stream.messages.begin()
        );

        // Remember the original messages end index, we may append reject responses.
        let loopback_stream_messages_end = loopback_stream.messages.end();

        // Wrap it within a StreamSlice.
        let loopback_stream_slice: StreamSlice = loopback_stream.clone().into();

        // Induct all messages. This will add signals to the loopback stream.
        let mut stream_slices = BTreeMap::new();
        stream_slices.insert(self.subnet_id, loopback_stream_slice);
        state = self.induct_stream_slices(state, stream_slices);

        // We know for sure that the loopback stream exists, so it is safe to unwrap.
        let loopback_stream = state.get_mut_stream(self.subnet_id).unwrap();
        // Garbage collect all initial messages.
        self.discard_messages_before(loopback_stream, loopback_stream_messages_end);

        state
    }

    /// Garbage collects outgoing `Streams` based on the signals present in
    /// incoming `stream_slices`. As we do not have explicit signals (only a
    /// `signals_end` index) there is no need to garbage collect signals.
    fn garbage_collect_local_state(
        &self,
        mut state: ReplicatedState,
        stream_slices: &BTreeMap<SubnetId, StreamSlice>,
    ) -> ReplicatedState {
        for (remote_subnet, stream_slice) in stream_slices {
            match state.get_mut_stream(*remote_subnet) {
                Some(stream) => {
                    self.garbage_collect_messages(stream, *remote_subnet, stream_slice);
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
        state
    }

    /// Garbage collects the messages of an outgoing `Stream` based on the
    /// signals in an incoming stream slice.
    ///
    /// Panics if any of the incoming slices' `signals_end` refers to a
    /// nonexistent (already garbage collected or future) message.
    fn garbage_collect_messages(
        &self,
        stream: &mut Stream,
        remote_subnet: SubnetId,
        stream_slice: &StreamSlice,
    ) {
        assert!(
            stream.messages.begin() <= stream_slice.header().signals_end
                && stream_slice.header().signals_end <= stream.messages.end(),
            "Invalid signals in stream slice from subnet {}: signals_end {}, messages [{}, {})",
            remote_subnet,
            stream_slice.header().signals_end,
            stream.messages.begin(),
            stream.messages.end(),
        );

        {
            let mut time_in_stream_metrics = self.time_in_stream_metrics.lock().unwrap();
            time_in_stream_metrics.observe_indexes(
                remote_subnet,
                stream.messages.begin()..stream_slice.header().signals_end,
            );
        }

        // Remove the consumed messages from our outgoing stream.
        self.discard_messages_before(stream, stream_slice.header().signals_end);
    }

    /// Helper function, discards all messages before `new_begin` while
    /// recording the number of garbage collected messages.
    fn discard_messages_before(&self, stream: &mut Stream, new_begin: StreamIndex) {
        self.observe_gced_messages(stream.messages.begin(), new_begin);
        stream.messages.discard_before(new_begin);
    }

    /// Records latency metrics for the provided stream slices.
    fn observe_stream_slices(&self, stream_slices: &BTreeMap<SubnetId, StreamSlice>) {
        let mut time_in_backlog_metrics = self.time_in_backlog_metrics.borrow_mut();
        for (remote_subnet_id, stream_slice) in stream_slices {
            if let Some(messages) = stream_slice.messages() {
                time_in_backlog_metrics
                    .observe_indexes(*remote_subnet_id, messages.begin()..messages.end());
            }
        }
    }

    /// Inducts the messages in the provided stream slices into the
    /// `InductionPool`, generating a signal for each message.
    fn induct_stream_slices(
        &self,
        mut state: ReplicatedState,
        stream_slices: BTreeMap<SubnetId, StreamSlice>,
    ) -> ReplicatedState {
        let mut streams = state.take_streams();

        for (remote_subnet_id, mut stream_slice) in stream_slices {
            // Output stream, for resulting signals and (in the initial iteration) reject
            // `Responses`.
            let stream = streams.entry(remote_subnet_id).or_default();

            while let Some((stream_index, msg)) = stream_slice.pop_message() {
                self.induct_message(msg, remote_subnet_id, stream_index, &mut state, stream);
            }
        }

        state.put_streams(streams);
        state
    }

    /// Attempts to unducts the given message at `stream_index` in the incoming
    /// stream from `remote_subnet_id` into `state` and generates a signal into
    /// the provided reverse `stream`. The induction attempt will result in one
    /// of the following outcomes:
    ///
    ///  * enqueuing the message into the corresponding input queue;
    ///  * a reject response enqueued into the reverse stream: if enqueuing of a
    ///    request failed (queue full, canister not found);
    ///  * no other action: if the sender canister and source subnet do not
    ///    match; or enqueuing of a response failed.
    fn induct_message(
        &self,
        msg: RequestOrResponse,
        remote_subnet_id: SubnetId,
        stream_index: StreamIndex,
        state: &mut ReplicatedState,
        stream: &mut Stream,
    ) {
        let payload_size = match &msg {
            RequestOrResponse::Request(req) => req.payload_size_bytes().get(),
            RequestOrResponse::Response(res) => res.response_payload.size_of().get(),
        };
        let msg_type = match msg {
            RequestOrResponse::Request(_) => LABEL_VALUE_TYPE_REQUEST,
            RequestOrResponse::Response(_) => LABEL_VALUE_TYPE_RESPONSE,
        };

        match state
            .metadata
            .network_topology
            .routing_table
            .route(msg.sender().get())
        {
            Some(host_subnet) => {
                if host_subnet == remote_subnet_id {
                    // Sender is hosted by `remote_subnet_id`, proceed with induction.
                    match state.push_input(QUEUE_INDEX_NONE, msg) {
                        // Message successfully inducted, all done.
                        Ok(()) => {
                            self.observe_inducted_message_status(msg_type, LABEL_VALUE_SUCCESS);
                            self.observe_inducted_payload_size(payload_size);
                        }

                        // Message not inducted.
                        Err((err, msg)) => {
                            debug!(self.log, "Induction failed with error '{}', generating reject Response for {:?}", &err, &msg);
                            self.observe_inducted_message_status(msg_type, err.to_label_value());

                            let code = reject_code_for_state_error(&err);
                            self.try_enqueue_reject_response(msg, code, err.to_string(), stream);
                        }
                    }
                } else {
                    // Sender is hosted by a subnet other than `remote_subnet_id`.
                    //
                    // Do not enqueue a reject response as remote subnet is likely malicious and
                    // trying to cause a memory leak by sending bogus messages and never consuming
                    // reject responses.
                    warn!(self.log,
                        "Dropping message from subnet {} claiming to be from sender {} hosted by subnet {}: {:?}",
                        remote_subnet_id,
                        msg.sender(),
                        host_subnet,
                        msg);
                    self.observe_inducted_message_status(
                        msg_type,
                        LABEL_VALUE_SENDER_SUBNET_MISMATCH,
                    );
                }
            }

            // Unknown host subnet for sender.
            //
            // Not enqueuing a reject response, see explanation above.
            None => {
                warn!(self.log,
                    "Dropping message from subnet {} claiming to be from sender {} with unknown host subnet: {:?}",
                    remote_subnet_id,
                    msg.sender(),
                    msg);
                self.observe_inducted_message_status(msg_type, LABEL_VALUE_SENDER_SUBNET_UNKNOWN);
            }
        }

        // Signals use the `StreamIndex` of the incoming message.
        assert_eq!(
            stream.signals_end, stream_index,
            "Expecting signal with stream index {}, got {}",
            stream.signals_end, stream_index
        );
        stream.signals_end.inc_assign();
    }

    /// Enqueues a reject `Response` for the provided `msg` (iff it is a
    /// `Request`) onto the provided `stream`, with the given reject code
    /// and error message.
    ///
    /// The VSR generates `Accept` signals for all messages, but if the message
    /// cannot be inducted (e.g. because the canister is not found or the queue
    /// is full) Message Routing generates a reject `Response` and enqueues it
    /// directly onto the reverse stream.
    fn try_enqueue_reject_response(
        &self,
        msg: RequestOrResponse,
        reject_code: RejectCode,
        reject_message: String,
        stream: &mut Stream,
    ) {
        match msg {
            RequestOrResponse::Request(_) => {
                let context = RejectContext::new(reject_code, reject_message);
                stream.messages.push(generate_reject_response(msg, context))
            }
            RequestOrResponse::Response(_) => {}
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
        StateError::CanisterOutOfCycles { .. } => RejectCode::SysTransient,
        StateError::CanisterNotFound(_) => RejectCode::DestinationInvalid,
        StateError::CanisterStopped(_) => RejectCode::CanisterReject,
        StateError::CanisterStopping(_) => RejectCode::CanisterReject,
        StateError::UnknownSubnetMethod(_) => RejectCode::CanisterReject,
        StateError::InvalidSubnetPayload => RejectCode::CanisterReject,
    }
}
