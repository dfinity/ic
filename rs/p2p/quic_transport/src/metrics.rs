use ic_base_types::NodeId;
use ic_metrics::{
    buckets::decimal_buckets, tokio_metrics_collector::TokioTaskMetricsCollector, MetricsRegistry,
};
use prometheus::{GaugeVec, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec};
use quinn::{Connection, ConnectionError, ReadError, ReadToEndError, StoppedError, WriteError};
use tokio_metrics::TaskMonitor;

const CONNECTION_RESULT_LABEL: &str = "status";
const PEER_ID_LABEL: &str = "peer";
const REQUEST_TASK_MONITOR_NAME: &str = "quic_transport_request_handler";
const STREAM_TYPE_LABEL: &str = "stream";
const HANDLER_LABEL: &str = "handler";
const ERROR_TYPE_LABEL: &str = "error";
const REQUEST_TYPE_LABEL: &str = "request";
pub(crate) const CONNECTION_RESULT_SUCCESS_LABEL: &str = "success";
pub(crate) const CONNECTION_RESULT_FAILED_LABEL: &str = "failed";
pub(crate) const ERROR_TYPE_APP: &str = "app";
pub(crate) const INFALIBBLE: &str = "infallible";
const ERROR_CLOSED_STREAM: &str = "closed_stream";
const ERROR_RESET_STREAM: &str = "reset_stream";
const ERROR_STOPPED_STREAM: &str = "stopped_stream";
const ERROR_APP_CLOSED_CONN: &str = "app_closed_conn";
const ERROR_LOCALLY_CLOSED_CONN: &str = "locally_closed_conn";
const ERROR_QUIC_CLOSED_CONN: &str = "quic_closed_conn";

pub(crate) const STREAM_TYPE_BIDI: &str = "bidi";

#[derive(Clone, Debug)]
pub struct QuicTransportMetrics {
    // Connection manager
    pub active_connections: IntGauge,
    pub peer_map_size: IntGauge,
    pub topology_size: IntGauge,
    pub topology_changes_total: IntCounter,
    pub peers_removed_total: IntCounter,
    pub inbound_connection_total: IntCounter,
    pub outbound_connection_total: IntCounter,
    pub connection_results_total: IntCounterVec,
    pub connecting_connections: IntGauge,
    pub delay_queue_size: IntGauge,
    pub closed_request_handlers_total: IntCounter,
    // Request handler
    pub request_task_monitor: TaskMonitor,
    pub request_handle_errors_total: IntCounterVec,
    pub request_handle_bytes_received_total: IntCounterVec,
    pub request_handle_bytes_sent_total: IntCounterVec,
    pub request_handle_duration_seconds: HistogramVec,
    // Connection handle
    pub connection_handle_bytes_received_total: IntCounterVec,
    pub connection_handle_bytes_sent_total: IntCounterVec,
    pub connection_handle_duration_seconds: HistogramVec,
    pub connection_handle_errors_total: IntCounterVec,
    // Quinn
    quinn_path_rtt_seconds: GaugeVec,
    quinn_path_congestion_window: IntGaugeVec,
    quinn_path_sent_packets: IntGaugeVec,
    quinn_path_lost_packets: IntGaugeVec,
}

impl QuicTransportMetrics {
    /// The constructor returns a `GossipMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        let (collector, request_task_monitor) =
            TokioTaskMetricsCollector::new(REQUEST_TASK_MONITOR_NAME);
        metrics_registry.register(collector);

        Self {
            // Connection manager
            active_connections: metrics_registry.int_gauge(
                "quic_transport_active_connections",
                "Number of active quic connections.",
            ),
            peer_map_size: metrics_registry.int_gauge(
                "quic_transport_peer_map_size",
                "Number of connections stored in the peer map.",
            ),
            topology_size: metrics_registry.int_gauge(
                "quic_transport_toplogy_size",
                "Number of peers in topology.",
            ),
            topology_changes_total: metrics_registry.int_counter(
                "quic_transport_topology_changes_total",
                "Number topology changes deliverd by peer manager.",
            ),
            peers_removed_total: metrics_registry.int_counter(
                "quic_transport_peers_removed_total",
                "Peers removed because they are not part of topology anymore.",
            ),
            inbound_connection_total: metrics_registry.int_counter(
                "quic_transport_inbound_connection_total",
                "Number of received inbound connection requests.",
            ),
            outbound_connection_total: metrics_registry.int_counter(
                "quic_transport_outbound_connection_total",
                "Number of outbound connection requests.",
            ),
            connection_results_total: metrics_registry.int_counter_vec(
                "quic_transport_connection_results_total",
                "Connection setup outcome.",
                &[CONNECTION_RESULT_LABEL],
            ),
            connecting_connections: metrics_registry.int_gauge(
                "quic_transport_connecting_connections",
                "Number of connections that are in connecting state.",
            ),
            delay_queue_size: metrics_registry
                .int_gauge("quic_transport_delay_queue_size", "Size of delay queue."),
            closed_request_handlers_total: metrics_registry.int_counter(
                "quic_transport_closed_request_handler_total",
                "Number of closed request handlers.",
            ),
            // Request handler
            request_task_monitor,
            request_handle_errors_total: metrics_registry.int_counter_vec(
                "quic_transport_request_handle_errors_total",
                "Request handler errors by stream type and error type.",
                &[STREAM_TYPE_LABEL, ERROR_TYPE_LABEL],
            ),
            request_handle_bytes_received_total: metrics_registry.int_counter_vec(
                "quic_transport_request_handle_bytes_received_total",
                "Request handler requests total by handler.",
                &[HANDLER_LABEL],
            ),
            request_handle_bytes_sent_total: metrics_registry.int_counter_vec(
                "quic_transport_request_handle_bytes_sent_total",
                "Request handler requests total by handler.",
                &[HANDLER_LABEL],
            ),
            request_handle_duration_seconds: metrics_registry.histogram_vec(
                "quic_transport_request_handle_requests_duration_seconds",
                "Request handler request execution duration by handler.",
                decimal_buckets(-2, 0),
                &[HANDLER_LABEL],
            ),
            // Connection handler
            connection_handle_bytes_received_total: metrics_registry.int_counter_vec(
                "quic_transport_connection_handle_bytes_received_total",
                "Request handler requests total by handler.",
                &[HANDLER_LABEL],
            ),
            connection_handle_bytes_sent_total: metrics_registry.int_counter_vec(
                "quic_transport_connection_handle_bytes_sent_total",
                "Request handler requests total by handler.",
                &[HANDLER_LABEL],
            ),
            connection_handle_duration_seconds: metrics_registry.histogram_vec(
                "quic_transport_connection_handle_duration_seconds",
                "Request handler request execution duration by handler.",
                decimal_buckets(-2, 0),
                &[HANDLER_LABEL],
            ),
            connection_handle_errors_total: metrics_registry.int_counter_vec(
                "quic_transport_connection_handle_errors_total",
                "Request handler errors by stream type and error type.",
                &[REQUEST_TYPE_LABEL, ERROR_TYPE_LABEL],
            ),

            // Quinn stats
            quinn_path_rtt_seconds: metrics_registry.gauge_vec(
                "quic_transport_quinn_path_rtt_seconds",
                "Estimated rtt of this connection.",
                &[PEER_ID_LABEL],
            ),
            quinn_path_congestion_window: metrics_registry.int_gauge_vec(
                "quic_transport_quinn_path_congestion_window",
                "Congestion window of this connection.",
                &[PEER_ID_LABEL],
            ),
            quinn_path_sent_packets: metrics_registry.int_gauge_vec(
                "quic_transport_quinn_path_sent_packets",
                "The amount of packets sent on this path.",
                &[PEER_ID_LABEL],
            ),
            quinn_path_lost_packets: metrics_registry.int_gauge_vec(
                "quic_transport_quinn_path_lost_packets",
                "The amount of packets lost on this path.",
                &[PEER_ID_LABEL],
            ),
        }
    }

    pub(crate) fn collect_quic_connection_stats(&self, conn: &Connection, peer_id: &NodeId) {
        let path_stats = conn.stats().path;
        let peer_id_label: [&str; 1] = [&peer_id.to_string()];

        self.quinn_path_rtt_seconds
            .with_label_values(&peer_id_label)
            .set(path_stats.rtt.as_secs_f64());

        self.quinn_path_congestion_window
            .with_label_values(&peer_id_label)
            .set(path_stats.cwnd as i64);

        self.quinn_path_sent_packets
            .with_label_values(&peer_id_label)
            .set(path_stats.sent_packets as i64);

        self.quinn_path_lost_packets
            .with_label_values(&peer_id_label)
            .set(path_stats.lost_packets as i64);
    }
}

pub fn observe_conn_error(err: &ConnectionError, op: &str, counter: &IntCounterVec) {
    match err {
        // TODO: most likely this can be made infallible
        ConnectionError::LocallyClosed => counter
            .with_label_values(&[op, ERROR_LOCALLY_CLOSED_CONN])
            .inc(),
        ConnectionError::ApplicationClosed(_) => counter
            .with_label_values(&[op, ERROR_APP_CLOSED_CONN])
            .inc(),
        // A connection was closed by the QUIC protocol.
        _ => counter
            .with_label_values(&[op, ERROR_QUIC_CLOSED_CONN])
            .inc(),
    }
}

pub fn observe_write_error(err: &WriteError, op: &str, counter: &IntCounterVec) {
    match err {
        // This should be infallible. The peer will never stop a stream, it can only reset it.
        WriteError::Stopped(_) => counter.with_label_values(&[op, ERROR_STOPPED_STREAM]).inc(),
        WriteError::ConnectionLost(conn_err) => observe_conn_error(conn_err, op, counter),
        // This should be infallible
        WriteError::ClosedStream => counter.with_label_values(&[op, ERROR_CLOSED_STREAM]).inc(),
        _ => counter.with_label_values(&[op, INFALIBBLE]).inc(),
    }
}

pub fn observe_read_error(err: &ReadError, op: &str, counter: &IntCounterVec) {
    match err {
        // This can happen if the peer reset the stream due to aborting the future that writes to the stream.
        // E.g. the RPC method is part of a select branch.
        ReadError::Reset(_) => counter.with_label_values(&[op, ERROR_RESET_STREAM]).inc(),
        ReadError::ConnectionLost(conn_err) => observe_conn_error(conn_err, op, counter),
        // If any of the following errors occur it means that we have a bug in the protocol implementation or
        // there is malicious peer on the other side.
        ReadError::IllegalOrderedRead | ReadError::ClosedStream | ReadError::ZeroRttRejected => {
            counter.with_label_values(&[op, INFALIBBLE]).inc()
        }
    }
}

pub fn observe_stopped_error(err: &StoppedError, op: &str, counter: &IntCounterVec) {
    match err {
        StoppedError::ConnectionLost(conn_err) => observe_conn_error(conn_err, op, counter),
        StoppedError::ZeroRttRejected => counter.with_label_values(&[op, INFALIBBLE]).inc(),
    }
}

pub fn observe_read_to_end_error(err: &ReadToEndError, op: &str, counter: &IntCounterVec) {
    match err {
        ReadToEndError::TooLong => counter.with_label_values(&[op, INFALIBBLE]).inc(),
        ReadToEndError::Read(read_err) => observe_read_error(read_err, op, counter),
    }
}
