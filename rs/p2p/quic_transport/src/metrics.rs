use ic_base_types::NodeId;
use ic_metrics::{
    buckets::decimal_buckets, tokio_metrics_collector::TokioTaskMetricsCollector, MetricsRegistry,
};
use prometheus::{GaugeVec, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec};
use quinn::Connection;
use tokio_metrics::TaskMonitor;

use crate::TransportError;

const CONNECTION_RESULT_LABEL: &str = "status";
const PEER_ID_LABEL: &str = "peer";
const REQUEST_TASK_MONITOR_NAME: &str = "quic_transport_request_handler";
const HANDLER_LABEL: &str = "handler";
const ERROR_TYPE_LABEL: &str = "error";
pub(crate) const CONNECTION_RESULT_SUCCESS_LABEL: &str = "success";
pub(crate) const CONNECTION_RESULT_FAILED_LABEL: &str = "failed";

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
                "Peers removed from the peer map.",
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
                &[ERROR_TYPE_LABEL],
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
                &[ERROR_TYPE_LABEL],
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

pub fn observe_transport_error(err: &TransportError, counter: &IntCounterVec) {
    match err {
        TransportError::StreamCancelled => counter.with_label_values(&["stream_cancelled"]).inc(),
        TransportError::ConnectionClosed => counter.with_label_values(&["connection_closed"]).inc(),
        TransportError::TimedOut => counter.with_label_values(&["connection_timed_out"]).inc(),
        TransportError::ConnectionNotFound => {
            counter.with_label_values(&["connection_not_found"]).inc()
        }
        TransportError::Internal(_) => counter.with_label_values(&["internal"]).inc(),
    }
}
