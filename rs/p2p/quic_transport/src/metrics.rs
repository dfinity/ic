use ic_metrics::{tokio_metrics_collector::TokioTaskMetricsCollector, MetricsRegistry};
use ic_types::NodeId;
use prometheus::{GaugeVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec};
use quinn::Connection;
use tokio_metrics::TaskMonitor;

const CONNECTION_RESULT_LABEL: &str = "status";
const PEER_ID_LABEL: &str = "peer";
const REQUEST_TASK_MONITOR_NAME: &str = "quic_transport_request_handler";
const REQUEST_HANDLER_STREAM_TYPE_LABEL: &str = "stream";
const REQUEST_HANDLER_ERROR_TYPE_LABEL: &str = "error";
pub(crate) const CONNECTION_RESULT_SUCCESS_LABEL: &str = "success";
pub(crate) const CONNECTION_RESULT_FAILED_LABEL: &str = "failed";
pub(crate) const REQUEST_HANDLER_ERROR_TYPE_ACCEPT: &str = "accept";
pub(crate) const REQUEST_HANDLER_ERROR_TYPE_APP: &str = "app";
pub(crate) const REQUEST_HANDLER_ERROR_TYPE_FINISH: &str = "finish";
pub(crate) const REQUEST_HANDLER_ERROR_TYPE_READ: &str = "read";
pub(crate) const REQUEST_HANDLER_ERROR_TYPE_WRITE: &str = "write";
pub(crate) const REQUEST_HANDLER_STREAM_TYPE_BIDI: &str = "bidi";
pub(crate) const REQUEST_HANDLER_STREAM_TYPE_UNI: &str = "uni";

#[derive(Debug, Clone)]
pub struct QuicTransportMetrics {
    // Connection manager
    pub active_connections: IntGauge,
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
    // Quinn
    quinn_frame_rx_data_blocked_total: IntGaugeVec,
    quinn_frame_rx_stream_data_blocked_total: IntGaugeVec,
    quinn_frame_rx_streams_blocked_bidi_total: IntGaugeVec,
    quinn_path_rtt_duration: GaugeVec,
    quinn_path_cwnd_size: IntGaugeVec,
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
                &[
                    REQUEST_HANDLER_STREAM_TYPE_LABEL,
                    REQUEST_HANDLER_ERROR_TYPE_LABEL,
                ],
            ),
            // Quinn stats
            // Indicates that sending data is blocked due to connection level flow control.
            quinn_frame_rx_data_blocked_total: metrics_registry.int_gauge_vec(
                "quic_transport_quinn_frame_rx_data_blocked_total",
                "Quinn connection stat.",
                &[PEER_ID_LABEL],
            ),
            // Indicates that sending data is blocked due to stream level flow control.
            quinn_frame_rx_stream_data_blocked_total: metrics_registry.int_gauge_vec(
                "quic_transport_quinn_frame_rx_stream_data_blocked_total",
                "Blocked stream data frames received.",
                &[PEER_ID_LABEL],
            ),
            // Indicates that opening a new stream is blocked because already at bidi stream limit.
            quinn_frame_rx_streams_blocked_bidi_total: metrics_registry.int_gauge_vec(
                "quic_transport_quinn_frame_rx_streams_blocked_bidi_total",
                "Blocked bidi stream frames received.",
                &[PEER_ID_LABEL],
            ),
            quinn_path_rtt_duration: metrics_registry.gauge_vec(
                "quic_transport_quinn_path_rtt_duration",
                "Estimated rtt of this connection.",
                &[PEER_ID_LABEL],
            ),
            // Congestion window of this connection.
            quinn_path_cwnd_size: metrics_registry.int_gauge_vec(
                "quic_transport_quinn_path_cwnd_size",
                "Congestion window of this connection.",
                &[PEER_ID_LABEL],
            ),
        }
    }

    pub(crate) fn collect_quic_connection_stats(&self, conn: &Connection, peer_id: &NodeId) {
        let stats = conn.stats();
        // frame stats
        self.quinn_frame_rx_data_blocked_total
            .with_label_values(&[&peer_id.to_string()])
            .set(stats.frame_rx.data_blocked as i64);
        self.quinn_frame_rx_stream_data_blocked_total
            .with_label_values(&[&peer_id.to_string()])
            .set(stats.frame_rx.stream_data_blocked as i64);
        self.quinn_frame_rx_streams_blocked_bidi_total
            .with_label_values(&[&peer_id.to_string()])
            .set(stats.frame_rx.streams_blocked_bidi as i64);

        self.quinn_path_rtt_duration
            .with_label_values(&[&peer_id.to_string()])
            .set(stats.path.rtt.as_secs_f64());
        self.quinn_path_cwnd_size
            .with_label_values(&[&peer_id.to_string()])
            .set(stats.path.cwnd as i64);
    }
}
