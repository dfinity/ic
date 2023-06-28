use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::NodeId;
use prometheus::{HistogramVec, IntCounter, IntGauge, IntGaugeVec};
use quinn::Connection;

#[derive(Debug, Clone)]
pub struct QuicTransportMetrics {
    pub active_connections: IntGauge,
    pub connecting_connections: IntGauge,
    pub delay_queue_size: IntGauge,
    pub quic_stats: IntGaugeVec,
    pub inflight_requests: IntGaugeVec,
    pub request_duration: HistogramVec,
    pub closed_request_handlers: IntCounter,
}

impl QuicTransportMetrics {
    /// The constructor returns a `GossipMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            active_connections: metrics_registry.int_gauge(
                "quic_transport_active_connections",
                "Number of active quic connections.",
            ),
            connecting_connections: metrics_registry.int_gauge(
                "quic_transport_connecting_connections",
                "Number of connections that are in connecting state.",
            ),
            delay_queue_size: metrics_registry
                .int_gauge("quic_transport_delay_queue_size", "Size of delay queue."),
            quic_stats: metrics_registry.int_gauge_vec(
                "quic_transport_quinn_stats",
                "Quinn connection stat.",
                &["peer", "stat"],
            ),
            inflight_requests: metrics_registry.int_gauge_vec(
                "quic_transport_inflight_requests",
                "Quinn connection stat.",
                &["peer"],
            ),
            request_duration: metrics_registry.histogram_vec(
                "quic_transport_request_duration_seconds",
                "quic request serving duation. Without reading the request.",
                decimal_buckets(-3, 0),
                // 1ms, 2ms, 5ms, 10ms, 20ms, ..., 10s, 20s, 50s
                &["path", "part"],
            ),
            closed_request_handlers: metrics_registry.int_counter(
                "quic_transport_closed_request_handler_total",
                "Number of times request handler was closed for one peer..",
            ),
        }
    }
    pub(crate) fn collect_quic_connection_stats(&self, conn: &Connection, node_id: &NodeId) {
        let stats = conn.stats();
        // udp stats
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "udp_tx_datagrams"])
            .set(stats.udp_tx.datagrams as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "udp_tx_bytes"])
            .set(stats.udp_tx.bytes as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "udp_tx_transmits"])
            .set(stats.udp_tx.transmits as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "udp_rx_datagrams"])
            .set(stats.udp_rx.datagrams as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "udp_rx_bytes"])
            .set(stats.udp_rx.bytes as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "udp_rx_transmits"])
            .set(stats.udp_rx.transmits as i64);
        // frame stats
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_tx_max_data"])
            .set(stats.frame_tx.max_data as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_tx_max_stream_data"])
            .set(stats.frame_tx.max_stream_data as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_tx_max_streams_bidi"])
            .set(stats.frame_tx.max_streams_bidi as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_tx_stream_data_blocked"])
            .set(stats.frame_tx.stream_data_blocked as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_tx_streams_blocked_bidi"])
            .set(stats.frame_tx.streams_blocked_bidi as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_tx_stream"])
            .set(stats.frame_tx.stream as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_rx_max_data"])
            .set(stats.frame_rx.max_data as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_rx_max_stream_data"])
            .set(stats.frame_rx.max_stream_data as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_rx_max_streams_bidi"])
            .set(stats.frame_rx.max_streams_bidi as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_rx_stream_data_blocked"])
            .set(stats.frame_rx.stream_data_blocked as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_rx_streams_blocked_bidi"])
            .set(stats.frame_rx.streams_blocked_bidi as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "frame_rx_stream"])
            .set(stats.frame_rx.stream as i64);

        // path stat
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "path_cwnd"])
            .set(stats.path.cwnd as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "path_congestion_events"])
            .set(stats.path.congestion_events as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "path_lost_packets"])
            .set(stats.path.lost_packets as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "path_lost_bytes"])
            .set(stats.path.lost_bytes as i64);
        self.quic_stats
            .with_label_values(&[&node_id.to_string(), "path_sent_packets"])
            .set(stats.path.sent_packets as i64);
    }
}
