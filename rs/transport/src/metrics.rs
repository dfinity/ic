//! Transport related metrics

use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec};

pub(crate) const STATUS_SUCCESS: &str = "success";
pub(crate) const STATUS_ERROR: &str = "error";
pub(crate) const LABEL_DETAIL: &str = "detail";
pub(crate) const LABEL_CHANNEL_ID: &str = "channel_id";
pub(crate) const TRANSPORT_API: &str = "transport_api";

/// This is intended to be used as RAII type that will increment the gauge
/// at construction and decrease the gauge on Drop.
pub(crate) struct IntGaugeResource(IntGauge);

impl IntGaugeResource {
    pub(crate) fn new(gauge: IntGauge) -> Self {
        gauge.inc();
        IntGaugeResource(gauge)
    }
}

impl Drop for IntGaugeResource {
    fn drop(&mut self) {
        self.0.dec();
    }
}

#[derive(Clone)]
pub(crate) struct ControlPlaneMetrics {
    pub(crate) flow_state: IntGaugeVec,
    pub(crate) tcp_accepts: IntCounterVec,
    pub(crate) tcp_accept_conn_success: IntCounterVec,
    pub(crate) tcp_connects: IntCounterVec,
    pub(crate) tcp_conn_to_server_success: IntCounterVec,
    pub(crate) retry_connection: IntCounterVec,
    pub(crate) tls_handshakes: IntCounterVec,
    pub(crate) async_tasks: IntGaugeVec,
}

impl ControlPlaneMetrics {
    pub(crate) fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            async_tasks: metrics_registry.int_gauge_vec(
                "transport_async_tasks",
                "Current number of running tokio tasks",
                &["name"],
            ),
            flow_state: metrics_registry.int_gauge_vec(
                "transport_flow_state",
                "Current state of the flow",
                &["flow_peer_id", "flow_tag"],
            ),
            tcp_accepts: metrics_registry.int_counter_vec(
                "transport_tcp_accepts_total",
                "Total incoming TcpStream in server mode",
                &["status"],
            ),
            tcp_accept_conn_success: metrics_registry.int_counter_vec(
                "transport_tcp_accept_conn_success",
                "Successfully connected to incoming TcpStream in server mode",
                &["flow_tag"],
            ),
            tcp_connects: metrics_registry.int_counter_vec(
                "transport_tcp_connects_total",
                "Total outgoing connects in client mode",
                &["status"],
            ),
            tcp_conn_to_server_success: metrics_registry.int_counter_vec(
                "transport_conn_to_server_success",
                "Successfully connected to peer TCP server as client",
                &["flow_peer_id", "flow_tag"],
            ),
            retry_connection: metrics_registry.int_counter_vec(
                "transport_retry_connection",
                "Connection retries to reconnect to a peer from Transport",
                &["peer_id", "flow_tag", TRANSPORT_API],
            ),
            tls_handshakes: metrics_registry.int_counter_vec(
                "transport_tls_handshakes_total",
                "TLS handshakes in Transport",
                &["role", "status"],
            ),
        }
    }
}

#[derive(Clone)]
pub(crate) struct DataPlaneMetrics {
    pub(crate) event_handler_message_duration: HistogramVec,
    pub(crate) read_message_duration: HistogramVec,
    pub(crate) write_bytes_total: IntCounterVec,
    pub(crate) send_message_duration: HistogramVec,
    pub(crate) read_bytes_total: IntCounterVec,
    pub(crate) message_read_errors_total: IntCounterVec,
    pub(crate) heart_beats_sent: IntCounterVec,
    pub(crate) heart_beats_received: IntCounterVec,
    pub(crate) write_tasks: IntGauge,
    pub(crate) read_tasks: IntGauge,
}

impl DataPlaneMetrics {
    pub(crate) fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            event_handler_message_duration: HistogramVec::new(
                HistogramOpts::new(
                    "transport_event_handler_message_duration_seconds",
                    "Time spent by the client callback processing a message event.",
                )
                .buckets(decimal_buckets(-3, 1)),
                &[LABEL_CHANNEL_ID, TRANSPORT_API],
            )
            .unwrap(),
            read_message_duration: HistogramVec::new(
                HistogramOpts::new(
                    "read_message_duration_seconds",
                    "Time spent to parse a full message.",
                )
                .buckets(decimal_buckets(-3, 1)),
                &[LABEL_CHANNEL_ID, LABEL_DETAIL, TRANSPORT_API],
            )
            .unwrap(),
            write_bytes_total: metrics_registry.int_counter_vec(
                "transport_write_bytes_total",
                "Total bytes written at the application-level",
                &[LABEL_CHANNEL_ID, TRANSPORT_API],
            ),
            send_message_duration: HistogramVec::new(
                HistogramOpts::new(
                    "transport_send_message_duration_seconds",
                    "Time it takes for a single message to be flushed into the lower level transport",
                )
                .buckets(
                    decimal_buckets(-3, 1),
                ),
                &[LABEL_CHANNEL_ID, TRANSPORT_API],
            )
            .unwrap(),
            read_bytes_total: metrics_registry.int_counter_vec(
                "transport_read_bytes_total",
                "Total bytes read at the application-level",
                &[LABEL_CHANNEL_ID, TRANSPORT_API],
            ),
            message_read_errors_total: metrics_registry.int_counter_vec(
                "transport_read_message_errors_total",
                "Number of times reading a single message failed",
                &[LABEL_CHANNEL_ID, LABEL_DETAIL, TRANSPORT_API],
            ),
            heart_beats_received: metrics_registry.int_counter_vec(
                "transport_heart_beats_received",
                "Number of heart beats as seen by receiver",
                &[LABEL_CHANNEL_ID, TRANSPORT_API],
            ),
            heart_beats_sent: metrics_registry.int_counter_vec(
                "transport_heart_beats_sent",
                "Number of heart beats sent by sender",
                &[LABEL_CHANNEL_ID, TRANSPORT_API],
            ),
            write_tasks: metrics_registry
                .int_gauge("transport_write_tasks", "Active data plane write tasks"),
            read_tasks: metrics_registry
                .int_gauge("transport_read_tasks", "Active data plane read tasks"),
        }
    }
}

// TODO: (NET-867)
/// Per send queue metrics
#[derive(Clone)]
pub(crate) struct SendQueueMetrics {
    pub(crate) add_count: IntCounterVec,
    pub(crate) add_bytes: IntCounterVec,
    pub(crate) remove_count: IntCounterVec,
    pub(crate) remove_bytes: IntCounterVec,
    pub(crate) queue_full: IntCounterVec,
    pub(crate) queue_clear: IntCounterVec,
    pub(crate) receive_end_updates: IntCounterVec,
    pub(crate) queue_time_msec: HistogramVec,
    pub(crate) no_receiver: IntCounterVec,
}

impl SendQueueMetrics {
    pub(crate) fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            add_count: metrics_registry.int_counter_vec(
                "transport_send_queue_add_count",
                "Enqueued messages",
                &["flow_peer_id", "flow_tag"],
            ),
            add_bytes: metrics_registry.int_counter_vec(
                "transport_send_queue_add_bytes",
                "Enqueued bytes",
                &["flow_peer_id", "flow_tag"],
            ),
            remove_count: metrics_registry.int_counter_vec(
                "transport_send_queue_remove_count",
                "Dequeued messages",
                &["flow_peer_id", "flow_tag"],
            ),
            remove_bytes: metrics_registry.int_counter_vec(
                "transport_send_queue_remove_bytes",
                "Dequeued bytes",
                &["flow_peer_id", "flow_tag"],
            ),
            queue_full: metrics_registry.int_counter_vec(
                "transport_send_queue_full",
                "Queue full count",
                &["flow_peer_id", "flow_tag"],
            ),
            queue_clear: metrics_registry.int_counter_vec(
                "transport_send_queue_clear",
                "Queue cleared count",
                &["flow_peer_id", "flow_tag"],
            ),
            receive_end_updates: metrics_registry.int_counter_vec(
                "transport_receive_end_updates",
                "Channel receive end update count",
                &["flow_peer_id", "flow_tag"],
            ),
            queue_time_msec: HistogramVec::new(
                HistogramOpts::new(
                    "transport_send_queue_time_msec",
                    "Time spent in the send queue, in milliseconds",
                )
                .buckets(
                    // 1ms, 2ms, 5ms - 100 sec, 200 sec, 500 sec
                    decimal_buckets(0, 5),
                ),
                &["flow_peer_id", "flow_tag"],
            )
            .unwrap(),
            no_receiver: metrics_registry.int_counter_vec(
                "transport_send_no_receiver",
                "Message send failed as receive channel end closed",
                &["flow_peer_id", "flow_tag"],
            ),
        }
    }
}
