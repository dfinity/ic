//! Transport related metrics

use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec};

pub(crate) const STATUS_SUCCESS: &str = "success";
pub(crate) const STATUS_ERROR: &str = "error";

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
                &["peer_id", "flow_tag"],
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
    pub(crate) client_send_time_msec: HistogramVec,
    pub(crate) socket_write_bytes: IntCounterVec,
    pub(crate) socket_write_size: HistogramVec,
    pub(crate) socket_write_time_msec: HistogramVec,
    pub(crate) socket_read_bytes: IntCounterVec,
    pub(crate) socket_heart_beat_timeouts: IntCounterVec,
    pub(crate) heart_beats_sent: IntCounterVec,
    pub(crate) heart_beats_received: IntCounterVec,
    pub(crate) write_tasks: IntGauge,
    pub(crate) read_tasks: IntGauge,
    pub(crate) write_task_overhead_time_msec: HistogramVec,
}

impl DataPlaneMetrics {
    pub(crate) fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            // TODO: (NET-867)
            client_send_time_msec: HistogramVec::new(
                HistogramOpts::new(
                    "transport_client_send_time_msec",
                    "Time spent in client message callback, in milliseconds",
                )
                .buckets(
                    // 1ms, 2ms, 5ms - 100 sec, 200 sec, 500 sec
                    decimal_buckets(0, 5),
                ),
                &["flow_peer_id", "flow_tag"],
            )
            .unwrap(),
            socket_write_bytes: metrics_registry.int_counter_vec(
                "transport_socket_write_bytes",
                "Bytes written to sockets",
                &["flow_peer_id", "flow_tag"],
            ),
            // TODO: (NET-867)
            socket_write_size: HistogramVec::new(
                HistogramOpts::new(
                    "transport_socket_write_size",
                    "Bytes written per socket write",
                )
                .buckets(
                    // 1K, 2K, 5K - 1MB, 2MB, 5MB
                    decimal_buckets(3, 6),
                ),
                &["flow_peer_id", "flow_tag"],
            )
            .unwrap(),
            // TODO: (NET-867)
            socket_write_time_msec: HistogramVec::new(
                HistogramOpts::new(
                    "transport_socket_write_time_msec",
                    "Socket write time, in milliseconds",
                )
                .buckets(
                    // 1ms, 2ms, 5ms - 100 sec, 200 sec, 500 sec
                    decimal_buckets(0, 5),
                ),
                &["flow_peer_id", "flow_tag"],
            )
            .unwrap(),
            socket_read_bytes: metrics_registry.int_counter_vec(
                "transport_socket_read_bytes",
                "Bytes read from sockets",
                &["flow_peer_id", "flow_tag"],
            ),
            socket_heart_beat_timeouts: metrics_registry.int_counter_vec(
                "transport_heart_beat_timeouts",
                "Number of times the heart beat timed out.",
                &["flow_peer_id", "flow_tag"],
            ),
            heart_beats_received: metrics_registry.int_counter_vec(
                "transport_heart_beats_received",
                "Number of heart beats as seen by receiver",
                &["flow_peer_id", "flow_tag"],
            ),
            heart_beats_sent: metrics_registry.int_counter_vec(
                "transport_heart_beats_sent",
                "Number of heart beats sent by sender",
                &["flow_peer_id", "flow_tag"],
            ),
            write_tasks: metrics_registry
                .int_gauge("transport_write_tasks", "Active data plane write tasks"),
            read_tasks: metrics_registry
                .int_gauge("transport_read_tasks", "Active data plane read tasks"),
            // TODO: (NET-867)
            write_task_overhead_time_msec: HistogramVec::new(
                HistogramOpts::new(
                    "transport_write_task_overhead_time_msec",
                    "Time before socket write, in milliseconds",
                )
                .buckets(
                    // 1ms, 2ms, 5ms - 100 sec, 200 sec, 500 sec
                    decimal_buckets(0, 5),
                ),
                &["flow_peer_id", "flow_tag"],
            )
            .unwrap(),
        }
    }
}

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
            // TODO: (NET-867)
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
