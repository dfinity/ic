use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec};

/// The *Gossip* metrics.
#[derive(Debug, Clone)]
pub struct GossipMetrics {
    /// The time required to execute the given operation in milliseconds.
    pub op_duration: HistogramVec,
    /// The number of chunk requests not found.
    pub chunk_req_not_found: IntCounter,
    /// The number of dropped artifacts.
    pub artifacts_dropped: IntCounter,
}

impl GossipMetrics {
    /// The constructor returns a `GossipMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            op_duration: metrics_registry.histogram_vec(
                "p2p_gossip_op_duration",
                "The time it took to execute the given op, in milliseconds",
                vec![
                    1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 300.0, 400.0, 500.0, 600.0,
                    700.0, 800.0, 900.0, 1000.0, 1200.0, 1400.0, 1600.0, 1800.0, 2000.0, 2500.0,
                    3000.0, 4000.0, 5000.0, 7000.0, 10000.0, 20000.0,
                ],
                &["op"],
            ),
            chunk_req_not_found: metrics_registry
                .int_counter("chunk_req_not_found", "Number of chunk requests not found"),
            artifacts_dropped: metrics_registry.int_counter(
                "p2p_gossip_artifacts_dropped",
                "Number of artifacts dropped by Gossip",
            ),
        }
    }
}

/// The download management metrics.
#[derive(Debug)]
pub struct DownloadManagementMetrics {
    /// The times required to execute the given operation in milliseconds.
    pub op_duration: HistogramVec,
    // Artifact fields.
    /// The number of received artifacts.
    pub artifacts_received: IntCounter,
    /// The number of artifact timeouts.
    pub artifact_timeouts: IntCounter,
    /// The size of received artifacts.
    pub received_artifact_size: IntGauge,
    /// The number of failed integrity hash checks.
    pub integrity_hash_check_failed: IntCounter,

    // Chunking fields.
    /// The number of requested chunks.
    pub chunks_requested: IntCounter,
    /// The number of failures to send chunk requests.
    pub chunk_request_send_failed: IntCounter,
    /// The number of sent chunks.
    pub chunks_sent: IntCounter,
    /// The number of failures to send chunks.
    pub chunk_send_failed: IntCounter,
    /// The number of received chunks.
    pub chunks_received: IntCounter,
    /// The number of timed-out chunks.
    pub chunks_timed_out: IntCounter,
    /// The chunk delivery times.
    pub chunk_delivery_time: HistogramVec,
    /// The number of failures to download chunks.
    pub chunks_download_failed: IntCounter,
    /// The number of chunks not served from this peer.
    pub chunks_not_served_from_peer: IntCounter,
    /// The number of download retry attempts.
    pub chunks_download_retry_attempts: IntCounter,
    /// The number of unsolicited or timed-out chunks.
    pub chunks_unsolicited_or_timed_out: IntCounter,
    /// The number of chunks that were downloaded after the artifact was marked
    /// as complete.
    pub chunks_redundant_residue: IntCounter,
    /// The number of failures to verify a chunk.
    pub chunks_verification_failed: IntCounter,

    // Advert fields.
    /// The number of sent adverts(total).
    pub adverts_sent: IntCounter,
    /// The number of sent adverts(by advert action).
    pub adverts_by_action: IntCounterVec,
    /// The number of failures to send adverts.
    pub adverts_send_failed: IntCounter,
    /// The number of received adverts.
    pub adverts_received: IntCounter,
    /// The number of dropped adverts.
    pub adverts_dropped: IntCounter,

    // Retransmission fields.
    /// The number of sent retransmission requests.
    pub retransmission_requests_sent: IntCounter,
    /// The number of failures to send retransmission requests.
    pub retransmission_request_send_failed: IntCounter,
    /// The retransmission request times.
    pub retransmission_request_time: Histogram,

    // registry
    pub registry_version_used: IntGauge,

    // node removal
    pub nodes_removed: IntCounter,

    // Connection fields.
    /// The number of a connection events.
    pub connection_up_events: IntCounter,
    /// The number of a disconnections events.
    pub connection_down_events: IntCounter,

    // Download next stats.
    /// The time spent in the `download_next()` function.
    pub download_next_time: IntGauge,
    /// The total number of entries returned by `get_peer_priority_queues()`.
    pub download_next_total_entries: IntGauge,
    /// The number of entries checked in the `download_next()` function.
    pub download_next_visited: IntGauge,
    /// The number of entries selected for download by the `download_next()`
    /// function.
    pub download_next_selected: IntGauge,
    /// The number of calls to the `download_next()` function.
    pub download_next_calls: IntCounter,
    /// The number of sent retransmission requests.
    pub download_next_retrans_requests_sent: IntCounter,
}

impl DownloadManagementMetrics {
    /// The constructor returns a `DownloadManagementMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            op_duration: metrics_registry.histogram_vec(
                "p2p_peermgmt_op_duration",
                "The time it took to execute the given op, in milliseconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms
                decimal_buckets(-4, -1),
                &["op"],
            ),

            // Artifact fields.
            artifacts_received: metrics_registry
                .int_counter("gossip_artifacts_received", "number of artifact received"),
            artifact_timeouts: metrics_registry
                .int_counter("artifact_timeouts", "number of artifact timeouts"),
            received_artifact_size: metrics_registry
                .int_gauge("gossip_received_artifact_size", "size of received artifact"),
            integrity_hash_check_failed: metrics_registry.int_counter(
                "integrity_hash_check_failed",
                "Number of times the integrity check failed for artifacts",
            ),

            // Chunking fields.
            chunks_requested: metrics_registry.int_counter(
                "gossip_chunks_requested",
                "Number of chunks that were requested",
            ),
            chunk_request_send_failed: metrics_registry.int_counter(
                "chunk_request_send_failed",
                "Number of chunk request send failures",
            ),
            chunks_received: metrics_registry
                .int_counter("gossip_chunks_received", "Number of chunks received"),
            chunk_delivery_time: metrics_registry.histogram_vec(
                "gossip_chunk_delivery_time",
                "Time it took to deliver a chunk after it has been requested (in milliseconds)",
                vec![
                    1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 300.0, 400.0, 500.0, 600.0,
                    700.0, 800.0, 900.0, 1000.0, 1200.0, 1400.0, 1600.0, 1800.0, 2000.0, 2500.0,
                    3000.0, 4000.0, 5000.0, 7000.0, 10000.0, 20000.0,
                ],
                &["artifact_type"],
            ),
            chunks_sent: metrics_registry
                .int_counter("gossip_chunks_sent", "Number of chunks sent"),
            chunk_send_failed: metrics_registry
                .int_counter("chunkd_send_failed", "Number of chunk send failures"),
            chunks_timed_out: metrics_registry
                .int_counter("gossip_chunks_timedout", "Timed-out chunks"),
            connection_up_events: metrics_registry.int_counter(
                "gossip_connection_up_event",
                "Number of connection up events received",
            ),
            connection_down_events: metrics_registry.int_counter(
                "gossip_connection_down_event",
                "Number of connection down events received",
            ),
            chunks_download_failed: metrics_registry.int_counter(
                "gossip_chunks_download_failed",
                "Number for failed chunk downloads (for various reasons)",
            ),
            chunks_not_served_from_peer: metrics_registry.int_counter(
                "gossip_chunks_not_served_from_peer",
                "Number for time peers failed to serve a chunk",
            ),
            chunks_download_retry_attempts: metrics_registry.int_counter(
                "gossip_chunks_download_retried",
                "Number for times chunk downloads were retried",
            ),
            chunks_unsolicited_or_timed_out: metrics_registry.int_counter(
                "gossip_chunks_num_unsolicited",
                "Number for unsolicited chunks received",
            ),
            chunks_redundant_residue: metrics_registry.int_counter(
                "gossip_chunks_redundant_residue",
                "Number of chunks that were downloaded after the artifact was marked complete",
            ),
            chunks_verification_failed: metrics_registry.int_counter(
                "gossip_chunk_verification_failed",
                "Number of chunks that failed verification",
            ),

            // Adverts fields.
            adverts_sent: metrics_registry.int_counter(
                "gossip_adverts_sent",
                "Total number of artifact advertisements sent",
            ),
            adverts_by_action: metrics_registry.int_counter_vec(
                "gossip_adverts_by_action",
                "Total number of artifact advertisements sent, by action type",
                &["type"],
            ),
            adverts_send_failed: metrics_registry
                .int_counter("adverts_send_failed", "Number of advert send failures"),
            adverts_received: metrics_registry.int_counter(
                "gossip_adverts_received",
                "Number of adverts received from all peers",
            ),
            adverts_dropped: metrics_registry.int_counter(
                "gossip_adverts_ignored",
                "Number of adverts that were dropped",
            ),

            // Retransmission fields.
            retransmission_requests_sent: metrics_registry.int_counter(
                "retransmission_requests_sent",
                "Number of retransmission requests successfully sent",
            ),
            retransmission_request_send_failed: metrics_registry.int_counter(
                "retransmission_request_send_failed",
                "Critical error a lagging replica isn't able to send a retransmission request",
            ),
            retransmission_request_time: metrics_registry.histogram(
                "retransmission_request_time",
                "The time it took to send retransmission request, in milliseconds",
                vec![
                    1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 300.0, 400.0, 500.0, 600.0,
                    700.0, 800.0, 900.0, 1000.0, 1200.0, 1400.0, 1600.0, 1800.0, 2000.0, 2500.0,
                    3000.0, 4000.0, 5000.0, 7000.0, 10000.0, 20000.0,
                ],
            ),

            // Registry version.
            registry_version_used: metrics_registry.int_gauge(
                "registry_version_used",
                "The registry version currently in use by P2P",
            ),

            // Nodes removed in P2P.
            nodes_removed: metrics_registry.int_counter(
                "p2p_nodes_removed",
                "Nodes removed by p2p based on registry node membership changes",
            ),

            // Download next stats.
            download_next_time: metrics_registry
                .int_gauge("download_next_time", "Time spent in download_next()"),
            download_next_total_entries: metrics_registry.int_gauge(
                "download_next_total_entries",
                "Total entries returned by get_peer_priority_queues()",
            ),
            download_next_visited: metrics_registry.int_gauge(
                "download_next_visited",
                "Entries checked by download_next()",
            ),
            download_next_selected: metrics_registry.int_gauge(
                "download_next_selected",
                "Entries selected for download by download_next()",
            ),
            download_next_calls: metrics_registry
                .int_counter("download_next_calls", "Num calls to download_next()"),
            download_next_retrans_requests_sent: metrics_registry.int_counter(
                "download_next_retrans_requests_sent",
                "Number of retransmission requests sent",
            ),
        }
    }
}

/// The download prioritizer metrics.
pub struct DownloadPrioritizerMetrics {
    /// The number of adverts deleted from this peer.
    pub adverts_deleted_from_peer: IntCounter,
    /// THe number of dropped adverts.
    pub priority_adverts_dropped: IntCounter,
    /// The number of updates to the priority function.
    pub priority_fn_updates: IntCounter,
    /// The times required to update the priorities using the priority
    /// functions.
    pub priority_fn_timer: Histogram,

    /// Number of adverts added to each peer's queue
    pub advert_queue_add: IntCounterVec,
    /// Number of adverts removed from each peer's queue
    pub advert_queue_remove: IntCounterVec,
    /// Size of each peer's queue
    pub advert_queue_size: IntGaugeVec,
}

impl DownloadPrioritizerMetrics {
    /// The constructor returns a `DownloadPrioritizerMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            adverts_deleted_from_peer: metrics_registry.int_counter(
                "priority_adverts_deleted",
                "Number of adverts deleted from peer",
            ),
            priority_adverts_dropped: metrics_registry
                .int_counter("priority_adverts_dropped", "Number of adverts dropped"),
            priority_fn_updates: metrics_registry.int_counter(
                "priority_fn_updates",
                "Number of times priority function was updated",
            ),
            priority_fn_timer: metrics_registry.histogram(
                "priority_fn_time",
                "The time it took to update priorities with priority functions, in seconds",
                // 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0
                decimal_buckets(-1, 1),
            ),
            advert_queue_add: metrics_registry.int_counter_vec(
                "advert_queue_add",
                "Adverts added to the gossip advert map",
                &["peer", "priority"],
            ),
            advert_queue_remove: metrics_registry.int_counter_vec(
                "advert_queue_remove",
                "Adverts removed from the gossip advert map",
                &["peer", "priority"],
            ),
            advert_queue_size: metrics_registry.int_gauge_vec(
                "advert_queue_size",
                "Size of the gossip advert map",
                &["peer", "priority"],
            ),
        }
    }
}

/// The event handler metrics.
pub struct EventHandlerMetrics {
    /// The times required for send message calls.
    pub send_message_duration_ms: HistogramVec,
}

impl EventHandlerMetrics {
    /// The constructor returns an `EventHandlerMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            send_message_duration_ms: metrics_registry.histogram_vec(
                "send_message_duration_msec",
                "Time taken by event handler for send message call, in milliseconds",
                // 1ms, 2ms, 5ms - 100 sec, 200 sec, 500 sec
                decimal_buckets(0, 5),
                &["msg_type"],
            ),
        }
    }
}
