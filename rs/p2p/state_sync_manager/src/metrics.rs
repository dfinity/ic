use ic_metrics::{
    buckets::decimal_buckets, tokio_metrics_collector::TokioTaskMetricsCollector, MetricsRegistry,
};
use prometheus::{Histogram, IntCounter, IntCounterVec, IntGauge};
use tokio_metrics::TaskMonitor;

use crate::ongoing::DownloadChunkError;

const CHUNK_DOWNLOAD_STATUS_LABEL: &str = "status";
const CHUNK_DOWNLOAD_STATUS_SUCCESS: &str = "success";

#[derive(Clone, Debug)]
pub(crate) struct StateSyncManagerMetrics {
    pub state_syncs_total: IntCounter,
    pub adverts_received_total: IntCounter,
    pub highest_state_broadcasted: IntGauge,
    pub lowest_state_broadcasted: IntGauge,
    pub ongoing_state_sync_metrics: OngoingStateSyncMetrics,
}

impl StateSyncManagerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            state_syncs_total: metrics_registry.int_counter(
                "state_sync_manager_started_sync_total",
                "Total number of started state syncs.",
            ),
            adverts_received_total: metrics_registry.int_counter(
                "state_sync_manager_adverts_received_total",
                "Total number of adverts received.",
            ),
            highest_state_broadcasted: metrics_registry.int_gauge(
                "state_sync_manager_highest_state_broadcasted",
                "Highest state height broadcasted.",
            ),
            lowest_state_broadcasted: metrics_registry.int_gauge(
                "state_sync_manager_lowest_state_broadcasted",
                "Lowest state height broadcasted.",
            ),
            ongoing_state_sync_metrics: OngoingStateSyncMetrics::new(metrics_registry),
        }
    }
}
#[derive(Clone, Debug)]
pub struct StateSyncManagerHandlerMetrics {
    pub compression_ratio: Histogram,
}

impl StateSyncManagerHandlerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            compression_ratio: metrics_registry.histogram(
                "state_sync_manager_chunk_compression_ratio",
                "State sync manager chunk compression ratio.",
                vec![1.0, 1.25, 1.5, 2.0, 3.0, 5.0, 10.0],
            ),
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct OngoingStateSyncMetrics {
    pub download_task_monitor: TaskMonitor,
    pub allowed_parallel_downloads: IntGauge,
    pub chunk_size_compressed_total: IntCounter,
    pub chunk_size_decompressed_total: IntCounter,
    pub chunks_to_download_calls_total: IntCounter,
    pub chunks_to_download_total: IntCounter,
    pub peers_serving_state: IntGauge,
    pub chunk_download_duration: Histogram,
    pub chunk_download_results_total: IntCounterVec,
}

impl OngoingStateSyncMetrics {
    /// The constructor returns a `GossipMetrics` instance.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        let (task_collector, download_task_monitor) =
            TokioTaskMetricsCollector::new("state_sync_manager_download_tasks");
        metrics_registry.register(task_collector);
        Self {
            download_task_monitor,
            allowed_parallel_downloads: metrics_registry.int_gauge(
                "state_sync_manager_allowed_parallel_downloads",
                "Number outstanding download requests that are allowed.",
            ),
            chunk_size_compressed_total: metrics_registry.int_counter(
                "state_sync_manager_chunk_size_compressed_total",
                "Sum of all chunks received from transport.",
            ),
            chunk_size_decompressed_total: metrics_registry.int_counter(
                "state_sync_manager_chunk_size_decompressed_total",
                "Sum of all chunks received after decompresssion.",
            ),
            chunks_to_download_calls_total: metrics_registry.int_counter(
                "state_sync_manager_chunks_to_download_calls_total",
                "Number of times manager asked state sync for list of chunks to download.",
            ),
            chunks_to_download_total: metrics_registry.int_counter(
                "state_sync_manager_chunks_to_download_total",
                "Number chunks instructed to download.",
            ),
            peers_serving_state: metrics_registry.int_gauge(
                "state_sync_manager_peers_serving_state",
                "Number of serving the requested state.",
            ),
            chunk_download_duration: metrics_registry.histogram(
                "state_sync_manager_chunk_download_duration",
                "State sync manager chunk download duration.",
                // 100ms, 200ms, 500ms, 1s, 2s, 5s
                decimal_buckets(-1, 0),
            ),
            chunk_download_results_total: metrics_registry.int_counter_vec(
                "state_sync_manager_chunk_download_results_total",
                "Chunk download request results.",
                &[CHUNK_DOWNLOAD_STATUS_LABEL],
            ),
        }
    }

    /// Utility to record metrics for download result.
    pub fn record_chunk_download_result(&self, res: &Result<(), DownloadChunkError>) {
        match res {
            // Received chunk
            Ok(()) => {
                self.chunk_download_results_total
                    .with_label_values(&[CHUNK_DOWNLOAD_STATUS_SUCCESS])
                    .inc();
            }
            Err(e) => {
                self.chunk_download_results_total
                    .with_label_values(&[&e.to_string()])
                    .inc();
            }
        }
    }
}
