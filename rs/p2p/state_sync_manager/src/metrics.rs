use ic_metrics::{
    buckets::decimal_buckets, tokio_metrics_collector::TokioTaskMetricsCollector, MetricsRegistry,
};
use prometheus::{
    exponential_buckets, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge,
};
use tokio_metrics::TaskMonitor;

use crate::ongoing::{CompletedStateSync, DownloadChunkError};

const HANDLER_LABEL: &str = "handler";
pub(crate) const CHUNK_HANDLER_LABEL: &str = "chunk";
pub(crate) const ADVERT_HANDLER_LABEL: &str = "advert";

const CHUNK_DOWNLOAD_STATUS_LABEL: &str = "status";
const CHUNK_DOWNLOAD_STATUS_MORE_NEEDED: &str = "more_needed";
const CHUNK_DOWNLOAD_STATUS_SUCCESS: &str = "success";

#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct StateSyncManagerHandlerMetrics {
    pub request_duration: HistogramVec,
}

impl StateSyncManagerHandlerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            request_duration: metrics_registry.histogram_vec(
                "state_sync_manager_request_duration",
                "State sync manager request handler duration.",
                // 1ms, 10ms, 100ms, 1s
                exponential_buckets(0.001, 10.0, 4).unwrap(),
                &[HANDLER_LABEL],
            ),
        }
    }
}
#[derive(Debug, Clone)]
pub(crate) struct OngoingStateSyncMetrics {
    pub download_task_monitor: TaskMonitor,
    pub allowed_parallel_downloads: IntGauge,
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
    pub fn record_chunk_download_result(
        &self,
        res: &Result<Option<CompletedStateSync>, DownloadChunkError>,
    ) {
        match res {
            // Received chunk
            Ok(Some(_)) => {
                self.chunk_download_results_total
                    .with_label_values(&[CHUNK_DOWNLOAD_STATUS_SUCCESS])
                    .inc();
            }
            Ok(None) => {
                self.chunk_download_results_total
                    .with_label_values(&[CHUNK_DOWNLOAD_STATUS_MORE_NEEDED])
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
