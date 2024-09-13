use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::artifact::PbArtifact;
use prometheus::{histogram_opts, labels, opts, Histogram, IntCounter};

use super::download::uri_prefix;

#[derive(Clone)]
pub(crate) struct FetchArtifactMetrics {
    // Download management
    pub download_task_stashed_total: IntCounter,
    pub download_task_artifact_download_duration: Histogram,
    pub download_task_artifact_download_errors_total: IntCounter,
}

impl FetchArtifactMetrics {
    pub fn new<Artifact: PbArtifact>(metrics_registry: &MetricsRegistry) -> Self {
        let prefix = uri_prefix::<Artifact>();
        let const_labels_string = labels! {"client".to_string() => prefix.clone()};
        let const_labels = labels! {"client" => prefix.as_str()};
        Self {
            download_task_stashed_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_artifact_downloader_download_task_stashed_total",
                    "Adverts stashed at least once.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
            download_task_artifact_download_duration: metrics_registry.register(
                Histogram::with_opts(histogram_opts!(
                    "ic_artifact_downloader_download_task_artifact_download_duration",
                    "Download time for artifact.",
                    decimal_buckets(-2, 1),
                    const_labels_string.clone(),
                ))
                .unwrap(),
            ),
            download_task_artifact_download_errors_total: metrics_registry.register(
                IntCounter::with_opts(opts!(
                    "ic_artifact_downloader_download_task_artifact_download_errors_total",
                    "Error occurred when downloading artifact.",
                    const_labels.clone(),
                ))
                .unwrap(),
            ),
        }
    }
}
