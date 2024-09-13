use ic_metrics::{buckets::decimal_buckets_with_zero, MetricsRegistry};
use prometheus::{histogram_opts, labels, Histogram};

#[derive(Clone)]
pub(crate) struct FetchStrippedConsensusArtifactMetrics {
    pub(crate) missing_stripped_ingress_messages: Histogram,
    pub(crate) found_stripped_ingress_messages: Histogram,
    pub(crate) total_ingress_messages: Histogram,
    pub(crate) download_missing_ingress_messages_duration: Histogram,
}

impl FetchStrippedConsensusArtifactMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            missing_stripped_ingress_messages: metrics_registry.register(
                Histogram::with_opts(histogram_opts!(
                    "ic_stripped_consensus_artifact_downloader_missing_stripped_ingress_messages",
                    "Number of stripped ingress messages in a block which are not in the local \
                    ingress pool and which have to be downloaded from peers",
                    decimal_buckets_with_zero(0, 3),
                    labels! {}
                ))
                .unwrap(),
            ),
            found_stripped_ingress_messages: metrics_registry.register(
                Histogram::with_opts(histogram_opts!(
                    "ic_stripped_consensus_artifact_downloader_found_stripped_ingress_messages",
                    "Number of stripped ingress messages in a block which are in the local \
                    ingress pool and which don't have to be downloaded from peers",
                    decimal_buckets_with_zero(0, 3),
                    labels! {}
                ))
                .unwrap(),
            ),
            total_ingress_messages: metrics_registry.register(
                Histogram::with_opts(histogram_opts!(
                    "ic_stripped_consensus_artifact_downloader_total_ingress_messages",
                    "Total number of ingress messages in the block",
                    decimal_buckets_with_zero(0, 3),
                    labels! {}
                ))
                .unwrap(),
            ),
            download_missing_ingress_messages_duration: metrics_registry.register(
                Histogram::with_opts(histogram_opts!(
                    "ic_stripped_consensus_artifact_downloader_missing_stripped_ingress_messages_fetch_duration",
                    "Download time for all the missing ingress messages in the block",
                    decimal_buckets_with_zero(-2, 1),
                    labels! {}
                ))
                .unwrap(),
            ),
        }
    }
}
