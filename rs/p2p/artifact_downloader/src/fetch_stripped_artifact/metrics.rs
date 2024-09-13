use ic_metrics::{buckets::decimal_buckets_with_zero, MetricsRegistry};
use prometheus::{Histogram, HistogramVec};

const SOURCE_LABEL: &str = "source";

#[derive(Clone)]
pub(crate) struct FetchStrippedConsensusArtifactMetrics {
    pub(crate) ingress_messages_in_a_block_count: HistogramVec,
    pub(crate) download_missing_ingress_messages_duration: Histogram,
    pub(crate) total_block_assembly_duration: Histogram,
}

#[derive(Copy, Clone)]
pub(crate) enum IngressMessageSource {
    Peer,
    IngressPool,
}

impl IngressMessageSource {
    fn as_str(&self) -> &str {
        match self {
            IngressMessageSource::Peer => "peer",
            IngressMessageSource::IngressPool => "ingress_pool",
        }
    }
}

impl FetchStrippedConsensusArtifactMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            ingress_messages_in_a_block_count: metrics_registry.histogram_vec(
                    "ic_stripped_consensus_artifact_downloader_ingress_messages_in_a_block_count",
                    "Number of ingress messages in a block partitioned by the source of the \
                    ingress message (a peer or replica's own ingress pool)",
                    decimal_buckets_with_zero(0, 3),
                    &[SOURCE_LABEL],
            ),
            download_missing_ingress_messages_duration: metrics_registry.histogram(
                    "ic_stripped_consensus_artifact_downloader_missing_stripped_ingress_messages_fetch_duration",
                    "Download time for all the missing ingress messages in the block",
                    decimal_buckets_with_zero(-2, 1),
            ),
            total_block_assembly_duration: metrics_registry.histogram(
                    "ic_stripped_consensus_artifact_total_duration",
                    "Total time to download and assemble a block",
                    decimal_buckets_with_zero(-2, 1),
            ),
        }
    }

    pub(crate) fn report_ingress_messages_count(&self, source: IngressMessageSource, count: u64) {
        self.ingress_messages_in_a_block_count
            .with_label_values(&[source.as_str()])
            .observe(count as f64)
    }
}
