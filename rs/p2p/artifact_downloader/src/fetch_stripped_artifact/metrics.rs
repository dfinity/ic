use ic_metrics::{MetricsRegistry, buckets::decimal_buckets_with_zero};
use prometheus::{Histogram, HistogramVec, IntCounterVec, IntGauge};

const SOURCE_LABEL: &str = "source";
const STRIPPED_MESSAGE_TYPE_LABEL: &str = "type";

#[derive(Clone)]
pub(super) struct FetchStrippedConsensusArtifactMetrics {
    pub(super) ingress_messages_in_a_block_count: HistogramVec,
    pub(super) download_missing_ingress_messages_duration: Histogram,
    pub(super) missing_ingress_messages_bytes: Histogram,
    pub(super) total_block_assembly_duration: Histogram,
    pub(super) active_ingress_message_downloads: IntGauge,
    pub(super) total_ingress_message_download_errors: IntCounterVec,
}

#[derive(Copy, Clone)]
pub(super) enum IngressMessageSource {
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
    pub(super) fn new(metrics_registry: &MetricsRegistry) -> Self {
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
                    "Download time for all the missing ingress messages in the block, in seconds",
                    decimal_buckets_with_zero(-2, 1),
            ),
            missing_ingress_messages_bytes: metrics_registry.histogram(
                    "ic_stripped_consensus_artifact_downloader_missing_ingress_messages_bytes",
                    "Size of missing ingress messages, in bytes",
                    // 0B, 1B, ..., 5MB
                    decimal_buckets_with_zero(0, 6),
            ),
            total_block_assembly_duration: metrics_registry.histogram(
                    "ic_stripped_consensus_artifact_total_block_assembly_duration",
                    "Total time to download and assemble a block, in seconds",
                    decimal_buckets_with_zero(-2, 1),
            ),
            active_ingress_message_downloads: metrics_registry.int_gauge(
                    "ic_stripped_consensus_artifact_active_ingress_message_downloads",
                    "The number of active missing ingress message downloads",
            ),
            total_ingress_message_download_errors: metrics_registry.int_counter_vec(
                    "ic_stripped_consensus_artifact_total_ingress_message_download_errors",
                    "The total number of errors occurred while downloading \
                    missing ingress messages",
                    &["error"],
            ),
        }
    }

    pub(super) fn report_ingress_messages_count(&self, source: IngressMessageSource, count: u64) {
        self.ingress_messages_in_a_block_count
            .with_label_values(&[source.as_str()])
            .observe(count as f64)
    }

    pub(super) fn report_download_error(&self, label: &str) {
        self.total_ingress_message_download_errors
            .with_label_values(&[label])
            .inc()
    }
}

#[derive(Clone)]
pub(super) struct StrippedMessageSenderMetrics {
    pub(super) stripped_messages_in_pool: IntCounterVec,
    pub(super) stripped_messages_in_block: IntCounterVec,
    pub(super) stripped_messages_not_found: IntCounterVec,
}

impl StrippedMessageSenderMetrics {
    pub(super) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            stripped_messages_in_pool: metrics_registry.int_counter_vec(
                "ic_stripped_consensus_artifact_sender_stripped_messages_in_pool",
                "Total number number of handled stripped message requests \
                where the requested message was found in the respective pool",
                &[STRIPPED_MESSAGE_TYPE_LABEL],
            ),
            stripped_messages_in_block: metrics_registry.int_counter_vec(
                "ic_stripped_consensus_artifact_sender_stripped_messages_in_block",
                "Total number number of handled stripped message requests \
                where the requested message was found in a block in the consensus pool",
                &[STRIPPED_MESSAGE_TYPE_LABEL],
            ),
            stripped_messages_not_found: metrics_registry.int_counter_vec(
                "ic_stripped_consensus_artifact_sender_stripped_messages_not_found",
                "Total number number of handled stripped message requests \
                where the requested message was not found",
                &[STRIPPED_MESSAGE_TYPE_LABEL],
            ),
        }
    }
}
