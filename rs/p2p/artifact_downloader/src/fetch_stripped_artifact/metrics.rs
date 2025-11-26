use ic_metrics::{MetricsRegistry, buckets::decimal_buckets_with_zero};
use prometheus::{Histogram, HistogramVec, IntCounterVec, IntGaugeVec};

use crate::fetch_stripped_artifact::types::StrippedMessageType;

const SOURCE_LABEL: &str = "source";
const STRIPPED_MESSAGE_TYPE_LABEL: &str = "type";

#[derive(Clone)]
pub(super) struct FetchStrippedConsensusArtifactMetrics {
    pub(super) stripped_messages_in_a_block_count: HistogramVec,
    pub(super) download_missing_stripped_messages_duration: Histogram,
    pub(super) missing_stripped_messages_bytes: HistogramVec,
    pub(super) total_block_assembly_duration: Histogram,
    pub(super) active_stripped_message_downloads: IntGaugeVec,
    pub(super) total_stripped_message_download_errors: IntCounterVec,
}

#[derive(Copy, Clone)]
pub(super) enum StrippedMessageSource {
    Peer,
    Pool,
}

impl StrippedMessageSource {
    fn as_str(&self) -> &str {
        match self {
            StrippedMessageSource::Peer => "peer",
            StrippedMessageSource::Pool => "pool",
        }
    }
}

impl FetchStrippedConsensusArtifactMetrics {
    pub(super) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            stripped_messages_in_a_block_count: metrics_registry.histogram_vec(
                    "ic_stripped_consensus_artifact_downloader_stripped_messages_in_a_block_count",
                    "Number of stripped messages in a block partitioned by the source of the \
                    message (a peer or replica's own pool), and the message type",
                    decimal_buckets_with_zero(0, 3),
                    &[SOURCE_LABEL, STRIPPED_MESSAGE_TYPE_LABEL],
            ),
            download_missing_stripped_messages_duration: metrics_registry.histogram(
                    "ic_stripped_consensus_artifact_downloader_missing_stripped_messages_fetch_duration",
                    "Download time for all the missing stripped messages in the block, in seconds",
                    decimal_buckets_with_zero(-2, 1),
            ),
            missing_stripped_messages_bytes: metrics_registry.histogram_vec(
                    "ic_stripped_consensus_artifact_downloader_missing_stripped_messages_bytes",
                    "Size of missing stripped messages, in bytes",
                    // 0B, 1B, ..., 5MB
                    decimal_buckets_with_zero(0, 6),
                    &[STRIPPED_MESSAGE_TYPE_LABEL],
            ),
            total_block_assembly_duration: metrics_registry.histogram(
                    "ic_stripped_consensus_artifact_total_block_assembly_duration",
                    "Total time to download and assemble a block, in seconds",
                    decimal_buckets_with_zero(-2, 1),
            ),
            active_stripped_message_downloads: metrics_registry.int_gauge_vec(
                    "ic_stripped_consensus_artifact_active_stripped_message_downloads",
                    "The number of active missing stripped message downloads",
                    &[STRIPPED_MESSAGE_TYPE_LABEL],
            ),
            total_stripped_message_download_errors: metrics_registry.int_counter_vec(
                    "ic_stripped_consensus_artifact_total_stripped_message_download_errors",
                    "The total number of errors occurred while downloading \
                    missing stripped messages",
                    &["error", STRIPPED_MESSAGE_TYPE_LABEL],
            ),
        }
    }

    pub(super) fn report_missing_stripped_messages_bytes(
        &self,
        message_type: StrippedMessageType,
        bytes: usize,
    ) {
        self.missing_stripped_messages_bytes
            .with_label_values(&[message_type.as_str()])
            .observe(bytes as f64)
    }

    pub(super) fn report_stripped_messages_count(
        &self,
        source: StrippedMessageSource,
        message_type: StrippedMessageType,
        count: u64,
    ) {
        self.stripped_messages_in_a_block_count
            .with_label_values(&[source.as_str(), message_type.as_str()])
            .observe(count as f64)
    }

    pub(super) fn report_download_error(&self, label: &str, message_type: StrippedMessageType) {
        self.total_stripped_message_download_errors
            .with_label_values(&[label, message_type.as_str()])
            .inc()
    }

    pub(super) fn report_started_stripped_message_download(
        &self,
        message_type: StrippedMessageType,
    ) {
        self.active_stripped_message_downloads
            .with_label_values(&[message_type.as_str()])
            .inc()
    }

    pub(super) fn report_finished_stripped_message_download(
        &self,
        message_type: StrippedMessageType,
    ) {
        self.active_stripped_message_downloads
            .with_label_values(&[message_type.as_str()])
            .dec()
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

    pub(super) fn report_stripped_message_in_pool(&self, message_type: StrippedMessageType) {
        self.stripped_messages_in_pool
            .with_label_values(&[message_type.as_str()])
            .inc()
    }

    pub(super) fn report_stripped_message_in_block(&self, message_type: StrippedMessageType) {
        self.stripped_messages_in_block
            .with_label_values(&[message_type.as_str()])
            .inc()
    }

    pub(super) fn report_stripped_message_not_found(&self, message_type: StrippedMessageType) {
        self.stripped_messages_not_found
            .with_label_values(&[message_type.as_str()])
            .inc()
    }
}
