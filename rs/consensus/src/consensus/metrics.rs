use ic_consensus_utils::pool_reader::PoolReader;
use ic_https_outcalls_consensus::payload_builder::CanisterHttpBatchStats;
use ic_interfaces::ingress_manager::IngressSelector;
use ic_metrics::{
    buckets::{decimal_buckets, decimal_buckets_with_zero, linear_buckets},
    MetricsRegistry,
};
use ic_types::{
    batch::BatchPayload,
    consensus::{
        idkg::{CompletedReshareRequest, CompletedSignature, IDkgPayload, KeyTranscriptCreation},
        Block, BlockPayload, BlockProposal, ConsensusMessageHashable, HasHeight, HasRank,
    },
    CountBytes, Height,
};
use prometheus::{
    GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};
use std::sync::RwLock;

use crate::idkg::metrics::{
    count_by_master_public_key_id, expected_keys, key_id_label, CounterPerMasterPublicKeyId,
    KEY_ID_LABEL,
};

use super::utils::get_block_hash_string;

// For certain metrics, we record metrics based on block's rank.
// Since we can only record limited number of them, the follow is
// the range of ranks that are permitted to show up in metrics.
const RANKS_TO_RECORD: [&str; 6] = ["0", "1", "2", "3", "4", "5"];

pub(crate) const CRITICAL_ERROR_PAYLOAD_TOO_LARGE: &str = "consensus_payload_too_large";
pub(crate) const CRITICAL_ERROR_VALIDATION_NOT_PASSED: &str = "consensus_validation_not_passed";
pub(crate) const CRITICAL_ERROR_SUBNET_RECORD_ISSUE: &str = "consensus_subnet_record_issue";

pub struct BlockMakerMetrics {
    pub get_payload_calls: IntCounterVec,
    pub block_size_bytes_estimate: IntGaugeVec,
}

impl BlockMakerMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            get_payload_calls: metrics_registry.int_counter_vec(
                "consensus_get_payload_calls",
                "The number of times of calling get_payload(), for success, pending or other status.",
                &["status"],
            ),
            block_size_bytes_estimate: metrics_registry.int_gauge_vec(
                "consensus_block_size_bytes_estimate",
                "An estimate about the block size produced by the block maker.",
                &["payload_type"])
        }
    }

    /// Reports byte estimate metrics.
    pub fn report_byte_estimate_metrics(&self, xnet_bytes: usize, ingress_bytes: usize) {
        let _ = self
            .block_size_bytes_estimate
            .get_metric_with_label_values(&["xnet"])
            .map(|gauge| gauge.set(xnet_bytes as i64));
        let _ = self
            .block_size_bytes_estimate
            .get_metric_with_label_values(&["ingress"])
            .map(|gauge| gauge.set(ingress_bytes as i64));
    }
}

pub struct ConsensusMetrics {
    pub on_state_change_duration: HistogramVec,
    pub on_state_change_invocations: IntCounterVec,
    pub on_state_change_change_set_size: HistogramVec,
    pub time_since_last_invoked: GaugeVec,
    pub starvation_counter: IntCounterVec,
}

impl ConsensusMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            on_state_change_duration: metrics_registry.histogram_vec(
                "consensus_on_state_change_duration_seconds",
                "The time it took to execute on_state_change(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["sub_component"],
            ),
            on_state_change_invocations: metrics_registry.int_counter_vec(
                "consensus_on_state_change_invocations",
                "The number of times the on_state_change() method has been called",
                &["sub_component"],
            ),
            on_state_change_change_set_size: metrics_registry.histogram_vec(
                "consensus_on_state_change_change_set_size",
                "The size of the Mutations returned by on_state_change()",
                // 0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000
                decimal_buckets_with_zero(0, 3),
                &["sub_component"],
            ),
            time_since_last_invoked: metrics_registry.gauge_vec(
                "consensus_time_since_last_invoked",
                "The time between two invocations of the component",
                &["sub_component"],
            ),
            starvation_counter: metrics_registry.int_counter_vec(
                "consensus_starvation_counter",
                "Counts the number of starvations that happened.",
                &["sub_component"],
            ),
        }
    }
}

// Block related stats
pub struct BlockStats {
    pub block_hash: String,
    pub block_height: u64,
    pub block_context_certified_height: u64,
    pub idkg_stats: Option<IDkgStats>,
}

impl From<&Block> for BlockStats {
    fn from(block: &Block) -> Self {
        Self {
            block_hash: get_block_hash_string(block),
            block_height: block.height().get(),
            block_context_certified_height: block.context.certified_height.get(),
            idkg_stats: block.payload.as_ref().as_idkg().map(IDkgStats::from),
        }
    }
}

// Batch payload stats
#[derive(Debug, Default)]
pub struct BatchStats {
    pub batch_height: u64,
    pub ingress_messages_delivered: usize,
    pub ingress_message_bytes_delivered: usize,
    pub xnet_bytes_delivered: usize,
    pub ingress_ids: Vec<ic_types::artifact::IngressMessageId>,
    pub canister_http: CanisterHttpBatchStats,
}

impl BatchStats {
    pub(crate) fn new(batch_height: Height) -> Self {
        Self {
            batch_height: batch_height.get(),
            ..Self::default()
        }
    }

    pub(crate) fn add_from_payload(&mut self, payload: &BatchPayload) {
        self.ingress_messages_delivered += payload.ingress.message_count();
        self.ingress_message_bytes_delivered += payload.ingress.count_bytes();
        self.xnet_bytes_delivered += payload.xnet.size_bytes();
        self.ingress_ids
            .extend_from_slice(&payload.ingress.message_ids());
    }
}

// IDkg payload stats
pub struct IDkgStats {
    pub signature_agreements: usize,
    pub key_transcripts_created: CounterPerMasterPublicKeyId,
    pub available_pre_signatures: CounterPerMasterPublicKeyId,
    pub pre_signatures_in_creation: CounterPerMasterPublicKeyId,
    pub ongoing_xnet_reshares: CounterPerMasterPublicKeyId,
    pub xnet_reshare_agreements: CounterPerMasterPublicKeyId,
}

impl From<&IDkgPayload> for IDkgStats {
    fn from(payload: &IDkgPayload) -> Self {
        let mut key_transcripts_created = CounterPerMasterPublicKeyId::new();

        for (key_id, key_transcript) in &payload.key_transcripts {
            if let KeyTranscriptCreation::Created(transcript) = &key_transcript.next_in_creation {
                let transcript_id = &transcript.as_ref().transcript_id;
                let current_transcript_id = key_transcript
                    .current
                    .as_ref()
                    .map(|transcript| &transcript.as_ref().transcript_id);
                if Some(transcript_id) != current_transcript_id
                    && payload.idkg_transcripts.contains_key(transcript_id)
                {
                    *key_transcripts_created.entry(key_id.clone()).or_default() += 1;
                }
            }
        }

        let keys = expected_keys(payload);

        Self {
            key_transcripts_created,
            signature_agreements: payload
                .signature_agreements
                .values()
                .filter(|status| matches!(status, CompletedSignature::Unreported(_)))
                .count(),
            available_pre_signatures: count_by_master_public_key_id(
                payload.available_pre_signatures.values(),
                &keys,
            ),
            pre_signatures_in_creation: count_by_master_public_key_id(
                payload.pre_signatures_in_creation.values(),
                &keys,
            ),
            ongoing_xnet_reshares: count_by_master_public_key_id(
                payload.ongoing_xnet_reshares.keys(),
                &keys,
            ),
            xnet_reshare_agreements: count_by_master_public_key_id(
                payload
                    .xnet_reshare_agreements
                    .iter()
                    .filter(|(_, status)| matches!(status, CompletedReshareRequest::Unreported(_))),
                &keys,
            ),
        }
    }
}

pub struct FinalizerMetrics {
    pub batches_delivered: IntCounterVec,
    pub batch_height: IntGauge,
    pub ingress_messages_delivered: Histogram,
    pub ingress_message_bytes_delivered: Histogram,
    pub xnet_bytes_delivered: Histogram,
    pub finalization_certified_state_difference: IntGauge,
    // idkg payload related metrics
    pub master_key_transcripts_created: IntCounterVec,
    pub threshold_signature_agreements: IntCounter,
    pub idkg_available_pre_signatures: IntGaugeVec,
    pub idkg_pre_signatures_in_creation: IntGaugeVec,
    pub idkg_ongoing_xnet_reshares: IntGaugeVec,
    pub idkg_xnet_reshare_agreements: IntCounterVec,
    // canister http payload metrics
    pub canister_http_success_delivered: IntCounter,
    pub canister_http_timeouts_delivered: IntCounter,
    pub canister_http_divergences_delivered: IntCounter,
}

impl FinalizerMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            batches_delivered: metrics_registry.int_counter_vec(
                "consensus_batches_delivered",
                "The number of batches sent to Message Routing, by status",
                &["status"],
            ),
            batch_height: metrics_registry.int_gauge(
                "consensus_batch_height",
                "The height of batches sent to Message Routing",
            ),
            finalization_certified_state_difference: metrics_registry.int_gauge(
                "consensus_finalization_certified_state_difference",
                "The height difference between the finalized tip and the referenced certified state",
            ),
            ingress_messages_delivered: metrics_registry.histogram(
                "consensus_ingress_messages_delivered",
                "The number of the ingress messages delivered to Message Routing",
                // 0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000
                decimal_buckets_with_zero(0, 3),
            ),
            ingress_message_bytes_delivered: metrics_registry.histogram(
                "consensus_ingress_message_bytes_delivered",
                "The number of bytes in ingress messages delivered to Message Routing",
                // 0, 1, 2, 5, 10, 20, 50, 100, ..., 10MB, 20MB, 50MB
                decimal_buckets_with_zero(0, 7),
            ),
            xnet_bytes_delivered: metrics_registry.histogram(
                "consensus_xnet_bytes_delivered",
                "The number of bytes in xnet messages delivered to Message Routing",
                // 0, 1, 2, 5, 10, 20, 50, 100, ..., 10MB, 20MB, 50MB
                decimal_buckets_with_zero(0, 7),
            ),
            // idkg payload related metrics
            master_key_transcripts_created: metrics_registry.int_counter_vec(
                "consensus_master_key_transcripts_created",
                "The number of times a master key transcript is created",
                &[KEY_ID_LABEL],
            ),
            threshold_signature_agreements: metrics_registry.int_counter(
                "consensus_threshold_signature_agreements",
                "Total number of threshold signature agreements created",
            ),
            idkg_available_pre_signatures: metrics_registry.int_gauge_vec(
                "consensus_idkg_available_pre_signatures",
                "The number of available IDKG pre-signatures",
                &[KEY_ID_LABEL],
            ),
            idkg_pre_signatures_in_creation: metrics_registry.int_gauge_vec(
                "consensus_idkg_pre_signatures_in_creation",
                "The number of IDKG pre-signatures in creation",
                &[KEY_ID_LABEL],
            ),
            idkg_ongoing_xnet_reshares: metrics_registry.int_gauge_vec(
                "consensus_idkg_ongoing_xnet_reshares",
                "The number of ongoing IDKG xnet reshares",
                &[KEY_ID_LABEL],
            ),
            idkg_xnet_reshare_agreements: metrics_registry.int_counter_vec(
                "consensus_idkg_reshare_agreements",
                "Total number of IDKG reshare agreements created",
                &[KEY_ID_LABEL],
            ),
            // canister http payload metrics
            canister_http_success_delivered: metrics_registry.int_counter(
                "canister_http_success_delivered",
                "Total number of canister http messages successfully delivered",
            ),
            canister_http_timeouts_delivered: metrics_registry.int_counter(
                "canister_http_timeouts_delivered",
                "Total number of canister http messages delivered as timeouts",
            ),
            canister_http_divergences_delivered: metrics_registry.int_counter(
                "canister_http_divergences_delivered",
                "Total number of canister http messages delivered as divergences",
            ),
        }
    }

    pub fn process(&self, block_stats: &BlockStats, batch_stats: &BatchStats) {
        self.batches_delivered.with_label_values(&["success"]).inc();
        self.batch_height.set(batch_stats.batch_height as i64);
        self.ingress_messages_delivered
            .observe(batch_stats.ingress_messages_delivered as f64);
        self.ingress_message_bytes_delivered
            .observe(batch_stats.ingress_message_bytes_delivered as f64);
        self.xnet_bytes_delivered
            .observe(batch_stats.xnet_bytes_delivered as f64);
        self.finalization_certified_state_difference.set(
            block_stats.block_height as i64 - block_stats.block_context_certified_height as i64,
        );
        self.canister_http_success_delivered
            .inc_by(batch_stats.canister_http.responses as u64);
        self.canister_http_timeouts_delivered
            .inc_by(batch_stats.canister_http.timeouts as u64);
        self.canister_http_divergences_delivered
            .inc_by(batch_stats.canister_http.divergence_responses as u64);

        if let Some(idkg) = &block_stats.idkg_stats {
            let set = |metric: &IntGaugeVec, counts: &CounterPerMasterPublicKeyId| {
                for (key_id, count) in counts.iter() {
                    metric
                        .with_label_values(&[&key_id_label(Some(key_id))])
                        .set(*count as i64);
                }
            };

            let inc_by = |metric: &IntCounterVec, counts: &CounterPerMasterPublicKeyId| {
                for (key_id, count) in counts.iter() {
                    metric
                        .with_label_values(&[&key_id_label(Some(key_id))])
                        .inc_by(*count as u64);
                }
            };

            inc_by(
                &self.master_key_transcripts_created,
                &idkg.key_transcripts_created,
            );
            self.threshold_signature_agreements
                .inc_by(idkg.signature_agreements as u64);
            set(
                &self.idkg_available_pre_signatures,
                &idkg.available_pre_signatures,
            );
            set(
                &self.idkg_pre_signatures_in_creation,
                &idkg.pre_signatures_in_creation,
            );
            set(
                &self.idkg_ongoing_xnet_reshares,
                &idkg.ongoing_xnet_reshares,
            );
            inc_by(
                &self.idkg_xnet_reshare_agreements,
                &idkg.xnet_reshare_agreements,
            );
        }
    }
}

pub struct NotaryMetrics {
    pub time_to_notary_sign: HistogramVec,
}

impl NotaryMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            time_to_notary_sign: metrics_registry.histogram_vec(
                "consensus_time_to_notary_sign",
                "The duration since round start for replicas to notary-sign a block, labelled by ranks",
                vec![0.0, 0.2, 0.4, 0.6, 0.8, 1.0, 1.2, 1.4, 1.6, 1.8, 2.0, 2.2, 2.4, 2.6, 2.8, 3.0, 3.5, 4.0, 4.5, 5.0, 6.0, 8.0, 10.0, 15.0, 20.0],
                &["rank"],
            ),
        }
    }

    /// Report metrics after notarizing `block`
    pub fn report_notarization(&self, block: &Block, elapsed: std::time::Duration) {
        let rank = block.rank().0 as usize;
        if rank < RANKS_TO_RECORD.len() {
            self.time_to_notary_sign
                .with_label_values(&[RANKS_TO_RECORD[rank]])
                .observe(elapsed.as_secs_f64())
        }
    }
}

pub struct PayloadBuilderMetrics {
    pub get_payload_duration: Histogram,
    pub validate_payload_duration: Histogram,
    pub past_payloads_length: Histogram,

    /// Critical error for payloads above the maximum supported size
    pub critical_error_payload_too_large: IntCounter,

    /// Critical error for newly created payloads that do not pass their own validation function
    pub critical_error_validation_not_passed: IntCounter,

    /// Critical error triggered if the subnet record contains entries that would not make sense to consensus
    pub critical_error_subnet_record_data_issue: IntCounter,
}

impl PayloadBuilderMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            get_payload_duration: metrics_registry.histogram(
                "consensus_get_payload_duration_seconds",
                "The time it took to execute get_payload(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s
                decimal_buckets(-4, 0),
            ),
            validate_payload_duration: metrics_registry.histogram(
                "consensus_validate_payload_duration_seconds",
                "The time it took to execute validate_payload(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s
                decimal_buckets(-4, 0),
            ),
            past_payloads_length: metrics_registry.histogram(
                "consensus_past_payloads_length",
                "The length of past_payloads in payload selection",
                linear_buckets(0.0, 1.0, 6),
            ),
            critical_error_payload_too_large: metrics_registry
                .error_counter(CRITICAL_ERROR_PAYLOAD_TOO_LARGE),
            critical_error_validation_not_passed: metrics_registry
                .error_counter(CRITICAL_ERROR_VALIDATION_NOT_PASSED),
            critical_error_subnet_record_data_issue: metrics_registry
                .error_counter(CRITICAL_ERROR_SUBNET_RECORD_ISSUE),
        }
    }
}

/// Metrics for a consensus validator.
pub struct ValidatorMetrics {
    pub(crate) time_to_receive_block: HistogramVec,
    pub(crate) duplicate_artifact: IntCounterVec,
    pub(crate) validation_duration: HistogramVec,
    pub(crate) dkg_validator: IntCounterVec,
    // Used to sum the values within a single validator run
    dkg_time_per_validator_run: RwLock<f64>,
    pub(crate) idkg_validation_duration: HistogramVec,
    pub(crate) validation_random_tape_shares_count: IntGauge,
    pub(crate) validation_random_beacon_shares_count: IntGauge,
    pub(crate) validation_share_batch_size: HistogramVec,
    // Payload metrics
    pub(crate) ingress_messages: Histogram,
    // The number of messages in a block which are not (yet) present in the Ingress Pool.
    // This is a temporary metrics needed for a hashes in blocks experiment.
    // TODO(CON-1312): Delete this once not necessary anymore
    pub(crate) missing_ingress_messages: Histogram,
}

impl ValidatorMetrics {
    /// The constructor creates a [`ValidatorMetrics`] instance.
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            time_to_receive_block: metrics_registry.histogram_vec(
                "consensus_time_to_receive_block",
                "The duration to receive a block since round start, labeled by ranks, in seconds.",
                vec![
                    0.0, 0.2, 0.4, 0.6, 0.8, 1.0, 1.2, 1.4, 1.6, 1.8, 2.0, 2.2, 2.4, 2.6, 2.8, 3.0,
                    3.5, 4.0, 4.5, 5.0, 6.0, 8.0, 10.0, 15.0, 20.0,
                ],
                &["rank"],
            ),
            duplicate_artifact: metrics_registry.int_counter_vec(
                "consensus_duplicate_artifact",
                "The number of duplicate notarizations and finalizations Consensus has received",
                &["artifact"],
            ),
            validation_duration: metrics_registry.histogram_vec(
                "consensus_validation_duration_seconds",
                "Time to validate by subcomponent, in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["type"],
            ),
            dkg_validator: metrics_registry.int_counter_vec(
                "consensus_dkg_validator",
                "DKG validator counter",
                &["type"],
            ),
            dkg_time_per_validator_run: RwLock::new(0.0),
            idkg_validation_duration: metrics_registry.histogram_vec(
                "consensus_idkg_validation_duration_seconds",
                "Time to validate IDKG component, in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["type"],
            ),
            validation_random_tape_shares_count: metrics_registry.int_gauge(
                "consensus_validation_tape_shares",
                "Number of random tape shares being validated every block",
            ),
            validation_random_beacon_shares_count: metrics_registry.int_gauge(
                "consensus_validation_beacon_shares",
                "Number of random beacon shares being validated every block",
            ),
            validation_share_batch_size: metrics_registry.histogram_vec(
                "consensus_validation_share_batch_size",
                "Number of validation shares per state change invocation, labels: [tape, beacon]",
                linear_buckets(1.0, 1.0, 10),
                &["type"],
            ),
            ingress_messages: metrics_registry.histogram(
                "consensus_ingress_messages_in_block",
                "The number of ingress messages in a validated block",
                // 0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000
                decimal_buckets_with_zero(0, 3),
            ),
            missing_ingress_messages: metrics_registry.histogram(
                "consensus_missing_ingress_messages_in_block",
                "The number of ingress messages in a validated block \
                which are not present in the ingress pool",
                // 0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000
                decimal_buckets_with_zero(0, 3),
            ),
        }
    }

    pub(crate) fn observe_data_payload(
        &self,
        proposal: &BlockProposal,
        ingress_selector: Option<&dyn IngressSelector>,
    ) {
        let BlockPayload::Data(payload) = proposal.as_ref().payload.as_ref() else {
            // Skip if it's a summary block.
            return;
        };

        let total_ingress_messages = payload.batch.ingress.message_count();
        self.ingress_messages.observe(total_ingress_messages as f64);

        if let Some(ingress_selector) = ingress_selector {
            let missing_ingress_messages = payload
                .batch
                .ingress
                .message_ids()
                .iter()
                .filter(|message_id| !ingress_selector.has_message(message_id))
                .count();

            self.missing_ingress_messages
                .observe(missing_ingress_messages as f64);
        }
    }

    pub(crate) fn observe_block(&self, pool_reader: &PoolReader, proposal: &BlockProposal) {
        let rank = proposal.rank().0 as usize;
        if rank < RANKS_TO_RECORD.len() {
            if let Some(start_time) = pool_reader.get_round_start_time(proposal.height()) {
                if let Some(timestamp) = pool_reader
                    .pool()
                    .unvalidated()
                    .get_timestamp(&proposal.get_id())
                {
                    if timestamp >= start_time {
                        self.time_to_receive_block
                            .with_label_values(&[RANKS_TO_RECORD[rank]])
                            .observe(
                                (timestamp.saturating_duration_since(start_time)).as_secs_f64(),
                            );
                    }
                }
            }
        }
    }

    pub(crate) fn add_to_dkg_time_per_validator_run(&self, elapsed_time: f64) {
        let mut dkg_time = self.dkg_time_per_validator_run.write().unwrap();
        *dkg_time += elapsed_time;
    }

    pub(crate) fn observe_and_reset_dkg_time_per_validator_run(&self) {
        let mut dkg_time = self.dkg_time_per_validator_run.write().unwrap();
        self.validation_duration
            .with_label_values(&["DkgPerRun"])
            .observe(*dkg_time);
        *dkg_time = 0.0;
    }
}

pub struct PurgerMetrics {
    pub unvalidated_pool_purge_height: IntGauge,
    pub validated_pool_purge_height: IntGauge,
    pub replicated_state_purge_height: IntGauge,
    pub replicated_state_purge_height_disk: IntGauge,
    pub validated_pool_bounds_exceeded: IntCounter,
}

impl PurgerMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            unvalidated_pool_purge_height: metrics_registry.int_gauge(
                "unvalidated_pool_purge_height",
                "The height below which unvalidated artifacts are purged",
            ),
            validated_pool_purge_height: metrics_registry.int_gauge(
                "validated_pool_purge_height",
                "The height below which unvalidated artifacts are purged",
            ),
            replicated_state_purge_height: metrics_registry.int_gauge(
                "replicated_state_purge_height",
                "The height below which in-memory replicated states are purged",
            ),
            replicated_state_purge_height_disk: metrics_registry.int_gauge(
                "replicated_state_purge_height_disk",
                "The height below which on-disk replicated states (checkpoints) are purged",
            ),
            validated_pool_bounds_exceeded: metrics_registry.int_counter(
                "validated_pool_bounds_exceeded",
                "The validated pool exceeded its size bounds",
            ),
        }
    }
}
