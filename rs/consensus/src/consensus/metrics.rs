use ic_consensus_utils::{get_block_hash_string, pool_reader::PoolReader};
use ic_https_outcalls_consensus::payload_builder::CanisterHttpBatchStats;
use ic_management_canister_types::EcdsaKeyId;
use ic_metrics::{
    buckets::{decimal_buckets, decimal_buckets_with_zero, linear_buckets},
    MetricsRegistry,
};
use ic_types::{
    batch::BatchPayload,
    consensus::{
        ecdsa::{
            CompletedReshareRequest, CompletedSignature, EcdsaPayload, HasEcdsaKeyId,
            KeyTranscriptCreation,
        },
        Block, BlockProposal, ConsensusMessageHashable, HasHeight, HasRank,
    },
    CountBytes, Height,
};
use prometheus::{
    GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};
use std::{collections::BTreeMap, sync::RwLock};

// For certain metrics, we record metrics based on block's rank.
// Since we can only record limited number of them, the follow is
// the range of ranks that are permitted to show up in metrics.
const RANKS_TO_RECORD: [&str; 6] = ["0", "1", "2", "3", "4", "5"];

pub(crate) const CRITICAL_ERROR_PAYLOAD_TOO_LARGE: &str = "consensus_payload_too_large";
pub(crate) const CRITICAL_ERROR_VALIDATION_NOT_PASSED: &str = "consensus_validation_not_passed";
pub(crate) const CRITICAL_ERROR_SUBNET_RECORD_ISSUE: &str = "consensus_subnet_record_issue";
pub(crate) const CRITICAL_ERROR_ECDSA_KEY_TRANSCRIPT_MISSING: &str = "ecdsa_key_transcript_missing";
pub(crate) const CRITICAL_ERROR_ECDSA_RETAIN_ACTIVE_TRANSCRIPTS: &str =
    "ecdsa_retain_active_transcripts_error";

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
                "The size of the ChangeSet returned by on_state_change()",
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

pub struct ConsensusGossipMetrics {
    pub get_priority_update_block_duration: HistogramVec,
}

impl ConsensusGossipMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            get_priority_update_block_duration: metrics_registry.histogram_vec(
                "consensus_get_priority_update_block_duration",
                "The time it took to execute the update_block sections of get_priority",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["block_type"],
            ),
        }
    }
}

// Block related stats
pub struct BlockStats {
    pub block_hash: String,
    pub block_height: u64,
    pub block_context_certified_height: u64,
    pub ecdsa_stats: Option<EcdsaStats>,
}

impl From<&Block> for BlockStats {
    fn from(block: &Block) -> Self {
        Self {
            block_hash: get_block_hash_string(block),
            block_height: block.height().get(),
            block_context_certified_height: block.context.certified_height.get(),
            ecdsa_stats: block.payload.as_ref().as_ecdsa().map(EcdsaStats::from),
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

// TODO(kpop): remove this Option eventually
type CounterPerEcdsaKeyId = BTreeMap<Option<EcdsaKeyId>, usize>;

// Ecdsa payload stats
pub struct EcdsaStats {
    pub signature_agreements: usize,
    pub key_transcript_created: CounterPerEcdsaKeyId,
    pub available_quadruples: CounterPerEcdsaKeyId,
    pub quadruples_in_creation: CounterPerEcdsaKeyId,
    pub ongoing_xnet_reshares: CounterPerEcdsaKeyId,
    pub xnet_reshare_agreements: CounterPerEcdsaKeyId,
}

impl From<&EcdsaPayload> for EcdsaStats {
    fn from(payload: &EcdsaPayload) -> Self {
        let mut key_transcript_created = CounterPerEcdsaKeyId::new();
        if let KeyTranscriptCreation::Created(transcript) = payload.key_transcript.next_in_creation
        {
            let transcript_id = &transcript.as_ref().transcript_id;
            let current_transcript_id = payload
                .key_transcript
                .current
                .as_ref()
                .map(|transcript| &transcript.as_ref().transcript_id);
            if Some(transcript_id) != current_transcript_id
                && payload.idkg_transcripts.get(transcript_id).is_some()
            {
                *key_transcript_created
                    .entry(Some(payload.key_transcript.key_id.clone()))
                    .or_default() += 1;
            }
        }

        let keys = vec![None, Some(payload.key_transcript.key_id.clone())];

        Self {
            key_transcript_created,
            signature_agreements: payload
                .signature_agreements
                .values()
                .filter(|status| matches!(status, CompletedSignature::Unreported(_)))
                .count(),
            available_quadruples: count_by_ecdsa_key_id(payload.available_quadruples.keys(), &keys),
            quadruples_in_creation: count_by_ecdsa_key_id(
                payload.quadruples_in_creation.keys(),
                &keys,
            ),
            ongoing_xnet_reshares: count_by_ecdsa_key_id(
                payload.ongoing_xnet_reshares.keys(),
                &keys,
            ),
            xnet_reshare_agreements: count_by_ecdsa_key_id(
                payload
                    .xnet_reshare_agreements
                    .iter()
                    .filter(|(_, status)| matches!(status, CompletedReshareRequest::Unreported(_))),
                &keys,
            ),
        }
    }
}

fn count_by_ecdsa_key_id<T: HasEcdsaKeyId>(
    collection: impl Iterator<Item = T>,
    expected_keys: &Vec<Option<EcdsaKeyId>>,
) -> CounterPerEcdsaKeyId {
    let mut counter_per_key_id = CounterPerEcdsaKeyId::new();

    // To properly report `0` for ecdsa keys which do not appear in the `collection`, we insert the
    // default values for all the ecdsa keys which we expect to see in the payload.
    for key in expected_keys {
        counter_per_key_id.insert(key.clone(), 0);
    }

    for item in collection {
        *counter_per_key_id
            .entry(item.key_id().cloned())
            .or_default() += 1;
    }

    counter_per_key_id
}

pub struct FinalizerMetrics {
    pub batches_delivered: IntCounterVec,
    pub batch_height: IntGauge,
    pub ingress_messages_delivered: Histogram,
    pub ingress_message_bytes_delivered: Histogram,
    pub xnet_bytes_delivered: Histogram,
    pub finalization_certified_state_difference: IntGauge,
    // ecdsa payload related metrics
    pub ecdsa_key_transcript_created: IntCounterVec,
    pub ecdsa_signature_agreements: IntCounter,
    pub ecdsa_available_quadruples: IntGaugeVec,
    pub ecdsa_quadruples_in_creation: IntGaugeVec,
    pub ecdsa_ongoing_xnet_reshares: IntGaugeVec,
    pub ecdsa_xnet_reshare_agreements: IntCounterVec,
    // canister http payload metrics
    pub canister_http_success_delivered: IntCounter,
    pub canister_http_timeouts_delivered: IntCounter,
    pub canister_http_divergences_delivered: IntCounter,
}

const ECDSA_KEY_ID_LABEL: &str = "key_id";

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
            // ecdsa payload related metrics
            ecdsa_key_transcript_created: metrics_registry.int_counter_vec(
                "consensus_ecdsa_key_transcript_created",
                "The number of times ECDSA key transcript is created",
                &[ECDSA_KEY_ID_LABEL],
            ),
            ecdsa_signature_agreements: metrics_registry.int_counter(
                "consensus_ecdsa_signature_agreements",
                "Total number of ECDSA signature agreements created",
            ),
            ecdsa_available_quadruples: metrics_registry.int_gauge_vec(
                "consensus_ecdsa_available_quadruples",
                "The number of available ECDSA quadruples",
                &[ECDSA_KEY_ID_LABEL],
            ),
            ecdsa_quadruples_in_creation: metrics_registry.int_gauge_vec(
                "consensus_ecdsa_quadruples_in_creation",
                "The number of ECDSA quadruples in creation",
                &[ECDSA_KEY_ID_LABEL],
            ),
            ecdsa_ongoing_xnet_reshares: metrics_registry.int_gauge_vec(
                "consensus_ecdsa_ongoing_xnet_reshares",
                "The number of ongoing ECDSA xnet reshares",
                &[ECDSA_KEY_ID_LABEL],
            ),
            ecdsa_xnet_reshare_agreements: metrics_registry.int_counter_vec(
                "consensus_ecdsa_reshare_agreements",
                "Total number of ECDSA reshare agreements created",
                &[ECDSA_KEY_ID_LABEL],
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

        if let Some(ecdsa) = &block_stats.ecdsa_stats {
            let set = |metric: &IntGaugeVec, counts: &CounterPerEcdsaKeyId| {
                for (key_id, count) in counts.iter() {
                    metric
                        .with_label_values(&[&key_id_label(key_id.as_ref())])
                        .set(*count as i64);
                }
            };

            let inc_by = |metric: &IntCounterVec, counts: &CounterPerEcdsaKeyId| {
                for (key_id, count) in counts.iter() {
                    metric
                        .with_label_values(&[&key_id_label(key_id.as_ref())])
                        .inc_by(*count as u64);
                }
            };

            inc_by(
                &self.ecdsa_key_transcript_created,
                &ecdsa.key_transcript_created,
            );
            self.ecdsa_signature_agreements
                .inc_by(ecdsa.signature_agreements as u64);
            set(
                &self.ecdsa_available_quadruples,
                &ecdsa.available_quadruples,
            );
            set(
                &self.ecdsa_quadruples_in_creation,
                &ecdsa.quadruples_in_creation,
            );
            set(
                &self.ecdsa_ongoing_xnet_reshares,
                &ecdsa.ongoing_xnet_reshares,
            );
            inc_by(
                &self.ecdsa_xnet_reshare_agreements,
                &ecdsa.xnet_reshare_agreements,
            );
        }
    }
}

fn key_id_label(key_id: Option<&EcdsaKeyId>) -> String {
    key_id.map(|key_id| key_id.to_string()).unwrap_or_default()
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
    pub(crate) ecdsa_validation_duration: HistogramVec,
    pub(crate) validation_random_tape_shares_count: IntGauge,
    pub(crate) validation_random_beacon_shares_count: IntGauge,
    pub(crate) validation_share_batch_size: HistogramVec,
}

impl ValidatorMetrics {
    /// The constructor creates a [`ValidatorMetrics`] instance.
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            time_to_receive_block: metrics_registry.histogram_vec(
                "consensus_time_to_receive_block",
                "The duration to receive a block since round start, labelled by ranks, in seconds.",
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
            ecdsa_validation_duration: metrics_registry.histogram_vec(
                "consensus_ecdsa_validation_duration_seconds",
                "Time to validate ECDSA component, in seconds",
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
        }
    }
}

#[derive(Clone)]
pub struct EcdsaClientMetrics {
    pub on_state_change_duration: HistogramVec,
    pub client_metrics: IntCounterVec,
    pub client_errors: IntCounterVec,
    /// critical error when retain_active_transcripts fails
    pub critical_error_ecdsa_retain_active_transcripts: IntCounter,
}

impl EcdsaClientMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            on_state_change_duration: metrics_registry.histogram_vec(
                "ecdsa_on_state_change_duration_seconds",
                "The time it took to execute ECDSA on_state_change(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["sub_component"],
            ),
            client_metrics: metrics_registry.int_counter_vec(
                "ecdsa_client_metrics",
                "ECDSA client related metrics",
                &["type"],
            ),
            client_errors: metrics_registry.int_counter_vec(
                "ecdsa_client_errors",
                "ECDSA client related errors",
                &["type"],
            ),
            critical_error_ecdsa_retain_active_transcripts: metrics_registry
                .error_counter(CRITICAL_ERROR_ECDSA_RETAIN_ACTIVE_TRANSCRIPTS),
        }
    }
}

#[derive(Clone)]
pub struct EcdsaGossipMetrics {
    pub dropped_adverts: IntCounterVec,
}

impl EcdsaGossipMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            dropped_adverts: metrics_registry.int_counter_vec(
                "ecdsa_priority_fn_dropped_adverts",
                "ECDSA adverts dropped by priority fn",
                &["type"],
            ),
        }
    }
}

#[derive(Clone)]
pub struct EcdsaPreSignerMetrics {
    pub on_state_change_duration: HistogramVec,
    pub pre_sign_metrics: IntCounterVec,
    pub pre_sign_errors: IntCounterVec,
}

impl EcdsaPreSignerMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            on_state_change_duration: metrics_registry.histogram_vec(
                "ecdsa_pre_signer_on_state_change_duration_seconds",
                "The time it took to execute pre-signer on_state_change(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["sub_component"],
            ),
            pre_sign_metrics: metrics_registry.int_counter_vec(
                "ecdsa_pre_signer_metrics",
                "Pre-signing related metrics",
                &["type"],
            ),
            pre_sign_errors: metrics_registry.int_counter_vec(
                "ecdsa_pre_signer_errors",
                "Pre-signing related errors",
                &["type"],
            ),
        }
    }

    pub fn pre_sign_metrics_inc(&self, label: &str) {
        self.pre_sign_metrics.with_label_values(&[label]).inc();
    }

    pub fn pre_sign_errors_inc(&self, label: &str) {
        self.pre_sign_errors.with_label_values(&[label]).inc();
    }
}

#[derive(Clone)]
pub struct EcdsaSignerMetrics {
    pub on_state_change_duration: HistogramVec,
    pub sign_metrics: IntCounterVec,
    pub sign_errors: IntCounterVec,
}

impl EcdsaSignerMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            on_state_change_duration: metrics_registry.histogram_vec(
                "ecdsa_signer_on_state_change_duration_seconds",
                "The time it took to execute signer on_state_change(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["sub_component"],
            ),
            sign_metrics: metrics_registry.int_counter_vec(
                "ecdsa_signer_metrics",
                "Signing related metrics",
                &["type"],
            ),
            sign_errors: metrics_registry.int_counter_vec(
                "ecdsa_signer_errors",
                "Signing related errors",
                &["type"],
            ),
        }
    }
    pub fn sign_metrics_inc(&self, label: &str) {
        self.sign_metrics.with_label_values(&[label]).inc();
    }

    pub fn sign_errors_inc(&self, label: &str) {
        self.sign_errors.with_label_values(&[label]).inc();
    }
}

pub(crate) struct EcdsaPayloadMetrics {
    payload_metrics: IntGaugeVec,
    payload_errors: IntCounterVec,
    transcript_builder_metrics: IntCounterVec,
    transcript_builder_errors: IntCounterVec,
    pub(crate) transcript_builder_duration: HistogramVec,
    /// Critical error for failure to create/reshare key transcript
    pub(crate) critical_error_ecdsa_key_transcript_missing: IntCounter,
}

impl EcdsaPayloadMetrics {
    pub(crate) fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            payload_metrics: metrics_registry.int_gauge_vec(
                "ecdsa_payload_metrics",
                "ECDSA payload related metrics",
                &["type", ECDSA_KEY_ID_LABEL],
            ),
            payload_errors: metrics_registry.int_counter_vec(
                "ecdsa_payload_errors",
                "ECDSA payload related errors",
                &["type"],
            ),
            transcript_builder_metrics: metrics_registry.int_counter_vec(
                "ecdsa_transcript_builder_metrics",
                "ECDSA transcript builder metrics",
                &["type"],
            ),
            transcript_builder_errors: metrics_registry.int_counter_vec(
                "ecdsa_transcript_builder_errors",
                "ECDSA transcript builder related errors",
                &["type"],
            ),
            transcript_builder_duration: metrics_registry.histogram_vec(
                "ecdsa_transcript_builder_duration_seconds",
                "Time taken by transcript builder, in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["sub_component"],
            ),
            critical_error_ecdsa_key_transcript_missing: metrics_registry
                .error_counter(CRITICAL_ERROR_ECDSA_KEY_TRANSCRIPT_MISSING),
        }
    }

    pub(crate) fn report(&self, payload: &EcdsaPayload) {
        let expected_keys = vec![None, Some(payload.key_transcript.key_id.clone())];

        self.payload_metrics_set_without_key_id_label(
            "signature_agreements",
            payload.signature_agreements.len(),
        );
        self.payload_metrics_set(
            "available_quadruples",
            count_by_ecdsa_key_id(payload.available_quadruples.keys(), &expected_keys),
        );
        self.payload_metrics_set(
            "quaruples_in_creation",
            count_by_ecdsa_key_id(payload.quadruples_in_creation.keys(), &expected_keys),
        );
        self.payload_metrics_set(
            "ongoing_xnet_reshares",
            count_by_ecdsa_key_id(payload.ongoing_xnet_reshares.keys(), &expected_keys),
        );
        self.payload_metrics_set(
            "xnet_reshare_agreements",
            count_by_ecdsa_key_id(payload.xnet_reshare_agreements.keys(), &expected_keys),
        );
    }

    fn payload_metrics_set_without_key_id_label(&self, label: &str, value: usize) {
        self.payload_metrics
            .with_label_values(&[label, /*key_id=*/ ""])
            .set(value as i64);
    }

    fn payload_metrics_set(&self, label: &str, values: CounterPerEcdsaKeyId) {
        for (key_id, value) in values {
            self.payload_metrics
                .with_label_values(&[label, &key_id_label(key_id.as_ref())])
                .set(value as i64);
        }
    }

    pub(crate) fn payload_metrics_inc(&self, label: &str, key_id: Option<&EcdsaKeyId>) {
        self.payload_metrics
            .with_label_values(&[label, &key_id_label(key_id)])
            .inc();
    }

    pub(crate) fn payload_errors_inc(&self, label: &str) {
        self.payload_errors.with_label_values(&[label]).inc();
    }

    pub(crate) fn transcript_builder_metrics_inc(&self, label: &str) {
        self.transcript_builder_metrics
            .with_label_values(&[label])
            .inc();
    }

    pub(crate) fn transcript_builder_metrics_inc_by(&self, value: u64, label: &str) {
        self.transcript_builder_metrics
            .with_label_values(&[label])
            .inc_by(value);
    }

    pub(crate) fn transcript_builder_errors_inc(&self, label: &str) {
        self.transcript_builder_errors
            .with_label_values(&[label])
            .inc();
    }
}

pub fn timed_call<F, R>(label: &str, call_fn: F, metric: &HistogramVec) -> R
where
    F: FnOnce() -> R,
{
    let _timer = metric.with_label_values(&[label]).start_timer();
    (call_fn)()
}

#[derive(Clone)]
pub struct EcdsaComplaintMetrics {
    pub on_state_change_duration: HistogramVec,
    pub complaint_metrics: IntCounterVec,
    pub complaint_errors: IntCounterVec,
}

impl EcdsaComplaintMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            on_state_change_duration: metrics_registry.histogram_vec(
                "ecdsa_complaint_on_state_change_duration_seconds",
                "The time it took to execute complaint on_state_change(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["sub_component"],
            ),
            complaint_metrics: metrics_registry.int_counter_vec(
                "ecdsa_complaint_metrics",
                "Complaint related metrics",
                &["type"],
            ),
            complaint_errors: metrics_registry.int_counter_vec(
                "ecdsa_complaint_errors",
                "Complaint related errors",
                &["type"],
            ),
        }
    }

    pub fn complaint_metrics_inc(&self, label: &str) {
        self.complaint_metrics.with_label_values(&[label]).inc();
    }

    pub fn complaint_errors_inc(&self, label: &str) {
        self.complaint_errors.with_label_values(&[label]).inc();
    }
}

#[derive(Clone)]
pub struct EcdsaTranscriptMetrics {
    pub active_transcripts: IntGauge,
    pub support_validation_duration: HistogramVec,
    pub support_validation_total_duration: HistogramVec,
    pub support_aggregation_duration: HistogramVec,
    pub support_aggregation_total_duration: HistogramVec,
    pub create_transcript_duration: HistogramVec,
    pub create_transcript_total_duration: HistogramVec,
    pub transcript_e2e_latency: HistogramVec,
}

impl EcdsaTranscriptMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            active_transcripts: metrics_registry
                .int_gauge("ecdsa_active_transcripts", "Currently active transcripts"),
            support_validation_duration: metrics_registry.histogram_vec(
                "ecdsa_support_validation_duration",
                "Support validation duration, in msec",
                decimal_buckets(0, 2),
                &["type"],
            ),
            support_validation_total_duration: metrics_registry.histogram_vec(
                "ecdsa_support_validation_total_duration",
                "Total support validation duration, in msec",
                decimal_buckets(0, 4),
                &["type"],
            ),
            support_aggregation_duration: metrics_registry.histogram_vec(
                "ecdsa_support_aggregation_duration",
                "Support aggregation duration, in msec",
                decimal_buckets(0, 2),
                &["type"],
            ),
            support_aggregation_total_duration: metrics_registry.histogram_vec(
                "ecdsa_support_aggregation_total_duration",
                "Total support aggregation duration, in msec",
                decimal_buckets(0, 4),
                &["type"],
            ),
            create_transcript_duration: metrics_registry.histogram_vec(
                "ecdsa_create_transcript_duration",
                "Time to create transcript, in msec",
                decimal_buckets(0, 5),
                &["type"],
            ),
            create_transcript_total_duration: metrics_registry.histogram_vec(
                "ecdsa_create_transcript_total_duration",
                "Total time to create transcript, in msec",
                decimal_buckets(0, 5),
                &["type"],
            ),
            transcript_e2e_latency: metrics_registry.histogram_vec(
                "ecdsa_transcript_e2e_latency",
                "End to end latency to build the transcript, in sec",
                linear_buckets(0.5, 0.5, 30),
                &["type"],
            ),
        }
    }
}

#[derive(Clone)]
pub struct EcdsaQuadrupleMetrics {
    pub quadruple_e2e_latency: Histogram,
}

impl EcdsaQuadrupleMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            quadruple_e2e_latency: metrics_registry.histogram(
                "ecdsa_quadruple_e2e_latency",
                "End to end latency to build the quadruple, in sec",
                linear_buckets(2.0, 0.5, 60),
            ),
        }
    }
}

#[derive(Clone)]
pub struct EcdsaSignatureMetrics {
    pub active_signatures: IntGauge,
    pub sig_share_validation_duration: Histogram,
    pub sig_share_validation_total_duration: Histogram,
    pub sig_share_aggregation_duration: Histogram,
    pub sig_share_aggregation_total_duration: Histogram,
    pub signature_e2e_latency: Histogram,
}

impl EcdsaSignatureMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            active_signatures: metrics_registry
                .int_gauge("ecdsa_active_signatures", "Currently active signatures"),
            sig_share_validation_duration: metrics_registry.histogram(
                "ecdsa_sig_share_validation_duration",
                "Sig share validation duration, in msec",
                decimal_buckets(0, 2),
            ),
            sig_share_validation_total_duration: metrics_registry.histogram(
                "ecdsa_sig_share_validation_total_duration",
                "Total sig share validation duration, in msec",
                decimal_buckets(0, 4),
            ),
            sig_share_aggregation_duration: metrics_registry.histogram(
                "ecdsa_sig_share_aggregation_duration",
                "Sig share aggregation duration, in msec",
                decimal_buckets(0, 2),
            ),
            sig_share_aggregation_total_duration: metrics_registry.histogram(
                "ecdsa_sig_share_aggregation_total_duration",
                "Total sig share aggregation duration, in msec",
                decimal_buckets(0, 4),
            ),
            signature_e2e_latency: metrics_registry.histogram(
                "ecdsa_signature_e2e_latency",
                "End to end latency to build the signature, in sec",
                linear_buckets(0.5, 0.5, 30),
            ),
        }
    }
}
