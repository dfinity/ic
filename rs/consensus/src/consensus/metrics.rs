use crate::consensus::pool_reader::PoolReader;
use ic_consensus_message::ConsensusMessageHashable;
use ic_metrics::{
    buckets::{decimal_buckets, decimal_buckets_with_zero, linear_buckets},
    MetricsRegistry,
};
use ic_types::consensus::{Block, BlockProposal, HasHeight, HasRank};
use prometheus::{GaugeVec, Histogram, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec};
use std::sync::RwLock;

// For certain metrics, we record metrics based on block's rank.
// Since we can only record limited number of them, the follow is
// the range of ranks that are permitted to show up in metrics.
const RANKS_TO_RECORD: [&str; 6] = ["0", "1", "2", "3", "4", "5"];

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

pub struct FinalizerMetrics {
    pub batches_delivered: IntCounterVec,
    pub batch_height: IntGauge,
    pub ingress_messages_delivered: Histogram,
    pub ingress_message_bytes_delivered: Histogram,
    pub xnet_bytes_delivered: Histogram,
    pub finalization_certified_state_difference: IntGauge,
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
    pub ingress_payload_cache_size: IntGauge,
    pub past_payloads_length: Histogram,
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
            ingress_payload_cache_size: metrics_registry.int_gauge(
                "ingress_payload_cache_size",
                "The number of HashSets in payload builder's ingress payload cache.",
            ),
            past_payloads_length: metrics_registry.histogram(
                "consensus_past_payloads_length",
                "The length of past_payloads in payload selection",
                linear_buckets(0.0, 1.0, 6),
            ),
        }
    }
}

pub struct ValidatorMetrics {
    pub time_to_receive_block: HistogramVec,
    pub duplicate_artifact: IntCounterVec,
    pub validation_duration: HistogramVec,
    pub dkg_validator: IntCounterVec,
    // Used to sum the values within a single validator run
    dkg_time_per_validator_run: RwLock<f64>,
}

impl ValidatorMetrics {
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
        }
    }

    pub fn observe_block(&self, pool_reader: &PoolReader, proposal: &BlockProposal) {
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
                            .observe((timestamp - start_time).as_secs_f64());
                    }
                }
            }
        }
    }

    pub fn add_to_dkg_time_per_validator_run(&self, elapsed_time: f64) {
        let mut dkg_time = self.dkg_time_per_validator_run.write().unwrap();
        *dkg_time += elapsed_time;
    }

    pub fn observe_and_reset_dkg_time_per_validator_run(&self) {
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
                "The height below which replicated states are purged",
            ),
        }
    }
}

#[derive(Clone)]
pub struct EcdsaClientMetrics {
    pub on_state_change_duration: HistogramVec,
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

pub fn timed_call<F, R>(label: &str, call_fn: F, metric: &HistogramVec) -> R
where
    F: FnOnce() -> R,
{
    let _timer = metric.with_label_values(&[label]).start_timer();
    (call_fn)()
}
