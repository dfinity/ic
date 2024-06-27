//! Metrics for the ecdsa feature

use ic_management_canister_types::MasterPublicKeyId;
use ic_metrics::{
    buckets::{decimal_buckets, linear_buckets},
    MetricsRegistry,
};
use ic_types::consensus::idkg::EcdsaPayload;
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec};

pub(crate) const CRITICAL_ERROR_ECDSA_KEY_TRANSCRIPT_MISSING: &str = "ecdsa_key_transcript_missing";
pub(crate) const CRITICAL_ERROR_ECDSA_RETAIN_ACTIVE_TRANSCRIPTS: &str =
    "ecdsa_retain_active_transcripts_error";

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
        let expected_keys = expected_keys(payload);

        self.payload_metrics_set_without_key_id_label(
            "signature_agreements",
            payload.signature_agreements.len(),
        );
        self.payload_metrics_set(
            "available_quadruples",
            count_by_master_public_key_id(
                payload.available_pre_signatures.values(),
                &expected_keys,
            ),
        );
        self.payload_metrics_set(
            "quadruples_in_creation",
            count_by_master_public_key_id(
                payload.pre_signatures_in_creation.values(),
                &expected_keys,
            ),
        );
        self.payload_metrics_set(
            "ongoing_xnet_reshares",
            count_by_master_public_key_id(payload.ongoing_xnet_reshares.keys(), &expected_keys),
        );
        self.payload_metrics_set(
            "xnet_reshare_agreements",
            count_by_master_public_key_id(payload.xnet_reshare_agreements.keys(), &expected_keys),
        );
        self.payload_metrics_set_without_key_id_label("payload_layout_multiple_keys", 1);
        self.payload_metrics_set_without_key_id_label(
            "payload_layout_generalized_pre_signatures",
            1,
        );
        self.payload_metrics_set_without_key_id_label(
            "key_transcripts",
            payload.key_transcripts.len(),
        );
        self.payload_metrics_set_without_key_id_label(
            "key_transcripts_with_ecdsa_key_id",
            payload
                .key_transcripts
                .values()
                .filter(|k| k.deprecated_key_id.is_some())
                .count(),
        );
    }

    fn payload_metrics_set_without_key_id_label(&self, label: &str, value: usize) {
        self.payload_metrics
            .with_label_values(&[label, /*key_id=*/ ""])
            .set(value as i64);
    }

    fn payload_metrics_set(&self, label: &str, values: CounterPerMasterPublicKeyId) {
        for (key_id, value) in values {
            self.payload_metrics
                .with_label_values(&[label, &key_id_label(Some(&key_id))])
                .set(value as i64);
        }
    }

    pub(crate) fn payload_metrics_inc(&self, label: &str, key_id: Option<&MasterPublicKeyId>) {
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

fn expected_keys(payload: &EcdsaPayload) -> Vec<MasterPublicKeyId> {
    payload.key_transcripts.keys().cloned().collect()
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
pub struct EcdsaPreSignatureMetrics {
    pub pre_signature_e2e_latency: HistogramVec,
}

impl EcdsaPreSignatureMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            pre_signature_e2e_latency: metrics_registry.histogram_vec(
                "ecdsa_quadruple_e2e_latency",
                "End to end latency to build the pre-signature, in sec",
                linear_buckets(1.0, 0.5, 30),
                &["key_id"],
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
