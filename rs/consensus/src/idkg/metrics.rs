//! Metrics for the idkg feature

use ic_management_canister_types::MasterPublicKeyId;
use ic_metrics::{
    buckets::{decimal_buckets, linear_buckets},
    MetricsRegistry,
};
use ic_types::consensus::idkg::{HasMasterPublicKeyId, IDkgPayload};
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec};
use std::collections::BTreeMap;

pub const KEY_ID_LABEL: &str = "key_id";

pub(crate) const CRITICAL_ERROR_MASTER_KEY_TRANSCRIPT_MISSING: &str =
    "master_key_transcript_missing";
pub(crate) const CRITICAL_ERROR_IDKG_RETAIN_ACTIVE_TRANSCRIPTS: &str =
    "idkg_retain_active_transcripts_error";

#[derive(Clone)]
pub struct IDkgClientMetrics {
    pub on_state_change_duration: HistogramVec,
    pub client_metrics: IntCounterVec,
    pub client_errors: IntCounterVec,
    /// critical error when retain_active_transcripts fails
    pub critical_error_idkg_retain_active_transcripts: IntCounter,
}

impl IDkgClientMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            on_state_change_duration: metrics_registry.histogram_vec(
                "idkg_on_state_change_duration_seconds",
                "The time it took to execute IDkg on_state_change(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["sub_component"],
            ),
            client_metrics: metrics_registry.int_counter_vec(
                "idkg_client_metrics",
                "IDkg client related metrics",
                &["type"],
            ),
            client_errors: metrics_registry.int_counter_vec(
                "idkg_client_errors",
                "IDkg client related errors",
                &["type"],
            ),
            critical_error_idkg_retain_active_transcripts: metrics_registry
                .error_counter(CRITICAL_ERROR_IDKG_RETAIN_ACTIVE_TRANSCRIPTS),
        }
    }
}

#[derive(Clone)]
pub struct IDkgPreSignerMetrics {
    pub on_state_change_duration: HistogramVec,
    pub pre_sign_metrics: IntCounterVec,
    pub pre_sign_errors: IntCounterVec,
}

impl IDkgPreSignerMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            on_state_change_duration: metrics_registry.histogram_vec(
                "idkg_pre_signer_on_state_change_duration_seconds",
                "The time it took to execute pre-signer on_state_change(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["sub_component"],
            ),
            pre_sign_metrics: metrics_registry.int_counter_vec(
                "idkg_pre_signer_metrics",
                "Pre-signing related metrics",
                &["type"],
            ),
            pre_sign_errors: metrics_registry.int_counter_vec(
                "idkg_pre_signer_errors",
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
pub struct ThresholdSignerMetrics {
    pub on_state_change_duration: HistogramVec,
    pub sign_metrics: IntCounterVec,
    pub sign_errors: IntCounterVec,
}

impl ThresholdSignerMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            on_state_change_duration: metrics_registry.histogram_vec(
                "idkg_signer_on_state_change_duration_seconds",
                "The time it took to execute signer on_state_change(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["sub_component"],
            ),
            sign_metrics: metrics_registry.int_counter_vec(
                "idkg_signer_metrics",
                "Signing related metrics",
                &["type"],
            ),
            sign_errors: metrics_registry.int_counter_vec(
                "idkg_signer_errors",
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

pub(crate) struct IDkgPayloadMetrics {
    payload_metrics: IntGaugeVec,
    payload_errors: IntCounterVec,
    transcript_builder_metrics: IntCounterVec,
    transcript_builder_errors: IntCounterVec,
    pub(crate) transcript_builder_duration: HistogramVec,
    /// Critical error for failure to create/reshare key transcript
    pub(crate) critical_error_master_key_transcript_missing: IntCounter,
}

impl IDkgPayloadMetrics {
    pub(crate) fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            payload_metrics: metrics_registry.int_gauge_vec(
                "idkg_payload_metrics",
                "IDkg payload related metrics",
                &["type", KEY_ID_LABEL],
            ),
            payload_errors: metrics_registry.int_counter_vec(
                "idkg_payload_errors",
                "IDkg payload related errors",
                &["type"],
            ),
            transcript_builder_metrics: metrics_registry.int_counter_vec(
                "idkg_transcript_builder_metrics",
                "IDkg transcript builder metrics",
                &["type"],
            ),
            transcript_builder_errors: metrics_registry.int_counter_vec(
                "idkg_transcript_builder_errors",
                "IDkg transcript builder related errors",
                &["type"],
            ),
            transcript_builder_duration: metrics_registry.histogram_vec(
                "idkg_transcript_builder_duration_seconds",
                "Time taken by transcript builder, in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["sub_component"],
            ),
            critical_error_master_key_transcript_missing: metrics_registry
                .error_counter(CRITICAL_ERROR_MASTER_KEY_TRANSCRIPT_MISSING),
        }
    }

    pub(crate) fn report(&self, payload: &IDkgPayload) {
        let expected_keys = expected_keys(payload);

        self.payload_metrics_set_without_key_id_label(
            "signature_agreements",
            payload.signature_agreements.len(),
        );
        self.payload_metrics_set(
            "available_pre_signatures",
            count_by_master_public_key_id(
                payload.available_pre_signatures.values(),
                &expected_keys,
            ),
        );
        self.payload_metrics_set(
            "pre_signatures_in_creation",
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
        self.payload_metrics_set_without_key_id_label(
            "key_transcripts",
            payload.key_transcripts.len(),
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
pub struct IDkgComplaintMetrics {
    pub on_state_change_duration: HistogramVec,
    pub complaint_metrics: IntCounterVec,
    pub complaint_errors: IntCounterVec,
}

impl IDkgComplaintMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            on_state_change_duration: metrics_registry.histogram_vec(
                "idkg_complaint_on_state_change_duration_seconds",
                "The time it took to execute complaint on_state_change(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["sub_component"],
            ),
            complaint_metrics: metrics_registry.int_counter_vec(
                "idkg_complaint_metrics",
                "Complaint related metrics",
                &["type"],
            ),
            complaint_errors: metrics_registry.int_counter_vec(
                "idkg_complaint_errors",
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
pub struct IDkgTranscriptMetrics {
    pub active_transcripts: IntGauge,
    pub support_validation_duration: HistogramVec,
    pub support_validation_total_duration: HistogramVec,
    pub support_aggregation_duration: HistogramVec,
    pub support_aggregation_total_duration: HistogramVec,
    pub create_transcript_duration: HistogramVec,
    pub create_transcript_total_duration: HistogramVec,
    pub transcript_e2e_latency: HistogramVec,
}

impl IDkgTranscriptMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            active_transcripts: metrics_registry
                .int_gauge("idkg_active_transcripts", "Currently active transcripts"),
            support_validation_duration: metrics_registry.histogram_vec(
                "idkg_support_validation_duration",
                "Support validation duration, in msec",
                decimal_buckets(0, 2),
                &["type"],
            ),
            support_validation_total_duration: metrics_registry.histogram_vec(
                "idkg_support_validation_total_duration",
                "Total support validation duration, in msec",
                decimal_buckets(0, 4),
                &["type"],
            ),
            support_aggregation_duration: metrics_registry.histogram_vec(
                "idkg_support_aggregation_duration",
                "Support aggregation duration, in msec",
                decimal_buckets(0, 2),
                &["type"],
            ),
            support_aggregation_total_duration: metrics_registry.histogram_vec(
                "idkg_support_aggregation_total_duration",
                "Total support aggregation duration, in msec",
                decimal_buckets(0, 4),
                &["type"],
            ),
            create_transcript_duration: metrics_registry.histogram_vec(
                "idkg_create_transcript_duration",
                "Time to create transcript, in msec",
                decimal_buckets(0, 5),
                &["type"],
            ),
            create_transcript_total_duration: metrics_registry.histogram_vec(
                "idkg_create_transcript_total_duration",
                "Total time to create transcript, in msec",
                decimal_buckets(0, 5),
                &["type"],
            ),
            transcript_e2e_latency: metrics_registry.histogram_vec(
                "idkg_transcript_e2e_latency",
                "End to end latency to build the transcript, in sec",
                linear_buckets(0.5, 0.5, 30),
                &["type"],
            ),
        }
    }
}

#[derive(Clone)]
pub struct IDkgPreSignatureMetrics {
    pub pre_signature_e2e_latency: HistogramVec,
}

impl IDkgPreSignatureMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            pre_signature_e2e_latency: metrics_registry.histogram_vec(
                "idkg_pre_signature_e2e_latency",
                "End to end latency to build the pre-signature, in sec",
                linear_buckets(1.0, 0.5, 30),
                &["key_id"],
            ),
        }
    }
}

#[derive(Clone)]
pub struct ThresholdSignatureMetrics {
    pub active_signatures: IntGauge,
    pub sig_share_validation_duration: Histogram,
    pub sig_share_validation_total_duration: Histogram,
    pub sig_share_aggregation_duration: Histogram,
    pub sig_share_aggregation_total_duration: Histogram,
    pub signature_e2e_latency: Histogram,
}

impl ThresholdSignatureMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            active_signatures: metrics_registry
                .int_gauge("idkg_active_signatures", "Currently active signatures"),
            sig_share_validation_duration: metrics_registry.histogram(
                "threshold_sig_share_validation_duration",
                "Sig share validation duration, in msec",
                decimal_buckets(0, 2),
            ),
            sig_share_validation_total_duration: metrics_registry.histogram(
                "threshold_sig_share_validation_total_duration",
                "Total sig share validation duration, in msec",
                decimal_buckets(0, 4),
            ),
            sig_share_aggregation_duration: metrics_registry.histogram(
                "threshold_sig_share_aggregation_duration",
                "Sig share aggregation duration, in msec",
                decimal_buckets(0, 2),
            ),
            sig_share_aggregation_total_duration: metrics_registry.histogram(
                "threshold_sig_share_aggregation_total_duration",
                "Total sig share aggregation duration, in msec",
                decimal_buckets(0, 4),
            ),
            signature_e2e_latency: metrics_registry.histogram(
                "threshold_signature_e2e_latency",
                "End to end latency to build the signature, in sec",
                linear_buckets(0.5, 0.5, 30),
            ),
        }
    }
}

/// Returns the key id corresponding to the [`MasterPublicKeyId`]
pub fn key_id_label(key_id: Option<&MasterPublicKeyId>) -> String {
    key_id.map(ToString::to_string).unwrap_or_default()
}

pub fn expected_keys(payload: &IDkgPayload) -> Vec<MasterPublicKeyId> {
    payload.key_transcripts.keys().cloned().collect()
}

pub type CounterPerMasterPublicKeyId = BTreeMap<MasterPublicKeyId, usize>;

pub fn count_by_master_public_key_id<T: HasMasterPublicKeyId>(
    collection: impl Iterator<Item = T>,
    expected_keys: &[MasterPublicKeyId],
) -> CounterPerMasterPublicKeyId {
    let mut counter_per_key_id = CounterPerMasterPublicKeyId::new();

    // To properly report `0` for master keys which do not appear in the `collection`, we insert the
    // default values for all the master keys which we expect to see in the payload.
    for key in expected_keys {
        counter_per_key_id.insert(key.clone(), 0);
    }

    for item in collection {
        *counter_per_key_id.entry(item.key_id().clone()).or_default() += 1;
    }

    counter_per_key_id
}
