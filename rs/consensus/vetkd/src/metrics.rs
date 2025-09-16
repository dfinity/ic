//! This module contains the metric struct for the vetKD feature

use ic_management_canister_types_private::MasterPublicKeyId;
use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use prometheus::{HistogramVec, IntCounterVec};

const KEY_ID_LABEL: &str = "key_id";

pub struct VetKdPayloadBuilderMetrics {
    /// Records the time it took to perform an operation
    pub op_duration: HistogramVec,
    /// Errors that occured during payload building or validation
    payload_errors: IntCounterVec,
    /// Metrics collected during payload building or validation
    payload_metrics: IntCounterVec,
}

impl VetKdPayloadBuilderMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            op_duration: metrics_registry.histogram_vec(
                "vetkd_payload_build_duration",
                "The time it took the payload builder to perform an operation",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &["operation"],
            ),
            payload_metrics: metrics_registry.int_counter_vec(
                "vetkd_payload_metrics",
                "VetKD payload related metrics",
                &["type", KEY_ID_LABEL],
            ),
            payload_errors: metrics_registry.int_counter_vec(
                "vetkd_payload_errors",
                "VetKD payload related errors",
                &["type", KEY_ID_LABEL],
            ),
        }
    }

    pub(crate) fn payload_metrics_inc(&self, label: &str, key_id: &MasterPublicKeyId) {
        self.payload_metrics
            .with_label_values(&[label, &key_id.to_string()])
            .inc();
    }

    pub(crate) fn payload_errors_inc(&self, label: &str, key_id: &MasterPublicKeyId) {
        self.payload_errors
            .with_label_values(&[label, &key_id.to_string()])
            .inc();
    }
}
