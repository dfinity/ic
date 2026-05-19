use ic_metrics::{
    MetricsRegistry,
    buckets::{decimal_buckets, linear_buckets},
};
use ic_types::{
    consensus::{BlockPayload, dkg::RemoteDkgAttempts},
    crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTargetSubnet},
};
use prometheus::{Histogram, HistogramTimer, HistogramVec, IntCounterVec};
use std::collections::BTreeMap;

pub(crate) struct DkgClientMetrics {
    pub(crate) on_state_change_duration: Histogram,
    pub(crate) on_state_change_processed: Histogram,
}

impl DkgClientMetrics {
    pub(crate) fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            on_state_change_duration: metrics_registry.histogram(
                "consensus_dkg_on_state_change_duration_seconds",
                "The time it took to execute on_state_change(), in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
            ),
            on_state_change_processed: metrics_registry.histogram(
                "consensus_dkg_on_state_change_processed",
                "Number of entries processed by on_state_change()",
                // 0 - 100
                linear_buckets(0.0, 1.0, 100),
            ),
        }
    }
}

pub struct DkgPayloadMetrics {
    payload_errors: IntCounterVec,
    payload_duration: HistogramVec,
}

impl DkgPayloadMetrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            payload_errors: metrics_registry.int_counter_vec(
                "consensus_dkg_payload_errors",
                "NiDKG payload related errors",
                &["type"],
            ),
            payload_duration: metrics_registry.histogram_vec(
                "consensus_dkg_payload_creation_seconds",
                "Time taken to create a NiDKG payload, in seconds",
                decimal_buckets(-4, 2),
                &["type"],
            ),
        }
    }

    pub fn payload_errors_inc(&self, label: &str) {
        self.payload_errors.with_label_values(&[label]).inc();
    }
}

pub(crate) trait DkgPayloadMetricsOptionExt {
    fn payload_errors_inc(self, label: &str);
    fn payload_creation_timer(self, label: &str) -> Option<HistogramTimer>;
}

impl DkgPayloadMetricsOptionExt for Option<&DkgPayloadMetrics> {
    fn payload_errors_inc(self, label: &str) {
        if let Some(metrics) = self {
            metrics.payload_errors_inc(label);
        }
    }

    fn payload_creation_timer(self, label: &str) -> Option<HistogramTimer> {
        self.map(|metrics| {
            metrics
                .payload_duration
                .with_label_values(&[label])
                .start_timer()
        })
    }
}

pub struct DkgPayloadStats {
    pub remote_dkg_attempts_map_size: Option<usize>,
    pub remote_dkg_attempts_map_sum: Option<u64>,
    pub dealings_included: BTreeMap<(NiDkgTag, NiDkgTargetSubnet), usize>,
    pub remote_transcripts_delivered: BTreeMap<NiDkgTag, usize>,
}

impl From<&BlockPayload> for DkgPayloadStats {
    fn from(payload: &BlockPayload) -> Self {
        let mut dealings_included = BTreeMap::new();
        let mut remote_transcripts_delivered = BTreeMap::new();
        let (remote_dkg_attempts_map_size, remote_dkg_attempts_map_sum) = match payload {
            BlockPayload::Summary(summary_payload) => (
                Some(summary_payload.dkg.remote_dkg_attempts.len()),
                Some(
                    summary_payload
                        .dkg
                        .remote_dkg_attempts
                        .values()
                        .map(|attempts| match attempts {
                            RemoteDkgAttempts::Completed => 0_u64,
                            RemoteDkgAttempts::Attempt(n) => *n as u64,
                        })
                        .sum(),
                ),
            ),
            BlockPayload::Data(data_payload) => {
                for message in &data_payload.dkg.messages {
                    let dkg_id = &message.content.dkg_id;
                    dealings_included
                        .entry((dkg_id.dkg_tag.clone(), dkg_id.target_subnet))
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }

                for transcript in &data_payload.dkg.transcripts_for_remote_subnets {
                    remote_transcripts_delivered
                        .entry(transcript.dkg_id.dkg_tag.clone())
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }

                (None, None)
            }
        };
        Self {
            remote_dkg_attempts_map_size,
            remote_dkg_attempts_map_sum,
            dealings_included,
            remote_transcripts_delivered,
        }
    }
}
