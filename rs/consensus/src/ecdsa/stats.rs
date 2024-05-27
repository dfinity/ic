//! ECDSA specific stats.

use crate::consensus::metrics::{
    EcdsaQuadrupleMetrics, EcdsaSignatureMetrics, EcdsaTranscriptMetrics,
};
use ic_types::consensus::idkg::{EcdsaBlockReader, EcdsaStats, PreSigId, RequestId};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgDealingSupport, IDkgTranscriptId, IDkgTranscriptParams,
};

use ic_metrics::MetricsRegistry;
use prometheus::{Histogram, HistogramVec};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Implementation of EcdsaStats
pub struct EcdsaStatsImpl {
    state: Mutex<EcdsaStatsInternal>,
    transcript_metrics: EcdsaTranscriptMetrics,
    quadruple_metrics: EcdsaQuadrupleMetrics,
    signature_metrics: EcdsaSignatureMetrics,
}

struct EcdsaStatsInternal {
    transcript_stats: HashMap<IDkgTranscriptId, TranscriptStats>,
    quadruple_stats: HashMap<PreSigId, QuadrupleStats>,
    signature_stats: HashMap<RequestId, SignatureStats>,
}

struct TranscriptStats {
    start_time: Instant,
    transcript_type: String,
    support_validation_duration: Vec<Duration>,
    support_aggregation_duration: Vec<Duration>,
    create_transcript_duration: Vec<Duration>,
}

struct QuadrupleStats {
    start_time: Instant,
}

struct SignatureStats {
    start_time: Instant,
    sig_share_validation_duration: Vec<Duration>,
    sig_share_aggregation_duration: Vec<Duration>,
}

impl EcdsaStatsImpl {
    /// Creates EcdsaStatsImpl
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            state: Mutex::new(EcdsaStatsInternal {
                transcript_stats: HashMap::new(),
                quadruple_stats: HashMap::new(),
                signature_stats: HashMap::new(),
            }),
            transcript_metrics: EcdsaTranscriptMetrics::new(metrics_registry.clone()),
            quadruple_metrics: EcdsaQuadrupleMetrics::new(metrics_registry.clone()),
            signature_metrics: EcdsaSignatureMetrics::new(metrics_registry),
        }
    }

    /// Called when the transcript completed building. Reports the accumulated
    /// stats.
    fn on_transcript_done(&self, transcript_stats: &TranscriptStats) {
        let report_durations = |type_str: &str,
                                durations: &[Duration],
                                individual_metric: &HistogramVec,
                                total_metric: &HistogramVec| {
            if durations.is_empty() {
                return;
            }

            let mut total = 0_f64;
            for duration in durations {
                let val = duration.as_millis() as f64;
                total += val;
                individual_metric
                    .with_label_values(&[type_str])
                    .observe(val);
            }
            total_metric.with_label_values(&[type_str]).observe(total);
        };

        report_durations(
            &transcript_stats.transcript_type,
            &transcript_stats.support_validation_duration,
            &self.transcript_metrics.support_validation_duration,
            &self.transcript_metrics.support_validation_total_duration,
        );
        report_durations(
            &transcript_stats.transcript_type,
            &transcript_stats.support_aggregation_duration,
            &self.transcript_metrics.support_aggregation_duration,
            &self.transcript_metrics.support_aggregation_total_duration,
        );
        report_durations(
            &transcript_stats.transcript_type,
            &transcript_stats.create_transcript_duration,
            &self.transcript_metrics.create_transcript_duration,
            &self.transcript_metrics.create_transcript_total_duration,
        );
        self.transcript_metrics
            .transcript_e2e_latency
            .with_label_values(&[&transcript_stats.transcript_type])
            .observe(transcript_stats.start_time.elapsed().as_secs_f64());
    }

    /// Called when the quadruple completed building. Reports the accumulated
    /// stats.
    fn on_quadruple_done(&self, quadruple_stats: &QuadrupleStats) {
        self.quadruple_metrics
            .quadruple_e2e_latency
            .observe(quadruple_stats.start_time.elapsed().as_secs_f64());
    }

    /// Called when the signature is completed. Reports the accumulated
    /// stats.
    fn on_signature_done(&self, signature_stats: &SignatureStats) {
        let report_durations =
            |durations: &[Duration], individual_metric: &Histogram, total_metric: &Histogram| {
                if durations.is_empty() {
                    return;
                }

                let mut total = 0_f64;
                for duration in durations {
                    let val = duration.as_millis() as f64;
                    total += val;
                    individual_metric.observe(val);
                }
                total_metric.observe(total);
            };

        report_durations(
            &signature_stats.sig_share_validation_duration,
            &self.signature_metrics.sig_share_validation_duration,
            &self.signature_metrics.sig_share_validation_total_duration,
        );
        report_durations(
            &signature_stats.sig_share_aggregation_duration,
            &self.signature_metrics.sig_share_aggregation_duration,
            &self.signature_metrics.sig_share_aggregation_total_duration,
        );
        self.signature_metrics
            .signature_e2e_latency
            .observe(signature_stats.start_time.elapsed().as_secs_f64());
    }
}

impl EcdsaStats for EcdsaStatsImpl {
    fn update_active_transcripts(&self, block_reader: &dyn EcdsaBlockReader) {
        let mut active_transcripts = HashSet::new();
        let mut state = self.state.lock().unwrap();
        for transcript_params_ref in block_reader.requested_transcripts() {
            active_transcripts.insert(transcript_params_ref.transcript_id);
            state
                .transcript_stats
                .entry(transcript_params_ref.transcript_id)
                .or_insert(TranscriptStats {
                    start_time: Instant::now(),
                    transcript_type: transcript_params_ref.operation_type_ref.as_str(),
                    support_validation_duration: Vec::new(),
                    support_aggregation_duration: Vec::new(),
                    create_transcript_duration: Vec::new(),
                });
        }

        // Remove the entries that are no longer active, and finish reporting their
        // metrics
        let mut to_remove = HashSet::new();
        for (transcript_id, transcript_stats) in &state.transcript_stats {
            if !active_transcripts.contains(transcript_id) {
                to_remove.insert(*transcript_id);
                self.on_transcript_done(transcript_stats);
            }
        }
        for transcript_id in &to_remove {
            state.transcript_stats.remove(transcript_id);
        }
        self.transcript_metrics
            .active_transcripts
            .set(state.transcript_stats.len() as i64);
    }

    fn update_active_quadruples(&self, block_reader: &dyn EcdsaBlockReader) {
        let mut active_quadruples = HashSet::new();
        let mut state = self.state.lock().unwrap();
        for pre_sig_id in block_reader.pre_signatures_in_creation() {
            active_quadruples.insert(pre_sig_id);

            state
                .quadruple_stats
                .entry(*pre_sig_id)
                .or_insert(QuadrupleStats {
                    start_time: Instant::now(),
                });
        }

        // Remove the entries that are no longer active, and finish reporting their metrics
        let mut to_remove = HashSet::new();
        for (pre_sig_id, quadruple_stats) in &state.quadruple_stats {
            if !active_quadruples.contains(pre_sig_id) {
                to_remove.insert(*pre_sig_id);
                self.on_quadruple_done(quadruple_stats);
            }
        }

        for pre_sig_id in &to_remove {
            state.quadruple_stats.remove(pre_sig_id);
        }
    }

    fn record_support_validation(&self, support: &IDkgDealingSupport, duration: Duration) {
        let mut state = self.state.lock().unwrap();
        let transcript_stats = match state.transcript_stats.get_mut(&support.transcript_id) {
            Some(val) => val,
            _ => return,
        };
        transcript_stats.support_validation_duration.push(duration);
    }

    fn record_support_aggregation(
        &self,
        transcript_params: &IDkgTranscriptParams,
        support_shares: &[IDkgDealingSupport],
        duration: Duration,
    ) {
        if support_shares.is_empty() {
            return;
        }

        let mut state = self.state.lock().unwrap();
        let transcript_stats = match state
            .transcript_stats
            .get_mut(&transcript_params.transcript_id())
        {
            Some(val) => val,
            _ => return,
        };
        transcript_stats.support_aggregation_duration.push(duration);
    }

    fn record_transcript_creation(
        &self,
        transcript_params: &IDkgTranscriptParams,
        duration: Duration,
    ) {
        let mut state = self.state.lock().unwrap();
        let transcript_stats = match state
            .transcript_stats
            .get_mut(&transcript_params.transcript_id())
        {
            Some(val) => val,
            _ => return,
        };
        transcript_stats.create_transcript_duration.push(duration);
    }

    fn update_active_signature_requests(&self, requests: Vec<RequestId>) {
        let mut active_requests = HashSet::new();
        let mut state = self.state.lock().unwrap();
        for request_id in &requests {
            active_requests.insert(request_id);

            state
                .signature_stats
                .entry(request_id.clone())
                .or_insert(SignatureStats {
                    start_time: Instant::now(),
                    sig_share_validation_duration: Vec::new(),
                    sig_share_aggregation_duration: Vec::new(),
                });
        }

        // Remove the entries no longer active, and finish reporting their metrics
        let mut to_remove = HashSet::new();
        for (request_id, signature_stats) in &state.signature_stats {
            if !active_requests.contains(request_id) {
                to_remove.insert(request_id.clone());
                self.on_signature_done(signature_stats);
            }
        }

        for request_id in &to_remove {
            state.signature_stats.remove(request_id);
        }

        self.signature_metrics
            .active_signatures
            .set(state.signature_stats.len() as i64);
    }

    fn record_sig_share_validation(&self, request_id: &RequestId, duration: Duration) {
        let mut state = self.state.lock().unwrap();
        let signature_stats = match state.signature_stats.get_mut(request_id) {
            Some(val) => val,
            _ => return,
        };
        signature_stats.sig_share_validation_duration.push(duration);
    }

    fn record_sig_share_aggregation(&self, request_id: &RequestId, duration: Duration) {
        let mut state = self.state.lock().unwrap();
        let signature_stats = match state.signature_stats.get_mut(request_id) {
            Some(val) => val,
            _ => return,
        };
        signature_stats
            .sig_share_aggregation_duration
            .push(duration);
    }
}
