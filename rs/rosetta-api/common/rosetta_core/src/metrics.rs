use actix_web_prom::{PrometheusMetrics, PrometheusMetricsBuilder};
use prometheus::{
    register_gauge, register_histogram, register_histogram_vec, register_int_counter,
    register_int_counter_vec, register_int_gauge, Gauge, Histogram, HistogramTimer, HistogramVec,
    IntCounter, IntCounterVec, IntGauge,
};
use std::sync::Mutex;

use lazy_static::lazy_static;

lazy_static! {
    static ref ENDPOINTS_METRICS: RosettaEndpointsMetrics = RosettaEndpointsMetrics::new();

    static ref VERIFIED_HEIGHT: IntGauge =
        register_int_gauge!("rosetta_verified_block_height", "Verified block height").unwrap();
    static ref SYNCED_HEIGHT: IntGauge =
        register_int_gauge!("rosetta_synched_block_height", "Synced block height").unwrap();
    static ref TARGET_HEIGHT: IntGauge =
        register_int_gauge!("rosetta_target_block_height", "Target height (tip)").unwrap();
    static ref SYNC_ERR_COUNTER: IntCounter = register_int_counter!(
        "blockchain_sync_errors_total",
        "Number of times synchronization failed"
    )
    .unwrap();
    static ref OUT_OF_SYNC_TIME: Gauge = register_gauge!(
        "ledger_sync_attempt_duration_seconds",
        "Number of seconds since the last successful sync"
    )
    .unwrap();
    static ref OUT_OF_SYNC_TIME_HIST: Histogram = register_histogram!(
        "ledger_sync_attempt_duration_seconds_hist",
        "Number of seconds since last successful sync",
        vec![0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 5.0, 10.0, 15.0]
    )
    .unwrap();
    static ref BLOCKS_FETCHED_COUNTER: IntCounter = register_int_counter!(
        "ledger_sync_blocks_fetched_total",
        "Number of blocks fetched from the ledger"
    ).unwrap();
    // Counter for number of retries when fetching blocks from the canister.
    static ref BLOCKS_FETCH_RETRIES_COUNTER: IntCounter = register_int_counter!(
        "ledger_sync_blocks_fetch_retries_total",
        "Number of retries when fetching blocks from the ledger"
    ).unwrap();

    pub static ref SYNC_THREAD_RESTARTS: IntCounter = register_int_counter!(
        "blockchain_sync_thread_restarts_total",
        "Number of times the sync thread has been restarted"
    )
    .unwrap();

    static ref METRICS: Mutex<Option<PrometheusMetrics>> = Mutex::new(None);
}

struct RosettaEndpointsMetrics {
    pub request_duration: HistogramVec,
    pub rosetta_api_status_total: IntCounterVec,
}

impl RosettaEndpointsMetrics {
    pub fn new() -> Self {
        Self {
            request_duration: register_histogram_vec!(
                "http_request_duration",
                "HTTP request latency in seconds indexed by endpoint",
                &["endpoint"]
            )
            .unwrap(),
            rosetta_api_status_total: register_int_counter_vec!(
                "rosetta_api_status_total",
                "Response status for ic-rosetta-api endpoints",
                &["status_code"]
            )
            .unwrap(),
        }
    }
}

// Metrics accessor for the Rosetta endpoints.
pub struct RosettaMetrics {}

impl RosettaMetrics {
    pub fn inc_api_status_count(status: &str) {
        let labels = &[status];
        ENDPOINTS_METRICS
            .rosetta_api_status_total
            .with_label_values(labels)
            .inc();
    }

    pub fn start_request_duration_timer(endpoint: &str) -> HistogramTimer {
        let labels = &[endpoint];
        ENDPOINTS_METRICS
            .request_duration
            .with_label_values(labels)
            .start_timer()
    }

    pub fn set_target_height(height: u64) {
        TARGET_HEIGHT.set(height.try_into().unwrap());
    }

    pub fn set_synced_height(height: u64) {
        SYNCED_HEIGHT.set(height.try_into().unwrap());
    }

    pub fn set_verified_height(height: u64) {
        VERIFIED_HEIGHT.set(height.try_into().unwrap());
    }

    pub fn set_out_of_sync_time(seconds: f64) {
        OUT_OF_SYNC_TIME.set(seconds);
        OUT_OF_SYNC_TIME_HIST.observe(seconds);
    }

    pub fn add_blocks_fetched(count: u64) {
        BLOCKS_FETCHED_COUNTER.inc_by(count);
    }

    pub fn inc_fetch_retries() {
        BLOCKS_FETCH_RETRIES_COUNTER.inc();
    }

    pub fn inc_sync_errors() {
        SYNC_ERR_COUNTER.inc();
    }

    pub fn inc_sync_thread_restarts() {
        SYNC_THREAD_RESTARTS.inc();
    }

    pub fn http_metrics_wrapper(expose: bool) -> PrometheusMetrics {
        let mut metrics_guard = METRICS.lock().unwrap();
        if let Some(metrics) = &*metrics_guard {
            return metrics.clone();
        }

        let metrics = PrometheusMetricsBuilder::new("rosetta")
            .registry(prometheus::default_registry().clone());

        let metrics = if expose {
            metrics.endpoint("/metrics").build().unwrap()
        } else {
            metrics.build().unwrap()
        };

        *metrics_guard = Some(metrics.clone());
        metrics
    }
}
