use ic_metrics::{
    buckets::{add_bucket, decimal_buckets},
    MetricsRegistry,
};
use prometheus::{Histogram, IntCounterVec};

pub struct Metrics {
    /// Iff there are no errors during a poll interval, this counter is
    /// incremented by one.
    pub poll_count: IntCounterVec,
    /// Iff an error occurs during the a poll interval, a respective counter
    /// is increased.
    pub error_count: IntCounterVec,
    /// A histogram tracking the latency for updating all polled registries.
    pub registries_update_latency_seconds: Histogram,
}

pub const ERROR_TYPE: &str = "error_type";
pub const POLL_STATUS: &str = "poll_status";

impl Metrics {
    pub fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            poll_count: metrics_registry.int_counter_vec(
                "discovery_poll_count",
                "Count of successful poll iterations.",
                &[POLL_STATUS],
            ),
            error_count: metrics_registry.int_counter_vec(
                "discovery_error_count",
                "Total number of errors that occured while scraping ICs.",
                &[ERROR_TYPE],
            ),
            registries_update_latency_seconds: metrics_registry.histogram(
                "discovery_registries_update_latency_seconds",
                "The amount of time it takes to update all registries within a poll interval.",
                // 1ms, 2ms, 5ms, 10ms, 20ms, ..., 10s, 15s, 20s, 50s
                add_bucket(15.0, decimal_buckets(-3, 1)),
            ),
        }
    }
}
