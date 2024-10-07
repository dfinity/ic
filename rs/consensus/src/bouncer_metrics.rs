use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};

use prometheus::{histogram_opts, labels, Histogram, HistogramTimer};

pub(crate) struct BouncerMetrics {
    update_duration: Histogram,
}

impl BouncerMetrics {
    pub(crate) fn new(registry: &MetricsRegistry, pool_type: &str) -> Self {
        Self {
            update_duration: registry.register(
                Histogram::with_opts(histogram_opts!(
                    "consensus_bouncer_update_duration",
                    "How long it took to compute the bouncer function, in seconds",
                    // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                    // 1s, 2s, 5s, 10s, 20s, 50s
                    decimal_buckets(-4, 1),
                    labels! { String::from("type") => pool_type.to_string() }
                ))
                .unwrap(),
            ),
        }
    }

    pub(crate) fn start_timer(&self) -> HistogramTimer {
        self.update_duration.start_timer()
    }
}
