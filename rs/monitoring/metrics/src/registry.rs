use prometheus::{
    core::Collector, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, Opts,
};

/// A wrapper around `prometheus::Registry` with helpers for creating metrics
///
/// We do not use the static metrics of Prometheus to allow simpler testing of
/// the metrics. Besides that, passing the registry around explicitly is useful
/// for detecting the situation when two different versions of Prometheus are
/// are used in different packages.
#[derive(Debug, Clone, Default)]
pub struct MetricsRegistry {
    registry: prometheus::Registry,
}

impl MetricsRegistry {
    /// Get the registry that is global to this process.
    pub fn global() -> Self {
        let registry = prometheus::default_registry().clone();

        // Remove this when the `prometheus` crate exports the `process_threads` metric.
        #[cfg(target_os = "linux")]
        registry
            .register(Box::new(crate::process_collector::ProcessCollector::new()))
            // Don't `unwrap()`: this may be called repeatedly and we only want to register the
            // collector once.
            .ok();

        Self { registry }
    }

    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            registry: prometheus::Registry::new(),
        }
    }

    /// Create and register a histogram with specified options.
    pub fn histogram<S: Into<String>>(&self, name: S, help: S, buckets: Vec<f64>) -> Histogram {
        self.register(
            Histogram::with_opts(HistogramOpts::new(name, help).buckets(buckets)).unwrap(),
        )
    }

    /// Create and register a `HistogramVec`
    pub fn histogram_vec<S: Into<String>>(
        &self,
        name: S,
        help: S,
        buckets: Vec<f64>,
        label_names: &[&str],
    ) -> HistogramVec {
        self.register(
            HistogramVec::new(HistogramOpts::new(name, help).buckets(buckets), label_names)
                .unwrap(),
        )
    }

    /// Create and register an `IntGauge`.
    pub fn int_gauge<S: Into<String>>(&self, name: S, help: S) -> IntGauge {
        self.register(IntGauge::new(name, help).unwrap())
    }

    /// Create and register an `IntGaugeVec`.
    pub fn int_gauge_vec<S: Into<String>>(
        &self,
        name: S,
        help: S,
        label_names: &[&str],
    ) -> IntGaugeVec {
        self.register(IntGaugeVec::new(Opts::new(name, help), label_names).unwrap())
    }

    /// Create and register a `Gauge`.
    pub fn gauge<S: Into<String>>(&self, name: S, help: S) -> Gauge {
        self.register(Gauge::new(name, help).unwrap())
    }

    /// Create and register a `GaugeVec`.
    pub fn gauge_vec<S: Into<String>>(&self, name: S, help: S, label_names: &[&str]) -> GaugeVec {
        self.register(GaugeVec::new(Opts::new(name, help), label_names).unwrap())
    }

    /// Create and register an `IntCounter`.
    pub fn int_counter<S: Into<String>>(&self, name: S, help: S) -> IntCounter {
        self.register(IntCounter::new(name, help).unwrap())
    }

    /// Create and register an `IntCounterVec`.
    pub fn int_counter_vec<S: Into<String>>(
        &self,
        name: S,
        help: S,
        label_names: &[&str],
    ) -> IntCounterVec {
        self.register(IntCounterVec::new(Opts::new(name, help), label_names).unwrap())
    }

    /// Creates a `critical_errors{error="<error>"}` counter for the given error
    /// type. Any increase in the counter is intended to trigger an alert and
    /// should always be paired with a log message to aid in debugging.
    ///
    /// Panics if `error_counter()` has already been called with the same
    /// `error` value.
    ///
    /// Sample usage:
    /// ```
    /// use ic_logger::{error, ReplicaLogger};
    /// use ic_metrics::MetricsRegistry;
    /// use prometheus::IntCounter;
    ///
    /// pub struct FooMetrics {
    ///     bar_above_limit: IntCounter,
    /// }
    ///
    /// impl FooMetrics {
    ///     pub fn new(metrics_registry: &MetricsRegistry) -> Self {
    ///         FooMetrics {
    ///             bar_above_limit: metrics_registry.error_counter("foo_bar_above_limit"),
    ///         }
    ///     }
    /// }
    ///
    /// fn set_bar(new_bar: u64, metrics: &FooMetrics, log: &ReplicaLogger) {
    ///     if new_bar > 13 {
    ///         error!(log, "foo_bar_above_limit: bar {} > 13", new_bar);
    ///         metrics.bar_above_limit.inc();
    ///     }
    ///
    ///     // ...
    /// }
    /// ```
    pub fn error_counter(&self, error: &str) -> IntCounter {
        self.register(
            IntCounter::with_opts(
                Opts::new(
                    "critical_errors",
                    "Count of encountered critical errors, by type. Intended to trigger alerts and always paired with a log message to aid in debugging.",
                )
                .const_label("error", error),
            )
            .unwrap(),
        )
    }

    pub fn prometheus_registry(&self) -> &prometheus::Registry {
        &self.registry
    }

    pub fn register<C: 'static + Collector + Clone>(&self, c: C) -> C {
        self.registry.register(Box::new(C::clone(&c))).unwrap();
        c
    }
}
