use crate::adapter_metrics_registry::AdapterMetricsRegistry;
use ic_adapter_metrics_client::AdapterMetrics;
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
#[derive(Debug, Clone)]
pub struct MetricsRegistry {
    registry: prometheus::Registry,
    /// A collection of adapters (remote processes) that expose
    /// a metrics endpoint to scrape prometheus metrics from.  
    adapter_metrics: AdapterMetricsRegistry,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    /// Get the registry that is global to this process.
    pub fn global() -> Self {
        let registry = prometheus::default_registry().clone();
        let adapter_metrics = AdapterMetricsRegistry::new(&registry);

        // Remove this when the `prometheus` crate exports the `process_threads` metric.
        #[cfg(target_os = "linux")]
        registry
            .register(Box::new(crate::process_collector::ProcessCollector::new()))
            // Don't `unwrap()`: this may be called repeatedly and we only want to register the
            // collector once.
            .ok();

        Self {
            registry,
            adapter_metrics,
        }
    }

    /// Create a new, empty registry.
    pub fn new() -> Self {
        let registry = prometheus::Registry::new();
        let adapter_metrics = AdapterMetricsRegistry::new(&registry);
        Self {
            registry,
            adapter_metrics,
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
    /// type. Any increase in the counter will trigger an alert and must always
    /// be paired with a error message (prefixed by the error name) to aid in
    /// debugging.
    ///
    /// Additionally, the playbook for `IC_Replica_CriticalError` must describe
    /// each error, possible root causes and mitigations.
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
    /// /// Critical error tracking if `foo_bar` ever goes over the limit.
    /// const CRITICAL_ERROR_FOO_BAR_ABOVE_LIMIT: &str = "foo_bar_above_limit";
    ///
    /// pub struct FooMetrics {
    ///     bar_above_limit: IntCounter,
    /// }
    ///
    /// impl FooMetrics {
    ///     pub fn new(metrics_registry: &MetricsRegistry) -> Self {
    ///         FooMetrics {
    ///             bar_above_limit: metrics_registry.error_counter(CRITICAL_ERROR_FOO_BAR_ABOVE_LIMIT),
    ///         }
    ///     }
    /// }
    ///
    /// fn set_bar(new_bar: u64, metrics: &FooMetrics, log: &ReplicaLogger) {
    ///     if new_bar > 13 {
    ///         error!(log, "{}: bar {} > 13", CRITICAL_ERROR_FOO_BAR_ABOVE_LIMIT, new_bar);
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

    pub fn adapter_registry(&self) -> &AdapterMetricsRegistry {
        &self.adapter_metrics
    }

    pub fn register<C: 'static + Collector + Clone>(&self, c: C) -> C {
        self.registry.register(Box::new(C::clone(&c))).unwrap();
        c
    }
    /// Since adapter are remote processes and are unaware of the replica metrics registry
    /// we need to make sure that the metrics exported by the adapter are unique. We do this
    /// by namespacing the adapter with a name.
    ///
    /// This function panics if you try to register an adapter with the same name as an
    /// already registered adapter.
    pub fn register_adapter(&self, adapter_metrics: AdapterMetrics) {
        self.adapter_metrics.register(adapter_metrics).unwrap()
    }
}
