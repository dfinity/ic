use crate::adapter_metrics_registry::AdapterMetricsRegistry;
use ic_adapter_metrics_client::AdapterMetrics;
use prometheus::{
    CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, IntGaugeVec, Opts,
    core::{Collector, Desc},
    proto::MetricFamily,
};
use std::collections::HashMap;

/// A wrapper around `prometheus::Registry` with helpers for creating metrics
///
/// We do not use the static metrics of Prometheus to allow simpler testing of
/// the metrics. Besides that, passing the registry around explicitly is useful
/// for detecting the situation when two different versions of Prometheus are
/// are used in different packages.
#[derive(Clone, Debug)]
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

    /// Create and register a `CounterVec`.
    pub fn counter_vec<S: Into<String>>(
        &self,
        name: S,
        help: S,
        label_names: &[&str],
    ) -> CounterVec {
        self.register(CounterVec::new(Opts::new(name, help), label_names).unwrap())
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

    /// Exports an already-registered `collector`'s metrics under an additional
    /// `name`, without duplicating the underlying metric. Both the original and
    /// the aliased name are collected from the same `collector`, so they always
    /// report identical values (and share the same help string and type).
    ///
    /// This is intended for renaming a metric: register the collector normally
    /// (exposing the old name), then call `register_alias` to also expose the
    /// new name. Once the new name has been rolled out everywhere, drop the
    /// original registration and register directly under the new name.
    ///
    /// Only supports collectors that expose exactly one metric (e.g. `Gauge`,
    /// `GaugeVec`, `CounterVec`); panics otherwise.
    pub fn register_alias<C: 'static + Collector + Clone>(&self, collector: &C, name: &str) {
        self.registry
            .register(Box::new(AliasCollector::new(collector.clone(), name)))
            .unwrap();
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

/// A `Collector` that re-exports the metrics of an inner collector under a
/// different name, sharing the inner collector's underlying data. See
/// [`MetricsRegistry::register_alias`].
#[derive(Clone)]
struct AliasCollector<C: Collector> {
    inner: C,
    /// The name under which the inner collector's metrics are re-exported.
    name: String,
    /// Descriptor advertising the aliased `name` (with the inner metric's help
    /// and labels), used by the registry for collision detection at
    /// registration time.
    desc: Desc,
}

impl<C: Collector> AliasCollector<C> {
    fn new(inner: C, name: &str) -> Self {
        let inner_descs = inner.desc();
        assert_eq!(
            inner_descs.len(),
            1,
            "register_alias only supports collectors with exactly one metric, \
             but the collector for `{}` exposes {}",
            name,
            inner_descs.len(),
        );
        let inner_desc = inner_descs[0];
        let const_labels: HashMap<String, String> = inner_desc
            .const_label_pairs
            .iter()
            .map(|pair| (pair.name().to_string(), pair.value().to_string()))
            .collect();
        let desc = Desc::new(
            name.to_string(),
            inner_desc.help.clone(),
            inner_desc.variable_labels.clone(),
            const_labels,
        )
        .unwrap();
        Self {
            inner,
            name: name.to_string(),
            desc,
        }
    }
}

impl<C: Collector> Collector for AliasCollector<C> {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let mut families = self.inner.collect();
        for family in &mut families {
            family.set_name(self.name.clone());
        }
        families
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_alias_exports_same_metric_under_both_names() {
        let registry = MetricsRegistry::new();
        let gauge = registry.gauge("original_name", "The help string.");
        registry.register_alias(&gauge, "aliased_name");

        gauge.set(42.0);

        let families = registry.prometheus_registry().gather();
        let by_name: HashMap<_, _> = families
            .iter()
            .map(|mf| (mf.name().to_string(), mf))
            .collect();

        for name in ["original_name", "aliased_name"] {
            let mf = by_name
                .get(name)
                .unwrap_or_else(|| panic!("missing metric family `{}`", name));
            // Same help string and value are exported under both names.
            assert_eq!(mf.help(), "The help string.");
            assert_eq!(mf.get_metric().len(), 1);
            assert_eq!(mf.get_metric()[0].get_gauge().value(), 42.0);
        }
    }

    #[test]
    fn register_alias_preserves_labels_of_vec_metric() {
        let registry = MetricsRegistry::new();
        let gauge_vec = registry.gauge_vec("original_vec", "The help string.", &["use_case"]);
        registry.register_alias(&gauge_vec, "aliased_vec");

        gauge_vec.with_label_values(&["foo"]).set(7.0);

        let families = registry.prometheus_registry().gather();
        for name in ["original_vec", "aliased_vec"] {
            let mf = families
                .iter()
                .find(|mf| mf.name() == name)
                .unwrap_or_else(|| panic!("missing metric family `{}`", name));
            assert_eq!(mf.get_metric().len(), 1);
            let metric = &mf.get_metric()[0];
            assert_eq!(metric.get_label().len(), 1);
            assert_eq!(metric.get_label()[0].name(), "use_case");
            assert_eq!(metric.get_label()[0].value(), "foo");
            assert_eq!(metric.get_gauge().value(), 7.0);
        }
    }
}
