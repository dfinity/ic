use ic_metrics::MetricsRegistry;
use prometheus::proto::MetricType;
use std::collections::BTreeMap;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct HistogramStats {
    pub count: u64,
    pub sum: f64,
}

/// Fetches the stats of a `Histogram`, given its name.
pub fn fetch_histogram_stats(registry: &MetricsRegistry, name: &str) -> Option<HistogramStats> {
    let mut stats_map = fetch_histogram_vec_stats(registry, name);
    let stats = stats_map.remove(&Labels::new());
    assert!(
        stats_map.is_empty(),
        "{}: expecting `Histogram`, found `HistogramVec` {:?}",
        name,
        stats_map
    );
    stats
}

#[test]
fn test_fetch_histogram_stats() {
    use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};

    let r = MetricsRegistry::new();
    let h = r.histogram(
        "p2p_message_size_bytes",
        "Message size in bytes.",
        decimal_buckets(0, 6),
    );

    h.observe(3.0);
    assert_eq!(
        fetch_histogram_stats(&r, "p2p_message_size_bytes"),
        Some(HistogramStats { count: 1, sum: 3.0 })
    )
}

/// Fetches the stats of all label value combinations of a `HistogramVec`, given
/// its name.
pub fn fetch_histogram_vec_stats(
    registry: &MetricsRegistry,
    name: &str,
) -> MetricVec<HistogramStats> {
    let mut stats = MetricVec::new();

    for metric_family in registry.prometheus_registry().gather() {
        if metric_family.get_name() == name {
            assert_eq!(MetricType::HISTOGRAM, metric_family.get_field_type());
            for metric in metric_family.get_metric() {
                stats.insert(
                    to_labels(metric),
                    HistogramStats {
                        count: metric.get_histogram().get_sample_count(),
                        sum: metric.get_histogram().get_sample_sum(),
                    },
                );
            }
            break;
        }
    }
    stats
}

#[test]
fn test_fetch_histogram_vec_stats() {
    use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};

    let r = MetricsRegistry::new();
    let h = r.histogram_vec(
        "p2p_message_size_bytes",
        "Message size in bytes.",
        decimal_buckets(0, 6),
        &["device"],
    );

    h.with_label_values(&["/dev/disk0"]).observe(1.0);
    h.with_label_values(&["/dev/eth0"]).observe(3.0);

    assert_eq!(
        metric_vec(&[
            (
                &[("device", "/dev/disk0")],
                HistogramStats { count: 1, sum: 1.0 }
            ),
            (
                &[("device", "/dev/eth0")],
                HistogramStats { count: 1, sum: 3.0 }
            ),
        ]),
        fetch_histogram_vec_stats(&r, "p2p_message_size_bytes"),
    );
}

/// Fetches the values of the `_count` field of all label value combinations of
/// a `HistogramVec`, given its name.
///
/// See [fetch_histogram_vec_stats()] for an example.
pub fn fetch_histogram_vec_count(registry: &MetricsRegistry, name: &str) -> MetricVec<u64> {
    fetch_histogram_vec_stats(registry, name)
        .into_iter()
        .map(|(k, v)| (k, v.count))
        .collect()
}

/// Fetches the value of an `IntCounter`, given its name.
pub fn fetch_int_counter(registry: &MetricsRegistry, name: &str) -> Option<u64> {
    fetch_counter(registry, name).map(|v| v as u64)
}

#[test]
fn test_fetch_int_counter() {
    use ic_metrics::MetricsRegistry;

    let r = MetricsRegistry::new();
    let c = r.int_counter("p2p_sent_bytes", "Num bytes sent");

    c.inc_by(3);
    assert_eq!(fetch_int_counter(&r, "p2p_sent_bytes"), Some(3))
}

/// Fetches the values of all label value combinations of an `IntCounterVec`,
/// given its name.
pub fn fetch_int_counter_vec(registry: &MetricsRegistry, name: &str) -> MetricVec<u64> {
    fetch_counter_vec(registry, name)
        .into_iter()
        .map(|(k, v)| (k, v as u64))
        .collect()
}

#[test]
fn test_fetch_int_counter_vec() {
    use ic_metrics::MetricsRegistry;

    let r = MetricsRegistry::new();
    let c = r.int_counter_vec("p2p_sent_bytes", "Num bytes sent", &["device"]);

    c.with_label_values(&["/dev/disk0"]).inc_by(1024);
    c.with_label_values(&["/dev/eth0"]).inc_by(2048);

    assert_eq!(
        metric_vec(&[
            (&[("device", "/dev/disk0")], 1024),
            (&[("device", "/dev/eth0")], 2048),
        ]),
        fetch_int_counter_vec(&r, "p2p_sent_bytes"),
    );
}

/// Fetches the value of a `Counter`, given its name.
///
/// See [fetch_int_counter()] for an example.
pub fn fetch_counter(registry: &MetricsRegistry, name: &str) -> Option<f64> {
    let mut value_map = fetch_counter_vec(registry, name);
    let value = value_map.remove(&Labels::new());
    assert!(
        value_map.is_empty(),
        "{}: expecting `Counter`, found `CounterVec` {:?}",
        name,
        value_map
    );
    value
}

/// Fetches the values of all label value combinations of a `CounterVec`, given
/// its name.
///
/// See [fetch_int_counter_vec()] for an example.
pub fn fetch_counter_vec(registry: &MetricsRegistry, name: &str) -> MetricVec<f64> {
    let mut values = MetricVec::new();

    for metric_family in registry.prometheus_registry().gather() {
        if metric_family.get_name() == name {
            assert_eq!(MetricType::COUNTER, metric_family.get_field_type());
            for metric in metric_family.get_metric() {
                values.insert(to_labels(metric), metric.get_counter().get_value());
            }
            break;
        }
    }
    values
}

/// Fetches the value of an `IntGauge`, given its name.
pub fn fetch_int_gauge(registry: &MetricsRegistry, name: &str) -> Option<u64> {
    fetch_gauge(registry, name).map(|v| v as u64)
}

#[test]
fn test_fetch_int_gauge() {
    use ic_metrics::MetricsRegistry;

    let r = MetricsRegistry::new();
    let g = r.int_gauge("p2p_queue_size", "The advert queue length at last epoch");

    g.set(5);
    assert_eq!(fetch_int_gauge(&r, "p2p_queue_size"), Some(5))
}

/// Fetches the value of all label value combinations of an `IntGaugeVec`, given
/// its name.
pub fn fetch_int_gauge_vec(registry: &MetricsRegistry, name: &str) -> MetricVec<u64> {
    fetch_gauge_vec(registry, name)
        .into_iter()
        .map(|(k, v)| (k, v as u64))
        .collect()
}

#[test]
fn test_fetch_int_gauge_vec() {
    use ic_metrics::MetricsRegistry;

    let r = MetricsRegistry::new();
    let g = r.int_gauge_vec("p2p_queue_size", "Size of the p2p queues", &["queuetype"]);

    g.with_label_values(&["advert"]).set(1024);
    g.with_label_values(&["request"]).set(2048);

    assert_eq!(
        metric_vec(&[
            (&[("queuetype", "advert")], 1024),
            (&[("queuetype", "request")], 2048),
        ]),
        fetch_int_gauge_vec(&r, "p2p_queue_size"),
    );
}

/// Fetches the value of a `Gauge`, given its name.
///
/// See [fetch_int_gauge()] for an example.
pub fn fetch_gauge(registry: &MetricsRegistry, name: &str) -> Option<f64> {
    let mut value_map = fetch_gauge_vec(registry, name);
    let value = value_map.remove(&Labels::new());
    assert!(
        value_map.is_empty(),
        "{}: expecting `Gauge`, found `GaugeVec` {:?}",
        name,
        value_map
    );
    value
}

/// Fetches the values of all label value combinations of a `GaugeVec`, given
/// its name.
///
/// See [fetch_int_gauge_vec()] for an example.
pub fn fetch_gauge_vec(registry: &MetricsRegistry, name: &str) -> MetricVec<f64> {
    let mut values = MetricVec::new();

    for metric_family in registry.prometheus_registry().gather() {
        if metric_family.get_name() == name {
            assert_eq!(MetricType::GAUGE, metric_family.get_field_type());
            for metric in metric_family.get_metric() {
                values.insert(to_labels(metric), metric.get_gauge().get_value());
            }
            break;
        }
    }
    values
}

/// Sorted map of label-value pairs, for easy equality tests.
pub type Labels = BTreeMap<String, String>;

/// Map of `Labels` to value, for easy equality tests.
pub type MetricVec<V> = BTreeMap<Labels, V>;

/// Constructs a `MetricVec` out of a slice of labels-value tuples, to compare
/// with the output of `fetch_*_vec()` functions.
pub fn metric_vec<T1: ToString, T2: ToString, V: Copy>(
    metrics: &[(&[(T1, T2)], V)],
) -> MetricVec<V> {
    let mut mv = MetricVec::new();
    for metric in metrics {
        if mv.insert(labels(metric.0), metric.1).is_some() {
            panic!("Duplicate label value combination: {:?}", labels(metric.0));
        }
    }
    mv
}

/// Filters the given `MetricVec`, retaining only metrics with non-zero values.
pub fn nonzero_values<V: From<u8> + PartialEq<V> + Copy>(metrics: MetricVec<V>) -> MetricVec<V> {
    metrics
        .into_iter()
        .filter(|(_, value)| value != &V::from(0))
        .collect()
}

/// Constructs a `Labels` out of a slice of label-value tuples.
pub fn labels<T1: ToString, T2: ToString>(label_pairs: &[(T1, T2)]) -> Labels {
    let mut labels = Labels::new();
    for label_pair in label_pairs {
        if labels
            .insert(label_pair.0.to_string(), label_pair.1.to_string())
            .is_some()
        {
            panic!("Duplicate label: {}", label_pair.0.to_string(),);
        }
    }
    labels
}

/// Extracts the labels of a `prometheus::proto::Metric` into a sorted map, for
/// easy equality tests.
fn to_labels(metric: &prometheus::proto::Metric) -> Labels {
    metric
        .get_label()
        .iter()
        .map(|label_pair| {
            (
                label_pair.get_name().to_string(),
                label_pair.get_value().to_string(),
            )
        })
        .collect()
}
