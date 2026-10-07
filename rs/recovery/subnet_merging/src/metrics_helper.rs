//! Scraping of replica metrics, and the Prometheus aggregations the "merge
//! readiness" condition is stated in.
//!
//! The condition is stated as Prometheus queries over the metrics of all
//! replicas of a subnet; this module provides the same data by scraping the
//! metrics endpoints of the nodes directly.

use futures::future::join_all;
use prometheus_parse::{Scrape, Value};

use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

/// Timeout of a single metrics request, as in `ic_recovery::get_node_metrics`.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The labels of a series, by label name.
pub type Labels = BTreeMap<String, String>;

/// The metrics of a set of nodes, keyed by series (i.e. metric name plus
/// labels), with one value per node reporting the series.
pub type Metrics = BTreeMap<(String, Labels), Vec<f64>>;

/// The nodes whose metrics could not be scraped, with the reason for each.
#[derive(Debug)]
pub struct ScrapeError {
    pub failures: Vec<(IpAddr, String)>,
}

impl fmt::Display for ScrapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to scrape the metrics of {} node(s): ",
            self.failures.len()
        )?;
        for (i, (ip, reason)) in self.failures.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            write!(f, "{ip}: {reason}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ScrapeError {}

/// Fetches all series of the given metrics from the given nodes.
///
/// Fails if any node cannot be scraped, unlike Prometheus, which would simply
/// have no value for that node: a condition evaluated on the median across
/// nodes could otherwise hold on partial data. A series that no node reports
/// is absent though (which `sum_of_medians` reads as zero, and
/// `median_across_replicas` as `None`), as a node that responds simply does not
/// export that series.
pub async fn fetch_metrics(node_ips: &[IpAddr], metrics: &[&str]) -> Result<Metrics, ScrapeError> {
    let responses = join_all(node_ips.iter().map(fetch_node_metrics)).await;

    let mut result = Metrics::new();
    let mut failures = Vec::new();
    for (ip, body) in node_ips.iter().zip(responses) {
        match body {
            Ok(body) => {
                for (series, value) in parse_metrics(&body, metrics) {
                    result.entry(series).or_default().push(value);
                }
            }
            Err(reason) => failures.push((*ip, reason)),
        }
    }
    if !failures.is_empty() {
        return Err(ScrapeError { failures });
    }
    Ok(result)
}

async fn fetch_node_metrics(ip: &IpAddr) -> Result<String, String> {
    // The timeout covers reading the body too: `reqwest::get` completes as soon
    // as the response headers arrive, and a node stalling after that would
    // otherwise keep `fetch_metrics` from ever returning.
    let response = tokio::time::timeout(REQUEST_TIMEOUT, async {
        reqwest::get(format!("http://{}", SocketAddr::new(*ip, 9090)))
            .await?
            .error_for_status()?
            .text()
            .await
    })
    .await;
    match response {
        Ok(Ok(body)) => Ok(body),
        Ok(Err(err)) => Err(format!("request failed: {err}")),
        Err(_) => Err(format!("request timed out after {REQUEST_TIMEOUT:?}")),
    }
}

/// Picks the series of the requested metrics out of a Prometheus text
/// exposition. Histograms and summaries are skipped, as are NaN values.
fn parse_metrics(body: &str, metrics: &[&str]) -> Vec<((String, Labels), f64)> {
    // `Scrape::parse` only fails if reading a line fails, which it cannot here.
    let scrape = Scrape::parse(body.lines().map(|line| Ok(line.to_string())))
        .expect("parsing a string should not fail");
    scrape
        .samples
        .into_iter()
        .filter(|sample| metrics.contains(&sample.metric.as_str()))
        .filter_map(|sample| {
            let value = match sample.value {
                Value::Counter(value) | Value::Gauge(value) | Value::Untyped(value) => value,
                Value::Histogram(_) | Value::Summary(_) => return None,
            };
            let labels = sample
                .labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            (!value.is_nan()).then_some(((sample.metric, labels), value))
        })
        .collect()
}

/// The per-node values of every series of `metric` whose labels match
/// `labels_match`.
pub fn matching_series<'a>(
    metrics: &'a Metrics,
    metric: &str,
    labels_match: impl Fn(&Labels) -> bool,
) -> Vec<&'a Vec<f64>> {
    metrics
        .iter()
        .filter(|((name, labels), _)| name == metric && labels_match(labels))
        .map(|(_, values)| values)
        .collect()
}

/// Prometheus' `quantile(0.5, ...)`: the median of `values`, interpolating
/// between the two middle values if there is an even number of them. `None` iff
/// `values` is empty.
pub fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut values = values.to_vec();
    values.sort_by(|a, b| a.partial_cmp(b).expect("metric value should not be NaN"));
    let middle = (values.len() - 1) as f64 / 2.0;
    Some((values[middle.floor() as usize] + values[middle.ceil() as usize]) / 2.0)
}

/// `sum(quantile without(ic_node, instance) (0.5, <metric>{<labels_match>}))`:
/// the median across the replicas reporting each matching series, summed over
/// those series.
pub fn sum_of_medians(
    metrics: &Metrics,
    metric: &str,
    labels_match: impl Fn(&Labels) -> bool,
) -> f64 {
    matching_series(metrics, metric, labels_match)
        .into_iter()
        .filter_map(|values| median(values))
        .sum()
}

/// `quantile(0.5, <metric>{<labels_match>})`: the median across all replicas
/// reporting any matching series. `None` if there is no such series.
///
/// This pools the values of all matching series (e.g. across all `remote` or
/// `state` label values), so it is only meaningful for unlabeled metrics or if
/// `labels_match` selects a single label combination.
pub fn median_across_replicas(
    metrics: &Metrics,
    metric: &str,
    labels_match: impl Fn(&Labels) -> bool,
) -> Option<f64> {
    let values: Vec<f64> = matching_series(metrics, metric, labels_match)
        .into_iter()
        .flatten()
        .copied()
        .collect();
    median(&values)
}

/// `min(<metric>{<labels_match>})` over all `replicas` replicas: the smallest
/// value any of them reports for any matching series. `None` if fewer than
/// `replicas` values are reported, i.e. if a replica does not export the
/// series: unlike the medians above, which describe the replicas that do
/// report a series, a minimum that has to hold on every replica is only
/// meaningful once every one of them reports.
pub fn min_across_replicas(
    metrics: &Metrics,
    metric: &str,
    labels_match: impl Fn(&Labels) -> bool,
    replicas: usize,
) -> Option<f64> {
    let values: Vec<f64> = matching_series(metrics, metric, labels_match)
        .into_iter()
        .flatten()
        .copied()
        .collect();
    (values.len() >= replicas)
        .then(|| values.into_iter().reduce(f64::min))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series(metric: &str, labels: &[(&str, &str)]) -> (String, Labels) {
        let labels = labels
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        (metric.to_string(), labels)
    }

    const BODY: &str = "\
# HELP mr_stream_messages Messages in streams.
# TYPE mr_stream_messages gauge
mr_stream_messages{remote=\"subnet_1\"} 3
mr_stream_messages{remote=\"subnet_2\"} 4 1700000000000
mr_stream_messages{remote=\"subnet 3\"} 5
mr_stream_messages_total 7
# TYPE some_histogram histogram
some_histogram_bucket{le=\"1\"} 1
some_histogram_bucket{le=\"+Inf\"} 2
some_histogram_sum 1.5
some_histogram_count 2
replicated_state_pending_refunds 0 1700000000000
some_other_metric 12
";

    #[test]
    fn parse_metrics_test() {
        let parsed = parse_metrics(
            BODY,
            &[
                "mr_stream_messages",
                "replicated_state_pending_refunds",
                "some_histogram",
            ],
        );

        assert_eq!(
            parsed,
            vec![
                (series("mr_stream_messages", &[("remote", "subnet_1")]), 3.0),
                (series("mr_stream_messages", &[("remote", "subnet_2")]), 4.0),
                (series("mr_stream_messages", &[("remote", "subnet 3")]), 5.0),
                (series("replicated_state_pending_refunds", &[]), 0.0),
            ],
            "the series of `mr_stream_messages_total`, which `mr_stream_messages` is a prefix \
             of, must not be picked up; a trailing timestamp must not be read as the value; a \
             label value may contain a space; and histograms must be skipped",
        );
    }

    #[test]
    fn median_test() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[3.0]), Some(3.0));
        assert_eq!(median(&[3.0, 1.0]), Some(2.0));
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), Some(2.5));
    }

    #[test]
    fn medians_across_series_test() {
        let metrics = Metrics::from([
            (
                series("mr_stream_messages", &[("remote", "a")]),
                vec![1.0, 3.0],
            ),
            (series("mr_stream_messages", &[("remote", "b")]), vec![5.0]),
            (series("mr_stream_messages_total", &[]), vec![100.0]),
        ]);

        assert_eq!(
            sum_of_medians(&metrics, "mr_stream_messages", |_| true),
            7.0
        );
        assert_eq!(
            sum_of_medians(&metrics, "mr_stream_messages", |labels| labels
                .get("remote")
                .is_some_and(|remote| remote == "b")),
            5.0
        );
        assert_eq!(
            median_across_replicas(&metrics, "mr_stream_messages", |_| true),
            Some(3.0)
        );
        assert_eq!(
            median_across_replicas(&metrics, "mr_registry_version", |_| true),
            None
        );
        assert_eq!(
            min_across_replicas(&metrics, "mr_stream_messages", |_| true, 3),
            Some(1.0)
        );
        assert_eq!(
            min_across_replicas(&metrics, "mr_stream_messages", |_| true, 4),
            None,
            "a replica that does not report the series must not be skipped"
        );
        assert_eq!(
            min_across_replicas(&metrics, "mr_registry_version", |_| true, 0),
            None
        );
    }
}
