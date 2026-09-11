//! Scraping of replica metrics, as the `Subnet merging` dashboard reads them.
//!
//! The dashboard evaluates its conditions on Prometheus queries over the
//! metrics of all replicas of a subnet; this module provides the same data to
//! the tool, by scraping the metrics endpoints of the nodes directly.

use futures::future::join_all;
use ic_recovery::util::block_on;
use slog::{Logger, warn};

use std::{collections::BTreeMap, net::IpAddr, time::Duration};

/// Timeout of a single metrics request, as in `ic_recovery::get_node_metrics`.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The metrics of a set of nodes, keyed by series (i.e. metric name plus
/// labels), with one value per node reporting the series.
pub type Metrics = BTreeMap<String, Vec<f64>>;

/// Fetches all series of the given metrics from the given nodes.
///
/// Best effort, exactly like the dashboard: a node that cannot be scraped
/// contributes no value, and a series that no node reports is absent (which
/// every helper below reads as zero). A condition that has to hold on every
/// node of every subnet therefore has to be written so that missing data keeps
/// it unsatisfied -- see `readiness::evaluate_merge_readiness`.
pub fn fetch_metrics(logger: &Logger, node_ips: &[IpAddr], metrics: &[&str]) -> Metrics {
    let responses = block_on(join_all(
        node_ips.iter().map(|ip| fetch_node_metrics(logger, ip)),
    ));

    let mut result = Metrics::new();
    for (ip, body) in node_ips.iter().zip(responses) {
        let Some(body) = body else {
            warn!(logger, "Failed to scrape the metrics of node {ip}");
            continue;
        };
        for (series, value) in parse_metrics(&body, metrics) {
            result.entry(series).or_default().push(value);
        }
    }
    result
}

async fn fetch_node_metrics(logger: &Logger, ip: &IpAddr) -> Option<String> {
    let response =
        tokio::time::timeout(REQUEST_TIMEOUT, reqwest::get(format!("http://[{ip}]:9090"))).await;
    match response {
        Ok(Ok(response)) => match response.text().await {
            Ok(body) => Some(body),
            Err(err) => {
                warn!(logger, "Failed to decode the metrics of node {ip}: {err}");
                None
            }
        },
        Ok(Err(err)) => {
            warn!(logger, "Failed to request the metrics of node {ip}: {err}");
            None
        }
        Err(_) => {
            warn!(logger, "Timed out requesting the metrics of node {ip}");
            None
        }
    }
}

/// Picks the series of the requested metrics out of a Prometheus text exposition.
fn parse_metrics(body: &str, metrics: &[&str]) -> Vec<(String, f64)> {
    body.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let (series, value) = line.rsplit_once(' ')?;
            let series = series.trim();
            if !metrics.iter().any(|metric| is_series_of(series, metric)) {
                return None;
            }
            let value = value.trim().parse::<f64>().ok()?;
            (!value.is_nan()).then(|| (series.to_string(), value))
        })
        .collect()
}

/// Whether `series` is a series of `metric`, i.e. the metric name followed by
/// its labels (if any). Metric names are prefixes of one another (e.g.
/// `..._messages` and `..._messages_total`), so a plain prefix check would mix
/// up their series.
fn is_series_of(series: &str, metric: &str) -> bool {
    match series.strip_prefix(metric) {
        Some(labels) => labels.is_empty() || labels.starts_with('{'),
        None => false,
    }
}

/// The per-node values of every series of `metric` whose labels (`{...}`, or
/// the empty string for an unlabeled series) match `labels_match`.
pub fn matching_series<'a>(
    metrics: &'a Metrics,
    metric: &str,
    labels_match: impl Fn(&str) -> bool,
) -> Vec<&'a Vec<f64>> {
    metrics
        .iter()
        .filter(|(series, _)| match series.strip_prefix(metric) {
            Some(labels) if labels.is_empty() || labels.starts_with('{') => labels_match(labels),
            _ => false,
        })
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

/// `sum(quantile by (<labels>) (0.5, <metric>{<filter>}))`: the median across
/// the replicas reporting each matching series, summed over those series.
pub fn sum_of_medians(metrics: &Metrics, metric: &str, labels_match: impl Fn(&str) -> bool) -> f64 {
    matching_series(metrics, metric, labels_match)
        .into_iter()
        .filter_map(|values| median(values))
        .sum()
}

/// `quantile(0.5, <metric>{<filter>})`: the median across all replicas
/// reporting any matching series. `None` if there is no such series.
pub fn median_across_replicas(
    metrics: &Metrics,
    metric: &str,
    labels_match: impl Fn(&str) -> bool,
) -> Option<f64> {
    let values: Vec<f64> = matching_series(metrics, metric, labels_match)
        .into_iter()
        .flatten()
        .copied()
        .collect();
    median(&values)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "\
# HELP mr_stream_messages Messages in streams.
# TYPE mr_stream_messages gauge
mr_stream_messages{remote=\"subnet_1\"} 3
mr_stream_messages{remote=\"subnet_2\"} 4
mr_stream_messages_total 7
replicated_state_pending_refunds 0
some_other_metric 12
";

    #[test]
    fn parse_metrics_test() {
        let parsed = parse_metrics(
            BODY,
            &["mr_stream_messages", "replicated_state_pending_refunds"],
        );

        assert_eq!(
            parsed,
            vec![
                ("mr_stream_messages{remote=\"subnet_1\"}".to_string(), 3.0),
                ("mr_stream_messages{remote=\"subnet_2\"}".to_string(), 4.0),
                ("replicated_state_pending_refunds".to_string(), 0.0),
            ],
            "the series of `mr_stream_messages_total`, which `mr_stream_messages` is a prefix \
             of, must not be picked up",
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
                "mr_stream_messages{remote=\"a\"}".to_string(),
                vec![1.0, 3.0],
            ),
            ("mr_stream_messages{remote=\"b\"}".to_string(), vec![5.0]),
            ("mr_stream_messages_total".to_string(), vec![100.0]),
        ]);

        assert_eq!(
            sum_of_medians(&metrics, "mr_stream_messages", |_| true),
            7.0
        );
        assert_eq!(
            sum_of_medians(&metrics, "mr_stream_messages", |labels| labels
                .contains("remote=\"b\"")),
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
    }
}
