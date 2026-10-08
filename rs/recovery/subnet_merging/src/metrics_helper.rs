//! Scraping of replica metrics, and the aggregations across the replicas of a
//! subnet that the "merge readiness" condition is evaluated on.

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
/// labels), with values keyed by the IP of each node reporting the series.
pub type Metrics = BTreeMap<(String, Labels), BTreeMap<IpAddr, f64>>;

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
/// Fails if any node cannot be scraped: a condition evaluated across the nodes
/// could otherwise hold on partial data. A series that no node reports is
/// absent though, as a node that responds simply does not export that series.
pub async fn fetch_metrics(node_ips: &[IpAddr], metrics: &[&str]) -> Result<Metrics, ScrapeError> {
    let responses = join_all(node_ips.iter().map(fetch_node_metrics)).await;

    let mut result = Metrics::new();
    let mut failures = Vec::new();
    for (ip, body) in node_ips.iter().zip(responses) {
        match body {
            Ok(body) => {
                for (series, value) in parse_metrics(&body, metrics) {
                    result.entry(series).or_default().insert(*ip, value);
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
) -> Vec<&'a BTreeMap<IpAddr, f64>> {
    metrics
        .iter()
        .filter(|((name, labels), _)| name == metric && labels_match(labels))
        .map(|(_, values)| values)
        .collect()
}

/// The largest value any replica reports for any series of `metric` whose
/// labels match `labels_match`. A series that a replica does not report reads
/// as zero, so this is zero if there is no such series.
pub fn max_across_replicas(
    metrics: &Metrics,
    metric: &str,
    labels_match: impl Fn(&Labels) -> bool,
) -> f64 {
    matching_series(metrics, metric, labels_match)
        .into_iter()
        .flat_map(|values| values.values())
        .copied()
        .fold(0.0, f64::max)
}

/// The smallest value any of the given replicas reports for any series of
/// `metric` whose labels match `labels_match`. A replica that reports no such
/// series reads as zero, and so does an empty `replicas`: multiple series
/// reported by one node cannot stand in for another node.
pub fn min_across_replicas(
    metrics: &Metrics,
    metric: &str,
    labels_match: impl Fn(&Labels) -> bool,
    replicas: &[IpAddr],
) -> f64 {
    let series = matching_series(metrics, metric, labels_match);
    replicas
        .iter()
        .map(|ip| {
            series
                .iter()
                .filter_map(|values| values.get(ip))
                .copied()
                .reduce(f64::min)
                .unwrap_or(0.0)
        })
        .reduce(f64::min)
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(node: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, node])
    }

    fn values(entries: &[(u8, f64)]) -> BTreeMap<IpAddr, f64> {
        entries
            .iter()
            .map(|&(node, value)| (ip(node), value))
            .collect()
    }

    #[test]
    fn minimum_requires_each_replica_to_report() {
        let metrics = Metrics::from([
            (series("m", &[("kind", "a")]), values(&[(1, 5.0)])),
            (series("m", &[("kind", "b")]), values(&[(1, 6.0)])),
        ]);
        assert_eq!(
            min_across_replicas(&metrics, "m", |_| true, &[ip(1), ip(2)]),
            0.0
        );
        assert_eq!(min_across_replicas(&metrics, "m", |_| true, &[ip(1)]), 5.0);
        assert_eq!(min_across_replicas(&metrics, "m", |_| true, &[]), 0.0);
    }

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
    fn across_replicas_test() {
        let metrics = Metrics::from([
            (
                series("mr_stream_messages", &[("remote", "a")]),
                values(&[(1, 1.0), (2, 3.0)]),
            ),
            (
                series("mr_stream_messages", &[("remote", "b")]),
                values(&[(1, 5.0)]),
            ),
            (
                series("mr_stream_messages_total", &[]),
                values(&[(1, 100.0)]),
            ),
        ]);

        assert_eq!(
            max_across_replicas(&metrics, "mr_stream_messages", |_| true),
            5.0
        );
        assert_eq!(
            max_across_replicas(&metrics, "mr_stream_messages", |labels| labels
                .get("remote")
                .is_some_and(|remote| remote == "a")),
            3.0
        );
        assert_eq!(
            max_across_replicas(&metrics, "mr_registry_version", |_| true),
            0.0
        );
        assert_eq!(
            min_across_replicas(&metrics, "mr_registry_version", |_| true, &[]),
            0.0
        );
    }
}
