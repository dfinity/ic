//! Scraping of replica metrics, and the aggregations across the replicas of a
//! subnet that the "merge readiness" condition is evaluated on.

use futures::{StreamExt, stream};
use prometheus_parse::{Scrape, Value};

use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

/// Timeout of a single metrics request, as in `ic_recovery::get_node_metrics`.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The maximum number of nodes scraped at the same time. On mainnet, a
/// readiness round scrapes every replica of every subnet, i.e. several hundred.
const MAX_CONCURRENT_SCRAPES: usize = 64;

/// The port a replica exports its metrics on.
const METRICS_PORT: u16 = 9090;

/// The labels of a series, by label name.
pub type Labels = BTreeMap<String, String>;

/// The metrics of a single node, keyed by series (i.e. metric name plus
/// labels).
pub type ReplicaMetrics = BTreeMap<(String, Labels), f64>;

/// The metrics of a set of nodes, keyed by the IP of each node.
pub type MetricsByReplica = BTreeMap<IpAddr, ReplicaMetrics>;

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

/// Fetches all series of the given metrics from those of the given nodes that
/// can be scraped. Returns the metrics of exactly those nodes, along with the
/// nodes that could not be scraped, if any.
pub async fn fetch_available_metrics(
    node_ips: &[IpAddr],
    metrics: &[&str],
) -> (MetricsByReplica, Option<ScrapeError>) {
    fetch_available_metrics_by_group([((), node_ips, metrics)])
        .await
        .remove(&())
        .unwrap_or_default()
}

/// Like `fetch_available_metrics`, for several groups of nodes (e.g. subnets),
/// each with the metrics to fetch from its nodes. The nodes of all groups are
/// scraped concurrently, at most `MAX_CONCURRENT_SCRAPES` at a time. Returns
/// the result of every group, by key.
pub async fn fetch_available_metrics_by_group<'a, K: Copy + Ord>(
    groups: impl IntoIterator<Item = (K, &'a [IpAddr], &'a [&'a str])>,
) -> BTreeMap<K, (MetricsByReplica, Option<ScrapeError>)> {
    let mut results: BTreeMap<K, (MetricsByReplica, Vec<(IpAddr, String)>)> = BTreeMap::new();
    let mut scrapes = Vec::new();
    for (key, node_ips, metrics) in groups {
        results.entry(key).or_default();
        scrapes.extend(node_ips.iter().map(move |ip| (key, *ip, metrics)));
    }

    let responses: Vec<_> = stream::iter(scrapes)
        .map(|(key, ip, metrics)| async move {
            let response = fetch_node_metrics(&ip)
                .await
                .map(|body| parse_metrics(&body, metrics).into_iter().collect());
            (key, ip, response)
        })
        .buffer_unordered(MAX_CONCURRENT_SCRAPES)
        .collect()
        .await;

    for (key, ip, response) in responses {
        let (metrics, failures) = results.get_mut(&key).expect("every key was inserted");
        match response {
            Ok(replica_metrics) => {
                metrics.insert(ip, replica_metrics);
            }
            Err(reason) => failures.push((ip, reason)),
        }
    }
    results
        .into_iter()
        .map(|(key, (metrics, mut failures))| {
            failures.sort();
            let failures = (!failures.is_empty()).then_some(ScrapeError { failures });
            (key, (metrics, failures))
        })
        .collect()
}

async fn fetch_node_metrics(ip: &IpAddr) -> Result<String, String> {
    let response = tokio::time::timeout(REQUEST_TIMEOUT, async {
        reqwest::get(format!("http://{}", SocketAddr::new(*ip, METRICS_PORT)))
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

/// The values a node reports for the series of `metric` whose labels match
/// `labels_match`, given the metrics of that node.
pub fn replica_values(
    metrics: &ReplicaMetrics,
    metric: &str,
    labels_match: impl Fn(&Labels) -> bool,
) -> impl Iterator<Item = f64> {
    metrics
        .iter()
        .filter(move |((name, labels), _)| name == metric && labels_match(labels))
        .map(|(_, value)| *value)
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
    fn replica_values_test() {
        let metrics = ReplicaMetrics::from([
            (series("mr_stream_messages", &[("remote", "a")]), 1.0),
            (series("mr_stream_messages", &[("remote", "b")]), 5.0),
            (series("mr_stream_messages_total", &[]), 100.0),
        ]);
        let values = |metric, labels_match: fn(&Labels) -> bool| {
            replica_values(&metrics, metric, labels_match).collect::<Vec<_>>()
        };

        assert_eq!(values("mr_stream_messages", |_| true), vec![1.0, 5.0]);
        assert_eq!(
            values("mr_stream_messages", |labels| labels
                .get("remote")
                .is_some_and(|remote| remote == "b")),
            vec![5.0]
        );
        // No matching series.
        assert_eq!(values("mr_registry_version", |_| true), Vec::<f64>::new());
    }
}
