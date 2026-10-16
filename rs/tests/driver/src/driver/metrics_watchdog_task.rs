//! Checks that the replica and orchestrator metrics configured on a `SystemTestGroup` (see
//! `SystemTestGroup::remove_metrics_to_check`) never exceed their maximum allowed values.
//!
//! The replica and orchestrator keep their metrics in memory, so the values are lost whenever the
//! process restarts, e.g. during subnet or NNS recoveries, upgrades, or when a node joins or
//! leaves a subnet. Checking the metrics only once at the end of a test therefore misses any
//! violation that happened before the last restart. To catch those, the `metrics_watchdog` task
//! periodically scrapes all nodes during the whole test and records the peak value of every checked
//! metric per process lifetime, identified by the `process_start_time_seconds` of the process. The
//! `assert_no_metrics_errors` teardown then scrapes all nodes one last time and fails if any
//! recorded peak exceeds its maximum allowed value.
//!
//! The checked metrics are counters, which only grow during the lifetime of a process. So checking
//! their peak per lifetime is equivalent to checking every lifetime at its end, as was previously
//! done only for the last one. A violation is still missed if it happens less than one scrape
//! interval before a restart. Calling `assert_no_critical_errors` right before a restart triggered
//! by the test closes that window.

use crate::driver::{
    constants::GROUP_SETUP_DIR,
    context::GroupContext,
    test_env::{HasIcPrepDir, TestEnv, TestEnvAttribute},
    test_env_api::{
        HasTopologySnapshot, IcNodeContainer, ORCHESTRATOR_METRICS_PORT, REPLICA_METRICS_PORT,
        TopologySnapshot, sync_local_registry_with_nns,
    },
};
use crate::util::block_on;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use slog::{Logger, debug, info, warn};
use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

pub(crate) const METRICS_WATCHDOG_TASK_NAME: &str = "metrics_watchdog";

/// How often the watchdog scrapes all nodes. Same as the scrape interval of the `PrometheusVm`.
const SCRAPE_INTERVAL: Duration = Duration::from_secs(10);
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often scrapes outside of the watchdog are attempted, to tolerate endpoints that are briefly
/// unavailable, e.g. right after a restart.
const SCRAPE_ATTEMPTS: usize = 3;
const SCRAPE_BACKOFF: Duration = Duration::from_secs(5);

const PROCESS_START_TIME_METRIC: &str = "process_start_time_seconds";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum MetricsEndpoint {
    Replica,
    Orchestrator,
}

impl MetricsEndpoint {
    fn port(self) -> u16 {
        match self {
            Self::Replica => REPLICA_METRICS_PORT,
            Self::Orchestrator => ORCHESTRATOR_METRICS_PORT,
        }
    }
}

impl fmt::Display for MetricsEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replica => write!(f, "replica"),
            Self::Orchestrator => write!(f, "orchestrator"),
        }
    }
}

/// The metrics to check on each endpoint, mapped to their maximum allowed value. A metric name
/// also matches all metrics it is a prefix of, so the names of an endpoint must be prefix-free.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct MetricsToCheck {
    pub(crate) replica: BTreeMap<String, u64>,
    pub(crate) orchestrator: BTreeMap<String, u64>,
}

impl TestEnvAttribute for MetricsToCheck {
    fn attribute_name() -> String {
        String::from("metrics_to_check")
    }
}

impl MetricsToCheck {
    pub(crate) fn is_empty(&self) -> bool {
        self.replica.is_empty() && self.orchestrator.is_empty()
    }

    fn of(&self, endpoint: MetricsEndpoint) -> &BTreeMap<String, u64> {
        match endpoint {
            MetricsEndpoint::Replica => &self.replica,
            MetricsEndpoint::Orchestrator => &self.orchestrator,
        }
    }

    /// Returns the checked metric name that `series` matches, along with its maximum allowed value.
    fn max_value(&self, endpoint: MetricsEndpoint, series: &str) -> Option<(&str, u64)> {
        self.of(endpoint)
            .iter()
            .find(|(name, _)| series.starts_with(name.as_str()))
            .map(|(name, max_value)| (name.as_str(), *max_value))
    }

    fn assert_prefix_free(&self) {
        for endpoint in [MetricsEndpoint::Replica, MetricsEndpoint::Orchestrator] {
            let names = self.of(endpoint);
            for name in names.keys() {
                for other in names.keys() {
                    assert!(
                        name == other || !name.starts_with(other.as_str()),
                        "The {endpoint} metrics to check `{other}` and `{name}` are not \
                        prefix-free. This is not allowed. Please specify a prefix-free set of \
                        metrics to check."
                    );
                }
            }
        }
    }
}

/// A metrics endpoint of a node.
#[derive(Clone, Debug)]
struct Target {
    node_id: String,
    ip_addr: IpAddr,
    endpoint: MetricsEndpoint,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the {} on node {}", self.endpoint, self.node_id)
    }
}

/// Returns the endpoints to scrape: the replica and the orchestrator of nodes assigned to a subnet,
/// and only the orchestrator of unassigned and API boundary nodes, which don't run a replica.
fn targets(topology: &TopologySnapshot, metrics: &MetricsToCheck) -> Vec<Target> {
    let assigned_nodes = topology.subnets().flat_map(|subnet| subnet.nodes());
    let other_nodes = topology
        .unassigned_nodes()
        .chain(topology.api_boundary_nodes());
    let mut targets = Vec::new();
    for (node, endpoints) in assigned_nodes
        .map(|node| {
            (
                node,
                &[MetricsEndpoint::Replica, MetricsEndpoint::Orchestrator][..],
            )
        })
        .chain(other_nodes.map(|node| (node, &[MetricsEndpoint::Orchestrator][..])))
    {
        let ip_addr = node.get_ip_addr();
        for &endpoint in endpoints {
            if !metrics.of(endpoint).is_empty() {
                targets.push(Target {
                    node_id: node.node_id.to_string(),
                    ip_addr,
                    endpoint,
                });
            }
        }
    }
    targets
}

/// The values of the checked metrics in one scrape of an endpoint.
struct Scrape {
    at: DateTime<Utc>,
    start_time_secs: Option<f64>,
    values: BTreeMap<String, f64>,
}

fn metrics_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(SCRAPE_TIMEOUT)
        .build()
        .expect("Failed to build HTTP client for metrics scraping")
}

async fn scrape(
    client: &reqwest::Client,
    target: &Target,
    metrics: &MetricsToCheck,
) -> Result<Scrape> {
    let url = format!(
        "http://{}",
        SocketAddr::new(target.ip_addr, target.endpoint.port())
    );
    let body = client
        .get(&url)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .with_context(|| format!("Failed to scrape {url}"))?
        .text()
        .await
        .with_context(|| format!("Failed to read the metrics from {url}"))?;
    let mut scrape = Scrape {
        at: Utc::now(),
        start_time_secs: None,
        values: BTreeMap::new(),
    };
    for (series, value) in body.lines().filter_map(parse_sample) {
        if series == PROCESS_START_TIME_METRIC {
            scrape.start_time_secs = Some(value);
        } else if metrics.max_value(target.endpoint, series).is_some() {
            scrape.values.insert(series.to_string(), value);
        }
    }
    Ok(scrape)
}

/// Parses a line `<name>[{<labels>}] <value> [<timestamp>]` of the Prometheus text format into the
/// series (name and labels) and the value. Returns `None` for comments and malformed lines.
fn parse_sample(line: &str) -> Option<(&str, f64)> {
    if line.starts_with('#') {
        return None;
    }
    let series_end = match line.find('{') {
        Some(_) => line.rfind('}')? + 1,
        None => line.find(char::is_whitespace)?,
    };
    let (series, rest) = line.split_at(series_end);
    let value = rest.split_whitespace().next()?.parse().ok()?;
    Some((series, value))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Peak {
    value: f64,
    first_seen: DateTime<Utc>,
}

/// The peak values of the checked metrics of one process, i.e. of a replica or an orchestrator
/// between two restarts.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProcessLifetime {
    node_id: String,
    endpoint: MetricsEndpoint,
    /// The `process_start_time_seconds` of the process, if exported. Otherwise, all the processes
    /// of the endpoint are recorded as a single lifetime.
    start_time_secs: Option<f64>,
    first_scrape: DateTime<Utc>,
    last_scrape: DateTime<Utc>,
    /// The peak value of each checked metric series.
    peaks: BTreeMap<String, Peak>,
}

impl ProcessLifetime {
    fn is_of(&self, target: &Target) -> bool {
        self.node_id == target.node_id && self.endpoint == target.endpoint
    }
}

/// The peak values of the checked metrics of all processes observed during the test.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct MetricsPeaks {
    lifetimes: Vec<ProcessLifetime>,
}

impl TestEnvAttribute for MetricsPeaks {
    fn attribute_name() -> String {
        String::from("metrics_peaks")
    }
}

impl MetricsPeaks {
    fn latest(&self, target: &Target) -> Option<&ProcessLifetime> {
        self.lifetimes
            .iter()
            .filter(|lifetime| lifetime.is_of(target))
            .max_by_key(|lifetime| lifetime.last_scrape)
    }

    /// Records a scrape of `target`, logging when it reveals that the process restarted or that a
    /// metric newly exceeded its maximum allowed value.
    fn record(&mut self, target: &Target, scrape: Scrape, metrics: &MetricsToCheck, log: &Logger) {
        let index = match self.lifetimes.iter().position(|lifetime| {
            lifetime.is_of(target) && lifetime.start_time_secs == scrape.start_time_secs
        }) {
            Some(index) => index,
            None => {
                if let Some(previous) = self.latest(target) {
                    info!(
                        log,
                        "{target} restarted since its last scrape at {}. Increases of its metrics \
                        between that scrape and the restart were not checked.",
                        previous.last_scrape
                    );
                }
                self.lifetimes.push(ProcessLifetime {
                    node_id: target.node_id.clone(),
                    endpoint: target.endpoint,
                    start_time_secs: scrape.start_time_secs,
                    first_scrape: scrape.at,
                    last_scrape: scrape.at,
                    peaks: BTreeMap::new(),
                });
                self.lifetimes.len() - 1
            }
        };
        let lifetime = &mut self.lifetimes[index];
        lifetime.last_scrape = scrape.at;
        for (series, value) in scrape.values {
            let previous_peak = lifetime.peaks.get(&series).map(|peak| peak.value);
            if previous_peak.is_some_and(|peak| value <= peak) {
                continue;
            }
            if let Some((_, max_value)) = metrics.max_value(target.endpoint, &series) {
                let max_value = max_value as f64;
                if value > max_value && previous_peak.is_none_or(|peak| peak <= max_value) {
                    warn!(
                        log,
                        "The metric `{series}` of {target} exceeded its maximum allowed value: \
                        {value} > {max_value}. The test will fail."
                    );
                }
            }
            lifetime.peaks.insert(
                series,
                Peak {
                    value,
                    first_seen: scrape.at,
                },
            );
        }
    }

    fn violations(&self, metrics: &MetricsToCheck) -> Vec<String> {
        let mut violations = Vec::new();
        for lifetime in &self.lifetimes {
            let restarted_later = self.lifetimes.iter().any(|other| {
                other.node_id == lifetime.node_id
                    && other.endpoint == lifetime.endpoint
                    && other.first_scrape > lifetime.last_scrape
            });
            for (series, peak) in &lifetime.peaks {
                let Some((name, max_value)) = metrics.max_value(lifetime.endpoint, series) else {
                    continue;
                };
                if peak.value <= max_value as f64 {
                    continue;
                }
                let hint = match lifetime.endpoint {
                    MetricsEndpoint::Replica => format!("`remove_metrics_to_check(\"{name}\")`"),
                    MetricsEndpoint::Orchestrator => format!(
                        "`remove_metrics_to_check(\"{name}\")` or with \
                        `update_orchestrator_metrics_to_check(\"{name}\", $max_value)`"
                    ),
                };
                violations.push(format!(
                    "The metric `{series}` of the {} on node {} exceeded the maximum allowed \
                    value: {} > {max_value} (first seen at {}{}). If this is expected to happen \
                    in the test, create `SystemTestGroup` with {hint}.",
                    lifetime.endpoint,
                    lifetime.node_id,
                    peak.value,
                    peak.first_seen,
                    if restarted_later {
                        ", in a process that restarted later"
                    } else {
                        ""
                    },
                ));
            }
        }
        violations
    }
}

#[derive(Default)]
struct ScrapeResults {
    /// The targets whose scrape contained none of the metrics to check.
    without_metrics: Vec<Target>,
    /// The targets that could not be scraped, along with the reason.
    unreachable: Vec<(Target, anyhow::Error)>,
}

/// Scrapes all `targets` concurrently and records the scrapes in `peaks`.
async fn scrape_and_record(
    client: &reqwest::Client,
    targets: Vec<Target>,
    metrics: &MetricsToCheck,
    peaks: &mut MetricsPeaks,
    log: &Logger,
) -> ScrapeResults {
    let scrapes = join_all(targets.iter().map(|target| scrape(client, target, metrics))).await;
    let mut results = ScrapeResults::default();
    for (target, scrape) in targets.into_iter().zip(scrapes) {
        match scrape {
            Ok(scrape) => {
                if scrape.values.is_empty() {
                    results.without_metrics.push(target.clone());
                }
                peaks.record(&target, scrape, metrics, log);
            }
            Err(e) => results.unreachable.push((target, e)),
        }
    }
    results
}

/// Like `scrape_and_record`, but retries the targets that could not be scraped.
async fn scrape_and_record_with_retries(
    targets: Vec<Target>,
    metrics: &MetricsToCheck,
    peaks: &mut MetricsPeaks,
    log: &Logger,
) -> ScrapeResults {
    let client = metrics_client();
    let mut targets = targets;
    let mut results = ScrapeResults::default();
    for attempt in 1..=SCRAPE_ATTEMPTS {
        let attempt_results = scrape_and_record(&client, targets, metrics, peaks, log).await;
        results
            .without_metrics
            .extend(attempt_results.without_metrics);
        if attempt_results.unreachable.is_empty() || attempt == SCRAPE_ATTEMPTS {
            results.unreachable = attempt_results.unreachable;
            break;
        }
        targets = attempt_results
            .unreachable
            .into_iter()
            .map(|(target, _)| target)
            .collect();
        tokio::time::sleep(SCRAPE_BACKOFF).await;
    }
    results
}

fn without_metrics_violation(target: &Target) -> String {
    format!(
        "None of the metrics to check were found in the metrics of {target}. Please check the \
        names of the metrics to check."
    )
}

/// Task that periodically scrapes the replica and orchestrator metrics of all nodes in the latest
/// topology and records the peak value of every checked metric per process lifetime in the
/// `MetricsPeaks` attribute of the setup environment.
///
/// As a supervisor of the setup, tests and teardowns, a panic of this task would fail the whole
/// test, so failures are only logged.
pub(crate) fn metrics_watchdog_task(group_ctx: GroupContext, metrics: MetricsToCheck) {
    let logger = group_ctx.logger().clone();
    debug!(logger, ">>> metrics_watchdog_fn");
    let setup_dir = group_ctx.group_dir.join(GROUP_SETUP_DIR);
    let env = TestEnv::new_without_duplicating_logger(setup_dir.clone(), logger.clone());
    while !setup_dir.exists() || env.prep_dir("").is_none() {
        debug!(logger, "Setup and/or prep directories not created yet.");
        std::thread::sleep(Duration::from_secs(2));
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build the runtime of the metrics watchdog");
    let client = metrics_client();
    let mut peaks = MetricsPeaks::try_read_attribute(&env).unwrap_or_default();
    loop {
        if let Err(e) = rt.block_on(sync_local_registry_with_nns(&env)) {
            debug!(logger, "{e:?}. Using cached topology.");
        }
        // Reading the topology panics on unexpected registry contents. Don't let that fail the
        // test, the teardown reads the topology again anyway.
        match catch_unwind(AssertUnwindSafe(|| {
            env.safe_topology_snapshot()
                .map(|topology| targets(&topology, &metrics))
        })) {
            Ok(Ok(targets)) => {
                let results = rt.block_on(scrape_and_record(
                    &client, targets, &metrics, &mut peaks, &logger,
                ));
                for (target, e) in results.unreachable {
                    debug!(logger, "Could not scrape {target}: {e:?}");
                }
                if let Err(e) = env.write_json_object(MetricsPeaks::attribute_name(), &peaks) {
                    warn!(logger, "Could not persist the metrics peaks: {e:?}");
                }
            }
            Ok(Err(e)) => debug!(logger, "Could not get topology: {e:?}"),
            Err(_) => warn!(
                logger,
                "Reading the topology panicked, skipping this scrape."
            ),
        }
        std::thread::sleep(SCRAPE_INTERVAL);
    }
}

/// Fails if a checked metric exceeded its maximum allowed value on any node during the test, either
/// in the peaks recorded by the `metrics_watchdog` task or in a final scrape of all nodes in the
/// latest topology.
pub(crate) fn assert_no_metrics_errors(env: &TestEnv, metrics: &MetricsToCheck) {
    metrics.assert_prefix_free();
    let log = env.logger();
    let mut peaks = MetricsPeaks::try_read_attribute(env).unwrap_or_default();
    if let Err(e) = block_on(sync_local_registry_with_nns(env)) {
        info!(log, "{e:?}. Using cached topology.");
    }
    let mut violations = Vec::new();
    match env.safe_topology_snapshot() {
        Ok(topology) => {
            let results = block_on(scrape_and_record_with_retries(
                targets(&topology, metrics),
                metrics,
                &mut peaks,
                &log,
            ));
            violations.extend(
                results
                    .without_metrics
                    .iter()
                    .map(without_metrics_violation),
            );
            if !results.unreachable.is_empty() {
                let unreachable = results
                    .unreachable
                    .iter()
                    .map(|(target, e)| match peaks.latest(target) {
                        Some(lifetime) => {
                            format!("{target}: last scraped at {} ({e:#})", lifetime.last_scrape)
                        }
                        None => format!("{target}: never scraped ({e:#})"),
                    })
                    .collect::<Vec<_>>();
                env.emit_report(format!(
                    "Could not scrape the metrics of {} endpoint(s) at the end of the test, so \
                    their metrics were only checked up to their last scrape:\n{}",
                    unreachable.len(),
                    unreachable.join("\n")
                ));
            }
        }
        Err(e) => info!(
            log,
            "Could not get topology ({e:?}) => only checking the metrics recorded during the test."
        ),
    }
    violations.extend(peaks.violations(metrics));
    assert!(
        violations.is_empty(),
        "{} metric check(s) failed:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// Fails if a checked metric currently exceeds its maximum allowed value on any node in the
/// topology of `env`.
pub(crate) fn assert_current_metrics(env: &TestEnv, metrics: &MetricsToCheck) {
    metrics.assert_prefix_free();
    let log = env.logger();
    let mut peaks = MetricsPeaks::default();
    let results = block_on(scrape_and_record_with_retries(
        targets(&env.topology_snapshot(), metrics),
        metrics,
        &mut peaks,
        &log,
    ));
    for (target, e) in &results.unreachable {
        info!(log, "Could not scrape {target}: {e:?}");
    }
    let violations = results
        .without_metrics
        .iter()
        .map(without_metrics_violation)
        .chain(peaks.violations(metrics))
        .collect::<Vec<_>>();
    assert!(
        violations.is_empty(),
        "{} metric check(s) failed:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use slog::o;

    fn metrics() -> MetricsToCheck {
        MetricsToCheck {
            replica: BTreeMap::from([(String::from("critical_errors"), 0)]),
            orchestrator: BTreeMap::from([(
                String::from("orchestrator_processes_start_attempts_total"),
                1,
            )]),
        }
    }

    fn target(endpoint: MetricsEndpoint) -> Target {
        Target {
            node_id: String::from("node"),
            ip_addr: IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
            endpoint,
        }
    }

    fn scrape(start_time_secs: f64, secs: i64, values: &[(&str, f64)]) -> Scrape {
        Scrape {
            at: DateTime::from_timestamp(secs, 0).unwrap(),
            start_time_secs: Some(start_time_secs),
            values: values
                .iter()
                .map(|(series, value)| (series.to_string(), *value))
                .collect(),
        }
    }

    #[test]
    fn parses_samples() {
        assert_eq!(parse_sample("# HELP critical_errors Count"), None);
        assert_eq!(parse_sample(""), None);
        assert_eq!(
            parse_sample("process_start_time_seconds 1760612345.5"),
            Some(("process_start_time_seconds", 1760612345.5))
        );
        assert_eq!(
            parse_sample("critical_errors{error=\"a b\"} 3 1760612345000"),
            Some(("critical_errors{error=\"a b\"}", 3.0))
        );
        assert_eq!(parse_sample("critical_errors{error=\"a\"} oops"), None);
    }

    #[test]
    fn detects_violation_before_restart() {
        let log = Logger::root(slog::Discard, o!());
        let metrics = metrics();
        let replica = target(MetricsEndpoint::Replica);
        let series = "critical_errors{error=\"foo\"}";
        let mut peaks = MetricsPeaks::default();
        peaks.record(
            &replica,
            scrape(100.0, 110, &[(series, 0.0)]),
            &metrics,
            &log,
        );
        peaks.record(
            &replica,
            scrape(100.0, 120, &[(series, 1.0)]),
            &metrics,
            &log,
        );
        // The replica restarts and its counter is reset.
        peaks.record(
            &replica,
            scrape(200.0, 210, &[(series, 0.0)]),
            &metrics,
            &log,
        );

        let violations = peaks.violations(&metrics);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains(series), "{violations:?}");
        assert!(
            violations[0].contains("in a process that restarted later"),
            "{violations:?}"
        );
    }

    #[test]
    fn checks_max_value_per_lifetime() {
        let log = Logger::root(slog::Discard, o!());
        let metrics = metrics();
        let orchestrator = target(MetricsEndpoint::Orchestrator);
        let series = "orchestrator_processes_start_attempts_total{process_name=\"replica\"}";
        let mut peaks = MetricsPeaks::default();
        // Each orchestrator process starts the replica once, which is within the limit even though
        // the replica was started twice in total.
        peaks.record(
            &orchestrator,
            scrape(100.0, 110, &[(series, 1.0)]),
            &metrics,
            &log,
        );
        peaks.record(
            &orchestrator,
            scrape(200.0, 210, &[(series, 1.0)]),
            &metrics,
            &log,
        );
        assert_eq!(peaks.violations(&metrics), Vec::<String>::new());

        peaks.record(
            &orchestrator,
            scrape(200.0, 220, &[(series, 2.0)]),
            &metrics,
            &log,
        );
        let violations = peaks.violations(&metrics);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(
            !violations[0].contains("in a process that restarted later"),
            "{violations:?}"
        );
    }

    #[test]
    #[should_panic(expected = "are not prefix-free")]
    fn rejects_metrics_that_are_not_prefix_free() {
        let mut metrics = metrics();
        metrics
            .replica
            .insert(String::from("critical_errors_foo"), 0);
        metrics.assert_prefix_free();
    }
}
