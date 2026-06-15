//! Tool: `ic_metrics`.
//!
//! Scrapes Prometheus text exposition from one of the IC node's
//! observability endpoints (`replica`, `orchestrator`, `node_exporter`)
//! and answers four kinds of question about the result:
//!
//! * `list` — discover metric names without dumping a 10k-line scrape;
//! * `get` — current samples for a named metric, optionally filtered
//!   by labels;
//! * `summary` — a curated dashboard per source so the LLM doesn't
//!   have to know which 6 metric names matter for "is the replica
//!   healthy?";
//! * `rate` — per-second delta computed against a tiny in-memory LRU
//!   of the previous (timestamp, value) for the same (source, metric,
//!   labels) tuple.
//!
//! The target node's IPv6 is resolved through the shared
//! [`NodeDirectory`] from a `node_id` argument. As an escape hatch the
//! caller may pass a raw `ipv6` (e.g. when poking at a not-yet-in-
//! registry node from a dev machine).

use std::{
    collections::BTreeMap,
    net::Ipv6Addr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use lru::LruCache;
use prometheus_parse::{Sample, Scrape, Value};
use rig::{completion::ToolDefinition, tool::Tool};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::AppState;

// Per-source URL parameters. Each scrape source on a GuestOS node
// exposes Prometheus exposition with a slightly different shape —
// these constants are the source of truth, verified against live
// nodes:
//
//   replica       → http://[ipv6]:9090/   (root, plain HTTP)
//   orchestrator  → http://[ipv6]:9091/   (root, plain HTTP)
//   node_exporter → https://[ipv6]:9100/metrics
//                                         (self-signed TLS, /metrics path)
//
// The HTTPS-with-self-signed-cert quirk on node_exporter means we have
// to disable certificate validation on the shared HTTP client; see
// `IcMetrics::new` below.
const REPLICA_PORT: u16 = 9090;
const ORCHESTRATOR_PORT: u16 = 9091;
const NODE_EXPORTER_PORT: u16 = 9100;

/// HTTP timeout for a single scrape. Generous because `node_exporter`
/// can take a few hundred ms to gather disk stats on a busy box.
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on the rate-cache size. ~1k entries is roughly 100 metrics
/// across 10 nodes — enough headroom that we never thrash, but bounded
/// so a misbehaving LLM can't grow it without limit.
const RATE_CACHE_CAPACITY: usize = 1024;

/// Cap on `op = "list"` results. The LLM should never need to see
/// more than this in one shot; if it does, it should narrow the
/// `metric` substring filter.
const LIST_LIMIT: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum IcMetricsError {
    #[error("invalid arg: {0}")]
    InvalidArg(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("upstream {service} returned {status}: {body}")]
    Upstream {
        service: &'static str,
        status: u16,
        body: String,
    },

    #[error("prometheus parse error: {0}")]
    Prom(String),

    #[error("node directory: {0}")]
    Directory(#[from] crate::tools::node_directory::NodeDirectoryError),
}

#[derive(Debug, Deserialize)]
pub struct MetricsArgs {
    /// Source: "replica" | "orchestrator" | "node_exporter".
    pub source: String,

    /// Operation: "list" | "get" | "summary" | "rate".
    pub op: String,

    /// For "get"/"rate": metric name. For "list": optional substring
    /// filter applied to metric names.
    pub metric: Option<String>,

    /// For "get"/"rate": optional label filter, e.g.
    /// `{"status": "200"}`. All labels must match exactly.
    pub labels: Option<BTreeMap<String, String>>,

    /// For "rate": window in seconds. Currently informational — the
    /// rate is always computed against whatever previous sample we
    /// have for the (source, metric, labels) tuple. Default 60.
    pub window_secs: Option<u64>,

    /// Textual `NodeId` of the peer node to scrape. Resolved through
    /// the registry local store. Either this OR `ipv6` must be
    /// provided.
    pub node_id: Option<String>,

    /// Optional raw IPv6 override (without brackets). Useful for
    /// dev/test before the target is in the registry.
    pub ipv6: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MetricsOutput {
    pub source: String,
    pub op: String,
    pub target: TargetInfo,
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct TargetInfo {
    pub node_id: Option<String>,
    pub ipv6: String,
    pub url: String,
}

/// Source enum plus its scrape port and human label.
#[derive(Clone, Copy, Debug)]
enum Source {
    Replica,
    Orchestrator,
    NodeExporter,
}

impl Source {
    fn parse(s: &str) -> Result<Self, IcMetricsError> {
        match s {
            "replica" => Ok(Self::Replica),
            "orchestrator" => Ok(Self::Orchestrator),
            "node_exporter" => Ok(Self::NodeExporter),
            other => Err(IcMetricsError::InvalidArg(format!(
                "unknown source '{other}'; expected replica|orchestrator|node_exporter"
            ))),
        }
    }

    fn port(self) -> u16 {
        match self {
            Self::Replica => REPLICA_PORT,
            Self::Orchestrator => ORCHESTRATOR_PORT,
            Self::NodeExporter => NODE_EXPORTER_PORT,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Replica => "replica",
            Self::Orchestrator => "orchestrator",
            Self::NodeExporter => "node_exporter",
        }
    }

    /// URL scheme this source listens on. node_exporter terminates TLS
    /// (with a self-signed cert); the replica and orchestrator are
    /// plain HTTP on a loopback-style admin port.
    fn scheme(self) -> &'static str {
        match self {
            Self::Replica | Self::Orchestrator => "http",
            Self::NodeExporter => "https",
        }
    }

    /// URL path. The replica and orchestrator serve their full
    /// exposition at `/`; node_exporter at `/metrics` per upstream
    /// convention.
    fn path(self) -> &'static str {
        match self {
            Self::Replica | Self::Orchestrator => "/",
            Self::NodeExporter => "/metrics",
        }
    }
}

// Curated `summary` metric sets per source. Every name below has been
// verified against a real GuestOS node's exposition output — *not*
// cross-referenced from upstream docs, where naming drifts. Order is
// intentional: most-actionable first, so an LLM that only quotes the
// first few entries still surfaces the most useful signal.
//
// When the IC code base renames a metric, update these lists in lockstep
// — `op = "summary"` will silently return zero samples for a stale name
// rather than erroring.

/// node_exporter (host VM) — primary triage source. Covers CPU, memory,
/// swap, disk space, disk I/O saturation, network throughput, PSI
/// (pressure stall), clock health, file-descriptor exhaustion, and live
/// TCP socket count. Filesystem and disk metrics are per-mount/per-device,
/// so the LLM should narrow with `op = "get"` + label filter (e.g.
/// `mountpoint="/var/lib/ic/data"` for the IC state partition) to make
/// sense of multi-sample results.
const NODE_EXPORTER_SUMMARY: &[&str] = &[
    "node_load1",
    "node_load5",
    "node_load15",
    "node_memory_MemAvailable_bytes",
    "node_memory_MemTotal_bytes",
    "node_memory_SwapFree_bytes",
    "node_memory_SwapTotal_bytes",
    "node_filesystem_avail_bytes",
    "node_filesystem_size_bytes",
    "node_disk_io_time_seconds_total",
    "node_network_receive_bytes_total",
    "node_network_transmit_bytes_total",
    "node_pressure_io_stalled_seconds_total",
    "node_time_seconds",
    "node_filefd_allocated",
    "node_filefd_maximum",
    "node_netstat_Tcp_CurrEstab",
];

/// replica (consensus + state-sync internals). Health-focused: certified
/// height, checkpoint count, batch height, block production, peer-count
/// sanity, critical-error counter, RSS. Heavier debugging paths (QUIC,
/// state-sync detail) live behind `op = "get"`.
const REPLICA_SUMMARY: &[&str] = &[
    "state_manager_latest_certified_height",
    "state_manager_checkpoints_on_disk_count",
    "consensus_batch_height",
    "mr_blocks_proposed_total",
    "mr_subnet_size",
    "critical_errors",
    "process_resident_memory_bytes",
];

/// orchestrator (replica supervisor + upgrade manager). Small surface;
/// most names are zero in steady state and only move when something is
/// going wrong, which is exactly what we want to surface in a summary.
const ORCHESTRATOR_SUMMARY: &[&str] = &[
    "orchestrator_cup_deserialization_failed_total",
    "orchestrator_failed_consecutive_upgrade_checks_total",
    "orchestrator_replica_process_start_attempts_total",
    "orchestrator_state_removal_failed_total",
    "orchestrator_key_rotation_status",
    "reboot_duration_seconds",
];

/// Cache key for the rate computation. Labels are serialised
/// deterministically (BTreeMap iteration is ordered).
#[derive(Hash, Eq, PartialEq, Clone)]
struct RateKey {
    source: &'static str,
    target: String,
    metric: String,
    labels: String,
}

/// Cached rate-cache entry. We store unix-seconds + the sample value
/// (cast to f64; histogram/counter buckets are read as f64 by
/// `prometheus_parse`).
#[derive(Clone, Copy)]
struct RateEntry {
    timestamp_secs: i64,
    value: f64,
}

/// Tool struct.
pub struct IcMetrics {
    state: Arc<AppState>,
    /// Shared HTTP client. `reqwest` clients are designed to be
    /// long-lived and shared; building one per call would hammer the
    /// connection pool and slow scrapes noticeably.
    http: reqwest::Client,
    /// Last sample for each (source, target, metric, labels) tuple.
    /// `std::sync::Mutex` is fine here — the critical section is a
    /// hashmap lookup + insert and never blocks on anything async.
    rate_cache: Mutex<LruCache<RateKey, RateEntry>>,
}

impl IcMetrics {
    pub fn new(state: Arc<AppState>) -> Self {
        // node_exporter terminates TLS with a self-signed certificate
        // (per GuestOS provisioning). Replica and orchestrator both
        // serve plain HTTP, so the only cost of disabling cert
        // validation here is on the node_exporter path. We rely on
        // (a) reaching the node over an IPv6 address that came from
        // the registry and (b) the node_exporter port being firewalled
        // to the IC peer mesh — both of which the LLM can't subvert
        // through this tool.
        let http = reqwest::Client::builder()
            .timeout(SCRAPE_TIMEOUT)
            .danger_accept_invalid_certs(true)
            .build()
            .expect("reqwest client builder is infallible with default features");
        Self {
            state,
            http,
            rate_cache: Mutex::new(LruCache::new(RATE_CACHE_CAPACITY)),
        }
    }

    /// Resolve the target's IPv6 from either `ipv6` (verbatim) or
    /// `node_id` (registry lookup).
    async fn resolve_target(
        &self,
        node_id: Option<&str>,
        ipv6: Option<&str>,
    ) -> Result<(Ipv6Addr, Option<String>), IcMetricsError> {
        if let Some(raw) = ipv6 {
            let ip = Ipv6Addr::from_str(raw)
                .map_err(|e| IcMetricsError::InvalidArg(format!("invalid ipv6 '{raw}': {e}")))?;
            return Ok((ip, None));
        }
        let nid = node_id.ok_or_else(|| {
            IcMetricsError::InvalidArg("either node_id or ipv6 must be provided".to_string())
        })?;
        let directory = self.state.node_directory().await?;
        let ip = directory.resolve_ipv6(nid)?;
        Ok((ip, Some(nid.to_string())))
    }

    /// Build the scrape URL for a given source + IPv6. The shape
    /// (scheme, port, path) varies by source — see the comment block
    /// next to the port constants at the top of the file for the full
    /// matrix.
    fn build_url(source: Source, ipv6: Ipv6Addr) -> String {
        format!(
            "{scheme}://[{ipv6}]:{port}{path}",
            scheme = source.scheme(),
            port = source.port(),
            path = source.path(),
        )
    }

    /// Fetch and parse a scrape from the given URL.
    async fn fetch_scrape(&self, source: Source, url: &str) -> Result<Scrape, IcMetricsError> {
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IcMetricsError::Upstream {
                service: source.label(),
                status: status.as_u16(),
                body: truncate(&body, 512),
            });
        }
        let body = resp.text().await?;
        // `prometheus_parse::Scrape::parse` wants an iterator of
        // `Result<String, _>` so it can stream over the lines. We
        // already have the full body in memory.
        let lines = body.lines().map(|l| Ok::<_, std::io::Error>(l.to_string()));
        Scrape::parse(lines).map_err(|e| IcMetricsError::Prom(e.to_string()))
    }

    fn op_list(scrape: &Scrape, filter: Option<&str>) -> serde_json::Value {
        let mut names: Vec<&str> = scrape.docs.keys().map(|s| s.as_str()).collect();
        // Some metrics (e.g. process_*) appear only in `samples`, not
        // `docs`. Union the two so the LLM sees everything.
        for s in &scrape.samples {
            names.push(&s.metric);
        }
        names.sort();
        names.dedup();

        let filtered: Vec<String> = match filter {
            Some(f) if !f.is_empty() => {
                let needle = f;
                names
                    .iter()
                    .filter(|n| n.contains(needle))
                    .map(|n| n.to_string())
                    .collect()
            }
            _ => names.iter().map(|n| n.to_string()).collect(),
        };

        let total = filtered.len();
        let truncated = total > LIST_LIMIT;
        let limited: Vec<String> = filtered.into_iter().take(LIST_LIMIT).collect();
        json!({
            "metric_names": limited,
            "total": total,
            "truncated": truncated,
        })
    }

    fn op_get(
        scrape: &Scrape,
        metric: &str,
        labels: Option<&BTreeMap<String, String>>,
    ) -> serde_json::Value {
        let samples = filter_samples(scrape, metric, labels);
        let rendered: Vec<serde_json::Value> = samples.iter().map(render_sample).collect();
        json!({
            "metric": metric,
            "count": rendered.len(),
            "samples": rendered,
        })
    }

    fn op_summary(scrape: &Scrape, source: Source) -> serde_json::Value {
        let names = match source {
            Source::Replica => REPLICA_SUMMARY,
            Source::Orchestrator => ORCHESTRATOR_SUMMARY,
            Source::NodeExporter => NODE_EXPORTER_SUMMARY,
        };
        let mut out = serde_json::Map::new();
        for name in names {
            let samples = filter_samples(scrape, name, None);
            let rendered: Vec<serde_json::Value> = samples.iter().map(render_sample).collect();
            out.insert((*name).to_string(), json!(rendered));
        }
        serde_json::Value::Object(out)
    }

    fn op_rate(
        &self,
        scrape: &Scrape,
        target: &str,
        source: Source,
        metric: &str,
        labels: Option<&BTreeMap<String, String>>,
        window_secs: u64,
    ) -> serde_json::Value {
        let samples = filter_samples(scrape, metric, labels);
        if samples.is_empty() {
            return json!({
                "metric": metric,
                "rate": null,
                "value": null,
                "hint": format!(
                    "no current sample for {metric} matching the requested labels"
                ),
            });
        }

        // `rate` is only meaningful on a single time series. If
        // multiple samples come back, take the first and surface a
        // hint so the LLM tightens its label filter.
        let sample = &samples[0];
        let now = chrono::Utc::now().timestamp();
        let value = sample_to_f64(&sample.value);

        let key = RateKey {
            source: source.label(),
            target: target.to_string(),
            metric: metric.to_string(),
            labels: serialize_labels(labels),
        };
        let prev = self.rate_cache.lock().unwrap().pop(&key);
        self.rate_cache.lock().unwrap().put(
            key,
            RateEntry {
                timestamp_secs: now,
                value,
            },
        );

        let multi_hint = if samples.len() > 1 {
            Some(format!(
                "{} samples matched; rate computed from the first. Tighten labels for accuracy.",
                samples.len()
            ))
        } else {
            None
        };

        match prev {
            Some(prev) => {
                let dt = (now - prev.timestamp_secs) as f64;
                if dt <= 0.0 {
                    return json!({
                        "metric": metric,
                        "rate": null,
                        "value": value,
                        "hint": "previous sample was not older than the current; ignored",
                    });
                }
                let rate = (value - prev.value) / dt;
                let mut out = json!({
                    "metric": metric,
                    "rate": rate,
                    "rate_per_sec": rate,
                    "value": value,
                    "previous_value": prev.value,
                    "delta_secs": dt,
                    "window_secs_requested": window_secs,
                });
                if let Some(h) = multi_hint {
                    out["hint"] = serde_json::Value::String(h);
                }
                out
            }
            None => {
                let mut out = json!({
                    "metric": metric,
                    "rate": null,
                    "value": value,
                    "hint": "no prior sample; call rate again later to get a per-second delta",
                });
                if let Some(h) = multi_hint {
                    out["secondary_hint"] = serde_json::Value::String(h);
                }
                out
            }
        }
    }
}

/// Filter `scrape.samples` to entries whose metric matches `name` and
/// whose labels are a superset of `required` (if any).
fn filter_samples<'a>(
    scrape: &'a Scrape,
    name: &str,
    required: Option<&BTreeMap<String, String>>,
) -> Vec<&'a Sample> {
    scrape
        .samples
        .iter()
        .filter(|s| s.metric == name)
        .filter(|s| match required {
            None => true,
            Some(req) => req.iter().all(|(k, v)| s.labels.get(k) == Some(v.as_str())),
        })
        .collect()
}

/// Render a `prometheus_parse::Sample` to a small JSON object the LLM
/// can reason about without seeing parser internals.
fn render_sample(s: &&Sample) -> serde_json::Value {
    // Sort labels deterministically for stable LLM-facing output —
    // `prometheus_parse::Labels` is a HashMap underneath.
    let labels: BTreeMap<String, String> = s
        .labels
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    json!({
        "labels": labels,
        "value": sample_to_f64(&s.value),
        "timestamp_unix_ms": s.timestamp.timestamp_millis(),
        "kind": value_kind(&s.value),
    })
}

/// Cast a `prometheus_parse::Value` to f64 for general comparisons.
/// Histograms and summaries are reduced to their `+Inf`-bucket count
/// (for histograms) or `count` (for summaries), which is the
/// monotonic component callers most often want a rate over.
fn sample_to_f64(v: &Value) -> f64 {
    match v {
        Value::Counter(x) | Value::Gauge(x) | Value::Untyped(x) => *x,
        Value::Histogram(buckets) => {
            // `+Inf` bucket = total count.
            buckets.iter().last().map(|h| h.count).unwrap_or(0.0)
        }
        Value::Summary(quantiles) => {
            // Summary `count` is not directly exposed by the parser
            // here; fall back to the highest-quantile value as a
            // monotone-ish proxy.
            quantiles.iter().last().map(|q| q.count).unwrap_or(0.0)
        }
    }
}

fn value_kind(v: &Value) -> &'static str {
    match v {
        Value::Counter(_) => "counter",
        Value::Gauge(_) => "gauge",
        Value::Untyped(_) => "untyped",
        Value::Histogram(_) => "histogram",
        Value::Summary(_) => "summary",
    }
}

fn serialize_labels(labels: Option<&BTreeMap<String, String>>) -> String {
    match labels {
        None => String::new(),
        Some(l) => {
            let mut parts: Vec<String> = l.iter().map(|(k, v)| format!("{k}={v}")).collect();
            parts.sort();
            parts.join(",")
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

impl Tool for IcMetrics {
    const NAME: &'static str = "ic_metrics";
    type Error = IcMetricsError;
    type Args = MetricsArgs;
    type Output = MetricsOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Fetch and analyze Prometheus metrics from one of three IC node \
                sources. Pick `source` based on the question:\n\
                \n\
                * `node_exporter` (guest VM) — DEFAULT for general health, performance, \
                  and resource questions: CPU load, memory, swap, disk space, disk I/O \
                  saturation, network throughput, file descriptors, TCP socket counts, \
                  PSI pressure-stall, clock health. The most useful source for \
                  troubleshooting; start here.\n\
                * `replica` — IC-specific consensus and state-sync internals: certified \
                  height, checkpoints on disk, block production rate, subnet membership, \
                  critical-error counter. Use when the question is about IC liveness or \
                  state-sync.\n\
                * `orchestrator` — replica supervisor and upgrade manager: CUP \
                  deserialization failures, failed upgrade checks, replica restarts, \
                  key rotation status, reboot timing. Use for upgrade and orchestration \
                  issues.\n\
                \n\
                Operations: `list` discovers metric names (use a `metric` substring \
                to narrow), `get` returns current samples, `summary` returns a curated \
                dashboard for the chosen source, `rate` computes a per-second delta \
                against the previous call. Targets a specific peer node by `node_id` \
                (resolved via the local registry) or by raw `ipv6`.\n\
                \n\
                IMPORTANT: do NOT query the local node (this AI node). It is a passive \
                state-sync observer, not an active subnet member, so its metrics are \
                not representative of subnet health — replica counters will be near \
                zero, consensus metrics will be missing entirely, and node_exporter \
                will reflect only this AI node's own host. Always pick a `node_id` \
                of an active consensus member (use `ic_state` op=`subnet` to list \
                them and copy a node id from the `nodes` array)."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "enum": ["node_exporter", "replica", "orchestrator"],
                        "description":
                            "Which scrape endpoint to read. \
                             `node_exporter` for host-level CPU/memory/disk/network \
                             (preferred default); \
                             `replica` for IC consensus/state-sync internals; \
                             `orchestrator` for upgrade/CUP/restart issues."
                    },
                    "op": {
                        "type": "string",
                        "enum": ["list", "get", "summary", "rate"],
                        "description":
                            "What to do with the scrape. list=metric names; \
                             get=current samples; summary=curated dashboard; \
                             rate=per-second delta vs. previous call."
                    },
                    "metric": {
                        "type": "string",
                        "description":
                            "Metric name. Required for get/rate; optional substring \
                             filter for list."
                    },
                    "labels": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description":
                            "Label exact-match filter, e.g. {\"status\":\"200\"}."
                    },
                    "window_secs": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Hint for the rate window (default 60)."
                    },
                    "node_id": {
                        "type": "string",
                        "description":
                            "Textual NodeId of the peer to scrape. Resolved through \
                             the local registry. Either node_id or ipv6 is required."
                    },
                    "ipv6": {
                        "type": "string",
                        "description":
                            "Raw IPv6 of the peer (without brackets). Override for \
                             dev/test."
                    }
                },
                "required": ["source", "op"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let source = Source::parse(&args.source)?;
        let (ipv6, resolved_node_id) = self
            .resolve_target(args.node_id.as_deref(), args.ipv6.as_deref())
            .await?;
        let url = Self::build_url(source, ipv6);

        // Validate per-op required args before doing the scrape so we
        // fail fast on operator mistakes.
        match args.op.as_str() {
            "get" | "rate" => {
                if args.metric.as_deref().unwrap_or("").is_empty() {
                    return Err(IcMetricsError::InvalidArg(format!(
                        "metric is required for op={}",
                        args.op
                    )));
                }
            }
            "list" | "summary" => {}
            other => {
                return Err(IcMetricsError::InvalidArg(format!(
                    "unknown op '{other}'; expected list|get|summary|rate"
                )));
            }
        }

        let scrape = self.fetch_scrape(source, &url).await?;

        let data = match args.op.as_str() {
            "list" => Self::op_list(&scrape, args.metric.as_deref()),
            "get" => Self::op_get(&scrape, args.metric.as_ref().unwrap(), args.labels.as_ref()),
            "summary" => Self::op_summary(&scrape, source),
            "rate" => self.op_rate(
                &scrape,
                &ipv6.to_string(),
                source,
                args.metric.as_ref().unwrap(),
                args.labels.as_ref(),
                args.window_secs.unwrap_or(60),
            ),
            // Already validated above.
            _ => unreachable!(),
        };

        Ok(MetricsOutput {
            source: source.label().to_string(),
            op: args.op,
            target: TargetInfo {
                node_id: resolved_node_id,
                ipv6: ipv6.to_string(),
                url,
            },
            data,
        })
    }
}
