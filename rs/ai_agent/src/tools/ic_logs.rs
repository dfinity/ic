//! Tool: `ic_logs`.
//!
//! Pulls recent journald entries for an allow-listed systemd unit
//! through `systemd-journal-gatewayd`, which every IC node exposes on
//! port 19531 over HTTP.
//!
//! Gatewayd's journal API is documented at
//! <https://www.freedesktop.org/software/systemd/man/latest/systemd-journal-gatewayd.service.html>.
//! In short: `GET /entries` with `Accept: application/json` returns
//! one JSON object per entry per line ("application/json-seq" with
//! ASCII-RS framing in newer versions, but most deployments still
//! emit plain newline-delimited JSON; we handle both). Filtering by
//! unit is done with a `_SYSTEMD_UNIT=...` query parameter; line
//! count via `Range: entries=:-N:N`. Time-bound and priority filtering
//! are applied client-side because gatewayd's native filter for those
//! is awkward to compose.

use std::{net::Ipv6Addr, str::FromStr, sync::Arc, time::Duration};

use chrono::{DateTime, TimeZone, Utc};
use rig::{completion::ToolDefinition, tool::Tool};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::AppState;

/// Default port `systemd-journal-gatewayd` listens on.
const GATEWAYD_PORT: u16 = 19531;

/// HTTP timeout. Generous because gatewayd can be slow on big journals.
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

/// Default lookback window when `since` is not supplied.
const DEFAULT_LOOKBACK: Duration = Duration::from_secs(15 * 60);

/// Default and hard upper bound on lines fetched per call.
const DEFAULT_LINES: u32 = 200;
const MAX_LINES: u32 = 5000;

/// Default priority ceiling (only entries with `PRIORITY <=` this are
/// returned). 6 = info; matches the spec.
const DEFAULT_PRIORITY: u8 = 6;

/// Allow-list of systemd units the LLM may query. Keeping this short
/// and explicit is the only thing standing between the LLM and a
/// query like "show me the last 5000 lines of `ssh.service`". Adding
/// a unit here is a deliberate decision.
const ALLOWED_SERVICES: &[&str] = &[
    "ic-replica.service",
    "ic-orchestrator.service",
    "ic-crypto-csp.service",
    "ic-https-outcalls-adapter.service",
    "ic-btc-adapter.service",
    "node_exporter.service",
    "host_node_exporter.service",
    "nftables.service",
    "chrony.service",
];

#[derive(Debug, thiserror::Error)]
pub enum IcLogsError {
    #[error("invalid arg: {0}")]
    InvalidArg(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("upstream gatewayd returned {status}: {body}")]
    Upstream { status: u16, body: String },

    #[error("invalid timestamp '{value}': {source}")]
    Timestamp {
        value: String,
        #[source]
        source: chrono::ParseError,
    },

    #[error("node directory: {0}")]
    Directory(#[from] crate::tools::node_directory::NodeDirectoryError),
}

#[derive(Debug, Deserialize)]
pub struct LogsArgs {
    /// systemd unit name. Must be in the built-in allow-list.
    pub service: String,

    /// Lines to fetch from gatewayd before client-side filtering.
    /// Default 200, capped at 5000.
    pub lines: Option<u32>,

    /// RFC3339 lower bound. Default: now - 15 minutes.
    pub since: Option<String>,

    /// RFC3339 upper bound. Default: now.
    pub until: Option<String>,

    /// Min syslog priority (0=emerg .. 7=debug). Default 6 (info).
    /// Entries with `PRIORITY > priority` are dropped.
    pub priority: Option<u8>,

    /// Optional client-side substring filter on the message body
    /// (literal `.contains()`, not regex).
    pub grep: Option<String>,

    /// Textual `NodeId` to query. Either this or `ipv6` is required.
    pub node_id: Option<String>,

    /// Raw IPv6 override (without brackets) for dev/test.
    pub ipv6: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LogsOutput {
    pub service: String,
    pub returned: usize,
    /// True if gatewayd had more entries within the time window than
    /// we asked for. Lets the LLM know to widen `lines` or narrow the
    /// time window.
    pub truncated: bool,
    pub target: TargetInfo,
    pub entries: Vec<LogEntry>,
}

#[derive(Debug, Serialize)]
pub struct TargetInfo {
    pub node_id: Option<String>,
    pub ipv6: String,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct LogEntry {
    /// RFC3339-formatted timestamp.
    pub timestamp: String,
    /// Syslog priority (0..=7), or 6 (info) if the entry didn't
    /// declare one.
    pub priority: u8,
    pub unit: String,
    pub message: String,
}

/// Tool struct.
pub struct IcLogs {
    state: Arc<AppState>,
    http: reqwest::Client,
}

impl IcLogs {
    pub fn new(state: Arc<AppState>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .build()
            .expect("reqwest client builder is infallible with default features");
        Self { state, http }
    }

    async fn resolve_target(
        &self,
        node_id: Option<&str>,
        ipv6: Option<&str>,
    ) -> Result<(Ipv6Addr, Option<String>), IcLogsError> {
        if let Some(raw) = ipv6 {
            let ip = Ipv6Addr::from_str(raw)
                .map_err(|e| IcLogsError::InvalidArg(format!("invalid ipv6 '{raw}': {e}")))?;
            return Ok((ip, None));
        }
        let nid = node_id.ok_or_else(|| {
            IcLogsError::InvalidArg("either node_id or ipv6 must be provided".to_string())
        })?;
        let directory = self.state.node_directory().await?;
        let ip = directory.resolve_ipv6(nid)?;
        Ok((ip, Some(nid.to_string())))
    }
}

/// Validate that `service` is on the allow-list.
fn check_allowed(service: &str) -> Result<(), IcLogsError> {
    if !ALLOWED_SERVICES.contains(&service) {
        return Err(IcLogsError::InvalidArg(format!(
            "service '{service}' is not on the allow-list ({:?})",
            ALLOWED_SERVICES
        )));
    }
    Ok(())
}

fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, IcLogsError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| IcLogsError::Timestamp {
            value: s.to_string(),
            source: e,
        })
}

/// Decode one journald-export-as-JSON object emitted by gatewayd into
/// our public `LogEntry`. Best-effort: gatewayd quotes strings except
/// for binary fields which it base64-encodes; our allow-listed
/// services don't emit binary messages so we treat all values as
/// strings.
fn decode_entry(v: &serde_json::Value) -> Option<LogEntry> {
    let obj = v.as_object()?;

    // Timestamp: gatewayd emits `__REALTIME_TIMESTAMP` as a string of
    // microseconds-since-epoch. Newer versions also emit
    // `__REALTIME_TIMESTAMP_USEC` and `__REALTIME_TIMESTAMP_NSEC`; we
    // only need one.
    let ts_us: i64 = obj
        .get("__REALTIME_TIMESTAMP")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())?;
    let secs = ts_us / 1_000_000;
    let nsec = ((ts_us % 1_000_000) as u32) * 1_000;
    let ts = Utc.timestamp_opt(secs, nsec).single()?;

    let priority: u8 = obj
        .get("PRIORITY")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(DEFAULT_PRIORITY);

    let unit = obj
        .get("_SYSTEMD_UNIT")
        .or_else(|| obj.get("UNIT"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let message = obj
        .get("MESSAGE")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Some(LogEntry {
        timestamp: ts.to_rfc3339(),
        priority,
        unit,
        message,
    })
}

impl Tool for IcLogs {
    const NAME: &'static str = "ic_logs";
    type Error = IcLogsError;
    type Args = LogsArgs;
    type Output = LogsOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        // Inline the allow-list into the schema so the LLM sees the
        // exact set of accepted services rather than just a free-form
        // string field.
        let services_json: Vec<serde_json::Value> = ALLOWED_SERVICES
            .iter()
            .map(|s| serde_json::Value::String((*s).to_string()))
            .collect();
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Fetch recent systemd journal logs from one IC node's services. \
                Allowed services include `ic-replica.service`, `ic-orchestrator.service`, \
                and a few system units. Use this for \"what happened\" or \"why did X \
                fail\" questions. Returns structured log entries with timestamp, \
                priority, and message. Targets a specific peer node by `node_id` or \
                raw `ipv6`."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "enum": services_json,
                        "description": "systemd unit to query."
                    },
                    "lines": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_LINES,
                        "description": "Lines to fetch (default 200, max 5000)."
                    },
                    "lines": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_LINES,
                        "description": "Lines to fetch (default 200, max 5000)."
                    },
                    "since": {
                        "type": "string",
                        "description": "RFC3339 lower bound. Default: now - 15 minutes."
                    },
                    "until": {
                        "type": "string",
                        "description": "RFC3339 upper bound. Default: now."
                    },
                    "priority": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 7,
                        "description":
                            "Min syslog priority (0=emerg .. 7=debug). Entries with \
                             higher numeric priority are dropped. Default 6 (info)."
                    },
                    "grep": {
                        "type": "string",
                        "description":
                            "Optional substring filter (literal, not regex)."
                    },
                    "node_id": {
                        "type": "string",
                        "description":
                            "Textual NodeId of the peer to query. Resolved via the \
                             local registry. Either node_id or ipv6 is required."
                    },
                    "ipv6": {
                        "type": "string",
                        "description":
                            "Raw IPv6 of the peer (without brackets). Override for \
                             dev/test."
                    }
                },
                "required": ["service"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        check_allowed(&args.service)?;

        let lines = args.lines.unwrap_or(DEFAULT_LINES).clamp(1, MAX_LINES);
        let priority = args.priority.unwrap_or(DEFAULT_PRIORITY);
        if priority > 7 {
            return Err(IcLogsError::InvalidArg(format!(
                "priority must be 0..=7, got {priority}"
            )));
        }

        let now = Utc::now();
        let since = match args.since.as_deref() {
            Some(s) => parse_rfc3339(s)?,
            None => now - chrono::Duration::from_std(DEFAULT_LOOKBACK).unwrap(),
        };
        let until = match args.until.as_deref() {
            Some(s) => parse_rfc3339(s)?,
            None => now,
        };
        if since > until {
            return Err(IcLogsError::InvalidArg(format!(
                "since {since} is after until {until}"
            )));
        }

        let (ipv6, resolved_node_id) = self
            .resolve_target(args.node_id.as_deref(), args.ipv6.as_deref())
            .await?;

        // gatewayd field-equality filter is encoded into the URL as
        // `?_SYSTEMD_UNIT=foo.service`; the `Range: entries=:-N:N`
        // header asks for the last N entries.
        let url = format!(
            "http://[{ipv6}]:{port}/entries?_SYSTEMD_UNIT={service}",
            ipv6 = ipv6,
            port = GATEWAYD_PORT,
            service = args.service,
        );
        let range = format!("entries=:-{lines}:{lines}");

        let resp = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::RANGE, range)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IcLogsError::Upstream {
                status: status.as_u16(),
                body: truncate(&body, 512),
            });
        }
        let body = resp.text().await?;

        // Most gatewayd builds emit one JSON object per line. Some
        // newer builds use `application/json-seq` (RS-prefixed). We
        // accept both by stripping leading `0x1e` (record separator)
        // before parsing each line.
        let mut entries: Vec<LogEntry> = Vec::new();
        let mut total_seen: usize = 0;
        for line in body.lines() {
            let line = line.trim_start_matches('\u{1e}').trim();
            if line.is_empty() {
                continue;
            }
            total_seen += 1;
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(entry) = decode_entry(&v) else {
                continue;
            };
            // Filter: time window.
            let ts = match DateTime::parse_from_rfc3339(&entry.timestamp) {
                Ok(t) => t.with_timezone(&Utc),
                Err(_) => continue,
            };
            if ts < since || ts > until {
                continue;
            }
            // Filter: priority ceiling.
            if entry.priority > priority {
                continue;
            }
            // Filter: grep (literal substring, not regex).
            if let Some(needle) = args.grep.as_deref()
                && !needle.is_empty()
                && !entry.message.contains(needle)
            {
                continue;
            }
            entries.push(entry);
        }

        let truncated = total_seen as u32 >= lines && (entries.len() as u32) >= lines;
        let returned = entries.len();

        Ok(LogsOutput {
            service: args.service,
            returned,
            truncated,
            target: TargetInfo {
                node_id: resolved_node_id,
                ipv6: ipv6.to_string(),
                url,
            },
            entries,
        })
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
