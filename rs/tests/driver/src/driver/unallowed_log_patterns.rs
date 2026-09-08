//! The `assert_no_unallowed_log_patterns` teardown: fails a system test when an
//! IC node log line contains an unallowed phrase (by default `panicked` and
//! `This is a bug`, see `SystemTestGroup::new`) that is not covered by one of
//! that phrase's exclusions. Patterns are configured through
//! `SystemTestGroup::{add,remove}_unallowed_log_pattern*` as a map from pattern
//! to its set of exclusion phrases ([`UnallowedLogPatterns`]).
//!
//! The IC node logs come from one of two sources, chosen once at plan-build
//! time in `SystemTestGroup::make_plan` ([`LogSource`]):
//!
//! * Farm (without `--no-logs`): ElasticSearch, fed by the Vector VM
//!   (`vector_vm.rs`, `assets/vector.toml`). The query is filtered on
//!   `ic == GroupSetup::infra_group_name` and the `GroupStartTime..now` range
//!   and uses `match_phrase` as a server-side pre-filter.
//! * Local (with `--stream-ic-node-logs`): the JSON Lines files that
//!   `logs_stream_task` persists under `<group_dir>/journald_logs/nodes/`, one
//!   per IC node. Only that directory is scanned, mirroring the `ic` filter
//!   above (Vector does not ship universal VM or colocate container logs
//!   either). The teardown runs while the streamer is still appending (it is a
//!   child of the `logs_stream` supervisor in the plan), so a final line
//!   without a trailing newline is skipped, unparseable lines are skipped and
//!   counted, and matches are de-duplicated by `__CURSOR` (a reconnecting
//!   stream re-emits the record at its cursor). IC nodes excluded from
//!   streaming via `--exclude-logs` are not scanned.
//!
//! Both sources are matched on the Vector-normalized `MESSAGE`
//! ([`normalize_message`] reproduces the `to_json` transform of
//! `assets/vector.toml`, so for replica log lines only the inner slog message
//! is matched, not the JSON metadata around it) with one ASCII
//! case-insensitive substring predicate ([`CompiledPatterns::matching`]; ES
//! `match_phrase` lowercases too, but is token-anchored where this is not:
//! `bug` matches `debugging`) and rendered with one report and panic text.
//! Infrastructure problems (ElasticSearch unreachable, log directory missing,
//! unreadable file) are logged and skipped, i.e. the check fails open, while
//! real matches panic.

use crate::driver::{
    group::GroupStartTime,
    logs_stream_task::{JOURNALD_LOG_FILE_EXTENSION, JournalRecord},
    test_env::{TestEnv, TestEnvAttribute},
    test_env_api::{HasTopologySnapshot, IcNodeContainer},
    test_setup::GroupSetup,
};
use crate::util::block_on;
use chrono::{DateTime, SecondsFormat, Utc};
use slog::{Logger, info, warn};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashSet},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    time::Duration,
};

/// Map from an unallowed log phrase to its set of exclusion phrases, as stored
/// in `SystemTestGroup::unallowed_log_patterns`.
pub(crate) type UnallowedLogPatterns = BTreeMap<String, BTreeSet<String>>;

/// Where the teardown obtains the IC node log lines of the group. Decided once
/// in `SystemTestGroup::make_plan`, which builds the same plan in the parent
/// and in every task subprocess (`SYSTEM_TEST_BACKEND` is inherited and
/// `--working-dir`/`--no-logs`/`--stream-ic-node-logs` are forwarded), and
/// captured by the teardown closure.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum LogSource {
    /// Farm: query ElasticSearch for the records Vector shipped for this group.
    ElasticSearch,
    /// Local: scan the `<node_id>.jsonl` files `logs_stream_task` persisted
    /// under `nodes_dir` (`logs_stream_task::journald_node_logs_dir`).
    JournaldLogFiles { nodes_dir: PathBuf },
}

const MAX_SAMPLES_PER_PATTERN: usize = 3;
/// Journald records travel node -> gatewayd -> `logs_stream_task` -> disk with
/// sub-second latency, but nothing waits for that pipeline before the teardown
/// starts. Give records emitted in the last moments of the last test (e.g. a
/// replica panicking while being killed) time to land on disk.
const LOCAL_LOGS_SETTLE_DELAY: Duration = Duration::from_secs(5);
const ELASTICSEARCH_SEARCH_URL: &str = "https://elasticsearch.testnet.dfinity.network/testnet-vector-push-*/_search?filter_path=hits.hits";
const ES_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ES_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Teardown entry point. No-op for empty `patterns`. Reads `GroupSetup` for the
/// group name used in the report (soft-skip if absent), collects the matching
/// log lines from `source`, and panics with a report if any pattern matched.
pub(crate) fn check_unallowed_log_patterns(
    env: &TestEnv,
    source: &LogSource,
    patterns: &UnallowedLogPatterns,
) {
    check_unallowed_log_patterns_impl(env, source, patterns, LOCAL_LOGS_SETTLE_DELAY)
}

fn check_unallowed_log_patterns_impl(
    env: &TestEnv,
    source: &LogSource,
    patterns: &UnallowedLogPatterns,
    settle_delay: Duration,
) {
    if patterns.is_empty() {
        return;
    }

    let logger = env.logger();

    let group_name = match GroupSetup::try_read_attribute(env) {
        Ok(g) => g.infra_group_name,
        Err(e) => {
            info!(
                logger,
                "GroupSetup attribute is not available ({e:?}) \
                 => skipping unallowed log pattern check."
            );
            return;
        }
    };

    let compiled = CompiledPatterns::new(patterns);
    let matches = match source {
        LogSource::ElasticSearch => {
            check_elasticsearch(env, &logger, &group_name, patterns, &compiled)
        }
        LogSource::JournaldLogFiles { nodes_dir } => {
            check_journald_log_files(env, &logger, nodes_dir, &compiled, settle_delay)
        }
    };

    match matches {
        Some(matches) if !matches.is_empty() => {
            panic_with_report(&group_name, &render_report(&matches))
        }
        _ => {}
    }
}

/// Farm path. `None` means there is nothing to report: a soft-skip (already
/// logged) or no hits. Panics itself when ElasticSearch returned hits that the
/// local predicate cannot attribute to any pattern.
fn check_elasticsearch(
    env: &TestEnv,
    logger: &Logger,
    group_name: &str,
    patterns: &UnallowedLogPatterns,
    compiled: &CompiledPatterns,
) -> Option<MatchesByPattern> {
    let start_time = match GroupStartTime::try_read_attribute(env) {
        Ok(g) => g.0,
        Err(e) => {
            info!(
                logger,
                "GroupStartTime attribute is not available ({e:?}) \
                 => skipping unallowed log pattern check."
            );
            return None;
        }
    };
    let hits = fetch_elasticsearch_lines(logger, group_name, start_time, Utc::now(), patterns)?;
    if hits.is_empty() {
        return None;
    }
    let matches = attribute_lines(&hits, compiled);
    if matches.is_empty() {
        panic_with_report(group_name, &render_unattributed_report(&hits));
    }
    Some(matches)
}

/// Local path. `None` means there is nothing to report: a soft-skip (already
/// logged) or no records at all.
fn check_journald_log_files(
    env: &TestEnv,
    logger: &Logger,
    nodes_dir: &Path,
    compiled: &CompiledPatterns,
    settle_delay: Duration,
) -> Option<MatchesByPattern> {
    std::thread::sleep(settle_delay);
    let outcome = match scan_journald_log_files(nodes_dir, compiled) {
        Ok(outcome) => outcome,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            log_no_records_hint(env, logger, nodes_dir);
            return None;
        }
        Err(err) => {
            info!(
                logger,
                "Cannot scan the IC node journald logs under {} ({err}) \
                 => skipping unallowed log pattern check.",
                nodes_dir.display()
            );
            return None;
        }
    };
    info!(
        logger,
        "Scanned {} journald record(s) ({} byte(s)) in {} file(s) under {}: \
         {} truncated line(s), {} unparseable line(s), {} duplicate match(es), \
         {} unreadable file(s).",
        outcome.records,
        outcome.bytes,
        outcome.files,
        nodes_dir.display(),
        outcome.truncated_lines,
        outcome.unparseable_lines,
        outcome.duplicate_matches,
        outcome.unreadable_files,
    );
    if outcome.records == 0 {
        log_no_records_hint(env, logger, nodes_dir);
        return None;
    }
    Some(outcome.matches)
}

/// There are no IC node journald records under `nodes_dir`. Explain whether
/// that is expected (no IC deployed) or a sign that `logs_stream_task` never
/// captured the IC node logs.
fn log_no_records_hint(env: &TestEnv, logger: &Logger, nodes_dir: &Path) {
    match env.safe_topology_snapshot() {
        Err(_) => info!(
            logger,
            "No IC node journald records under {} and no IC is deployed in this group \
             => skipping unallowed log pattern check.",
            nodes_dir.display()
        ),
        Ok(topology) => {
            let node_count = topology
                .subnets()
                .flat_map(|subnet| subnet.nodes())
                .chain(topology.unassigned_nodes())
                .chain(topology.api_boundary_nodes())
                .count();
            warn!(
                logger,
                "The IC has {node_count} node(s) but there are no journald records under {}: \
                 logs_stream_task never captured the IC node logs \
                 => skipping unallowed log pattern check.",
                nodes_dir.display()
            );
        }
    }
}

/// A source-agnostic candidate log line: the ElasticSearch `_source` triple
/// (`timestamp`, `ic_node`, Vector-normalized `MESSAGE`) or its reconstruction
/// from a persisted journald record.
struct LogLine {
    timestamp: String,
    node: String,
    message: String,
}

impl LogLine {
    fn render(&self) -> String {
        format!("[{} {}] {}", self.timestamp, self.node, self.message)
    }
}

/// The patterns with their exclusions, ASCII-lowercased once so that matching
/// is case-insensitive (ElasticSearch `match_phrase` lowercases too).
struct CompiledPatterns(Vec<CompiledPattern>);

struct CompiledPattern {
    pattern: String,
    needle: String,
    exclusions: Vec<String>,
}

impl CompiledPatterns {
    fn new(patterns: &UnallowedLogPatterns) -> Self {
        Self(
            patterns
                .iter()
                .map(|(pattern, exclusions)| CompiledPattern {
                    pattern: pattern.clone(),
                    needle: pattern.to_ascii_lowercase(),
                    exclusions: exclusions
                        .iter()
                        .map(|exclusion| exclusion.to_ascii_lowercase())
                        .collect(),
                })
                .collect(),
        )
    }

    /// The patterns `message` matches, in [`UnallowedLogPatterns`] (i.e.
    /// `BTreeMap`) order: a message matches a pattern iff it contains the
    /// pattern and none of the pattern's exclusions, comparing ASCII
    /// case-insensitively.
    fn matching(&self, message: &str) -> Vec<&str> {
        let message = message.to_ascii_lowercase();
        self.0
            .iter()
            .filter(|p| {
                message.contains(&p.needle) && !p.exclusions.iter().any(|e| message.contains(e))
            })
            .map(|p| p.pattern.as_str())
            .collect()
    }
}

/// The matches of one pattern: the total count plus the first
/// `MAX_SAMPLES_PER_PATTERN` rendered lines (the file scan is unbounded, unlike
/// the ElasticSearch query, so we must not buffer every matching line).
#[derive(Debug, Default, PartialEq)]
struct PatternMatches {
    count: usize,
    samples: Vec<String>,
}

impl PatternMatches {
    fn push(&mut self, line: String) {
        self.count += 1;
        if self.samples.len() < MAX_SAMPLES_PER_PATTERN {
            self.samples.push(line);
        }
    }
}

/// `pattern -> matches`; `BTreeMap` keeps the report order stable.
type MatchesByPattern = BTreeMap<String, PatternMatches>;

/// Applies the predicate to already-normalized lines (ElasticSearch path).
fn attribute_lines(lines: &[LogLine], patterns: &CompiledPatterns) -> MatchesByPattern {
    let mut matches = MatchesByPattern::new();
    for line in lines {
        let matching = patterns.matching(&line.message);
        if matching.is_empty() {
            continue;
        }
        let rendered = line.render();
        for pattern in matching {
            matches
                .entry(pattern.to_string())
                .or_default()
                .push(rendered.clone());
        }
    }
    matches
}

/// Reproduces the `to_json` remap of `assets/vector.toml`, i.e. what
/// ElasticSearch stores as `MESSAGE` for a given raw journald `MESSAGE`:
/// * not a JSON object (kernel, systemd, Rust panic output, ...): unchanged;
/// * a JSON object with a non-null `log_entry` (replica/orchestrator slog
///   lines): `log_entry.message`, or the empty (unmatchable) string when that
///   is not a string, just like Vector's `null`;
/// * any other JSON object (API boundary node logs): its top-level `message`
///   string, or the raw text when there is none.
fn normalize_message(raw: &str) -> Cow<'_, str> {
    if !raw.trim_start().starts_with('{') {
        return Cow::Borrowed(raw);
    }
    let Ok(serde_json::Value::Object(object)) = serde_json::from_str::<serde_json::Value>(raw)
    else {
        return Cow::Borrowed(raw);
    };
    match object.get("log_entry") {
        Some(log_entry) if !log_entry.is_null() => Cow::Owned(
            log_entry
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
        ),
        _ => match object.get("message") {
            Some(serde_json::Value::String(message)) => Cow::Owned(message.clone()),
            _ => Cow::Borrowed(raw),
        },
    }
}

/// Renders a journald `__REALTIME_TIMESTAMP` (decimal microseconds since the
/// Unix epoch) as RFC 3339 UTC with microseconds, e.g. `"1700000000123456"`
/// becomes `"2023-11-14T22:13:20.123456Z"`. Falls back to the raw string when
/// it does not parse and to `""` when absent (like the ElasticSearch path).
fn render_realtime_timestamp(realtime_us: Option<&str>) -> String {
    let Some(raw) = realtime_us else {
        return String::new();
    };
    raw.parse::<i64>()
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_micros)
        .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Micros, true))
        .unwrap_or_else(|| raw.to_string())
}

fn render_report(matches: &MatchesByPattern) -> String {
    let mut report = String::new();
    for (pattern, pattern_matches) in matches {
        report.push_str(&format!(
            "\n- Pattern `{pattern}`: {} match(es)\n",
            pattern_matches.count
        ));
        for line in &pattern_matches.samples {
            report.push_str(&format!("    {line}\n"));
        }
        if pattern_matches.count > pattern_matches.samples.len() {
            report.push_str(&format!(
                "    ... and {} more\n",
                pattern_matches.count - pattern_matches.samples.len()
            ));
        }
    }
    report
}

fn render_unattributed_report(hits: &[LogLine]) -> String {
    let mut report = format!(
        "\n- ElasticSearch returned {} hit(s), but none could be attributed via local MESSAGE substring matching.\n",
        hits.len()
    );
    for hit in hits.iter().take(MAX_SAMPLES_PER_PATTERN) {
        report.push_str(&format!("    {}\n", hit.render()));
    }
    if hits.len() > MAX_SAMPLES_PER_PATTERN {
        report.push_str(&format!(
            "    ... and {} more raw hit(s)\n",
            hits.len() - MAX_SAMPLES_PER_PATTERN
        ));
    }
    report
}

fn panic_with_report(group_name: &str, report: &str) -> ! {
    panic!(
        "Found unallowed log patterns in IC logs for group `{group_name}`:{report}\n\
         If these patterns are expected in the test, create `SystemTestGroup` with \
         `add_unallowed_log_pattern_except(\"<pattern>\", \"<exclusion>\")`, \
         `remove_unallowed_log_pattern(\"<pattern>\")`, or \
         `remove_all_unallowed_log_patterns()`.",
    );
}

/// Queries ElasticSearch for the IC log lines of `group_name` in the given time
/// range whose `MESSAGE` matches (ES `match_phrase`) at least one pattern
/// without matching that pattern's exclusions. `None` on any transport or parse
/// error (logged), which the caller treats as a soft-skip.
fn fetch_elasticsearch_lines(
    logger: &Logger,
    group_name: &str,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    patterns: &UnallowedLogPatterns,
) -> Option<Vec<LogLine>> {
    // One `should` clause per pattern: match_phrase on the pattern, minus match_phrase on
    // any of its exclusions. A hit needs to satisfy at least one such clause.
    let should: Vec<serde_json::Value> = patterns
        .iter()
        .map(|(pattern, exclusions)| {
            let must_not: Vec<serde_json::Value> = exclusions
                .iter()
                .map(|e| serde_json::json!({ "match_phrase": { "MESSAGE": e } }))
                .collect();
            serde_json::json!({
                "bool": {
                    "filter": [ { "match_phrase": { "MESSAGE": pattern } } ],
                    "must_not": must_not,
                }
            })
        })
        .collect();

    let body = serde_json::json!({
        "size": 100,
        "query": {
            "bool": {
                "must": [
                    { "match_phrase": { "ic": group_name } },
                    { "range": { "timestamp": {
                        "gte": start_time.to_rfc3339(),
                        "lte": end_time.to_rfc3339(),
                    }}},
                ],
                "should": should,
                "minimum_should_match": 1,
            }
        },
        "_source": ["timestamp", "ic_node", "MESSAGE"],
    });

    info!(
        logger,
        "Querying {ELASTICSEARCH_SEARCH_URL} for unallowed log patterns with body: {body} ..."
    );

    let client = match reqwest::Client::builder()
        .connect_timeout(ES_CONNECT_TIMEOUT)
        .timeout(ES_REQUEST_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            info!(
                logger,
                "Failed to build reqwest client for ES query ({e:?}) \
                 => skipping unallowed log pattern check."
            );
            return None;
        }
    };

    let response: Result<serde_json::Value, reqwest::Error> = block_on(async {
        client
            .post(ELASTICSEARCH_SEARCH_URL)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json::<serde_json::Value>()
            .await
    });

    let value = match response {
        Ok(v) => v,
        Err(e) => {
            info!(
                logger,
                "Failed to query ElasticSearch for unallowed log patterns ({e:?}) \
                 => skipping unallowed log pattern check."
            );
            return None;
        }
    };

    let hits = value
        .get("hits")
        .and_then(|h| h.get("hits"))
        .and_then(|h| h.as_array())
        .cloned()
        .unwrap_or_default();

    Some(
        hits.iter()
            .map(|hit| {
                let source = hit.get("_source");
                let field = |name: &str| {
                    source
                        .and_then(|s| s.get(name))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                };
                LogLine {
                    timestamp: field("timestamp"),
                    node: field("ic_node"),
                    message: field("MESSAGE"),
                }
            })
            .collect(),
    )
}

#[derive(Debug, Default)]
struct ScanOutcome {
    matches: MatchesByPattern,
    files: usize,
    unreadable_files: usize,
    records: usize,
    bytes: u64,
    truncated_lines: usize,
    unparseable_lines: usize,
    duplicate_matches: usize,
}

/// Scans every `*.jsonl` file directly under `nodes_dir` (sorted by name, the
/// file stem being the node id). Fails only when `nodes_dir` itself cannot be
/// listed (`NotFound` when it does not exist); a file that cannot be read is
/// counted in `unreadable_files` and otherwise skipped.
fn scan_journald_log_files(
    nodes_dir: &Path,
    patterns: &CompiledPatterns,
) -> std::io::Result<ScanOutcome> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(nodes_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext == JOURNALD_LOG_FILE_EXTENSION)
        })
        .collect();
    paths.sort();

    let mut outcome = ScanOutcome::default();
    for path in paths {
        outcome.files += 1;
        let node = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default();
        if scan_journald_log_file(&path, &node, patterns, &mut outcome).is_err() {
            outcome.unreadable_files += 1;
        }
    }
    Ok(outcome)
}

/// Scans one persisted journald log file (see `logs_stream_task::JournalFileSink`)
/// line by line, in bounded memory. The writer may still be appending: a final
/// line without a trailing newline is its in-flight write and is skipped.
fn scan_journald_log_file(
    path: &Path,
    node: &str,
    patterns: &CompiledPatterns,
    out: &mut ScanOutcome,
) -> std::io::Result<()> {
    let mut reader = BufReader::with_capacity(64 * 1024, std::fs::File::open(path)?);
    let mut line: Vec<u8> = Vec::new();
    let mut seen_cursors: HashSet<String> = HashSet::new();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        if line.last() != Some(&b'\n') {
            out.truncated_lines += 1;
            break;
        }
        out.bytes += n as u64;
        let record: JournalRecord = match serde_json::from_slice(&line) {
            Ok(record) => record,
            Err(_) => {
                out.unparseable_lines += 1;
                continue;
            }
        };
        out.records += 1;
        let message = normalize_message(&record.message);
        let matching = patterns.matching(&message);
        if matching.is_empty() {
            continue;
        }
        if seen_cursors.contains(&record.cursor) {
            out.duplicate_matches += 1;
            continue;
        }
        let rendered = LogLine {
            timestamp: render_realtime_timestamp(record.realtime_timestamp.as_deref()),
            node: node.to_string(),
            message: message.into_owned(),
        }
        .render();
        for pattern in matching {
            out.matches
                .entry(pattern.to_string())
                .or_default()
                .push(rendered.clone());
        }
        seen_cursors.insert(record.cursor);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALTIME_US: &str = "1700000000123456";
    const REALTIME_RFC3339: &str = "2023-11-14T22:13:20.123456Z";
    const PANIC_HEADER: &str =
        "thread 'consensus_Processor' (1450) panicked at rs/consensus/src/consensus.rs:357:17:";
    const STATE_MANAGER_BUG: &str =
        "Previous state hash was not available after awaiting the hash thread. This is a bug.";

    fn default_patterns() -> UnallowedLogPatterns {
        BTreeMap::from([
            ("This is a bug".to_string(), BTreeSet::new()),
            (
                "panicked".to_string(),
                BTreeSet::from([
                    "canister".to_string(),
                    "rs/canister_sandbox/src/replica_controller/allowed_panics.rs".to_string(),
                ]),
            ),
        ])
    }

    fn compiled() -> CompiledPatterns {
        CompiledPatterns::new(&default_patterns())
    }

    /// A replica slog line as it appears in the raw journald `MESSAGE`.
    fn replica_message(crate_: &str, inner: &str) -> String {
        serde_json::json!({
            "msg": format!("s:subnet/n:node/{crate_}/module {inner}"),
            "level": "INFO",
            "ts": "2023-11-14T22:13:20.123Z",
            "log_entry": {
                "level": "INFO",
                "utc_time": "2023-11-14T22:13:20.123Z",
                "message": inner,
                "crate_": crate_,
                "module": "module",
                "line": 1,
            }
        })
        .to_string()
    }

    /// One persisted JSON line.
    fn record_line(cursor: &str, message: &str) -> String {
        serde_json::to_string(&JournalRecord {
            cursor: cursor.to_string(),
            realtime_timestamp: Some(REALTIME_US.to_string()),
            message: message.to_string(),
            system_unit: None,
            container_name: None,
            comm: None,
        })
        .unwrap()
    }

    fn write_node_log(nodes_dir: &Path, node: &str, lines: &[String], trailing_newline: bool) {
        std::fs::create_dir_all(nodes_dir).unwrap();
        let mut contents = lines.join("\n");
        if trailing_newline {
            contents.push('\n');
        }
        std::fs::write(nodes_dir.join(format!("{node}.jsonl")), contents).unwrap();
    }

    fn discard_logger() -> Logger {
        Logger::root(slog::Discard, slog::o!())
    }

    fn setup_env(group_dir: &Path, group_name: Option<&str>) -> TestEnv {
        let env =
            TestEnv::new_without_duplicating_logger(group_dir.join("setup"), discard_logger());
        if let Some(group_name) = group_name {
            GroupSetup {
                infra_group_name: group_name.to_string(),
                ..Default::default()
            }
            .write_attribute(&env);
        }
        env
    }

    #[test]
    fn normalize_message_keeps_non_json_and_invalid_json_as_is() {
        for raw in [
            PANIC_HEADER,
            "<MESSAGE omitted: too large to serialize>",
            "{not json",
            r#"["panicked"]"#,
            r#""panicked""#,
            "42",
            "",
        ] {
            assert_eq!(normalize_message(raw), raw);
        }
    }

    #[test]
    fn normalize_message_uses_inner_message_of_replica_log_entry() {
        let raw = replica_message("ic_state_manager", STATE_MANAGER_BUG);
        let normalized = normalize_message(&raw);
        assert_eq!(normalized, STATE_MANAGER_BUG);
        assert_eq!(normalize_message(&format!("  {raw}")), STATE_MANAGER_BUG);
    }

    #[test]
    fn normalize_message_makes_log_entry_without_string_message_unmatchable() {
        for raw in [
            r#"{"log_entry":{"level":"INFO"}}"#,
            r#"{"log_entry":"panicked"}"#,
            r#"{"log_entry":{"message":42},"message":"panicked"}"#,
        ] {
            assert_eq!(normalize_message(raw), "");
        }
    }

    #[test]
    fn normalize_message_uses_top_level_message_of_flat_json() {
        assert_eq!(
            normalize_message(r#"{"message":"request panicked","level":"error"}"#),
            "request panicked"
        );
        assert_eq!(
            normalize_message(r#"{"log_entry":null,"message":"request panicked"}"#),
            "request panicked"
        );
        // No recursion into a JSON-valued message.
        assert_eq!(
            normalize_message(r#"{"message":"{\"message\":\"inner\"}"}"#),
            r#"{"message":"inner"}"#
        );
    }

    #[test]
    fn normalize_message_keeps_flat_json_without_string_message_as_is() {
        for raw in [
            r#"{"level":"error"}"#,
            r#"{"message":null}"#,
            r#"{"message":42}"#,
            r#"{"message":{"nested":true}}"#,
        ] {
            assert_eq!(normalize_message(raw), raw);
        }
    }

    #[test]
    fn matching_returns_all_matching_patterns_in_order() {
        let compiled = compiled();
        assert_eq!(
            compiled.matching(&format!("{PANIC_HEADER} This is a bug")),
            vec!["This is a bug", "panicked"]
        );
        assert_eq!(compiled.matching(PANIC_HEADER), vec!["panicked"]);
        assert_eq!(compiled.matching("all good"), Vec::<&str>::new());
    }

    #[test]
    fn matching_exclusion_only_suppresses_its_own_pattern() {
        let compiled = compiled();
        assert_eq!(
            compiled.matching("canister 42 panicked. This is a bug"),
            vec!["This is a bug"]
        );
        assert_eq!(
            compiled.matching(
                "thread 'x' panicked at rs/canister_sandbox/src/replica_controller/allowed_panics.rs:1:1:"
            ),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn matching_is_ascii_case_insensitive() {
        let compiled = compiled();
        assert_eq!(compiled.matching("this is a bug"), vec!["This is a bug"]);
        assert_eq!(compiled.matching("THIS IS A BUG"), vec!["This is a bug"]);
        assert_eq!(compiled.matching("Task PANICKED"), vec!["panicked"]);
        assert_eq!(
            compiled.matching("Canister 42 panicked"),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn render_realtime_timestamp_formats_micros_as_rfc3339_utc() {
        assert_eq!(
            render_realtime_timestamp(Some(REALTIME_US)),
            REALTIME_RFC3339
        );
        assert_eq!(render_realtime_timestamp(Some("garbage")), "garbage");
        assert_eq!(render_realtime_timestamp(None), "");
    }

    #[test]
    fn render_report_caps_samples_and_counts_the_rest() {
        let mut matches = MatchesByPattern::new();
        for i in 0..5 {
            matches
                .entry("panicked".to_string())
                .or_default()
                .push(format!("line {i}"));
        }
        assert_eq!(
            render_report(&matches),
            "\n- Pattern `panicked`: 5 match(es)\n    line 0\n    line 1\n    line 2\n    ... and 2 more\n"
        );
    }

    #[test]
    fn scan_missing_dir_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = scan_journald_log_files(&dir.path().join("nodes"), &compiled()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn scan_empty_dir_has_no_files() {
        let dir = tempfile::tempdir().unwrap();
        let outcome = scan_journald_log_files(dir.path(), &compiled()).unwrap();
        assert_eq!(outcome.files, 0);
        assert_eq!(outcome.records, 0);
        assert!(outcome.matches.is_empty());
    }

    #[test]
    fn scan_reports_matches_with_node_id_and_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        write_node_log(
            dir.path(),
            "node-a",
            &[
                record_line("c1", "all good"),
                record_line(
                    "c2",
                    &replica_message("ic_state_manager", STATE_MANAGER_BUG),
                ),
                record_line("c3", PANIC_HEADER),
            ],
            true,
        );
        let outcome = scan_journald_log_files(dir.path(), &compiled()).unwrap();
        assert_eq!(outcome.files, 1);
        assert_eq!(outcome.records, 3);
        assert_eq!(outcome.truncated_lines, 0);
        assert_eq!(outcome.unparseable_lines, 0);
        assert_eq!(
            outcome.matches["This is a bug"].samples,
            vec![format!("[{REALTIME_RFC3339} node-a] {STATE_MANAGER_BUG}")]
        );
        assert_eq!(
            outcome.matches["panicked"].samples,
            vec![format!("[{REALTIME_RFC3339} node-a] {PANIC_HEADER}")]
        );
    }

    #[test]
    fn scan_skips_truncated_last_line_and_unparseable_lines() {
        let dir = tempfile::tempdir().unwrap();
        write_node_log(
            dir.path(),
            "node-a",
            &[
                record_line("c1", "all good"),
                "not json at all".to_string(),
                record_line("c2", PANIC_HEADER),
                record_line("c3", "This is a bug"),
            ],
            false,
        );
        let outcome = scan_journald_log_files(dir.path(), &compiled()).unwrap();
        assert_eq!(outcome.records, 2);
        assert_eq!(outcome.unparseable_lines, 1);
        assert_eq!(outcome.truncated_lines, 1);
        assert_eq!(outcome.matches["panicked"].count, 1);
        assert!(!outcome.matches.contains_key("This is a bug"));
    }

    #[test]
    fn scan_dedups_matches_by_cursor() {
        let dir = tempfile::tempdir().unwrap();
        write_node_log(
            dir.path(),
            "node-a",
            &[
                record_line("c1", PANIC_HEADER),
                record_line("c1", PANIC_HEADER),
                record_line("c2", PANIC_HEADER),
            ],
            true,
        );
        let outcome = scan_journald_log_files(dir.path(), &compiled()).unwrap();
        assert_eq!(outcome.records, 3);
        assert_eq!(outcome.duplicate_matches, 1);
        assert_eq!(outcome.matches["panicked"].count, 2);
    }

    #[test]
    fn scan_matches_normalized_message_not_json_metadata() {
        let dir = tempfile::tempdir().unwrap();
        write_node_log(
            dir.path(),
            "node-a",
            &[
                // Crate name contains `canister`, the inner message does not: matched.
                record_line(
                    "c1",
                    &replica_message(
                        "ic_canister_sandbox",
                        "thread 'x' panicked at rs/foo.rs:1:1",
                    ),
                ),
                // The inner message itself contains the exclusion: not matched.
                record_line(
                    "c2",
                    &replica_message("ic_execution", "canister 42 panicked"),
                ),
            ],
            true,
        );
        let outcome = scan_journald_log_files(dir.path(), &compiled()).unwrap();
        assert_eq!(outcome.matches["panicked"].count, 1);
        assert_eq!(
            outcome.matches["panicked"].samples,
            vec![format!(
                "[{REALTIME_RFC3339} node-a] thread 'x' panicked at rs/foo.rs:1:1"
            )]
        );
    }

    #[test]
    fn scan_aggregates_sorted_jsonl_files_only() {
        let dir = tempfile::tempdir().unwrap();
        write_node_log(
            dir.path(),
            "node-b",
            &[record_line("c1", PANIC_HEADER)],
            true,
        );
        write_node_log(
            dir.path(),
            "node-a",
            &[record_line("c2", PANIC_HEADER)],
            true,
        );
        std::fs::write(
            dir.path().join("notes.txt"),
            record_line("c3", PANIC_HEADER),
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("sub.jsonl")).unwrap();
        let outcome = scan_journald_log_files(dir.path(), &compiled()).unwrap();
        assert_eq!(outcome.files, 2);
        assert_eq!(
            outcome.matches["panicked"].samples,
            vec![
                format!("[{REALTIME_RFC3339} node-a] {PANIC_HEADER}"),
                format!("[{REALTIME_RFC3339} node-b] {PANIC_HEADER}"),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "Found unallowed log patterns in IC logs for group `g`")]
    fn check_journald_log_files_panics_on_match() {
        let dir = tempfile::tempdir().unwrap();
        let nodes_dir = dir.path().join("journald_logs").join("nodes");
        write_node_log(
            &nodes_dir,
            "node-a",
            &[record_line("c1", PANIC_HEADER)],
            true,
        );
        let env = setup_env(dir.path(), Some("g"));
        check_unallowed_log_patterns_impl(
            &env,
            &LogSource::JournaldLogFiles { nodes_dir },
            &default_patterns(),
            Duration::ZERO,
        );
    }

    #[test]
    fn check_journald_log_files_soft_skips_without_records_or_group_setup() {
        let dir = tempfile::tempdir().unwrap();
        let nodes_dir = dir.path().join("journald_logs").join("nodes");
        let source = LogSource::JournaldLogFiles {
            nodes_dir: nodes_dir.clone(),
        };
        // No GroupSetup attribute.
        write_node_log(
            &nodes_dir,
            "node-a",
            &[record_line("c1", PANIC_HEADER)],
            true,
        );
        let env = setup_env(dir.path(), None);
        check_unallowed_log_patterns_impl(&env, &source, &default_patterns(), Duration::ZERO);
        // Empty patterns.
        let env = setup_env(dir.path(), Some("g"));
        check_unallowed_log_patterns_impl(&env, &source, &BTreeMap::new(), Duration::ZERO);
        // Matches only under `uvms/` are ignored; `nodes/` is missing.
        let dir = tempfile::tempdir().unwrap();
        write_node_log(
            &dir.path().join("journald_logs").join("uvms"),
            "uvm-a",
            &[record_line("c1", PANIC_HEADER)],
            true,
        );
        let env = setup_env(dir.path(), Some("g"));
        check_unallowed_log_patterns_impl(
            &env,
            &LogSource::JournaldLogFiles {
                nodes_dir: dir.path().join("journald_logs").join("nodes"),
            },
            &default_patterns(),
            Duration::ZERO,
        );
        // Records without matches.
        let dir = tempfile::tempdir().unwrap();
        let nodes_dir = dir.path().join("journald_logs").join("nodes");
        write_node_log(&nodes_dir, "node-a", &[record_line("c1", "all good")], true);
        let env = setup_env(dir.path(), Some("g"));
        check_unallowed_log_patterns_impl(
            &env,
            &LogSource::JournaldLogFiles { nodes_dir },
            &default_patterns(),
            Duration::ZERO,
        );
    }

    #[test]
    fn attribute_lines_renders_elasticsearch_hits() {
        let lines = vec![
            LogLine {
                timestamp: "t1".to_string(),
                node: "n1".to_string(),
                message: "this is a bug".to_string(),
            },
            LogLine {
                timestamp: "t2".to_string(),
                node: "n2".to_string(),
                message: "fine".to_string(),
            },
        ];
        let matches = attribute_lines(&lines, &compiled());
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches["This is a bug"].samples,
            vec!["[t1 n1] this is a bug".to_string()]
        );
        assert_eq!(
            render_unattributed_report(&lines[1..]),
            "\n- ElasticSearch returned 1 hit(s), but none could be attributed via local MESSAGE substring matching.\n    [t2 n2] fine\n"
        );
    }
}
