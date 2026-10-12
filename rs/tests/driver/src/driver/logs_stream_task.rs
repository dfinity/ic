//! Streams journald logs from a system test's deployed machines into the test
//! log and persists them to disk. A background task (`logs_stream_task`)
//! periodically discovers the group's universal VMs (and, when
//! `--stream-ic-node-logs` is set, its IC nodes) and, for every newly
//! discovered target, opens a long-lived `follow` connection to that machine's
//! systemd-journal-gatewayd over IPv6. Each journald record received is parsed,
//! printed to stdout so it appears inline in the test output, and appended as
//! one JSON object per line to
//! `<group_dir>/journald_logs/{nodes,uvms}/<target>.jsonl` (see
//! [`JournalFileSink`]). On the Local backend, which has no Vector VM to ship
//! logs to ElasticSearch, the `nodes/` files are what the
//! `assert_no_unallowed_log_patterns` teardown scans
//! (`crate::driver::unallowed_log_patterns`). Targets matching an
//! `--exclude-logs` pattern are skipped, streams reconnect from their last
//! cursor when a connection ends or fails (TCP keepalive bounds a stalled read,
//! see `KEEPALIVE_*`), skipping the record re-emitted at the checkpoint, and on
//! the Local backend IC node streams bind to a dedicated per-group source
//! address to avoid exhausting the GuestOS per-source firewall connection
//! budget.

use crate::driver::{
    constants::{COLOCATE_CONTAINER_NAME, GROUP_SETUP_DIR},
    context::GroupContext,
    local_backend::{LocalBackend, sanitize_name},
    resource::AllocatedVm,
    test_env::{TestEnv, TestEnvAttribute},
    test_env_api::{HasTopologySnapshot, IcNodeContainer},
    test_setup::{GroupSetup, SystemTestBackend},
    universal_vm::UNIVERSAL_VMS_DIR,
};
use anyhow::{Context, Result};
use nix::sys::socket::{setsockopt, sockopt};
use regex::Regex;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use slog::{Logger, debug, info, warn};
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpSocket, TcpStream},
    runtime::Runtime,
};
use walkdir::WalkDir;

pub(crate) const LOGS_STREAM_TASK_NAME: &str = "logs_stream";

/// The port of systemd-journal-gatewayd on IC nodes and universal VMs.
const JOURNAL_GATEWAYD_PORT: u16 = 19531;
const RETRY_DELAY_JOURNALD_STREAM: Duration = Duration::from_secs(5);
const RETRY_DELAY_DISCOVER_TARGETS: Duration = Duration::from_secs(5);
/// TCP keepalive of the streaming sockets: a dead peer (no FIN/RST) fails the
/// read within `KEEPALIVE_IDLE + KEEPALIVE_COUNT * KEEPALIVE_INTERVAL` = 30 s.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const KEEPALIVE_COUNT: u32 = 3;
/// Bounds the connect (SYN) phase, which keepalive does not cover.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// A failure that repeats with the same text is logged again every this many
/// attempts, so a stream that never recovers stays visible.
const REPEATED_FAILURE_LOG_EVERY: u32 = 60;

/// `<group_dir>/journald_logs`: the persisted journald records, one JSON Lines
/// file per streamed target (see [`JournalFileSink`]).
pub(crate) const JOURNALD_LOGS_DIR: &str = "journald_logs";
/// IC nodes: `journald_logs/nodes/<node_id>.jsonl`. The only sub-directory the
/// `assert_no_unallowed_log_patterns` teardown scans, mirroring the data Vector
/// ships to ElasticSearch on Farm (IC nodes only).
pub(crate) const JOURNALD_LOGS_NODES_SUBDIR: &str = "nodes";
/// Universal VMs: `journald_logs/uvms/<sanitized_vm_name>.jsonl`. Never
/// scanned (Vector does not ship universal VM logs either).
pub(crate) const JOURNALD_LOGS_UVMS_SUBDIR: &str = "uvms";
pub(crate) const JOURNALD_LOG_FILE_EXTENSION: &str = "jsonl";

pub(crate) fn journald_logs_dir(group_dir: &Path) -> PathBuf {
    group_dir.join(JOURNALD_LOGS_DIR)
}

pub(crate) fn journald_node_logs_dir(group_dir: &Path) -> PathBuf {
    journald_logs_dir(group_dir).join(JOURNALD_LOGS_NODES_SUBDIR)
}

pub(crate) fn journald_uvm_logs_dir(group_dir: &Path) -> PathBuf {
    journald_logs_dir(group_dir).join(JOURNALD_LOGS_UVMS_SUBDIR)
}

/// `<logs_dir>/<sanitize_name(target)>.jsonl`. Sanitization is the identity on
/// node ids (principal text is `[a-z0-9-]`), so the file stem of a node log
/// file *is* the node id; universal VM names are user-provided and may need it.
pub(crate) fn journald_log_path(logs_dir: &Path, target: &str) -> PathBuf {
    logs_dir.join(format!(
        "{}.{JOURNALD_LOG_FILE_EXTENSION}",
        sanitize_name(target)
    ))
}

pub(crate) fn logs_stream_task(group_ctx: GroupContext) -> () {
    let logger = group_ctx.logger().clone();
    debug!(logger, ">>> {LOGS_STREAM_TASK_NAME}");
    let rt: Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("Could not create tokio runtime: {err}"));
    // The root env lives at `<group_dir>/root_env`, so the directory tree that
    // `discover_uvms` walks is simply the group directory. We deliberately avoid
    // `get_root_env()` here: it opens `root_env/test.log` with an exclusive
    // (non-blocking) flock, which fails with EAGAIN when another long-lived
    // process spawned by the Local backend holds that lock. We only need the path.
    let root_search_dir = group_ctx.group_dir.clone();
    // Where the records of each streamed target are persisted, by target kind.
    let uvm_logs_dir = journald_uvm_logs_dir(&group_ctx.group_dir);
    let node_logs_dir = journald_node_logs_dir(&group_ctx.group_dir);
    // The IPv6 addresses of the IC nodes are not stored on disk next to the
    // UVMs; they live in the registry local store which is surfaced through the
    // topology snapshot of the setup environment. We build a `TestEnv` for the
    // setup directory *without* duplicating the logger, because doing so would
    // otherwise take the same exclusive `test.log` flock discussed above.
    let setup_env = TestEnv::new_without_duplicating_logger(
        group_ctx.group_dir.join(GROUP_SETUP_DIR),
        logger.clone(),
    );
    let mut streamed_uvms: HashMap<String, Ipv6Addr> = HashMap::new();
    let mut skipped_uvms: BTreeSet<String> = BTreeSet::new();
    let mut streamed_nodes: HashMap<String, Ipv6Addr> = HashMap::new();
    let mut skipped_nodes: BTreeSet<String> = BTreeSet::new();
    // How each IC node's journald stream is sourced, resolved once from the
    // active backend (see the `stream_ic_node_logs` block below):
    //
    // * `ic_node_logs_resolved` flips to `true` once we know how to stream,
    //   i.e. once the backend attribute — and, on Local, the `GroupSetup` it
    //   derives from — has been persisted. Until then we don't stream IC node
    //   logs, so that every stream is created with the correct source.
    // * `ic_node_logs_source` is the source address each stream binds to:
    //   `Some` on the Local backend, `None` on Farm (kernel-chosen source).
    //   The GuestOS firewall caps simultaneous connections *per source
    //   address*, so on Local we bind to a *dedicated* per-group address
    //   (distinct from the management address used for all other host→node
    //   traffic); otherwise these long-lived streams would consume a slot that
    //   tests saturating that budget (the firewall `connection_count_test`)
    //   rely on. That address is derived from the group name and assigned to
    //   `lo` by `LocalBackend::create_group`. Farm has no such budget to
    //   protect, so it lets the kernel pick the source.
    let mut ic_node_logs_resolved = false;
    let mut ic_node_logs_source: Option<Ipv6Addr> = None;
    loop {
        match discover_uvms(root_search_dir.clone()) {
            Ok(discovered_uvms) => process_discovered(
                discovered_uvms,
                "uvm",
                &uvm_logs_dir,
                &mut streamed_uvms,
                &mut skipped_uvms,
                &group_ctx.exclude_logs,
                None,
                &rt,
                &logger,
            ),
            Err(err) => {
                warn!(logger, "Discovering deployed uvms failed with err:{err}");
            }
        }

        // IC node log streaming is opt-in via `--stream-ic-node-logs`. Today
        // only the Local backend sets it: it runs in a sandbox without external
        // network access and so has no Vector VM to ship logs to ElasticSearch,
        // and instead streams each IC node's journald directly to the test log.
        // The records persisted under `journald_logs/nodes/` are additionally
        // what the `assert_no_unallowed_log_patterns` teardown scans there.
        // The block below nonetheless handles both backends, so enabling the
        // flag on Farm later streams node logs there too (with a kernel-chosen
        // source). When the flag is unset this whole block is skipped.
        if group_ctx.stream_ic_node_logs {
            // Resolve once how to source the IC node journald streams, based on
            // the active backend. This is lazy because the backend attribute
            // (and, on Local, the `GroupSetup` it derives from) is only
            // persisted once group setup starts.
            if !ic_node_logs_resolved {
                match SystemTestBackend::try_read_attribute(&setup_env) {
                    // On Local, bind each stream to the dedicated per-group
                    // source address (assigned to `lo` by
                    // `LocalBackend::create_group`). Deriving it needs
                    // `GroupSetup`, so we stay unresolved until it is persisted.
                    Ok(SystemTestBackend::Local) => {
                        if let Ok(group_setup) = GroupSetup::try_read_attribute(&setup_env) {
                            let addr = LocalBackend::group_logs_ipv6(&group_setup.infra_group_name);
                            match addr.parse::<Ipv6Addr>() {
                                Ok(addr) => {
                                    ic_node_logs_source = Some(addr);
                                    ic_node_logs_resolved = true;
                                }
                                Err(err) => warn!(
                                    logger,
                                    "Could not parse IC node journald source address {addr:?}: {err}"
                                ),
                            }
                        }
                    }
                    // On Farm there is no per-source firewall budget to
                    // protect, so let the kernel pick the source
                    // (`ic_node_logs_source` stays `None`).
                    Ok(SystemTestBackend::Farm) => ic_node_logs_resolved = true,
                    // The backend attribute isn't persisted yet; retry next loop.
                    Err(_) => {}
                }
            }
            // Once resolved, stream every newly discovered IC node's journald,
            // binding to the dedicated source on Local and letting the kernel
            // pick it on Farm.
            if ic_node_logs_resolved {
                match discover_ic_nodes(&setup_env) {
                    Ok(discovered_nodes) => process_discovered(
                        discovered_nodes,
                        "node",
                        &node_logs_dir,
                        &mut streamed_nodes,
                        &mut skipped_nodes,
                        &group_ctx.exclude_logs,
                        ic_node_logs_source,
                        &rt,
                        &logger,
                    ),
                    Err(err) => {
                        // Until the setup function has written the prep directory
                        // the topology is not yet available; this is expected
                        // early in the run, so we only log it at debug level.
                        debug!(
                            logger,
                            "Discovering IC nodes failed (setup likely not ready yet): {err}"
                        );
                    }
                }
            }
        }

        std::thread::sleep(RETRY_DELAY_DISCOVER_TARGETS);
    }
}

/// Spawns a journald streaming task for every newly discovered target,
/// deduplicating against `streamed` and honoring the `--exclude-logs` patterns
/// (recorded in `skipped`). `kind` is used both as the log-line prefix
/// (e.g. `uvm=<name>` or `node=<id>`) and in informational messages; the
/// records of each target are persisted to `journald_log_path(logs_dir, key)`.
///
/// When `bind_addr` is `Some`, each streaming socket is bound to that local
/// source address before connecting (used for IC nodes on the Local backend, so
/// the persistent stream does not share the management address' per-source
/// firewall connection budget); when `None` the kernel picks the source.
fn process_discovered(
    discovered: HashMap<String, Ipv6Addr>,
    kind: &str,
    logs_dir: &Path,
    streamed: &mut HashMap<String, Ipv6Addr>,
    skipped: &mut BTreeSet<String>,
    exclude_logs: &[Regex],
    bind_addr: Option<Ipv6Addr>,
    rt: &Runtime,
    logger: &Logger,
) {
    for (key, value) in discovered {
        if skipped.contains(&key) {
            continue;
        }

        let key_match = exclude_logs.iter().any(|pattern| pattern.is_match(&key));
        if key_match {
            debug!(
                logger,
                "Skipping journald streaming of [{kind}={key}] because it was excluded by the `--exclude-logs` pattern"
            );
            skipped.insert(key);
            continue;
        }

        streamed.entry(key.clone()).or_insert_with(|| {
            let logger = logger.clone();
            let label = format!("{kind}={key}");
            let log_path = journald_log_path(logs_dir, &key);
            info!(
                logger,
                "Streaming Journald for newly discovered [{label}] with ipv6={value}, persisting records to {}",
                log_path.display()
            );
            // The task starts, but the handle is never joined.
            rt.spawn(stream_journald_with_retries(
                logger,
                label,
                SocketAddr::new(IpAddr::V6(value), JOURNAL_GATEWAYD_PORT),
                bind_addr,
                log_path,
                RETRY_DELAY_JOURNALD_STREAM,
            ));
            value
        });
    }
}

/// Discovers all IC nodes (assigned, unassigned and API boundary nodes) of the
/// no-name Internet Computer by reading the topology snapshot from the setup
/// environment's registry local store. Returns a map from node id to its IPv6
/// address.
fn discover_ic_nodes(env: &TestEnv) -> Result<HashMap<String, Ipv6Addr>> {
    let topology = env.safe_topology_snapshot()?;
    let mut nodes: HashMap<String, Ipv6Addr> = HashMap::new();
    for node in topology
        .subnets()
        .flat_map(|subnet| subnet.nodes())
        .chain(topology.unassigned_nodes())
        .chain(topology.api_boundary_nodes())
    {
        // IC nodes in the system-test infra are addressed via IPv6; an
        // IPv4-only node would not be reachable on the journald gateway port,
        // so we simply skip any such (in practice non-existent) node.
        if let IpAddr::V6(ipv6) = node.get_ip_addr() {
            nodes.insert(node.node_id.to_string(), ipv6);
        }
    }
    Ok(nodes)
}

fn discover_uvms(root_path: PathBuf) -> Result<HashMap<String, Ipv6Addr>> {
    let mut uvms: HashMap<String, Ipv6Addr> = HashMap::new();
    for entry in WalkDir::new(root_path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.path()
                .to_str()
                .map(|p| p.contains(UNIVERSAL_VMS_DIR))
                .unwrap_or(false)
        })
        .filter(|e| {
            let file_name = String::from(e.file_name().to_string_lossy());
            e.file_type().is_file() && file_name == "vm.json"
        })
        .map(|e| e.path().to_owned())
    {
        let file =
            std::fs::File::open(&entry).with_context(|| format!("Could not open: {:?}", entry))?;
        let vm: AllocatedVm = serde_json::from_reader(file)
            .with_context(|| format!("{:?}: Could not read json.", entry))?;
        uvms.insert(vm.name.to_string(), vm.ipv6);
    }
    Ok(uvms)
}

/// A projection of a systemd-journal-gatewayd JSON record.
///
/// This is also the on-disk JSON Lines schema under [`JOURNALD_LOGS_DIR`] (see
/// [`JournalFileSink`]), hence the journald field names via `serde(rename)`.
/// Deserialization accepts both a live gatewayd record (dozens of extra fields,
/// which are ignored, and a possibly non-string `MESSAGE`, see
/// `deserialize_journal_message`) and this struct's own serialized form
/// (plain-string `MESSAGE`, `None` fields omitted).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct JournalRecord {
    #[serde(rename = "__CURSOR")]
    pub(crate) cursor: String,
    /// The journald receive time as a decimal string of microseconds since the
    /// Unix epoch, as gatewayd emits it. This is what Vector turns into the
    /// ElasticSearch `timestamp` field (`assets/vector.toml`).
    #[serde(
        rename = "__REALTIME_TIMESTAMP",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) realtime_timestamp: Option<String>,
    // `MESSAGE` is deserialized leniently: systemd-journal-gatewayd encodes
    // fields that are not valid UTF-8 as an array of byte values, and replaces
    // fields exceeding its size limit with `null`. Without this, large or binary
    // replica log messages would fail to deserialize and be silently dropped
    // (which is historically why IC node logs had to be streamed as plaintext).
    // See `deserialize_journal_message`.
    #[serde(rename = "MESSAGE", deserialize_with = "deserialize_journal_message")]
    pub(crate) message: String,
    #[serde(rename = "_SYSTEMD_UNIT", skip_serializing_if = "Option::is_none")]
    pub(crate) system_unit: Option<String>,
    #[serde(rename = "CONTAINER_NAME", skip_serializing_if = "Option::is_none")]
    pub(crate) container_name: Option<String>,
    #[serde(rename = "_COMM", skip_serializing_if = "Option::is_none")]
    pub(crate) comm: Option<String>,
}

/// Deserializes a journald `MESSAGE` field, which systemd-journal-gatewayd may
/// encode as:
/// * a UTF-8 string (the common case),
/// * an array of byte values (for non-UTF-8 / binary payloads), or
/// * `null` (when the field is too large to be serialized inline).
fn deserialize_journal_message<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct MessageVisitor;

    impl<'de> Visitor<'de> for MessageVisitor {
        type Value = String;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a journald MESSAGE as a string, an array of bytes, or null")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v.to_string())
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok("<MESSAGE omitted: too large to serialize>".to_string())
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok("<MESSAGE omitted: too large to serialize>".to_string())
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut bytes: Vec<u8> = Vec::new();
            while let Some(byte) = seq.next_element::<u8>()? {
                bytes.push(byte);
            }
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }
    }

    deserializer.deserialize_any(MessageVisitor)
}

impl std::fmt::Display for JournalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(ref container) = self.container_name
            && container == COLOCATE_CONTAINER_NAME
        {
            return write!(f, "TEST_LOG: {}", self.message);
        }
        let mut display = format!("message: \"{}\"", self.message);
        if let Some(x) = &self.system_unit {
            display += format!(", system_unit: \"{x}\"").as_str()
        }
        if let Some(x) = &self.container_name {
            display += format!(", container_name: \"{x}\"").as_str()
        }
        if let Some(x) = &self.comm {
            display += format!(", comm: \"{x}\"").as_str()
        }
        write!(f, "JournalRecord {{{display}}}")
    }
}

/// Append-only JSON Lines sink for the records of one streamed target.
///
/// Each record is one `write_all(b"<json>\n")` on an `O_APPEND` `std::fs::File`
/// with no userspace buffer: the `logs_stream` subprocess is SIGKILLed with no
/// flush window once the subtree it supervises finishes (`process.rs`), and the
/// `assert_no_unallowed_log_patterns` teardown scans the file while we are
/// still appending (it runs inside that subtree). `std::fs` rather than
/// `tokio::fs` on purpose: this task's runtime has `max_blocking_threads(1)`,
/// so every `tokio::fs` operation would be a `spawn_blocking` hop serialized
/// through one thread for all streams, whereas a page-cache append takes
/// microseconds — the same trade-off the blocking `println!` already makes.
struct JournalFileSink {
    file: std::fs::File,
}

impl JournalFileSink {
    fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self { file })
    }

    fn append(&mut self, record: &JournalRecord) -> std::io::Result<()> {
        let mut line = serde_json::to_string(record)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())
    }
}

/// Per-target streaming state shared by the retry loop and its connections.
#[derive(Default)]
struct StreamState {
    cursor: Cursor,
    /// Records delivered by the current connection, the skipped checkpoint
    /// record excluded.
    records: u64,
    /// When the last record was received, if any.
    last_record_at: Option<Instant>,
    /// Set once a connection ends or fails, cleared when records flow again.
    outage: Option<Outage>,
}

struct Outage {
    /// Connections attempted since the outage started.
    attempts: u32,
}

/// Streams the journald of `addr` forever: whenever a connection ends or fails,
/// a new one is opened after `retry_delay`, resuming from the last cursor.
async fn stream_journald_with_retries(
    logger: Logger,
    label: String,
    addr: SocketAddr,
    bind_addr: Option<Ipv6Addr>,
    log_path: PathBuf,
    retry_delay: Duration,
) {
    let mut state = StreamState::default();
    // The last failure that was logged; a repeat of it is logged only every
    // `REPEATED_FAILURE_LOG_EVERY` attempts.
    let mut last_err: Option<String> = None;
    loop {
        state.records = 0;
        let result =
            stream_journald_from_cursor(&logger, &label, addr, bind_addr, &log_path, &mut state)
                .await;
        if state.records > 0 {
            // The connection was healthy for a while: a later failure, even with
            // the same text as the last one, is a new outage worth a line.
            last_err = None;
        }
        let outage = state.outage.get_or_insert(Outage { attempts: 0 });
        outage.attempts += 1;
        let from = match state.cursor {
            Cursor::Start => "the beginning",
            Cursor::Position(_) => "the last cursor",
        };
        let delay = retry_delay.as_secs();
        match result {
            Ok(()) => {
                warn!(
                    logger,
                    "Journald stream of [{label}] ended: peer closed the connection after {} record(s); reconnecting from {from} in {delay}s",
                    state.records
                );
                last_err = None;
            }
            Err(err) => {
                let err = format!("{err:#}");
                if last_err.as_deref() != Some(err.as_str())
                    || outage.attempts.is_multiple_of(REPEATED_FAILURE_LOG_EVERY)
                {
                    warn!(
                        logger,
                        "Journald stream of [{label}] failed after {} record(s): {err}; reconnecting from {from} every {delay}s until it succeeds",
                        state.records
                    );
                    last_err = Some(err);
                }
            }
        }
        tokio::time::sleep(retry_delay).await;
    }
}

/// `Start` is the empty cursor, i.e. the beginning of the journal.
#[derive(Default)]
enum Cursor {
    #[default]
    Start,
    Position(String),
}

impl std::fmt::Display for Cursor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Cursor::Start => write!(f, ""),
            Cursor::Position(x) => write!(f, "{x}"),
        }
    }
}

/// Connects to the journald gateway at `addr` with TCP keepalive enabled,
/// binding the socket to `bind_addr` first when given.
async fn connect_journald(addr: SocketAddr, bind_addr: Option<Ipv6Addr>) -> Result<TcpStream> {
    let socket = TcpSocket::new_v6()?;
    configure_keepalive(&socket).context("configuring TCP keepalive")?;
    // Bind the stream to its dedicated source address (when set) so it does not
    // share the management address' per-source firewall connection budget; see
    // `LocalBackend::group_logs_ipv6`. Port 0 lets the kernel pick an ephemeral
    // source port.
    if let Some(bind_addr) = bind_addr {
        socket
            .bind(SocketAddr::new(bind_addr.into(), 0))
            .with_context(|| format!("binding to {bind_addr}"))?;
    }
    tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("timed out after {}s", CONNECT_TIMEOUT.as_secs()))
        .and_then(|result| result.map_err(anyhow::Error::from))
        .with_context(|| format!("connecting to {addr}"))
}

fn configure_keepalive(socket: &TcpSocket) -> nix::Result<()> {
    setsockopt(socket, sockopt::KeepAlive, &true)?;
    setsockopt(
        socket,
        sockopt::TcpKeepIdle,
        &(KEEPALIVE_IDLE.as_secs() as u32),
    )?;
    setsockopt(
        socket,
        sockopt::TcpKeepInterval,
        &(KEEPALIVE_INTERVAL.as_secs() as u32),
    )?;
    setsockopt(socket, sockopt::TcpKeepCount, &KEEPALIVE_COUNT)
}

/// One connection: streams records from `state.cursor` (advanced as records
/// arrive) until the peer closes the connection (`Ok`) or it fails (`Err`).
async fn stream_journald_from_cursor(
    logger: &Logger,
    label: &str,
    addr: SocketAddr,
    bind_addr: Option<Ipv6Addr>,
    log_path: &Path,
    state: &mut StreamState,
) -> Result<()> {
    // Persist the records of this connection to disk. Persistence must never
    // break the pre-existing streaming to stdout, so an open failure only
    // disables it until the next reconnect re-opens the file.
    let mut sink = match JournalFileSink::open(log_path) {
        Ok(sink) => Some(sink),
        Err(err) => {
            warn!(
                logger,
                "Not persisting journald records of [{label}] to {}: {err}",
                log_path.display()
            );
            None
        }
    };
    let mut stream = connect_journald(addr, bind_addr).await?;
    stream.write_all(b"GET /entries?follow HTTP/1.1\n").await?;
    stream.write_all(b"Accept: application/json\n").await?;
    stream
        .write_all(format!("Host: {}:{}\n", addr.ip(), addr.port()).as_bytes())
        .await?;
    stream
        .write_all(format!("Range: entries={}\n\r\n\r", state.cursor).as_bytes())
        .await?;
    let mut lines = BufReader::new(stream).lines();
    while let Some(line) = lines.next_line().await? {
        let Ok(record) = serde_json::from_str::<JournalRecord>(&line) else {
            continue;
        };
        // `entries=<cursor>` is inclusive: skip the re-emitted checkpoint record.
        if state.records == 0
            && let Cursor::Position(checkpoint) = &state.cursor
            && *checkpoint == record.cursor
        {
            continue;
        }
        if let Some(outage) = state.outage.take() {
            match state.last_record_at {
                Some(last_record_at) => info!(
                    logger,
                    "Journald stream of [{label}] resumed after {} attempt(s), {}s after its last record",
                    outage.attempts,
                    last_record_at.elapsed().as_secs()
                ),
                None => info!(
                    logger,
                    "Journald stream of [{label}] started after {} attempt(s)", outage.attempts
                ),
            }
        }
        if let Some(s) = sink.as_mut()
            && let Err(err) = s.append(&record)
        {
            // Warn once per connection (e.g. disk full); the next reconnect
            // re-opens the file and tries again.
            warn!(
                logger,
                "Stopped persisting journald records of [{label}] to {}: {err}",
                log_path.display()
            );
            sink = None;
        }
        println!("[{label}] {record}");
        state.records += 1;
        state.last_record_at = Some(Instant::now());
        state.cursor = Cursor::Position(record.cursor);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::getsockopt;
    use slog::o;
    use std::io::{BufRead, Read};
    use std::sync::mpsc::{Sender, channel};

    const GATEWAYD_RECORD: &str = r#"{"__CURSOR":"s=abc;i=1","__REALTIME_TIMESTAMP":"1700000000123456","__MONOTONIC_TIMESTAMP":"12345","_BOOT_ID":"b","_HOSTNAME":"guestos","PRIORITY":"6","_SYSTEMD_UNIT":"ic-replica.service","_COMM":"replica","SYSLOG_IDENTIFIER":"orchestrator","MESSAGE":"hello"}"#;

    fn record(cursor: &str, message: &str) -> JournalRecord {
        JournalRecord {
            cursor: cursor.to_string(),
            realtime_timestamp: None,
            message: message.to_string(),
            system_unit: None,
            container_name: None,
            comm: None,
        }
    }

    #[test]
    fn journal_record_deserializes_gatewayd_record_and_ignores_unknown_fields() {
        let record: JournalRecord = serde_json::from_str(GATEWAYD_RECORD).unwrap();
        assert_eq!(
            record,
            JournalRecord {
                cursor: "s=abc;i=1".to_string(),
                realtime_timestamp: Some("1700000000123456".to_string()),
                message: "hello".to_string(),
                system_unit: Some("ic-replica.service".to_string()),
                container_name: None,
                comm: Some("replica".to_string()),
            }
        );
    }

    #[test]
    fn journal_record_deserializes_byte_array_message_lossily() {
        let record: JournalRecord =
            serde_json::from_str(r#"{"__CURSOR":"c","MESSAGE":[104,105,255]}"#).unwrap();
        assert_eq!(record.message, "hi\u{FFFD}");
        assert_eq!(record.realtime_timestamp, None);
    }

    #[test]
    fn journal_record_deserializes_null_message_as_sentinel() {
        let record: JournalRecord =
            serde_json::from_str(r#"{"__CURSOR":"c","MESSAGE":null}"#).unwrap();
        assert_eq!(record.message, "<MESSAGE omitted: too large to serialize>");
    }

    #[test]
    fn journal_record_serializes_with_journald_field_names_on_one_line() {
        let mut record = record("c", "two\nlines");
        record.realtime_timestamp = Some("1".to_string());
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains('\n'));
        assert_eq!(
            json,
            r#"{"__CURSOR":"c","__REALTIME_TIMESTAMP":"1","MESSAGE":"two\nlines"}"#
        );
    }

    #[test]
    fn journal_record_round_trips_through_json() {
        let all_some = JournalRecord {
            cursor: "c".to_string(),
            realtime_timestamp: Some("1".to_string()),
            message: "m".to_string(),
            system_unit: Some("u".to_string()),
            container_name: Some("n".to_string()),
            comm: Some("x".to_string()),
        };
        for record in [all_some, record("c", "")] {
            let json = serde_json::to_string(&record).unwrap();
            assert_eq!(
                serde_json::from_str::<JournalRecord>(&json).unwrap(),
                record
            );
        }
    }

    #[test]
    fn journal_file_sink_appends_one_line_per_record_across_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes").join("node-1.jsonl");
        JournalFileSink::open(&path)
            .unwrap()
            .append(&record("c1", "m1"))
            .unwrap();
        JournalFileSink::open(&path)
            .unwrap()
            .append(&record("c2", "m2"))
            .unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.ends_with('\n'));
        let records: Vec<JournalRecord> = contents
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records, vec![record("c1", "m1"), record("c2", "m2")]);
    }

    #[test]
    fn journal_file_sink_append_fails_on_read_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ro.jsonl");
        std::fs::write(&path, b"").unwrap();
        let mut sink = JournalFileSink {
            file: std::fs::File::open(&path).unwrap(),
        };
        assert!(sink.append(&record("c", "m")).is_err());
    }

    #[test]
    fn journald_log_path_layout_and_sanitization() {
        let group_dir = Path::new("/g");
        assert_eq!(
            journald_node_logs_dir(group_dir),
            PathBuf::from("/g/journald_logs/nodes")
        );
        assert_eq!(
            journald_uvm_logs_dir(group_dir),
            PathBuf::from("/g/journald_logs/uvms")
        );
        assert_eq!(
            journald_log_path(&journald_node_logs_dir(group_dir), "2vxsx-fae"),
            PathBuf::from("/g/journald_logs/nodes/2vxsx-fae.jsonl")
        );
        assert_eq!(
            journald_log_path(&journald_uvm_logs_dir(group_dir), "my vm/1"),
            PathBuf::from("/g/journald_logs/uvms/my-vm-1.jsonl")
        );
    }

    #[test]
    fn connect_journald_enables_keepalive() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
            let stream = connect_journald(listener.local_addr().unwrap(), None)
                .await
                .unwrap();
            assert!(getsockopt(&stream, sockopt::KeepAlive).unwrap());
            assert_eq!(
                getsockopt(&stream, sockopt::TcpKeepIdle).unwrap(),
                KEEPALIVE_IDLE.as_secs() as u32
            );
            assert_eq!(
                getsockopt(&stream, sockopt::TcpKeepInterval).unwrap(),
                KEEPALIVE_INTERVAL.as_secs() as u32
            );
            assert_eq!(
                getsockopt(&stream, sockopt::TcpKeepCount).unwrap(),
                KEEPALIVE_COUNT
            );
        });
    }

    /// A gatewayd stand-in on `[::1]`: per connection it reads the request up to
    /// the `Range` header, reports the requested cursor on `ranges`, writes the
    /// scripted response and closes the connection, except for the last script
    /// entry, which it holds open like a real `follow` stream.
    fn spawn_fake_gatewayd(scripts: &'static [&'static str], ranges: Sender<String>) -> SocketAddr {
        let listener = std::net::TcpListener::bind("[::1]:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let last = scripts.len() - 1;
            for (i, script) in scripts.iter().enumerate() {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = std::io::BufReader::new(stream);
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap() == 0 {
                        return;
                    }
                    if let Some(range) = line.trim().strip_prefix("Range: entries=") {
                        ranges.send(range.to_string()).unwrap();
                        break;
                    }
                }
                let mut stream = reader.into_inner();
                stream.write_all(script.as_bytes()).unwrap();
                if i == last {
                    let _ = stream.read_to_end(&mut Vec::new());
                }
            }
        });
        addr
    }

    #[test]
    fn stream_reconnects_from_last_cursor_without_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("n1.jsonl");
        let (ranges_tx, ranges) = channel();
        let addr = spawn_fake_gatewayd(
            &[
                "HTTP/1.1 200 OK\r\n\r\n{\"__CURSOR\":\"c1\",\"MESSAGE\":\"m1\"}\n{\"__CURSOR\":\"c2\",\"MESSAGE\":\"m2\"}\n",
                // The reconnect re-emits the checkpoint record `c2`.
                "HTTP/1.1 200 OK\r\n\r\n{\"__CURSOR\":\"c2\",\"MESSAGE\":\"m2\"}\n{\"__CURSOR\":\"c3\",\"MESSAGE\":\"m3\"}\n",
            ],
            ranges_tx,
        );
        let rt = Runtime::new().unwrap();
        rt.spawn(stream_journald_with_retries(
            Logger::root(slog::Discard, o!()),
            "node=n1".to_string(),
            addr,
            None,
            log_path.clone(),
            Duration::from_millis(10),
        ));
        let next_range = || ranges.recv_timeout(Duration::from_secs(30)).unwrap();
        assert_eq!(next_range(), "");
        assert_eq!(next_range(), "c2");
        let deadline = Instant::now() + Duration::from_secs(30);
        let messages = loop {
            let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
            // Lines are appended concurrently; a torn last line is simply not ready yet.
            let messages: Vec<String> = contents
                .lines()
                .filter_map(|line| serde_json::from_str::<JournalRecord>(line).ok())
                .map(|record| record.message)
                .collect();
            if messages.len() >= 3 || Instant::now() > deadline {
                break messages;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(messages, vec!["m1", "m2", "m3"]);
    }
}
