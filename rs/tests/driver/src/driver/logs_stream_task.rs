//! Streams journald logs from a system test's deployed machines into the test
//! log. A background task (`logs_stream_task`) periodically discovers the
//! group's universal VMs (and, when `--stream-ic-node-logs` is set, its IC
//! nodes) and, for every newly discovered target, opens a long-lived
//! `follow` connection to that machine's systemd-journal-gatewayd over IPv6.
//! Each journald record received is parsed and printed to stdout so it appears
//! inline in the test output. Targets matching an `--exclude-logs` pattern are
//! skipped, streams resume from the last cursor after transient failures, and
//! on the Local backend IC node streams bind to a dedicated per-group source
//! address to avoid exhausting the GuestOS per-source firewall connection
//! budget.

use crate::driver::{
    constants::{COLOCATE_CONTAINER_NAME, GROUP_SETUP_DIR},
    context::GroupContext,
    local_backend::LocalBackend,
    resource::AllocatedVm,
    test_env::{TestEnv, TestEnvAttribute},
    test_env_api::{HasTopologySnapshot, IcNodeContainer},
    test_setup::{GroupSetup, SystemTestBackend},
    universal_vm::UNIVERSAL_VMS_DIR,
};
use anyhow::{Context, Result};
use regex::Regex;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};
use slog::{Logger, debug, error, info, warn};
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpSocket,
    runtime::Runtime,
};
use walkdir::WalkDir;

pub(crate) const LOGS_STREAM_TASK_NAME: &str = "logs_stream";

const RETRY_DELAY_JOURNALD_STREAM: Duration = Duration::from_secs(5);
const RETRY_DELAY_DISCOVER_TARGETS: Duration = Duration::from_secs(5);

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
/// (e.g. `uvm=<name>` or `node=<id>`) and in informational messages.
///
/// When `bind_addr` is `Some`, each streaming socket is bound to that local
/// source address before connecting (used for IC nodes on the Local backend, so
/// the persistent stream does not share the management address' per-source
/// firewall connection budget); when `None` the kernel picks the source.
fn process_discovered(
    discovered: HashMap<String, Ipv6Addr>,
    kind: &str,
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
            info!(
                logger,
                "Streaming Journald for newly discovered [{label}] with ipv6={value}"
            );
            // The task starts, but the handle is never joined.
            rt.spawn(stream_journald_with_retries(
                logger, label, value, bind_addr,
            ));
            value
        });
    }
}

/// Discovers all IC nodes (assigned and unassigned) of the no-name Internet
/// Computer by reading the topology snapshot from the setup environment's
/// registry local store. Returns a map from node id to its IPv6 address.
fn discover_ic_nodes(env: &TestEnv) -> Result<HashMap<String, Ipv6Addr>> {
    let topology = env.safe_topology_snapshot()?;
    let mut nodes: HashMap<String, Ipv6Addr> = HashMap::new();
    for node in topology
        .subnets()
        .flat_map(|subnet| subnet.nodes())
        .chain(topology.unassigned_nodes())
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

#[derive(Debug, Deserialize)]
struct JournalRecord {
    #[serde(rename = "__CURSOR")]
    cursor: String,
    // `MESSAGE` is deserialized leniently: systemd-journal-gatewayd encodes
    // fields that are not valid UTF-8 as an array of byte values, and replaces
    // fields exceeding its size limit with `null`. Without this, large or binary
    // replica log messages would fail to deserialize and be silently dropped
    // (which is historically why IC node logs had to be streamed as plaintext).
    // See `deserialize_journal_message`.
    #[serde(rename = "MESSAGE", deserialize_with = "deserialize_journal_message")]
    message: String,
    #[serde(rename = "_SYSTEMD_UNIT")]
    system_unit: Option<String>,
    #[serde(rename = "CONTAINER_NAME")]
    container_name: Option<String>,
    #[serde(rename = "_COMM")]
    comm: Option<String>,
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

async fn stream_journald_with_retries(
    logger: slog::Logger,
    label: String,
    ipv6: Ipv6Addr,
    bind_addr: Option<Ipv6Addr>,
) {
    // Start streaming Journald from the very beginning, which corresponds to the cursor="".
    let mut cursor = Cursor::Start;
    loop {
        // In normal scenarios, i.e. without errors/interrupts, the function below should never return.
        // In case it returns unexpectedly, we restart reading logs from the checkpoint cursor.
        let (cursor_next, result) =
            stream_journald_from_cursor(label.clone(), ipv6, cursor, bind_addr).await;
        cursor = cursor_next;
        if let Err(err) = result {
            error!(
                logger,
                "Streaming Journald for {label} with ipv6={ipv6} failed with: {err}"
            );
        }
        // Should we stop reading Journald here?
        warn!(
            logger,
            "All entries of Journald are read to completion. Streaming Journald will start again in {} sec ...",
            RETRY_DELAY_JOURNALD_STREAM.as_secs()
        );
        tokio::time::sleep(RETRY_DELAY_JOURNALD_STREAM).await;
    }
}

enum Cursor {
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

macro_rules! unwrap_or_return {
    ( $val1:expr_2021, $val2:expr_2021 ) => {
        match $val2 {
            Ok(x) => x,
            Err(x) => return ($val1, Err(x.into())),
        }
    };
}

async fn stream_journald_from_cursor(
    label: String,
    ipv6: Ipv6Addr,
    mut cursor: Cursor,
    bind_addr: Option<Ipv6Addr>,
) -> (Cursor, anyhow::Result<()>) {
    let socket_addr = std::net::SocketAddr::new(ipv6.into(), 19531);
    let socket = unwrap_or_return!(cursor, TcpSocket::new_v6());
    // Bind the stream to its dedicated source address (when set) so it does not
    // share the management address' per-source firewall connection budget; see
    // `LocalBackend::group_logs_ipv6`. Port 0 lets the kernel pick an ephemeral
    // source port.
    if let Some(bind_addr) = bind_addr {
        unwrap_or_return!(
            cursor,
            socket.bind(std::net::SocketAddr::new(bind_addr.into(), 0))
        );
    }
    let mut stream = unwrap_or_return!(cursor, socket.connect(socket_addr).await);
    unwrap_or_return!(
        cursor,
        stream.write_all(b"GET /entries?follow HTTP/1.1\n").await
    );
    unwrap_or_return!(
        cursor,
        stream.write_all(b"Accept: application/json\n").await
    );
    unwrap_or_return!(
        cursor,
        stream
            .write_all(format!("Host: {ipv6}:19531\n").as_bytes())
            .await
    );
    unwrap_or_return!(
        cursor,
        stream
            .write_all(format!("Range: entries={cursor}\n\r\n\r").as_bytes())
            .await
    );
    let buf_reader = BufReader::new(stream);
    let mut lines = buf_reader.lines();
    while let Some(line) = unwrap_or_return!(cursor, lines.next_line().await) {
        let record_result: Result<JournalRecord, serde_json::Error> = serde_json::from_str(&line);
        if let Ok(record) = record_result {
            println!("[{label}] {record}");
            // We update the cursor value, so that in case function errors, journald entries can be streamed from this checkpoint.
            cursor = Cursor::Position(record.cursor);
        }
    }
    (cursor, Ok(()))
}
