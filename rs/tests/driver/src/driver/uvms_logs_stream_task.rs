use crate::driver::{
    constants::COLOCATE_CONTAINER_NAME, context::GroupContext, resource::AllocatedVm,
    universal_vm::UNIVERSAL_VMS_DIR,
};
use anyhow::{Context, Result};
use serde::Deserialize;
use slog::{debug, error, info, warn};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;
use std::{collections::HashMap, net::Ipv6Addr};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpSocket,
    runtime::Runtime,
};
use walkdir::WalkDir;

pub(crate) const UVMS_LOGS_STREAM_TASK_NAME: &str = "uvms_logs_stream";

const RETRY_DELAY_JOURNALD_STREAM: Duration = Duration::from_secs(5);
const RETRY_DELAY_DISCOVER_UVMS: Duration = Duration::from_secs(5);

pub(crate) fn uvms_logs_stream_task(group_ctx: GroupContext) -> () {
    let logger = group_ctx.logger().clone();
    debug!(logger, ">>> {UVMS_LOGS_STREAM_TASK_NAME}");
    let rt: Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("Could not create tokio runtime: {err}"));
    let root_search_dir = {
        let root_env = group_ctx
            .clone()
            .get_root_env()
            .expect("root_env should already exist");
        let base_path = root_env.base_path();
        base_path
            .parent()
            .expect("root_env dir should have a parent dir")
            .to_path_buf()
    };
    let mut streamed_uvms: HashMap<String, Ipv6Addr> = HashMap::new();
    let mut skipped_uvms: BTreeSet<String> = BTreeSet::new();
    loop {
        match discover_uvms(root_search_dir.clone()) {
            Ok(discovered_uvms) => {
                for (key, value) in discovered_uvms {
                    if skipped_uvms.contains(&key) {
                        continue;
                    }

                    let key_match = group_ctx
                        .exclude_logs
                        .iter()
                        .any(|pattern| pattern.is_match(&key));

                    if key_match {
                        debug!(
                            logger,
                            "Skipping journald streaming of [uvm={key}] because it was excluded by the `--exclude-logs` pattern"
                        );
                        skipped_uvms.insert(key);
                        continue;
                    }

                    streamed_uvms.entry(key.clone()).or_insert_with(|| {
                        let logger = logger.clone();
                        info!(
                            logger,
                            "Streaming Journald for newly discovered [uvm={key}] with ipv6={value}"
                        );
                        // The task starts, but the handle is never joined.
                        rt.spawn(stream_journald_with_retries(logger, key.clone(), value));
                        value
                    });
                }
            }
            Err(err) => {
                warn!(logger, "Discovering deployed uvms failed with err:{err}");
            }
        }
        std::thread::sleep(RETRY_DELAY_DISCOVER_UVMS);
    }
}

#[derive(Debug, Deserialize)]
struct JournalRecord {
    #[serde(rename = "__CURSOR")]
    cursor: String,
    #[serde(rename = "MESSAGE")]
    message: String,
    #[serde(rename = "_SYSTEMD_UNIT")]
    system_unit: Option<String>,
    #[serde(rename = "CONTAINER_NAME")]
    container_name: Option<String>,
    #[serde(rename = "_COMM")]
    comm: Option<String>,
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
            std::fs::File::open(&entry).with_context(|| format!("Could not open: {:?}", &entry))?;
        let vm: AllocatedVm = serde_json::from_reader(file)
            .with_context(|| format!("{:?}: Could not read json.", &entry))?;
        uvms.insert(vm.name.to_string(), vm.ipv6);
    }
    Ok(uvms)
}

async fn stream_journald_with_retries(logger: slog::Logger, uvm_name: String, ipv6: Ipv6Addr) {
    // Start streaming Journald from the very beginning, which corresponds to the cursor="".
    let mut cursor = Cursor::Start;
    loop {
        // In normal scenarios, i.e. without errors/interrupts, the function below should never return.
        // In case it returns unexpectedly, we restart reading logs from the checkpoint cursor.
        let (cursor_next, result) =
            stream_journald_from_cursor(uvm_name.clone(), ipv6, cursor).await;
        cursor = cursor_next;
        if let Err(err) = result {
            error!(
                logger,
                "Streaming Journald for uvm={uvm_name} with ipv6={ipv6} failed with: {err}"
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
    uvm_name: String,
    ipv6: Ipv6Addr,
    mut cursor: Cursor,
) -> (Cursor, anyhow::Result<()>) {
    let socket_addr = std::net::SocketAddr::new(ipv6.into(), 19531);
    let socket = unwrap_or_return!(cursor, TcpSocket::new_v6());
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
            println!("[uvm={uvm_name}] {record}");
            // We update the cursor value, so that in case function errors, journald entries can be streamed from this checkpoint.
            cursor = Cursor::Position(record.cursor);
        }
    }
    (cursor, Ok(()))
}
