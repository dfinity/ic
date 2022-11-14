//! An experimental component that allows scraping logs using the http-endpoint
//! exposed by systemd-journal-gatewayd.
use std::collections::{btree_map::Entry, BTreeMap};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fs::File, sync::Arc};

use ic_types::NodeId;
use slog::{info, warn};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use service_discovery::{IcServiceDiscovery, TargetGroup};

pub async fn scrape_logs<F>(
    log: slog::Logger,
    scraper: Arc<dyn IcServiceDiscovery>,
    filter: Option<String>,
    out_file: File,
    shutdown_signal: F,
    job_name: &'static str,
) where
    F: Future<Output = ()>,
{
    let f = parse_filter(filter);
    let mut target_map = BTreeMap::<NodeId, LogScraper>::new();
    let (out_sender, out_receiver) = tokio::sync::mpsc::unbounded_channel::<String>();

    let should_run = Arc::new(AtomicBool::new(true));

    let mut tasks = vec![];
    tasks.push(tokio::task::spawn(file_sink(
        log.clone(),
        out_receiver,
        out_file,
        should_run.clone(),
    )));

    tasks.push(tokio::task::spawn({
        let should_run = should_run.clone();
        let log = log.clone();
        async move {
            while should_run.load(Ordering::Relaxed) {
                let mut cur_targets = match scraper.get_target_groups(job_name) {
                    Ok(targets) => targets,
                    Err(e) => {
                        warn!(log, "Could not fetch targets: {:?}", e);
                        continue;
                    }
                };

                cur_targets.retain(&f);

                // adjust targets
                for t in &cur_targets {
                    if let Entry::Vacant(e) = target_map.entry(t.node_id) {
                        let log = log.clone();
                        e.insert(LogScraper::start(log, out_sender.clone(), t.clone()).await);
                    }
                }

                let stopped_scrapers = target_map
                    .keys()
                    .filter(|k| !cur_targets.iter().any(|t| t.node_id == **k))
                    .map(|n| n.to_owned())
                    .collect::<Vec<_>>();

                for n in stopped_scrapers {
                    let s = target_map.remove(&n).unwrap();
                    if let Err(e) = s.stop().await {
                        warn!(log, "Error when stopping scraper task: {:?}", e);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        }
    }));

    shutdown_signal.await;
    should_run.store(false, Ordering::Relaxed);

    for jh in tasks {
        if let Err(e) = jh.await {
            warn!(log, "Task returned error: {:?}", e);
        }
    }
}

fn parse_filter(filter: Option<String>) -> impl Fn(&TargetGroup) -> bool {
    move |p: &TargetGroup| {
        if let Some(filter) = &filter {
            let mut parts = filter.split('=');
            let key = parts.next().unwrap().to_string();
            let value = parts.next().unwrap().to_string();
            if key == "node_id" {
                p.node_id.to_string() == value
            } else {
                p.subnet_id
                    .map(|s| s.to_string() == value)
                    .unwrap_or_default()
            }
        } else {
            true
        }
    }
}

struct LogScraper {
    should_run: Arc<AtomicBool>,
    join_handle: JoinHandle<std::io::Result<()>>,
}

impl LogScraper {
    async fn start(log: slog::Logger, out: UnboundedSender<String>, p_target: TargetGroup) -> Self {
        let mut socket_addr = *p_target.targets.iter().next().expect("no targets!");
        socket_addr.set_port(19531);
        let should_run = Arc::new(AtomicBool::new(true));
        let join_handle = tokio::task::spawn({
            let should_run = should_run.clone();
            async move {
                let socket = TcpSocket::new_v6()?;
                let mut stream = socket.connect(socket_addr).await?;

                stream.write_all(b"GET /entries?follow HTTP/1.1\n").await?;
                stream.write_all(b"Accept: application/json\n").await?;
                stream.write_all(b"Range: entries=:-1:\n\r\n\r").await?;

                let bf = BufReader::new(stream);
                let mut lines = bf.lines();

                info!(log, "Connection to {} established.", &p_target.node_id);
                while should_run.load(Ordering::Relaxed) {
                    if let Some(line) = lines.next_line().await? {
                        if let Some('{') = line.chars().next() {
                            let line = annotate_with(line, &p_target);
                            out.send(line).unwrap();
                        }
                    } else {
                        break;
                    }
                }
                Ok(())
            }
        });

        Self {
            should_run,
            join_handle,
        }
    }

    async fn stop(self) -> std::io::Result<()> {
        let _ = self.should_run.store(false, Ordering::Relaxed);
        self.join_handle.await?
    }
}

async fn file_sink(
    log: slog::Logger,
    mut chan: UnboundedReceiver<String>,
    f: File,
    should_run: Arc<AtomicBool>,
) {
    let mut f = tokio::fs::File::from_std(f);
    while should_run.load(Ordering::Relaxed) {
        if let Some(mut line) = chan.recv().await {
            line.push('\n');
            if let Err(e) = f.write_all(line.as_bytes()).await {
                warn!(log, "Failed to write log line to file: {:?}", e);
            }
        } else {
            break;
        }
    }
}

/// If `log_line` contains a String ending in '}', inserts the node_id and
/// subnet_id as key-value serialization in the second-to-last position and
/// returns the new string.
fn annotate_with(mut log_line: String, p: &TargetGroup) -> String {
    let n = log_line.len();
    if log_line.ends_with('}') {
        let subnet_id = p.subnet_id.map(|s| s.to_string()).unwrap_or_default();
        let node_id = p.node_id.to_string();
        let dc_id = match p.dc_id.as_ref() {
            Some(id) => id.clone(),
            None => String::from(""),
        };
        let operator_id = p.operator_id.map(|s| s.to_string()).unwrap_or_default();
        let entries = format!(",\"node_id\": \"{node_id}\",\"subnet_id\": \"{subnet_id}\", \"dc_id\": \"{dc_id}\", \"operator_id\": \"{operator_id}\"");
        log_line.insert_str(n - 1, &entries);
    }
    log_line
}
