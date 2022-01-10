#![allow(dead_code)]
#![allow(unreachable_code)]
#![allow(unused_variables)]
use nix::unistd::Pid;
use std::collections::BTreeMap;
use std::ops::Deref;
use std::path::PathBuf;
use std::process;
use std::sync::{Arc, Mutex, RwLock};
use url::Url;

use ic_prep_lib::prep_state_directory::IcPrepStateDir;
use ic_protobuf::log::log_entry::v1::LogEntry;

use slog::{debug, o, Logger};
mod inner;

use crate::ic_instance::InternetComputer;
pub mod buffered_reader;
pub mod handle;
pub mod process_pool;
use crate::mio::InputSource;
use crossbeam_channel::unbounded;
pub use handle::{FarmInfo, IcControl, IcEndpoint, IcHandle, IcSubnet, RuntimeDescriptor};
pub use inner::*;
use std::collections::BTreeSet;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::time::Instant;

/// The [Event]s produced by the [IcManager], which are subsequently
/// fed into the passive pipeline are either events from a replica or
/// a fondue's [Event].
#[derive(Debug, Clone)]
pub enum Event {
    FromPid(Pid, NodeEvent),
    Stop(i32),
}

/// Replica events are a natural extension of [process_pool::Event],
/// but it carries parsed log entries instead of raw output lines
/// whenever these can be parsed. By fondue's requirement,
/// it needs two injections implemented by the means of `From`
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", content = "event")]
pub enum NodeEvent {
    Log {
        src: InputSource,
        log_entry: LogEntry,
    },
    OutputLine {
        src: InputSource,
        line: String,
    },
    Exited {
        #[serde(serialize_with = "serialize_status")]
        status: process::ExitStatus,
    },
}

fn serialize_status<S>(status: &process::ExitStatus, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_i32(status.code().expect("missing status code"))
}

/// Injects a [process_pool::Event] into a [IcManager] [Event]. This is
/// done by attempting to parse every output line as a log entry.
impl From<process_pool::Event> for Event {
    fn from(ev: process_pool::Event) -> Self {
        match ev {
            process_pool::Event::Signal(sig) => Event::Stop(sig),
            process_pool::Event::ChildEvent(pid, e) => Event::FromPid(
                pid,
                match e {
                    process_pool::ChildEvent::Exited { status } => NodeEvent::Exited { status },
                    process_pool::ChildEvent::Line { src, line } => {
                        // Tries to parse the output line as a `LogEntryLine` (check
                        // the comments for `LogEntryLine` for why that type even exists) and,
                        // if we succeed, make it into a event.
                        if let Ok(le) = serde_json::from_str::<LogEntryLine>(&line) {
                            NodeEvent::Log {
                                src,
                                log_entry: le.log_entry,
                            }
                        } else {
                            NodeEvent::OutputLine { src, line }
                        }
                    }
                },
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IcManagerSettings {
    pub tee_replica_logs_base_dir: Option<PathBuf>,
    pub existing_endpoints: Option<Vec<IcEndpoint>>,
}

impl Default for IcManagerSettings {
    fn default() -> Self {
        IcManagerSettings {
            tee_replica_logs_base_dir: None,
            existing_endpoints: None,
        }
    }
}

impl IcManagerSettings {
    pub fn request_handle(&self) -> Option<IcHandle> {
        // false positive: Option::map can't return a trait object
        #[allow(clippy::manual_map)]
        match &self.existing_endpoints {
            Some(public_api_endpoints) => Some(IcHandle {
                public_api_endpoints: public_api_endpoints.clone(),
                malicious_public_api_endpoints: vec![],
                ic_prep_working_dir: None,
            }),
            None => None,
        }
    }
}

/// Finally, the [IcManager] is a valid [Manager]
impl IcManager {
    pub fn start(
        pot_name: String,
        settings: IcManagerSettings,
        cfg: InternetComputer,
        parent_logger: &Logger,
    ) -> Self {
        let logger = parent_logger.new(o!("where" => "ic_manager"));
        // Self::Config -> IO [ProcConfig]
        // in words, we identify the processes that we need to launch for a given IC
        // configuration and prepare the environment.
        let prep_working_dir = tempfile::tempdir().expect("Could not create temporary directory");
        let node_commands = Self::synthesize_ic_commands(&logger, &cfg, &prep_working_dir);
        let pipeline_logger = parent_logger.new(o!("where" => "endpoint_pipeline"));

        // we send pending events to this channel
        let logger_clone = logger.clone();

        let (send, rec) = unbounded();

        let (procman, registry) = process_pool::process_pool(node_commands, &logger, move || {
            let logs_writer = settings.tee_replica_logs_base_dir.clone().map(|mut dir| {
                dir.push(pot_name);
                create_dir_all(&dir).expect("could not create a replica logs base dir");
                LogsWriter::new(dir)
            });

            Box::new(move |ev: Event| {
                let logs_writer = logs_writer.clone();
                match &ev {
                    Event::FromPid(pid, nev) => {
                        let src = match &nev {
                            NodeEvent::Log { src, log_entry: _ }
                            | NodeEvent::OutputLine { src, line: _ } => src,
                            NodeEvent::Exited { status: _ } => &InputSource::Stdout,
                        };
                        if let Some(mut w) = logs_writer {
                            w.write(pid, src, nev);
                        }

                        if let NodeEvent::OutputLine { src, line } = nev {
                            debug!(
                                logger_clone,
                                "Unstructured line from {:?} on {:?}: {:?}", pid, src, line
                            );
                        };
                    }
                    Event::Stop(sig) => {
                        send.send(Some(*sig)).unwrap();
                    }
                }
            })
        });

        // we assume all PIDs are properly registered at this point
        let malicious_pids: BTreeSet<Pid> = procman
            .configs
            .iter()
            .filter_map(|(pid, cfg)| {
                if cfg.is_malicious {
                    return Some(*pid);
                }
                None
            })
            .collect();

        IcManager {
            inner: Arc::new(RwLock::new(IcManagerInner::new(procman, registry))),
            prep_working_dir: Arc::new(prep_working_dir),
            malicious_pids,
            logger,
            signal_receiver: Arc::new(RwLock::new(rec)),
        }
    }

    pub fn wait_for_signal(&self) -> Option<i32> {
        let receiver = self.signal_receiver.read().unwrap();
        match receiver.recv() {
            Ok(sig) => sig,
            Err(_) => None,
        }
    }

    pub fn handle(&self) -> IcHandle {
        let guard = self.inner.read().unwrap();
        let endpoints = guard.procman.configs.iter();

        let to_ic_endpoint = |(pid, nc): (&Pid, &NodeCommand)| {
            let addr = if nc.http_addr.ip().is_ipv4() {
                format!("{}", nc.http_addr.ip())
            } else {
                format!("[{}]", nc.http_addr.ip())
            };
            let port = nc.http_addr.port();
            let url = Url::parse(&format!("http://{}:{}/", addr, port)).expect("Can't fail");
            let metrics_url = Some(
                Url::parse(&format!("http://{}:{}/", addr, nc.metrics_port)).expect("Can't fail"),
            );
            IcEndpoint {
                runtime_descriptor: RuntimeDescriptor::Process(*pid),
                url,
                metrics_url,
                is_root_subnet: nc.is_root_subnet,
                subnet: Some(IcSubnet {
                    id: nc.subnet_id,
                    type_of: nc.initial_subnet_type,
                }),
                started_at: Instant::now(),
                ssh_key_pairs: vec![],
                node_id: nc.node_id,
            }
        };

        IcHandle {
            public_api_endpoints: endpoints
                .clone()
                .filter(|(_, nc)| !nc.is_malicious)
                .map(to_ic_endpoint)
                .collect(),
            malicious_public_api_endpoints: endpoints
                .filter(|(_, nc)| nc.is_malicious)
                .map(to_ic_endpoint)
                .collect(),
            ic_prep_working_dir: Some(IcPrepStateDir::new(PathBuf::from(
                self.prep_working_dir.deref().path(),
            ))),
        }
    }
}

impl Drop for IcManager {
    fn drop(&mut self) {
        self.inner.write().unwrap().procman.stop();
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct FileId(Pid, InputSource);

#[derive(Clone)]
struct LogsWriter {
    base_dir: PathBuf,
    writers: Arc<Mutex<BTreeMap<FileId, std::io::BufWriter<Box<File>>>>>,
}

impl LogsWriter {
    pub fn new(base_dir: PathBuf) -> Self {
        LogsWriter {
            base_dir,
            writers: Arc::new(Mutex::new(BTreeMap::default())),
        }
    }

    /// Writes an event emitted by a replica to a file whose name is derived
    /// from the currently executed pot, pid of the replica and a channel.
    pub fn write(&mut self, pid: &Pid, src: &InputSource, event: &NodeEvent) {
        let file_id = FileId(*pid, *src);
        let mut writers = self.writers.lock().expect("couldn't lock");
        writers.entry(file_id).or_insert_with(|| {
            let w = std::io::BufWriter::new(Box::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(self.build_filename(&file_id))
                    .expect("couldn't open replica_tee file"),
            ));
            w
        });
        let writer = writers.get_mut(&file_id).expect("log writer lookup failed");
        let json = serde_json::to_string(event).expect("failed to serialize event to json");
        writeln!(writer, "{}", json).expect("couldn't write to replica_tee");
    }

    fn build_filename(&self, id: &FileId) -> PathBuf {
        let mut filepath = PathBuf::new();
        filepath.push(&self.base_dir);
        filepath.push(format!("{}:{}.log", id.0, id.1));
        filepath.set_extension("log");
        filepath
    }
}

#[derive(serde::Deserialize)]
struct LogEntryLine {
    log_entry: LogEntry,
}
