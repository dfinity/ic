//! Implements the LogSender and LogReceiver using Unix Domain stream sockets instead of
//! datagram sockets. This allows for arbitrarily sized messages. Also, a stream is tied to a
//! specific subprocess and is thus closed when the subprocess exits. A stream therefore
//! trivially allows to identify the last log message sent by a subprocess, while datagrams and
//! exit signals are not necessarily correlated.
//!
//! While a unix listener can accept multiple connections, we assume that each subprocess uses
//! a separate unix domain socket; thus the client does not need to identify itself after it
//! connected.
//!
//! The LogReceiver parses out report and failure messages from child processes.
//!
//! Every message is preceded with the length of the messages. All messages are encoded using
//! `bincode`.

use crate::driver::constants::{PANIC_LOG_PREFIX, SUBREPORT_LOG_PREFIX};
use crate::driver::event::TaskId;
use bincode;
use serde::{Deserialize, Serialize};
use slog::{error, warn, Drain, Level, Logger, OwnedKVList, Record};
use std::{
    io::{self, Write},
    os::unix::net::UnixStream,
    path::Path,
    sync::{Arc, Mutex},
};
use tokio::net::UnixListener;

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct LogEvent {
    task_id: TaskId,
    log_record: LogRecord,
}

impl LogEvent {
    pub fn from_slog_record(task_id: TaskId, record: &slog::Record<'_>) -> Self {
        let log_record = LogRecord::from_slog_record(record);

        Self {
            task_id,
            log_record,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct LogRecord {
    level: usize,
    file: String,
    module: String,
    line: u32,
    msg: String,
}

impl LogRecord {
    pub fn from_slog_record(record: &slog::Record<'_>) -> Self {
        Self {
            level: record.level().as_usize(),
            file: record.file().to_string(),
            module: record.module().to_string(),
            line: record.line(),
            msg: record.msg().to_string(),
        }
    }
}

pub fn log_panic_event(log: &slog::Logger, msg: &str) {
    warn!(log, "{PANIC_LOG_PREFIX}{msg}");
}

pub fn log_report_event(log: &slog::Logger, msg: &str) {
    warn!(log, "{SUBREPORT_LOG_PREFIX}{msg}");
}

pub struct LogSender {
    task_id: TaskId,
    stream: Mutex<UnixStream>,
}

impl LogSender {
    pub fn new<P: AsRef<Path>>(task_id: TaskId, sock_path: P) -> io::Result<Self> {
        let stream = UnixStream::connect(sock_path.as_ref())?;
        let stream = Mutex::new(stream);

        Ok(Self { task_id, stream })
    }

    fn send_log_event(&self, log_event: &LogEvent) {
        let mut stream = self.stream.lock().expect("could not grab mutex!");
        let buf = bincode::serialize(&log_event)
            .expect("[should not fail!] could not serialize LogEvent");
        let msg_len = buf.len() as u64;
        if let Err(e) = stream.write_all(&msg_len.to_be_bytes()) {
            eprintln!("ERROR: when writing msg. length to stream (size: {msg_len}): {e:?}");
            return;
        }
        if let Err(e) = stream.write_all(&buf[..]) {
            // this object is assumed to be the only log channel available in this process. Thus,
            // in case of a failure, we just print out to stderr.
            eprintln!("ERROR: when writing log event: {e:?}");
        }
    }
}

impl Drain for LogSender {
    type Ok = ();
    type Err = slog::Never;

    /// Send a log message to the log_server.
    fn log(&self, record: &Record<'_>, _values: &OwnedKVList) -> Result<Self::Ok, Self::Err> {
        // XXX: Because deserialization of structures w/ references is tricky, the LogRecord
        // structure owns all its fields. However, this results in two heap allocations here. One
        // might consider using a different structure for serialization/deserialization, where the
        // one for serialization only holds references.
        self.send_log_event(&LogEvent::from_slog_record(self.task_id.clone(), record));
        Ok(())
    }
}

pub struct LogReceiver {
    log: Logger,
    listener: UnixListener,
    box_records: Arc<Mutex<ser::BoxRecords>>,
}

impl LogReceiver {
    /// Binds a unix domain listener to the given path.
    pub async fn new<P>(socket_path: P, log: Logger) -> io::Result<Self>
    where
        P: AsRef<Path>,
    {
        let listener = UnixListener::bind(socket_path.as_ref())?;
        Ok(Self {
            log,
            listener,
            box_records: Arc::new(Mutex::new(Default::default())),
        })
    }

    /// Accepts exactly one connection and receives all the log messages from that connection.
    /// The method only returns when the stream is closed or an I/O error occurs.
    ///
    /// A return value of `Ok(None)` signifies that neither a report message, nor a failure
    /// message was received. If either report or failure messages are received multiple times,
    /// the last such message defines the return value. Any I/O errors are returned
    /// correspondingly.
    pub async fn receive_all(&self) -> io::Result<Option<ReportOrFailure>> {
        use std::io::ErrorKind;
        use tokio::io::AsyncReadExt;

        let (mut stream, _addr) = self.listener.accept().await?;
        let mut buf: Vec<u8> = vec![0u8; 4096];
        let mut log = {
            let log = self.log.clone();
            move |r: &'_ slog::Record<'_>| {
                log.log(r);
            }
        };

        let mut report_or_failure = None;
        // consume all messages
        loop {
            // read length of the message
            let msg_len = match stream.read_u64().await {
                Ok(n) => n as usize,
                // Eof => stream has been closed
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            };
            // increase buffer size if necessary
            if buf.len() < msg_len {
                buf.resize(msg_len, 0u8);
            }

            // read message
            let _ = stream.read_exact(&mut buf[0..msg_len]).await?;

            match bincode::deserialize::<LogEvent>(&buf[0..msg_len]) {
                Ok(log_event) => {
                    if let Some(report) = Self::extract_message(SUBREPORT_LOG_PREFIX, &log_event) {
                        report_or_failure = Some(ReportOrFailure::Report(report));
                    } else if let Some(Level::Warning) =
                        Level::from_usize(log_event.log_record.level)
                    {
                        if let Some(msg) = Self::extract_message(PANIC_LOG_PREFIX, &log_event) {
                            report_or_failure = Some(ReportOrFailure::Failure(msg));
                        }
                    }

                    let mut box_records = self.box_records.lock().unwrap();
                    box_records.box_record(log_event, &mut log);
                }
                Err(e) => {
                    error!(self.log, "Could not parse log event: {e:?}");
                }
            }
        }
        Ok(report_or_failure)
    }

    fn extract_message(prefix: &str, log_event: &LogEvent) -> Option<String> {
        if let Some(pos) = log_event.log_record.msg.find(prefix) {
            let start_pos = pos + prefix.len();
            let msg = (log_event.log_record.msg[start_pos..]).to_string();
            return Some(msg);
        }
        None
    }
}

#[derive(Clone, Debug)]
pub enum ReportOrFailure {
    Report(String),
    Failure(String),
}

impl ReportOrFailure {
    pub fn msg(&self) -> &str {
        match self {
            Self::Report(ref x) => x,
            Self::Failure(ref x) => x,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use crossbeam_channel::{unbounded, Sender};
    use rand::Rng;
    use slog::{info, o, warn};
    use std::{path::PathBuf, sync::Arc};
    use tokio::runtime::Runtime;

    #[test]
    fn can_send_and_receive_messages() {
        let rt = Runtime::new().expect("failed to create tokio runtime");
        let sock_path = get_unique_sock_path();
        #[allow(clippy::disallowed_methods)]
        let (log_send, log_rcvr_chan) = unbounded();
        let parent_drain = ParentDrain(log_send);
        let parent_logger = Logger::root(parent_drain, o!());

        let log_rcvr = rt
            .block_on(LogReceiver::new(&sock_path, parent_logger))
            .unwrap();
        let log_rcvr = Arc::new(log_rcvr);

        let jh = rt.spawn(async move { log_rcvr.receive_all().await });

        let expected_task_id = TaskId::Test("fake_test".to_string());
        // setup sender
        let subproc_sender = LogSender::new(expected_task_id, &sock_path).unwrap();
        let subproc_logger = Logger::root(subproc_sender, o!());

        // send logs
        info!(subproc_logger, "hello info");
        warn!(subproc_logger, "hello warn");

        // send panic
        log_panic_event(&subproc_logger, "oh, a panic!");

        // shutdown log_server
        std::mem::drop(subproc_logger);

        let info_log_msg = log_rcvr_chan.recv().unwrap();
        assert_eq!(info_log_msg.level, slog::Level::Info.as_usize());
        assert_eq!(info_log_msg.msg, "hello info");

        let warn_log_msg = log_rcvr_chan.recv().unwrap();
        assert_eq!(warn_log_msg.level, slog::Level::Warning.as_usize());
        assert_eq!(warn_log_msg.msg, "hello warn");

        let report_or_failure = rt.block_on(jh).unwrap().unwrap();

        assert_matches!(report_or_failure, Some(ReportOrFailure::Failure(msg)) if msg == "oh, a panic!");
    }

    #[test]
    fn can_receive_failure() {
        let rt = Runtime::new().expect("failed to create tokio runtime");
        let sock_path = get_unique_sock_path();

        #[allow(clippy::disallowed_methods)]
        let (log_send, _log_rcvr_chan) = unbounded();
        let parent_drain = ParentDrain(log_send);
        let parent_logger = Logger::root(parent_drain, o!());

        let log_rcvr = rt
            .block_on(LogReceiver::new(&sock_path, parent_logger))
            .unwrap();
        let log_rcvr = Arc::new(log_rcvr);

        let jh = rt.spawn(async move { log_rcvr.receive_all().await });

        let expected_task_id = TaskId::Test("fake_test".to_string());
        // setup sender
        let subproc_sender = LogSender::new(expected_task_id, &sock_path).unwrap();
        let subproc_logger = Logger::root(subproc_sender, o!());

        let expected_msg = "a report from a successful test";
        // send report
        log_report_event(&subproc_logger, expected_msg);

        // shutdown log_server
        std::mem::drop(subproc_logger);

        let report_or_failure = rt.block_on(jh).unwrap().unwrap();
        assert_matches!(report_or_failure, Some(ReportOrFailure::Report(msg)) if msg == expected_msg);
    }

    fn get_unique_sock_path() -> PathBuf {
        let mut rng = rand::thread_rng();
        let random_n: u64 = rng.gen();
        let pid = std::process::id();
        let tmpdir = std::env::temp_dir();

        tmpdir.join(format!("{pid}_{random_n}"))
    }

    // A slog Drain that takes a log message and sends it to a crossbeam channel.
    struct ParentDrain(Sender<LogRecord>);

    impl Drain for ParentDrain {
        type Ok = ();
        type Err = slog::Never;

        fn log(&self, record: &Record<'_>, _values: &OwnedKVList) -> Result<Self::Ok, Self::Err> {
            let _ = self.0.send(LogRecord::from_slog_record(record));
            Ok(())
        }
    }
}

/// Serialize/Deserialization of log events.
mod ser {
    use super::*;
    use slog::{b, Level, Record, RecordLocation, RecordStatic};
    use std::collections::HashSet;

    /// Turn a LogRecord into a slog::Record<'_> and use equivalent, but globally allocated strings
    /// for fields that require static lifetime.
    ///
    /// Unfortunately, getting serde to deserialize messages without creating clones (i.e.
    /// referencing the original buffer) is non-trivial. This also means that we need to find
    /// static str equivalents to some strings that are contained in the messages that we received,
    /// as the slog::Record contains `&'static str` references. The latter fortunately only affects
    /// the `file` and `module` fields.
    #[derive(Default)]
    pub struct BoxRecords {
        static_strings: HashSet<&'static str>,
    }

    impl BoxRecords {
        #[inline]
        pub fn box_record<F: FnMut(&'_ slog::Record<'_>)>(
            &mut self,
            log_event: LogEvent,
            mut f: F,
        ) {
            let LogEvent {
                task_id,
                log_record,
            } = log_event;

            let file = self.get_static_str(&log_record.file);
            let module = self.get_static_str(&log_record.module);
            let level = Level::from_usize(log_record.level)
                .expect("Could not convert to Level from usize.");
            let line = log_record.line;
            let msg = log_record.msg;

            let rl = RecordLocation {
                file,
                line,
                // not supported by slog
                column: 0,
                // not supported by slog
                function: "",
                module,
            };
            let rs = RecordStatic {
                location: &rl,
                // not supported by slog
                tag: "",
                level,
            };

            f(&Record::new(
                &rs,
                &format_args!("{}", msg),
                b!("task_id" => format!("{}", task_id)),
            ));
        }

        #[inline]
        fn get_static_str(&mut self, s: &str) -> &'static str {
            if let Some(s) = self.static_strings.get(s) {
                s
            } else {
                let s = Box::leak(Box::new(s.to_string()));
                self.static_strings.insert(s);
                s
            }
        }
    }
}
