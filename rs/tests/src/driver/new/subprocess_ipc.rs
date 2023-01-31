use super::event::{Event, EventSubscriber, TaskId};
use crate::driver::new::constants::{PANIC_LOG_PREFIX, SUBREPORT_LOG_PREFIX};
use bincode;
use serde::{Deserialize, Serialize};
use slog::{error, warn, Drain, Level, Logger, OwnedKVList, Record};
use std::{
    io::{self},
    net::Shutdown,
    os::unix::net::UnixDatagram,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const MSG_BUF_SIZE: usize = 64 * 1024; // 64 KiB
const MSG_TRUNC_SIZE: usize = 60 * 1024;
const TRUNC_WARNING: &str = "[...]Logged message has been truncated (>64kB)!";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    fn truncate_msg(&self) -> Self {
        Self {
            task_id: self.task_id.clone(),
            log_record: self.log_record.truncate_msg(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    pub fn truncate_msg(&self) -> Self {
        let bytes = self.msg.as_bytes();
        let mut index = MSG_TRUNC_SIZE;
        // seek for utf-8 character boundary: cut after a byte with MSB 0.
        while (bytes[index] & 128) != 0 {
            index -= 1;
        }
        let mut msg = self.msg.clone();
        msg.truncate(index + 1);
        msg.push_str(TRUNC_WARNING);
        Self {
            level: self.level,
            file: self.file.clone(),
            module: self.module.clone(),
            line: self.line,
            msg,
        }
    }
}

pub struct SubprocessSender {
    task_id: TaskId,
    sock: UnixDatagram,
    sock_path: PathBuf,
}

impl SubprocessSender {
    pub fn new<P: AsRef<Path>>(task_id: TaskId, sock_path: P) -> io::Result<Self> {
        let sock = UnixDatagram::unbound()?;
        let sock_path = PathBuf::from(sock_path.as_ref());

        Ok(Self {
            task_id,
            sock,
            sock_path,
        })
    }

    #[inline]
    fn send_log_event(&self, log_event: &LogEvent) {
        if log_event.log_record.msg.len() > MSG_TRUNC_SIZE {
            self.send_log_event_(&log_event.truncate_msg());
        } else {
            self.send_log_event_(log_event);
        }
    }

    #[inline]
    fn send_log_event_(&self, log_event: &LogEvent) {
        let buf = bincode::serialize(&log_event)
            .expect("[should not fail!] could not serialize LogEvent");
        if let Err(e) = self.sock.send_to(&buf[..], &self.sock_path) {
            // this object is assumed to be the only log channel available in this process. Thus,
            // in case of a failure, we just print out to stderr.
            eprintln!("Could not send log event: {e:?}");
        }
    }
}

#[inline]
pub fn log_panic_event(log: &slog::Logger, msg: &str) {
    warn!(log, "{PANIC_LOG_PREFIX}{msg}");
}

/// There are no datastructures that actually need to be synchronized between threads. Thus, we can
/// safely clone this structure. However, because `UnixDatagram` only implement `TryClone` and not
/// `Clone`, we have to provide a custom implementation of `Clone`.
impl Clone for SubprocessSender {
    fn clone(&self) -> Self {
        Self {
            task_id: self.task_id.clone(),
            sock: self.sock.try_clone().expect("could not clone socket"),
            sock_path: self.sock_path.clone(),
        }
    }
}

impl Drain for SubprocessSender {
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

pub struct LogServer {
    sub: Arc<Mutex<Box<dyn EventSubscriber>>>,
    log: Logger,
    box_records: Arc<Mutex<ser::BoxRecords>>,
    sock: UnixDatagram,
}

impl LogServer {
    pub fn new<P, E>(socket_path: P, sub: E, log: Logger) -> io::Result<Self>
    where
        P: AsRef<Path>,
        E: EventSubscriber + 'static,
    {
        let sock = UnixDatagram::bind(socket_path.as_ref())?;
        let sub = Arc::new(Mutex::new(Box::new(sub) as Box<dyn EventSubscriber>));

        Ok(Self {
            sub,
            log,
            box_records: Arc::new(Mutex::new(Default::default())),
            sock,
        })
    }

    /// Consume all events and either log them out or generate a corresponding event.
    pub fn receive_all_events(&self) -> io::Result<()> {
        let mut buf = vec![0u8; MSG_BUF_SIZE];
        let mut log = {
            let log = self.log.clone();
            move |r: &'_ slog::Record<'_>| {
                log.log(r);
            }
        };

        loop {
            match self.sock.recv(&mut buf[..]) {
                Ok(n) if n > 0 => {
                    // parse message
                    match bincode::deserialize(&buf[..n]) {
                        Ok(log_event) => {
                            self.emit_panic_event(&log_event);
                            self.emit_subreport_event(&log_event);
                            let LogEvent {
                                // for now, when receiving a message, we just ignore the task id and
                                // rely on the code location of the log message to provide context.
                                task_id: _task_id,
                                log_record,
                            } = log_event;
                            let mut box_records = self.box_records.lock().unwrap();
                            box_records.box_record(log_record, &mut log);
                        }
                        Err(e) => {
                            error!(self.log, "Could not parse log event: {e:?}");
                        }
                    }
                }
                // channel was shut down
                Ok(_) => break,
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Given a log event, emit the corresponding panic event if the log message contains a panic
    /// message. This is the counterpart to the [log_panic_event] function.
    #[inline]
    fn emit_panic_event(&self, log_event: &LogEvent) {
        if let Some(Level::Warning) = Level::from_usize(log_event.log_record.level) {
            if let Some(pos) = log_event.log_record.msg.find(PANIC_LOG_PREFIX) {
                let task_id = log_event.task_id.clone();
                let start_pos = pos + PANIC_LOG_PREFIX.len();
                let msg = (log_event.log_record.msg[start_pos..]).to_string();
                let mut sub = self.sub.lock().unwrap();
                (sub)(Event::task_caught_panic(task_id, msg))
            }
        }
    }

    /// Given a log event, emit the corresponding panic event if the log message contains a panic
    /// message. This is the counterpart to the [log_panic_event] function.
    #[inline]
    fn emit_subreport_event(&self, log_event: &LogEvent) {
        if let Some(pos) = log_event.log_record.msg.find(SUBREPORT_LOG_PREFIX) {
            let task_id = log_event.task_id.clone();
            let start_pos = pos + SUBREPORT_LOG_PREFIX.len();
            let report = (log_event.log_record.msg[start_pos..]).to_string();
            let mut sub = self.sub.lock().unwrap();
            (sub)(Event::task_sub_report(task_id, report))
        }
    }

    /// Shutdown log_server
    pub fn shutdown(&self) -> io::Result<()> {
        self.sock.shutdown(Shutdown::Both)
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
            log_event: LogRecord,
            mut f: F,
        ) {
            let file = self.get_static_str(&log_event.file);
            let module = self.get_static_str(&log_event.module);
            let level =
                Level::from_usize(log_event.level).expect("Could not convert to Level from usize.");
            let line = log_event.line;
            let msg = log_event.msg;

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

            let kv = b!();

            f(&Record::new(&rs, &format_args!("{}", msg), kv));
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

#[cfg(test)]
mod tests {
    use super::super::event::EventPayload;
    use super::*;
    use crossbeam_channel::{unbounded, Sender};
    use rand::Rng;
    use slog::{info, o, warn};
    use std::sync::Arc;

    #[test]
    fn can_send_and_receive_messages() {
        let sock_path = get_unique_sock_path();
        let (subfact, evt_rcvr) = crate::driver::new::event::test_utils::create_subfact();
        let sub = subfact.create_broadcasting_subscriber();

        // setup
        let (log_send, log_rcvr) = unbounded();
        let parent_drain = ParentDrain(log_send);
        let parent_logger = Logger::root(parent_drain, o!());

        // setup log_server
        let log_server = LogServer::new(&sock_path, sub, parent_logger).unwrap();
        let log_server = Arc::new(log_server);

        let jh = std::thread::spawn({
            let log_server = log_server.clone();
            move || log_server.receive_all_events()
        });

        let expected_task_id = TaskId::Test("fake_test".to_string());
        // setup sender
        let subproc_sender = SubprocessSender::new(expected_task_id.clone(), &sock_path).unwrap();
        let subproc_logger = Logger::root(subproc_sender, o!());
        // send logs
        info!(subproc_logger, "hello info");
        warn!(subproc_logger, "hello warn");
        //send huge string
        let huge_str = (0..(MSG_BUF_SIZE + 1)).map(|_| "x").collect::<String>();
        info!(subproc_logger, "{}", huge_str);
        // send panic
        log_panic_event(&subproc_logger, "oh, a panic!");
        // shutdown log_server
        assert!(log_server.shutdown().is_ok());
        // check received messages

        assert!(jh.join().is_ok());

        let info_log_msg = log_rcvr.recv().unwrap();
        assert_eq!(info_log_msg.level, slog::Level::Info.as_usize());
        assert_eq!(info_log_msg.msg, "hello info");

        let warn_log_msg = log_rcvr.recv().unwrap();
        assert_eq!(warn_log_msg.level, slog::Level::Warning.as_usize());
        assert_eq!(warn_log_msg.msg, "hello warn");

        assert_eq!(info_log_msg.line + 1, warn_log_msg.line);

        let info_log_msg = log_rcvr.recv().unwrap();
        assert!(info_log_msg.msg.ends_with(TRUNC_WARNING));

        let panic_event = evt_rcvr.recv().unwrap();

        if let EventPayload::TaskCaughtPanic { task_id, msg } = panic_event.what {
            assert_eq!(task_id, expected_task_id);
            assert_eq!(msg, "oh, a panic!");
        } else {
            panic!("wrong event type!");
        }
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
