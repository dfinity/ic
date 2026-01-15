//! Provide an in-memory logger for testing purposes,
//! where written logs can be asserted upon in a unit test.
//!
//! Fluent assertions on written log entries are provided in [`assertions::LogEntriesAssert`].

use ic_config::logger::{Config as LoggerConfig, LogFormat};
use ic_logger::{LoggerImpl, ReplicaLogger, new_logger, new_replica_logger};
use ic_protobuf::log::log_entry::v1::LogEntry;
use parking_lot::RwLock;
use slog_async::AsyncGuard;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

pub mod assertions;

/// A [`ReplicaLogger`] that logs into memory and where written logs can be read.
///
/// Useful for example in a unit test to ensure that
/// some expected log message with a certain log level was written.
///
/// # Example
///```
///  # use slog::Level;
///  # use ic_logger::{debug, info, ReplicaLogger};
///  # use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
///  # use ic_test_utilities_in_memory_logger::InMemoryReplicaLogger;
///  let in_memory_logger = InMemoryReplicaLogger::new();
///  let replica_logger = ReplicaLogger::from(&in_memory_logger);
///  info!(replica_logger, "1 this is an info test log");
///  debug!(replica_logger, "2 this is a debug test log");
///
///  let logs = in_memory_logger.drain_logs();
///
///  LogEntriesAssert::assert_that(logs)
///      .has_len(2)
///      .has_only_one_message_containing(&Level::Info, "1 this is an info test log")
///      .has_only_one_message_containing(&Level::Debug, "2 this is a debug test log");
///```
pub struct InMemoryReplicaLogger {
    drain: InMemoryDrain<Vec<u8>>,
    replica_logger: ReplicaLogger,
    guard: AsyncGuard,
}

impl InMemoryReplicaLogger {
    pub fn new() -> Self {
        let drain = InMemoryDrain::new();
        let (replica_logger, guard) = new_json_replica_logger(drain.clone());
        InMemoryReplicaLogger {
            drain,
            replica_logger,
            guard,
        }
    }

    pub fn drain_logs(self) -> Vec<LogEntry> {
        //force flush low priority messages
        drop(self.guard);
        let mut parsed_logs = Vec::new();
        for line in self.drain.into_utf8().lines() {
            // each line is a JSON map where the key is always "log_entry"
            // and the value is a JSON object corresponding to the serialization of LogEntry.
            // The key should be ignored.
            let parsed_log: HashMap<String, LogEntry> =
                serde_json::from_slice(line.as_ref()).expect("invalid log entry");
            for (_key, log_entry) in parsed_log.into_iter() {
                parsed_logs.push(log_entry);
            }
        }
        parsed_logs
    }
}

impl From<&InMemoryReplicaLogger> for ReplicaLogger {
    fn from(in_memory_logger: &InMemoryReplicaLogger) -> Self {
        new_logger!(in_memory_logger.replica_logger)
    }
}

impl Default for InMemoryReplicaLogger {
    fn default() -> Self {
        Self::new()
    }
}

fn new_json_replica_logger<W>(writer: W) -> (ReplicaLogger, AsyncGuard)
where
    W: 'static + io::Write + Send,
{
    let logger_config = LoggerConfig {
        format: LogFormat::Json,
        ..LoggerConfig::default()
    };
    let LoggerImpl {
        root,
        async_log_guard,
    } = LoggerImpl::new_for_test(writer, &logger_config);
    let logger = new_replica_logger(root, &logger_config);
    (logger, async_log_guard)
}

struct InMemoryDrain<W> {
    drain: Arc<RwLock<W>>,
}

impl<W> Clone for InMemoryDrain<W> {
    fn clone(&self) -> Self {
        Self {
            drain: self.drain.clone(),
        }
    }
}

impl<W> io::Write for InMemoryDrain<W>
where
    W: io::Write,
{
    #[allow(clippy::disallowed_methods)] //need to implement trait method
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.drain.write().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain.write().flush()
    }
}

impl InMemoryDrain<Vec<u8>> {
    fn new() -> Self {
        Self {
            drain: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn into_utf8(self) -> String {
        String::from_utf8(self.drain.read().to_vec()).expect("invalid UTF-8 characters")
    }
}
