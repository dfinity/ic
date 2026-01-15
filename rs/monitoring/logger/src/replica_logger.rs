use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use ic_protobuf::log::log_entry::v1::LogEntry;
use ic_utils::str::StrEllipsize;

use crate::context_logger::{ContextLogger, LogMetadata, Logger};

/// A logger that logs `LogEntry`s using a `LogEntryLogger`
pub type ReplicaLogger = ContextLogger<LogEntry, LogEntryLogger>;

/// The value of this constant is larger than the maximum allowed length of `8 KiB` for `UserError` description
/// so that we don't get a pair of ellipses (`...`) if the `UserError` description is of the maximum length
const MAX_LOG_MESSAGE_LEN_BYTES: usize = 16 * 1024;

/// A logger that doesn't log. Used in tests.
pub fn no_op_logger() -> ReplicaLogger {
    LogEntryLogger::new(
        slog::Logger::root(slog::Discard, slog::o!()),
        ic_config::logger::Level::Critical,
    )
    .into()
}

impl From<LogEntryLogger> for ReplicaLogger {
    fn from(logger: LogEntryLogger) -> Self {
        ReplicaLogger::new(logger)
    }
}

/// Logs `LogEntry`s using `slog`
pub struct LogEntryLogger {
    pub root: slog::Logger,
    // Only logs at `level` or above
    pub level: slog::Level,
    pub last_log: Mutex<HashMap<String, Instant>>,
}

impl LogEntryLogger {
    pub fn new(root: slog::Logger, level: ic_config::logger::Level) -> Self {
        let slog_level = match level {
            ic_config::logger::Level::Critical => slog::Level::Critical,
            ic_config::logger::Level::Error => slog::Level::Error,
            ic_config::logger::Level::Warning => slog::Level::Warning,
            ic_config::logger::Level::Info => slog::Level::Info,
            ic_config::logger::Level::Debug => slog::Level::Debug,
            ic_config::logger::Level::Trace => slog::Level::Trace,
        };
        Self {
            root,
            level: slog_level,
            last_log: Mutex::new(HashMap::new()),
        }
    }
}

impl From<slog::Logger> for LogEntryLogger {
    fn from(root: slog::Logger) -> Self {
        let level = if cfg!(debug_assertions) {
            ic_config::logger::Level::Trace
        } else {
            ic_config::logger::Level::Info
        };

        Self::new(root, level)
    }
}

impl Clone for LogEntryLogger {
    fn clone(&self) -> Self {
        Self {
            root: self.root.new(slog::o!()),
            level: self.level,
            // `last_log` is not cloned because different instances of this
            // logger will log at disjoint module/line pairs, so these
            // instances don't need to share the same mutex, or need to both
            // update the same `HashMap`.
            last_log: Mutex::new(HashMap::new()),
        }
    }
}

impl Logger<LogEntry> for LogEntryLogger {
    fn log(&self, message: String, mut log_entry: LogEntry, metadata: LogMetadata) {
        let crate_ = get_crate(metadata.module_path);
        let module = get_module(metadata.module_path);

        // truncates message to be of length at most `MAX_LOG_MESSAGE_LEN_BYTES` bytes
        let message = message.ellipsize(MAX_LOG_MESSAGE_LEN_BYTES, 50);

        log_entry.level = metadata.level.as_str().to_string();
        log_entry.utc_time = get_utc_time();
        log_entry.crate_.clone_from(&crate_);
        log_entry.module.clone_from(&module);
        log_entry.message.clone_from(&message);
        log_entry.line = metadata.line;

        let net_context = format!("s:{}/n:{}/", log_entry.subnet_id, log_entry.node_id);

        // Example:
        // s:0/n:0/ic_consensus/certifier Received 0 hash(es) to be certified in 11.26µs
        let message = format!("{net_context}{crate_}/{module} {message}");

        let kv = slog::o!("log_entry" => log_entry);

        match metadata.level {
            slog::Level::Trace => slog::trace!(self.root, "{}", message; kv),
            slog::Level::Debug => slog::debug!(self.root, "{}", message; kv),
            slog::Level::Info => slog::info!(self.root, "{}", message; kv),
            slog::Level::Warning => slog::warn!(self.root, "{}", message; kv),
            slog::Level::Error => slog::error!(self.root, "{}", message; kv),
            slog::Level::Critical => slog::crit!(self.root, "{}", message; kv),
        }
    }

    fn is_enabled_at(&self, level: slog::Level) -> bool {
        level.is_at_least(self.level)
    }

    fn is_n_seconds<T: Into<i32>>(&self, seconds: T, metadata: LogMetadata) -> bool {
        let key = metadata.module_path.to_string() + &metadata.line.to_string();
        let now = Instant::now();
        let mut last_log = self.last_log.lock().unwrap();
        if let Some(last) = last_log.get_mut(&key) {
            if (now - *last) > Duration::new(seconds.into() as u64, 0) {
                *last = now;
                true
            } else {
                false
            }
        } else {
            last_log.insert(key, now);
            true
        }
    }
}

/// Return the current time in UTC
pub fn get_utc_time() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Return the crate that generated the given `Record`
pub fn get_crate(module_path: &'static str) -> String {
    let path: Vec<&str> = module_path.split("::").collect();
    (*path.first().unwrap_or(&"")).to_string()
}

/// Return the module that generated the given `Record`
pub fn get_module(module_path: &'static str) -> String {
    let path: Vec<&str> = module_path.split("::").collect();
    (*path.last().unwrap_or(&"")).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_seconds() {
        let logger = LogEntryLogger::new(
            slog::Logger::root(slog::Discard, slog::o!()),
            ic_config::logger::Level::Critical,
        );

        for i in 1u32..10u32 {
            assert!(
                logger.is_n_seconds(
                    1,
                    LogMetadata {
                        level: slog::Level::Warning,
                        module_path: std::module_path!(),
                        line: std::line!(),
                        column: std::column!(),
                    }
                ) == ((i == 1u32) || i == 6u32)
            );
            if i == 4u32 {
                std::thread::sleep(Duration::from_millis(500));
            }
            if i == 5u32 {
                std::thread::sleep(Duration::from_millis(5001));
            }
        }
    }
}
