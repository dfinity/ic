use ic_context_logger::{ContextLogger, LogMetadata, Logger};
use ic_protobuf::log::log_entry::v1::LogEntry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A logger that logs `LogEntry`s using a `LogEntryLogger`
pub type ReplicaLogger = ContextLogger<LogEntry, LogEntryLogger>;

/// A logger that doesn't log. Used in tests.
pub fn no_op_logger() -> ReplicaLogger {
    LogEntryLogger::new(
        slog::Logger::root(slog::Discard, slog::o!()),
        slog::Level::Critical,
        vec![],
        HashMap::new(),
        vec![],
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
    pub debug_overrides: Vec<String>,
    pub sampling_rates: HashMap<String, u32>,
    pub enabled_tags: Vec<String>,
    pub last_log: Arc<Mutex<HashMap<String, Instant>>>,
}

impl LogEntryLogger {
    pub fn new(
        root: slog::Logger,
        level: slog::Level,
        debug_overrides: Vec<String>,
        sampling_rates: HashMap<String, u32>,
        enabled_tags: Vec<String>,
    ) -> Self {
        Self {
            root,
            level,
            debug_overrides,
            sampling_rates,
            enabled_tags,
            last_log: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl From<slog::Logger> for LogEntryLogger {
    fn from(root: slog::Logger) -> Self {
        let level = if cfg!(debug_assertions) {
            slog::Level::Trace
        } else {
            slog::Level::Info
        };

        Self::new(root, level, vec![], HashMap::new(), vec![])
    }
}

impl Clone for LogEntryLogger {
    fn clone(&self) -> Self {
        Self {
            root: self.root.new(slog::o!()),
            level: self.level,
            debug_overrides: self.debug_overrides.clone(),
            sampling_rates: self.sampling_rates.clone(),
            enabled_tags: self.enabled_tags.clone(),
            last_log: self.last_log.clone(),
        }
    }
}

impl Logger<LogEntry> for LogEntryLogger {
    fn log(&self, message: String, mut log_entry: LogEntry, metadata: LogMetadata) {
        let crate_ = get_crate(metadata.module_path);
        let module = get_module(metadata.module_path);

        log_entry.level = metadata.level.as_str().to_string();
        log_entry.utc_time = get_utc_time();
        log_entry.crate_ = crate_.clone();
        log_entry.module = module.clone();
        log_entry.message = message.clone();
        log_entry.line = metadata.line;

        let net_context = format!("s:{}/n:{}/", log_entry.subnet_id, log_entry.node_id);

        // Example:
        // s:0/n:0/ic_consensus/certifier Received 0 hash(es) to be certified in 11.26µs
        let message = format!("{}{}/{} {}", net_context, crate_, module, message);

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

    fn is_enabled_at(&self, level: slog::Level, module_path: &'static str) -> bool {
        if !self.debug_overrides.is_empty()
            && level == slog::Level::Debug
            && self.debug_overrides.contains(&module_path.to_string())
        {
            true
        } else {
            level.is_at_least(self.level)
        }
    }

    fn should_sample<T: Into<u32>>(&self, key: String, value: T) -> bool {
        if let Some(&sample_rate) = self.sampling_rates.get(&key) {
            sample_rate != 0 && value.into() % sample_rate == 0
        } else {
            false
        }
    }

    fn is_tag_enabled(&self, tag: String) -> bool {
        self.enabled_tags.contains(&tag)
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
    fn test_should_sample() {
        let mut logger = LogEntryLogger::new(
            slog::Logger::root(slog::Discard, slog::o!()),
            slog::Level::Critical,
            vec![],
            HashMap::new(),
            vec![],
        );

        logger.sampling_rates = [
            ("ten".into(), 10u32),
            ("one".into(), 1u32),
            ("zero".into(), 0u32),
        ]
        .iter()
        .cloned()
        .collect();

        for i in 1u32..10u32 {
            assert!(!logger.should_sample("ten".to_string(), i));
            assert!(logger.should_sample("one".to_string(), i));
            assert!(!logger.should_sample("zero".to_string(), i));
        }

        assert!(logger.should_sample("ten".to_string(), 10u32));
    }

    #[test]
    fn test_is_tag_enabled() {
        let logger = LogEntryLogger::new(
            slog::Logger::root(slog::Discard, slog::o!()),
            slog::Level::Critical,
            vec![],
            HashMap::new(),
            vec!["my_tag".into()],
        );

        assert!(logger.is_tag_enabled("my_tag".to_string()));
    }

    #[test]
    fn test_is_seconds() {
        let logger = LogEntryLogger::new(
            slog::Logger::root(slog::Discard, slog::o!()),
            slog::Level::Critical,
            vec![],
            HashMap::new(),
            vec!["my_tag".into()],
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
