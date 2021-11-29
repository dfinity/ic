//! Logger that can log to STDERR and to multiple log files, one per log level.
//!
//! Each file has a prefix part to the filename composed of the following
//! '.' separated parts:
//!
//! - binary name (string) - e.g., 'ic-p8s-service-discovery'
//! - date/timestamp the logs were created (RFC3339 format with milliseconds) -
//!   e.g., 2020-03-30T15:34:44.066Z.  This is slightly more readable than
//!   20200330T153444066Z, the extra 4 characters are worth the readability
//!   improvement)
//! - process ID (decimal) - to distinguish between logs started within the same
//!   millisecond
//!
//! So
//!
//! ```text
//! ic-p8s-service-discovery.2020-03-30T15:34:44.066Z.123456.ERROR.log
//! ----- ------------------------ ------ -----
//!  bin       timestamp            pid   level
//! ```
//!
//! In addition, it symlinks a short-form of the name to the long form, the
//! short form is
//!
//!  <binary name>.<level>.log
//!
//! Each file contains the log entries for that level and all levels above, so
//!
//! ```text
//! tail -F ic-p8s-service-discovery.WARN.log
//! ```
//!
//! will follow the most recent log showing warnings, errors, and critical
//! log messages.
//!
//! Honours the following command line flags:
//!
//! --log-level             - minimum level of log messages to send (to both
//!                           disk and stderr)
//! --log-to-stderr         - send log messages to STDERR
//! --log-to-stderr-pretty  - write 'pretty' JSON logs to STDERR
//! --log-to-disk PATH      - path to write log files to
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex};
use std::{env, io};

use chrono::{DateTime, SecondsFormat, Utc};
use elastic_common_schema as ecs;
use gflags::custom::{Arg, Value};
use gflags_derive::GFlags;
use serde::{Deserialize, Serialize};
use slog::{o, Drain, Duplicate, Fuse, IgnoreResult, LevelFilter, Logger};
use slog_async::{AsyncGuard, OverflowStrategy};
use strum_macros::{Display, EnumString};
use thiserror::Error;

#[derive(Clone, Debug, Display, EnumString, Serialize, Deserialize)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Critical,
    Error,
    Warning,
    Info,
    Debug,
    Trace,
}

impl Default for Level {
    fn default() -> Self {
        Level::Info
    }
}

impl Value for Level {
    fn parse(arg: Arg) -> gflags::custom::Result<Self> {
        match arg.get_str().to_ascii_lowercase().as_ref() {
            "critical" => Ok(Level::Critical),
            "error" => Ok(Level::Error),
            "warning" => Ok(Level::Warning),
            "info" => Ok(Level::Info),
            "debug" => Ok(Level::Debug),
            "trace" => Ok(Level::Trace),
            _ => Err(gflags::custom::Error::new("invalid logging level")),
        }
    }
}

impl From<Level> for slog::Level {
    fn from(level: Level) -> Self {
        match level {
            Level::Critical => slog::Level::Critical,
            Level::Error => slog::Level::Error,
            Level::Warning => slog::Level::Warning,
            Level::Info => slog::Level::Info,
            Level::Debug => slog::Level::Debug,
            Level::Trace => slog::Level::Trace,
        }
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("invalid logging level: {0}")]
    InvalidLoggingLevel(String),

    #[error("invalid logging directory: {source}")]
    InvalidLoggingDirectory {
        #[from]
        source: io::Error,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, GFlags)]
#[serde(default)]
#[gflags(prefix = "log_")]
pub struct Config {
    /// True if logs should be written to STDERR
    #[gflags(default = false)]
    to_stderr: bool,

    /// True if logs printed to STDERR should be pretty-printed
    #[gflags(default = false)]
    to_stderr_pretty: bool,

    /// Minimum log level to log at
    #[gflags(placeholder = "LEVEL")]
    level: Level,

    /// Path to write logs to
    #[gflags(type = "&str", placeholder = "PATH")]
    to_disk: Option<PathBuf>,

    /// Name of this binary
    #[gflags(skip)]
    binary_name: String,
}

impl Default for Config {
    /// Creates and returns a default logging configuration.
    ///
    /// The defaults are:
    ///   - Do not send log messages to STDERR
    ///   - Do not pretty print logs to STDERR
    ///   - The minimum log level is Debug
    ///   - Do not write logs to disk
    ///   - The binary name corresponds to the filename of the executable
    fn default() -> Self {
        let mut default = Self {
            to_stderr: false,
            to_stderr_pretty: false,
            level: Level::Info,
            to_disk: None,
            binary_name: "".to_string(),
        };

        let current_exe = env::current_exe().expect("Could not determine executable path");
        let binary_name = current_exe
            .file_name()
            .expect("Could not determine executable file");

        default.binary_name = binary_name.to_string_lossy().to_string();

        default
    }
}

/// Creates and returns a logging configuration derived from `config`
/// overridden by command line flags
pub fn from_flags(config: Config) -> Result<Config, ConfigError> {
    let mut config = config;

    if LOG_TO_STDERR.is_present() {
        config.to_stderr = LOG_TO_STDERR.flag;
    }

    if LOG_TO_STDERR_PRETTY.is_present() {
        config.to_stderr_pretty = LOG_TO_STDERR.flag;
    }

    if LOG_LEVEL.is_present() {
        config.level = LOG_LEVEL.flag.clone();
    }

    if LOG_TO_DISK.is_present() {
        config.to_disk = Some(PathBuf::from(LOG_TO_DISK.flag).canonicalize()?);
    }

    Ok(config)
}

pub struct LoggerImpl {
    pub root: Logger,
    pub file_guard: Option<AsyncGuard>,
    pub stderr_guard: Option<AsyncGuard>,
}

impl LoggerImpl {
    pub fn new(config: &Config, thread_name: String) -> Self {
        Self::new_internal(config, thread_name)
    }

    fn new_internal(config: &Config, thread_name: String) -> Self {
        let now: DateTime<Utc> = Utc::now();
        let pid = process::id();

        let file_drain = if let Some(log_dir) = &config.to_disk {
            let critical_drain =
                Self::new_file_drain(log_dir, &config.binary_name, now, pid, Level::Critical);
            let error_drain =
                Self::new_file_drain(log_dir, &config.binary_name, now, pid, Level::Error);
            let warning_drain =
                Self::new_file_drain(log_dir, &config.binary_name, now, pid, Level::Warning);
            let info_drain =
                Self::new_file_drain(log_dir, &config.binary_name, now, pid, Level::Info);
            let debug_drain =
                Self::new_file_drain(log_dir, &config.binary_name, now, pid, Level::Debug);
            let trace_drain =
                Self::new_file_drain(log_dir, &config.binary_name, now, pid, Level::Trace);

            // We want high-priority messages (Error and Critical) to be
            // written synchronously and messages with lower priorities to be
            // written asynchronously.  This way we reduce the probability of
            // losing important messages if the process crashes after logging
            // a critical failure while reducing latency for casual records.
            let high_priority_drain = Duplicate::new(critical_drain, error_drain).ignore_res();

            let low_priority_drain = Duplicate::new(
                Duplicate::new(warning_drain, info_drain),
                Duplicate::new(debug_drain, trace_drain),
            )
            .ignore_res();

            let async_builder = slog_async::Async::new(low_priority_drain)
                .overflow_strategy(OverflowStrategy::DropAndReport);
            let async_builder = async_builder.chan_size(2048);
            let async_builder = async_builder.thread_name(thread_name.clone());
            let (low_priority_drain, async_builder_guard) = async_builder.build_with_guard();

            Some((
                Duplicate::new(high_priority_drain, low_priority_drain)
                    .filter_level(slog::Level::from(config.level.clone()))
                    .ignore_res(),
                async_builder_guard,
            ))
        } else {
            None
        };

        let stderr_drain = if config.to_stderr {
            let drain = Arc::new(Mutex::new(
                ecs::drain::Drain::default(std::io::stderr(), config.to_stderr_pretty).fuse(),
            ))
            .ignore_res();

            // We want high-priority messages (Error and Critical) to be
            // written synchronously and messages with lower priorities to be
            // written asynchronously.  This way we reduce the probability of
            // losing important messages if the process crashes after logging
            // a critical failure while reducing latency for casual records.
            let high_priority_drain = drain.clone().filter_level(slog::Level::Error).ignore_res();

            let low_priority_drain = drain
                .filter(|record| !record.level().is_at_least(slog::Level::Error))
                .ignore_res();

            let async_builder = slog_async::Async::new(low_priority_drain)
                .overflow_strategy(OverflowStrategy::DropAndReport);
            let async_builder = async_builder.chan_size(2048);
            let async_builder = async_builder.thread_name(thread_name);
            let (low_priority_drain, async_builder_guard) = async_builder.build_with_guard();

            Some((
                Duplicate::new(high_priority_drain, low_priority_drain)
                    .filter_level(slog::Level::from(config.level.clone()))
                    .ignore_res(),
                async_builder_guard,
            ))
        } else {
            None
        };

        let (root, file_guard, stderr_guard) = match (file_drain, stderr_drain) {
            (None, None) => (slog::Logger::root(slog::Discard, o!()), None, None),
            (None, Some((stderr_drain, stderr_guard))) => (
                slog::Logger::root(stderr_drain, o!()),
                None,
                Some(stderr_guard),
            ),
            (Some((file_drain, file_guard)), None) => {
                (slog::Logger::root(file_drain, o!()), Some(file_guard), None)
            }
            (Some((file_drain, file_guard)), Some((stderr_drain, stderr_guard))) => (
                slog::Logger::root(Duplicate::new(file_drain, stderr_drain).ignore_res(), o!()),
                Some(file_guard),
                Some(stderr_guard),
            ),
        };

        Self {
            root,
            file_guard,
            stderr_guard,
        }
    }

    /// Returns a `Drain` that writes messages of the given `level` to a file.
    /// The final filename is constructed from `log_dir`, `binary_name`,
    /// `timestamp`, `process_id`, and `level`.
    ///
    /// In addition, creates a symlink to the generated logfile in `log_dir`,
    /// called `{binary_name}.{level}.log`.
    #[allow(clippy::type_complexity)]
    fn new_file_drain(
        log_dir: &Path,
        binary_name: &str,
        timestamp: DateTime<Utc>,
        process_id: u32,
        level: Level,
    ) -> IgnoreResult<LevelFilter<Arc<Mutex<Fuse<ecs::drain::Drain<File>>>>>> {
        use std::fs;
        use std::os::unix;

        let filename = format!(
            "{}.{}.{}.{}.log",
            binary_name,
            timestamp.to_rfc3339_opts(SecondsFormat::Millis, true),
            process_id,
            level.to_string()
        );

        let log_path: PathBuf = [log_dir, &PathBuf::from(filename)].iter().collect();
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)
            .expect("open failed");

        let symlink_name = format!("{}.{}.log", binary_name, level.to_string());
        let symlink_path: PathBuf = [log_dir, &PathBuf::from(symlink_name)].iter().collect();
        if let Err(e) = fs::remove_file(&symlink_path) {
            match e.kind() {
                ErrorKind::NotFound => (), // Safe to ignore file-not-found errors
                _ => panic!("{}", e),      // Panic on other errors
            }
        }
        unix::fs::symlink(&log_path, &symlink_path).expect("creating symlink failed");

        let drain = ecs::drain::Drain::default(file, false).fuse();

        Arc::new(Mutex::new(drain))
            .filter_level(slog::Level::from(level))
            .ignore_res()
    }
}
