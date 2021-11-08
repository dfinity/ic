use ic_config::logger::{Config as LoggerConfig, LogFormat, LogTarget};
use slog::{o, Drain, Logger};
use slog_async::{AsyncGuard, OverflowStrategy};
use slog_scope::GlobalLoggerGuard;
use std::io;
use std::sync::{Arc, Mutex};

pub mod replica_logger;
pub use ic_context_logger::{debug, error, fatal, info, info_sample, log, new_logger, trace, warn};
use replica_logger::LogEntryLogger;
pub use replica_logger::ReplicaLogger;

pub fn new_replica_logger(log: slog::Logger, config: &LoggerConfig) -> ReplicaLogger {
    let log_entry_logger = LogEntryLogger::new(
        log,
        config.level,
        config.debug_overrides.clone(),
        config.sampling_rates.clone(),
        config.enabled_tags.clone(),
    );
    ReplicaLogger::new(log_entry_logger)
}

pub struct LoggerImpl {
    pub root: Logger,
    pub async_log_guard: AsyncGuard,
}

impl LoggerImpl {
    pub fn new(config: &LoggerConfig, thread_name: String) -> Self {
        match config.target.clone() {
            LogTarget::Stdout => Self::new_internal(std::io::stdout(), config, thread_name),
            LogTarget::Stderr => Self::new_internal(std::io::stderr(), config, thread_name),
            LogTarget::File(f) => Self::new_internal(
                std::fs::File::create(f).expect("Couldn't open/create log file"),
                config,
                thread_name,
            ),
        }
    }

    pub fn new_for_test(config: LoggerConfig) -> Self {
        Self::new_internal(slog_term::TestStdoutWriter, &config, "test".to_string())
    }

    fn new_internal<W>(i: W, config: &LoggerConfig, thread_name: String) -> Self
    where
        W: 'static + std::io::Write + std::marker::Send,
    {
        let drain = Arc::new(Mutex::new(Self::get_formatter(i, config.format).fuse())).ignore_res();

        // We want high-priority messages (Error and Critical) to be
        // written synchronously and messages with lower priorities to be
        // written asynchronously.  This way we reduce the probability of
        // losing important messages if the process crashes after logging
        // a critical failure while reducing latency for casual records.

        let high_priority_drain = drain.clone().filter_level(slog::Level::Error).ignore_res();

        let low_priority_drain = drain
            .filter(|record| !record.level().is_at_least(slog::Level::Error))
            .ignore_res();

        // In System Testing, for instrumentation purposes, we currently use logging. To
        // ensure that logs are not dropped in a system test environment, we use a
        // config flag to set the behavior to blocking instead of dropping.
        let overflow_strategy = if config.block_on_overflow {
            OverflowStrategy::Block
        } else {
            OverflowStrategy::DropAndReport
        };

        let async_builder =
            slog_async::Async::new(low_priority_drain).overflow_strategy(overflow_strategy);
        let async_builder = async_builder.chan_size(10240);
        let async_builder = async_builder.thread_name(thread_name);
        let (low_priority_drain, async_log_guard) = async_builder.build_with_guard();

        let drain = slog::Duplicate::new(high_priority_drain, low_priority_drain).ignore_res();
        let root = slog::Logger::root(drain, o!());
        let guard = slog_scope::set_global_logger(root.clone());
        GlobalLoggerGuard::cancel_reset(guard);

        Self {
            root,
            async_log_guard,
        }
    }

    /// Return the log formatter based on config
    ///
    /// The log formatter controls the format of emitted logs. If
    /// `config.emit_json` is `true`, use a JSON formatter, else use a
    /// plain-text formatter.
    fn get_formatter<W>(
        writer: W,
        format: LogFormat,
    ) -> Box<dyn Drain<Ok = (), Err = io::Error> + Send>
    where
        W: 'static + std::io::Write + std::marker::Send,
    {
        match format {
            LogFormat::Json => Box::new(slog_json::Json::new(writer).build()),
            LogFormat::TextFull => Box::new(
                slog_term::FullFormat::new(slog_term::PlainSyncDecorator::new(writer))
                    .use_utc_timestamp()
                    .use_original_order()
                    .build(),
            ),
        }
    }
}
