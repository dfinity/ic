use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Represents the required log level defined in the `LoggerConfig`.
//
// Note that `slog::Level` does not provide an implementation of `Deserialize`
// so we use the approach for remote derives (https://serde.rs/remote-derive.html)
// provided by serde.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Critical,
    Error,
    Warning,
    Info,
    Debug,
    Trace,
}

/// Possible formatting for log lines
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    TextFull,
    Json,
}

/// Possible destitations where emitted logs can be written
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub enum LogDestination {
    #[default]
    Stdout,
    Stderr,
    File(PathBuf),
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub level: Level,
    /// The format of emitted log lines.
    pub format: LogFormat,
    /// The destination where logs should be written.
    pub log_destination: LogDestination,
    /// If set to `false`, the logging thread will _not_ block even if the queue/buffer full.
    ///
    /// Messages are logged asynchronously.
    /// The default behavior is to block when the async-(queue/buffer) is full.
    #[serde(default = "default_block_on_overflow")]
    pub block_on_overflow: bool,
}

fn default_block_on_overflow() -> bool {
    false
}

impl Default for Config {
    fn default() -> Self {
        Self {
            level: Level::Debug,
            format: LogFormat::TextFull,
            log_destination: LogDestination::default(),
            block_on_overflow: false,
        }
    }
}
