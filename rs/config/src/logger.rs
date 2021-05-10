use serde::{Deserialize, Serialize};
use slog::Level;
use std::collections::HashMap;
use std::path::PathBuf;

/// Represents the required log level defined in the `LoggerConfig`.
//
// Note that `slog::Level` does not provide an implementation of `Deserialize`
// so we use the approach for remote derives (https://serde.rs/remote-derive.html)
// provided by serde.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(remote = "Level")]
#[serde(rename_all = "snake_case")]
pub enum LevelDef {
    Critical,
    Error,
    Warning,
    Info,
    Debug,
    Trace,
}

/// The format of emitted log lines
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    TextFull,
    Json,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogTarget {
    Stdout,
    Stderr,
    File(PathBuf),
}

//Because serde is particular with its options and we want
//to be retrocompatible, we'll keep Stdout as the default
//log target, but it has to be through a function that gets
//passed to serde(default ...) below.
pub fn default_logtarget() -> LogTarget {
    LogTarget::Stdout
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub node_id: u64,
    pub dc_id: u64,
    #[serde(with = "LevelDef")]
    pub level: Level,
    pub format: LogFormat,
    pub debug_overrides: Vec<String>,
    pub sampling_rates: HashMap<String, u32>,
    pub enabled_tags: Vec<String>,
    #[serde(default = "default_logtarget")]
    pub target: LogTarget,

    // If `true` the async channel for low-priority messages will block instead of drop messages.
    // This behavior is required for instrumentation in System Testing until we have a
    // dedicated solution for instrumentation.
    //
    // The default for this value is `false` and thus matches the previously expected behavior in
    // production use cases.
    #[serde(default = "Default::default")]
    pub block_on_overflow: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node_id: 100,
            dc_id: 200,
            level: Level::Debug,
            format: LogFormat::TextFull,
            debug_overrides: vec![],
            sampling_rates: HashMap::new(),
            enabled_tags: vec![],
            target: default_logtarget(),
            block_on_overflow: false,
        }
    }
}
