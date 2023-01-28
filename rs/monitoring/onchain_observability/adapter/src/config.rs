use ic_config::logger::Config as LoggerConfig;
use serde::{Deserialize, Serialize};

/// This struct contains configuration options for the HTTP Adapter.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct Config {
    pub logger: LoggerConfig,
}
