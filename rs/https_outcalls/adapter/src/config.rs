use ic_config::logger::Config as LoggerConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_HTTP_CONNECT_TIMEOUT_SECS: u64 = 2;
const DEFAULT_HTTP_REQUEST_TIMEOUT_SECS: u64 = 30;

#[derive(Default, Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
/// The source of the unix domain socket to be used for inter-process
/// communication.
pub enum IncomingSource {
    /// We use systemd's created socket.
    #[default]
    Systemd,
    /// We use the corresponding path as socket.
    Path(PathBuf),
}

/// This struct contains configuration options for the HTTP Adapter.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct Config {
    pub http_connect_timeout_secs: u64,
    pub http_request_timeout_secs: u64,
    pub incoming_source: IncomingSource,
    pub logger: LoggerConfig,
    /// Socks proxy docs: https://github.com/dfinity/ic/blob/master/ic-os/boundary-guestos/docs/Components.adoc#user-content-socks-proxy
    /// If the socks_proxy is an empty String, the socks proxy client will be None.
    pub socks_proxy: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            http_connect_timeout_secs: DEFAULT_HTTP_CONNECT_TIMEOUT_SECS,
            http_request_timeout_secs: DEFAULT_HTTP_REQUEST_TIMEOUT_SECS,
            incoming_source: IncomingSource::default(),
            logger: LoggerConfig::default(),
            socks_proxy: String::default(),
        }
    }
}
