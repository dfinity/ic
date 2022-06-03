use ic_config::logger::Config as LoggerConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_HTTP_CONNECT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_HTTP_REQUEST_TIMEOUT_SECS: u64 = 10;
const DEFAULT_HTTP_REQUEST_SIZE_LIMIT_BYTES: usize = 10 * 1024 * 1024; // 10Mb

#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
/// The source of the unix domain socket to be used for inter-process
/// communication.
pub enum IncomingSource {
    /// We use systemd's created socket.
    Systemd,
    /// We use the corresponing path as socket.
    Path(PathBuf),
}

impl Default for IncomingSource {
    fn default() -> Self {
        IncomingSource::Systemd
    }
}

/// This struct contains configuration options for the HTTP Adapter.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct Config {
    pub http_connect_timeout_secs: u64,
    pub http_request_timeout_secs: u64,
    pub http_request_size_limit_bytes: usize,
    pub incoming_source: IncomingSource,
    pub logger: LoggerConfig,
    /// Socks proxy docs: https://gitlab.com/dfinity-lab/public/ic/-/blob/master/ic-os/boundary-guestos/doc/Components.adoc#user-content-socks-proxy
    /// Testing environment shared socks proxy address: socks5://socks5.testnet.dfinity.network:1080
    /// Proxy url is validated and needs to have scheme, host and port specified. I.e socks5://socksproxy.com:1080.
    pub socks_proxy: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            http_connect_timeout_secs: DEFAULT_HTTP_CONNECT_TIMEOUT_SECS,
            http_request_timeout_secs: DEFAULT_HTTP_REQUEST_TIMEOUT_SECS,
            http_request_size_limit_bytes: DEFAULT_HTTP_REQUEST_SIZE_LIMIT_BYTES,
            incoming_source: IncomingSource::default(),
            logger: LoggerConfig::default(),
            socks_proxy: None,
        }
    }
}
