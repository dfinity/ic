use ic_config::logger::Config as LoggerConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

const DEFAULT_HTTP_CONNECT_TIMEOUT_SECS: u64 = 1;
const DEFAULT_HTTP_REQUEST_TIMEOUT_SECS: u64 = 3;
const DEFAULT_HTTP_REQUEST_SIZE_LIMIT_BYTES: u64 = 1048576; // 1Mb

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
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub http_connect_timeout_secs: u64,
    pub http_request_timeout_secs: u64,
    pub http_request_size_limit_bytes: u64,
    pub incoming_source: IncomingSource,
    pub logger: LoggerConfig,
    // Boundary node socks proxy on mainnet: https://gitlab.com/dfinity-lab/public/ic/-/blob/master/ic-os/boundary-guestos/doc/Components.adoc#user-content-socks-proxy
    // Testing environment shared socks proxy address: socks5.testnet.dfinity.network:1080
    pub socks_proxy: Option<Url>,
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
