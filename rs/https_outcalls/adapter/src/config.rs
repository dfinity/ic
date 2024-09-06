use ic_config::logger::Config as LoggerConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_HTTP_CONNECT_TIMEOUT_SECS: u64 = 2;
const DEFAULT_HTTP_REQUEST_TIMEOUT_SECS: u64 = 30;

#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
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
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub http_connect_timeout_secs: u64,
    pub http_request_timeout_secs: u64,
    pub incoming_source: IncomingSource,
    pub logger: LoggerConfig,
    /// Socks proxy docs: https://github.com/dfinity/ic/blob/master/ic-os/boundary-guestos/docs/Components.adoc#user-content-socks-proxy
    /// Proxy url is validated and needs to have scheme, host and port specified. I.e socks5://socksproxy.com:1080
    /// `Option<String>` can't be used because the decision on using a proxy is based on the subnet and this information
    /// is not present at adapter startup. So to enable/disable the proxy there exists a `socks_proxy_allowed` field in
    /// the adapter request.
    pub socks_proxy: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            http_connect_timeout_secs: DEFAULT_HTTP_CONNECT_TIMEOUT_SECS,
            http_request_timeout_secs: DEFAULT_HTTP_REQUEST_TIMEOUT_SECS,
            incoming_source: IncomingSource::default(),
            logger: LoggerConfig::default(),
            socks_proxy: "socks5://notaproxy:1080".to_string(),
        }
    }
}
