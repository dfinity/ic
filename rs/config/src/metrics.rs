use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exporter {
    /// Log metrics at `TRACE` level every 30 seconds.
    Log,
    /// Expose Prometheus metrics on the specified address.
    Http(SocketAddr),
    /// Dump metrics to the given file on shutdown.
    File(PathBuf),
}

impl Default for Config {
    fn default() -> Self {
        Self {
            exporter: Exporter::Log,
            connection_read_timeout_seconds: default_connection_read_timeout_seconds(),
            max_outstanding_connections: default_max_outstanding_connections(),
            max_concurrent_requests: default_max_concurrent_requests(),
            request_timeout_seconds: default_request_timeout_seconds(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub exporter: Exporter,

    /// If no bytes are read from a connection for the duration of
    /// 'connection_read_timeout_seconds', then the connection is dropped.
    /// There is no point is setting a timeout on the write bytes since
    /// they are conditioned on the received requests.
    #[serde(default = "default_connection_read_timeout_seconds")]
    pub connection_read_timeout_seconds: u64,

    /// We can serve from at most 'max_outstanding_connections'
    /// live TCP connections. If we are at the limit and a new
    /// TCP connection arrives, we accept and drop it immediately.
    #[serde(default = "default_max_outstanding_connections")]
    pub max_outstanding_connections: usize,

    /// There can be at most 'max_concurrent_requests' in-flight requests.
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,

    /// Per request timeout in seconds before the server replies with 504 Gateway Timeout.
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
}

fn default_connection_read_timeout_seconds() -> u64 {
    300 // 5 min
}

fn default_max_outstanding_connections() -> usize {
    20
}

fn default_max_concurrent_requests() -> usize {
    50
}

fn default_request_timeout_seconds() -> u64 {
    30
}
