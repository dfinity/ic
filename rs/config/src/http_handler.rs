use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

const DEFAULT_IP_ADDR: &str = "0.0.0.0";

const DEFAULT_PORT: u16 = 8080u16;

/// The internal configuration -- any historical warts from the external
/// configuration are removed. Anything using this struct can trust that it
/// has been validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// IP address and port to listen on
    pub listen_addr: SocketAddr,
    /// The path to write the listening port to
    pub port_file_path: Option<PathBuf>,

    /// We can serve from at most 'max_outstanding_connections'
    /// live TCP connections. If we are at the limit and a new
    /// TCP connection arrives, we accept and drop it immediately.
    #[serde(default = "default_max_outstanding_connections")]
    pub max_outstanding_connections: usize,

    /// If no bytes are read from a connection for the duration of
    /// 'connection_read_timeout_seconds', then the connection is dropped.
    /// There is no point is setting a timeout on the write bytes since
    /// they are conditioned on the received requests.
    #[serde(default = "default_connection_read_timeout_seconds")]
    pub connection_read_timeout_seconds: u64,

    /// Per request timeout in seconds before the server replies with 504 Gateway Timeout.
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
}

fn default_max_outstanding_connections() -> usize {
    20_000
}

fn default_connection_read_timeout_seconds() -> u64 {
    1_200 // 20 min
}

fn default_request_timeout_seconds() -> u64 {
    300 // 5 min
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::new(
                DEFAULT_IP_ADDR.parse().expect("can't fail"),
                DEFAULT_PORT,
            ),
            port_file_path: None,
            max_outstanding_connections: default_max_outstanding_connections(),
            connection_read_timeout_seconds: default_connection_read_timeout_seconds(),
            request_timeout_seconds: default_request_timeout_seconds(),
        }
    }
}
