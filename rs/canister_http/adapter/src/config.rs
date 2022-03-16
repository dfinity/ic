use ic_config::logger::Config as LoggerConfig;
use ic_logger::{new_replica_logger, LoggerImpl, ReplicaLogger};
use serde::{Deserialize, Serialize};
use slog_async::AsyncGuard;

const DEFAULT_HTTP_CONNECT_TIMEOUT_SECS: u64 = 1;
const DEFAULT_HTTP_REQUEST_TIMEOUT_SECS: u64 = 3;
const DEFAULT_HTTP_REQUEST_SIZE_LIMIT_BYTES: u64 = 1048576; // 1Mb

/// This struct contains configuration options for the HTTP Adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub http_connect_timeout_secs: u64,
    pub http_request_timeout_secs: u64,
    pub http_request_size_limit_bytes: u64,
    pub logger: LoggerConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            http_connect_timeout_secs: DEFAULT_HTTP_CONNECT_TIMEOUT_SECS,
            http_request_timeout_secs: DEFAULT_HTTP_REQUEST_TIMEOUT_SECS,
            http_request_size_limit_bytes: DEFAULT_HTTP_REQUEST_SIZE_LIMIT_BYTES,
            logger: LoggerConfig::default(),
        }
    }
}

/// Return a `ReplicaLogger` and its `AsyncGuard`
///
/// Note: Do not drop the `AsyncGuard`! If it is dropped, all async logs
/// (typically logs below level `Error`) will not be logged.
pub fn get_canister_http_logger(logger_config: &LoggerConfig) -> (ReplicaLogger, AsyncGuard) {
    let base_logger = LoggerImpl::new(logger_config, "canister-http".to_string());
    let logger = new_replica_logger(base_logger.root.clone(), logger_config);

    (logger, base_logger.async_log_guard)
}
