use serde::{Deserialize, Serialize};

const DEFAULT_HTTP_CONNECT_TIMEOUT_SECS: u64 = 1;
const DEFAULT_HTTP_REQUEST_TIMEOUT_SECS: u64 = 3;
const DEFAULT_HTTP_REQUEST_SIZE_LIMIT_BYTES: u64 = 1048576; // 1Mb

/// This struct contains configuration options for the HTTP Adapter.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_http_connect_timeout_secs")]
    pub http_connect_timeout_secs: u64,
    #[serde(default = "default_http_request_timeout_secs")]
    pub http_request_timeout_secs: u64,
    #[serde(default = "default_http_request_size_limit_bytes")]
    pub http_request_size_limit_bytes: u64,
}

pub fn default_http_connect_timeout_secs() -> u64 {
    DEFAULT_HTTP_CONNECT_TIMEOUT_SECS
}
pub fn default_http_request_timeout_secs() -> u64 {
    DEFAULT_HTTP_REQUEST_TIMEOUT_SECS
}
pub fn default_http_request_size_limit_bytes() -> u64 {
    DEFAULT_HTTP_REQUEST_SIZE_LIMIT_BYTES
}
