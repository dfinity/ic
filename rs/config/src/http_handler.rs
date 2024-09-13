use crate::execution_environment::QUERY_EXECUTION_THREADS_TOTAL;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

const DEFAULT_IP_ADDR: &str = "0.0.0.0";

const DEFAULT_PORT: u16 = 8080u16;

/// The internal configuration -- any historical warts from the external
/// configuration are removed. Anything using this struct can trust that it
/// has been validated.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    /// IP address and port to listen on
    pub listen_addr: SocketAddr,

    /// The path to write the listening port to
    pub port_file_path: Option<PathBuf>,

    /// If no bytes are read from a connection for the duration of
    /// 'connection_read_timeout_seconds', then the connection is dropped.
    /// There is no point is setting a timeout on the write bytes since
    /// they are conditioned on the received requests.
    pub connection_read_timeout_seconds: u64,

    /// Per request timeout in seconds before the server replies with `504 Gateway Timeout`.
    pub request_timeout_seconds: u64,

    /// The `SETTINGS_MAX_CONCURRENT_STREAMS` option for HTTP2 connections.
    pub http_max_concurrent_streams: u32,

    /// Request with body size bigger than `max_request_size_bytes` will be rejected
    /// and [`413 Content Too Large`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/413) will be returned to the user.
    pub max_request_size_bytes: u64,

    /// Delegation certificate requests with body size bigger than `max_delegation_certificate_size_bytes`
    /// will be rejected. For valid IC delegation certificates this is never the case since the size is always constant.
    pub max_delegation_certificate_size_bytes: u64,

    /// Serving at most `max_read_state_concurrent_requests` requests concurrently for endpoint `/api/v2/read_state`.
    pub max_read_state_concurrent_requests: usize,

    /// Serving at most `max_status_concurrent_requests` requests concurrently for endpoint `/api/v2/status`.
    pub max_status_concurrent_requests: usize,

    /// Serving at most `max_catch_up_package_concurrent_requests` requests concurrently for endpoint `/_/catch_up_package`.
    pub max_catch_up_package_concurrent_requests: usize,

    /// Serving at most `max_dashboard_concurrent_requests` requests concurrently for endpoint `/_/dashboard`.
    pub max_dashboard_concurrent_requests: usize,

    /// Serving at most `max_call_concurrent_requests` requests concurrently for endpoint `/api/v2/call`.
    pub max_call_concurrent_requests: usize,

    /// Serving at most `max_call_concurrent_requests` requests concurrently for endpoint `/api/v2/query`.
    pub max_query_concurrent_requests: usize,

    /// Serving at most `max_pprof_concurrent_requests` requessts concurrently for all endpoints under `/_/pprof`.
    pub max_pprof_concurrent_requests: usize,

    /// The maximum time the replica will wait for a message to be certified before timing out the requests and responding with `202`, for endpoint `/api/v3/call`.
    pub ingress_message_certificate_timeout_seconds: u64,

    /// Serving at most `max_tracing_flamegraph_concurrent_requests` requests concurrently for all endpoints under `/_/tracing/flamegraph`.
    pub max_tracing_flamegraph_concurrent_requests: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::new(
                DEFAULT_IP_ADDR.parse().expect("can't fail"),
                DEFAULT_PORT,
            ),
            port_file_path: None,
            connection_read_timeout_seconds: 1_200, // 20 min
            request_timeout_seconds: 300,           // 5 min
            http_max_concurrent_streams: 1000,
            max_request_size_bytes: 5 * 1024 * 1024, // 5MB
            max_delegation_certificate_size_bytes: 1024 * 1024, // 1MB
            max_read_state_concurrent_requests: 100,
            max_catch_up_package_concurrent_requests: 100,
            max_dashboard_concurrent_requests: 100,
            max_status_concurrent_requests: 100,
            max_call_concurrent_requests: 50,
            max_query_concurrent_requests: QUERY_EXECUTION_THREADS_TOTAL * 100,
            max_pprof_concurrent_requests: 5,
            ingress_message_certificate_timeout_seconds: 10,
            max_tracing_flamegraph_concurrent_requests: 5,
        }
    }
}
