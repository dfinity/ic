use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Parser};
use url::Url;

use crate::core::{AUTHOR_NAME, SERVICE_NAME};

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = AUTHOR_NAME)]
pub struct Cli {
    #[command(flatten, next_help_heading = "registry")]
    pub registry: RegistryConfig,

    #[command(flatten, next_help_heading = "listen")]
    pub listen: ListenConfig,

    #[command(flatten, next_help_heading = "health")]
    pub health: HealthChecksConfig,

    #[command(flatten, next_help_heading = "firewall")]
    pub firewall: FirewallConfig,

    #[cfg(feature = "tls")]
    #[command(flatten, next_help_heading = "tls")]
    pub tls: TlsConfig,

    #[command(flatten, next_help_heading = "monitoring")]
    pub monitoring: MonitoringConfig,

    #[command(flatten, next_help_heading = "rate_limiting")]
    pub rate_limiting: RateLimitingConfig,

    #[command(flatten, next_help_heading = "cache")]
    pub cache: CacheConfig,

    #[command(flatten, next_help_heading = "retry")]
    pub retry: RetryConfig,

    #[command(flatten, next_help_heading = "bouncer")]
    pub bouncer: BouncerConfig,
}

#[derive(Args)]
pub struct RegistryConfig {
    /// Comma separated list of NNS URLs to bootstrap the registry
    #[clap(long, value_delimiter = ',', default_value = "https://ic0.app")]
    pub nns_urls: Vec<Url>,

    /// The path to the NNS public key file
    #[clap(long)]
    pub nns_pub_key_pem: Option<PathBuf>,

    /// The delay between NNS polls in milliseconds
    #[clap(long, default_value = "5000")]
    pub nns_poll_interval_ms: u64,

    /// The registry local store path to be populated
    #[clap(long)]
    pub local_store_path: Option<PathBuf>,

    /// Whether to disable internal registry replicator
    #[clap(long)]
    pub disable_registry_replicator: bool,

    /// Instead of using the registry - use the specified replica nodes.
    /// This disables the registry client, registry replicator and health checking.
    /// To be used only for performance testing.
    #[clap(long)]
    pub stub_replica: Vec<SocketAddr>,

    /// Minimum snapshot version age to be useful for initial publishing, in seconds
    #[clap(long, default_value = "10")]
    pub min_version_age: u64,
}

#[derive(Args)]
pub struct ListenConfig {
    /// Port to listen on for HTTP (listens on IPv6 wildcard "::")
    #[clap(long)]
    pub http_port: Option<u16>,

    /// Unix socket to listen on for HTTP
    #[cfg(not(feature = "tls"))]
    #[clap(long)]
    pub http_unix_socket: Option<PathBuf>,

    /// Port to listen for HTTPS
    #[cfg(feature = "tls")]
    #[clap(long, default_value = "443")]
    pub https_port: u16,

    /// Skip replica TLS certificate verification. DANGER: to be used only for testing
    #[clap(long)]
    pub skip_replica_tls_verification: bool,

    /// Timeout for the whole HTTP request in milliseconds.
    /// From when it starts connecting until the response body is finished.
    #[clap(long, default_value = "120000")]
    pub http_timeout: u64,

    /// Timeout for the HTTP connect phase in milliseconds.
    /// This is applied to both normal and health check requests.
    #[clap(long, default_value = "4000")]
    pub http_timeout_connect: u64,

    /// Max number of in-flight requests that can be served in parallel.
    /// If this is exceeded - new requests would be throttled.
    #[clap(long)]
    pub max_concurrency: Option<usize>,

    /// Exponential Weighted Moving Average parameter for load shedding algorithm.
    /// Value of 0.1 means that the next measurement would account for 10% of moving average.
    /// Should be in range 0..1.
    #[clap(long)]
    pub shed_ewma_param: Option<f64>,

    /// Target latency for load shedding algorithm in milliseconds.
    /// It tries to keep the request latency less than this.
    #[clap(long, default_value = "1200", value_parser = clap::value_parser!(u64).range(10..))]
    pub shed_target_latency: u64,

    /// How frequently to send TCP/HTTP2 keepalives, in seconds. Affects both incoming and outgoing connections.
    #[clap(long, default_value = "15")]
    pub http_keepalive: u64,

    /// How long to wait for a keepalive response, in seconds
    #[clap(long, default_value = "3")]
    pub http_keepalive_timeout: u64,

    /// How long to keep idle outgoing connections open, in seconds
    #[clap(long, default_value = "120")]
    pub http_idle_timeout: u64,

    /// Backlog of incoming connections to set on the listening socket.
    /// Currently used only for UNIX socket.
    #[clap(long, default_value = "8192")]
    pub backlog: u32,

    /// Disable HTTP2 support for outgoing connections (to replicas)
    #[clap(long)]
    pub disable_http2_client: bool,

    /// Number of HTTP clients to create to spread the load over
    #[clap(long, default_value = "1", value_parser = clap::value_parser!(u8).range(1..))]
    pub http_client_count: u8,
}

#[derive(Args)]
pub struct HealthChecksConfig {
    /// How frequently to run node checks in milliseconds
    #[clap(long, default_value = "1000")]
    pub check_interval: u64,

    /// How frequently to recalculate healthy nodes set (per-subnet) e.g. based on height lagging
    #[clap(long, default_value = "5000")]
    pub update_interval: u64,

    /// Timeout for the check request in milliseconds.
    /// This includes connection phase and the actual HTTP request.
    /// Should be longer than --http-timeout-connect
    #[clap(long, default_value = "5000")]
    pub check_timeout: u64,

    /// Maximum block height lag for a replica to be included in the routing table
    #[clap(long, default_value = "50")]
    pub max_height_lag: u64,
}

#[derive(Args)]
pub struct FirewallConfig {
    /// The path to the nftables replica ruleset file to update
    #[clap(long)]
    pub nftables_system_replicas_path: Option<PathBuf>,

    /// The name of the nftables variable to export
    #[clap(long, default_value = "ipv6_system_replica_ips")]
    pub nftables_system_replicas_var: String,
}

#[cfg(feature = "tls")]
#[derive(Args)]
pub struct TlsConfig {
    /// Hostname to request TLS certificate for
    #[clap(long, default_value = "")]
    pub hostname: String,

    /// How many days before certificate expires to start renewing it
    #[clap(long, default_value = "30", value_parser = clap::value_parser!(u32).range(1..90))]
    pub renew_days_before: u32,

    /// Path to the ACME credentials file. If file does not exist - new account will be created & saved to it, so the folder needs to be writeable.
    /// If this argument is not specified or the file is empty then ACME client will not be created and only certificate specified by
    /// --tls-*-path options will be used (this is useful mostly for testing).
    #[clap(long)]
    pub acme_credentials_path: Option<PathBuf>,

    /// The path to the ingress TLS cert.
    /// If ACME client is used (see above) - the file needs to be writeable.
    #[clap(long, default_value = "cert.pem")]
    pub tls_cert_path: Option<PathBuf>,

    /// The path to the ingress TLS private-key.
    /// If ACME client is used (see above) - the file needs to be writeable.
    #[clap(long, default_value = "pkey.pem")]
    pub tls_pkey_path: Option<PathBuf>,
}

#[derive(Args)]
pub struct MonitoringConfig {
    /// The socket used to export metrics.
    #[clap(long, default_value = "127.0.0.1:9090")]
    pub metrics_addr: SocketAddr,
    /// Maximum logging level
    #[clap(long, default_value = "info")]
    pub max_logging_level: tracing::Level,
    /// Disable per-request logging and metrics recording
    #[clap(long)]
    pub disable_request_logging: bool,
    /// Log only failed (non-2xx status code or other problems) requests
    #[clap(long)]
    pub log_failed_requests_only: bool,
    /// Enables logging to stdout
    #[clap(long)]
    pub log_stdout: bool,
    /// Enables logging to Journald
    #[clap(long)]
    pub log_journald: bool,
    /// Enables logging to /dev/null (to benchmark logging)
    #[clap(long)]
    pub log_null: bool,
    /// Path to a GeoIP country database file
    #[clap(long)]
    pub geoip_db: Option<PathBuf>,
}

#[derive(Args)]
pub struct RateLimitingConfig {
    /// Allowed number of update calls per second per subnet per boundary node. Panics if 0 is passed!
    #[clap(long)]
    pub rate_limit_per_second_per_subnet: Option<u32>,
    /// Allowed number of update calls per second per ip per boundary node. Panics if 0 is passed!
    #[clap(long)]
    pub rate_limit_per_second_per_ip: Option<u32>,
    /// Path to a generic rate-limiter rules, if the file does not exist - no rules are applied.
    /// File is checked every 10sec and is reloaded if the changes are detected.
    /// Expecting YAML list with objects that have (canister_id, methods, limit) fields.
    /// E.g.
    ///
    /// - canister_id: aaaaa-aa
    ///   methods: ^(foo|bar)$
    ///   limit: 60/1s
    ///
    /// - subnet_id: aaaaaa-aa
    ///   canister_id: aaaaa-aa
    ///   methods: ^baz$
    ///   limit: block (this blocks all requests)
    #[clap(
        long,
        default_value = "/run/ic-node/etc/ic-boundary/canister-ratelimit.yml"
    )]
    pub rate_limit_generic: PathBuf,
}

#[derive(Args)]
pub struct CacheConfig {
    /// Maximum size of in-memory cache in bytes. Specify a size to enable caching.
    #[clap(long)]
    pub cache_size_bytes: Option<u64>,
    /// Maximum size of a single cached response item in bytes
    #[clap(long, default_value = "131072")]
    pub cache_max_item_size_bytes: u64,
    /// Time-to-live for cache entries in seconds
    #[clap(long, default_value = "1")]
    pub cache_ttl_seconds: u64,
    /// Whether to cache non-anonymous requests
    #[clap(long, default_value = "false")]
    pub cache_non_anonymous: bool,
}

#[derive(Args)]
pub struct RetryConfig {
    /// How many times to retry a failed request.
    /// Should be in range [0..10], value of 0 disables the retries.
    /// If there are less healthy nodes in the subnet - then less retries would be done.
    #[clap(long, default_value = "2", value_parser = clap::value_parser!(u8).range(0..11))]
    pub retry_count: u8,

    /// Whether to retry update calls
    #[clap(long, default_value = "false")]
    pub retry_update_call: bool,

    /// Whether to use latency-based routing for /call
    #[clap(long, default_value = "false")]
    pub disable_latency_routing: bool,
}

#[derive(Args)]
pub struct BouncerConfig {
    /// Enable the firewall bouncer
    #[clap(long)]
    pub bouncer_enable: bool,

    /// Whether to use sudo to call `nft` executable
    #[clap(long, default_value = "true")]
    pub bouncer_sudo: bool,

    /// Path to a sudo binary, defaults to /usr/bin/sudo
    #[clap(long)]
    pub bouncer_sudo_path: Option<String>,

    /// Path to an nft binary, defaults to /usr/sbin/nft
    #[clap(long)]
    pub bouncer_nft_path: Option<String>,

    /// Number of requests per second that are allowed from a single IP
    #[clap(long, default_value = "300", value_parser = clap::value_parser!(u32).range(1..))]
    pub bouncer_ratelimit: u32,

    /// Number of requests in a burst allowed, must be higher than --bouncer-ratelimit
    #[clap(long, default_value = "600", value_parser = clap::value_parser!(u64).range(1..))]
    pub bouncer_burst_size: u64,

    /// For how long to ban the IPs
    #[clap(long, default_value = "600")]
    pub bouncer_ban_seconds: u64,

    /// Maximum number of IPs to track. This restricts memory usage to store buckets.
    /// If exceeded - old ones will be removed
    #[clap(long, default_value = "20000")]
    pub bouncer_max_buckets: u64,

    /// TTL of a per-IP bucket. If no requests are coming from given IP for this number
    /// of seconds then the bucket is removed
    #[clap(long, default_value = "30")]
    pub bouncer_bucket_ttl: u64,

    /// How frequently to check if updates to the firewall are needed
    #[clap(long, default_value = "1")]
    pub bouncer_apply_interval: u64,

    /// NFTables table name for IPv4
    #[clap(long, default_value = "filter")]
    pub bouncer_v4_table: String,

    /// NFTables set name for IPv4
    #[clap(long, default_value = "blackhole")]
    pub bouncer_v4_set: String,

    /// NFTables table name for IPv6
    #[clap(long, default_value = "filter")]
    pub bouncer_v6_table: String,

    /// NFTables set name for IPv6
    #[clap(long, default_value = "blackhole6")]
    pub bouncer_v6_set: String,
}
