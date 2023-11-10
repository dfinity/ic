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
}

#[derive(Args)]
pub struct RegistryConfig {
    /// Comma separated list of NNS URLs to bootstrap the registry
    #[clap(long, value_delimiter = ',', default_value = "https://ic0.app")]
    pub nns_urls: Vec<Url>,

    /// The path to the NNS public key file
    #[clap(long)]
    pub nns_pub_key_pem: PathBuf,

    /// The delay between NNS polls in milliseconds
    #[clap(long, default_value = "5000")]
    pub nns_poll_interval_ms: u64,

    /// The registry local store path to be populated
    #[clap(long)]
    pub local_store_path: PathBuf,

    /// Whether to disable internal registry replicator
    #[clap(long, default_value = "false")]
    pub disable_registry_replicator: bool,

    /// Minimum snapshot version age to be useful for initial publishing, in seconds
    #[clap(long, default_value = "10")]
    pub min_version_age: u64,
}

#[derive(Args)]
pub struct ListenConfig {
    /// Port to listen for HTTP
    #[clap(long, default_value = "80")]
    pub http_port: u16,

    /// Port to listen for HTTPS
    #[cfg(feature = "tls")]
    #[clap(long, default_value = "443")]
    pub https_port: u16,

    /// Timeout for the whole HTTP request in seconds
    #[clap(long, default_value = "600")]
    pub http_timeout: u64,

    /// Timeout for the HTTP connect phase in seconds
    #[clap(long, default_value = "2")]
    pub http_timeout_connect: u64,

    /// Max number of in-flight requests that can be served in parallel
    /// If this is exceeded - new requests would be throttled
    #[clap(long, default_value = "512")]
    pub max_concurrency: usize,

    /// How frequently to send TCP/HTTP2 keepalives, in seconds
    #[clap(long, default_value = "15")]
    pub http_keepalive: u64,

    /// How long to wait for a keepalive response, in seconds
    #[clap(long, default_value = "3")]
    pub http_keepalive_timeout: u64,

    /// How long to keep idle outgoing connections open
    #[clap(long, default_value = "10")]
    pub http_idle_timeout: u64,
}

#[derive(Args)]
pub struct HealthChecksConfig {
    /// How frequently to run node checks in seconds
    #[clap(long, default_value = "10")]
    pub check_interval: u64,

    /// How many attempts to do when checking a node
    #[clap(long, default_value = "3")]
    pub check_retries: u32,

    /// How long to wait between retries in seconds
    #[clap(long, default_value = "1")]
    pub check_retry_interval: u64,

    /// Minimum registry version snapshot to process
    #[clap(long, default_value = "0")]
    pub min_registry_version: u64,

    /// Minimum required OK health checks
    /// for a replica to be included in the routing table
    #[clap(long, default_value = "1")]
    pub min_ok_count: u8,

    /// Maximum block height lag for a replica to be included in the routing table
    #[clap(long, default_value = "1000")]
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
    /// The path to the ACME credentials file

    #[clap(long, default_value = "acme.json")]
    pub acme_credentials_path: PathBuf,

    /// The path to the ingress TLS cert
    #[clap(long, default_value = "cert.pem")]
    pub tls_cert_path: PathBuf,

    /// The path to the ingress TLS private-key
    #[clap(long, default_value = "pkey.pem")]
    pub tls_pkey_path: PathBuf,
}

#[derive(Args)]
pub struct MonitoringConfig {
    /// The socket used to export metrics.
    #[clap(long, default_value = "127.0.0.1:9090")]
    pub metrics_addr: SocketAddr,
}

#[derive(Args)]
pub struct RateLimitingConfig {
    /// Allowed number of update calls per second per subnet per boundary node. Panics if 0 is passed!
    #[clap(long)]
    pub rate_limit_per_second_per_subnet: Option<u32>,
    /// Allowed number of update calls per second per ip per boundary node. Panics if 0 is passed!
    #[clap(long)]
    pub rate_limit_per_second_per_ip: Option<u32>,
}

#[derive(Args)]
pub struct CacheConfig {
    /// Maximum size of in-memory cache in bytes. Specify a size to enable caching.
    #[clap(long)]
    pub cache_size_bytes: Option<u64>,
    /// Maximum size of a single cached response item in bytes
    #[clap(long, default_value = "65536")]
    pub cache_max_item_size_bytes: u64,
    /// Time-to-live for cache entries in seconds
    #[clap(long, default_value = "1")]
    pub cache_ttl_seconds: u64,
    /// Whether to cache non-anonymous requests
    #[clap(long, default_value = "false")]
    pub cache_non_anonymous: bool,
}
