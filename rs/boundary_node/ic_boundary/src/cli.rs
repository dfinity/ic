use candid::Principal;
use clap::{Args, Parser};
use humantime::parse_duration;
use ic_bn_lib::{
    http::{
        self,
        shed::cli::{ShedSharded, ShedSystem},
    },
    parse_size, parse_size_usize,
};
use ic_config::crypto::CryptoConfig;
use ic_types::CanisterId;
use std::time::Duration;
use std::{net::SocketAddr, path::PathBuf};
use url::Url;

use crate::{
    core::{AUTHOR_NAME, SERVICE_NAME},
    http::RequestType,
};

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = AUTHOR_NAME)]
pub struct Cli {
    #[command(flatten, next_help_heading = "Listen")]
    pub listen: Listen,

    #[command(flatten, next_help_heading = "Network")]
    pub network: Network,

    #[command(flatten, next_help_heading = "HTTP Server")]
    pub http_server: http::server::cli::HttpServer,

    #[command(flatten, next_help_heading = "HTTP Client")]
    pub http_client: http::client::cli::HttpClient,

    #[command(flatten, next_help_heading = "TLS settings")]
    pub tls: Tls,

    #[command(flatten, next_help_heading = "Registry")]
    pub registry: Registry,

    #[command(flatten, next_help_heading = "Health")]
    pub health: Health,

    #[command(flatten, next_help_heading = "Observability")]
    pub obs: Observability,

    #[command(flatten, next_help_heading = "Rate Limiting")]
    pub rate_limiting: RateLimiting,

    #[command(flatten, next_help_heading = "Caching")]
    pub cache: Cache,

    #[command(flatten, next_help_heading = "Retries")]
    pub retry: Retry,

    #[command(flatten, next_help_heading = "Load")]
    pub load: Load,

    #[command(flatten, next_help_heading = "Nftables")]
    pub nftables: NfTables,

    #[command(flatten, next_help_heading = "Shedding System")]
    pub shed_system: ShedSystem,

    #[command(flatten, next_help_heading = "Shedding Latency")]
    pub shed_latency: ShedSharded<RequestType>,

    #[command(flatten, next_help_heading = "Firewall Bouncer")]
    pub bouncer: Bouncer,

    #[command(flatten, next_help_heading = "Misc")]
    pub misc: Misc,
}

#[derive(Args)]
pub struct Registry {
    /// Comma separated list of NNS URLs to bootstrap the registry
    #[clap(env, long, value_delimiter = ',', default_value = "https://ic0.app")]
    pub registry_nns_urls: Vec<Url>,

    /// The path to the NNS public key file
    #[clap(env, long)]
    pub registry_nns_pub_key_pem: Option<PathBuf>,

    /// The delay between NNS polls
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub registry_nns_poll_interval: Duration,

    /// The registry local store path to be populated
    #[clap(env, long)]
    pub registry_local_store_path: Option<PathBuf>,

    /// Whether to disable internal registry replicator
    #[clap(env, long)]
    pub registry_disable_replicator: bool,

    /// Instead of using the registry - use the specified replica nodes.
    /// This disables the registry client, registry replicator and health checking.
    /// To be used only for performance testing.
    #[clap(env, long)]
    pub registry_stub_replica: Vec<SocketAddr>,

    /// Minimum snapshot version age to be useful for initial publishing
    #[clap(env, long, default_value = "10s", value_parser = parse_duration)]
    pub registry_min_version_age: Duration,
}

#[derive(Args)]
pub struct Load {
    /// Max number of in-flight requests that can be served in parallel.
    /// If this is exceeded - new requests would be throttled.
    #[clap(env, long)]
    pub load_max_concurrency: Option<usize>,
}

#[derive(Args)]
pub struct Listen {
    /// Port to listen on for HTTP (listens on IPv6 wildcard "::")
    #[clap(env, long)]
    pub listen_http_port: Option<u16>,

    /// Port to listen for HTTPS (listens on IPv6 wildcard "::")
    #[clap(env, long)]
    pub listen_https_port: Option<u16>,

    /// Unix socket to listen on for HTTP
    #[clap(env, long)]
    pub listen_http_unix_socket: Option<PathBuf>,

    /// Port on 127.0.0.1 to listen on for loopback usage.
    /// Only needed if a rate-limiting canister or anonymization salt canister is used.
    /// Change if the default one is occupied for whatever reason.
    #[clap(env, long, default_value = "31337")]
    pub listen_http_port_loopback: u16,
}

#[derive(Args)]
pub struct Network {
    /// Disable HTTP2 support for outgoing connections (to replicas)
    #[clap(env, long)]
    pub network_disable_http2_client: bool,

    /// Number of HTTP clients to create to spread the load over
    #[clap(env, long, default_value = "1", value_parser = clap::value_parser!(u16).range(1..))]
    pub network_http_client_count: u16,
}

#[derive(Args)]
pub struct Health {
    /// How frequently to run health checks
    #[clap(env, long, default_value = "1s", value_parser = parse_duration)]
    pub health_check_interval: Duration,

    /// How frequently to recalculate healthy nodes set (per-subnet) e.g. based on height lagging
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub health_update_interval: Duration,

    /// Timeout for the health check request.
    /// This includes connection phase and the actual HTTP request.
    /// Should be longer than HTTP client connect timeout.
    #[clap(env, long, default_value = "4s", value_parser = parse_duration)]
    pub health_check_timeout: Duration,

    /// Maximum block height lag for a replica to be included in the routing table
    #[clap(env, long, default_value = "50")]
    pub health_max_height_lag: u64,

    /// Fraction of nodes that should be healthy in the subnet to consider the subnet healthy
    #[clap(env, long, default_value = "0.6666")]
    pub health_nodes_per_subnet_alive_threshold: f64,

    /// Fraction of subnets that should be healthy to consider our node healthy
    #[clap(env, long, default_value = "0.51")]
    pub health_subnets_alive_threshold: f64,
}

#[derive(Args)]
pub struct NfTables {
    /// The path to the nftables replica ruleset file to update
    #[clap(env, long)]
    pub nftables_system_replicas_path: Option<PathBuf>,

    /// The name of the nftables variable to export
    #[clap(env, long, default_value = "ipv6_system_replica_ips")]
    pub nftables_system_replicas_var: String,
}

#[derive(Args)]
pub struct Tls {
    /// Hostname to request TLS certificate for
    #[clap(env, long)]
    pub tls_hostname: Option<String>,

    /// Path to the ACME credentials folder, needs to be writeable - it stores the account info & issued certificate.
    /// This enables the ACME client.
    /// On the first start the account will be created.
    #[clap(env, long)]
    pub tls_acme_credentials_path: Option<PathBuf>,

    /// Whether to use LetsEncrypt staging environment.
    #[clap(env, long)]
    pub tls_acme_staging: bool,

    /// The path to the TLS certificate in PEM format.
    /// This is required if the ACME client is not used.
    #[clap(env, long)]
    pub tls_cert_path: Option<PathBuf>,

    /// The path to the TLS private key in PEM format.
    /// This is required if the ACME client is not used.
    #[clap(env, long)]
    pub tls_pkey_path: Option<PathBuf>,
}

#[derive(Args)]
pub struct Observability {
    /// The socket used to export metrics.
    #[clap(env, long, default_value = "127.0.0.1:9090")]
    pub obs_metrics_addr: SocketAddr,

    /// Maximum logging level
    #[clap(env, long, default_value = "info")]
    pub obs_max_logging_level: tracing::Level,

    /// Disable per-request logging and metrics recording
    #[clap(env, long)]
    pub obs_disable_request_logging: bool,

    /// Log only failed (non-2xx status code or other problems) requests
    #[clap(env, long)]
    pub obs_log_failed_requests_only: bool,

    /// Enables logging to stdout
    #[clap(env, long)]
    pub obs_log_stdout: bool,

    /// Enables logging to Journald
    #[clap(env, long)]
    pub obs_log_journald: bool,

    /// Enables Websocket endpoint to subscribe to logs
    #[clap(env, long)]
    pub obs_log_websocket: bool,

    /// Websocket broker buffer size (per-topic)
    #[clap(env, long, default_value = "1000")]
    pub obs_log_websocket_buffer: usize,

    /// Websocket broker topic idle timeout, after which the topic is removed.
    #[clap(env, long, default_value = "10m", value_parser = parse_duration)]
    pub obs_log_websocket_idle_timeout: Duration,

    /// Websocket broker max topics
    #[clap(env, long, default_value = "100000")]
    pub obs_log_websocket_max_topics: u64,

    /// Websocket broker max subscribers (per-Topic total)
    #[clap(env, long, default_value = "1000")]
    pub obs_log_websocket_max_subscribers_per_topic: usize,

    /// Websocket max subscribers (per-Topic per-IP), 2^16 max
    #[clap(env, long, default_value = "5")]
    pub obs_log_websocket_max_subscribers_per_topic_per_ip: u16,

    /// Enables logging to /dev/null (to benchmark logging)
    #[clap(env, long)]
    pub obs_log_null: bool,

    /// Log Anonymization Canister ID
    #[clap(env, long)]
    pub obs_log_anonymization_canister_id: Option<Principal>,

    /// Frequency to poll the canister for the anonymization salt
    #[clap(env, long, default_value = "60s", value_parser = parse_duration)]
    pub obs_log_anonymization_poll_interval: Duration,
}

#[derive(Args)]
pub struct RateLimiting {
    /// Allowed number of update calls per second per subnet per boundary node. Panics if 0 is passed!
    #[clap(env, long)]
    pub rate_limit_per_second_per_subnet: Option<u32>,

    /// Allowed number of update calls per second per ip per boundary node. Panics if 0 is passed!
    #[clap(env, long)]
    pub rate_limit_per_second_per_ip: Option<u32>,

    /// Path to a generic rate-limiter rules, if the file does not exist - no rules are applied.
    /// File is checked every 10sec and is reloaded if the changes are detected.
    /// Expecting YAML list with objects that have at least one of
    /// (canister_id, subnet_id, methods_regex, request_types, limit) fields.
    /// E.g.
    ///
    /// - canister_id: aaaaa-aa
    ///   methods_regex: ^(foo|bar)$
    ///   request_types: [query]
    ///   limit: 60/1s
    ///
    /// - subnet_id: aaaaaa-aa
    ///   canister_id: aaaaa-aa
    ///   methods_regex: ^baz$
    ///   limit: block
    #[clap(env, long)]
    pub rate_limit_generic_file: Option<PathBuf>,

    /// ID of the rate-limiting canister where to obtain the rules.
    /// If specified together with the file above - file takes precedence.
    #[clap(env, long)]
    pub rate_limit_generic_canister_id: Option<CanisterId>,

    /// How frequently to poll for rules (from file or canister)
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub rate_limit_generic_poll_interval: Duration,

    /// Time-to-idle for rules that have the `ip_group_prefix`.
    /// If no requests are coming for the given shard - it will be removed.
    #[clap(env, long, default_value = "1h", value_parser = parse_duration)]
    pub rate_limit_generic_tti: Duration,

    /// Maximum number of shards that we store (per rule)
    #[clap(env, long, default_value = "30000")]
    pub rate_limit_generic_max_shards: u64,

    /// Whether to use the number of API BNs from the registry to scale the rate limit rules.
    /// E.g. if a ratelimit action is set to "500/1h" and the number of API BNs is 5 then the
    /// rule would be adjusted to "100/1h" so that the total ratelimit of all API BNs would be "500/1h".
    /// Important: if after the divison the numerator would be less than 1 then it would be rounded to 1.
    #[clap(env, long)]
    pub rate_limit_generic_autoscale: bool,
}

#[derive(Args)]
pub struct Cache {
    /// Maximum size of in-memory cache in bytes. Specify a size to enable caching.
    #[clap(env, long, value_parser = parse_size)]
    pub cache_size: Option<u64>,

    /// Maximum size of a single cached response item in bytes
    #[clap(env, long, default_value = "10MB", value_parser = parse_size_usize)]
    pub cache_max_item_size: usize,

    /// Time-to-live for cache entries
    #[clap(env, long, default_value = "1s", value_parser = parse_duration)]
    pub cache_ttl: Duration,

    /// Whether to cache non-anonymous requests
    #[clap(env, long, default_value = "false")]
    pub cache_non_anonymous: bool,
}

#[derive(Args)]
pub struct Retry {
    /// How many times to retry a failed request.
    /// Should be in range [0..10], value of 0 disables the retries.
    /// If there are less healthy nodes in the subnet - then less retries would be done.
    #[clap(env, long, default_value = "2", value_parser = clap::value_parser!(u8).range(0..11))]
    pub retry_count: u8,

    /// Whether to retry update calls
    #[clap(env, long, default_value = "false")]
    pub retry_update_call: bool,

    /// Whether to use latency-based routing for /call
    #[clap(env, long, default_value = "false")]
    pub retry_disable_latency_routing: bool,
}

#[derive(Args)]
pub struct Bouncer {
    /// Enable the firewall bouncer
    #[clap(env, long)]
    pub bouncer_enable: bool,

    /// Whether to use sudo to call `nft` executable
    #[clap(env, long, default_value = "true")]
    pub bouncer_sudo: bool,

    /// Path to a sudo binary, defaults to /usr/bin/sudo
    #[clap(env, long)]
    pub bouncer_sudo_path: Option<String>,

    /// Path to a nft binary, defaults to /usr/sbin/nft
    #[clap(env, long)]
    pub bouncer_nft_path: Option<String>,

    /// Number of requests per second that are allowed from a single IP
    #[clap(env, long, default_value = "300", value_parser = clap::value_parser!(u32).range(1..))]
    pub bouncer_ratelimit: u32,

    /// Number of requests in a burst allowed, must be higher than --bouncer-ratelimit
    #[clap(env, long, default_value = "600", value_parser = clap::value_parser!(u32).range(1..))]
    pub bouncer_burst_size: u32,

    /// For how long to ban the IPs
    #[clap(env, long, default_value = "10m", value_parser = parse_duration)]
    pub bouncer_ban_time: Duration,

    /// Maximum number of IPs to track. This restricts memory usage to store buckets.
    /// If exceeded - old ones will be removed
    #[clap(env, long, default_value = "20000")]
    pub bouncer_max_buckets: u64,

    /// TTL of a per-IP bucket. If no requests are coming from given IP for this duration
    /// then the bucket is removed
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub bouncer_bucket_ttl: Duration,

    /// How frequently to check if updates to the firewall are needed
    #[clap(env, long, default_value = "1s", value_parser = parse_duration)]
    pub bouncer_apply_interval: Duration,

    /// NFTables table name for IPv4
    #[clap(env, long, default_value = "filter")]
    pub bouncer_v4_table: String,

    /// NFTables set name for IPv4
    #[clap(env, long, default_value = "blackhole")]
    pub bouncer_v4_set: String,

    /// NFTables table name for IPv6
    #[clap(env, long, default_value = "filter")]
    pub bouncer_v6_table: String,

    /// NFTables set name for IPv6
    #[clap(env, long, default_value = "blackhole6")]
    pub bouncer_v6_set: String,
}

#[derive(Args)]
pub struct Misc {
    /// Path to a GeoIP country database file
    #[clap(env, long)]
    pub geoip_db: Option<PathBuf>,

    /// Skip replica TLS certificate verification. DANGER: to be used only for testing
    #[clap(env, long)]
    pub skip_replica_tls_verification: bool,

    /// Configuration of the node's crypto-vault to use with the IC agent.
    /// If not specified - then the agent will use anonymous sender.
    #[clap(env, long, value_parser=parse_crypto_config)]
    pub crypto_config: Option<CryptoConfig>,
}

fn parse_crypto_config(arg: &str) -> Result<CryptoConfig, serde_json::Error> {
    serde_json::from_str(arg)
}
