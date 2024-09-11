use ic_types::malicious_behaviour::MaliciousBehaviour;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use url::Url;

/// SetupOS configuration. User-facing configuration files
/// (e.g., `config.ini`, `deployment.json`) are transformed into `SetupOSConfig`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SetupOSConfig {
    pub network_settings: NetworkSettings,
    pub icos_settings: ICOSSettings,
    pub setupos_settings: SetupOSSettings,
    pub hostos_settings: HostOSSettings,
    pub guestos_settings: GuestOSSettings,
}

/// HostOS configuration. In production, this struct inherits settings from `SetupOSConfig`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HostOSConfig {
    pub network_settings: NetworkSettings,
    pub icos_settings: ICOSSettings,
    pub hostos_settings: HostOSSettings,
    pub guestos_settings: GuestOSSettings,
}

/// GuestOS configuration. In production, this struct inherits settings from `HostOSConfig`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct GuestOSConfig {
    pub network_settings: NetworkSettings,
    pub icos_settings: ICOSSettings,
    pub guestos_settings: GuestOSSettings,
}

/// Placeholder for SetupOS-specific settings.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SetupOSSettings;

/// HostOS-specific settings.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HostOSSettings {
    pub vm_memory: u32,
    pub vm_cpu: String,
    pub verbose: bool,
}

/// GuestOS-specific settings.
#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct GuestOSSettings {
    pub ic_crypto_path: Option<PathBuf>,
    pub ic_state_path: Option<PathBuf>,
    pub ic_registry_local_store_path: Option<PathBuf>,
    pub guestos_dev: GuestosDevConfig,
}

/// GuestOS development configuration. These settings are strictly used for development images.
#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct GuestosDevConfig {
    pub backup_retention_time_seconds: Option<String>,
    pub backup_purging_interval_seconds: Option<String>,
    pub malicious_behavior: Option<MaliciousBehaviour>,
    pub query_stats_epoch_length: Option<String>,
    pub bitcoind_addr: Option<String>,
    pub jaeger_addr: Option<String>,
    pub socks_proxy: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct NetworkSettings {
    // Config files can specify ipv6_prefix and ipv6_gateway, or just an ipv6_address.
    // ipv6_address takes precedence. Some tests provide only ipv6_address.
    pub ipv6_prefix: Option<String>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub ipv6_prefix_length: u8,
    pub ipv6_gateway: Ipv6Addr,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv4_gateway: Option<Ipv4Addr>,
    pub ipv4_prefix_length: Option<u8>,
    pub domain: Option<String>,
    pub mgmt_mac: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ICOSSettings {
    pub logging: Logging,
    pub nns_public_key_path: PathBuf,
    pub nns_urls: Vec<Url>,
    pub hostname: String,
    pub node_operator_private_key_path: Option<PathBuf>,
    pub ssh_authorized_keys_path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Logging {
    pub elasticsearch_hosts: String,
    pub elasticsearch_tags: Option<String>,
}

// ConfigIniSettings is not a public config interface and is strictly used for parsing config.ini
pub struct ConfigIniSettings {
    pub network_settings: NetworkSettings,
    pub verbose: bool,
}
