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
    /// Externally generated cryptographic keys.
    /// Must be a directory with contents matching the internal representation of the ic_crypto directory. 
    /// When given, this provides the private keys of the node. 
    /// If not given, the node will generate its own private/public key pair.
    pub ic_crypto_path: Option<PathBuf>,
    pub ic_state_path: Option<PathBuf>,
    /// Initial registry state.
    /// Must be a directory with contents matching the internal representation of the ic_registry_local_store.
    /// When given, this provides the initial state of the registry. 
    /// If not given, the node will fetch (initial) registry state from the NNS.
    pub ic_registry_local_store_path: Option<PathBuf>,
    pub guestos_dev: GuestosDevConfig,
}

/// GuestOS development configuration. These settings are strictly used for development images.
#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct GuestosDevConfig {
    pub backup_spool: Option<BackupSpoolSettings>,
    pub malicious_behavior: Option<MaliciousBehaviour>,
    pub query_stats_epoch_length: Option<String>,
    pub bitcoind_addr: Option<String>,
    pub jaeger_addr: Option<String>,
    pub socks_proxy: Option<String>,
}

/// Configures the usage of the backup spool directory.
#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct BackupSpoolSettings {
    /// The maximum age of any file or directory kept in the backup spool.
    pub backup_retention_time_seconds: Option<String>,
    /// The interval at which the backup spool directory will be scanned for files to delete.
    pub backup_purging_interval_seconds: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct NetworkSettings {
    // Config.ini can specify ipv6_prefix and ipv6_gateway, or just an ipv6_address.
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
    /// This file must be a text file containing the public key of the NNS to be used.
    pub nns_public_key_path: PathBuf,
    /// The URL (HTTP) of the NNS node(s).
    pub nns_urls: Vec<Url>,
    pub hostname: String,
    /// This file contains the Node Operator private key,
    /// which is registered with the NNS and used to sign the IC join request. 
    pub node_operator_private_key_path: Option<PathBuf>,
    /// This directory contains individual files named `admin`, `backup`, `readonly`. 
    /// The contents of these files serve as `authorized_keys` for their respective role account. 
    /// This means that, for example, `accounts_ssh_authorized_keys/admin` 
    /// is transferred to `~admin/.ssh/authorized_keys` on the target system.
    /// backup and readonly can only be modified via an NNS proposal
    /// and are in place for subnet recovery or issue debugging purposes.
    pub ssh_authorized_keys_path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Logging {
    /// Space-separated lists of hosts to ship logs to.
    pub elasticsearch_hosts: String,
    /// Space-separated list of tags to apply to exported log records.
    pub elasticsearch_tags: Option<String>,
}
