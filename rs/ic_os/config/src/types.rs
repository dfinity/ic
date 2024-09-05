use ic_types::malicious_behaviour::MaliciousBehaviour;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
pub struct SetupOSConfig {
    pub network_settings: NetworkSettings,
    pub icos_settings: ICOSSettings,
    pub hostos_settings: HostOSSettings,
    pub guestos_settings: GuestOSSettings,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HostOSConfig {
    pub network_settings: NetworkSettings,
    pub icos_settings: ICOSSettings,
    pub hostos_settings: HostOSSettings,
    pub guestos_settings: GuestOSSettings,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GuestOSConfig {
    pub network_settings: NetworkSettings,
    pub icos_settings: ICOSSettings,
    pub guestos_settings: GuestOSSettings,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HostOSSettings {
    pub vm_memory: u32,
    pub vm_cpu: String,
    pub verbose: bool,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkSettings {
    pub ipv6_prefix: Option<Ipv6Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub ipv6_gateway: Ipv6Addr,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv4_gateway: Option<Ipv4Addr>,
    pub ipv4_prefix_length: Option<u8>,
    pub domain: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ICOSSettings {
    pub nns_public_key_path: PathBuf,
    pub nns_urls: Vec<Url>,
    pub elasticsearch_hosts: String,
    // help: elasticsearch_tags is a dev field?
    pub elasticsearch_tags: Option<String>,
    pub hostname: String,
    pub node_operator_private_key_path: Option<PathBuf>,
    pub ssh_authorized_keys_path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct GuestOSSettings {
    pub ic_crypto_path: Option<PathBuf>,
    pub ic_state_path: Option<PathBuf>,
    pub ic_registry_local_store_path: Option<PathBuf>,
    pub guestos_dev: GuestosDevConfig,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct GuestosDevConfig {
    pub backup_retention_time_seconds: Option<String>,
    pub backup_purging_interval_seconds: Option<String>,
    pub malicious_behavior: Option<MaliciousBehaviour>,
    pub query_stats_epoch_length: Option<String>,
    pub bitcoind_addr: Option<String>,
    pub jaeger_addr: Option<String>,
    pub socks_proxy: Option<String>,
}
