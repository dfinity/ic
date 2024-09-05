use anyhow::{Context, Result};
use ic_types::malicious_behaviour::MaliciousBehaviour;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::Read;
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
    pub nns_url: Vec<Url>,
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

pub fn deserialize_config<T: for<'de> Deserialize<'de>>(file_path: &str) -> Result<T> {
    let mut file =
        File::open(file_path).with_context(|| format!("Failed to open file: {}", file_path))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .with_context(|| format!("Failed to read file: {}", file_path))?;

    let json_value: Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON from file: {}", file_path))?;
    let deserialized: T = serde_json::from_value(json_value)
        .with_context(|| "Failed to deserialize JSON to the specified type".to_string())?;

    Ok(deserialized)
}
