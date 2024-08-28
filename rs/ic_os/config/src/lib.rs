use std::collections::HashMap;
use std::fs::read_to_string;
use std::path::Path;

use anyhow::{Context, Result};

use ic_types::malicious_behaviour::MaliciousBehaviour;

struct SetuposConfig {
    hostos_config: HostOSConfig,
}

struct HostOSConfig {
    vm_memory: u32,
    vm_cpu: String,
    ic_config: IcConfig,
}

// todo: fix types and separate dev/prod
struct IcConfig {
    networking: Networking,
    nns_public_key_path: String,
    nns_url: String,
    elasticsearch_hosts: String,
    elasticsearch_tags: Option<String>,
    hostname: String,
    node_operator_private_key_path: Option<String>,

    ic_crypto_path: String,
    ic_state_path: String,
    ic_registry_local_store_path: String,
    accounts_ssh_authorized_keys_path: String,
    backup_retention_time_seconds: String,
    backup_puging_interval_seconds: String,
    malicious_behavior: MaliciousBehaviour,
    query_stats_epoch_length: String,
    bitcoind_addr: String,
    jaeger_addr: String,
    socks_proxy: String,
}

struct Networking {
    ipv6_address: String,
    ipv6_gateway: String,
    ipv4_address: Option<String>,
    ipv4_gateway: Option<String>,
    domain: Option<String>,
}

pub type ConfigMap = HashMap<String, String>;

pub static DEFAULT_SETUPOS_CONFIG_FILE_PATH: &str = "/var/ic/config/config.ini";
pub static DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH: &str = "/data/deployment.json";

pub static DEFAULT_HOSTOS_CONFIG_FILE_PATH: &str = "/boot/config/config.ini";
pub static DEFAULT_HOSTOS_DEPLOYMENT_JSON_PATH: &str = "/boot/config/deployment.json";

fn parse_config_line(line: &str) -> Option<(String, String)> {
    // Skip blank lines and comments
    if line.is_empty() || line.trim().starts_with('#') {
        return None;
    }

    let parts: Vec<&str> = line.splitn(2, '=').collect();
    if parts.len() == 2 {
        Some((parts[0].trim().into(), parts[1].trim().into()))
    } else {
        eprintln!("Warning: skipping config line due to unrecognized format: \"{line}\"");
        eprintln!("Expected format: \"<key>=<value>\"");
        None
    }
}

pub fn config_map_from_path(config_file_path: &Path) -> Result<ConfigMap> {
    let file_contents = read_to_string(config_file_path)
        .with_context(|| format!("Error reading file: {}", config_file_path.display()))?;
    Ok(file_contents
        .lines()
        .filter_map(parse_config_line)
        .collect())
}
