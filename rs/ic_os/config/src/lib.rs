use std::collections::HashMap;
use std::fs::read_to_string;
use std::path::Path;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::bail;
use anyhow::{Context, Result};
use url::Url;

mod types;
use types::Networking;

pub type ConfigMap = HashMap<String, String>;

// todo: update naming once config variables start applying to all config partitions
pub static DEFAULT_SETUPOS_CONFIG_FILE_PATH: &str = "/var/ic/config/config.ini";
pub static DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH: &str = "/data/deployment.json";
pub static DEFAULT_SETUPOS_NNS_PUBLIC_KEY_PATH: &str = "/data/nns_public_key.pem";
pub static DEFAULT_SETUPOS_SSH_AUTHORIZED_KEYS_PATH: &str = "/var/ic/config/ssh_authorized_keys";
pub static DEFAULT_SETUPOS_NODE_OPERATOR_PRIVATE_KEY_PATH: &str =
    "/var/ic/config/node_operator_private_key.pem";

//todo: delete
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

// todo: look into better way of storing this. As a networking constructor?
pub fn parse_config_ini_networking(config_file_path: &Path) -> Result<Networking> {
    let config_map: ConfigMap = config_map_from_path(config_file_path)?;

    // Per PFOPS - this will never not be 64
    let ipv6_subnet = 64_u8;

    let ipv6_prefix = match config_map.get("ipv6_prefix") {
        Some(ipv6_prefix) => {
            // Prefix should have a max length of 19 ("1234:6789:1234:6789")
            // It could have fewer characters though. Parsing as an ip address with trailing '::' should work.
            if !is_valid_ipv6_prefix(ipv6_prefix) {
                bail!("Invalid ipv6 prefix: {}", ipv6_prefix);
            }
            Some(ipv6_prefix.clone())
        }
        None => None,
    };

    // Optional ipv6_address - for testing. Takes precedence over ipv6_prefix.
    let ipv6_address = match config_map.get("ipv6_address") {
        Some(address) => {
            // ipv6_address might be formatted with the trailing suffix. Remove it.
            let ipv6_subnet = format!("/{}", ipv6_subnet);
            let address = address.strip_suffix(&ipv6_subnet).unwrap_or(address);
            let address: Ipv6Addr = address
                .parse::<Ipv6Addr>()
                .context(format!("Invalid ipv6 address: {}", address))?;
            Some(address)
        }
        None => None,
    };

    if ipv6_address.is_none() && ipv6_prefix.is_none() {
        bail!("Missing config parameter: need at least one of ipv6_prefix or ipv6_address");
    }

    let ipv6_gateway = config_map
        .get("ipv6_gateway")
        .context("Missing config parameter: ipv6_gateway")?;
    let ipv6_gateway: Ipv6Addr = ipv6_gateway
        .parse::<Ipv6Addr>()
        .context(format!("Invalid ipv6 address: {}", ipv6_gateway))?;

    let ipv4_address = match config_map.get("ipv4_address") {
        Some(address) => {
            let address = address
                .parse::<Ipv4Addr>()
                .context(format!("Invalid IPv4 address: {}", address))?;
            Some(address)
        }
        None => None,
    };

    let ipv4_gateway = match config_map.get("ipv4_gateway") {
        Some(address) => {
            let address = address
                .parse::<Ipv4Addr>()
                .context(format!("Invalid IPv4 gateway: {}", address))?;
            Some(address)
        }
        None => None,
    };

    let ipv4_prefix_length = match config_map.get("ipv4_prefix_length") {
        Some(prefix) => {
            let prefix = prefix
                .parse::<u8>()
                .context(format!("Invalid IPv4 prefix length: {}", prefix))?;

            if prefix > 32 {
                return Err(anyhow::anyhow!(
                    "IPv4 prefix length must be between 0 and 32, got {}",
                    prefix
                ));
            }

            Some(prefix)
        }
        None => None,
    };

    let domain = config_map.get("domain").cloned();

    Ok(Networking {
        ipv6_prefix,
        ipv6_address,
        ipv6_gateway,
        ipv4_address,
        ipv4_gateway,
        ipv4_prefix_length,
        domain,
    })
}

fn is_valid_ipv6_prefix(ipv6_prefix: &str) -> bool {
    ipv6_prefix.len() <= 19 && format!("{ipv6_prefix}::").parse::<Ipv6Addr>().is_ok()
}

pub fn default_deployment_values() -> (u32, String, Vec<Url>, String, String) {
    (
        490,
        "kvm".to_string(),
        vec![
            Url::parse("https://icp-api.io").unwrap(),
            Url::parse("https://icp0.io").unwrap(),
            Url::parse("https://ic0.app").unwrap(),
        ],
        "mainnet".to_string(),
        [
            "elasticsearch-node-0.mercury.dfinity.systems:443",
            "elasticsearch-node-1.mercury.dfinity.systems:443",
            "elasticsearch-node-2.mercury.dfinity.systems:443",
            "elasticsearch-node-3.mercury.dfinity.systems:443",
        ]
        .join(" "),
    )
}