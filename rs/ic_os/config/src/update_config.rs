use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use url::Url;

use anyhow::{anyhow, Context, Result};
use macaddr::MacAddr6;

use crate::config_ini::{get_config_ini_settings, ConfigIniSettings};
use crate::deployment_json::get_deployment_settings;
use crate::{deserialize_config, serialize_and_write_config};
use config_types::*;
use network::resolve_mgmt_mac;

pub static CONFIG_ROOT: &str = "/boot/config";
pub static STATE_ROOT: &str = "/var/lib/ic/data";

pub fn update_guestos_config() -> Result<()> {
    let config_dir = Path::new(CONFIG_ROOT);
    log_directory_structure(config_dir)?;
    let state_root = Path::new(STATE_ROOT);
    log_directory_structure(state_root)?;

    let network_conf_path = config_dir.join("network.conf");
    let config_json_path = config_dir.join("config.json");

    // If a config already exists and is Testnet, do not update.
    if config_json_path.exists() {
        if let Ok(existing_config) = deserialize_config::<GuestOSConfig, _>(&config_json_path) {
            if existing_config.icos_settings.deployment_environment
                == DeploymentEnvironment::Testnet
            {
                println!("A new GuestOSConfig already exists and the environment is Testnet. Skipping update.");
                return Ok(());
            }
        }
    }

    let old_config_exists = network_conf_path.exists();

    if old_config_exists {
        // Read existing configuration files and generate new config.json
        let network_config_result = read_network_conf(config_dir)?;
        let network_settings = network_config_result.network_settings;
        let hostname = network_config_result.hostname.clone();

        let nns_urls = read_nns_conf(config_dir)?;
        let node_reward_type = read_reward_conf(config_dir)?;

        let use_nns_public_key = state_root.join("nns_public_key.pem").exists();
        let use_node_operator_private_key =
            state_root.join("node_operator_private_key.pem").exists();
        let use_ssh_authorized_keys = config_dir.join("accounts_ssh_authorized_keys").is_dir();

        let mgmt_mac = derive_mgmt_mac_from_hostname(hostname.as_deref())?;
        let deployment_environment = DeploymentEnvironment::Mainnet;

        let icos_settings = ICOSSettings {
            node_reward_type,
            mgmt_mac,
            deployment_environment,
            logging: Logging::default(),
            use_nns_public_key,
            nns_urls,
            use_node_operator_private_key,
            use_ssh_authorized_keys,
            icos_dev_settings: ICOSDevSettings::default(),
        };

        let guestos_settings = GuestOSSettings::default();

        let guestos_config = GuestOSConfig {
            config_version: CONFIG_VERSION.to_string(),
            network_settings,
            icos_settings,
            guestos_settings,
        };

        // GuestOSConfig is safe to log; it does not contain any secret material
        println!("New GuestOSConfig: {:?}", guestos_config);

        serialize_and_write_config(&config_json_path, &guestos_config)?;

        println!(
            "New GuestOSConfig has been written to {}",
            config_json_path.display()
        );
    } else {
        println!("No update-config action taken.");
    }

    Ok(())
}

fn read_network_conf(config_dir: &Path) -> Result<NetworkConfigResult> {
    let network_conf_path = config_dir.join("network.conf");
    let conf_map = read_conf_file(&network_conf_path)?;

    let ipv6_address_opt = conf_map.get("ipv6_address").cloned();
    let ipv6_gateway_opt = conf_map.get("ipv6_gateway").cloned();
    let ipv4_address_opt = conf_map.get("ipv4_address").cloned();
    let ipv4_gateway_opt = conf_map.get("ipv4_gateway").cloned();
    let domain_name = conf_map.get("domain").cloned();
    let hostname = conf_map.get("hostname").cloned();

    let ipv6_config = match (ipv6_address_opt, ipv6_gateway_opt) {
        (Some(ipv6_address), Some(ipv6_gateway)) => {
            let address = ipv6_address;
            let gateway = ipv6_gateway
                .parse::<Ipv6Addr>()
                .with_context(|| format!("Invalid IPv6 gateway: {}", ipv6_gateway))?;
            Ipv6Config::Fixed(FixedIpv6Config { address, gateway })
        }
        _ => Ipv6Config::RouterAdvertisement,
    };

    let ipv4_config = match (ipv4_address_opt, ipv4_gateway_opt) {
        (Some(ipv4_address), Some(ipv4_gateway)) => {
            let (address_str, prefix_str) = ipv4_address
                .split_once('/')
                .with_context(|| format!("Invalid ipv4_address format: {}", ipv4_address))?;
            let address = address_str
                .parse::<Ipv4Addr>()
                .with_context(|| format!("Invalid IPv4 address: {}", address_str))?;
            let prefix_length = prefix_str
                .parse::<u8>()
                .with_context(|| format!("Invalid IPv4 prefix length: {}", prefix_str))?;
            let gateway = ipv4_gateway
                .parse::<Ipv4Addr>()
                .with_context(|| format!("Invalid IPv4 gateway: {}", ipv4_gateway))?;
            Some(Ipv4Config {
                address,
                gateway,
                prefix_length,
            })
        }
        _ => None,
    };

    let network_settings = NetworkSettings {
        ipv6_config,
        ipv4_config,
        domain_name,
    };

    Ok(NetworkConfigResult {
        network_settings,
        hostname,
    })
}

struct NetworkConfigResult {
    network_settings: NetworkSettings,
    hostname: Option<String>,
}

fn read_nns_conf(config_dir: &Path) -> Result<Vec<Url>> {
    let nns_conf_path = config_dir.join("nns.conf");
    let conf_map = match read_conf_file(&nns_conf_path) {
        Ok(map) => map,
        Err(_) => {
            // Set default values if nns.conf doesn't exist
            let default_urls = vec![
                Url::parse("https://icp-api.io")?,
                Url::parse("https://icp0.io")?,
                Url::parse("https://ic0.app")?,
            ];
            return Ok(default_urls);
        }
    };

    let nns_url_str = conf_map.get("nns_url").cloned().unwrap_or_default();

    let mut nns_urls = Vec::new();
    for s in nns_url_str.split(',') {
        let s = s.trim();
        match Url::parse(s) {
            Ok(url) => nns_urls.push(url),
            Err(e) => {
                println!("Invalid URL '{}': {}", s, e);
            }
        }
    }

    Ok(nns_urls)
}

fn read_reward_conf(config_dir: &Path) -> Result<Option<String>> {
    let reward_conf_path = config_dir.join("reward.conf");
    if !reward_conf_path.exists() {
        return Ok(None);
    }

    let conf_map = read_conf_file(&reward_conf_path)?;
    let node_reward_type = conf_map.get("node_reward_type").cloned();
    Ok(node_reward_type)
}

fn derive_mgmt_mac_from_hostname(hostname: Option<&str>) -> Result<MacAddr6> {
    if let Some(unformatted_mac) = hostname.and_then(|h| h.strip_prefix("guest-")) {
        unformatted_mac
            .parse()
            .map_err(|_| anyhow!("Unable to parse mac address: {}", unformatted_mac))
    } else {
        "00:00:00:00:00:00"
            .parse()
            .map_err(|_| anyhow!("Unable to parse dummy mac address"))
    }
}

fn read_conf_file(path: &Path) -> Result<HashMap<String, String>> {
    println!("Reading configuration file: {:?}", path);
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read configuration file: {:?}", path))?;
    println!("Contents of {:?}:\n{}", path, content);

    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(map)
}

fn log_directory_structure(path: &Path) -> Result<()> {
    println!("Listing directory structure of {}", path.display());

    if path.is_dir() {
        println!("{}/", path.display());

        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();

            let file_name = entry_path
                .file_name()
                .unwrap_or_else(|| OsStr::new(""))
                .to_string_lossy();

            if entry_path.is_dir() {
                println!("  {}/", file_name);
            } else {
                println!("  {}", file_name);
            }
        }
    } else {
        println!("{} is not a directory", path.display());
    }

    Ok(())
}

pub fn update_hostos_config(
    config_ini_path: &Path,
    deployment_json_path: &Path,
    hostos_config_json_path: &PathBuf,
) -> Result<()> {
    // If a config already exists and is Testnet, do not update.
    if hostos_config_json_path.exists() {
        if let Ok(existing_config) = deserialize_config::<HostOSConfig, _>(&hostos_config_json_path)
        {
            if existing_config.icos_settings.deployment_environment
                == DeploymentEnvironment::Testnet
            {
                println!("A new HostOSConfig already exists and the environment is Testnet. Skipping update.");
                return Ok(());
            }
        }
    }

    let old_config_exists = config_ini_path.exists();

    if old_config_exists {
        let hostos_config_json_path = Path::new(&hostos_config_json_path);

        let ConfigIniSettings {
            ipv6_prefix,
            ipv6_prefix_length,
            ipv6_gateway,
            ipv4_address,
            ipv4_gateway,
            ipv4_prefix_length,
            domain_name,
            verbose,
            node_reward_type,
        } = get_config_ini_settings(config_ini_path)?;

        let deterministic_config = DeterministicIpv6Config {
            prefix: ipv6_prefix,
            prefix_length: ipv6_prefix_length,
            gateway: ipv6_gateway,
        };

        let ipv4_config = match (ipv4_address, ipv4_gateway, ipv4_prefix_length) {
            (Some(address), Some(gateway), Some(prefix_length)) => Some(Ipv4Config {
                address,
                gateway,
                prefix_length,
            }),
            (None, None, None) => None,
            _ => {
                println!("Warning: Partial IPv4 configuration provided. All parameters are required for IPv4 configuration.");
                None
            }
        };

        let network_settings = NetworkSettings {
            ipv6_config: Ipv6Config::Deterministic(deterministic_config),
            ipv4_config,
            domain_name,
        };

        let deployment_json_settings = get_deployment_settings(deployment_json_path)?;

        let mgmt_mac = resolve_mgmt_mac(deployment_json_settings.deployment.mgmt_mac)?;

        let use_nns_public_key = Path::new("/boot/config/nns_public_key.pem").exists();
        let use_node_operator_private_key =
            Path::new("/boot/config/node_operator_private_key.pem").exists();
        let use_ssh_authorized_keys = Path::new("/boot/config/ssh_authorized_keys").exists();

        let icos_settings = ICOSSettings {
            node_reward_type,
            mgmt_mac,
            deployment_environment: deployment_json_settings.deployment.name.parse()?,
            logging: Logging::default(),
            use_nns_public_key,
            nns_urls: deployment_json_settings.nns.url.clone(),
            use_node_operator_private_key,
            use_ssh_authorized_keys,
            icos_dev_settings: ICOSDevSettings::default(),
        };

        let hostos_settings = HostOSSettings {
            vm_memory: deployment_json_settings.resources.memory,
            vm_cpu: deployment_json_settings
                .resources
                .cpu
                .clone()
                .unwrap_or("kvm".to_string()),
            verbose,
        };

        let guestos_settings = GuestOSSettings::default();

        let hostos_config = HostOSConfig {
            config_version: CONFIG_VERSION.to_string(),
            network_settings,
            icos_settings,
            hostos_settings,
            guestos_settings,
        };

        // HostOSConfig is safe to log; it does not contain any secret material
        println!("New HostOSConfig: {:?}", hostos_config);

        serialize_and_write_config(hostos_config_json_path, &hostos_config)?;

        println!(
            "New HostOSConfig has been written to {}",
            hostos_config_json_path.display()
        );
    } else {
        println!("No update-config action taken.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_derive_mgmt_mac_from_hostname() -> Result<()> {
        // Test with a valid hostname
        let hostname = Some("guest-001122334455");
        let expected_mac: MacAddr6 = "00:11:22:33:44:55".parse().unwrap();
        let mac = derive_mgmt_mac_from_hostname(hostname)?;
        assert_eq!(mac, expected_mac);

        // Test empty hostname
        let expected_mac: MacAddr6 = "00:00:00:00:00:00".parse().unwrap();
        let mac = derive_mgmt_mac_from_hostname(None)?;
        assert_eq!(mac, expected_mac);

        Ok(())
    }

    #[test]
    fn test_read_conf_file() -> Result<()> {
        let dir = tempdir()?;
        let file_path = dir.path().join("test.conf");
        let mut file = fs::File::create(&file_path)?;
        writeln!(file, "key1=value1")?;
        writeln!(file, "key2=value2")?;
        writeln!(file, "# This is a comment")?;
        writeln!(file, "key3 = value3")?;

        let conf_map = read_conf_file(&file_path)?;

        assert_eq!(conf_map.get("key1"), Some(&"value1".to_string()));
        assert_eq!(conf_map.get("key2"), Some(&"value2".to_string()));
        assert_eq!(conf_map.get("key3"), Some(&"value3".to_string()));

        Ok(())
    }

    #[test]
    fn test_read_network_conf() -> Result<()> {
        let dir = tempdir()?;
        let network_conf_path = dir.path().join("network.conf");
        let mut file = fs::File::create(&network_conf_path)?;
        writeln!(file, "ipv6_address=2001:db8::1/64")?;
        writeln!(file, "ipv6_gateway=2001:db8::fffe")?;
        writeln!(file, "ipv4_address=192.0.2.1/24")?;
        writeln!(file, "ipv4_gateway=192.0.2.254")?;
        writeln!(file, "domain=example.com")?;
        writeln!(file, "hostname=guest-001122334455")?;

        let result = read_network_conf(dir.path())?;

        assert_eq!(
            result.network_settings,
            NetworkSettings {
                ipv6_config: Ipv6Config::Fixed(FixedIpv6Config {
                    address: "2001:db8::1/64".to_string(),
                    gateway: "2001:db8::fffe".parse().unwrap(),
                }),
                ipv4_config: Some(Ipv4Config {
                    address: "192.0.2.1".parse().unwrap(),
                    prefix_length: 24,
                    gateway: "192.0.2.254".parse().unwrap(),
                }),
                domain_name: Some("example.com".to_string()),
            }
        );

        assert_eq!(result.hostname, Some("guest-001122334455".to_string()));

        Ok(())
    }

    #[test]
    fn test_read_nns_conf_existing_file() -> Result<()> {
        let dir = tempdir()?;
        let nns_conf_path = dir.path().join("nns.conf");
        let mut file = fs::File::create(&nns_conf_path)?;
        writeln!(
            file,
            "nns_url=https://nns1.example.com,https://nns2.example.com"
        )?;

        let nns_urls = read_nns_conf(dir.path())?;

        assert_eq!(
            nns_urls,
            vec![
                Url::parse("https://nns1.example.com")?,
                Url::parse("https://nns2.example.com")?,
            ]
        );

        Ok(())
    }

    #[test]
    fn test_read_nns_conf_missing_file() -> Result<()> {
        let dir = tempdir()?;
        let nns_urls = read_nns_conf(dir.path())?;

        assert_eq!(
            nns_urls,
            vec![
                Url::parse("https://icp-api.io")?,
                Url::parse("https://icp0.io")?,
                Url::parse("https://ic0.app")?,
            ]
        );

        Ok(())
    }
}
