use crate::serialize_and_write_config;
use anyhow::{Context, Result};
use mac_address::mac_address::FormattedMacAddress;
use serde_json;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use url::Url;

use crate::types::*;

pub static CONFIG_ROOT: &str = "/boot/config";
pub static STATE_ROOT: &str = "/var/lib/ic/data";

pub fn update_guestos_config(output_file: PathBuf) -> Result<()> {
    let config_dir = Path::new(CONFIG_ROOT);
    log_directory_structure(config_dir)?;
    let state_root = Path::new(STATE_ROOT);
    log_directory_structure(state_root)?;

    let network_conf_path = config_dir.join("network.conf");
    let config_json_path = config_dir.join("config.json");

    let network_conf_exists = network_conf_path.exists();
    let config_json_exists = config_json_path.exists();

    if network_conf_exists && !config_json_exists {
        // Read existing configuration files and generate new config.json
        let network_config_result = read_network_conf(config_dir)?;
        let network_settings = network_config_result.network_settings;
        let hostname = network_config_result.hostname.clone();

        let logging = read_filebeat_conf(config_dir)?;
        let nns_urls = read_nns_conf(config_dir)?;
        let node_reward_type = read_reward_conf(config_dir)?;

        let nns_public_key_exists = state_root.join("nns_public_key.pem").exists();
        let node_operator_private_key_exists =
            state_root.join("node_operator_private_key.pem").exists();
        let use_ssh_authorized_keys = config_dir.join("accounts_ssh_authorized_keys").is_dir();

        let mgmt_mac = derive_mgmt_mac_from_hostname(hostname.as_deref())?;
        let deployment_environment = "mainnet".to_string();

        let icos_settings = ICOSSettings {
            node_reward_type,
            mgmt_mac,
            deployment_environment,
            logging,
            nns_public_key_exists,
            nns_urls,
            node_operator_private_key_exists,
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

        println!("New GuestOSConfig: {:?}", guestos_config);

        serialize_and_write_config(&output_file, &guestos_config)?;

        println!(
            "New GuestOSConfig has been written to {}",
            output_file.display()
        );
    } else if config_json_exists && !network_conf_exists {
        // Read config.json and generate old configuration files
        let guestos_config = read_guestos_config(&config_json_path)?;

        write_network_conf(
            &guestos_config.network_settings,
            &guestos_config.icos_settings.mgmt_mac,
        )?;
        write_filebeat_conf(&guestos_config.icos_settings.logging)?;
        write_nns_conf(&guestos_config.icos_settings.nns_urls)?;

        println!(
            "Configuration files have been generated from {}",
            config_json_path.display()
        );
    } else {
        println!(
            "No action taken. Either both config.json and network.conf exist, or neither exists."
        );
    }

    Ok(())
}

fn read_guestos_config(input_file: &Path) -> Result<GuestOSConfig> {
    let content = fs::read_to_string(input_file)
        .with_context(|| format!("Failed to read configuration file: {:?}", input_file))?;
    let guestos_config: GuestOSConfig = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON from file: {:?}", input_file))?;
    Ok(guestos_config)
}

fn write_network_conf(
    network_settings: &NetworkSettings,
    mgmt_mac: &FormattedMacAddress,
) -> Result<()> {
    let mut conf_lines = Vec::new();

    match &network_settings.ipv6_config {
        Ipv6Config::Fixed(config) => {
            conf_lines.push(format!("ipv6_address={}", config.address));
            conf_lines.push(format!("ipv6_gateway={}", config.gateway));
        }
        _ => {
            println!("Unexpected IPv6 configuration; expected Fixed configuration.");
        }
    }

    if let Some(ipv4_config) = &network_settings.ipv4_config {
        conf_lines.push(format!(
            "ipv4_address={}/{}",
            ipv4_config.address, ipv4_config.prefix_length
        ));
        conf_lines.push(format!("ipv4_gateway={}", ipv4_config.gateway));
    }

    if let Some(domain_name) = &network_settings.domain_name {
        conf_lines.push(format!("domain={}", domain_name));
    }

    // Generate hostname as "guest-{mgmt_mac without colons}"
    let mgmt_mac_str = mgmt_mac.get().replace(":", "");
    let hostname = format!("guest-{}", mgmt_mac_str);
    conf_lines.push(format!("hostname={}", hostname));

    let network_conf_path = Path::new(CONFIG_ROOT).join("network.conf");
    write_conf_file(&network_conf_path, &conf_lines)?;

    Ok(())
}

fn write_filebeat_conf(logging: &Logging) -> Result<()> {
    let mut conf_lines = Vec::new();
    conf_lines.push(format!(
        "elasticsearch_hosts={}",
        logging.elasticsearch_hosts
    ));
    if let Some(tags) = &logging.elasticsearch_tags {
        conf_lines.push(format!("elasticsearch_tags={}", tags));
    }

    let filebeat_conf_path = Path::new(CONFIG_ROOT).join("filebeat.conf");
    write_conf_file(&filebeat_conf_path, &conf_lines)?;

    Ok(())
}

fn write_nns_conf(nns_urls: &[Url]) -> Result<()> {
    let nns_url_str = nns_urls
        .iter()
        .map(|url| url.as_str())
        .collect::<Vec<_>>()
        .join(",");

    let conf_lines = vec![format!("nns_url={}", nns_url_str)];

    let nns_conf_path = Path::new(CONFIG_ROOT).join("nns.conf");
    write_conf_file(&nns_conf_path, &conf_lines)?;

    Ok(())
}

fn write_conf_file(conf_path: &Path, conf_lines: &[String]) -> Result<()> {
    let content = conf_lines.join("\n") + "\n";
    fs::write(conf_path, content)
        .with_context(|| format!("Failed to write config file to {:?}", conf_path))?;
    println!("Generated {:?}", conf_path);
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

fn read_filebeat_conf(config_dir: &Path) -> Result<Logging> {
    let filebeat_conf_path = config_dir.join("filebeat.conf");
    let conf_map = match read_conf_file(&filebeat_conf_path) {
        Ok(map) => map,
        Err(_) => {
            // Set default values if filebeat.conf doesn't exist
            return Ok(Logging {
                elasticsearch_hosts: "elasticsearch-node-0.mercury.dfinity.systems:443 \
                                       elasticsearch-node-1.mercury.dfinity.systems:443 \
                                       elasticsearch-node-2.mercury.dfinity.systems:443 \
                                       elasticsearch-node-3.mercury.dfinity.systems:443"
                    .to_string(),
                elasticsearch_tags: None,
            });
        }
    };

    let elasticsearch_hosts = conf_map
        .get("elasticsearch_hosts")
        .cloned()
        .unwrap_or_default();

    let elasticsearch_tags = conf_map.get("elasticsearch_tags").cloned();

    Ok(Logging {
        elasticsearch_hosts,
        elasticsearch_tags,
    })
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
    let conf_map = read_conf_file(&reward_conf_path)?;

    let node_reward_type = conf_map.get("node_reward_type").cloned();

    Ok(node_reward_type)
}

fn derive_mgmt_mac_from_hostname(hostname: Option<&str>) -> Result<FormattedMacAddress> {
    if let Some(hostname) = hostname {
        if let Some(unformatted_mac) = hostname.strip_prefix("guest-") {
            // Insert colons into mac_str to format it as a MAC address
            if unformatted_mac.len() != 12 {
                return Err(anyhow::anyhow!(
                    "Invalid MAC address length in hostname: {}",
                    hostname
                ));
            }
            let formatted_mac = unformatted_mac
                .chars()
                .collect::<Vec<_>>()
                .chunks(2)
                .map(|chunk| chunk.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(":");
            let formatted_mac = FormattedMacAddress::try_from(formatted_mac.as_str())
                .with_context(|| format!("Failed to parse mgmt_mac from hostname: {}", hostname))?;
            Ok(formatted_mac)
        } else {
            Err(anyhow::anyhow!(
                "Hostname does not start with 'guest-': {}",
                hostname
            ))
        }
    } else {
        Err(anyhow::anyhow!("Hostname is not specified"))
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
    log_directory_structure_internal(path, 0)
}

fn log_directory_structure_internal(path: &Path, depth: usize) -> Result<()> {
    let indent = "  ".repeat(depth);
    if path.is_dir() {
        if depth == 0 {
            println!("{}{}/", indent, path.display());
        } else {
            println!(
                "{}{}/",
                indent,
                path.file_name()
                    .unwrap_or_else(|| OsStr::new(""))
                    .to_string_lossy()
            );
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            log_directory_structure_internal(&path, depth + 1)?;
        }
    } else {
        println!(
            "{}{}",
            indent,
            path.file_name()
                .unwrap_or_else(|| OsStr::new(""))
                .to_string_lossy()
        );
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
        let expected_mac = "00:11:22:33:44:55";
        let mac = derive_mgmt_mac_from_hostname(hostname)?;
        assert_eq!(mac.get(), expected_mac);

        // Test with invalid hostname (wrong prefix)
        let invalid_hostname = Some("host-001122334455");
        let result = derive_mgmt_mac_from_hostname(invalid_hostname);
        assert!(result.is_err());

        // Test with invalid hostname (wrong length)
        let invalid_hostname_length = Some("guest-00112233");
        let result = derive_mgmt_mac_from_hostname(invalid_hostname_length);
        assert!(result.is_err());

        // Test with None
        let result = derive_mgmt_mac_from_hostname(None);
        assert!(result.is_err());

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
    fn test_write_conf_file() -> Result<()> {
        let dir = tempdir()?;
        let file_path = dir.path().join("test.conf");
        let conf_lines = vec![
            "key1=value1".to_string(),
            "key2=value2".to_string(),
            "key3=value3".to_string(),
        ];

        write_conf_file(&file_path, &conf_lines)?;

        let content = fs::read_to_string(&file_path)?;
        let expected_content = "key1=value1\nkey2=value2\nkey3=value3\n";
        assert_eq!(content, expected_content);

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
    fn test_read_filebeat_conf_existing_file() -> Result<()> {
        let dir = tempdir()?;
        let filebeat_conf_path = dir.path().join("filebeat.conf");
        let mut file = fs::File::create(&filebeat_conf_path)?;
        writeln!(file, "elasticsearch_hosts=host1:9200,host2:9200")?;
        writeln!(file, "elasticsearch_tags=tag1,tag2")?;

        let logging = read_filebeat_conf(dir.path())?;

        assert_eq!(
            logging.elasticsearch_hosts,
            "host1:9200,host2:9200".to_string()
        );
        assert_eq!(logging.elasticsearch_tags, Some("tag1,tag2".to_string()));

        Ok(())
    }

    #[test]
    fn test_read_filebeat_conf_missing_file() -> Result<()> {
        let dir = tempdir()?;
        let logging = read_filebeat_conf(dir.path())?;

        assert_eq!(
            logging.elasticsearch_hosts,
            "elasticsearch-node-0.mercury.dfinity.systems:443 \
            elasticsearch-node-1.mercury.dfinity.systems:443 \
            elasticsearch-node-2.mercury.dfinity.systems:443 \
            elasticsearch-node-3.mercury.dfinity.systems:443"
                .to_string()
        );
        assert_eq!(logging.elasticsearch_tags, None);

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
