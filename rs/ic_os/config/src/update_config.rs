use crate::serialize_and_write_config;
use anyhow::Context;
use anyhow::Result;
use mac_address::mac_address::FormattedMacAddress;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use url::Url;

use crate::types::*;

pub static CONFIG_ROOT: &str = "/boot/config";
pub static STATE_ROOT: &str = "/var/lib/ic";

pub fn update_guestos_config(output_file: PathBuf) -> Result<()> {
    let config_dir = Path::new(CONFIG_ROOT);

    let network_settings_result = read_network_conf(config_dir)?;
    let network_settings = network_settings_result.network_settings;
    let hostname = network_settings_result.hostname.clone();

    let logging = read_filebeat_conf(config_dir)?;
    let nns_urls = read_nns_conf(config_dir)?;

    let nns_public_key_exists = Path::new(STATE_ROOT)
        .join("data/nns_public_key.pem")
        .exists();

    let node_operator_private_key_exists = Path::new(STATE_ROOT)
        .join("data/node_operator_private_key.pem")
        .exists();

    let use_ssh_authorized_keys = Path::new(CONFIG_ROOT)
        .join("accounts_ssh_authorized_keys")
        .is_dir();

    let mgmt_mac = derive_mgmt_mac_from_hostname(hostname.as_deref())?;

    let deployment_environment = "mainnet".to_string();

    let icos_settings = ICOSSettings {
        config_version: CONFIG_VERSION.to_string(),
        mgmt_mac,
        deployment_environment,
        logging,
        nns_public_key_exists,
        nns_urls,
        node_operator_private_key_exists,
        use_ssh_authorized_keys,
        icos_dev_settings: ICOSDevSettings::default(),
    };

    let guestos_dev_settings = GuestOSDevSettings {
        backup_spool: None,
        malicious_behavior: None,
        query_stats_epoch_length: None,
        bitcoind_addr: None,
        jaeger_addr: None,
        socks_proxy: None,
        hostname: None,
        generate_ic_boundary_tls_cert: None,
    };

    let guestos_settings = GuestOSSettings {
        inject_ic_crypto: false,
        inject_ic_state: false,
        inject_ic_registry_local_store: false,
        guestos_dev_settings,
    };

    let guestos_config = GuestOSConfig {
        network_settings,
        icos_settings,
        guestos_settings,
    };

    serialize_and_write_config(&output_file, &guestos_config)?;

    println!(
        "New GuestOSConfig has been written to {}",
        output_file.display()
    );

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

    let ipv6_config = if let (Some(ipv6_address), Some(ipv6_gateway)) =
        (ipv6_address_opt.clone(), ipv6_gateway_opt.clone())
    {
        let address = ipv6_address;
        let gateway = ipv6_gateway.parse::<Ipv6Addr>()?;
        Ipv6Config::Fixed(FixedIpv6Config { address, gateway })
    } else {
        Ipv6Config::RouterAdvertisement
    };

    let ipv4_config = if let (Some(ipv4_address), Some(ipv4_gateway)) =
        (ipv4_address_opt.clone(), ipv4_gateway_opt.clone())
    {
        let parts: Vec<&str> = ipv4_address.split('/').collect();
        if parts.len() == 2 {
            let address = parts[0].parse::<Ipv4Addr>()?;
            let prefix_length = parts[1].parse::<u8>()?;
            let gateway = ipv4_gateway.parse::<Ipv4Addr>()?;
            Some(Ipv4Config {
                address,
                gateway,
                prefix_length,
            })
        } else {
            None
        }
    } else {
        None
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
            // if filebeat.conf doesn't exist or can't be read, set to default values
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
            // if nns.conf doesn't exist or can't be read, set to default values
            let default_urls = vec![
                Url::parse("https://icp-api.io")?,
                Url::parse("https://icp0.io")?,
                Url::parse("https://ic0.app")?,
            ];
            return Ok(default_urls);
        }
    };

    let nns_url_str = conf_map.get("nns_url").cloned().unwrap_or_default();

    let nns_urls = nns_url_str
        .split(',')
        .map(|s| s.trim())
        .filter_map(|s| {
            // Try parsing the URL as is
            if let Ok(url) = Url::parse(s) {
                return Some(url);
            }

            // parsing for if url is just an IPv6 address:
            let mut address = s.to_string();
            let is_ipv6 = address.contains(':');

            // Enclose IPv6 addresses in brackets if not already
            if is_ipv6 && !address.starts_with('[') && !address.ends_with(']') {
                address = format!("[{}]", address);
            }

            // Prepend 'http://' and append ':8080'
            let url_string = format!("http://{}", address);

            // Attempt to parse the constructed URL
            match Url::parse(&url_string) {
                Ok(url) => Some(url),
                Err(_) => None, // Parsing failed, skip this entry
            }
        })
        .collect();

    Ok(nns_urls)
}

fn derive_mgmt_mac_from_hostname(hostname: Option<&str>) -> Result<FormattedMacAddress> {
    if let Some(hostname) = hostname {
        if let Some(unformatted_mac) = hostname.strip_prefix("guest-") {
            // Insert colons into mac_str to format it as a MAC address
            let formatted_mac = unformatted_mac
                .chars()
                .collect::<Vec<_>>()
                .chunks(2)
                .map(|chunk| chunk.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(":");
            let formatted_mac = FormattedMacAddress::try_from(formatted_mac.as_str())
                .map_err(|e| anyhow::anyhow!("Failed to parse mgmt_mac: {}", e))?;
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
    let file = fs::File::open(path)
        .with_context(|| format!("Failed to open configuration file: {:?}", path))?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(map)
}
