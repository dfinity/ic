use anyhow::Result;
use mac_address::mac_address::FormattedMacAddress;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use url::Url;

use crate::serialize_and_write_config;
use crate::types::*;

pub struct GenerateTestnetConfigArgs {
    // NetworkSettings arguments
    pub ipv6_config_type: Option<String>, // "Deterministic", "Fixed", "RouterAdvertisement"
    pub deterministic_prefix: Option<String>,
    pub deterministic_prefix_length: Option<u8>,
    pub deterministic_gateway: Option<String>,
    pub fixed_address: Option<String>,
    pub fixed_gateway: Option<String>,
    pub ipv4_address: Option<String>,
    pub ipv4_gateway: Option<String>,
    pub ipv4_prefix_length: Option<u8>,
    pub ipv4_domain: Option<String>,

    // ICOSSettings arguments
    pub mgmt_mac: Option<String>,
    pub deployment_environment: Option<String>,
    pub elasticsearch_hosts: Option<String>,
    pub elasticsearch_tags: Option<String>,
    pub nns_public_key_path: Option<PathBuf>,
    pub nns_urls: Option<Vec<String>>,
    pub node_operator_private_key_path: Option<PathBuf>,
    pub ssh_authorized_keys_path: Option<PathBuf>,

    // GuestOSSettings arguments
    pub ic_crypto_path: Option<PathBuf>,
    pub ic_state_path: Option<PathBuf>,
    pub ic_registry_local_store_path: Option<PathBuf>,

    // GuestOSDevSettings arguments
    pub backup_retention_time_seconds: Option<u64>,
    pub backup_purging_interval_seconds: Option<u64>,
    pub malicious_behavior: Option<String>,
    pub query_stats_epoch_length: Option<u64>,
    pub bitcoind_addr: Option<String>,
    pub jaeger_addr: Option<String>,
    pub socks_proxy: Option<String>,

    // Output path
    pub guestos_config_json_path: PathBuf,
}

/// Generates a writes a serialized GuestOSConfig to guestos_config_json_path
/// Any required config fields that aren't specified will receive dummy values
pub fn generate_testnet_config(args: GenerateTestnetConfigArgs) -> Result<()> {
    let GenerateTestnetConfigArgs {
        ipv6_config_type,
        deterministic_prefix,
        deterministic_prefix_length,
        deterministic_gateway,
        fixed_address,
        fixed_gateway,
        ipv4_address,
        ipv4_gateway,
        ipv4_prefix_length,
        ipv4_domain,
        mgmt_mac,
        deployment_environment,
        elasticsearch_hosts,
        elasticsearch_tags,
        nns_public_key_path,
        nns_urls,
        node_operator_private_key_path,
        ssh_authorized_keys_path,
        ic_crypto_path,
        ic_state_path,
        ic_registry_local_store_path,
        backup_retention_time_seconds,
        backup_purging_interval_seconds,
        malicious_behavior,
        query_stats_epoch_length,
        bitcoind_addr,
        jaeger_addr,
        socks_proxy,
        guestos_config_json_path,
    } = args;

    // Construct the NetworkSettings
    let ipv6_config = match ipv6_config_type.as_deref() {
        Some("Deterministic") => {
            let prefix = deterministic_prefix.ok_or_else(|| {
                anyhow::anyhow!(
                    "deterministic_prefix is required when ipv6_config_type is 'Deterministic'"
                )
            })?;
            let prefix_length = deterministic_prefix_length.ok_or_else(|| {
                anyhow::anyhow!(
                    "deterministic_prefix_length is required when ipv6_config_type is 'Deterministic'"
                )
            })?;
            let gateway_str = deterministic_gateway.ok_or_else(|| {
                anyhow::anyhow!(
                    "deterministic_gateway is required when ipv6_config_type is 'Deterministic'"
                )
            })?;
            let gateway = gateway_str
                .parse::<Ipv6Addr>()
                .map_err(|e| anyhow::anyhow!("Failed to parse deterministic_gateway: {}", e))?;

            Ipv6Config::Deterministic(DeterministicIpv6Config {
                prefix,
                prefix_length,
                gateway,
            })
        }
        Some("Fixed") => {
            let address = fixed_address.ok_or_else(|| {
                anyhow::anyhow!("fixed_address is required when ipv6_config_type is 'Fixed'")
            })?;
            let gateway_str = fixed_gateway.ok_or_else(|| {
                anyhow::anyhow!("fixed_gateway is required when ipv6_config_type is 'Fixed'")
            })?;
            let gateway = gateway_str
                .parse::<Ipv6Addr>()
                .map_err(|e| anyhow::anyhow!("Failed to parse fixed_gateway: {}", e))?;

            Ipv6Config::Fixed(FixedIpv6Config { address, gateway })
        }
        // Default to RouterAdvertisement if not provided
        Some("RouterAdvertisement") | None => Ipv6Config::RouterAdvertisement,
        Some(other) => {
            anyhow::bail!("Invalid ipv6_config_type '{}'. Must be 'Deterministic', 'Fixed', or 'RouterAdvertisement'.", other);
        }
    };

    let ipv4_config = match (ipv4_address, ipv4_gateway, ipv4_prefix_length, ipv4_domain) {
        (Some(addr_str), Some(gw_str), Some(prefix_len), Some(domain)) => Some(Ipv4Config {
            address: addr_str
                .parse::<Ipv4Addr>()
                .map_err(|e| anyhow::anyhow!("Failed to parse ipv4_address: {}", e))?,
            gateway: gw_str
                .parse::<Ipv4Addr>()
                .map_err(|e| anyhow::anyhow!("Failed to parse ipv4_gateway: {}", e))?,
            prefix_length: prefix_len,
            domain,
        }),
        (None, None, None, None) => None,
        _ => {
            anyhow::bail!("Incomplete IPv4 configuration provided. All parameters (ipv4_address, ipv4_gateway, ipv4_prefix_length, ipv4_domain) are required for IPv4 configuration.");
        }
    };

    let network_settings = NetworkSettings {
        ipv6_config,
        ipv4_config,
    };

    // Construct ICOSSettings
    let mgmt_mac = match mgmt_mac {
        Some(mac_str) => FormattedMacAddress::try_from(mac_str.as_str())?,
        None => {
            // Use a dummy MAC address
            FormattedMacAddress::try_from("00:00:00:00:00:00")?
        }
    };

    let deployment_environment = deployment_environment.unwrap_or_else(|| "testnet".to_string());

    let logging = Logging {
        elasticsearch_hosts: elasticsearch_hosts.unwrap_or_else(|| "".to_string()),
        elasticsearch_tags,
    };

    let nns_public_key_path =
        nns_public_key_path.unwrap_or_else(|| PathBuf::from("/boot/config/nns_public_key.pem"));

    let nns_urls = match nns_urls {
        Some(urls) => urls
            .iter()
            .map(|s| Url::parse(s))
            .collect::<Result<Vec<Url>, _>>()?,
        None => vec![Url::parse("https://wiki.internetcomputer.org")?],
    };

    let icos_settings = ICOSSettings {
        mgmt_mac,
        deployment_environment,
        logging,
        nns_public_key_path,
        nns_urls,
        node_operator_private_key_path,
        ssh_authorized_keys_path,
        icos_dev_settings: ICOSDevSettings::default(),
    };

    // Construct GuestOSDevSettings
    let backup_spool =
        if backup_retention_time_seconds.is_some() || backup_purging_interval_seconds.is_some() {
            Some(BackupSpoolSettings {
                backup_retention_time_seconds,
                backup_purging_interval_seconds,
            })
        } else {
            None
        };

    let malicious_behavior = if let Some(mb_str) = malicious_behavior {
        Some(serde_json::from_str(&mb_str)?)
    } else {
        None
    };

    let guestos_dev_settings = GuestOSDevSettings {
        backup_spool,
        malicious_behavior,
        query_stats_epoch_length,
        bitcoind_addr,
        jaeger_addr,
        socks_proxy,
    };

    // Construct GuestOSSettings
    let guestos_settings = GuestOSSettings {
        ic_crypto_path,
        ic_state_path,
        ic_registry_local_store_path,
        guestos_dev_settings,
    };

    // Assemble GuestOSConfig
    let guestos_config = GuestOSConfig {
        network_settings,
        icos_settings,
        guestos_settings,
    };

    println!("GuestOSConfig: {:?}", guestos_config);

    // Write the configuration to a file
    serialize_and_write_config(&guestos_config_json_path, &guestos_config)?;

    println!(
        "GuestOSConfig has been written to {}",
        guestos_config_json_path.display()
    );

    Ok(())
}
