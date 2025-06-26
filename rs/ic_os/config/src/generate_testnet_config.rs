use anyhow::Result;
use macaddr::MacAddr6;
use std::net::{Ipv4Addr, Ipv6Addr};
use url::Url;

use config_types::*;

#[derive(Default)]
pub struct GenerateTestnetConfigArgs {
    // NetworkSettings arguments
    pub ipv6_config_type: Option<Ipv6ConfigType>,
    pub deterministic_prefix: Option<String>,
    pub deterministic_prefix_length: Option<u8>,
    pub deterministic_gateway: Option<String>,
    pub fixed_address: Option<String>,
    pub fixed_gateway: Option<String>,
    pub ipv4_address: Option<String>,
    pub ipv4_gateway: Option<String>,
    pub ipv4_prefix_length: Option<u8>,
    pub domain_name: Option<String>,

    // ICOSSettings arguments
    pub node_reward_type: Option<String>,
    pub mgmt_mac: Option<MacAddr6>,
    pub deployment_environment: Option<DeploymentEnvironment>,
    pub elasticsearch_hosts: Option<String>,
    pub elasticsearch_tags: Option<String>,
    pub use_nns_public_key: Option<bool>,
    pub nns_urls: Option<Vec<String>>,
    pub enable_trusted_execution_environment: Option<bool>,
    pub use_node_operator_private_key: Option<bool>,
    pub use_ssh_authorized_keys: Option<bool>,

    // GuestOSSettings arguments
    pub inject_ic_crypto: Option<bool>,
    pub inject_ic_state: Option<bool>,
    pub inject_ic_registry_local_store: Option<bool>,

    // GuestOSDevSettings arguments
    pub backup_retention_time_seconds: Option<u64>,
    pub backup_purging_interval_seconds: Option<u64>,
    pub malicious_behavior: Option<String>,
    pub query_stats_epoch_length: Option<u64>,
    pub bitcoind_addr: Option<String>,
    pub jaeger_addr: Option<String>,
    pub socks_proxy: Option<String>,
    pub hostname: Option<String>,
    pub generate_ic_boundary_tls_cert: Option<String>,
}

#[derive(Clone, clap::ValueEnum)]
pub enum Ipv6ConfigType {
    Deterministic,
    Fixed,
    RouterAdvertisement,
}

/// Constructs and returns a GuestOSConfig based on the provided arguments.
/// Any required config fields that aren't specified will receive dummy values.
fn create_guestos_config(config: GenerateTestnetConfigArgs) -> Result<GuestOSConfig> {
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
        domain_name,
        node_reward_type,
        mgmt_mac,
        deployment_environment,
        elasticsearch_hosts,
        elasticsearch_tags,
        use_nns_public_key,
        nns_urls,
        enable_trusted_execution_environment,
        use_node_operator_private_key,
        use_ssh_authorized_keys,
        inject_ic_crypto,
        inject_ic_state,
        inject_ic_registry_local_store,
        backup_retention_time_seconds,
        backup_purging_interval_seconds,
        malicious_behavior,
        query_stats_epoch_length,
        bitcoind_addr,
        jaeger_addr,
        socks_proxy,
        hostname,
        generate_ic_boundary_tls_cert,
    } = config;

    // Construct the NetworkSettings
    let ipv6_config = match ipv6_config_type {
        Some(Ipv6ConfigType::Deterministic) => {
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
        Some(Ipv6ConfigType::Fixed) => {
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
        Some(Ipv6ConfigType::RouterAdvertisement) | None => Ipv6Config::RouterAdvertisement,
    };

    let ipv4_config = match (ipv4_address, ipv4_gateway, ipv4_prefix_length) {
        (Some(addr_str), Some(gw_str), Some(prefix_len)) => Some(Ipv4Config {
            address: addr_str
                .parse::<Ipv4Addr>()
                .map_err(|e| anyhow::anyhow!("Failed to parse ipv4_address: {}", e))?,
            gateway: gw_str
                .parse::<Ipv4Addr>()
                .map_err(|e| anyhow::anyhow!("Failed to parse ipv4_gateway: {}", e))?,
            prefix_length: prefix_len,
        }),
        (None, None, None) => None,
        _ => {
            anyhow::bail!("Incomplete IPv4 configuration provided. All parameters (ipv4_address, ipv4_gateway, ipv4_prefix_length) are required for IPv4 configuration.");
        }
    };

    let network_settings = NetworkSettings {
        ipv6_config,
        ipv4_config,
        domain_name,
    };

    // Construct ICOSSettings
    let mgmt_mac = match mgmt_mac {
        Some(mac) => mac,
        // Use a dummy MAC address
        None => "00:00:00:00:00:00".parse()?,
    };

    let deployment_environment = deployment_environment.unwrap_or(DeploymentEnvironment::Testnet);

    let logging = Logging {
        elasticsearch_hosts,
        elasticsearch_tags,
    };

    let use_nns_public_key = use_nns_public_key.unwrap_or(true);

    let nns_urls = match nns_urls {
        Some(urls) => urls
            .iter()
            .map(|s| Url::parse(s))
            .collect::<Result<Vec<Url>, _>>()?,
        None => vec![Url::parse("https://cloudflare.com/cdn-cgi/trace")?],
    };

    let use_node_operator_private_key = use_node_operator_private_key.unwrap_or(false);

    let use_ssh_authorized_keys = use_ssh_authorized_keys.unwrap_or(true);

    let enable_trusted_execution_environment =
        enable_trusted_execution_environment.unwrap_or(false);

    let icos_settings = ICOSSettings {
        node_reward_type,
        mgmt_mac,
        deployment_environment,
        logging,
        use_nns_public_key,
        nns_urls,
        use_node_operator_private_key,
        enable_trusted_execution_environment,
        use_ssh_authorized_keys,
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
        hostname,
        generate_ic_boundary_tls_cert,
    };

    // Construct GuestOSSettings
    let guestos_settings = GuestOSSettings {
        inject_ic_crypto: inject_ic_crypto.unwrap_or(false),
        inject_ic_state: inject_ic_state.unwrap_or(false),
        inject_ic_registry_local_store: inject_ic_registry_local_store.unwrap_or(false),
        guestos_dev_settings,
    };

    // Assemble GuestOSConfig
    let guestos_config = GuestOSConfig {
        config_version: CONFIG_VERSION.to_string(),
        network_settings,
        icos_settings,
        guestos_settings,
        guest_vm_type: GuestVMType::Default,
        upgrade_config: GuestOSUpgradeConfig::default(),
    };

    Ok(guestos_config)
}

/// Generate and print GuestOSConfig for tests.
/// Any required config fields that aren't specified will receive dummy values.
pub fn generate_testnet_config(config: GenerateTestnetConfigArgs) -> Result<GuestOSConfig> {
    let guestos_config = create_guestos_config(config)?;
    println!("GuestOSConfig: {:?}", guestos_config);
    Ok(guestos_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_configuration() {
        let args = GenerateTestnetConfigArgs {
            ipv6_config_type: Some(Ipv6ConfigType::RouterAdvertisement),
            mgmt_mac: Some("00:11:22:33:44:55".parse().unwrap()),
            nns_urls: Some(vec!["https://example.com".to_string()]),
            ..Default::default()
        };

        let guestos_config =
            create_guestos_config(args).expect("Expected valid configuration to succeed");

        assert_eq!(
            guestos_config.icos_settings.mgmt_mac.to_string(),
            "00:11:22:33:44:55"
        );
        assert_eq!(
            guestos_config
                .icos_settings
                .nns_urls
                .first()
                .unwrap()
                .as_str(),
            "https://example.com/"
        );
        assert_eq!(
            guestos_config.network_settings.ipv6_config,
            Ipv6Config::RouterAdvertisement
        );
    }

    #[test]
    fn test_missing_deterministic_prefix() {
        let args = GenerateTestnetConfigArgs {
            ipv6_config_type: Some(Ipv6ConfigType::Deterministic),
            deterministic_prefix: None,
            deterministic_prefix_length: Some(64),
            deterministic_gateway: Some("fe80::1".to_string()),
            ..Default::default()
        };

        let err = create_guestos_config(args)
            .expect_err("Expected an error due to missing deterministic_prefix");

        assert_eq!(
            err.to_string(),
            "deterministic_prefix is required when ipv6_config_type is 'Deterministic'"
        );
    }

    #[test]
    fn test_missing_deterministic_prefix_length() {
        let args = GenerateTestnetConfigArgs {
            ipv6_config_type: Some(Ipv6ConfigType::Deterministic),
            deterministic_prefix: Some("2001:db8::".to_string()),
            deterministic_prefix_length: None,
            deterministic_gateway: Some("fe80::1".to_string()),
            ..Default::default()
        };

        let err = create_guestos_config(args)
            .expect_err("Expected an error due to missing deterministic_prefix_length");

        assert_eq!(
            err.to_string(),
            "deterministic_prefix_length is required when ipv6_config_type is 'Deterministic'"
        );
    }

    #[test]
    fn test_missing_deterministic_gateway() {
        let args = GenerateTestnetConfigArgs {
            ipv6_config_type: Some(Ipv6ConfigType::Deterministic),
            deterministic_prefix: Some("2001:db8::".to_string()),
            deterministic_prefix_length: Some(64),
            deterministic_gateway: None,
            ..Default::default()
        };

        let err = create_guestos_config(args)
            .expect_err("Expected an error due to missing deterministic_gateway");

        assert_eq!(
            err.to_string(),
            "deterministic_gateway is required when ipv6_config_type is 'Deterministic'"
        );
    }

    #[test]
    fn test_invalid_deterministic_gateway() {
        let args = GenerateTestnetConfigArgs {
            ipv6_config_type: Some(Ipv6ConfigType::Deterministic),
            deterministic_prefix: Some("2001:db8::".to_string()),
            deterministic_prefix_length: Some(64),
            deterministic_gateway: Some("invalid_ip".to_string()),
            ..Default::default()
        };

        let err = create_guestos_config(args)
            .expect_err("Expected parsing error due to invalid deterministic_gateway");

        assert!(
            err.to_string()
                .contains("Failed to parse deterministic_gateway"),
            "Expected parsing error, got: {}",
            err
        );
    }

    #[test]
    fn test_missing_fixed_address() {
        let args = GenerateTestnetConfigArgs {
            ipv6_config_type: Some(Ipv6ConfigType::Fixed),
            fixed_address: None,
            fixed_gateway: Some("fe80::1".to_string()),
            ..Default::default()
        };

        let err = create_guestos_config(args)
            .expect_err("Expected an error due to missing fixed_address");

        assert_eq!(
            err.to_string(),
            "fixed_address is required when ipv6_config_type is 'Fixed'"
        );
    }

    #[test]
    fn test_missing_fixed_gateway() {
        let args = GenerateTestnetConfigArgs {
            ipv6_config_type: Some(Ipv6ConfigType::Fixed),
            fixed_address: Some("2001:db8::1/64".to_string()),
            fixed_gateway: None,
            ..Default::default()
        };

        let err = create_guestos_config(args)
            .expect_err("Expected an error due to missing fixed_gateway");

        assert_eq!(
            err.to_string(),
            "fixed_gateway is required when ipv6_config_type is 'Fixed'"
        );
    }

    #[test]
    fn test_invalid_fixed_gateway() {
        let args = GenerateTestnetConfigArgs {
            ipv6_config_type: Some(Ipv6ConfigType::Fixed),
            fixed_address: Some("2001:db8::1/64".to_string()),
            fixed_gateway: Some("invalid_ip".to_string()),
            ..Default::default()
        };

        let err = create_guestos_config(args)
            .expect_err("Expected parsing error due to invalid fixed_gateway");

        assert!(
            err.to_string().contains("Failed to parse fixed_gateway"),
            "Expected parsing error, got: {}",
            err
        );
    }

    #[test]
    fn test_incomplete_ipv4_config() {
        let args = GenerateTestnetConfigArgs {
            ipv4_address: Some("192.0.2.1".to_string()),
            ipv4_gateway: Some("192.0.2.254".to_string()),
            ipv4_prefix_length: None,
            ..Default::default()
        };

        let err = create_guestos_config(args)
            .expect_err("Expected an error due to incomplete IPv4 configuration");

        assert_eq!(
            err.to_string(),
            "Incomplete IPv4 configuration provided. All parameters (ipv4_address, ipv4_gateway, ipv4_prefix_length) are required for IPv4 configuration."
        );
    }

    #[test]
    fn test_invalid_ipv4_address() {
        let args = GenerateTestnetConfigArgs {
            ipv4_address: Some("invalid_ip".to_string()),
            ipv4_gateway: Some("192.0.2.254".to_string()),
            ipv4_prefix_length: Some(24),
            ..Default::default()
        };

        let err = create_guestos_config(args)
            .expect_err("Expected parsing error due to invalid ipv4_address");

        assert!(
            err.to_string().contains("Failed to parse ipv4_address"),
            "Expected parsing error, got: {}",
            err
        );
    }

    #[test]
    fn test_invalid_ipv4_gateway() {
        let args = GenerateTestnetConfigArgs {
            ipv4_address: Some("192.0.2.1".to_string()),
            ipv4_gateway: Some("invalid_ip".to_string()),
            ipv4_prefix_length: Some(24),
            ..Default::default()
        };

        let err = create_guestos_config(args)
            .expect_err("Expected parsing error due to invalid ipv4_gateway");

        assert!(
            err.to_string().contains("Failed to parse ipv4_gateway"),
            "Expected parsing error, got: {}",
            err
        );
    }
}
