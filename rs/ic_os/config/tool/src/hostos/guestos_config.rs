use anyhow::{Result, bail, ensure};
use config_types::{
    CONFIG_VERSION, DeterministicIpv6Config, FixedIpv6Config, GuestOSConfig, GuestOSUpgradeConfig,
    GuestVMType, HostOSConfig, Ipv6Config, RecoveryConfig, TrustedExecutionEnvironmentConfig,
};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{IpVariant, MacAddr6Ext, calculate_deterministic_mac};
use std::net::Ipv6Addr;
use std::path::Path;
use utils::to_cidr;

const DEFAULT_GUESTOS_RECOVERY_FILE_PATH: &str = "/run/config/guestos_recovery_hash";

/// Generate the GuestOS configuration based on the provided HostOS configuration.
/// If hostos_config.icos_settings.enable_trusted_execution_environment is true,
/// sev_certificate_chain_pem must be provided.
pub fn generate_guestos_config(
    hostos_config: &HostOSConfig,
    guest_vm_type: GuestVMType,
    sev_certificate_chain_pem: Option<String>,
) -> Result<GuestOSConfig> {
    ensure!(
        !hostos_config
            .icos_settings
            .enable_trusted_execution_environment
            || sev_certificate_chain_pem.is_some(),
        "If enable_trusted_execution_environment is enabled, SEV cert chain must be provided."
    );

    // TODO: We won't have to modify networking between the hostos and
    // guestos config after completing the networking revamp (NODE-1327)
    let Ipv6Config::Deterministic(deterministic_ipv6_config) =
        &hostos_config.network_settings.ipv6_config
    else {
        bail!(
            "HostOSConfig Ipv6Config should always be of type Deterministic. \
             Cannot reassign GuestOS networking."
        );
    };

    // Configuration for GuestOS upgrades.
    let (node_type, upgrade_peer_node_type) = match guest_vm_type {
        GuestVMType::Default => (NodeType::GuestOS, NodeType::UpgradeGuestOS),
        GuestVMType::Upgrade => (NodeType::UpgradeGuestOS, NodeType::GuestOS),
        GuestVMType::Unknown => {
            bail!("GuestVMType::Unknown is not a valid type for generating GuestOS config");
        }
    };

    let guestos_ipv6_address =
        node_ipv6_address(node_type, hostos_config, deterministic_ipv6_config)?;
    let peer_ipv6_address = node_ipv6_address(
        upgrade_peer_node_type,
        hostos_config,
        deterministic_ipv6_config,
    )?;

    let mut guestos_network_settings = hostos_config.network_settings.clone();
    guestos_network_settings.ipv6_config = Ipv6Config::Fixed(FixedIpv6Config {
        address: to_cidr(
            guestos_ipv6_address,
            deterministic_ipv6_config.prefix_length,
        ),
        gateway: deterministic_ipv6_config.gateway,
    });

    let upgrade_config = GuestOSUpgradeConfig {
        peer_guest_vm_address: Some(peer_ipv6_address),
    };

    let trusted_execution_environment_config =
        sev_certificate_chain_pem.map(|certificate_chain| TrustedExecutionEnvironmentConfig {
            sev_cert_chain_pem: certificate_chain,
        });

    let recovery_config = guestos_recovery_config(DEFAULT_GUESTOS_RECOVERY_FILE_PATH.as_ref())?;

    let guestos_config = GuestOSConfig {
        config_version: CONFIG_VERSION.to_string(),
        network_settings: guestos_network_settings,
        icos_settings: hostos_config.icos_settings.clone(),
        guestos_settings: hostos_config.guestos_settings.clone(),
        guest_vm_type,
        upgrade_config,
        trusted_execution_environment_config,
        recovery_config,
    };

    Ok(guestos_config)
}

fn node_ipv6_address(
    node_type: NodeType,
    hostos_config: &HostOSConfig,
    deterministic_config: &DeterministicIpv6Config,
) -> Result<Ipv6Addr> {
    let mac = calculate_deterministic_mac(
        &hostos_config.icos_settings.mgmt_mac,
        hostos_config.icos_settings.deployment_environment,
        IpVariant::V6,
        node_type,
    );

    mac.calculate_slaac(&deterministic_config.prefix)
}

/// Retrieves the recovery-hash-prefix from the recovery file, if present.
/// The file is read once and then deleted to ensure one-time use.
fn guestos_recovery_config(recovery_file_path: &Path) -> Result<Option<RecoveryConfig>> {
    if recovery_file_path.exists() {
        let recovery_hash_prefix = std::fs::read_to_string(recovery_file_path)?
            .trim()
            .to_string();

        std::fs::remove_file(recovery_file_path)?;

        if !recovery_hash_prefix.is_empty() {
            return Ok(Some(RecoveryConfig {
                recovery_hash: recovery_hash_prefix,
            }));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use config_types::{DeterministicIpv6Config, HostOSConfig, Ipv6Config, NetworkSettings};
    use std::net::Ipv6Addr;
    use tempfile::tempdir;

    fn hostos_config_for_test() -> HostOSConfig {
        HostOSConfig {
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::Deterministic(DeterministicIpv6Config {
                    prefix: "2001:db8::".to_string(),
                    prefix_length: 64,
                    gateway: "2001:db8::1".parse().unwrap(),
                }),
                ..Default::default()
            },
            ..HostOSConfig::default()
        }
    }
    #[test]
    fn test_successful_conversion() {
        let hostos_config = hostos_config_for_test();

        let guestos_config =
            generate_guestos_config(&hostos_config, GuestVMType::Default, None).unwrap();

        assert_eq!(guestos_config.config_version, CONFIG_VERSION.to_string());
        assert_eq!(
            guestos_config.network_settings.domain_name,
            hostos_config.network_settings.domain_name
        );
        assert_eq!(
            guestos_config.network_settings.ipv4_config,
            hostos_config.network_settings.ipv4_config
        );
        assert_eq!(guestos_config.icos_settings, hostos_config.icos_settings);
        assert_eq!(
            guestos_config.guestos_settings,
            hostos_config.guestos_settings
        );

        if let Ipv6Config::Fixed(fixed) = &guestos_config.network_settings.ipv6_config {
            assert_eq!(fixed.address, "2001:db8::6801:94ff:feef:2978/64");
            assert_eq!(fixed.gateway, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        } else {
            panic!("Unexpected Ipv6Config type");
        }

        assert_eq!(guestos_config.guest_vm_type, GuestVMType::Default);
        assert_eq!(
            guestos_config.upgrade_config.peer_guest_vm_address,
            Some("2001:db8::6802:94ff:feef:2978".parse().unwrap())
        );
    }

    #[test]
    fn test_upgrade_vm_conversion() {
        let mut hostos_config = hostos_config_for_test();
        hostos_config.network_settings.ipv6_config =
            Ipv6Config::Deterministic(DeterministicIpv6Config {
                prefix: "2001:db8::".to_string(),
                prefix_length: 64,
                gateway: "2001:db8::1".parse().unwrap(),
            });

        let guestos_config =
            generate_guestos_config(&hostos_config, GuestVMType::Upgrade, None).unwrap();

        if let Ipv6Config::Fixed(fixed) = &guestos_config.network_settings.ipv6_config {
            assert_eq!(fixed.address, "2001:db8::6802:94ff:feef:2978/64");
            assert_eq!(fixed.gateway, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        } else {
            panic!("Unexpected Ipv6Config type");
        }

        assert_eq!(guestos_config.guest_vm_type, GuestVMType::Upgrade);
        assert_eq!(
            guestos_config.upgrade_config.peer_guest_vm_address,
            Some("2001:db8::6801:94ff:feef:2978".parse().unwrap())
        );
    }

    #[test]
    fn test_invalid_ipv6_configuration() {
        let mut hostos_config = hostos_config_for_test();

        hostos_config.network_settings.ipv6_config = Ipv6Config::Fixed(FixedIpv6Config {
            address: "2001:db8::1/64".to_string(),
            gateway: "2001:db8::1".parse().unwrap(),
        });

        let result = generate_guestos_config(&hostos_config, GuestVMType::Default, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Deterministic"));
    }

    #[test]
    fn test_adds_sev_certificate_chain() {
        let hostos_config = hostos_config_for_test();

        let result = generate_guestos_config(
            &hostos_config,
            GuestVMType::Default,
            Some("abc".to_string()),
        )
        .unwrap();
        assert_eq!(
            result
                .trusted_execution_environment_config
                .expect("trusted_execution_environment_config should be populated")
                .sev_cert_chain_pem,
            "abc"
        );
    }

    #[test]
    fn test_recovery_hash() {
        let temp_dir = tempdir().unwrap();
        let recovery_file_path = temp_dir.path().join("guestos_recovery_hash");

        // Test case 1: Recovery file does not exist
        let recovery_config = guestos_recovery_config(&recovery_file_path).unwrap();
        assert_eq!(recovery_config, None);
        assert!(!recovery_file_path.exists());

        // Test case 2: Recovery file exists but is empty
        std::fs::write(&recovery_file_path, "").unwrap();
        let recovery_config = guestos_recovery_config(&recovery_file_path).unwrap();
        assert_eq!(recovery_config, None);
        // File should be deleted after reading
        assert!(!recovery_file_path.exists());

        // Test case 3: Recovery file exists with whitespace-only content
        std::fs::write(&recovery_file_path, "   \n\t  ").unwrap();
        let recovery_config = guestos_recovery_config(&recovery_file_path).unwrap();
        assert_eq!(recovery_config, None);
        assert!(!recovery_file_path.exists());

        // Test case 4: Recovery file exists with valid hash
        // The function should return the recovery hash and delete the file
        std::fs::write(&recovery_file_path, "test123").unwrap();
        let recovery_config = guestos_recovery_config(&recovery_file_path).unwrap();
        assert_eq!(
            recovery_config,
            Some(RecoveryConfig {
                recovery_hash: "test123".to_string(),
            })
        );
        // File should be deleted after reading (one-time use)
        assert!(!recovery_file_path.exists());

        // Test case 5: Recovery file with hash and trailing whitespace
        std::fs::write(&recovery_file_path, "  test456  \n").unwrap();
        let recovery_config = guestos_recovery_config(&recovery_file_path).unwrap();
        assert_eq!(
            recovery_config,
            Some(RecoveryConfig {
                recovery_hash: "test456".to_string(),
            })
        );
        assert!(!recovery_file_path.exists());
    }
}
