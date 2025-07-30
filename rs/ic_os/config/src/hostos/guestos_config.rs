use anyhow::{bail, Context, Result};
use config_types::{
    DeterministicIpv6Config, FixedIpv6Config, GuestOSConfig, GuestOSUpgradeConfig, GuestVMType,
    HostOSConfig, Ipv6Config, TrustedExecutionEnvironmentConfig,
};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{calculate_deterministic_mac, IpVariant, MacAddr6Ext};
use ic_sev::HostSevCertificateProvider;
use std::net::Ipv6Addr;
use utils::to_cidr;

/// Generate the GuestOS configuration based on the provided HostOS configuration.
/// If hostos_config.icos_settings.enable_trusted_execution_environment is true,
/// sev_certificate_provider must be provided for fetching the AMD SEV-SNP certificate chain.
pub fn generate_guestos_config(
    hostos_config: &HostOSConfig,
    guest_vm_type: GuestVMType,
    sev_certificate_provider: &mut HostSevCertificateProvider,
) -> Result<GuestOSConfig> {
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
            anyhow::bail!("GuestVMType::Unknown is not a valid type for generating GuestOS config");
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

    let trusted_execution_environment_config = sev_certificate_provider
        .load_certificate_chain_pem()
        .context("Failed to load SEV certificate chain")?
        .map(|certificate_chain| TrustedExecutionEnvironmentConfig {
            sev_cert_chain_pem: certificate_chain,
        });

    let guestos_config = GuestOSConfig {
        config_version: hostos_config.config_version.clone(),
        network_settings: guestos_network_settings,
        icos_settings: hostos_config.icos_settings.clone(),
        guestos_settings: hostos_config.guestos_settings.clone(),
        guest_vm_type,
        upgrade_config,
        trusted_execution_environment_config,
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

#[cfg(test)]
mod tests {
    use super::*;
    use config_types::{
        DeploymentEnvironment, DeterministicIpv6Config, HostOSConfig, ICOSSettings, Ipv6Config,
        NetworkSettings,
    };
    use ic_sev::testing::mock_host_sev_certificate_provider;
    use std::net::Ipv6Addr;

    fn hostos_config_for_test() -> HostOSConfig {
        HostOSConfig {
            config_version: "1.0.0".to_string(),
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::Deterministic(DeterministicIpv6Config {
                    prefix: "2001:db8::".to_string(),
                    prefix_length: 64,
                    gateway: "2001:db8::1".parse().unwrap(),
                }),
                ipv4_config: None,
                domain_name: None,
            },
            icos_settings: ICOSSettings {
                node_reward_type: None,
                mgmt_mac: Default::default(),
                deployment_environment: DeploymentEnvironment::Testnet,
                logging: Default::default(),
                use_nns_public_key: None,
                nns_urls: vec![],
                use_node_operator_private_key: false,
                enable_trusted_execution_environment: false,
                use_ssh_authorized_keys: false,
                icos_dev_settings: Default::default(),
            },
            hostos_settings: Default::default(),
            guestos_settings: Default::default(),
        }
    }
    #[test]
    fn test_successful_conversion() {
        let hostos_config = hostos_config_for_test();

        let guestos_config = generate_guestos_config(
            &hostos_config,
            GuestVMType::Default,
            &mut HostSevCertificateProvider::new_disabled(),
        )
        .unwrap();

        assert_eq!(guestos_config.config_version, hostos_config.config_version);
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

        let guestos_config = generate_guestos_config(
            &hostos_config,
            GuestVMType::Upgrade,
            &mut HostSevCertificateProvider::new_disabled(),
        )
        .unwrap();

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

        let result = generate_guestos_config(
            &hostos_config,
            GuestVMType::Default,
            &mut HostSevCertificateProvider::new_disabled(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Deterministic"));
    }

    #[test]
    fn test_adds_sev_certificate_chain() {
        let hostos_config = hostos_config_for_test();

        let result = generate_guestos_config(
            &hostos_config,
            GuestVMType::Default,
            &mut mock_host_sev_certificate_provider()
                .expect("Failed to create SEV cert provider")
                .0,
        )
        .unwrap();
        assert!(!result
            .trusted_execution_environment_config
            .expect("trusted_execution_environment_config should be populated")
            .sev_cert_chain_pem
            .is_empty());
    }
}
