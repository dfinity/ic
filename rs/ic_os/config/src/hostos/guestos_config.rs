use anyhow::{bail, Context, Result};
use config_types::{
    FixedIpv6Config, GuestOSConfig, GuestOSUpgradeConfig, GuestVMType, HostOSConfig, Ipv6Config,
    TrustedExecutionEnvironmentConfig,
};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{calculate_deterministic_mac, IpVariant, MacAddr6Ext};
use ic_sev::HostSevCertificateProvider;
use utils::to_cidr;

/// Generate the GuestOS configuration based on the provided HostOS configuration.
/// If hostos_config.icos_settings.enable_trusted_execution_environment is true,
/// sev_certificate_provider must be provided for fetching the AMD SEV-SNP certificate chain.
pub fn generate_guestos_config(
    hostos_config: &HostOSConfig,
    sev_certificate_provider: &mut HostSevCertificateProvider,
) -> Result<GuestOSConfig> {
    let hostos_config = hostos_config.clone();
    // TODO: We won't have to modify networking between the hostos and
    // guestos config after completing the networking revamp (NODE-1327)
    let mut guestos_network_settings = hostos_config.network_settings;
    match &guestos_network_settings.ipv6_config {
        Ipv6Config::Deterministic(deterministic_ipv6_config) => {
            let generated_mac = calculate_deterministic_mac(
                &hostos_config.icos_settings.mgmt_mac,
                hostos_config.icos_settings.deployment_environment,
                IpVariant::V6,
                NodeType::GuestOS, // TODO(NODE-1608): support UpgradeGuestOS
            );
            let guestos_ipv6_address =
                generated_mac.calculate_slaac(&deterministic_ipv6_config.prefix)?;
            guestos_network_settings.ipv6_config = Ipv6Config::Fixed(FixedIpv6Config {
                address: to_cidr(
                    guestos_ipv6_address,
                    deterministic_ipv6_config.prefix_length,
                ),
                gateway: deterministic_ipv6_config.gateway,
            });
        }
        _ => bail!(
            "HostOSConfig Ipv6Config should always be of type Deterministic. \
             Cannot reassign GuestOS networking."
        ),
    }

    let trusted_execution_environment_config = sev_certificate_provider
        .load_certificate_chain_pem()
        .context("Failed to load SEV certificate chain")?
        .map(|certificate_chain| TrustedExecutionEnvironmentConfig {
            sev_cert_chain_pem: certificate_chain,
        });

    let guestos_config = GuestOSConfig {
        config_version: hostos_config.config_version,
        network_settings: guestos_network_settings,
        icos_settings: hostos_config.icos_settings,
        guestos_settings: hostos_config.guestos_settings,
        // TODO: Set these fields when adding Upgrade VMs.
        guest_vm_type: GuestVMType::Default,
        upgrade_config: GuestOSUpgradeConfig::default(),
        trusted_execution_environment_config,
    };

    Ok(guestos_config)
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
                use_nns_public_key: false,
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
