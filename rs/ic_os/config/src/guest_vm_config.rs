use crate::guestos_bootstrap_image::BootstrapOptions;
use crate::guestos_config::generate_guestos_config;
use anyhow::{bail, Context, Result};
use askama::Template;
use config_types::{GuestOSConfig, HostOSConfig, Ipv6Config};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{calculate_deterministic_mac, IpVariant};
use std::path::{Path, PathBuf};

// See build.rs
include!(concat!(env!("OUT_DIR"), "/guestos_vm_template.rs"));

pub fn assemble_config_media(hostos_config: &HostOSConfig, media_path: &Path) -> Result<()> {
    let guestos_config =
        generate_guestos_config(hostos_config).context("Failed to generate GuestOS config")?;

    let bootstrap_options = make_bootstrap_options(hostos_config, guestos_config)?;

    bootstrap_options.build_bootstrap_config_image(media_path)?;

    println!(
        "Assembling config media for GuestOS: {}",
        media_path.display()
    );

    Ok(())
}

fn make_bootstrap_options(
    hostos_config: &HostOSConfig,
    guestos_config: GuestOSConfig,
) -> Result<BootstrapOptions> {
    let guestos_ipv6_config = match &guestos_config.network_settings.ipv6_config {
        Ipv6Config::Fixed(ip_config) => ip_config.clone(),
        _ => bail!(
            "Expected GuestOS IPv6 address to be fixed but was {:?}",
            guestos_config.network_settings.ipv6_config
        ),
    };

    let mut bootstrap_options = BootstrapOptions {
        guestos_config: Some(guestos_config),
        ..Default::default()
    };

    #[cfg(feature = "dev")]
    if hostos_config.icos_settings.use_ssh_authorized_keys {
        bootstrap_options.accounts_ssh_authorized_keys =
            Some(PathBuf::from("/boot/config/ssh_authorized_keys"));
    }

    if hostos_config.icos_settings.use_nns_public_key {
        bootstrap_options.nns_public_key = Some(PathBuf::from("/boot/config/nns_public_key.pem"));
    }

    if hostos_config.icos_settings.use_node_operator_private_key {
        bootstrap_options.node_operator_private_key =
            Some(PathBuf::from("/boot/config/node_operator_private_key.pem"));
    }

    bootstrap_options.ipv6_address = Some(guestos_ipv6_config.address.clone());
    bootstrap_options.ipv6_gateway = Some(guestos_ipv6_config.gateway.to_string());

    if let Some(ipv4_config) = &hostos_config.network_settings.ipv4_config {
        bootstrap_options.ipv4_address = Some(format!(
            "{}/{}",
            ipv4_config.address, ipv4_config.prefix_length
        ));
        bootstrap_options.ipv4_gateway = Some(ipv4_config.gateway.to_string());
    }

    if let Some(domain) = &hostos_config.network_settings.domain_name {
        bootstrap_options.domain = Some(domain.clone());
    }

    if let Some(node_reward_type) = &hostos_config.icos_settings.node_reward_type {
        bootstrap_options.node_reward_type = Some(node_reward_type.clone());
    }

    let hostname = format!(
        "guest-{}",
        hostos_config
            .icos_settings
            .mgmt_mac
            .to_string()
            .replace(":", "")
    );
    bootstrap_options.hostname = Some(hostname);

    bootstrap_options.nns_urls = hostos_config
        .icos_settings
        .nns_urls
        .iter()
        .map(|url| url.to_string())
        .collect();

    Ok(bootstrap_options)
}

/// Generate the GuestOS VM libvirt XML configuration and return it as String.
pub fn generate_vm_config(config: &HostOSConfig, media_path: &Path) -> Result<String> {
    let mac_address = calculate_deterministic_mac(
        &config.icos_settings.mgmt_mac,
        config.icos_settings.deployment_environment,
        IpVariant::V6,
        NodeType::GuestOS,
    );

    let cpu_domain = if config.hostos_settings.vm_cpu == "qemu" {
        "qemu"
    } else {
        "kvm"
    };

    GuestOSTemplateProps {
        cpu_domain,
        vm_memory: config.hostos_settings.vm_memory,
        nr_of_vcpus: config.hostos_settings.vm_nr_of_vcpus,
        mac_address,
        config_media: &media_path.display().to_string(),
    }
    .render()
    .context("Failed to render GuestOS VM XML template")
}

#[cfg(test)]
mod tests {
    use super::*;
    use config_types::{
        DeploymentEnvironment, DeterministicIpv6Config, HostOSConfig, HostOSSettings, ICOSSettings,
        Ipv4Config, Ipv6Config, Logging, NetworkSettings,
    };
    use goldenfile::Mint;
    use std::env;
    use std::os::unix::prelude::MetadataExt;
    use tempfile::tempdir;

    fn create_test_hostos_config() -> HostOSConfig {
        HostOSConfig {
            config_version: "1.0".to_string(),
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::Deterministic(DeterministicIpv6Config {
                    prefix: "2001:db8::".to_string(),
                    prefix_length: 64,
                    gateway: "2001:db8::ffff".parse().unwrap(),
                }),
                ipv4_config: Some(Ipv4Config {
                    address: "192.168.1.2".parse().unwrap(),
                    gateway: "192.168.1.1".parse().unwrap(),
                    prefix_length: 24,
                }),
                domain_name: Some("test.domain".to_string()),
            },
            icos_settings: ICOSSettings {
                node_reward_type: Some("type3.1".to_string()),
                mgmt_mac: "00:11:22:33:44:55".parse().unwrap(),
                deployment_environment: DeploymentEnvironment::Testnet,
                logging: Logging {
                    elasticsearch_hosts: None,
                    elasticsearch_tags: None,
                },
                use_nns_public_key: false,
                nns_urls: vec![url::Url::parse("https://example.com").unwrap()],
                use_node_operator_private_key: false,
                enable_trusted_execution_environment: false,
                use_ssh_authorized_keys: false,
                icos_dev_settings: Default::default(),
            },
            hostos_settings: HostOSSettings {
                vm_memory: 490,
                vm_cpu: "qemu".to_string(),
                vm_nr_of_vcpus: 56,
                verbose: false,
            },
            guestos_settings: Default::default(),
        }
    }

    #[test]
    fn test_make_bootstrap_options() {
        let mut config = create_test_hostos_config();
        config.icos_settings.use_nns_public_key = true;
        config.icos_settings.use_ssh_authorized_keys = true;
        config.icos_settings.use_node_operator_private_key = true;

        let guestos_config = generate_guestos_config(&config).unwrap();

        let options = make_bootstrap_options(&config, guestos_config.clone()).unwrap();

        assert_eq!(
            options,
            BootstrapOptions {
                ipv6_address: Some("2001:db8::6801:aeff:fe1a:9bb/64".to_string()),
                ipv6_gateway: Some("2001:db8::ffff".to_string()),
                ipv4_address: Some("192.168.1.2/24".to_string()),
                ipv4_gateway: Some("192.168.1.1".to_string()),
                domain: Some("test.domain".to_string()),
                node_reward_type: Some("type3.1".to_string()),
                hostname: Some("guest-001122334455".to_string()),
                nns_urls: vec!["https://example.com/".to_string()],
                guestos_config: Some(guestos_config),
                nns_public_key: Some(PathBuf::from("/boot/config/nns_public_key.pem")),
                node_operator_private_key: Some(PathBuf::from(
                    "/boot/config/node_operator_private_key.pem"
                )),
                #[cfg(feature = "dev")]
                accounts_ssh_authorized_keys: Some(PathBuf::from(
                    "/boot/config/ssh_authorized_keys"
                )),
                ..Default::default()
            }
        );
    }

    fn goldenfiles_path() -> PathBuf {
        let mut path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push("golden");
        path
    }

    fn test_vm_config(cpu_type: &str, filename: &str) {
        let mut mint = Mint::new(goldenfiles_path());
        let mut config = create_test_hostos_config();

        config.hostos_settings = HostOSSettings {
            vm_memory: 490,
            vm_cpu: cpu_type.to_string(),
            vm_nr_of_vcpus: 56,
            verbose: false,
        };

        let vm_config = generate_vm_config(&config, Path::new("/tmp/config.img")).unwrap();
        std::fs::write(mint.new_goldenpath(filename).unwrap(), vm_config).unwrap();
    }

    #[test]
    fn test_generate_vm_config_qemu() {
        test_vm_config("qemu", "guestos_vm_qemu.xml");
    }

    #[test]
    fn test_generate_vm_config_kvm() {
        test_vm_config("kvm", "guestos_vm_kvm.xml");
    }

    #[test]
    fn test_assemble_config_media_creates_file() {
        let temp_dir = tempdir().unwrap();
        let media_path = temp_dir.path().join("config.img");
        let config = create_test_hostos_config();

        let result = assemble_config_media(&config, &media_path);

        assert!(
            result.is_ok(),
            "Failed to assemble config media: {:?}",
            result
        );
        assert!(media_path.exists(), "Config media file was not created");
        assert!(
            media_path.metadata().unwrap().size() > 0,
            "Config media file is empty"
        );
    }

    #[test]
    fn ensure_tested_with_dev() {
        // Ensure that the test is run with the dev feature enabled.
        assert!(cfg!(feature = "dev"));
    }
}
