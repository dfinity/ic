use crate::{GuestVMType, GUESTOS_DEVICE};
use anyhow::{Context, Result};
use askama::Template;
use config::hostos::guestos_bootstrap_image::BootstrapOptions;
use config::hostos::guestos_config::generate_guestos_config;
use config_types::{GuestOSConfig, HostOSConfig};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{calculate_deterministic_mac, IpVariant};
use std::path::{Path, PathBuf};

// See build.rs
include!(concat!(env!("OUT_DIR"), "/guestos_vm_template.rs"));

const DEFAULT_GUEST_VM_DOMAIN_NAME: &str = "guestos";
const UPGRADE_GUEST_VM_DOMAIN_NAME: &str = "upgrade-guestos";

const DEFAULT_SERIAL_LOG_PATH: &str = "/var/log/libvirt/qemu/guestos-serial.log";
const UPGRADE_SERIAL_LOG_PATH: &str = "/var/log/libvirt/qemu/upgrade-guestos-serial.log";

#[derive(Debug)]
pub struct DirectBootConfig {
    /// The kernel file
    pub kernel: PathBuf,
    /// The initrd file
    pub initrd: PathBuf,
    /// Kernel command line parameters
    pub kernel_cmdline: String,
}

pub fn assemble_config_media(
    hostos_config: &HostOSConfig,
    guest_vm_type: GuestVMType,
    media_path: &Path,
) -> Result<()> {
    let guestos_config = generate_guestos_config(hostos_config, guest_vm_type.to_config_type())
        .context("Failed to generate GuestOS config")?;

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

    Ok(bootstrap_options)
}

/// Generate the GuestOS VM libvirt XML configuration and return it as String.
pub fn generate_vm_config(
    config: &HostOSConfig,
    media_path: &Path,
    direct_boot: Option<DirectBootConfig>,
    guest_vm_type: GuestVMType,
) -> Result<String> {
    let node_type = match guest_vm_type {
        GuestVMType::Default => NodeType::GuestOS,
        GuestVMType::Upgrade => NodeType::UpgradeGuestOS,
    };
    let mac_address = calculate_deterministic_mac(
        &config.icos_settings.mgmt_mac,
        config.icos_settings.deployment_environment,
        IpVariant::V6,
        node_type,
    );

    let cpu_domain = if config.hostos_settings.vm_cpu == "qemu" {
        "qemu"
    } else {
        "kvm"
    };

    GuestOSTemplateProps {
        domain_name: vm_domain_name(guest_vm_type).to_string(),
        domain_uuid: vm_domain_uuid(guest_vm_type).to_string(),
        disk_device: GUESTOS_DEVICE.to_string(),
        cpu_domain: cpu_domain.to_string(),
        console_log_path: serial_log_path(guest_vm_type).display().to_string(),
        vm_memory: config.hostos_settings.vm_memory,
        nr_of_vcpus: config.hostos_settings.vm_nr_of_vcpus,
        mac_address,
        config_media_path: media_path.to_path_buf(),
        direct_boot,
        enable_sev: config.icos_settings.enable_trusted_execution_environment,
    }
    .render()
    .context("Failed to render GuestOS VM XML template")
}

pub fn vm_domain_name(guest_vm_type: GuestVMType) -> &'static str {
    match guest_vm_type {
        GuestVMType::Default => DEFAULT_GUEST_VM_DOMAIN_NAME,
        GuestVMType::Upgrade => UPGRADE_GUEST_VM_DOMAIN_NAME,
    }
}

pub fn vm_domain_uuid(guest_vm_type: GuestVMType) -> &'static str {
    match guest_vm_type {
        GuestVMType::Default => "fd897da5-8017-41c8-8575-a706dba30766",
        GuestVMType::Upgrade => "1ea49839-7f46-4560-a4c7-fce677bbfbbd",
    }
}

pub fn serial_log_path(guest_vm_type: GuestVMType) -> &'static Path {
    match guest_vm_type {
        GuestVMType::Default => Path::new(DEFAULT_SERIAL_LOG_PATH),
        GuestVMType::Upgrade => Path::new(UPGRADE_SERIAL_LOG_PATH),
    }
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

        let guestos_config =
            generate_guestos_config(&config, config_types::GuestVMType::Default).unwrap();

        let options = make_bootstrap_options(&config, guestos_config.clone()).unwrap();

        assert_eq!(
            options,
            BootstrapOptions {
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

    fn test_vm_config(
        filename: &str,
        hostos_settings: HostOSSettings,
        enable_trusted_execution_environment: bool,
        enable_direct_boot: bool,
        guest_vm_type: GuestVMType,
    ) {
        let mut mint = Mint::new(goldenfiles_path());
        let mut config = create_test_hostos_config();
        config.icos_settings.enable_trusted_execution_environment =
            enable_trusted_execution_environment;

        config.hostos_settings = hostos_settings;

        let direct_boot = if enable_direct_boot {
            Some(DirectBootConfig {
                kernel: PathBuf::from("/tmp/test-kernel"),
                initrd: PathBuf::from("/tmp/test-initrd"),
                kernel_cmdline: "security=selinux selinux=1 enforcing=0".to_string(),
            })
        } else {
            None
        };

        let vm_config = generate_vm_config(
            &config,
            Path::new("/tmp/config.img"),
            direct_boot,
            guest_vm_type,
        )
        .unwrap();
        std::fs::write(mint.new_goldenpath(filename).unwrap(), vm_config).unwrap();
    }

    #[test]
    fn test_generate_vm_config_qemu() {
        test_vm_config(
            "guestos_vm_qemu.xml",
            HostOSSettings {
                vm_memory: 490,
                vm_cpu: "qemu".to_string(),
                vm_nr_of_vcpus: 56,
                ..HostOSSettings::default()
            },
            /*enable_trusted_execution_environment=*/ false,
            /*enable_direct_boot=*/ true,
            GuestVMType::Default,
        );
    }

    #[test]
    fn test_generate_vm_config_upgrade_guestos() {
        test_vm_config(
            "upgrade_guestos.xml",
            HostOSSettings {
                vm_memory: 490,
                vm_cpu: "qemu".to_string(),
                vm_nr_of_vcpus: 64,
                ..HostOSSettings::default()
            },
            /*enable_trusted_execution_environment=*/ true,
            /*enable_direct_boot=*/ true,
            GuestVMType::Upgrade,
        );
    }

    #[test]
    fn test_generate_vm_config_kvm() {
        test_vm_config(
            "guestos_vm_kvm.xml",
            HostOSSettings {
                vm_memory: 490,
                vm_cpu: "kvm".to_string(),
                vm_nr_of_vcpus: 56,
                ..HostOSSettings::default()
            },
            /*enable_trusted_execution_environment=*/ false,
            /*enable_direct_boot=*/ false,
            GuestVMType::Default,
        );
    }

    #[test]
    fn test_generate_vm_config_sev() {
        test_vm_config(
            "guestos_vm_sev.xml",
            HostOSSettings {
                vm_memory: 490,
                vm_cpu: "kvm".to_string(),
                vm_nr_of_vcpus: 56,
                ..HostOSSettings::default()
            },
            /*enable_trusted_execution_environment=*/ true,
            /*enable_direct_boot=*/ true,
            GuestVMType::Default,
        );
    }

    #[test]
    fn test_assemble_config_media_creates_file() {
        let temp_dir = tempdir().unwrap();
        let media_path = temp_dir.path().join("config.img");
        let config = create_test_hostos_config();

        let result = assemble_config_media(&config, GuestVMType::Upgrade, &media_path);

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
