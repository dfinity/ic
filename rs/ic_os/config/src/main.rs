use anyhow::Result;
use clap::{Parser, Subcommand};
use config::config_ini::{get_config_ini_settings, ConfigIniSettings};
use config::deployment_json::get_deployment_settings;
use config::serialize_and_write_config;
use std::fs::File;
use std::path::{Path, PathBuf};

use config::types::*;

#[derive(Subcommand)]
pub enum Commands {
    /// Creates SetupOSConfig object
    CreateSetuposConfig {
        #[arg(long, default_value = config::DEFAULT_SETUPOS_CONFIG_INI_FILE_PATH, value_name = "config.ini")]
        config_ini_path: PathBuf,

        #[arg(long, default_value = config::DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH, value_name = "deployment.json")]
        deployment_json_path: PathBuf,

        #[arg(long, default_value = config::DEFAULT_SETUPOS_NNS_PUBLIC_KEY_PATH, value_name = "nns_public_key.pem")]
        nns_public_key_path: PathBuf,

        #[arg(long, default_value = config::DEFAULT_SETUPOS_SSH_AUTHORIZED_KEYS_PATH, value_name = "ssh_authorized_keys")]
        ssh_authorized_keys_path: PathBuf,

        #[arg(long, default_value = config::DEFAULT_SETUPOS_NODE_OPERATOR_PRIVATE_KEY_PATH, value_name = "node_operator_private_key.pem")]
        node_operator_private_key_path: PathBuf,

        #[arg(long, default_value = config::DEFAULT_SETUPOS_CONFIG_OBJECT_PATH, value_name = "config.json")]
        setupos_config_json_path: PathBuf,
    },
    /// Creates HostOSConfig object from existing SetupOS config.json file
    GenerateHostosConfig {
        #[arg(long, default_value = config::DEFAULT_SETUPOS_CONFIG_OBJECT_PATH, value_name = "config.json")]
        setupos_config_json_path: PathBuf,
        #[arg(long, default_value = config::DEFAULT_SETUPOS_HOSTOS_CONFIG_OBJECT_PATH, value_name = "config-hostos.json")]
        hostos_config_json_path: PathBuf,
    },
}

#[derive(Parser)]
#[command()]
struct ConfigArgs {
    #[command(subcommand)]
    command: Option<Commands>,
}

pub fn main() -> Result<()> {
    let opts = ConfigArgs::parse();

    match opts.command {
        Some(Commands::CreateSetuposConfig {
            config_ini_path,
            deployment_json_path,
            nns_public_key_path,
            ssh_authorized_keys_path,
            node_operator_private_key_path,
            setupos_config_json_path,
        }) => {
            // get config.ini settings
            let ConfigIniSettings {
                ipv6_prefix,
                ipv6_prefix_length,
                ipv6_gateway,
                ipv4_address,
                ipv4_gateway,
                ipv4_prefix_length,
                domain,
                verbose,
            } = get_config_ini_settings(&config_ini_path)?;

            // create NetworkSettings
            let deterministic_config = DeterministicIpv6Config {
                prefix: ipv6_prefix,
                prefix_length: ipv6_prefix_length,
                gateway: ipv6_gateway,
            };

            let ipv4_config = match (ipv4_address, ipv4_gateway, ipv4_prefix_length, domain) {
                (Some(address), Some(gateway), Some(prefix_length), Some(domain)) => {
                    Some(Ipv4Config {
                        address,
                        gateway,
                        prefix_length,
                        domain,
                    })
                }
                (None, None, None, None) => None,
                _ => {
                    println!("Warning: Partial IPv4 configuration provided. All parameters are required for IPv4 configuration.");
                    None
                }
            };

            let network_settings = NetworkSettings {
                ipv6_config: Ipv6Config::Deterministic(deterministic_config),
                ipv4_config,
            };

            // get deployment.json variables
            let deployment_json_settings = get_deployment_settings(&deployment_json_path)?;

            let logging = Logging {
                elasticsearch_hosts: deployment_json_settings.logging.hosts.to_string(),
                elasticsearch_tags: None,
            };

            let icos_dev_settings = ICOSDevSettings {
                mgmt_mac: deployment_json_settings.deployment.mgmt_mac,
            };

            let icos_settings = ICOSSettings {
                logging,
                nns_public_key_path: nns_public_key_path.to_path_buf(),
                nns_urls: deployment_json_settings.nns.url.clone(),
                hostname: deployment_json_settings.deployment.name.to_string(),
                node_operator_private_key_path: node_operator_private_key_path
                    .exists()
                    .then_some(node_operator_private_key_path),
                ssh_authorized_keys_path: ssh_authorized_keys_path
                    .exists()
                    .then_some(ssh_authorized_keys_path),
                icos_dev_settings,
            };

            let setupos_settings = SetupOSSettings;

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

            let setupos_config = SetupOSConfig {
                network_settings,
                icos_settings,
                setupos_settings,
                hostos_settings,
                guestos_settings,
            };
            println!("SetupOSConfig: {:?}", setupos_config);

            let setupos_config_json_path = Path::new(&setupos_config_json_path);
            serialize_and_write_config(setupos_config_json_path, &setupos_config)?;

            println!(
                "SetupOSConfig has been written to {}",
                setupos_config_json_path.display()
            );

            Ok(())
        }
        Some(Commands::GenerateHostosConfig {
            setupos_config_json_path,
            hostos_config_json_path,
        }) => {
            let setupos_config_json_path = Path::new(&setupos_config_json_path);

            let setupos_config: SetupOSConfig =
                serde_json::from_reader(File::open(setupos_config_json_path)?)?;

            // update select file paths for HostOS
            let mut hostos_icos_settings = setupos_config.icos_settings;
            let hostos_config_path = Path::new("/boot/config");
            if let Some(ref mut path) = hostos_icos_settings.ssh_authorized_keys_path {
                *path = hostos_config_path.join("ssh_authorized_keys");
            }
            if let Some(ref mut path) = hostos_icos_settings.node_operator_private_key_path {
                *path = hostos_config_path.join("node_operator_private_key.pem");
            }
            hostos_icos_settings.nns_public_key_path =
                hostos_config_path.join("nns_public_key.pem");

            let hostos_config = HostOSConfig {
                network_settings: setupos_config.network_settings,
                icos_settings: hostos_icos_settings,
                hostos_settings: setupos_config.hostos_settings,
                guestos_settings: setupos_config.guestos_settings,
            };

            let hostos_config_json_path = Path::new(&hostos_config_json_path);
            serialize_and_write_config(hostos_config_json_path, &hostos_config)?;

            println!(
                "HostOSConfig has been written to {}",
                hostos_config_json_path.display()
            );

            Ok(())
        }
        None => Ok(()),
    }
}
