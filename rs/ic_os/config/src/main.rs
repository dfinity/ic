use anyhow::Result;
use clap::{Parser, Subcommand};
use config::{get_config_ini_settings, get_deployment_settings, write_to_file};
use std::path::Path;
use std::fs::File;

use config::types::{SetupOSConfig, HostOSConfig, HostOSSettings, GuestOSSettings, GuestosDevConfig, ICOSSettings};

#[derive(Subcommand)]
pub enum Commands {
    /// Creates SetuposConfig object
    CreateSetuposConfig {
        #[arg(long, default_value_t = config::DEFAULT_SETUPOS_CONFIG_FILE_PATH.to_string(), value_name = "config.ini")]
        config_ini_path: String,

        #[arg(long, default_value_t = config::DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH.to_string(), value_name = "deployment.json")]
        deployment_json_path: String,

        #[arg(long, default_value_t = config::DEFAULT_SETUPOS_NNS_PUBLIC_KEY_PATH.to_string(), value_name = "nns_public_key.pem")]
        nns_public_key_path: String,

        #[arg(long, default_value_t = config::DEFAULT_SETUPOS_SSH_AUTHORIZED_KEYS_PATH.to_string(), value_name = "ssh_authorized_keys")]
        ssh_authorized_keys_path: String,

        #[arg(long, default_value_t = config::DEFAULT_SETUPOS_NODE_OPERATOR_PRIVATE_KEY_PATH.to_string(), value_name = "node_operator_private_key.pem")]
        node_operator_private_key_path: String,
    },
    GenerateHostosConfig {
        #[arg(long, default_value_t = config::DEFAULT_CONFIG_OBJECT_PATH.to_string(), value_name = "config.json")]
        setupos_config_json_path: String,
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
        }) => {
            let config_ini_path = Path::new(&config_ini_path);
            let deployment_json_path = Path::new(&deployment_json_path);
            // help: nns_public_key_path is copied to GuestOS (and it's contents are not copied into ic.json)
            let nns_public_key_path = Path::new(&nns_public_key_path);
            let ssh_authorized_keys_path = Path::new(&ssh_authorized_keys_path);
            let node_operator_private_key_path = Path::new(&node_operator_private_key_path);

            let ssh_authorized_keys_path = Some(ssh_authorized_keys_path.to_path_buf());

            let node_operator_private_key_path = if node_operator_private_key_path.exists() {
                Some(node_operator_private_key_path.to_path_buf())
            } else {
                None
            };

            // get config.ini variables
            let (network_settings, verbose) = get_config_ini_settings(config_ini_path)?;

            // get deployment.json variables
            let (vm_memory, vm_cpu, nns_url, hostname, elasticsearch_hosts) =
                get_deployment_settings(deployment_json_path);

            let icos_settings = ICOSSettings {
                nns_public_key_path: nns_public_key_path.to_path_buf(),
                nns_url,
                elasticsearch_hosts,
                elasticsearch_tags: None,
                hostname,
                node_operator_private_key_path,
                ssh_authorized_keys_path,
            };

            let guestos_settings = GuestOSSettings {
                ic_crypto_path: None,
                ic_state_path: None,
                ic_registry_local_store_path: None,
                guestos_dev: GuestosDevConfig::default(),
            };

            let hostos_settings = HostOSSettings { vm_memory, vm_cpu, verbose};

            let setupos_config = SetupOSConfig {
                network_settings,
                icos_settings,
                hostos_settings,
                guestos_settings,
            };

            let serialized_config = serde_json::to_string_pretty(&setupos_config)
                .expect("Failed to serialize SetuposConfig");

            let default_config_object_path = Path::new(config::DEFAULT_CONFIG_OBJECT_PATH);
            write_to_file(default_config_object_path, &serialized_config)?;

            println!(
                "SetuposConfig has been written to {}",
                default_config_object_path.display()
            );

            Ok(())
        }
        Some(Commands::GenerateHostosConfig { setupos_config_json_path }) => {
            let setupos_config_json_path = Path::new(&setupos_config_json_path);

            let setupos_config: SetupOSConfig = serde_json::from_reader(File::open(setupos_config_json_path)?)?;

            let hostos_config = HostOSConfig {
                network_settings: setupos_config.network_settings,
                icos_settings: setupos_config.icos_settings,
                hostos_settings: setupos_config.hostos_settings,
                guestos_settings: setupos_config.guestos_settings,
            };

            let serialized_hostos_config = serde_json::to_string_pretty(&hostos_config)
                .expect("Failed to serialize HostOSConfig");

            let output_path = Path::new("/var/ic/config/config-hostos.json");
            write_to_file(output_path, &serialized_hostos_config)?;

            println!(
                "HostOSConfig has been written to {}",
                output_path.display()
            );

            Ok(())
        }
        None => Ok(()),
    }
}
