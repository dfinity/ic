use anyhow::Result;
use clap::{Parser, Subcommand};
use config::{default_deployment_values, parse_config_ini};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use utils::deployment::read_deployment_file;

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

            // get config.ini variables
            let (networking, verbose) = parse_config_ini(config_ini_path)?;

            // get deployment.json variables
            let deployment = read_deployment_file(deployment_json_path);
            let (vm_memory, vm_cpu, nns_url, hostname, elasticsearch_hosts) = match &deployment {
                Ok(deployment_json) => (
                    deployment_json.resources.memory,
                    deployment_json
                        .resources
                        .cpu
                        .clone()
                        .unwrap_or("kvm".to_string()),
                    deployment_json.nns.url.clone(),
                    deployment_json.deployment.name.to_string(),
                    deployment_json.logging.hosts.to_string(),
                ),
                Err(e) => {
                    eprintln!(
                        "Error retrieving deployment file: {e}. Continuing with default values"
                    );
                    default_deployment_values()
                }
            };

            let node_operator_private_key_path = if node_operator_private_key_path.exists() {
                Some(node_operator_private_key_path.to_path_buf())
            } else {
                None
            };

            let ssh_authorized_keys_path = Some(ssh_authorized_keys_path.to_path_buf());

            let ic_config = config::types::IcConfigBuilder::new()
                .networking(networking)
                .nns_public_key_path(nns_public_key_path.to_path_buf())
                .nns_url(nns_url)
                .elasticsearch_hosts(elasticsearch_hosts)
                .hostname(hostname)
                .node_operator_private_key_path(node_operator_private_key_path)
                .ssh_authorized_keys_path(ssh_authorized_keys_path)
                .verbose(verbose)
                .build()
                .expect("Failed to build IcConfig");

            let setupos_config = config::types::SetuposConfig::new(vm_memory, vm_cpu, ic_config);

            let serialized_config = serde_json::to_string_pretty(&setupos_config)
                .expect("Failed to serialize SetuposConfig");

            let default_config_object_path = Path::new(config::DEFAULT_CONFIG_OBJECT_PATH);

            // Write serialized data to the file
            let mut config_file =
                File::create(default_config_object_path).expect("Failed to create config file");
            config_file
                .write_all(serialized_config.as_bytes())
                .expect("Failed to write to config file");

            println!(
                "SetuposConfig has been written to {}",
                default_config_object_path.display()
            );

            dbg!(setupos_config);

            Ok(())
        }
        None => Ok(()),
    }
}
