use anyhow::Result;
use clap::{Parser, Subcommand};
use config::{config_map_from_path, parse_config_ini_networking, default_deployment_values};
use std::path::Path;
use utils::deployment::read_deployment_file;

mod types;

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
            let networking = parse_config_ini_networking(config_ini_path)?;
            let config_ini_variables = config_map_from_path(config_ini_path)?;
            let verbose = config_ini_variables.get("verbose").cloned();

            // get deployment.json variables
            let deployment = read_deployment_file(deployment_json_path);
            let (vm_memory, vm_cpu, nns_url, hostname, elasticsearch_hosts) = match &deployment {
                Ok(deployment_json) => (
                    deployment_json.resources.memory,
                    deployment_json.resources.cpu.clone().unwrap_or("kvm".to_string()),
                    deployment_json.nns.url.clone(),
                    deployment_json.deployment.name.to_string(),
                    deployment_json.logging.hosts.to_string(),
                ),
                Err(e) => {
                    eprintln!("Error retrieving deployment file: {e}. Continuing with default values");
                    default_deployment_values()
                },
            };

            let node_operator_private_key_path = if node_operator_private_key_path.exists() {
                Some(node_operator_private_key_path.to_path_buf())
            } else {
                None
            };

            let ssh_authorized_keys_path = Some(ssh_authorized_keys_path.to_path_buf());

            // call SetuposConfig constructor (pass None for all none options)
            // todo: refactor and simplify
            let setupos_config = types::SetuposConfig::new(
                vm_memory,
                vm_cpu,
                nns_public_key_path.to_path_buf(),
                nns_url,
                elasticsearch_hosts,
                None,
                hostname,
                node_operator_private_key_path,
                networking.ipv6_prefix,
                networking.ipv6_address,
                networking.ipv6_gateway,
                networking.ipv4_address,
                networking.ipv4_gateway,
                networking.ipv4_prefix_length,
                networking.domain,
                verbose,
                None,
                None,
                None,
                ssh_authorized_keys_path,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            );

            dbg!(setupos_config);

            // write serialized setupOS json object to config /var (or wherever)

            //todo: fix return type
            Ok(())
        }
        None => Ok(()),
    }
}
