use anyhow::Result;
use clap::{Parser, Subcommand};
use config::{config_map_from_path, parse_config_ini_networking};
use std::path::Path;
use url::Url;
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
            let nns_public_key_path = Path::new(&nns_public_key_path);
            let ssh_authorized_keys_path = Path::new(&ssh_authorized_keys_path);
            let node_operator_private_key_path = Path::new(&node_operator_private_key_path);

            // get config.ini variables
            let networking = parse_config_ini_networking(config_ini_path)?;
            let config_ini_variables = config_map_from_path(config_ini_path)?;
            let verbose = config_ini_variables.get("verbose").cloned();

            // get deployment.json variables
            let deployment = read_deployment_file(deployment_json_path);
            let vm_memory: u32;
            let vm_cpu: String;
            let nns_url: Vec<Url>;
            let hostname: String;
            let elasticsearch_hosts: String;
            match &deployment {
                Ok(deployment_json) => {
                    vm_memory = deployment_json.resources.memory;
                    vm_cpu = deployment_json
                        .resources
                        .cpu
                        .clone()
                        .unwrap_or("kvm".to_string());
                    nns_url = deployment_json.nns.url.clone();
                    hostname = deployment_json.deployment.name.to_string();
                    elasticsearch_hosts = deployment_json.logging.hosts.to_string();
                }
                Err(e) => {
                    eprintln!(
                        "Error retrieving deployment file: {e}. Continuing with default values"
                    );
                    vm_memory = 490;
                    vm_cpu = "kvm".to_string();
                    nns_url = vec![
                        Url::parse("https://icp-api.io").unwrap(),
                        Url::parse("https://icp0.io").unwrap(),
                        Url::parse("https://ic0.app").unwrap(),
                    ];
                    hostname = "mainnet".to_string();
                    elasticsearch_hosts= "elasticsearch-node-0.mercury.dfinity.systems:443 elasticsearch-node-1.mercury.dfinity.systems:443 elasticsearch-node-2.mercury.dfinity.systems:443 elasticsearch-node-3.mercury.dfinity.systems:443".to_string();
                }
            }

            // help: nns_public_key_path is copied to GuestOS (and it's contents are not copied into ic.json)
            let elasticsearch_tags = None;
            let node_operator_private_key_path = if node_operator_private_key_path.exists() {
                Some(node_operator_private_key_path.to_path_buf())
            } else {
                None
            };

            let ic_crypto_path = None;
            let ic_state_path = None;
            let ic_registry_local_store_path = None;
            let ssh_authorized_keys_path = Some(ssh_authorized_keys_path.to_path_buf());
            let backup_retention_time_seconds = None;
            let backup_purging_interval_seconds = None;
            let malicious_behavior = None;
            let query_stats_epoch_length = None;
            let bitcoind_addr = None;
            let jaeger_addr = None;
            let socks_proxy = None;

            // call SetuposConfig constructor (pass None for all none options)
            // todo: refactor and simplify
            let setupos_config = types::SetuposConfig::new(
                vm_memory,
                vm_cpu,
                nns_public_key_path.to_path_buf(),
                nns_url,
                elasticsearch_hosts,
                elasticsearch_tags,
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
                ic_crypto_path,
                ic_state_path,
                ic_registry_local_store_path,
                ssh_authorized_keys_path,
                backup_retention_time_seconds,
                backup_purging_interval_seconds,
                malicious_behavior,
                query_stats_epoch_length,
                bitcoind_addr,
                jaeger_addr,
                socks_proxy,
            );

            dbg!(setupos_config);

            // write serialized setupOS json object to config /var (or wherever)

            //todo: fix return type
            Ok(())
        }
        None => Ok(()),
    }
}
