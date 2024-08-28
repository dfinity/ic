
use anyhow::Result;
use clap::{Parser, Subcommand};
use config::{config_map_from_path, ConfigMap};

// todo: add PathBuf
// use std::path::PathBuf;
use std::path::Path;

mod types;

#[derive(Subcommand)]
pub enum Commands {
    /// Creates SetuposConfig object
    CreateSetuposConfig{
        #[arg(short, long, default_value_t = config::DEFAULT_SETUPOS_CONFIG_FILE_PATH.to_string(), value_name = "config.ini")]
        config_ini_path: String,

        #[arg(short, long, default_value_t = config::DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH.to_string(), value_name = "deployment.json")]
        deployment_json_path: String,

        #[arg(short, long, default_value_t = config::DEFAULT_SETUPOS_NNS_PUBLIC_KEY_PATH.to_string(), value_name = "nns_public_key.pem")]
        nns_public_key_path: String,

        #[arg(short, long, default_value_t = config::DEFAULT_SETUPOS_SSH_AUTHORIZED_KEYS_PATH.to_string(), value_name = "ssh_authorized_keys")]
        ssh_authorized_keys_path: String,

        #[arg(short, long, default_value_t = config::DEFAULT_SETUPOS_NODE_OPERATOR_PRIVATE_KEY_PATH.to_string(), value_name = "node_operator_private_key.pem")]
        node_operator_private_key_path: String,
    }
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
        Some(Commands::CreateSetuposConfig { config_ini_path, deployment_json_path, nns_public_key_path, ssh_authorized_keys_path, node_operator_private_key_path}) => {
            let config_ini_path = Path::new(&config_ini_path);
            let deployment_json_path = Path::new(&deployment_json_path);
            let nns_public_key_path = Path::new(&nns_public_key_path);
            let ssh_authorized_keys_path = Path::new(&ssh_authorized_keys_path);
            let node_operator_private_key_path = Path::new(&node_operator_private_key_path);

            let config_ini_variables: ConfigMap = config_map_from_path(config_ini_path)?;
            // get deployment.json variables

            // todo: read out the nns_public_key value
            // todo: ssh_authorized_keys_path
            // todo: node_operator_private_key

            
            // todo: parse the values out of the files
            let vm_memory = ;
            let vm_cpu = ;
            // help: nns_public_key_path is copied to GuestOS (and it's contents are not copied into ic.json)
            // let nns_public_key_contents = ...
            let nns_url = ;
            let elasticsearch_hosts= ;
            let elasticsearch_tags = None;
            let hostname := ;
            let node_operator_private_key_path = if node_operator_private_key_path.exists() {
                Some(node_operator_private_key_path.to_path_buf())
            } else {
                None
            };
            let ipv6_address = config_ini_variables.get("ipv6_address")?;
            let ipv6_gateway = config_ini_variables.get("ipv6_address")?;
            let ipv4_address = config_ini_variables.get("ipv4_address");
            let ipv4_gateway = config_ini_variables.get("ipv4_gateway");
            let domain = config_ini_variables.get("domain");
            let verbose = config_ini_variables.get("verbose");
            let ic_crypto_path = None;
            let ic_state_path = None;
            let ic_registry_local_store_path = None;
            let accounts_ssh_authorized_keys_path = None;
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
                nns_public_key_path,
                nns_url ,
                elasticsearch_hosts,
                elasticsearch_tags,
                hostname,
                node_operator_private_key_path,
                ipv6_address,
                ipv6_gateway,
                ipv4_address,
                ipv4_gateway,
                domain,
                verbose,
                ic_crypto_path,
                ic_state_path,
                ic_registry_local_store_path,
                accounts_ssh_authorized_keys_path,
                backup_retention_time_seconds,
                backup_purging_interval_seconds,
                malicious_behavior,
                query_stats_epoch_length,
                bitcoind_addr,
                jaeger_addr,
                socks_proxy,
            );

            //todo: fix return type
            Ok(())
        }
        None => Ok(()),
    }
}