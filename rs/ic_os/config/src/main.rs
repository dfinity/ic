use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use config::generate_testnet_config::{
    generate_testnet_config, GenerateTestnetConfigArgs, Ipv6ConfigType,
};
use config::serialize_and_write_config;
use config::setupos::config_ini::{get_config_ini_settings, ConfigIniSettings};
use config::setupos::deployment_json::get_deployment_settings;
use config_types::*;
use macaddr::MacAddr6;
use network::resolve_mgmt_mac;
use regex::Regex;
use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Creates SetupOSConfig object
    CreateSetuposConfig {
        #[arg(long, default_value = config::DEFAULT_SETUPOS_CONFIG_INI_FILE_PATH, value_name = "config.ini")]
        config_ini_path: PathBuf,

        #[arg(long, default_value = config::DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH, value_name = "deployment.json")]
        deployment_json_path: PathBuf,

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
    /// Creates a GuestOSConfig object directly from GenerateTestnetConfigClapArgs. Only used for testing purposes.
    GenerateTestnetConfig(GenerateTestnetConfigClapArgs),
    /// Checks if the tool is config_dev or config
    CheckVariantType,
}

#[derive(Parser)]
#[command()]
struct ConfigArgs {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Args)]
pub struct GenerateTestnetConfigClapArgs {
    #[arg(long)]
    pub ipv6_config_type: Option<Ipv6ConfigType>,
    #[arg(long)]
    pub deterministic_prefix: Option<String>,
    #[arg(long)]
    pub deterministic_prefix_length: Option<u8>,
    #[arg(long)]
    pub deterministic_gateway: Option<String>,
    #[arg(long)]
    pub fixed_address: Option<String>,
    #[arg(long)]
    pub fixed_gateway: Option<String>,
    #[arg(long)]
    pub ipv4_address: Option<String>,
    #[arg(long)]
    pub ipv4_gateway: Option<String>,
    #[arg(long)]
    pub ipv4_prefix_length: Option<u8>,
    #[arg(long)]
    pub domain_name: Option<String>,

    // ICOSSettings arguments
    #[arg(long)]
    pub node_reward_type: Option<String>,
    #[arg(long)]
    pub mgmt_mac: Option<MacAddr6>,
    #[arg(long)]
    pub deployment_environment: Option<DeploymentEnvironment>,
    #[arg(long)]
    pub elasticsearch_hosts: Option<String>,
    #[arg(long)]
    pub elasticsearch_tags: Option<String>,
    #[arg(long)]
    pub enable_trusted_execution_environment: Option<bool>,
    #[arg(long)]
    pub nns_urls: Option<Vec<String>>,
    #[arg(long)]
    pub use_node_operator_private_key: Option<bool>,
    #[arg(long)]
    pub use_ssh_authorized_keys: Option<bool>,

    // GuestOSSettings arguments
    #[arg(long)]
    pub inject_ic_crypto: Option<bool>,
    #[arg(long)]
    pub inject_ic_state: Option<bool>,
    #[arg(long)]
    pub inject_ic_registry_local_store: Option<bool>,

    // GuestOSDevSettings arguments
    #[arg(long)]
    pub backup_retention_time_seconds: Option<u64>,
    #[arg(long)]
    pub backup_purging_interval_seconds: Option<u64>,
    #[arg(long)]
    pub malicious_behavior: Option<String>,
    #[arg(long)]
    pub query_stats_epoch_length: Option<u64>,
    #[arg(long)]
    pub bitcoind_addr: Option<String>,
    #[arg(long)]
    pub jaeger_addr: Option<String>,
    #[arg(long)]
    pub socks_proxy: Option<String>,
    #[arg(long)]
    pub hostname: Option<String>,
    #[arg(long)]
    pub generate_ic_boundary_tls_cert: Option<String>,

    // Output path
    #[arg(long)]
    pub guestos_config_json_path: PathBuf,
}

pub fn main() -> Result<()> {
    let opts = ConfigArgs::parse();

    match opts.command {
        Some(Commands::CreateSetuposConfig {
            config_ini_path,
            deployment_json_path,
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
                domain_name,
                verbose,
                node_reward_type,
                enable_trusted_execution_environment,
            } = get_config_ini_settings(&config_ini_path)?;

            // create NetworkSettings
            let deterministic_config = DeterministicIpv6Config {
                prefix: ipv6_prefix,
                prefix_length: ipv6_prefix_length,
                gateway: ipv6_gateway,
            };

            let ipv4_config = match (ipv4_address, ipv4_gateway, ipv4_prefix_length) {
                (Some(address), Some(gateway), Some(prefix_length)) => Some(Ipv4Config {
                    address,
                    gateway,
                    prefix_length,
                }),
                (None, None, None) => None,
                _ => {
                    println!("Warning: Partial IPv4 configuration provided. All parameters are required for IPv4 configuration.");
                    None
                }
            };

            let network_settings = NetworkSettings {
                ipv6_config: Ipv6Config::Deterministic(deterministic_config),
                ipv4_config,
                domain_name,
            };

            // get deployment.json variables
            let deployment_json_settings = get_deployment_settings(&deployment_json_path)?;

            let mgmt_mac = resolve_mgmt_mac(deployment_json_settings.deployment.mgmt_mac)?;

            if let Some(ref node_reward_type) = node_reward_type {
                let node_reward_type_pattern = Regex::new(r"^type[0-9]+(\.[0-9])?$")?;
                if !node_reward_type_pattern.is_match(node_reward_type) {
                    anyhow::bail!(
                            "Invalid node_reward_type '{}'. It must match the pattern ^type[0-9]+(\\.[0-9])?$",
                            node_reward_type
                        );
                }
            } else {
                println!("Node reward type is not set. Skipping validation.");
            }

            let icos_settings = ICOSSettings {
                node_reward_type,
                mgmt_mac,
                deployment_environment: deployment_json_settings.deployment.deployment_environment,
                logging: Logging {
                    elasticsearch_hosts: deployment_json_settings.logging.elasticsearch_hosts,
                    elasticsearch_tags: deployment_json_settings.logging.elasticsearch_tags,
                },
                use_nns_public_key: None,
                nns_urls: deployment_json_settings.nns.urls.clone(),
                use_node_operator_private_key: Path::new("/config/node_operator_private_key.pem")
                    .exists(),
                enable_trusted_execution_environment,
                use_ssh_authorized_keys: Path::new("/config/ssh_authorized_keys").exists(),
                icos_dev_settings: ICOSDevSettings::default(),
            };

            let setupos_settings = SetupOSSettings;

            let hostos_settings = HostOSSettings {
                vm_memory: deployment_json_settings.vm_resources.memory,
                vm_cpu: deployment_json_settings.vm_resources.cpu,
                vm_nr_of_vcpus: deployment_json_settings.vm_resources.nr_of_vcpus,
                verbose,
            };

            let guestos_settings = GuestOSSettings::default();

            let setupos_config = SetupOSConfig {
                config_version: CONFIG_VERSION.to_string(),
                network_settings,
                icos_settings,
                setupos_settings,
                hostos_settings,
                guestos_settings,
            };
            // SetupOSConfig is safe to log; it does not contain any secret material
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

            let hostos_config = HostOSConfig {
                config_version: setupos_config.config_version,
                network_settings: setupos_config.network_settings,
                icos_settings: setupos_config.icos_settings,
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
        Some(Commands::GenerateTestnetConfig(clap_args)) => {
            // Convert `clap_args` into `GenerateTestnetConfigArgs`
            let args = GenerateTestnetConfigArgs {
                ipv6_config_type: clap_args.ipv6_config_type,
                deterministic_prefix: clap_args.deterministic_prefix,
                deterministic_prefix_length: clap_args.deterministic_prefix_length,
                deterministic_gateway: clap_args.deterministic_gateway,
                fixed_address: clap_args.fixed_address,
                fixed_gateway: clap_args.fixed_gateway,
                ipv4_address: clap_args.ipv4_address,
                ipv4_gateway: clap_args.ipv4_gateway,
                ipv4_prefix_length: clap_args.ipv4_prefix_length,
                domain_name: clap_args.domain_name,
                node_reward_type: clap_args.node_reward_type,
                mgmt_mac: clap_args.mgmt_mac,
                deployment_environment: clap_args.deployment_environment,
                elasticsearch_hosts: clap_args.elasticsearch_hosts,
                elasticsearch_tags: clap_args.elasticsearch_tags,
                nns_urls: clap_args.nns_urls,
                enable_trusted_execution_environment: clap_args
                    .enable_trusted_execution_environment,
                use_node_operator_private_key: clap_args.use_node_operator_private_key,
                use_ssh_authorized_keys: clap_args.use_ssh_authorized_keys,
                inject_ic_crypto: clap_args.inject_ic_crypto,
                inject_ic_state: clap_args.inject_ic_state,
                inject_ic_registry_local_store: clap_args.inject_ic_registry_local_store,
                backup_retention_time_seconds: clap_args.backup_retention_time_seconds,
                backup_purging_interval_seconds: clap_args.backup_purging_interval_seconds,
                malicious_behavior: clap_args.malicious_behavior,
                query_stats_epoch_length: clap_args.query_stats_epoch_length,
                bitcoind_addr: clap_args.bitcoind_addr,
                jaeger_addr: clap_args.jaeger_addr,
                socks_proxy: clap_args.socks_proxy,
                hostname: clap_args.hostname,
                generate_ic_boundary_tls_cert: clap_args.generate_ic_boundary_tls_cert,
            };

            serialize_and_write_config(
                &clap_args.guestos_config_json_path,
                &generate_testnet_config(args)?,
            )
        }
        // Note: This command should generally be avoided.
        // Instead of relying on this command, consider porting the relevant bash logic to Rust
        // and integrating it directly into the config tool.
        Some(Commands::CheckVariantType) => {
            let is_dev_feature = cfg!(feature = "dev");

            if is_dev_feature {
                print!("dev");
            } else {
                print!("prod");
            }

            Ok(())
        }
        None => {
            println!("No command provided. Use --help for usage information.");
            Ok(())
        }
    }
}
