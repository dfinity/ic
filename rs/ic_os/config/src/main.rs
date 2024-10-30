use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use config::config_ini::{get_config_ini_settings, ConfigIniSettings};
use config::deployment_json::get_deployment_settings;
use config::serialize_and_write_config;
use mac_address::mac_address::{get_ipmi_mac, FormattedMacAddress};
use std::fs::File;
use std::path::{Path, PathBuf};

use config::generate_testnet_config::{
    generate_testnet_config, GenerateTestnetConfigArgs, Ipv6ConfigType,
};
use config::types::*;

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Creates SetupOSConfig object
    CreateSetuposConfig {
        #[arg(long, default_value = config::DEFAULT_SETUPOS_CONFIG_INI_FILE_PATH, value_name = "config.ini")]
        config_ini_path: PathBuf,

        #[arg(long, default_value = config::DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH, value_name = "deployment.json")]
        deployment_json_path: PathBuf,

        #[arg(long, default_value_t = true)]
        nns_public_key_exists: bool,

        #[arg(long, default_value_t = false)]
        use_ssh_authorized_keys: bool,

        #[arg(long, default_value_t = true)]
        node_operator_private_key_exists: bool,

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
    /// Creates GuestOSConfig object from existing HostOS config.json file
    GenerateGuestosConfig {
        #[arg(long, default_value = config::DEFAULT_HOSTOS_CONFIG_OBJECT_PATH, value_name = "config.json")]
        hostos_config_json_path: PathBuf,
        #[arg(long, default_value = config::DEFAULT_HOSTOS_GUESTOS_CONFIG_OBJECT_PATH, value_name = "config-guestos.json")]
        guestos_config_json_path: PathBuf,
        #[arg(long, value_name = "ipv6_address")]
        guestos_ipv6_address: String,
    },
    /// Creates a GuestOSConfig object directly from GenerateTestnetConfigClapArgs. Only used for testing purposes.
    GenerateTestnetConfig(GenerateTestnetConfigClapArgs),
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
    pub ipv4_domain: Option<String>,

    // ICOSSettings arguments
    #[arg(long)]
    pub mgmt_mac: Option<String>,
    #[arg(long)]
    pub deployment_environment: Option<String>,
    #[arg(long)]
    pub elasticsearch_hosts: Option<String>,
    #[arg(long)]
    pub elasticsearch_tags: Option<String>,
    #[arg(long)]
    pub nns_public_key_exists: Option<bool>,
    #[arg(long)]
    pub nns_urls: Option<Vec<String>>,
    #[arg(long)]
    pub node_operator_private_key_exists: Option<bool>,
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
            nns_public_key_exists,
            use_ssh_authorized_keys,
            node_operator_private_key_exists,
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

            let mgmt_mac = match deployment_json_settings.deployment.mgmt_mac {
                Some(config_mac) => {
                    let mgmt_mac = FormattedMacAddress::try_from(config_mac.as_str())?;
                    println!(
                        "Using mgmt_mac address found in deployment.json: {}",
                        mgmt_mac
                    );
                    mgmt_mac
                }
                None => get_ipmi_mac()?,
            };

            let icos_settings = ICOSSettings {
                config_version: CONFIG_VERSION.to_string(),
                mgmt_mac,
                deployment_environment: deployment_json_settings.deployment.name,
                logging,
                nns_public_key_exists,
                nns_urls: deployment_json_settings.nns.url.clone(),
                node_operator_private_key_exists,
                use_ssh_authorized_keys,
                icos_dev_settings: ICOSDevSettings::default(),
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

            let hostos_config = HostOSConfig {
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
        Some(Commands::GenerateGuestosConfig {
            hostos_config_json_path,
            guestos_config_json_path,
            guestos_ipv6_address,
        }) => {
            let hostos_config_json_path = Path::new(&hostos_config_json_path);

            let hostos_config: HostOSConfig =
                serde_json::from_reader(File::open(hostos_config_json_path)?)?;

            // TODO: We won't have to modify networking between the hostos and
            // guestos config after completing the networking revamp (NODE-1327)
            let mut guestos_network_settings = hostos_config.network_settings;
            // Update the GuestOS networking if `guestos_ipv6_address` is provided
            match &guestos_network_settings.ipv6_config {
                Ipv6Config::Deterministic(deterministic_ipv6_config) => {
                    guestos_network_settings.ipv6_config = Ipv6Config::Fixed(FixedIpv6Config {
                        address: guestos_ipv6_address,
                        gateway: deterministic_ipv6_config.gateway,
                    });
                }
                _ => {
                    anyhow::bail!(
                        "HostOSConfig Ipv6Config should always be of type Deterministic. Cannot reassign GuestOS networking."
                    );
                }
            }

            let guestos_config = GuestOSConfig {
                network_settings: guestos_network_settings,
                icos_settings: hostos_config.icos_settings,
                guestos_settings: hostos_config.guestos_settings,
            };

            let guestos_config_json_path = Path::new(&guestos_config_json_path);
            serialize_and_write_config(guestos_config_json_path, &guestos_config)?;

            println!(
                "GuestOSConfig has been written to {}",
                guestos_config_json_path.display()
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
                ipv4_domain: clap_args.ipv4_domain,
                mgmt_mac: clap_args.mgmt_mac,
                deployment_environment: clap_args.deployment_environment,
                elasticsearch_hosts: clap_args.elasticsearch_hosts,
                elasticsearch_tags: clap_args.elasticsearch_tags,
                nns_public_key_exists: clap_args.nns_public_key_exists,
                nns_urls: clap_args.nns_urls,
                node_operator_private_key_exists: clap_args.node_operator_private_key_exists,
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
            };

            generate_testnet_config(args, clap_args.guestos_config_json_path)
        }
        None => {
            println!("No command provided. Use --help for usage information.");
            Ok(())
        }
    }
}
