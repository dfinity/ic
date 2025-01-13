use std::path::Path;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use config::config_ini::config_map_from_path;
use config::deployment_json::get_deployment_settings;
use config::{DEFAULT_HOSTOS_CONFIG_INI_FILE_PATH, DEFAULT_HOSTOS_DEPLOYMENT_JSON_PATH};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{calculate_deterministic_mac, IpVariant, MacAddr6Ext};
use network::info::NetworkInfo;
use network::systemd::DEFAULT_SYSTEMD_NETWORK_DIR;
use network::{generate_network_config, resolve_mgmt_mac};
use utils::to_cidr;

#[derive(Subcommand)]
pub enum Commands {
    /// Generate systemd network configuration files. Bridges available NIC's for IC IPv6 connectivity.
    GenerateNetworkConfig {
        #[arg(short, long, default_value_t = DEFAULT_SYSTEMD_NETWORK_DIR.to_string(), value_name = "DIR")]
        /// systemd-networkd output directory
        output_directory: String,
    },
    GenerateIpv6Address {
        #[arg(short, long, default_value_t = NodeType::HostOS)]
        node_type: NodeType,
    },
    GenerateMacAddress {
        #[arg(short, long, default_value_t = NodeType::HostOS)]
        node_type: NodeType,
    },
    FetchMacAddress {},
}

#[derive(Parser)]
struct HostOSArgs {
    #[arg(short, long, default_value_t = DEFAULT_HOSTOS_CONFIG_INI_FILE_PATH.to_string(), value_name = "FILE")]
    config: String,

    #[arg(short, long, default_value_t = DEFAULT_HOSTOS_DEPLOYMENT_JSON_PATH.to_string(), value_name = "FILE")]
    /// deployment.json file path
    deployment_file: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

pub fn main() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("ERROR: this only runs on Linux.");
        std::process::exit(1);
    }

    let opts = HostOSArgs::parse();

    match opts.command {
        Some(Commands::GenerateNetworkConfig { output_directory }) => {
            let config_map = config_map_from_path(Path::new(&opts.config)).context(format!(
                "Failed to get config.ini settings for path: {}",
                &opts.config
            ))?;
            eprintln!("Using config: {:?}", config_map);

            let network_info = NetworkInfo::from_config_map(&config_map)?;
            eprintln!("Network info config: {:?}", &network_info);

            let deployment_settings = get_deployment_settings(Path::new(&opts.deployment_file))
                .context(format!(
                    "Failed to get deployment settings for file: {}",
                    &opts.deployment_file
                ))?;
            eprintln!("Deployment config: {:?}", deployment_settings);

            let mgmt_mac = resolve_mgmt_mac(deployment_settings.deployment.mgmt_mac)?;
            let deployment_environment = deployment_settings.deployment.name.parse()?;
            let generated_mac = calculate_deterministic_mac(
                &mgmt_mac,
                deployment_environment,
                IpVariant::V6,
                NodeType::HostOS,
            );

            generate_network_config(&network_info, &generated_mac, Path::new(&output_directory))
        }
        Some(Commands::GenerateIpv6Address { node_type }) => {
            let config_map = config_map_from_path(Path::new(&opts.config)).context(format!(
                "Failed to get config.ini settings for path: {}",
                &opts.config
            ))?;
            eprintln!("Using config: {:?}", config_map);

            let network_info = NetworkInfo::from_config_map(&config_map)?;
            eprintln!("Network info config: {:?}", &network_info);

            let deployment_settings = get_deployment_settings(Path::new(&opts.deployment_file))
                .context(format!(
                    "Failed to get deployment settings for file: {}",
                    &opts.deployment_file
                ))?;
            eprintln!("Deployment config: {:?}", deployment_settings);

            let mgmt_mac = resolve_mgmt_mac(deployment_settings.deployment.mgmt_mac)?;
            let deployment_environment = deployment_settings.deployment.name.parse()?;
            let generated_mac = calculate_deterministic_mac(
                &mgmt_mac,
                deployment_environment,
                IpVariant::V6,
                node_type,
            );
            let ipv6_address = generated_mac.calculate_slaac(&network_info.ipv6_prefix)?;
            println!("{}", to_cidr(ipv6_address, network_info.ipv6_subnet));
            Ok(())
        }
        Some(Commands::GenerateMacAddress { node_type }) => {
            let config_map = config_map_from_path(Path::new(&opts.config)).context(format!(
                "Failed to get config.ini settings for path: {}",
                &opts.config
            ))?;
            eprintln!("Using config: {:?}", config_map);

            let network_info = NetworkInfo::from_config_map(&config_map)?;
            eprintln!("Network info config: {:?}", &network_info);

            let deployment_settings = get_deployment_settings(Path::new(&opts.deployment_file))
                .context(format!(
                    "Failed to get deployment settings for file: {}",
                    &opts.deployment_file
                ))?;
            eprintln!("Deployment config: {:?}", deployment_settings);

            let mgmt_mac = resolve_mgmt_mac(deployment_settings.deployment.mgmt_mac)?;
            let deployment_environment = deployment_settings.deployment.name.parse()?;
            let generated_mac = calculate_deterministic_mac(
                &mgmt_mac,
                deployment_environment,
                IpVariant::V6,
                node_type,
            );
            println!("{}", generated_mac);
            Ok(())
        }
        Some(Commands::FetchMacAddress {}) => {
            let deployment_settings = get_deployment_settings(Path::new(&opts.deployment_file))
                .context(format!(
                    "Failed to get deployment settings for file: {}",
                    &opts.deployment_file
                ))?;
            eprintln!("Deployment config: {:?}", deployment_settings);

            let mgmt_mac = resolve_mgmt_mac(deployment_settings.deployment.mgmt_mac)?;
            println!("{}", mgmt_mac);
            Ok(())
        }
        None => Err(anyhow!(
            "No subcommand specified. Run with '--help' for subcommands"
        )),
    }
}
