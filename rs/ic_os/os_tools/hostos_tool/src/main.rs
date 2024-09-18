use std::path::Path;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use config::config_ini::config_map_from_path;
use config::deployment_json::get_deployment_settings;
use config::{DEFAULT_HOSTOS_CONFIG_INI_FILE_PATH, DEFAULT_HOSTOS_DEPLOYMENT_JSON_PATH};
use network::generate_network_config;
use network::info::NetworkInfo;
use network::ipv6::generate_ipv6_address;
use network::mac_address::{generate_mac_address, FormattedMacAddress};
use network::node_type::NodeType;
use network::systemd::DEFAULT_SYSTEMD_NETWORK_DIR;
use utils::to_cidr;

#[derive(Subcommand)]
pub enum Commands {
    /// Generate systemd network configuration files. Bridges available NIC's for IC IPv6 connectivity.
    GenerateNetworkConfig {
        #[arg(short, long, default_value_t = DEFAULT_SYSTEMD_NETWORK_DIR.to_string(), value_name = "DIR")]
        /// systemd-networkd output directory
        output_directory: String,
    },
    GenerateMacAddress {
        #[arg(short, long, default_value = "HostOS")]
        node_type: String,
    },
    GenerateIpv6Address {
        #[arg(short, long, default_value = "HostOS")]
        node_type: String,
    },
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
            let config_map = config_map_from_path(Path::new(&opts.config))
                .context("Please specify a valid config file with '--config'")?;
            eprintln!("Using config: {:?}", config_map);

            let network_info = NetworkInfo::from_config_map(&config_map)?;
            eprintln!("Network info config: {:?}", &network_info);

            let deployment_settings = get_deployment_settings(Path::new(&opts.deployment_file));

            let deployment_name: Option<&str> = match &deployment_settings {
                Ok(deployment) => Some(deployment.deployment.name.as_str()),
                Err(e) => {
                    eprintln!("Error retrieving deployment file: {e}. Continuing without it");
                    None
                }
            };

            let mgmt_mac: Option<&str> = match &deployment_settings {
                Ok(deployment) => deployment.deployment.mgmt_mac.as_deref(),
                Err(_) => None,
            };

            generate_network_config(
                &network_info,
                mgmt_mac,
                deployment_name,
                NodeType::HostOS,
                Path::new(&output_directory),
            )
        }
        Some(Commands::GenerateIpv6Address { node_type }) => {
            let deployment_settings = get_deployment_settings(Path::new(&opts.deployment_file))
                .context("Please specify a valid deployment file with '--deployment-file'")?;
            eprintln!("Deployment config: {:?}", deployment_settings);

            let config_map = config_map_from_path(Path::new(&opts.config))
                .context("Please specify a valid config file with '--config'")?;
            eprintln!("Using config: {:?}", config_map);

            let network_info = NetworkInfo::from_config_map(&config_map)?;
            eprintln!("Network info config: {:?}", &network_info);

            let node_type = node_type.parse::<NodeType>()?;
            let mac = generate_mac_address(
                &deployment_settings.deployment.name,
                &node_type,
                deployment_settings.deployment.mgmt_mac.as_deref(),
            )?;
            let ipv6_prefix = network_info
                .ipv6_prefix
                .context("ipv6_prefix required in config to generate ipv6 address")?;
            let ipv6_address = generate_ipv6_address(&ipv6_prefix, &mac)?;
            println!("{}", to_cidr(ipv6_address, network_info.ipv6_subnet));
            Ok(())
        }
        Some(Commands::GenerateMacAddress { node_type }) => {
            let config_map = config_map_from_path(Path::new(&opts.config))
                .context("Please specify a valid config file with '--config'")?;
            eprintln!("Using config: {:?}", config_map);

            let network_info = NetworkInfo::from_config_map(&config_map)?;
            eprintln!("Network info config: {:?}", &network_info);

            let deployment_settings = get_deployment_settings(Path::new(&opts.deployment_file))
                .context("Please specify a valid deployment file with '--deployment-file'")?;
            eprintln!("Deployment config: {:?}", deployment_settings);

            let node_type = node_type.parse::<NodeType>()?;
            let mac = generate_mac_address(
                &deployment_settings.deployment.name,
                &node_type,
                deployment_settings.deployment.mgmt_mac.as_deref(),
            )?;
            let mac = FormattedMacAddress::from(&mac);
            println!("{}", mac.get());
            Ok(())
        }
        None => Err(anyhow!(
            "No subcommand specified. Run with '--help' for subcommands"
        )),
    }
}
