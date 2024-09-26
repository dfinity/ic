use std::path::Path;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use config::config_ini::config_map_from_path;
use config::deployment_json::get_deployment_settings;
use config::{DEFAULT_HOSTOS_CONFIG_INI_FILE_PATH, DEFAULT_HOSTOS_DEPLOYMENT_JSON_PATH};
use network::generate_network_config;
use network::info::NetworkInfo;
use network::ipv6::generate_ipv6_address;
use network::mac_address::{generate_mac_address, get_ipmi_mac, FormattedMacAddress};
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

            let mgmt_mac = match deployment_settings.deployment.mgmt_mac {
                Some(config_mac) => {
                    let mgmt_mac = FormattedMacAddress::try_from(config_mac.as_str())?;
                    eprintln!(
                        "Using mgmt_mac address found in deployment.json: {}",
                        mgmt_mac.get()
                    );
                    mgmt_mac
                }
                None => get_ipmi_mac()?,
            };
            let generated_mac = generate_mac_address(
                &mgmt_mac,
                deployment_settings.deployment.name.as_str(),
                &NodeType::HostOS,
            )?;
            eprintln!("Using generated mac (unformatted) {}", generated_mac.get());

            generate_network_config(&network_info, generated_mac, Path::new(&output_directory))
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

            let node_type = node_type.parse::<NodeType>()?;
            let mgmt_mac = match deployment_settings.deployment.mgmt_mac {
                Some(config_mac) => {
                    let mgmt_mac = FormattedMacAddress::try_from(config_mac.as_str())?;
                    eprintln!(
                        "Using mgmt_mac address found in deployment.json: {}",
                        mgmt_mac.get()
                    );
                    mgmt_mac
                }
                None => get_ipmi_mac()?,
            };
            let generated_mac = generate_mac_address(
                &mgmt_mac,
                deployment_settings.deployment.name.as_str(),
                &node_type,
            )?;
            let ipv6_address = generate_ipv6_address(&network_info.ipv6_prefix, &mac)?;
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

            let node_type = node_type.parse::<NodeType>()?;
            let mgmt_mac = match deployment_settings.deployment.mgmt_mac {
                Some(config_mac) => {
                    let mgmt_mac = FormattedMacAddress::try_from(config_mac.as_str())?;
                    eprintln!(
                        "Using mgmt_mac address found in deployment.json: {}",
                        mgmt_mac.get()
                    );
                    mgmt_mac
                }
                None => get_ipmi_mac()?,
            };
            let generated_mac = generate_mac_address(
                &mgmt_mac,
                deployment_settings.deployment.name.as_str(),
                &node_type,
            )?;

            let generated_mac = FormattedMacAddress::from(&generated_mac);
            println!("{}", generated_mac.get());
            Ok(())
        }
        None => Err(anyhow!(
            "No subcommand specified. Run with '--help' for subcommands"
        )),
    }
}
