use std::path::Path;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use config::types::{HostOSConfig, Ipv6Config};
use config::{deserialize_config, DEFAULT_HOSTOS_CONFIG_OBJECT_PATH};
use mac_address::mac_address::{generate_mac_address, FormattedMacAddress};
use mac_address::node_type::NodeType;
use network::generate_network_config;
use network::ipv6::generate_ipv6_address;
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
    GenerateIpv6Address {
        #[arg(short, long, default_value = "HostOS")]
        node_type: String,
    },
    GenerateMacAddress {
        #[arg(short, long, default_value = "HostOS")]
        node_type: String,
    },
}

#[derive(Parser)]
struct HostOSArgs {
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
            let hostos_config: HostOSConfig =
                deserialize_config(DEFAULT_HOSTOS_CONFIG_OBJECT_PATH)?;

            eprintln!(
                "Network settings config: {:?}",
                &hostos_config.network_settings
            );

            let generated_mac = generate_mac_address(
                &hostos_config.icos_settings.mgmt_mac,
                &hostos_config.icos_settings.deployment_environment,
                &NodeType::HostOS,
            )?;
            eprintln!("Using generated mac (unformatted) {}", generated_mac);

            generate_network_config(
                &hostos_config.network_settings,
                generated_mac,
                Path::new(&output_directory),
            )
        }
        Some(Commands::GenerateIpv6Address { node_type }) => {
            let hostos_config: HostOSConfig =
                deserialize_config(DEFAULT_HOSTOS_CONFIG_OBJECT_PATH)?;

            eprintln!(
                "Network settings config: {:?}",
                &hostos_config.network_settings
            );

            let node_type = node_type.parse::<NodeType>()?;
            let generated_mac = generate_mac_address(
                &hostos_config.icos_settings.mgmt_mac,
                &hostos_config.icos_settings.deployment_environment,
                &node_type,
            )?;
            eprintln!("Using generated mac (unformatted) {}", generated_mac);

            let ipv6_config = if let Ipv6Config::Deterministic(ipv6_config) =
                &hostos_config.network_settings.ipv6_config
            {
                ipv6_config
            } else {
                return Err(anyhow!(
                    "Ipv6Config is not of type Deterministic. Cannot generate IPv6 address."
                ));
            };

            let ipv6_address = generate_ipv6_address(&ipv6_config.prefix, &generated_mac)?;
            println!("{}", to_cidr(ipv6_address, ipv6_config.prefix_length));

            Ok(())
        }
        Some(Commands::GenerateMacAddress { node_type }) => {
            let hostos_config: HostOSConfig =
                deserialize_config(DEFAULT_HOSTOS_CONFIG_OBJECT_PATH)?;

            eprintln!(
                "Network settings config: {:?}",
                &hostos_config.network_settings
            );

            let node_type = node_type.parse::<NodeType>()?;
            let generated_mac = generate_mac_address(
                &hostos_config.icos_settings.mgmt_mac,
                &hostos_config.icos_settings.deployment_environment,
                &node_type,
            )?;
            eprintln!("Using generated mac (unformatted) {}", generated_mac);

            let generated_mac = FormattedMacAddress::from(&generated_mac);

            println!("{}", generated_mac);
            Ok(())
        }
        None => Err(anyhow!(
            "No subcommand specified. Run with '--help' for subcommands"
        )),
    }
}
