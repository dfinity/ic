use std::path::Path;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};

use config::{DEFAULT_SETUPOS_CONFIG_OBJECT_PATH, deserialize_config};
use config_types::{Ipv6Config, SetupOSConfig};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{IpVariant, MacAddr6Ext, calculate_deterministic_mac};
use network::generate_network_config;
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
        #[arg(short, long, default_value_t = NodeType::SetupOS)]
        node_type: NodeType,
    },
}

#[derive(Parser)]
struct SetupOSArgs {
    #[arg(short, long, default_value_t = DEFAULT_SETUPOS_CONFIG_OBJECT_PATH.to_string(), value_name = "FILE")]
    setupos_config_object_path: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

pub fn main() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("ERROR: this only runs on Linux.");
        std::process::exit(1);
    }
    let opts = SetupOSArgs::parse();

    match opts.command {
        Some(Commands::GenerateNetworkConfig { output_directory }) => {
            let setupos_config: SetupOSConfig =
                deserialize_config(&opts.setupos_config_object_path)?;

            eprintln!(
                "Network settings config: {:?}",
                &setupos_config.network_settings
            );

            let generated_mac = calculate_deterministic_mac(
                &setupos_config.icos_settings.mgmt_mac,
                setupos_config.icos_settings.deployment_environment,
                IpVariant::V6,
                NodeType::SetupOS,
            );
            eprintln!("Using generated mac {generated_mac}");

            generate_network_config(
                &setupos_config.network_settings,
                &generated_mac,
                Path::new(&output_directory),
            )
        }
        Some(Commands::GenerateIpv6Address { node_type }) => {
            let setupos_config: SetupOSConfig =
                deserialize_config(&opts.setupos_config_object_path)?;

            eprintln!(
                "Network settings config: {:?}",
                &setupos_config.network_settings
            );

            let generated_mac = calculate_deterministic_mac(
                &setupos_config.icos_settings.mgmt_mac,
                setupos_config.icos_settings.deployment_environment,
                IpVariant::V6,
                node_type,
            );
            eprintln!("Using generated mac address {generated_mac}");

            let Ipv6Config::Deterministic(ipv6_config) =
                &setupos_config.network_settings.ipv6_config
            else {
                return Err(anyhow!(
                    "Ipv6Config is not of type Deterministic. Cannot generate IPv6 address."
                ));
            };

            let ipv6_address = generated_mac.calculate_slaac(&ipv6_config.prefix)?;
            println!("{}", to_cidr(ipv6_address, ipv6_config.prefix_length));

            Ok(())
        }
        None => Err(anyhow!(
            "No subcommand specified. Run with '--help' for subcommands"
        )),
    }
}
