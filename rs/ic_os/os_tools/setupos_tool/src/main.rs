use std::path::Path;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use config::{deserialize_config, DEFAULT_SETUPOS_CONFIG_OBJECT_PATH};
use config_types::{Ipv6Config, SetupOSConfig};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{calculate_deterministic_mac, IpVariant, MacAddr6Ext};
use network::info::NetworkInfo;
use network::resolve_mgmt_mac;
use utils::to_cidr;

#[derive(Subcommand)]
pub enum Commands {
    GenerateIpv6Address {
        #[arg(short, long, default_value_t = NodeType::SetupOS)]
        node_type: NodeType,
    },
    GenerateMacAddress {
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
            let ipv6_address = generated_mac.calculate_slaac(&network_info.ipv6_prefix)?;
            println!("{}", to_cidr(ipv6_address, network_info.ipv6_subnet));
            Ok(())
        }
        Some(Commands::GenerateMacAddress { node_type }) => {
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
            println!("{}", generated_mac);
            Ok(())
        }
        None => Err(anyhow!(
            "No subcommand specified. Run with '--help' for subcommands"
        )),
    }
}
