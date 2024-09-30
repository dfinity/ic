use std::path::Path;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use config::types::SetupOSConfig;
use config::{
    deserialize_config, DEFAULT_SETUPOS_CONFIG_INI_FILE_PATH, DEFAULT_SETUPOS_CONFIG_OBJECT_PATH,
    DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH,
};
use network::generate_network_config;
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
    GenerateIpv6Address {
        #[arg(short, long, default_value = "SetupOS")]
        node_type: String,
    },
}

#[derive(Parser)]
struct SetupOSArgs {
    #[arg(short, long, default_value_t = DEFAULT_SETUPOS_CONFIG_INI_FILE_PATH.to_string(), value_name = "FILE")]
    config: String,

    #[arg(short, long, default_value_t = DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH.to_string(), value_name = "FILE")]
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
    let opts = SetupOSArgs::parse();

    match opts.command {
        Some(Commands::GenerateNetworkConfig { output_directory }) => {
            let setup_config: SetupOSConfig =
                deserialize_config(DEFAULT_SETUPOS_CONFIG_OBJECT_PATH)?;

            eprintln!(
                "Network settings config: {:?}",
                &setup_config.network_settings
            );

            let mgmt_mac = match setup_config.network_settings.mgmt_mac.as_ref() {
                Some(config_mac) => {
                    let mgmt_mac = FormattedMacAddress::try_from(config_mac.as_str())?;
                    eprintln!(
                        "Using mgmt_mac address found in deployment.json: {}",
                        mgmt_mac
                    );
                    mgmt_mac
                }
                None => get_ipmi_mac()?,
            };
            let generated_mac = generate_mac_address(
                &mgmt_mac,
                &setup_config.icos_settings.hostname,
                &NodeType::SetupOS,
            )?;
            eprintln!("Using generated mac (unformatted) {}", generated_mac);

            generate_network_config(
                &setup_config.network_settings,
                generated_mac,
                Path::new(&output_directory),
            )
        }
        Some(Commands::GenerateIpv6Address { node_type }) => {
            let setup_config: SetupOSConfig =
                deserialize_config(DEFAULT_SETUPOS_CONFIG_OBJECT_PATH)?;

            eprintln!(
                "Network settings config: {:?}",
                &setup_config.network_settings
            );

            let node_type = node_type.parse::<NodeType>()?;

            let mgmt_mac = match setup_config.network_settings.mgmt_mac {
                Some(config_mac) => {
                    let mgmt_mac = FormattedMacAddress::try_from(config_mac.as_str())?;
                    eprintln!(
                        "Using mgmt_mac address found in deployment.json: {}",
                        mgmt_mac
                    );
                    mgmt_mac
                }
                None => get_ipmi_mac()?,
            };
            let generated_mac =
                generate_mac_address(&mgmt_mac, &setup_config.icos_settings.hostname, &node_type)?;
            eprintln!("Using generated mac (unformatted) {}", generated_mac);

            let ipv6_address =
                generate_ipv6_address(&setup_config.network_settings.ipv6_prefix, &generated_mac)?;
            println!(
                "{}",
                to_cidr(
                    ipv6_address,
                    setup_config.network_settings.ipv6_prefix_length
                )
            );

            Ok(())
        }
        None => Err(anyhow!(
            "No subcommand specified. Run with '--help' for subcommands"
        )),
    }
}
