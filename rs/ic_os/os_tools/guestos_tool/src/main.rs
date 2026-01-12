use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

mod generate_network_config;
use generate_network_config::{generate_networkd_config, validate_and_construct_ipv4_address_info};

use config_tool::deserialize_config;
use config_types::GuestOSConfig;
use network::systemd::{DEFAULT_SYSTEMD_NETWORK_DIR, restart_systemd_networkd};

#[derive(Subcommand)]
pub enum Commands {
    /// Generate systemd network configuration files.
    GenerateNetworkConfig {
        #[arg(long, default_value_t = DEFAULT_SYSTEMD_NETWORK_DIR.to_string(), value_name = "DIR")]
        /// systemd-networkd output directory
        systemd_network_dir: String,

        #[arg(long, default_value = config_tool::DEFAULT_GUESTOS_CONFIG_OBJECT_PATH, value_name = "FILE")]
        /// config.json input file
        config_object: PathBuf,
    },
    /// Regenerate systemd network configuration files, optionally incorporating specified IPv4 configuration parameters, and then restart the systemd network.
    RegenerateNetworkConfig {
        #[arg(long, default_value_t = DEFAULT_SYSTEMD_NETWORK_DIR.to_string(), value_name = "DIR")]
        /// systemd-networkd output directory
        systemd_network_dir: String,

        #[arg(long, default_value = config_tool::DEFAULT_GUESTOS_CONFIG_OBJECT_PATH, value_name = "FILE")]
        /// config.json input file
        config_object: PathBuf,

        #[arg(long, value_name = "IPV4_ADDRESS")]
        /// IPv4 address
        ipv4_address: Option<String>,

        #[arg(long, value_name = "IPV4_PREFIX_LENGTH")]
        /// IPv4 prefix length
        ipv4_prefix_length: Option<String>,

        #[arg(long, value_name = "IPV4_GATEWAY")]
        /// IPv4 gateway
        ipv4_gateway: Option<String>,
    },
}

#[derive(Parser)]
#[command()]
struct GuestOSArgs {
    #[command(subcommand)]
    command: Option<Commands>,
}

pub fn main() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("ERROR: this only runs on Linux.");
        std::process::exit(1);
    }
    let opts = GuestOSArgs::parse();

    match opts.command {
        Some(Commands::GenerateNetworkConfig {
            systemd_network_dir,
            config_object,
        }) => {
            let guestos_config: GuestOSConfig = deserialize_config(config_object)?;
            generate_networkd_config(
                guestos_config.network_settings.ipv6_config,
                Path::new(&systemd_network_dir),
                None,
            )
        }

        Some(Commands::RegenerateNetworkConfig {
            systemd_network_dir,
            config_object,
            ipv4_address,
            ipv4_prefix_length,
            ipv4_gateway,
        }) => {
            let ipv4_info = validate_and_construct_ipv4_address_info(
                ipv4_address.as_deref(),
                ipv4_prefix_length.as_deref(),
                ipv4_gateway.as_deref(),
            )?;

            let guestos_config: GuestOSConfig = deserialize_config(config_object)?;
            generate_networkd_config(
                guestos_config.network_settings.ipv6_config,
                Path::new(&systemd_network_dir),
                ipv4_info,
            )?;

            eprintln!("Restarting systemd networkd");
            restart_systemd_networkd();

            Ok(())
        }
        None => Ok(()),
    }
}
