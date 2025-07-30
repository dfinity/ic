use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod node_gen;
use node_gen::get_node_gen_metric;

mod prometheus_metric;
use prometheus_metric::write_single_metric;

mod generate_network_config;
mod setup_disk_encryption;

use generate_network_config::{generate_networkd_config, validate_and_construct_ipv4_address_info};

use config::hostos::guestos_config;
use config::{deserialize_config, DEFAULT_GUESTOS_CONFIG_OBJECT_PATH};
use config_types::GuestOSConfig;
use network::systemd::{restart_systemd_networkd, DEFAULT_SYSTEMD_NETWORK_DIR};

#[derive(Subcommand)]
pub enum Commands {
    /// Generate systemd network configuration files.
    GenerateNetworkConfig {
        #[arg(long, default_value_t = DEFAULT_SYSTEMD_NETWORK_DIR.to_string(), value_name = "DIR")]
        /// systemd-networkd output directory
        systemd_network_dir: String,

        #[arg(long, default_value = config::DEFAULT_GUESTOS_CONFIG_OBJECT_PATH, value_name = "FILE")]
        /// config.json input file
        config_object: PathBuf,
    },
    /// Regenerate systemd network configuration files, optionally incorporating specified IPv4 configuration parameters, and then restart the systemd network.
    RegenerateNetworkConfig {
        #[arg(long, default_value_t = DEFAULT_SYSTEMD_NETWORK_DIR.to_string(), value_name = "DIR")]
        /// systemd-networkd output directory
        systemd_network_dir: String,

        #[arg(long, default_value = config::DEFAULT_GUESTOS_CONFIG_OBJECT_PATH, value_name = "FILE")]
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
    SetHardwareGenMetric {
        #[arg(
            short = 'o',
            long = "output",
            default_value = "/run/node_exporter/collector_textfile/node_gen.prom"
        )]
        /// Filename to write the prometheus metric for node generation.
        /// Fails if directory doesn't exist.
        output_path: String,
    },
    // GetDiskEncryptionKey {
    //     #[arg(value_enum, long)]
    //     /// The partition to get encryption key for
    //     partition: guest::disk_encryption::Partition,
    // },
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
        Some(Commands::SetHardwareGenMetric { output_path }) => {
            write_single_metric(&get_node_gen_metric(), Path::new(&output_path))
        }
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
        // Some(Commands::GetDiskEncryptionKey { partition }) => {
        //     let guestos_config: GuestOSConfig =
        //         deserialize_config(DEFAULT_GUESTOS_CONFIG_OBJECT_PATH)?;
        //
        //     let enable_tee = guestos_config
        //         .icos_settings
        //         .enable_trusted_execution_environment;
        //
        //     let key = if enable_tee {
        //         let mut provider = SevKeyDeriver::new()?;
        //         provider
        //             .derive_key(partition)
        //             .context("Could not get disk encryption key")?
        //             .into_bytes()
        //     } else {
        //         std::fs::read("/boot/config/store.keyfile")
        //             .context("Could not read /boot/config/store.keyfile")?
        //     };
        //
        //     std::io::stdout().write(&key)?;
        //     std::io::stdout().flush()?;
        //     Ok(())
        // }
        None => Ok(()),
    }
}
