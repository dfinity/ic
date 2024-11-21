use std::path::Path;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod node_gen;
use node_gen::get_node_gen_metric;

mod prometheus_metric;
use prometheus_metric::write_single_metric;

use config::firewall_json;
use config::types::firewall;

mod generate_network_config;
use generate_network_config::{
    generate_networkd_config, validate_and_construct_ipv4_address_info,
    DEFAULT_GUESTOS_FIREWALL_JSON_PATH, DEFAULT_GUESTOS_NETWORK_CONFIG_PATH,
};

use network::systemd::{restart_systemd_networkd, DEFAULT_SYSTEMD_NETWORK_DIR};

#[derive(Subcommand)]
pub enum Commands {
    /// Generate systemd network configuration files.
    GenerateNetworkConfig {
        #[arg(long, default_value_t = DEFAULT_SYSTEMD_NETWORK_DIR.to_string(), value_name = "DIR")]
        /// systemd-networkd output directory
        systemd_network_dir: String,

        #[arg(long, default_value_t = DEFAULT_GUESTOS_NETWORK_CONFIG_PATH.to_string(), value_name = "FILE")]
        /// network.conf input file
        network_config: String,
    },
    /// Regenerate systemd network configuration files, optionally incorporating specified IPv4 configuration parameters, and then restart the systemd network.
    RegenerateNetworkConfig {
        #[arg(long, default_value_t = DEFAULT_SYSTEMD_NETWORK_DIR.to_string(), value_name = "DIR")]
        /// systemd-networkd output directory
        systemd_network_dir: String,

        #[arg(long, default_value_t = DEFAULT_GUESTOS_NETWORK_CONFIG_PATH.to_string(), value_name = "FILE")]
        /// network.conf input file
        network_config: String,

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
    RenderFirewallConfig {
        #[arg(index = 1)]
        /// Path to firewall.json.  Defaults to DEFAULT_GUESTOS_FIREWALL_JSON_PATH if unspecified.
        /// If the option is not specified, and the default file does not exist, it renders an
        /// empty firewall ruleset.  If the option is specified, and the file does not exist,
        /// it will raise an error.  If the file exists but the rules cannot be read, it will
        /// raise an error.
        firewall_file: Option<String>,
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
        Some(Commands::SetHardwareGenMetric { output_path }) => {
            write_single_metric(&get_node_gen_metric(), Path::new(&output_path))
        }
        Some(Commands::GenerateNetworkConfig {
            systemd_network_dir,
            network_config,
        }) => generate_networkd_config(
            Path::new(&network_config),
            Path::new(&systemd_network_dir),
            None,
        ),
        Some(Commands::RegenerateNetworkConfig {
            systemd_network_dir,
            network_config,
            ipv4_address,
            ipv4_prefix_length,
            ipv4_gateway,
        }) => {
            let ipv4_info = validate_and_construct_ipv4_address_info(
                ipv4_address.as_deref(),
                ipv4_prefix_length.as_deref(),
                ipv4_gateway.as_deref(),
            )?;

            generate_networkd_config(
                Path::new(&network_config),
                Path::new(&systemd_network_dir),
                ipv4_info,
            )?;

            eprintln!("Restarting systemd networkd");
            restart_systemd_networkd();

            Ok(())
        }
        Some(Commands::RenderFirewallConfig { firewall_file }) => {
            let config = firewall_json::get_firewall_rules_json_or_default(
                firewall_file.as_ref().map(Path::new),
                Path::new(DEFAULT_GUESTOS_FIREWALL_JSON_PATH),
            )?;
            eprintln!(
                "Firewall config ({}): {:#?}",
                match firewall_file {
                    Some(f) => format!("from explicitly specified {}", f),
                    None => format!("from default {}", DEFAULT_GUESTOS_FIREWALL_JSON_PATH),
                },
                config
            );
            println!(
                "{}",
                match config {
                    Some(c) => c.as_nftables(&firewall::FirewallRuleDestination::GuestOS),
                    None => "".to_string(),
                },
            );
            Ok(())
        }
        None => Ok(()),
    }
}
