use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use config_tool::{DEFAULT_HOSTOS_CONFIG_OBJECT_PATH, deserialize_config};
use config_types::{HostOSConfig, Ipv6Config};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{IpVariant, MacAddr6Ext, calculate_deterministic_mac};
use manual_guestos_recovery::GuestOSRecoveryApp;
use network::generate_network_config;
use network::systemd::DEFAULT_SYSTEMD_NETWORK_DIR;
use std::path::Path;
use utils::to_cidr;

mod node_gen;
use node_gen::get_node_gen_metric;

mod prometheus_metric;
use prometheus_metric::write_single_metric;

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
    /// Launch the Recovery TUI tool for manual node recovery
    ManualRecovery,
}

#[derive(Parser)]
struct HostOSArgs {
    #[arg(long, default_value_t = DEFAULT_HOSTOS_CONFIG_OBJECT_PATH.to_string(), value_name = "FILE")]
    hostos_config_object_path: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

pub fn main() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("ERROR: this only runs on Linux.");
        std::process::exit(1)
    }

    let opts = HostOSArgs::parse();

    match opts.command {
        Some(Commands::SetHardwareGenMetric { output_path }) => {
            write_single_metric(&get_node_gen_metric(), Path::new(&output_path))
        }
        Some(Commands::GenerateNetworkConfig { output_directory }) => {
            let hostos_config: HostOSConfig = deserialize_config(&opts.hostos_config_object_path)?;

            eprintln!(
                "Network settings config: {:?}",
                &hostos_config.network_settings
            );

            let generated_mac = calculate_deterministic_mac(
                &hostos_config.icos_settings.mgmt_mac,
                hostos_config.icos_settings.deployment_environment,
                IpVariant::V6,
                NodeType::HostOS,
            );

            generate_network_config(
                &hostos_config.network_settings,
                &generated_mac,
                Path::new(&output_directory),
            )
        }
        Some(Commands::GenerateIpv6Address { node_type }) => {
            let hostos_config: HostOSConfig = deserialize_config(&opts.hostos_config_object_path)?;

            eprintln!(
                "Network settings config: {:?}",
                &hostos_config.network_settings
            );

            let generated_mac = calculate_deterministic_mac(
                &hostos_config.icos_settings.mgmt_mac,
                hostos_config.icos_settings.deployment_environment,
                IpVariant::V6,
                node_type,
            );

            eprintln!("Using generated mac address {generated_mac}");

            let Ipv6Config::Deterministic(ipv6_config) =
                &hostos_config.network_settings.ipv6_config
            else {
                return Err(anyhow!(
                    "Ipv6Config is not of type Deterministic. Cannot generate IPv6 address."
                ));
            };

            let ipv6_address = generated_mac.calculate_slaac(&ipv6_config.prefix)?;
            println!("{}", to_cidr(ipv6_address, ipv6_config.prefix_length));

            Ok(())
        }
        Some(Commands::GenerateMacAddress { node_type }) => {
            let hostos_config: HostOSConfig = deserialize_config(&opts.hostos_config_object_path)?;

            eprintln!(
                "Network settings config: {:?}",
                &hostos_config.network_settings
            );

            let generated_mac = calculate_deterministic_mac(
                &hostos_config.icos_settings.mgmt_mac,
                hostos_config.icos_settings.deployment_environment,
                IpVariant::V6,
                node_type,
            );
            println!("{generated_mac}");
            Ok(())
        }
        Some(Commands::ManualRecovery) => {
            let mut app = GuestOSRecoveryApp::new();
            app.run()?;
            Ok(())
        }
        None => Err(anyhow!(
            "No subcommand specified. Run with '--help' for subcommands"
        )),
    }
}
