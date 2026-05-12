use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use ic_registry_keys::make_replica_version_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use tracing::{info, warn};
use url::Url;

use config_tool::{DEFAULT_SETUPOS_CONFIG_OBJECT_PATH, deserialize_config};
use config_types::{Ipv6Config, SetupOSConfig};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{MacAddr6Ext, calculate_deterministic_mac};
use network::generate_network_config;
use network::systemd::DEFAULT_SYSTEMD_NETWORK_DIR;
use utils::to_cidr;

/// Path to the SetupOS version file. Currently the GuestOS version is always
/// the same as the SetupOS version. Therefore, the SetupOS version is used to
/// determine if the GuestOS version is elected.
const VERSION_FILE_PATH: &str = "/opt/ic/share/version.txt";

#[derive(Subcommand)]
pub enum Commands {
    /// Generate systemd network configuration files. Bridges available NIC's for IC IPv6 connectivity.
    GenerateNetworkConfig {
        #[arg(short, long, default_value = DEFAULT_SYSTEMD_NETWORK_DIR, value_name = "DIR")]
        /// systemd-networkd output directory
        output_directory: PathBuf,
    },
    GenerateIpv6Address {
        #[arg(short, long, default_value_t = NodeType::SetupOS)]
        node_type: NodeType,
    },
    /// Check if the current SetupOS(=GuestOS) version is elected in the NNS registry.
    CheckElectedVersion {
        #[arg(short, long, default_value = VERSION_FILE_PATH, value_name = "FILE")]
        /// Path to the version file
        version_file: PathBuf,
    },
}

#[derive(Parser)]
struct SetupOSArgs {
    #[arg(short, long, default_value = DEFAULT_SETUPOS_CONFIG_OBJECT_PATH, value_name = "FILE")]
    setupos_config_object_path: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

pub fn main() -> Result<()> {
    ic_os_logging::init_logging();

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

            warn!(
                "Network settings config: {:?}",
                &setupos_config.network_settings
            );

            let generated_mac = calculate_deterministic_mac(
                &setupos_config.icos_settings.mgmt_mac,
                setupos_config.icos_settings.deployment_environment,
                NodeType::SetupOS,
            );
            warn!("Using generated mac {generated_mac}");

            generate_network_config(
                &setupos_config.network_settings,
                &generated_mac,
                &output_directory,
            )
        }
        Some(Commands::GenerateIpv6Address { node_type }) => {
            let setupos_config: SetupOSConfig =
                deserialize_config(&opts.setupos_config_object_path)?;

            warn!(
                "Network settings config: {:?}",
                &setupos_config.network_settings
            );

            let generated_mac = calculate_deterministic_mac(
                &setupos_config.icos_settings.mgmt_mac,
                setupos_config.icos_settings.deployment_environment,
                node_type,
            );
            warn!("Using generated mac address {generated_mac}");

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
        Some(Commands::CheckElectedVersion { version_file }) => {
            let setupos_config: SetupOSConfig =
                deserialize_config(&opts.setupos_config_object_path)?;

            check_elected_version(&setupos_config, version_file.as_path())
        }
        None => Err(anyhow!(
            "No subcommand specified. Run with '--help' for subcommands"
        )),
    }
}

/// Checks if the current SetupOS(=GuestOS) version is in the NNS registry.
fn check_elected_version(config: &SetupOSConfig, version_file: &Path) -> Result<()> {
    let current_version = fs::read_to_string(version_file)
        .map_err(|e| {
            anyhow!(
                "Failed to read version file '{}': {}",
                version_file.display(),
                e
            )
        })?
        .trim()
        .to_string();

    info!("Checking if version '{}' is elected...", current_version);

    let nns_urls: Vec<Url> = config.icos_settings.nns_urls.clone();
    if nns_urls.is_empty() {
        return Err(anyhow!("No NNS URLs configured"));
    }

    info!("Using NNS URLs: {:?}", nns_urls);

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| anyhow!("Failed to create tokio runtime: {}", e))?;

    runtime.block_on(async {
        let registry_canister = RegistryCanister::new(nns_urls);
        let response = registry_canister
            .get_value(
                make_replica_version_key(&current_version)
                    .as_bytes()
                    .to_vec(),
                None,
            )
            .await;

        match response {
            Ok(_) => {
                eprintln!("Version '{current_version}' is elected.");
            }
            Err(ic_registry_transport::Error::KeyNotPresent(_)) => {
                return Err(anyhow!("Version '{current_version}' is not elected."));
            }
            error => {
                error?;
            }
        }

        Ok(())
    })
}
