use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_registry_keys::make_blessed_replica_versions_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use prost::Message;
use url::Url;

use config_tool::{DEFAULT_SETUPOS_CONFIG_OBJECT_PATH, deserialize_config};
use config_types::{Ipv6Config, SetupOSConfig};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{IpVariant, MacAddr6Ext, calculate_deterministic_mac};
use network::generate_network_config;
use network::systemd::DEFAULT_SYSTEMD_NETWORK_DIR;
use utils::to_cidr;

/// Path to the SetupOS version file. Currently the GuestOS version is always
/// the same as the SetupOS version. Therefore, the SetupOS version is used to
/// determine if the GuestOS version is blessed.
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
    /// Check if the current SetupOS(=GuestOS) version is blessed in the NNS registry.
    CheckBlessedVersion {
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
                &output_directory,
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
        Some(Commands::CheckBlessedVersion { version_file }) => {
            let setupos_config: SetupOSConfig =
                deserialize_config(&opts.setupos_config_object_path)?;

            check_blessed_version(&setupos_config, version_file.as_path())
        }
        None => Err(anyhow!(
            "No subcommand specified. Run with '--help' for subcommands"
        )),
    }
}

/// Checks if the current SetupOS(=GuestOS) version is blessed in the NNS registry.
fn check_blessed_version(config: &SetupOSConfig, version_file: &Path) -> Result<()> {
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

    eprintln!("Checking if version '{}' is blessed...", current_version);

    let nns_urls: Vec<Url> = config.icos_settings.nns_urls.clone();
    if nns_urls.is_empty() {
        return Err(anyhow!("No NNS URLs configured"));
    }

    eprintln!("Using NNS URLs: {:?}", nns_urls);

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| anyhow!("Failed to create tokio runtime: {}", e))?;

    let blessed_versions = runtime.block_on(async {
        let registry_canister = RegistryCanister::new(nns_urls);
        let result = registry_canister
            .get_value(
                make_blessed_replica_versions_key().as_bytes().to_vec(),
                None,
            )
            .await
            .map_err(|e| anyhow!("Failed to query registry: {:?}", e))?;

        BlessedReplicaVersions::decode(&*result.0)
            .map_err(|e| anyhow!("Failed to decode blessed versions: {}", e))
    })?;

    let is_blessed = blessed_versions
        .blessed_version_ids
        .iter()
        .any(|v| v == &current_version);

    if is_blessed {
        eprintln!("Version '{}' is blessed.", current_version);
        Ok(())
    } else {
        Err(anyhow!(
            "Version '{}' is not blessed. Blessed versions: {:?}",
            current_version,
            blessed_versions.blessed_version_ids
        ))
    }
}
