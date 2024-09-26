use std::path::Path;

use anyhow::Result;

use crate::mac_address::generate_mac_address;
use crate::node_type::NodeType;
use crate::systemd::generate_systemd_config_files;
use config::types::NetworkSettings;
use ipv6::generate_ipv6_address;
use mac_address::FormattedMacAddress;

pub mod interfaces;
pub mod ipv6;
pub mod mac_address;
pub mod node_type;
pub mod systemd;

/// Write SetupOS or HostOS systemd network configuration.
/// Requires superuser permissions to run `ipmitool` and write to the systemd directory
pub fn generate_network_config(
    network_settings: &NetworkSettings,
    deployment_name: &str,
    node_type: NodeType,
    output_directory: &Path,
) -> Result<()> {
    let mac = generate_mac_address(
        deployment_name,
        &node_type,
        network_settings.mgmt_mac.as_deref(),
    )?;
    eprintln!("Using generated mac (unformatted) {}", mac.get());

    eprintln!("Generating ipv6 address");
    let ipv6_address = generate_ipv6_address(&network_settings.ipv6_prefix, &mac)?;
    eprintln!("Using ipv6 address: {}", ipv6_address);

    let formatted_mac = FormattedMacAddress::from(&mac);
    generate_systemd_config_files(
        output_directory,
        network_settings,
        Some(&formatted_mac),
        &ipv6_address,
    )
}
