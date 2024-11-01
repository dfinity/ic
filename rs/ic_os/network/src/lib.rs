use std::path::Path;

use anyhow::Result;

use crate::systemd::generate_systemd_config_files;
use info::NetworkInfo;
use ipv6::generate_ipv6_address;
use mac_address::mac_address::{FormattedMacAddress, UnformattedMacAddress};

pub mod info;
pub mod interfaces;
pub mod ipv6;
pub mod systemd;

/// Write SetupOS or HostOS systemd network configuration.
/// Requires superuser permissions to run `ipmitool` and write to the systemd directory
pub fn generate_network_config(
    network_info: &NetworkInfo,
    generated_mac: UnformattedMacAddress,
    output_directory: &Path,
) -> Result<()> {
    eprintln!("Generating ipv6 address");
    let ipv6_address = generate_ipv6_address(&network_info.ipv6_prefix, &generated_mac)?;
    eprintln!("Using ipv6 address: {}", ipv6_address);

    let formatted_mac = FormattedMacAddress::from(&generated_mac);
    generate_systemd_config_files(
        output_directory,
        network_info,
        Some(&formatted_mac),
        &ipv6_address,
    )
}
