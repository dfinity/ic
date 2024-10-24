use std::path::Path;

use anyhow::{anyhow, Result};

use crate::systemd::generate_systemd_config_files;
use config::types::{Ipv6Config, NetworkSettings};
use ipv6::generate_ipv6_address;
use mac_address::mac_address::{FormattedMacAddress, UnformattedMacAddress};

pub mod interfaces;
pub mod ipv6;
pub mod systemd;

/// Write SetupOS or HostOS systemd network configuration.
/// Requires superuser permissions to run `ipmitool` and write to the systemd directory
pub fn generate_network_config(
    network_settings: &NetworkSettings,
    generated_mac: UnformattedMacAddress,
    output_directory: &Path,
) -> Result<()> {
    eprintln!("Generating ipv6 address");

    match &network_settings.ipv6_config {
        Ipv6Config::RouterAdvertisement => {
            Err(anyhow!("IC-OS router advertisement is not yet supported"))
        }
        Ipv6Config::Fixed(_) => Err(anyhow!("Fixed IP configuration is not yet supported")),
        Ipv6Config::Deterministic(ipv6_config) => {
            let ipv6_address = generate_ipv6_address(&ipv6_config.prefix, &generated_mac)?;
            eprintln!("Using ipv6 address: {}", ipv6_address);

            let formatted_mac = FormattedMacAddress::from(&generated_mac);
            generate_systemd_config_files(
                output_directory,
                ipv6_config,
                Some(&formatted_mac),
                &ipv6_address,
            )
        }
    }
}
