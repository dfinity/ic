use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, anyhow};
use regex::Regex;

use crate::systemd::generate_systemd_config_files;
use config_types::{Ipv6Config, NetworkSettings};
use deterministic_ips::MacAddr6Ext;
use macaddr::MacAddr6;

pub mod interfaces;
pub mod systemd;

/// Write SetupOS or HostOS systemd network configuration.
/// Requires superuser permissions to run `ipmitool` and write to the systemd directory
pub fn generate_network_config(
    network_settings: &NetworkSettings,
    generated_mac: &MacAddr6,
    output_directory: &Path,
) -> Result<()> {
    eprintln!("Generating IPv6 address");

    match &network_settings.ipv6_config {
        Ipv6Config::Deterministic(ipv6_config) => {
            let ipv6_address = generated_mac.calculate_slaac(&ipv6_config.prefix)?;
            eprintln!("Using IPv6 address: {ipv6_address}");

            generate_systemd_config_files(
                output_directory,
                ipv6_config,
                Some(generated_mac),
                &ipv6_address,
            )
        }
        Ipv6Config::RouterAdvertisement => {
            Err(anyhow!("IC-OS router advertisement is not yet supported"))
        }
        Ipv6Config::Fixed(_) => Err(anyhow!("Fixed IP configuration is not yet supported")),
        Ipv6Config::Unknown => Err(anyhow!("Unknown Ipv6Config variant")),
    }
}

pub fn resolve_mgmt_mac(config_mac: Option<&str>) -> Result<MacAddr6> {
    if let Some(config_mac) = config_mac {
        // Take MAC address override from config
        let mgmt_mac = config_mac.parse()?;
        eprintln!("Using mgmt_mac address found in deployment.json: {mgmt_mac}");

        Ok(mgmt_mac)
    } else {
        // Retrieve the MAC address from the IPMI LAN interface
        let output = Command::new("ipmitool").arg("lan").arg("print").output()?;
        let ipmitool_output = String::from_utf8(output.stdout)?;

        parse_mac_address_from_ipmitool_output(&ipmitool_output).with_context(|| {
            // A bug in our version of ipmitool causes it to exit with an error
            // status, but we have enough output to work with anyway. If
            // parse_mac_address_from_ipmitool_output still fails, log the invocation details.
            // https://github.com/ipmitool/ipmitool/issues/388
            let stderr = std::str::from_utf8(&output.stderr).unwrap_or("[INVALID UTF8]");
            format!(
                "ipmitool status: {}, ipmitool stdout: {}\nipmitool stderr: {}",
                output.status, ipmitool_output, stderr
            )
        })
    }
}

fn parse_mac_address_from_ipmitool_output(output: &str) -> Result<MacAddr6> {
    let mac_line = output
        .lines()
        .find(|line| line.trim().starts_with("MAC Address"))
        .context(format!(
            "Could not find MAC address line in ipmitool output: {output}"
        ))?;

    // Parse MAC line
    let error_msg = format!("Could not parse MAC address line: {mac_line}");
    let re = Regex::new(r"MAC Address\s+:\s+(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))")?;
    let captures = re.captures(mac_line).context(error_msg.clone())?;
    let mac = captures.get(1).context(error_msg.clone())?;

    Ok(mac.as_str().parse()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_address_from_ipmitool_output() {
        assert_eq!(
            parse_mac_address_from_ipmitool_output(
                " MAC Address             : de:ad:be:ef:be:ef  "
            )
            .unwrap(),
            "de:ad:be:ef:be:ef".parse().unwrap()
        );

        let ipmitool_output = "Set in Progress         : Set In Progress
Auth Type Support       : NONE MD2 MD5 PASSWORD
Auth Type Enable        : Callback : MD2 MD5 PASSWORD
                        : User     : MD2 MD5 PASSWORD
                        : Operator : MD2 MD5 PASSWORD
                        : Admin    : MD2 MD5 PASSWORD
                        : OEM      : MD2 MD5 PASSWORD
IP Address Source       : Static Address
IP Address              : 10.12.4.62
Subnet Mask             : 255.255.252.0
MAC Address             : 3c:ec:ef:2f:7a:79
SNMP Community String   : public
IP Header               : TTL=0x00 Flags=0x00 Precedence=0x00 TOS=0x00
BMC ARP Control         : ARP Responses Enabled, Gratuitous ARP Disabled
Default Gateway IP      : 10.12.7.254
Default Gateway MAC     : 00:00:00:00:00:00
Backup Gateway IP       : 0.0.0.0
Backup Gateway MAC      : 00:00:00:00:00:00
802.1q VLAN ID          : Disabled
802.1q VLAN Priority    : 0
RMCP+ Cipher Suites     : 1,2,3,6,7,8,11,12
Cipher Suite Priv Max   : XaaaXXaaaXXaaXX
                        :     X=Cipher Suite Unused
                        :     c=CALLBACK
                        :     u=USER
                        :     o=OPERATOR
                        :     a=ADMIN
                        :     O=OEM
Bad Password Threshold  : 3
Invalid password disable: yes
Attempt Count Reset Int.: 300
User Lockout Interval   : 300";

        assert_eq!(
            parse_mac_address_from_ipmitool_output(ipmitool_output).unwrap(),
            "3c:ec:ef:2f:7a:79".parse().unwrap()
        );

        assert!(parse_mac_address_from_ipmitool_output("MAC Address : UNKNOWN").is_err());
    }
}
