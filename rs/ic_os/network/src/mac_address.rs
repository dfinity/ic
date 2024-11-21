use std::process::Command;

use anyhow::{Context, Result};
use hex;
use rand;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::node_type::NodeType;
use systemd::{detect_virt, VirtualizationType};

use config::types::{FormattedMacAddress, UnformattedMacAddress};

fn parse_mac_line(line: &str) -> Result<FormattedMacAddress> {
    let error_msg = format!("Could not parse mac address line: {}", line);
    let re = Regex::new(r"MAC Address\s+:\s+(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))")?;
    let captures = re.captures(line).context(error_msg.clone())?;
    let mac = captures.get(1).context(error_msg.clone())?;
    FormattedMacAddress::try_from(mac.as_str()).context(error_msg.clone())
}

pub fn get_mac_address_from_ipmitool_output(output: &str) -> Result<FormattedMacAddress> {
    let mac_line = output
        .lines()
        .find(|line| line.trim().starts_with("MAC Address"))
        .context(format!(
            "Could not find mac address line in ipmitool output: {}",
            output
        ))?;
    parse_mac_line(mac_line)
}

/// Generate a deterministic unformatted MAC address
/// E.g. "6a01eb49a2b0"
pub fn derive_mac_address_for_hostos(
    mgmt_mac: &FormattedMacAddress,
    deployment_environment: &str,
    node_type: &NodeType,
) -> Result<UnformattedMacAddress> {
    // Newline added to match behavior
    let seed = format!("{}{}\n", mgmt_mac.get(), deployment_environment);
    let vendor_part: String = hex::encode(Sha256::digest(seed)).chars().take(8).collect();
    let node_index = node_type.to_char();
    let mac = format!("6a0{}{}", node_index, vendor_part);
    UnformattedMacAddress::try_from(mac.as_str()).context("Could not format MAC address")
}

/// Retrieves the MAC address from the IPMI LAN interface
fn get_ipmi_mac() -> Result<FormattedMacAddress> {
    let output = Command::new("ipmitool").arg("lan").arg("print").output()?;
    let ipmitool_output = String::from_utf8(output.stdout)?;

    get_mac_address_from_ipmitool_output(&ipmitool_output).with_context(|| {
        // A bug in our version of ipmitool causes it to exit with an error
        // status, but we have enough output to work with anyway. If
        // get_mac_address_from_ipmitool_output still fails, log the invocation details.
        // https://github.com/ipmitool/ipmitool/issues/388
        let stderr = std::str::from_utf8(&output.stderr).unwrap_or("[INVALID UTF8]");
        format!(
            "ipmitool status: {}, ipmitool stdout: {}\nipmitool stderr: {}",
            output.status, ipmitool_output, stderr
        )
    })
}

/// Derive the management MAC address for a machine.
///
/// Uses the supplied MAC address if Some(), else retrieves the MAC
/// address from IPMI if available, else falls back to a randomized
/// set of six bytes, the first two (rendered as hex) being "badd"
/// and signifying likely offline operation.
pub fn derive_mgmt_mac(maybe_mac: Option<String>) -> Result<FormattedMacAddress> {
    match maybe_mac {
        Some(mac) => {
            FormattedMacAddress::try_from(mac.as_str()).context("Could not format MAC address")
        }
        None => match detect_virt()? {
            VirtualizationType::BareMetal => get_ipmi_mac(),
            VirtualizationType::Virtualized => FormattedMacAddress::try_from(
                format!(
                    "ba:dd:{:0x}:{:0x}:{:0x}:{:0x}",
                    rand::random::<u8>(),
                    rand::random::<u8>(),
                    rand::random::<u8>(),
                    rand::random::<u8>()
                )
                .as_str(),
            )
            .context("Could not format MAC address"),
        },
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn test_mac() {
        assert_eq!(
            FormattedMacAddress::try_from("DE:AD:BE:EF:FF:00")
                .unwrap()
                .get(),
            "de:ad:be:ef:ff:00"
        );
        assert!(FormattedMacAddress::try_from("123456789ABCDEF").is_err()); // Too many chars
        assert!(FormattedMacAddress::try_from("ZOOMBAWRONG1").is_err()); // Non-hex chars
        assert!(FormattedMacAddress::try_from("Fast times").is_err()); // Nonsense
        assert!(FormattedMacAddress::try_from("").is_err()); // Too few chars
        assert!(UnformattedMacAddress::try_from("").is_err()); // Too few chars

        let raw_mac = UnformattedMacAddress::try_from("ABCDEF123456");
        assert!(raw_mac.is_ok());
        assert_eq!(
            FormattedMacAddress::from(&raw_mac.unwrap()).get(),
            "ab:cd:ef:12:34:56"
        );
        let mac = FormattedMacAddress::try_from("AA:BB:CC:DD:EE:FF");
        assert!(mac.is_ok());
        assert_eq!(
            UnformattedMacAddress::from(&mac.unwrap()).get(),
            "aabbccddeeff"
        );
    }

    #[test]
    fn test_derive_mac_address_for_hostos() {
        assert_eq!(
            derive_mac_address_for_hostos(
                &FormattedMacAddress::try_from("de:ad:de:ad:de:ad").unwrap(),
                "mainnet",
                &NodeType::GuestOS,
            )
            .unwrap()
            .get(),
            "6a01f7e0c684"
        );
        assert_eq!(
            derive_mac_address_for_hostos(
                &FormattedMacAddress::try_from("00:aa:bb:cc:dd:ee").unwrap(),
                "mainnet",
                &NodeType::GuestOS,
            )
            .unwrap()
            .get(),
            "6a01d9ab57f2"
        );
    }

    #[test]
    fn test_get_mac_address_from_ipmitool_output() {
        assert_eq!(
            get_mac_address_from_ipmitool_output(" MAC Address             : de:ad:be:ef:be:ef  ")
                .unwrap()
                .get(),
            FormattedMacAddress::try_from("de:ad:be:ef:be:ef")
                .unwrap()
                .get()
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
            get_mac_address_from_ipmitool_output(ipmitool_output)
                .unwrap()
                .get(),
            FormattedMacAddress::try_from("3c:ec:ef:2f:7a:79")
                .unwrap()
                .get()
        );

        assert!(get_mac_address_from_ipmitool_output("MAC Address : UNKNOWN").is_err());
    }
}
