use std::process::Command;

use anyhow::{bail, Context, Result};
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::node_type::NodeType;
use utils::intersperse;

/// Wrapper types for MAC addresses
/// - ensure clients cannot modify or construct incorrectly.
///
/// Hex alpha digits are turned to lower case to match ipmitool presentation
/// Construct with `try_from(&str)`
/// Use `.get()` to get the underlying string
/// Transform between the types with `from(the_other)`
// TODO - Make a canonical type which can convert to either un/formatted on demand
#[derive(Clone, Debug)]
pub struct UnformattedMacAddress(String);
#[derive(Clone, Debug)]
pub struct FormattedMacAddress(String);

impl UnformattedMacAddress {
    pub fn get(&self) -> String {
        self.0.clone()
    }
}

impl FormattedMacAddress {
    pub fn get(&self) -> String {
        self.0.clone()
    }
}

impl TryFrom<&str> for UnformattedMacAddress {
    type Error = anyhow::Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.len() != 12 || s.chars().any(|c| !c.is_ascii_hexdigit()) {
            bail!("Malformed raw mac address: {}", s);
        }

        Ok(UnformattedMacAddress(s.to_string().to_lowercase()))
    }
}

impl TryFrom<&str> for FormattedMacAddress {
    type Error = anyhow::Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.len() != 17 || s.chars().filter(|c| *c == ':').count() != 5 {
            bail!(
                "Invalid BMC MAC. Must be formatted as MAC address with colons: {}",
                s
            );
        }

        Ok(FormattedMacAddress(s.to_string().to_lowercase()))
    }
}

impl From<&UnformattedMacAddress> for FormattedMacAddress {
    /// Return a standard formatted MAC address given a 'raw' unformatted 12 char string
    /// E.g. "aabbccddeeff" -> "aa:bb:cc:dd:ee:ff"
    /// Error if not the correct length or hexadecimal
    fn from(mac: &UnformattedMacAddress) -> Self {
        let result = intersperse(&mac.get(), ':', 2);
        FormattedMacAddress(result)
    }
}

impl From<&FormattedMacAddress> for UnformattedMacAddress {
    fn from(mac: &FormattedMacAddress) -> Self {
        let result: String = mac.0.chars().filter(|c| *c != ':').collect();
        UnformattedMacAddress(result)
    }
}

fn parse_mac_line(line: &str) -> Result<FormattedMacAddress> {
    let error_msg = format!("Could not parse mac address line: {}", line);
    let re = Regex::new(r"MAC Address\s+:\s+(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))")?;
    let captures = re.captures(line).context(error_msg.clone())?;
    let mac = captures.get(1).context(error_msg.clone())?;
    FormattedMacAddress::try_from(mac.as_str())
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
fn generate_mac_address_internal(
    mgmt_mac: &FormattedMacAddress,
    deployment_name: &str,
    node_type: &NodeType,
    version: char,
) -> Result<UnformattedMacAddress> {
    if version != '4' && version != '6' {
        bail!("Invalid version used to generate MAC address: {}", version);
    }

    // Newline added to match behavior
    let seed = format!("{}{}\n", mgmt_mac.get(), deployment_name);
    let vendor_part: String = hex::encode(Sha256::digest(seed)).chars().take(8).collect();
    // When IPv4 and IPv6 were split, a different MAC for each bond was desired.
    // Leave for compatibility until later
    let version_octet = match version {
        '4' => "4a",
        _ => "6a",
    };
    let node_index = node_type.to_char();
    let mac = format!("{}0{}{}", version_octet, node_index, vendor_part);
    UnformattedMacAddress::try_from(mac.as_str())
}

/// Query the BMC MAC address and return deterministically generated MAC
pub fn generate_mac_address(
    deployment_name: &str,
    node_type: &NodeType,
    mgmt_mac: Option<&str>,
) -> Result<UnformattedMacAddress> {
    let mgmt_mac = if let Some(mgmt_mac) = mgmt_mac {
        let mgmt_mac = FormattedMacAddress::try_from(mgmt_mac)?;
        eprintln!(
            "Using mgmt_mac address found in deployment.json: {}",
            mgmt_mac.get()
        );
        Ok(mgmt_mac)
    } else {
        // A bug in our version of ipmitool causes it to exit with an error
        // status, but we have enough output to work with anyway.
        // https://github.com/ipmitool/ipmitool/issues/388

        // let ipmitool_output = get_command_stdout("ipmitool", ["lan", "print"])?;
        let output = Command::new("ipmitool").arg("lan").arg("print").output()?;
        if !output.status.success() {
            eprintln!(
                "Error running ipmitool: {}",
                std::str::from_utf8(&output.stderr)?
            );
        }
        let ipmitool_output = String::from_utf8(output.stdout)?;

        get_mac_address_from_ipmitool_output(&ipmitool_output)
    }?;
    generate_mac_address_internal(&mgmt_mac, deployment_name, node_type, '6')
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
    fn test_generate_mac_address() {
        assert_eq!(
            generate_mac_address_internal(
                &FormattedMacAddress::try_from("de:ad:de:ad:de:ad").unwrap(),
                "mainnet",
                &NodeType::SetupOS,
                '4'
            )
            .unwrap()
            .get(),
            "4a0ff7e0c684"
        );
        assert_eq!(
            generate_mac_address_internal(
                &FormattedMacAddress::try_from("de:ad:de:ad:de:ad").unwrap(),
                "mainnet",
                &NodeType::GuestOS,
                '4'
            )
            .unwrap()
            .get(),
            "4a01f7e0c684"
        );
        assert_eq!(
            generate_mac_address_internal(
                &FormattedMacAddress::try_from("de:ad:de:ad:de:ad").unwrap(),
                "mainnet",
                &NodeType::GuestOS,
                '6'
            )
            .unwrap()
            .get(),
            "6a01f7e0c684"
        );
        assert_eq!(
            generate_mac_address_internal(
                &FormattedMacAddress::try_from("00:aa:bb:cc:dd:ee").unwrap(),
                "mainnet",
                &NodeType::GuestOS,
                '6'
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
