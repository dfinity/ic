use crate::node_type::NodeType;
use anyhow::{anyhow, Context, Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::Ipv6Addr;
use std::process::Command;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub fn new(octets: [u8; 6]) -> Self {
        MacAddress(octets)
    }

    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// Generates the SLAAC IPv6 address for the given prefix.
    pub fn calculate_slaac(&self, prefix: &str) -> Result<Ipv6Addr> {
        let mut octets = self.octets().to_vec();

        octets.insert(3, 0xff);
        octets.insert(4, 0xfe);

        octets[0] ^= 0x02;

        let interface_id = format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6], octets[7]
        );

        let address_str = format!("{}:{}", prefix.trim_end_matches(':'), interface_id);
        address_str
            .parse()
            .map_err(|_| anyhow!("Invalid IPv6 address: {}", address_str))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let octets = self.octets();
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
        )
    }
}

#[derive(Debug)]
pub enum MacAddressParseError {
    InvalidFormat,
    InvalidLength,
}

impl FromStr for MacAddress {
    type Err = MacAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_ascii_lowercase();
        let s_no_colons: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if s_no_colons.len() != 12 {
            return Err(MacAddressParseError::InvalidLength);
        }
        let bytes = (0..12)
            .step_by(2)
            .map(|i| u8::from_str_radix(&s_no_colons[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| MacAddressParseError::InvalidFormat)?;

        let octets: [u8; 6] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| MacAddressParseError::InvalidLength)?;
        Ok(MacAddress(octets))
    }
}

impl std::error::Error for MacAddressParseError {}

impl fmt::Display for MacAddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacAddressParseError::InvalidFormat => write!(f, "Invalid MAC address format"),
            MacAddressParseError::InvalidLength => write!(f, "Invalid MAC address length"),
        }
    }
}

/// Deployment environment.
#[derive(Debug, Clone, Copy)]
pub enum Deployment {
    Mainnet,
    Testnet,
}

impl fmt::Display for Deployment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Deployment::Mainnet => write!(f, "mainnet"),
            Deployment::Testnet => write!(f, "testnet"),
        }
    }
}

impl FromStr for Deployment {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Deployment::Mainnet),
            "testnet" => Ok(Deployment::Testnet),
            _ => Err(anyhow!("Invalid deployment: {}", s)),
        }
    }
}

/// IP version variant.
#[derive(Debug, Clone, Copy)]
pub enum IpVariant {
    V4,
    V6,
}

/// Generate a deterministic unformatted MAC address
/// E.g. "6a01eb49a2b0"
pub fn generate_deterministic_mac_address(
    mgmt_mac: &MacAddress,
    deployment: Deployment,
    node_type: NodeType,
    ip_variant: IpVariant,
) -> MacAddress {
    // NOTE: In order to be backwards compatible with existing scripts, this seed
    // **MUST** have a newline.
    let seed = format!("{}{}\n", mgmt_mac, deployment);

    let hash = Sha256::digest(seed.as_bytes());

    let version = match ip_variant {
        IpVariant::V4 => 0x4a,
        IpVariant::V6 => 0x6a,
    };

    let index = node_type.to_index();

    let octets = [version, index, hash[0], hash[1], hash[2], hash[3]];

    MacAddress::new(octets)
}

pub fn get_mac_address_from_ipmitool_output(output: &str) -> Result<MacAddress> {
    let mac_line = output
        .lines()
        .find(|line| line.trim().starts_with("MAC Address"))
        .ok_or_else(|| {
            anyhow!(
                "Could not find MAC address line in ipmitool output: {}",
                output
            )
        })?;

    let error_msg = format!("Could not parse MAC address line: {}", mac_line);
    let re = Regex::new(r"MAC Address\s+:\s+(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))")?;
    let captures = re
        .captures(mac_line)
        .ok_or_else(|| anyhow!(error_msg.clone()))?;
    let mac = captures.get(1).ok_or_else(|| anyhow!(error_msg.clone()))?;
    let mac_str = mac.as_str();
    let mac_address = MacAddress::from_str(mac_str)
        .map_err(|_| anyhow!("Invalid MAC address format: {}", mac_str))?;
    Ok(mac_address)
}

/// Retrieves the MAC address from the IPMI LAN interface
pub fn get_ipmi_mac() -> Result<MacAddress> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_address_parsing() {
        let mac = MacAddress::from_str("DE:AD:BE:EF:FF:00").unwrap();
        assert_eq!(mac.to_string(), "de:ad:be:ef:ff:00");

        let mac = MacAddress::from_str("deadbeefff00").unwrap();
        assert_eq!(mac.to_string(), "de:ad:be:ef:ff:00");

        assert!(MacAddress::from_str("123456789ABCDEF").is_err()); // Too many chars
        assert!(MacAddress::from_str("ZOOMBAWRONG1").is_err()); // Non-hex chars
        assert!(MacAddress::from_str("Fast times").is_err()); // Nonsense
        assert!(MacAddress::from_str("").is_err()); // Too few chars
    }

    #[test]
    fn test_generate_deterministic_mac_address() {
        let mgmt_mac = MacAddress::from_str("de:ad:de:ad:de:ad").unwrap();
        let mac = generate_deterministic_mac_address(
            &mgmt_mac,
            Deployment::Mainnet,
            NodeType::GuestOS,
            IpVariant::V4,
        );
        assert_eq!(mac.to_string(), "4a:01:f7:e0:c6:84");

        let mac = generate_deterministic_mac_address(
            &mgmt_mac,
            Deployment::Mainnet,
            NodeType::GuestOS,
            IpVariant::V6,
        );
        assert_eq!(mac.to_string(), "6a:01:f7:e0:c6:84");
    }

    #[test]
    fn test_get_mac_address_from_ipmitool_output() {
        let ipmitool_output = " MAC Address             : de:ad:be:ef:be:ef  ";
        let mac = get_mac_address_from_ipmitool_output(ipmitool_output).unwrap();
        assert_eq!(mac.to_string(), "de:ad:be:ef:be:ef");

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
        let mac = get_mac_address_from_ipmitool_output(ipmitool_output).unwrap();
        assert_eq!(mac.to_string(), "3c:ec:ef:2f:7a:79");

        let ipmitool_output = "MAC Address : UNKNOWN";
        assert!(get_mac_address_from_ipmitool_output(ipmitool_output).is_err());
    }

    #[test]
    fn test_calculate_slaac() {
        let mac = MacAddress::from_str("6a:01:e5:96:2d:49").unwrap();
        let prefix = "2a04:9dc0:0:108";
        let expected_ip = "2a04:9dc0:0:108:6801:e5ff:fe96:2d49"
            .parse::<Ipv6Addr>()
            .unwrap();
        let slaac = mac.calculate_slaac(prefix).unwrap();
        assert_eq!(slaac, expected_ip);
    }

    #[test]
    fn test_slaac_generation_with_deterministic_mac() {
        let mgmt_mac = MacAddress::from_str("b0:7b:25:c8:f6:c0").unwrap();
        let prefix = "2602:FFE4:801:17";
        let expected_ip = "2602:ffe4:801:17:6801:ff:feec:bd51"
            .parse::<Ipv6Addr>()
            .unwrap();

        let mac = generate_deterministic_mac_address(
            &mgmt_mac,
            Deployment::Mainnet,
            NodeType::GuestOS,
            IpVariant::V6,
        );
        let slaac = mac.calculate_slaac(prefix).unwrap();
        assert_eq!(slaac, expected_ip);
    }
}
