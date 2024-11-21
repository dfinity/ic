use crate::node_type::NodeType;
use anyhow::{anyhow, Context, Error, Result};
use macaddr::MacAddr6;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::fmt;
use std::net::Ipv6Addr;
use std::process::Command;
use std::str::FromStr;

#[derive(Debug)]
pub enum MacAddressParseError {
    InvalidFormat,
    InvalidLength,
}

impl fmt::Display for MacAddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacAddressParseError::InvalidFormat => write!(f, "Invalid MAC address format"),
            MacAddressParseError::InvalidLength => write!(f, "Invalid MAC address length"),
        }
    }
}

impl std::error::Error for MacAddressParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacAddress(MacAddr6);

impl MacAddress {
    pub fn new(octets: [u8; 6]) -> Self {
        MacAddress(MacAddr6::new(
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        ))
    }

    pub fn octets(&self) -> [u8; 6] {
        self.0
            .as_bytes()
            .try_into()
            .expect("MAC address should always be 6 bytes")
    }

    /// Returns the unformatted MAC address string (without colons)
    pub fn to_unformatted_string(&self) -> String {
        self.0.to_string().replace(":", "")
    }

    /// Returns the MAC address in lowercase hexadecimal with colons
    pub fn to_canonical(&self) -> String {
        self.to_string().to_lowercase()
    }

    /// Generates the SLAAC IPv6 address for the given prefix.
    pub fn calculate_slaac(&self, prefix: &str) -> Result<Ipv6Addr> {
        let octets = self.octets();

        let mut eui64 = [0u8; 8];

        eui64[0] = octets[0] ^ 0x02; // invert the Universal/Local bit
        eui64[1] = octets[1];
        eui64[2] = octets[2];
        eui64[3] = 0xff;
        eui64[4] = 0xfe;
        eui64[5] = octets[3];
        eui64[6] = octets[4];
        eui64[7] = octets[5];

        let interface_id = format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            eui64[0], eui64[1], eui64[2], eui64[3], eui64[4], eui64[5], eui64[6], eui64[7]
        );

        let address_str = format!("{}:{}", prefix.trim_end_matches(':'), interface_id);

        address_str
            .parse()
            .map_err(|_| anyhow!("Invalid IPv6 address: {}", address_str))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // macaddr's Display implementation uses lowercase and colons
        write!(f, "{}", self.0)
    }
}

impl FromStr for MacAddress {
    type Err = MacAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        let mac = s
            .parse::<MacAddr6>()
            .map_err(|_| MacAddressParseError::InvalidFormat)?;

        Ok(MacAddress(mac))
    }
}

impl Serialize for MacAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MacAddress {
    fn deserialize<D>(deserializer: D) -> Result<MacAddress, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        MacAddress::from_str(&s).map_err(serde::de::Error::custom)
    }
}

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

#[derive(Debug, Clone, Copy)]
pub enum IpVariant {
    V4,
    V6,
}

/// Generates a deterministic MAC address.
/// E.g., "6a:01:eb:49:a2:b0"
pub fn generate_deterministic_mac_address(
    mgmt_mac: &MacAddress,
    deployment: Deployment,
    node_type: NodeType,
    ip_variant: IpVariant,
) -> MacAddress {
    // Use the canonical form of the MAC address (lowercase with colons)
    // NOTE: In order to be backwards compatible with existing scripts, this seed
    // **MUST** have a newline.
    let seed = format!("{}{}\n", mgmt_mac.to_canonical(), deployment);

    let hash = Sha256::digest(seed.as_bytes());

    let version = match ip_variant {
        IpVariant::V4 => 0x4a,
        IpVariant::V6 => 0x6a,
    };

    let index = node_type.to_index();

    let octets = [version, index, hash[0], hash[1], hash[2], hash[3]];

    MacAddress::new(octets)
}

/// Parses the MAC address from `ipmitool` output.
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
    MacAddress::from_str(mac_str).map_err(|_| anyhow!("Invalid MAC address format: {}", mac_str))
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
    use crate::node_type::NodeType;

    #[test]
    fn test_mac_address_parsing() {
        // Test parsing formatted MAC address
        let mac = MacAddress::from_str("DE:AD:BE:EF:FF:00").unwrap();
        assert_eq!(mac.to_string(), "DE:AD:BE:EF:FF:00");

        // Test parsing unformatted MAC address
        let mac = MacAddress::from_str("deadbeefff00").unwrap();
        assert_eq!(mac.to_string(), "DE:AD:BE:EF:FF:00");

        // Test unformatted string representation
        assert_eq!(mac.to_unformatted_string(), "DEADBEEFFF00");

        // Test invalid MAC addresses
        assert!(MacAddress::from_str("123456789ABCDEF").is_err()); // Too many chars
        assert!(MacAddress::from_str("ZOOMBAWRONG1").is_err()); // Non-hex chars
        assert!(MacAddress::from_str("Fast times").is_err()); // Nonsense
        assert!(MacAddress::from_str("").is_err()); // Too few chars
    }

    #[test]
    fn test_generate_deterministic_mac_address() {
        let mgmt_mac = MacAddress::from_str("de:ad:de:ad:de:ad").unwrap();
        let mac_v4 = generate_deterministic_mac_address(
            &mgmt_mac,
            Deployment::Mainnet,
            NodeType::GuestOS,
            IpVariant::V4,
        );
        assert_eq!(mac_v4.to_string(), "4A:01:F7:E0:C6:84");

        let mac_v6 = generate_deterministic_mac_address(
            &mgmt_mac,
            Deployment::Mainnet,
            NodeType::GuestOS,
            IpVariant::V6,
        );
        assert_eq!(mac_v6.to_string(), "6A:01:F7:E0:C6:84");
    }

    #[test]
    fn test_get_mac_address_from_ipmitool_output() {
        let ipmitool_output = " MAC Address             : de:ad:be:ef:be:ef  ";
        let mac = get_mac_address_from_ipmitool_output(ipmitool_output).unwrap();
        assert_eq!(mac.to_string(), "DE:AD:BE:EF:BE:EF");

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
        assert_eq!(mac.to_string(), "3C:EC:EF:2F:7A:79");

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
        let prefix = "2602:ffe4:801:17";
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

    #[test]
    fn test_to_unformatted_string() {
        let mac = MacAddress::from_str("de:ad:be:ef:ff:00").unwrap();
        assert_eq!(mac.to_unformatted_string(), "DEADBEEFFF00");

        let mac = MacAddress::from_str("deadbeefff00").unwrap();
        assert_eq!(mac.to_unformatted_string(), "DEADBEEFFF00");
    }
}
