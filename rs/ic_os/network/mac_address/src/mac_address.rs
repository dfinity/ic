use std::fmt;
use std::process::Command;

use anyhow::{bail, Context, Result};
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::node_type::NodeType;
use serde::{Deserialize, Serialize};
use utils::intersperse;

/// Wrapper types for MAC addresses
/// - ensure clients cannot modify or construct incorrectly.
///
/// Hex alpha digits are turned to lower case to match ipmitool presentation
/// Construct with `try_from(&str)`
/// Use `.get()` to get the underlying string
/// Transform between the types with `from(the_other)`
// TODO - Make a canonical type which can convert to either un/formatted on demand
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
pub struct UnformattedMacAddress(String);
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
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

impl fmt::Display for UnformattedMacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

impl fmt::Display for FormattedMacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
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

/// Generate a deterministic unformatted MAC address
/// E.g. "6a01eb49a2b0"
pub fn generate_mac_address(
    mgmt_mac: &FormattedMacAddress,
    deployment_environment: &str,
    node_type: &NodeType,
) -> Result<UnformattedMacAddress> {
    // Newline added to match behavior
    let seed = format!("{}{}\n", mgmt_mac.get(), deployment_environment);
    let vendor_part: String = hex::encode(Sha256::digest(seed)).chars().take(8).collect();
    let node_index = node_type.to_char();
    let mac = format!("6a0{}{}", node_index, vendor_part);
    UnformattedMacAddress::try_from(mac.as_str())
}
