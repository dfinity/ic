use anyhow::{Error, anyhow};
use std::fmt;
use std::str::FromStr;

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NodeType {
    SetupOS,
    HostOS,
    GuestOS,
    UpgradeGuestOS,
}

impl NodeType {
    pub fn to_index(&self) -> u8 {
        match self {
            NodeType::SetupOS => 0x0f,
            NodeType::HostOS => 0x00,
            NodeType::GuestOS => 0x01,
            NodeType::UpgradeGuestOS => 0x02,
        }
    }
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NodeType::SetupOS => write!(f, "SetupOS"),
            NodeType::HostOS => write!(f, "HostOS"),
            NodeType::GuestOS => write!(f, "GuestOS"),
            NodeType::UpgradeGuestOS => write!(f, "UpgradeGuestOS"),
        }
    }
}

impl FromStr for NodeType {
    type Err = Error;

    fn from_str(s: &str) -> Result<NodeType, Self::Err> {
        let mut normalized = s.to_lowercase();
        normalized.retain(|c| c.is_alphanumeric());
        match normalized.as_str() {
            "setupos" => Ok(NodeType::SetupOS),
            "hostos" => Ok(NodeType::HostOS),
            "guestos" => Ok(NodeType::GuestOS),
            "upgradeguestos" => Ok(NodeType::UpgradeGuestOS),
            _ => Err(anyhow!("Invalid node type: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_type_from_str_valid() {
        assert_eq!(NodeType::from_str("SetupOS").unwrap(), NodeType::SetupOS);
        assert_eq!(NodeType::from_str("setupos").unwrap(), NodeType::SetupOS);
        assert_eq!(NodeType::from_str("HostOS").unwrap(), NodeType::HostOS);
        assert_eq!(NodeType::from_str("gUest.oS").unwrap(), NodeType::GuestOS);
        assert_eq!(
            NodeType::from_str("upgrade-guest-os").unwrap(),
            NodeType::UpgradeGuestOS
        );
    }
}
