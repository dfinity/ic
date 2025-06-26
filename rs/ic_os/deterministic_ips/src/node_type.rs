use anyhow::{anyhow, Error};
use std::fmt;
use std::str::FromStr;

#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum NodeType {
    SetupOS,
    HostOS,
    GuestOS,
}

impl NodeType {
    pub fn to_index(&self) -> u8 {
        match self {
            NodeType::SetupOS => 0x0f,
            NodeType::HostOS => 0x00,
            NodeType::GuestOS => 0x01,
            // 0x02 is reserved (previously used for BoundaryOS), don't use it
        }
    }
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NodeType::SetupOS => write!(f, "SetupOS"),
            NodeType::HostOS => write!(f, "HostOS"),
            NodeType::GuestOS => write!(f, "GuestOS"),
        }
    }
}

impl FromStr for NodeType {
    type Err = Error;

    fn from_str(s: &str) -> Result<NodeType, Self::Err> {
        match s.to_lowercase().as_str() {
            "setupos" => Ok(NodeType::SetupOS),
            "hostos" => Ok(NodeType::HostOS),
            "guestos" => Ok(NodeType::GuestOS),
            _ => Err(anyhow!("Invalid node type: {}", s)),
        }
    }
}
