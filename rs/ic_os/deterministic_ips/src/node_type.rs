use anyhow::{anyhow, Error};
use std::fmt;
use std::str::FromStr;

#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum NodeType {
    SetupOS,
    HostOS,
    GuestOS,
    BoundaryOS,
}

impl NodeType {
    pub fn to_index(&self) -> u8 {
        match self {
            NodeType::SetupOS => 0x0f,
            NodeType::HostOS => 0x00,
            NodeType::GuestOS => 0x01,
            NodeType::BoundaryOS => 0x02,
        }
    }
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NodeType::SetupOS => write!(f, "SetupOS"),
            NodeType::HostOS => write!(f, "HostOS"),
            NodeType::GuestOS => write!(f, "GuestOS"),
            NodeType::BoundaryOS => write!(f, "BoundaryOS"),
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
            "boundary" => Ok(NodeType::BoundaryOS),
            _ => Err(anyhow!("Invalid node type: {}", s)),
        }
    }
}
