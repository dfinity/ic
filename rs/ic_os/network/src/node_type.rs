use std::str::FromStr;

use anyhow::{anyhow, Error, Result};

#[non_exhaustive]
pub enum NodeType {
    SetupOS,
    HostOS,
    GuestOS,
    Boundary,
}

impl NodeType {
    pub fn to_char(&self) -> char {
        use NodeType::*;
        match self {
            SetupOS => 'f',
            HostOS => '0',
            GuestOS => '1',
            Boundary => '2',
        }
    }
}

impl FromStr for NodeType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use NodeType::*;
        match s.to_ascii_lowercase().as_str() {
            "setupos" => Ok(SetupOS),
            "hostos" => Ok(HostOS),
            "guestos" => Ok(GuestOS),
            "boundary" => Ok(Boundary),
            _ => Err(anyhow!("Invalid node type: {}", s)),
        }
    }
}
