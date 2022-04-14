#[cfg(test)]
mod tests;

use http::Uri;
use ic_types::{NodeId, PrincipalId, RegistryVersion};
use std::convert::TryFrom;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

/// Error indicating that parsing XNetAuthority failed.
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum XNetAuthParseError {
    InvalidNodeId { input: String, reason: String },
    InvalidRegistryVersion { input: String, reason: String },
    InvalidSocketAddress { input: String, reason: String },
}

impl fmt::Display for XNetAuthParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse xnet authority")?;
        match self {
            Self::InvalidNodeId { input, reason } => {
                write!(f, "{}: invalid node id: {}", input, reason)
            }
            Self::InvalidRegistryVersion { input, reason } => {
                write!(f, "{}: invalid registry version: {}", input, reason)
            }
            Self::InvalidSocketAddress { input, reason } => {
                write!(f, "{}: invalid socket address: {}", input, reason)
            }
        }
    }
}

impl std::error::Error for XNetAuthParseError {}

/// Contains data required to identify a remote node.
///
/// This type provides convenience methods to parse/encode the data
/// into URI authority section.
#[derive(Debug, PartialEq, Eq)]
pub struct XNetAuthority {
    /// The node we are pulling streams from.
    pub node_id: NodeId,
    /// The version of the registry that should be used for authentication.
    pub registry_version: RegistryVersion,
    /// The address of the remote node.
    pub address: SocketAddr,
}

impl fmt::Display for XNetAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}@{}",
            self.node_id, self.registry_version, self.address
        )
    }
}

impl TryFrom<&Uri> for XNetAuthority {
    type Error = XNetAuthParseError;

    fn try_from(uri: &Uri) -> Result<Self, Self::Error> {
        Self::from_str(
            uri.authority()
                .ok_or_else(|| XNetAuthParseError::InvalidNodeId {
                    input: uri.to_string(),
                    reason: "URI doesn't have authority that is used for specifying node-id"
                        .to_string(),
                })?
                .as_str(),
        )
    }
}

impl FromStr for XNetAuthority {
    type Err = XNetAuthParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let s = input;
        let node_id_end = s
            .find('.')
            .ok_or_else(|| XNetAuthParseError::InvalidNodeId {
                input: input.to_string(),
                reason: "missing the separator (.)".to_string(),
            })?;

        let node_id = PrincipalId::from_str(&s[0..node_id_end])
            .map_err(|err| XNetAuthParseError::InvalidNodeId {
                input: input.to_string(),
                reason: err.to_string(),
            })
            .map(NodeId::new)?;

        let s = &input[node_id_end + 1..s.len()];

        let version_end =
            s.find('@')
                .ok_or_else(|| XNetAuthParseError::InvalidRegistryVersion {
                    input: input.to_string(),
                    reason: "missing separator (@)".to_string(),
                })?;

        let registry_version = s[0..version_end]
            .parse::<u64>()
            .map(RegistryVersion::new)
            .map_err(|err| XNetAuthParseError::InvalidRegistryVersion {
                input: input.to_string(),
                reason: err.to_string(),
            })?;

        let s = &s[version_end + 1..s.len()];

        let address =
            SocketAddr::from_str(s).map_err(|err| XNetAuthParseError::InvalidSocketAddress {
                input: input.to_string(),
                reason: err.to_string(),
            })?;

        Ok(Self {
            node_id,
            registry_version,
            address,
        })
    }
}
