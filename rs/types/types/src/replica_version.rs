//! ReplicaVersion can be converted to/from string representation.
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

pub static REPLICA_BINARY_HASH: OnceCell<String> = OnceCell::new();

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct ReplicaVersion {
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc_str")]
    version_id: Arc<str>,
}

impl std::fmt::Display for ReplicaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.version_id.fmt(f)
    }
}

impl From<ReplicaVersion> for String {
    fn from(version: ReplicaVersion) -> String {
        (&version).into()
    }
}

impl From<&ReplicaVersion> for String {
    fn from(version: &ReplicaVersion) -> String {
        version.version_id.to_string()
    }
}

impl AsRef<str> for ReplicaVersion {
    fn as_ref(&self) -> &str {
        &self.version_id
    }
}

/// Checks if a given char is invalid for use in a replica version.
fn is_invalid_version_symbol(c: char) -> bool {
    !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-')
}

impl FromStr for ReplicaVersion {
    type Err = ReplicaVersionParseError;

    fn from_str(version_str: &str) -> Result<Self, Self::Err> {
        ReplicaVersion::try_from(version_str)
    }
}

impl TryFrom<&str> for ReplicaVersion {
    type Error = ReplicaVersionParseError;

    fn try_from(version_str: &str) -> Result<Self, Self::Error> {
        if version_str.is_empty() || version_str.chars().any(is_invalid_version_symbol) {
            Err(ReplicaVersionParseError(version_str.to_string()))
        } else {
            Ok(ReplicaVersion {
                version_id: version_str.into(),
            })
        }
    }
}

impl TryFrom<String> for ReplicaVersion {
    type Error = ReplicaVersionParseError;

    fn try_from(version_id: String) -> Result<Self, Self::Error> {
        ReplicaVersion::try_from(version_id.as_ref())
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct ReplicaVersionParseError(pub(crate) String);

impl fmt::Display for ReplicaVersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "version must not be empty, and contain only alpha-numeric characters, dots(.), dashes(-) and underscores(_), got '{}'",
            self.0
        )
    }
}

impl Error for ReplicaVersionParseError {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_replica_version() {
        assert!(ReplicaVersion::from_str("2020-09-25.0.1").is_ok());
        assert!(ReplicaVersion::from_str("1.2.1").is_ok());
        assert!(ReplicaVersion::from_str("8aefz17q_1").is_ok());
        assert!(ReplicaVersion::from_str("?+").is_err());
        assert!(ReplicaVersion::from_str("").is_err());
    }
}
