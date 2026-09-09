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

/// Checks if a valid replica version is allowed to contain specified char.
fn is_valid_version_symbol(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-')
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
        if !version_str.chars().all(is_valid_version_symbol) {
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
            "version must contain only alpha-numeric characters, dots(.), dashes(-) and underscores(_), got {}",
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
    }
}

/// The node's platform versions: the GuestOS version the node booted from and
/// the replica binary version.
///
/// Under normal conditions the two are the same. During a GuestOS fast
/// upgrade, binaries from the target (new) GuestOS are hot-swapped in the
/// running (old) GuestOS, so the replica version is ahead of the GuestOS
/// version until the node reboots into the target GuestOS.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct PlatformVersion {
    /// The GuestOS version the node booted from.
    pub guestos_version: ReplicaVersion,
    /// The replica binary version, possibly hot-swapped by a fast upgrade.
    pub replica_version: ReplicaVersion,
}
