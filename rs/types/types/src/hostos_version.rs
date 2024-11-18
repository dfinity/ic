//! HostOsVersion can be converted to/from string representation.
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct HostosVersion {
    version_id: String,
}

impl std::fmt::Display for HostosVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.version_id.fmt(f)
    }
}

impl From<HostosVersion> for String {
    fn from(version: HostosVersion) -> String {
        (&version).into()
    }
}

impl From<&HostosVersion> for String {
    fn from(version: &HostosVersion) -> String {
        version.version_id.clone()
    }
}

impl AsRef<str> for HostosVersion {
    fn as_ref(&self) -> &str {
        &self.version_id
    }
}

/// Checks if a valid HostOS version is allowed to contain specified char.
fn is_valid_version_symbol(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-')
}

impl TryFrom<&str> for HostosVersion {
    type Error = HostosVersionParseError;

    fn try_from(version_str: &str) -> Result<Self, Self::Error> {
        if !version_str.chars().all(is_valid_version_symbol) {
            Err(HostosVersionParseError(version_str.to_string()))
        } else {
            Ok(HostosVersion {
                version_id: version_str.to_string(),
            })
        }
    }
}

impl TryFrom<String> for HostosVersion {
    type Error = HostosVersionParseError;

    fn try_from(version_id: String) -> Result<Self, Self::Error> {
        HostosVersion::try_from(version_id.as_ref())
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct HostosVersionParseError(pub(crate) String);

impl fmt::Display for HostosVersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "version must contain only alpha-numeric characters, dots(.), dashes(-) and underscores(_), got {}",
            self.0
        )
    }
}

impl Error for HostosVersionParseError {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_hostos_version() {
        assert!(HostosVersion::try_from("2020-09-25.0.1").is_ok());
        assert!(HostosVersion::try_from("1.2.1").is_ok());
        assert!(HostosVersion::try_from("8aefz17q_1").is_ok());
        assert!(HostosVersion::try_from("?+").is_err());
    }
}
