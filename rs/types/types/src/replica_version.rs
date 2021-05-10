//! ReplicaVersion can be converted to/from string representation.
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ReplicaVersion {
    version_id: String,
}

static DEFAULT_VERSION_ID: OnceCell<String> = OnceCell::new();
pub static REPLICA_BINARY_HASH: OnceCell<String> = OnceCell::new();

/// The default replica version can be initialized only once to prevent
/// accidental mistakes. Otherwise its value is taken from environment
/// CARGO_PKG_VERSION at compile time.
impl ReplicaVersion {
    /// Set the default value, which can only be set once.
    /// Return error when it is already set.
    pub fn set_default_version(
        version: ReplicaVersion,
    ) -> Result<(), DefaultVersionAlreadySetError> {
        DEFAULT_VERSION_ID
            .set(version.version_id)
            .map_err(|_| DefaultVersionAlreadySetError)
    }
}

impl Default for ReplicaVersion {
    fn default() -> Self {
        ReplicaVersion {
            version_id: DEFAULT_VERSION_ID
                .get_or_init(|| env!("CARGO_PKG_VERSION").to_string())
                .clone(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DefaultVersionAlreadySetError;

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
        version.version_id.clone()
    }
}

impl AsRef<str> for ReplicaVersion {
    fn as_ref(&self) -> &str {
        &self.version_id
    }
}

/// Checks if a valid replica version is allowed to contain specified char.
fn is_valid_version_symbol(c: char) -> bool {
    match c {
        'a'..='z' => true,
        'A'..='Z' => true,
        '0'..='9' => true,
        '.' | '_' | '-' => true,
        _ => false,
    }
}

impl TryFrom<&str> for ReplicaVersion {
    type Error = ReplicaVersionParseError;

    fn try_from(version_str: &str) -> Result<Self, Self::Error> {
        if !version_str.chars().all(is_valid_version_symbol) {
            Err(ReplicaVersionParseError(version_str.to_string()))
        } else {
            Ok(ReplicaVersion {
                version_id: version_str.to_string(),
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

#[derive(Debug, PartialEq, Eq)]
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
        assert!(ReplicaVersion::try_from("2020-09-25.0.1").is_ok());
        assert!(ReplicaVersion::try_from("1.2.1").is_ok());
        assert!(ReplicaVersion::try_from("8aefz17q_1").is_ok());
        assert!(ReplicaVersion::try_from("?+").is_err());
        assert!(ReplicaVersion::try_from(ReplicaVersion::default().as_ref()).is_ok());
    }

    #[test]
    fn test_replica_default_version() {
        assert_eq!(
            ReplicaVersion::default().as_ref(),
            env!("CARGO_PKG_VERSION")
        );
        let version = ReplicaVersion::try_from("1.2.1").unwrap();
        assert!(ReplicaVersion::set_default_version(version).is_err());
    }

    use rusty_fork::rusty_fork_test;
    rusty_fork_test! {
        #[test]
        fn test_replica_default_version_can_be_set_once() {
            let version = ReplicaVersion::try_from("1.2.1").unwrap();
            assert!(ReplicaVersion::set_default_version(version.clone()).is_ok());
            assert_eq!(ReplicaVersion::default(), version);
            assert!(ReplicaVersion::set_default_version(version).is_err());
        }
    }
}
