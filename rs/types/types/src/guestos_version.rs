//! GuestOsVersion: the version of the GuestOS image the node booted from.
//!
//! Distinct from [`crate::ReplicaVersion`] (the binary version, which may differ
//! when a fast-upgrade overlay is active). The two types are comparable via
//! `PartialEq<ReplicaVersion>` so the upgrade-permit logic can check
//! `guestos_version == target_version` without explicit conversions.

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

use crate::ReplicaVersion;

/// Path to the file containing the GuestOS version (the version the node booted
/// from). This file is NOT overwritten by the overlay, so it stays at the
/// pre-upgrade version until a full GuestOS reboot.
pub const GUESTOS_VERSION_FILE_PATH: &str = "/opt/ic/share/version.txt";

static DEFAULT_GUESTOS_VERSION: OnceCell<String> = OnceCell::new();

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct GuestOsVersion {
    version_id: String,
}

impl std::fmt::Display for GuestOsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.version_id.fmt(f)
    }
}

impl AsRef<str> for GuestOsVersion {
    fn as_ref(&self) -> &str {
        &self.version_id
    }
}

/// Allow direct comparison between GuestOsVersion and ReplicaVersion.
impl PartialEq<ReplicaVersion> for GuestOsVersion {
    fn eq(&self, other: &ReplicaVersion) -> bool {
        self.version_id == other.as_ref()
    }
}
impl PartialEq<GuestOsVersion> for ReplicaVersion {
    fn eq(&self, other: &GuestOsVersion) -> bool {
        self.as_ref() == other.version_id
    }
}

/// Checks if a valid version is allowed to contain specified char.
fn is_valid_version_symbol(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-')
}

impl TryFrom<&str> for GuestOsVersion {
    type Error = GuestOsVersionParseError;

    fn try_from(version_str: &str) -> Result<Self, Self::Error> {
        if !version_str.chars().all(is_valid_version_symbol) {
            Err(GuestOsVersionParseError(version_str.to_string()))
        } else {
            Ok(GuestOsVersion {
                version_id: version_str.to_string(),
            })
        }
    }
}

impl TryFrom<String> for GuestOsVersion {
    type Error = GuestOsVersionParseError;

    fn try_from(version_id: String) -> Result<Self, Self::Error> {
        GuestOsVersion::try_from(version_id.as_ref())
    }
}

impl FromStr for GuestOsVersion {
    type Err = GuestOsVersionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        GuestOsVersion::try_from(s)
    }
}

/// The default GuestOS version is read lazily from
/// [`GUESTOS_VERSION_FILE_PATH`] on first access and cached for the process
/// lifetime. Falls back to [`ReplicaVersion::default`] when the file is not
/// available (e.g. unit tests).
impl Default for GuestOsVersion {
    fn default() -> Self {
        GuestOsVersion {
            version_id: DEFAULT_GUESTOS_VERSION
                .get_or_init(|| {
                    std::fs::read_to_string(GUESTOS_VERSION_FILE_PATH)
                        .map(|s| s.trim().to_string()).expect("Failed to read default GuestOS version from file")
                })
                .clone(),
        }
    }
}

impl GuestOsVersion {
    /// Set the default value, which can only be set once (for tests).
    pub fn set_default(version: GuestOsVersion) -> Result<(), DefaultVersionAlreadySetError> {
        DEFAULT_GUESTOS_VERSION
            .set(version.version_id)
            .map_err(|_| DefaultVersionAlreadySetError)
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct DefaultVersionAlreadySetError;

impl fmt::Display for DefaultVersionAlreadySetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "default GuestOS version already set")
    }
}

impl Error for DefaultVersionAlreadySetError {}

#[derive(Eq, PartialEq, Debug)]
pub struct GuestOsVersionParseError(pub(crate) String);

impl fmt::Display for GuestOsVersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "version must contain only alpha-numeric characters, dots(.), dashes(-) and underscores(_), got {}",
            self.0
        )
    }
}

impl Error for GuestOsVersionParseError {}
