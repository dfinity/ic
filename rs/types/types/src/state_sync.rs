use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Display;
use strum::EnumIter;

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, EnumIter, Serialize,
)]
pub enum StateSyncVersion {
    /// Initial version.
    V0 = 0,

    /// Also include version and chunk hashes into manifest hash.
    V1 = 1,

    /// Compute the manifest hash based on the encoded manifest.
    V2 = 2,

    /// File index-independent manifest hash: file index no longer included in file
    /// hash.
    V3 = 3,
}

impl std::convert::TryFrom<u32> for StateSyncVersion {
    type Error = u32;

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        use strum::IntoEnumIterator;
        for version in StateSyncVersion::iter() {
            if version as u32 == n {
                return Ok(version);
            }
        }
        Err(n)
    }
}

impl Display for StateSyncVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// The version of StateSync protocol that should be used for all newly created manifests.
pub const CURRENT_STATE_SYNC_VERSION: StateSyncVersion = StateSyncVersion::V3;
