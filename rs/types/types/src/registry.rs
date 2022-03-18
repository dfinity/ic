// (DFN-467): We disable the clippy warning for the whole module because they
// apply to generated code, meaning we can't locally disable the warnings (the
// code is defined in another module).
#![allow(clippy::redundant_closure)]
//! Types for working with the registry.

use crate::RegistryVersion;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub mod connection_endpoint;

/// Errors returned when requesting a value from the registry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryError {
    /// Requested registry version is older than minimum known version.
    VersionTooOld {
        min: RegistryVersion,
        max: RegistryVersion,
        requested: RegistryVersion,
    },
    /// Requested registry version is newer than maximum known version.
    VersionTooNew {
        min: RegistryVersion,
        max: RegistryVersion,
        requested: RegistryVersion,
    },
    /// Duplicate registry key at given registry version.
    DuplicateKey {
        kind: String,
        key: String,
        version: RegistryVersion,
    },
    /// Indicates a configuration error. Should contain a human readable
    /// description of the cause.
    Unreadable(String),
    /// Validation error when deserializing registry. Optionally wraps a source
    /// `RegistryError` for more detail.
    ValidationError {
        message: String,
        source: Option<Box<RegistryError>>,
    },
}

impl std::error::Error for RegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RegistryError::ValidationError {
                source: Some(source),
                ..
            } => Some(source),
            _ => None,
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::VersionTooOld {
                min,
                max,
                requested,
            } => write!(
                f,
                "Requested registry version {} is too old. Known versions: [{}, {}).",
                requested, min, max
            ),

            RegistryError::VersionTooNew {
                min,
                max,
                requested,
            } => write!(
                f,
                "Requested registry version {} is too new. Known versions: [{}, {}).",
                requested, min, max
            ),

            RegistryError::DuplicateKey { kind, key, version } => write!(
                f,
                "Duplicate {} registry entry for key {:?} at version {}.",
                kind, key, version
            ),

            RegistryError::Unreadable(s) => write!(f, "Registry could not be read: {:?}", s),

            RegistryError::ValidationError {
                message,
                source: Some(source),
            } => write!(f, "Invalid registry: {}: {}", message, *source),
            RegistryError::ValidationError {
                message,
                source: None,
            } => write!(f, "Invalid registry: {}", message),
        }
    }
}

impl RegistryError {
    pub fn is_version_too_old(&self) -> bool {
        matches!(self, RegistryError::VersionTooOld { .. })
    }

    pub fn is_version_too_new(&self) -> bool {
        matches!(self, RegistryError::VersionTooNew { .. })
    }

    pub fn is_duplicate_key(&self) -> bool {
        matches!(self, RegistryError::DuplicateKey { .. })
    }

    pub fn is_validation_error(&self) -> bool {
        matches!(self, RegistryError::ValidationError { .. })
    }
}

/// Errors returned by the registry data provider.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryDataProviderError {
    /// Timeout occurred when attempting to fetch updates from the registry
    /// canister.
    Timeout,
    /// Error when using registry transfer
    Transfer {
        source: ic_registry_transport::Error,
    },
}

impl std::error::Error for RegistryDataProviderError {}

impl fmt::Display for RegistryDataProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryDataProviderError::Timeout => write!(f, "Registry transport client timed out."),
            RegistryDataProviderError::Transfer { source } => write!(
                f,
                "Registry transport client failed to fetch registry update from registry canister: {}", source
            ),
        }
    }
}

/// Errors returned by the registry client.
#[derive(Error, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryClientError {
    #[error("the requested version is not available locally: {version}")]
    VersionNotAvailable { version: RegistryVersion },

    #[error("failed to query data provider: {source}")]
    DataProviderQueryFailed {
        #[from]
        source: RegistryDataProviderError,
    },

    #[error("failed to acquire poll lock: {error}")]
    PollLockFailed {
        // Ideally this would be a TryLockError, but that takes a type parameter
        // which 'infects' this enum, and everything that uses it.
        error: String,
    },

    #[error("failed to report the same version twice after {retries} times")]
    PollingLatestVersionFailed { retries: usize },
}
