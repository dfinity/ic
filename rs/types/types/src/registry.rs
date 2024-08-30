//! Types for working with the registry.

use crate::RegistryVersion;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Errors returned by the registry data provider.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryDataProviderError {
    /// Timeout occurred when attempting to fetch updates from the registry
    /// canister.
    Timeout,
    /// Error when using registry transfer
    Transfer { source: String },
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

    #[error("failed to decode registry contents: {error}")]
    DecodeError { error: String },
}
