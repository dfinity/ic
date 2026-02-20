use crate::registry_helper::RegistryError;
use ic_image_upgrader::error::UpgradeError;
use ic_types::{Height, NodeId, RegistryVersion};
use std::{
    error::Error,
    fmt, io,
    path::{Path, PathBuf},
};

pub(crate) type OrchestratorResult<T> = Result<T, OrchestratorError>;

/// Enumerates the possible errors that Orchestrator may encounter
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum OrchestratorError {
    /// An error occurred when querying the registry that prevents the orchestrator from making
    /// progress
    RegistryError(RegistryError),

    /// The CUP at the given height failed to be deserialized
    DeserializeCupError(Option<Height>, String),

    /// The crypto-config could not be serialized
    SerializeCryptoConfigError(serde_json::Error),

    /// An IO error occurred
    IoError(String, io::Error),

    /// Failed to exec a new Orchestrator binary
    ExecError(PathBuf, exec::Error),

    /// The provided configuration file (`ic.json5`) has invalid content.
    InvalidConfiguration(String),

    /// Generic error while monitoring key changes
    ThresholdKeyMonitoringError(String),

    /// Network configuration error
    NetworkConfigurationError(String),

    /// An error occurred when trying to get the role (Api boundary node, replica, ...) of the node
    /// at the given registry version.
    RoleError(String, RegistryVersion),

    /// The given node is missing a domain name
    DomainNameMissing(NodeId),
}

impl OrchestratorError {
    pub(crate) fn file_write_error(file_path: &Path, e: io::Error) -> Self {
        OrchestratorError::IoError(format!("Failed to write to file: {file_path:?}"), e)
    }

    pub(crate) fn invalid_configuration(msg: impl ToString) -> Self {
        OrchestratorError::InvalidConfiguration(msg.to_string())
    }

    pub(crate) fn key_monitoring_error(msg: impl ToString) -> Self {
        OrchestratorError::ThresholdKeyMonitoringError(msg.to_string())
    }

    pub(crate) fn deserialize_cup_error(height: Option<Height>, msg: impl ToString) -> Self {
        OrchestratorError::DeserializeCupError(height, msg.to_string())
    }
}

impl fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrchestratorError::RegistryError(e) => write!(f, "Registry error: {e}"),
            OrchestratorError::DeserializeCupError(height, error) => write!(
                f,
                "Failed to deserialize the CUP at height {height:?}, with error: {error}",
            ),
            OrchestratorError::SerializeCryptoConfigError(e) => {
                write!(f, "Failed to serialize crypto-config: {e}")
            }
            OrchestratorError::IoError(msg, e) => {
                write!(f, "IO error, message: {msg}, error: {e}")
            }
            OrchestratorError::ExecError(path, e) => write!(
                f,
                "Failed to exec new Orchestrator process: {path:?}, error: {e}"
            ),
            OrchestratorError::InvalidConfiguration(msg) => {
                write!(f, "Invalid configuration: {msg}")
            }
            OrchestratorError::ThresholdKeyMonitoringError(msg) => {
                write!(
                    f,
                    "Failed to read or write threshold key changed metric: {msg}"
                )
            }
            OrchestratorError::NetworkConfigurationError(msg) => {
                write!(f, "Failed to apply network configuration: {msg}")
            }
            OrchestratorError::RoleError(msg, registry_version) => {
                write!(
                    f,
                    "Failed to get the role of the node at the registry version {registry_version}: {msg}"
                )
            }
            OrchestratorError::DomainNameMissing(node_id) => {
                write!(f, "Node {node_id} does not have an associated domain name")
            }
        }
    }
}

impl From<OrchestratorError> for UpgradeError {
    fn from(e: OrchestratorError) -> UpgradeError {
        match e {
            OrchestratorError::RegistryError(e) => UpgradeError::RegistryError(e.to_string()),
            OrchestratorError::IoError(msg, err) => UpgradeError::IoError(msg, err),
            err => UpgradeError::GenericError(err.to_string()),
        }
    }
}

impl Error for OrchestratorError {}
