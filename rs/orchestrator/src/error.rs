use ic_http_utils::file_downloader::FileDownloadError;
use ic_types::replica_version::ReplicaVersionParseError;
use ic_types::{registry::RegistryClientError, NodeId, RegistryVersion, ReplicaVersion, SubnetId};
use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub type OrchestratorResult<T> = Result<T, OrchestratorError>;

/// Enumerates the possible errors that Orchestrator may encounter
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum OrchestratorError {
    /// The given node is not assigned to any Subnet
    NodeUnassignedError(NodeId, RegistryVersion),

    /// The given subnet ID does not map to a `SubnetRecord` at the given
    /// version
    SubnetMissingError(SubnetId, RegistryVersion),

    /// An error occurred when querying the Registry that prevents Orchestrator
    /// from making progress
    RegistryClientError(RegistryClientError),

    /// The genesis or recovery CUP failed to be constructed
    MakeRegistryCupError(SubnetId, RegistryVersion),

    /// The given replica version does not have an entry in the Registry
    ReplicaVersionMissingError(ReplicaVersion, RegistryVersion),

    /// A replica version (of a subnet record) could not be parsed
    ReplicaVersionParseError(ReplicaVersionParseError),

    /// An IO error occurred
    IoError(String, io::Error),

    /// An error occurred when downloading, extracting or checking the hash of a
    /// downloaded file
    FileDownloadError(FileDownloadError),

    /// Failed to exec a new Orchestrator binary
    ExecError(PathBuf, exec::Error),

    /// The provided configuration file (`ic.json5`) has invalid content.
    InvalidConfigurationError(String),

    /// Generic upgrade error
    UpgradeError(String),
}

impl OrchestratorError {
    pub(crate) fn file_write_error(file_path: &Path, e: io::Error) -> Self {
        OrchestratorError::IoError(format!("Failed to write to file: {:?}", file_path), e)
    }

    pub(crate) fn file_open_error(file_path: &Path, e: io::Error) -> Self {
        OrchestratorError::IoError(format!("Failed to open file: {:?}", file_path), e)
    }

    pub(crate) fn dir_create_error(dir: &Path, e: io::Error) -> Self {
        OrchestratorError::IoError(format!("Failed to create dir: {:?}", dir), e)
    }

    pub(crate) fn compute_hash_error(file_path: &Path, e: io::Error) -> Self {
        OrchestratorError::IoError(format!("Failed to hash of: {:?}", file_path), e)
    }

    pub(crate) fn invalid_configuration_error(msg: impl ToString) -> Self {
        OrchestratorError::InvalidConfigurationError(msg.to_string())
    }

    pub(crate) fn file_command_error(e: io::Error, cmd: &Command) -> Self {
        OrchestratorError::IoError(format!("Failed to executing command: {:?}", cmd), e)
    }
}

impl fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrchestratorError::NodeUnassignedError(node_id, registry_version) => write!(
                f,
                "Node {:?} is not found in any subnet at registry version {:?}",
                node_id, registry_version
            ),
            OrchestratorError::RegistryClientError(e) => write!(f, "{:?}", e),
            OrchestratorError::ReplicaVersionMissingError(replica_version, registry_version) => {
                write!(
                    f,
                    "Replica version {} was not found in the Registry at registry version {:?}",
                    replica_version, registry_version
                )
            }
            OrchestratorError::IoError(msg, e) => {
                write!(f, "IO error, message: {:?}, error: {:?}", msg, e)
            }
            OrchestratorError::FileDownloadError(e) => write!(f, "File download error: {:?}", e),
            OrchestratorError::ExecError(path, e) => write!(
                f,
                "Failed to exec new Orchestrator process: {:?}, error: {:?}",
                path, e
            ),
            OrchestratorError::InvalidConfigurationError(msg) => {
                write!(f, "Invalid configuration: {}", msg)
            }
            OrchestratorError::SubnetMissingError(subnet_id, registry_version) => write!(
                f,
                "Subnet ID {:?} does not exist in the Registry at registry version {:?}",
                subnet_id, registry_version
            ),
            OrchestratorError::ReplicaVersionParseError(e) => {
                write!(f, "Failed to parse replica version: {}", e)
            }
            OrchestratorError::MakeRegistryCupError(subnet_id, registry_version) => write!(
                f,
                "Failed to construct the genesis/recovery CUP, subnet_id: {}, registry_version: {}",
                subnet_id, registry_version,
            ),
            OrchestratorError::UpgradeError(msg) => write!(f, "Failed to upgrade: {}", msg),
        }
    }
}

impl From<FileDownloadError> for OrchestratorError {
    fn from(e: FileDownloadError) -> Self {
        OrchestratorError::FileDownloadError(e)
    }
}

impl Error for OrchestratorError {}
