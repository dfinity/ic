use ic_http_utils::file_downloader::FileDownloadError;
use ic_image_upgrader::error::UpgradeError;
use ic_types::{
    Height, NodeId, RegistryVersion, ReplicaVersion, SubnetId, registry::RegistryClientError,
    replica_version::ReplicaVersionParseError,
};
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
    /// The given node is not assigned to any Subnet
    NodeUnassignedError(NodeId, RegistryVersion),

    /// The given subnet ID does not map to a `SubnetRecord` at the given
    /// version
    SubnetMissingError(SubnetId, RegistryVersion),

    /// The given node id does not map to an `ApiBoundaryNodeRecord` at the
    /// given version
    ApiBoundaryNodeMissingError(NodeId, RegistryVersion),

    /// An error occurred when querying the Registry that prevents Orchestrator
    /// from making progress
    RegistryClientError(RegistryClientError),

    /// The genesis or recovery CUP failed to be constructed
    MakeRegistryCupError(SubnetId, RegistryVersion),

    /// The CUP at the given height failed to be deserialized
    DeserializeCupError(Option<Height>, String),

    /// The given replica version does not have an entry in the Registry
    ReplicaVersionMissingError(ReplicaVersion, RegistryVersion),

    /// A replica version (of a subnet record) could not be parsed
    ReplicaVersionParseError(ReplicaVersionParseError),

    /// The crypto-config could not be serialized
    SerializeCryptoConfigError(serde_json::Error),

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

    /// Generic error while handling reboot time
    RebootTimeError(String),

    /// Generic error while monitoring key changes
    ThresholdKeyMonitoringError(String),

    /// Network configuration error
    NetworkConfigurationError(String),

    /// An error occurred when trying to get the role (Api boundary node, replica, ...) of the node
    /// at the given registry version.
    RoleError(String, RegistryVersion),

    /// The given node is missing a domain name
    DomainNameMissingError(NodeId),
}

impl OrchestratorError {
    pub(crate) fn file_write_error(file_path: &Path, e: io::Error) -> Self {
        OrchestratorError::IoError(format!("Failed to write to file: {file_path:?}"), e)
    }

    pub(crate) fn invalid_configuration_error(msg: impl ToString) -> Self {
        OrchestratorError::InvalidConfigurationError(msg.to_string())
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
            OrchestratorError::NodeUnassignedError(node_id, registry_version) => write!(
                f,
                "Node {node_id:?} is not found in any subnet at registry version {registry_version:?}"
            ),
            OrchestratorError::RegistryClientError(e) => write!(f, "{e:?}"),
            OrchestratorError::ReplicaVersionMissingError(replica_version, registry_version) => {
                write!(
                    f,
                    "Replica version {replica_version} was not found in the Registry at registry version {registry_version:?}"
                )
            }
            OrchestratorError::IoError(msg, e) => {
                write!(f, "IO error, message: {msg:?}, error: {e:?}")
            }
            OrchestratorError::FileDownloadError(e) => write!(f, "File download error: {e:?}"),
            OrchestratorError::ExecError(path, e) => write!(
                f,
                "Failed to exec new Orchestrator process: {path:?}, error: {e:?}"
            ),
            OrchestratorError::InvalidConfigurationError(msg) => {
                write!(f, "Invalid configuration: {msg}")
            }
            OrchestratorError::RebootTimeError(msg) => {
                write!(f, "Failed to read or write reboot time: {msg}")
            }
            OrchestratorError::ThresholdKeyMonitoringError(msg) => {
                write!(
                    f,
                    "Failed to read or write threshold key changed metric: {msg}"
                )
            }
            OrchestratorError::SubnetMissingError(subnet_id, registry_version) => write!(
                f,
                "Subnet ID {subnet_id:?} does not exist in the Registry at registry version {registry_version:?}"
            ),
            OrchestratorError::ApiBoundaryNodeMissingError(node_id, registry_version) => write!(
                f,
                "Api Boundary Node ID {node_id:?} does not exist in the Registry at registry version {registry_version:?}"
            ),
            OrchestratorError::ReplicaVersionParseError(e) => {
                write!(f, "Failed to parse replica version: {e}")
            }
            OrchestratorError::SerializeCryptoConfigError(e) => {
                write!(f, "Failed to serialize crypto-config: {e}")
            }
            OrchestratorError::MakeRegistryCupError(subnet_id, registry_version) => write!(
                f,
                "Failed to construct the genesis/recovery CUP, subnet_id: {subnet_id}, registry_version: {registry_version}",
            ),
            OrchestratorError::DeserializeCupError(height, error) => write!(
                f,
                "Failed to deserialize the CUP at height {height:?}, with error: {error}",
            ),
            OrchestratorError::UpgradeError(msg) => write!(f, "Failed to upgrade: {msg}"),
            OrchestratorError::NetworkConfigurationError(msg) => {
                write!(f, "Failed to apply network configuration: {msg}")
            }
            OrchestratorError::RoleError(msg, registry_version) => {
                write!(
                    f,
                    "Failed to get the role of the node at the registry version {registry_version}: {msg}"
                )
            }
            OrchestratorError::DomainNameMissingError(node_id) => {
                write!(f, "Node {node_id} does not have an associated domain name")
            }
        }
    }
}

impl From<RegistryClientError> for OrchestratorError {
    fn from(err: RegistryClientError) -> Self {
        OrchestratorError::RegistryClientError(err)
    }
}

impl From<FileDownloadError> for OrchestratorError {
    fn from(e: FileDownloadError) -> Self {
        OrchestratorError::FileDownloadError(e)
    }
}

impl From<UpgradeError> for OrchestratorError {
    fn from(e: UpgradeError) -> Self {
        match e {
            UpgradeError::IoError(s, err) => OrchestratorError::IoError(s, err),
            UpgradeError::FileDownloadError(e) => OrchestratorError::FileDownloadError(e),
            UpgradeError::GenericError(s) => OrchestratorError::UpgradeError(s),
            UpgradeError::RebootTimeError(s) => OrchestratorError::RebootTimeError(s),
            UpgradeError::DiskEncryptionKeyExchangeError(s) => OrchestratorError::UpgradeError(s),
        }
    }
}

impl From<OrchestratorError> for UpgradeError {
    fn from(e: OrchestratorError) -> UpgradeError {
        match e {
            OrchestratorError::IoError(s, err) => UpgradeError::IoError(s, err),
            OrchestratorError::FileDownloadError(e) => UpgradeError::FileDownloadError(e),
            OrchestratorError::RebootTimeError(s) => UpgradeError::RebootTimeError(s),
            err => UpgradeError::GenericError(err.to_string()),
        }
    }
}

impl Error for OrchestratorError {}
