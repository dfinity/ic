use ic_http_utils::file_downloader::FileDownloadError;
use ic_release::error::ReleaseError;
use ic_types::replica_version::ReplicaVersionParseError;
use ic_types::{registry::RegistryClientError, NodeId, RegistryVersion, ReplicaVersion, SubnetId};
use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub type NodeManagerResult<T> = Result<T, NodeManagerError>;

/// Enumerates the possible errors that NodeManager may encounter
#[derive(Debug)]
pub enum NodeManagerError {
    /// The given node is not assigned to any Subnet
    NodeUnassignedError(NodeId, RegistryVersion),

    /// The given subnet ID does not map to a `SubnetRecord` at the given
    /// version
    SubnetMissingError(SubnetId, RegistryVersion),

    /// An error occurred when querying the Registry that prevents Node Manager
    /// from making progress
    RegistryError(RegistryClientError),

    /// The genesis or recovery CUP failed to be constructed
    MakeRegistryCupError(SubnetId, RegistryVersion),

    /// The given replica version does not have an entry in the Registry
    ReplicaVersionMissingError(ReplicaVersion, RegistryVersion),

    /// A replica version (of a subnet record) could not be parsed
    ReplicaVersionParseError(ReplicaVersionParseError),

    /// An IO error occurred
    IoError(String, io::Error),

    /// An error occurred when making an HTTP request for a binary
    BinaryHttpError(HttpError),

    /// An error occurred when downloading, extracting or checking the hash of a
    /// downloaded file
    FileDownloadError(FileDownloadError),

    /// A file's computed hash did not match the expected hash
    FileHashMismatchError {
        computed_hash: String,
        expected_hash: String,
        file_path: PathBuf,
    },

    /// Failed to exec a new Node Manager binary
    ExecError(PathBuf, exec::Error),

    /// The provided configuration file (`ic.json5`) has invalid content.
    InvalidConfigurationError(String),

    /// Generic upgrade error
    UpgradeError(String),

    /// An error occurred with a release package
    ReleasePackageError(ReleaseError),
}

impl NodeManagerError {
    pub(crate) fn file_write_error(file_path: &Path, e: io::Error) -> Self {
        NodeManagerError::IoError(format!("Failed to write to file: {:?}", file_path), e)
    }

    pub(crate) fn file_open_error(file_path: &Path, e: io::Error) -> Self {
        NodeManagerError::IoError(format!("Failed to open file: {:?}", file_path), e)
    }

    pub(crate) fn file_copy_error(src: &Path, dest: &Path, e: io::Error) -> Self {
        NodeManagerError::IoError(
            format!("Failed to copy file from {:?} to {:?}", src, dest),
            e,
        )
    }

    pub(crate) fn symlink_error(src: &Path, dest: &Path, e: io::Error) -> Self {
        NodeManagerError::IoError(format!("Failed to symlink {:?} as {:?}", src, dest), e)
    }

    pub(crate) fn dir_create_error(dir: &Path, e: io::Error) -> Self {
        NodeManagerError::IoError(format!("Failed to create dir: {:?}", dir), e)
    }

    pub(crate) fn compute_hash_error(file_path: &Path, e: io::Error) -> Self {
        NodeManagerError::IoError(format!("Failed to hash of: {:?}", file_path), e)
    }

    pub(crate) fn invalid_configuration_error(msg: impl ToString) -> Self {
        NodeManagerError::InvalidConfigurationError(msg.to_string())
    }

    pub(crate) fn file_hash_mismatch_error(
        computed_hash: String,
        expected_hash: String,
        file_path: PathBuf,
    ) -> Self {
        NodeManagerError::FileHashMismatchError {
            computed_hash,
            expected_hash,
            file_path,
        }
    }

    pub(crate) fn file_command_error(e: io::Error, cmd: &Command) -> Self {
        NodeManagerError::IoError(format!("Failed to executing command: {:?}", cmd), e)
    }
}

impl fmt::Display for NodeManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeManagerError::NodeUnassignedError(node_id, registry_version) => write!(
                f,
                "Node {:?} is not found in any subnet at registry version {:?}",
                node_id, registry_version
            ),
            NodeManagerError::RegistryError(e) => write!(f, "{:?}", e),
            NodeManagerError::ReplicaVersionMissingError(replica_version, registry_version) => {
                write!(
                    f,
                    "Replica version {} was not found in the Registry at registry version {:?}",
                    replica_version, registry_version
                )
            }
            NodeManagerError::IoError(msg, e) => {
                write!(f, "IO error, message: {:?}, error: {:?}", msg, e)
            }
            NodeManagerError::FileDownloadError(e) => write!(f, "File download error: {:?}", e),
            NodeManagerError::BinaryHttpError(HttpError::HyperError(e)) => {
                write!(f, "Encountered error when requesting binary: {:?}", e)
            }
            NodeManagerError::FileHashMismatchError {
                computed_hash,
                expected_hash,
                file_path,
            } => write!(
                f,
                "File failed hash validation: computed_hash: {}, expected_hash: {}, file: {:?}",
                computed_hash, expected_hash, file_path
            ),
            NodeManagerError::ExecError(path, e) => write!(
                f,
                "Failed to exec new Node Manager process: {:?}, error: {:?}",
                path, e
            ),
            NodeManagerError::InvalidConfigurationError(msg) => {
                write!(f, "Invalid configuration: {}", msg)
            }
            NodeManagerError::SubnetMissingError(subnet_id, registry_version) => write!(
                f,
                "Subnet ID {:?} does not exist in the Registry at registry version {:?}",
                subnet_id, registry_version
            ),
            NodeManagerError::ReplicaVersionParseError(e) => {
                write!(f, "Failed to parse replica version: {}", e)
            }
            NodeManagerError::ReleasePackageError(e) => {
                write!(f, "Error with a release package: {}", e)
            }
            NodeManagerError::MakeRegistryCupError(subnet_id, registry_version) => write!(
                f,
                "Failed to construct the genesis/recovery CUP, subnet_id: {}, registry_version: {}",
                subnet_id, registry_version,
            ),
            NodeManagerError::UpgradeError(msg) => write!(f, "Failed to upgrade: {}", msg),
        }
    }
}

impl From<hyper::Error> for NodeManagerError {
    fn from(e: hyper::Error) -> Self {
        NodeManagerError::BinaryHttpError(HttpError::HyperError(e))
    }
}

impl From<FileDownloadError> for NodeManagerError {
    fn from(e: FileDownloadError) -> Self {
        NodeManagerError::FileDownloadError(e)
    }
}

impl Error for NodeManagerError {}

/// An HTTP error that Node Manager may encounter
#[derive(Debug)]
pub enum HttpError {
    /// A hyper HTTP client produced an error
    HyperError(hyper::Error),
}
