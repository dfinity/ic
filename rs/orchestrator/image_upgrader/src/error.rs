use ic_http_utils::file_downloader::FileDownloadError;
use ic_types::{RegistryVersion, ReplicaVersion};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::PathBuf;

pub type UpgradeResult<T> = Result<T, UpgradeError>;

/// Enumerates the possible errors that the Upgrader may encounter
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum UpgradeError {
    /// Generic upgrade error
    GenericError(String),

    /// An error occurred when querying the registry that prevents the upgrade from making progress
    RegistryError(String),

    /// An error occurred when trying to determine the node's subnet ID
    FailedToDetermineSubnetId(String),

    /// An IO error occurred
    IoError(String, io::Error),

    /// An error occurred when downloading, extracting or checking the hash of a
    /// downloaded file
    FileDownloadError(FileDownloadError),

    /// Failed to exec a new process
    ExecError(PathBuf, exec::Error),

    /// Generic error while handling reboot time
    RebootTimeError(String),

    /// An error occurred while exchanging disk encryption keys
    DiskEncryptionKeyExchangeError(String),

    /// The replicator is not caught up with the registry, and thus cannot determine whether the
    /// given replica version is recalled or not. Contains the latest registry version known to the
    /// replicator
    ReplicatorNotCaughtUp(ReplicaVersion, RegistryVersion),

    /// The given replica version is recalled at the given registry version
    RecalledReplicaVersion(ReplicaVersion, RegistryVersion),
}

impl UpgradeError {
    pub(crate) fn reboot_time_error(msg: impl ToString) -> Self {
        UpgradeError::RebootTimeError(msg.to_string())
    }

    pub(crate) fn manageboot_error(e: io::Error, args: &[&OsStr]) -> Self {
        UpgradeError::IoError(
            format!("Failed to execute manageboot command with args {args:?}"),
            e,
        )
    }
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpgradeError::GenericError(msg) => write!(f, "Failed to upgrade: {msg}"),
            UpgradeError::RegistryError(e) => write!(f, "Registry error: {e}"),
            UpgradeError::FailedToDetermineSubnetId(msg) => {
                write!(f, "Failed to determine subnet ID: {msg}")
            }
            UpgradeError::IoError(msg, e) => {
                write!(f, "IO error, message: {msg:?}, error: {e:?}")
            }
            UpgradeError::FileDownloadError(e) => write!(f, "File download error: {e}"),
            UpgradeError::ExecError(path, e) => {
                write!(f, "Failed to exec new process: {path:?}, error: {e}")
            }
            UpgradeError::RebootTimeError(msg) => {
                write!(f, "Failed to read or write reboot time: {msg}")
            }
            UpgradeError::DiskEncryptionKeyExchangeError(msg) => {
                write!(f, "Failed to exchange disk encryption key: {msg}")
            }
            UpgradeError::ReplicatorNotCaughtUp(replica_version, registry_version) => write!(
                f,
                "Delaying upgrade to {replica_version} until registry data is recent enough. Latest registry version: {registry_version}",
            ),
            UpgradeError::RecalledReplicaVersion(replica_version, registry_version) => write!(
                f,
                "The replica version {replica_version} is recalled at registry version {registry_version}",
            ),
        }
    }
}

impl Error for UpgradeError {}
