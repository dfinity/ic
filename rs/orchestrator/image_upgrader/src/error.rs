use ic_http_utils::file_downloader::FileDownloadError;
use std::error::Error;
use std::fmt;
use std::io;
use tokio::process::Command;

pub type UpgradeResult<T> = Result<T, UpgradeError>;

/// Enumerates the possible errors that the Upgrader may encounter
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum UpgradeError {
    /// An IO error occurred
    IoError(String, io::Error),

    /// An error occurred when downloading, extracting or checking the hash of a
    /// downloaded file
    FileDownloadError(FileDownloadError),

    /// Generic upgrade error
    GenericError(String),

    /// Generic error while handling reboot time
    RebootTimeError(String),

    DiskEncryptionKeyExchangeError(String),
}

impl UpgradeError {
    pub(crate) fn reboot_time_error(msg: impl ToString) -> Self {
        UpgradeError::RebootTimeError(msg.to_string())
    }

    pub(crate) fn file_command_error(e: io::Error, cmd: &Command) -> Self {
        UpgradeError::IoError(format!("Failed to executing command: {cmd:?}"), e)
    }
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpgradeError::IoError(msg, e) => {
                write!(f, "IO error, message: {msg:?}, error: {e:?}")
            }
            UpgradeError::FileDownloadError(e) => write!(f, "File download error: {e}"),
            UpgradeError::RebootTimeError(msg) => {
                write!(f, "Failed to read or write reboot time: {msg}")
            }
            UpgradeError::GenericError(msg) => write!(f, "Failed to upgrade: {msg}"),
            UpgradeError::DiskEncryptionKeyExchangeError(msg) => {
                write!(f, "Failed to exchange disk encryption key: {msg}")
            }
        }
    }
}

impl From<FileDownloadError> for UpgradeError {
    fn from(e: FileDownloadError) -> Self {
        UpgradeError::FileDownloadError(e)
    }
}

impl Error for UpgradeError {}
