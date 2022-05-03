use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;

use ic_http_utils::file_downloader::FileDownloadError;
use std::process::Command;

pub type RecoveryResult<T> = Result<T, RecoveryError>;

/// Enumerates the possible errors that Recovery may encounter
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum RecoveryError {
    IoError(String, io::Error),
    CommandError(Option<i32>, String),
    OutputError(String),
    DownloadError(String, FileDownloadError),
    StepSkipped,
}

impl RecoveryError {
    pub(crate) fn dir_error(dir: &Path, e: io::Error) -> Self {
        RecoveryError::IoError(format!("Directory error: {:?}", dir), e)
    }
    pub(crate) fn file_error(file: &Path, e: io::Error) -> Self {
        RecoveryError::IoError(format!("File error: {:?}", file), e)
    }
    pub(crate) fn cmd_error(cmd: &Command, exit_code: Option<i32>, output: String) -> Self {
        RecoveryError::CommandError(
            exit_code,
            format!(
                "Failed to execute system command: {:?}, Output: {}",
                cmd, output
            ),
        )
    }
    pub(crate) fn invalid_output_error(output: String) -> Self {
        RecoveryError::OutputError(format!("Invalid output: {}", output))
    }
    pub(crate) fn download_error(url: String, target: &Path, e: FileDownloadError) -> Self {
        RecoveryError::DownloadError(
            format!("Failed to download from {} to {:?}", url, target),
            e,
        )
    }
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryError::IoError(msg, e) => {
                write!(f, "IO error, message: {:?}, error: {:?}", msg, e)
            }
            RecoveryError::CommandError(code, msg) => {
                write!(f, "Command error, message: {:?}, code: {:?}", msg, code)
            }
            RecoveryError::OutputError(msg) => {
                write!(f, "Output error, message: {:?}", msg)
            }
            RecoveryError::DownloadError(msg, e) => {
                write!(f, "Download error, message: {:?}, error: {:?}", msg, e)
            }
            RecoveryError::StepSkipped => {
                write!(f, "Recovery step skipped.")
            }
        }
    }
}

impl Error for RecoveryError {}
