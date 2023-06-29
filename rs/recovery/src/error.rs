use ic_http_utils::file_downloader::FileDownloadError;
use ic_state_manager::CheckpointError;
use std::{
    error::Error,
    fmt::{self, Display},
    io,
    path::Path,
    process::Command,
};

pub type RecoveryResult<T> = Result<T, RecoveryError>;

/// Enumerates the possible errors that Recovery may encounter
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum RecoveryError {
    IoError(String, io::Error),
    CommandError(Option<i32>, String),
    OutputError(String),
    DownloadError(String, FileDownloadError),
    ParsingError(serde_json::Error),
    SerializationError(serde_json::Error),
    UnexpectedError(String),
    StateToolError(String),
    CheckpointError(String, CheckpointError),
    RegistryError(String),
    ValidationFailed(String),
    AgentError(String),
    StepSkipped,
}

impl RecoveryError {
    pub(crate) fn dir_error(dir: &Path, e: io::Error) -> Self {
        RecoveryError::IoError(format!("Directory error: {:?}", dir), e)
    }
    pub fn file_error(file: &Path, e: io::Error) -> Self {
        RecoveryError::IoError(format!("File error: {:?}", file), e)
    }
    pub(crate) fn cmd_error(cmd: &Command, exit_code: Option<i32>, output: impl Display) -> Self {
        RecoveryError::CommandError(
            exit_code,
            format!(
                "Failed to execute system command: {:?}, Output: {}",
                cmd, output
            ),
        )
    }
    pub(crate) fn invalid_output_error(output: impl Display) -> Self {
        RecoveryError::OutputError(format!("Invalid output: {}", output))
    }
    pub(crate) fn parsing_error(e: serde_json::Error) -> Self {
        RecoveryError::ParsingError(e)
    }
    pub(crate) fn serialization_error(e: serde_json::Error) -> Self {
        RecoveryError::SerializationError(e)
    }
    pub(crate) fn download_error(url: impl Display, target: &Path, e: FileDownloadError) -> Self {
        RecoveryError::DownloadError(
            format!("Failed to download from {} to {:?}", url, target),
            e,
        )
    }

    pub fn validation_failed(message: impl Display, error: impl Display) -> Self {
        RecoveryError::ValidationFailed(format!("{}: {}", message, error))
    }
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryError::IoError(msg, e) => {
                write!(f, "IO error, message: {}, error: {}", msg, e)
            }
            RecoveryError::CommandError(code, msg) => {
                write!(f, "Command error, message: {}, code: {:?}", msg, code)
            }
            RecoveryError::OutputError(msg) => {
                write!(f, "Output error, message: {}", msg)
            }
            RecoveryError::DownloadError(msg, e) => {
                write!(f, "Download error, message: {}, error: {}", msg, e)
            }
            RecoveryError::UnexpectedError(msg) => {
                write!(f, "Unexpected error, message: {}", msg)
            }
            RecoveryError::StepSkipped => {
                write!(f, "Recovery step skipped.")
            }
            RecoveryError::ParsingError(e) => {
                write!(f, "Parsing error, error: {}", e)
            }
            RecoveryError::SerializationError(e) => {
                write!(f, "Serialization error, error: {}", e)
            }
            RecoveryError::CheckpointError(msg, e) => {
                write!(f, "Checkpoint error, message: {}, error: {}", msg, e)
            }
            RecoveryError::RegistryError(msg) => write!(f, "Registry error, message: {}", msg),
            RecoveryError::StateToolError(msg) => write!(f, "State tool error, message: {}", msg),
            RecoveryError::ValidationFailed(msg) => {
                write!(f, "Validation failed, message: {}", msg)
            }
            RecoveryError::AgentError(msg) => write!(f, "ic-agent error, message: {}", msg),
        }
    }
}

impl Error for RecoveryError {}
