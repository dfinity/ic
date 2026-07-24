use crate::error::fs::ReadFileError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StructuredFileError {
    #[error("failed to parse contents of {0} as json")]
    DeserializeJsonFileFailed(Box<PathBuf>, #[source] serde_json::Error),

    #[error("failed to read JSON file")]
    ReadJsonFileFailed(#[from] ReadFileError),
}
