use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("failed to create directory {path} and parents")]
pub struct CreateDirAllError {
    pub path: PathBuf,
    pub source: std::io::Error,
}

#[derive(Error, Debug)]
pub enum EnsureDirExistsError {
    #[error(transparent)]
    CreateDirAll(#[from] CreateDirAllError),

    #[error("path {0} is not a directory")]
    NotADirectory(PathBuf),
}

#[derive(Error, Debug)]
#[error("failed to read from {path}")]
pub struct ReadFileError {
    pub path: PathBuf,
    pub source: std::io::Error,
}

#[derive(Error, Debug)]
#[error("failed to read {path} as string")]
pub struct ReadToStringError {
    pub path: PathBuf,
    pub source: std::io::Error,
}
