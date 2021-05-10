use std::fmt;
use std::path::{Path, PathBuf};

pub type ReleaseResult<T> = Result<T, ReleaseError>;

#[derive(Debug)]
pub enum ReleaseError {
    /// A general I/O-Error
    IoError(String, std::io::Error),

    /// A specified file could not be found.
    FileNotFound(PathBuf),

    /// The provided paths are not unique.
    NonUniquePaths,

    /// The provided path is not a directory
    InvalidReleaseDirectory(PathBuf),

    /// Illegal filename
    InvalidFileName(PathBuf),

    /// The given key is missing from a `ReleaseContent`
    KeyMissing(String),
}

impl ReleaseError {
    pub fn io_error(err_msg: &str, e: std::io::Error) -> Self {
        ReleaseError::IoError(err_msg.to_string(), e)
    }

    pub fn file_not_found<P: AsRef<Path>>(file: P) -> Self {
        Self::FileNotFound(PathBuf::from(file.as_ref()))
    }

    pub fn file_read_err<P: AsRef<Path>>(file: P, e: std::io::Error) -> Self {
        Self::path_io_error("Could not read file", file, e)
    }

    pub fn file_open_error<P: AsRef<Path>>(file: P, e: std::io::Error) -> Self {
        Self::path_io_error("Could not open file", file, e)
    }

    pub fn gz_error(e: std::io::Error) -> Self {
        Self::io_error("Error when writing gz-stream.", e)
    }

    pub fn tar_error<P: AsRef<Path>>(file: P, e: std::io::Error) -> Self {
        Self::path_io_error("Error when adding file to tar archive", file, e)
    }

    pub fn tar_finish_error<P: AsRef<Path>>(file: P, e: std::io::Error) -> Self {
        Self::path_io_error("Could not build tar archive", file, e)
    }

    pub fn untar_error<P: AsRef<Path>>(file: P, e: std::io::Error) -> Self {
        Self::path_io_error("Failed at unpacking tar-file", file, e)
    }

    pub fn write_error<P: AsRef<Path>>(file: P, e: std::io::Error) -> Self {
        Self::path_io_error("Writing to file failed", file, e)
    }

    pub fn invalid_release_directory<P: AsRef<Path>>(path: P) -> Self {
        ReleaseError::InvalidReleaseDirectory(PathBuf::from(path.as_ref()))
    }

    pub fn release_directory_error<P: AsRef<Path>>(path: P, e: std::io::Error) -> Self {
        Self::path_io_error("Error reading directory with release content.", path, e)
    }

    pub fn invalid_file_name<P: AsRef<Path>>(path: P) -> Self {
        ReleaseError::InvalidFileName(PathBuf::from(path.as_ref()))
    }

    pub fn path_io_error<P: AsRef<Path>>(msg: &str, file: P, e: std::io::Error) -> Self {
        ReleaseError::IoError(format!("{} `{:?}`", msg, file.as_ref()), e)
    }

    pub fn file_set_permissions_error(file_path: &PathBuf, e: std::io::Error) -> Self {
        Self::path_io_error("Failed to set permissions on file", file_path, e)
    }
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ReleaseError::*;
        match self {
            IoError(error_str, e) => write!(f, "I/O Error: {}: {:?}", error_str, e),
            FileNotFound(path) => write!(f, "File not found: {:?}", path),
            NonUniquePaths => write!(f, "Provided paths are not unique."),
            InvalidReleaseDirectory(p) => write!(f, "Invalid release directory: {:?}", p),
            InvalidFileName(p) => write!(f, "Invalid file name: {:?}", p),
            KeyMissing(key) => write!(f, "Missing ReleaseContent key: {}", key),
        }
    }
}

impl std::error::Error for ReleaseError {}
