//! Trimmed from `dfx_core::fs`: only the read-side helpers used by the retained
//! identity- and network-resolution paths. Each wraps a `std::fs` call with a
//! path-annotated error, matching upstream behaviour and messages.
pub mod composite;

use crate::error::fs::{CreateDirAllError, ReadFileError, ReadToStringError};
use std::path::Path;

pub fn create_dir_all(path: &Path) -> Result<(), CreateDirAllError> {
    std::fs::create_dir_all(path).map_err(|source| CreateDirAllError {
        path: path.to_path_buf(),
        source,
    })
}

pub fn read(path: &Path) -> Result<Vec<u8>, ReadFileError> {
    std::fs::read(path).map_err(|source| ReadFileError {
        path: path.to_path_buf(),
        source,
    })
}

pub fn read_to_string(path: &Path) -> Result<String, ReadToStringError> {
    std::fs::read_to_string(path).map_err(|source| ReadToStringError {
        path: path.to_path_buf(),
        source,
    })
}
