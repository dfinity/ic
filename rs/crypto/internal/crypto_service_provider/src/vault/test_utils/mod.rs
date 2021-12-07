//! Utilities for testing `CspVault`-implementations

pub mod basic_sig;
pub mod multi_sig;
pub mod ni_dkg;
pub mod sks;
pub mod threshold_sig;
pub mod tls;

use std::path::PathBuf;

/// Creates a temporary file; it is the caller's responsibility to delete it
/// after use.
pub fn get_temp_file_path() -> PathBuf {
    // So, tempfile has no method for creating just the temporary file NAME,
    // instead, it suggests you create the file and then close it, to make sure
    // it gets deleted; but keep the path around.
    // (https://docs.rs/tempfile/3.2.0/tempfile/struct.TempPath.html#method.close)
    let tmp_file = tempfile::NamedTempFile::new().expect("Could not create temp file");
    let tmp_file = tmp_file.into_temp_path();
    let file_path = tmp_file.to_path_buf();
    tmp_file
        .close()
        .expect("Could not close temp file in order to make temp file name");
    file_path
}
