//! Computes manifest of a checkpoint.

use ic_state_manager::manifest::{manifest_from_path, manifest_hash};
use std::path::{Path, PathBuf};

/// Computes the manifest (chunk hashes, file hashes and root hash) of the
/// checkpoint rooted at `path`.
pub fn do_compute_manifest(path: PathBuf) -> Result<(), String> {
    println!("{}", compute_manifest(&path)?);

    Ok(())
}

pub fn compute_manifest(path: &Path) -> Result<String, String> {
    let manifest = manifest_from_path(path).map_err(|e| {
        format!(
            "Failed to compute manifest of checkpoint at {}: {}",
            path.display(),
            e
        )
    })?;

    Ok(format!(
        "{}\n\nROOT HASH: {}",
        manifest,
        hex::encode(manifest_hash(&manifest))
    ))
}
