//! Imports replicated state from an external location.

use crate::commands::utils;
use ic_state_layout::{CheckpointLayout, RwPolicy};
use ic_sys::fs::clone_file;
use ic_types::Height;
use ic_utils::fs::copy_file_sparse;
use std::fs;
use std::path::{Path, PathBuf};
use std::string::ToString;

/// Copies SRC into DST recursively.
///
/// Function is not crash-safe. Caller is responsible to follow guidelines
/// regarding crash-safe I/O.
fn copy_recursively(src: &Path, dst: &Path) -> Result<(), String> {
    enum CanCloneFiles {
        Yes,
        No,
    }
    fn go(src: &Path, dst: &Path, can_clone: &mut CanCloneFiles) -> Result<(), String> {
        let src_metadata = src
            .metadata()
            .map_err(|e| format!("failed to get metadata of path {}: {}", src.display(), e))?;

        if src_metadata.is_dir() {
            let entries = src
                .read_dir()
                .map_err(|e| format!("failed to read directory {}: {}", src.display(), e))?;

            fs::create_dir_all(&dst)
                .map_err(|e| format!("failed to create directory {}: {}", dst.display(), e))?;

            for entry_result in entries {
                let entry = entry_result.map_err(|e| {
                    format!("failed to read entry of directory {}: {}", src.display(), e)
                })?;
                let dst_entry = dst.join(entry.file_name());

                go(&entry.path(), &dst_entry, can_clone)?;
            }
        } else {
            if let CanCloneFiles::Yes = can_clone {
                match clone_file(src, dst) {
                    Ok(_) => return Ok(()),
                    Err(_) => {
                        *can_clone = CanCloneFiles::No;
                    }
                }
            }

            copy_file_sparse(src, dst).map_err(|e| {
                format!(
                    "Failed to copy {} -> {}: {}",
                    src.display(),
                    dst.display(),
                    e
                )
            })?;
        }

        Ok(())
    }
    // We try to clone files first because it's much faster for big files.
    // If cloning fails (most likely, because SRC and DST are on different file
    // systems), we fall back to usual copying.
    let mut can_clone = CanCloneFiles::Yes;
    go(src, dst, &mut can_clone)
}

/// Imports a checkpoint of replicated state into the replica state directory.
///
/// Function is not crash-safe. Caller is responsible to follow guidelines
/// regarding crash-safe I/O.
pub fn do_import(state_path: PathBuf, config_path: PathBuf, height: u64) -> Result<(), String> {
    let state_layout = utils::locate_state_root(config_path)?;
    let height = Height::new(height);

    if let Ok(cp_layout) = state_layout.checkpoint(height) {
        return Err(format!(
            "Checkpoint {} already exists at {}",
            height,
            cp_layout.raw_path().display()
        ));
    }

    let scratchpad_dir = state_layout
        .state_sync_scratchpad(height)
        .map_err(|e| format!("Failed to get a scratchpad directory: {}", e))?;

    copy_recursively(&state_path, &scratchpad_dir)?;

    let cp_layout = CheckpointLayout::<RwPolicy>::new(scratchpad_dir, height)
        .map_err(|e| format!("Failed to create scratchpad checkpoint layout: {}", e))?;

    state_layout
        .scratchpad_to_checkpoint(cp_layout, height)
        .map_err(|e| e.to_string())?;

    println!(
        "Successfully created checkpoint {} in state root {}",
        height,
        state_layout.raw_path().display()
    );

    Ok(())
}
