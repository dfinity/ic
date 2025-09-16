//! Imports replicated state from an external location.

use crate::commands::utils;
use ic_state_layout::StateLayout;
use ic_types::Height;
use std::path::PathBuf;

/// Imports a checkpoint of replicated state into the replica state directory.
///
/// Function is not crash-safe. Caller is responsible to follow guidelines
/// regarding crash-safe I/O.
pub fn do_import(state_path: PathBuf, config_path: PathBuf, height: u64) -> Result<(), String> {
    let state_layout = utils::locate_state_root(config_path)?;
    let height = Height::new(height);

    if let Ok(cp_layout) = state_layout.checkpoint_verified(height) {
        return Err(format!(
            "Checkpoint {} already exists at {}",
            height,
            cp_layout.raw_path().display()
        ));
    }

    state_layout
        .copy_and_sync_checkpoint(
            &format!("import_{height}"),
            &state_path,
            &state_layout
                .checkpoints()
                .join(StateLayout::checkpoint_name(height)),
            None,
        )
        .map_err(|e| format!("Failed to import checkpoint: {e}"))?;

    Ok(())
}
