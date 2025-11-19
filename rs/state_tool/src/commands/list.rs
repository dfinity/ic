//! Enumerates persisted states.

use crate::commands::utils;
use std::path::PathBuf;

/// Types of persisted state: verified checkpoints, unverified checkpoints, diverged checkpoints and backups.
enum CheckpointStatus {
    Verified,
    Unverified,
    Diverged,
    Backup,
}

/// Lists all persisted states (checkpoint, diverged and backup) under the state
/// root location indicated in the given configuration file.
pub fn do_list(config: PathBuf) -> Result<(), String> {
    let state_layout = utils::locate_state_root(config)?;
    let verified_heights = state_layout
        .checkpoint_heights()
        .map_err(|e| format!("failed to enumerate checkpoints: {e}"))?
        .into_iter()
        .map(|h| (h, CheckpointStatus::Verified));

    let unverified_heights = state_layout
        .unfiltered_checkpoint_heights()
        .map_err(|e| format!("failed to enumerate unverified checkpoints: {e}"))?
        .into_iter()
        .filter_map(|h| match state_layout.checkpoint_verification_status(h) {
            Ok(false) => Some((h, CheckpointStatus::Unverified)),
            _ => None,
        });

    let diverged_heights = state_layout
        .diverged_checkpoint_heights()
        .map_err(|e| format!("failed to enumerate diverged checkpoints: {e}"))?
        .into_iter()
        .map(|h| (h, CheckpointStatus::Diverged));

    let backups = state_layout
        .backup_heights()
        .map_err(|e| format!("failed to enumerate backed up checkpoints: {e}"))?
        .into_iter()
        .map(|h| (h, CheckpointStatus::Backup));

    let mut heights: Vec<_> = verified_heights
        .chain(unverified_heights)
        .chain(diverged_heights)
        .chain(backups)
        .collect();
    heights.sort_by_key(|(h, _)| *h);

    if heights.is_empty() {
        println!("No checkpoints to display");
        return Ok(());
    }

    println!("{:>15}    {:<10}    {:<}", "HEIGHT", "STATUS", "LOCATION");

    for (h, status) in heights {
        let (status_str, path) = match status {
            CheckpointStatus::Verified => {
                let cp_layout = state_layout
                    .checkpoint_verified(h)
                    .map_err(|e| format!("failed to access verified checkpoint @{h}: {e}"))?;
                ("verified", cp_layout.raw_path().to_path_buf())
            }
            CheckpointStatus::Unverified => {
                let cp_layout = state_layout
                    .checkpoint_in_verification(h)
                    .map_err(|e| format!("failed to access unverified checkpoint @{h}: {e}"))?;
                ("unverified", cp_layout.raw_path().to_path_buf())
            }
            CheckpointStatus::Diverged => ("diverged", state_layout.diverged_checkpoint_path(h)),
            CheckpointStatus::Backup => ("backup", state_layout.backup_checkpoint_path(h)),
        };

        println!(
            "{:>15}    {:<10}    {}",
            h.get(),
            status_str,
            path.display()
        );
    }

    Ok(())
}
