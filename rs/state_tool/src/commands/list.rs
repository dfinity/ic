//! Enumerates persisted states.

use crate::commands::utils;
use std::path::PathBuf;

/// Types of persisted state: checkpoints, diverged checkpoints and backups.
enum CheckpointStatus {
    Ok,
    Diverged,
    Backup,
}

/// Lists all persisted states (checkpoint, diverged and backup) under the state
/// root location indicated in the given configuration file.
pub fn do_list(config: PathBuf) -> Result<(), String> {
    let state_layout = utils::locate_state_root(config)?;
    let heights = state_layout
        .checkpoint_heights()
        .map_err(|e| format!("failed to enumerate checkpoints: {}", e))?
        .into_iter()
        .map(|h| (h, CheckpointStatus::Ok));

    let diverged_heights = state_layout
        .diverged_checkpoint_heights()
        .map_err(|e| format!("failed to enumerate diverged checkpoints: {}", e))?
        .into_iter()
        .map(|h| (h, CheckpointStatus::Diverged));

    let backups = state_layout
        .backup_heights()
        .map_err(|e| format!("failed to enumerate backed up checkpoints: {}", e))?
        .into_iter()
        .map(|h| (h, CheckpointStatus::Backup));

    let mut heights: Vec<_> = heights.chain(diverged_heights).chain(backups).collect();
    heights.sort_by_key(|(h, _)| *h);

    if heights.is_empty() {
        println!("No checkpoints to display");
        return Ok(());
    }

    println!("{:>15}    {:<10}    {:<}", "HEIGHT", "STATUS", "LOCATION");

    for (h, status) in heights {
        let (status_str, path) = match status {
            CheckpointStatus::Ok => {
                let cp_layout = state_layout
                    .checkpoint(h)
                    .map_err(|e| format!("failed to access checkpoint @{}: {}", h, e))?;
                ("ok", cp_layout.raw_path().to_path_buf())
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
