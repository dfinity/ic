//! Prints the batch time of a checkpoint.

use ic_state_layout::CompleteCheckpointLayout;
use ic_types::Height;
use std::path::PathBuf;

const HEIGHT_IS_IRRELEVANT_BECAUSE_ITS_UNUSED: Height = Height::new(0);

/// Prints the batch time of the checkpoint rooted at `path`, in nanoseconds
/// since the Epoch, i.e. the IC time the subnet had reached when it wrote the
/// checkpoint.
pub fn do_print_checkpoint_time(path: PathBuf) -> Result<(), String> {
    let checkpoint_layout =
        CompleteCheckpointLayout::new_untracked(path, HEIGHT_IS_IRRELEVANT_BECAUSE_ITS_UNUSED)
            .map_err(|err| format!("Failed to create CheckpointLayout: {err:?}"))?;
    let system_metadata = checkpoint_layout
        .system_metadata()
        .deserialize()
        .map_err(|err| format!("Failed to read the system metadata: {err:?}"))?;

    println!("{}", system_metadata.batch_time_nanos);

    Ok(())
}
