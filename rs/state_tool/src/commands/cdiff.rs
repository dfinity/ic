//! Computes diff of canonical trees between checkpoints.

use ic_registry_subnet_type::SubnetType;
use ic_state_layout::CompleteCheckpointLayout;
use ic_state_manager::{
    checkpoint::load_checkpoint,
    tree_diff::{diff, Changes, PrettyPrintedChanges},
    tree_hash::hash_state,
    CheckpointError, CheckpointMetrics,
};
use ic_types::Height;
use std::path::PathBuf;

/// Loads the checkponts at `path_a` and `path_b` and diffs them.
fn diff_checkpoints(path_a: PathBuf, path_b: PathBuf) -> Result<Changes, CheckpointError> {
    let unused_height = Height::from(0);
    let own_subnet_type = SubnetType::Application;
    let dummy_metrics_registry = ic_metrics::MetricsRegistry::new();
    let dummy_metrics = CheckpointMetrics::new(&dummy_metrics_registry);
    let state_a = load_checkpoint(
        &CompleteCheckpointLayout::new(path_a, unused_height)?,
        own_subnet_type,
        &dummy_metrics,
        None,
    )?;
    let state_b = load_checkpoint(
        &CompleteCheckpointLayout::new(path_b, unused_height)?,
        own_subnet_type,
        &dummy_metrics,
        None,
    )?;

    let tree_a = hash_state(&state_a);
    let tree_b = hash_state(&state_b);
    Ok(diff(&tree_a, &tree_b))
}

/// `cdiff` command entry point.
pub fn do_diff(path_a: PathBuf, path_b: PathBuf) -> Result<(), String> {
    let d = diff_checkpoints(path_a, path_b).map_err(|err| format!("✗ Diff FAILED:\n\t{}", err))?;
    if d.is_empty() {
        println!("✓ Snapshots are identical");
    } else {
        print!("{}", PrettyPrintedChanges(&d));
    }

    Ok(())
}
