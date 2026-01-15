//! Computes diff of canonical trees between checkpoints.

use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::page_map::TestPageAllocatorFileDescriptorImpl;
use ic_state_layout::CompleteCheckpointLayout;
use ic_state_manager::{
    CheckpointError, CheckpointMetrics,
    checkpoint::load_checkpoint,
    tree_diff::{Changes, PrettyPrintedChanges, diff},
    tree_hash::hash_state,
};
use ic_types::Height;
use std::path::PathBuf;
use std::sync::Arc;

/// Loads the checkpoints at `path_a` and `path_b` and diffs them.
fn diff_checkpoints(path_a: PathBuf, path_b: PathBuf) -> Result<Changes, CheckpointError> {
    let unused_height = Height::from(0);
    let own_subnet_type = SubnetType::Application;
    let dummy_metrics_registry = ic_metrics::MetricsRegistry::new();
    let dummy_metrics = CheckpointMetrics::new(&dummy_metrics_registry, crate::commands::logger());
    let state_a = load_checkpoint(
        &CompleteCheckpointLayout::new_untracked(path_a, unused_height)?,
        own_subnet_type,
        &dummy_metrics,
        None,
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )?;
    let state_b = load_checkpoint(
        &CompleteCheckpointLayout::new_untracked(path_b, unused_height)?,
        own_subnet_type,
        &dummy_metrics,
        None,
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )?;

    let tree_a = hash_state(&state_a);
    let tree_b = hash_state(&state_b);
    Ok(diff(&tree_a, &tree_b))
}

/// `cdiff` command entry point.
pub fn do_diff(path_a: PathBuf, path_b: PathBuf) -> Result<(), String> {
    let d = diff_checkpoints(path_a, path_b).map_err(|err| format!("✗ Diff FAILED:\n\t{err}"))?;
    if d.is_empty() {
        println!("✓ Snapshots are identical");
    } else {
        print!("{}", PrettyPrintedChanges(&d));
    }

    Ok(())
}
