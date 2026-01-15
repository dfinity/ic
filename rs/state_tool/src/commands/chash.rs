//! Computes partial state hash that is used for certification.

use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::page_map::TestPageAllocatorFileDescriptorImpl;
use ic_state_layout::CompleteCheckpointLayout;
use ic_state_manager::{CheckpointMetrics, checkpoint::load_checkpoint, tree_hash::hash_state};
use ic_types::Height;
use std::path::PathBuf;
use std::sync::Arc;

/// Computes and prints partial state hash used for certification.
pub fn do_hash(path: PathBuf) -> Result<(), String> {
    let cp_layout = CompleteCheckpointLayout::new_untracked(path.clone(), Height::new(0))
        .map_err(|e| format!("failed to create checkpoint layout: {e}"))?;

    let dummy_metrics_registry = ic_metrics::MetricsRegistry::new();
    let dummy_metrics = CheckpointMetrics::new(&dummy_metrics_registry, crate::commands::logger());

    let state = load_checkpoint(
        &cp_layout,
        SubnetType::Application,
        &dummy_metrics,
        None,
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .map_err(|e| format!("failed to load checkpoint at {}: {}", path.display(), e))?;

    println!("PARTIAL STATE HASH: {}", hash_state(&state).digest());

    Ok(())
}
