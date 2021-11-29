//! Computes manifest of a checkpoint.

use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_state_layout::{CheckpointLayout, ReadOnly};
use ic_state_manager::{
    manifest::{compute_manifest, manifest_hash, DEFAULT_CHUNK_SIZE},
    ManifestMetrics,
};
use ic_types::Height;
use std::path::PathBuf;

/// Computes the manifest (chunk hashes, file hashes and root hash) of the
/// checkpoint rooted at `path`.
pub fn do_compute_manifest(path: PathBuf) -> Result<(), String> {
    let cp_layout = CheckpointLayout::<ReadOnly>::new(path, Height::new(0))
        .map_err(|e| format!("Failed to create checkpoint layout: {}", e))?;

    let metadata = cp_layout.system_metadata().deserialize().map_err(|e| {
        format!(
            "Failed to deserialize system metadata to determine the manifest version: {}",
            e
        )
    })?;

    let mut thread_pool =
        scoped_threadpool::Pool::new(ic_state_manager::NUMBER_OF_CHECKPOINT_THREADS);
    let metrics_registry = MetricsRegistry::new();
    let manifest_metrics = ManifestMetrics::new(&metrics_registry);
    let manifest = compute_manifest(
        &mut thread_pool,
        &manifest_metrics,
        &no_op_logger(),
        metadata.state_sync_version,
        cp_layout.raw_path(),
        DEFAULT_CHUNK_SIZE,
        None,
    )
    .map_err(|e| {
        format!(
            "Failed to compute manifest of checkpoint at {}: {}",
            cp_layout.raw_path().display(),
            e
        )
    })?;

    println!("{}", manifest);
    println!();
    println!("ROOT HASH: {}", hex::encode(manifest_hash(&manifest)));

    Ok(())
}
