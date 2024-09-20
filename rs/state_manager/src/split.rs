//! Prunes a replicated state, as part of a subnet split.
use crate::{
    checkpoint::{load_checkpoint, make_checkpoint},
    flush_canister_snapshots_and_page_maps,
    tip::spawn_tip_thread,
    StateManagerMetrics, NUMBER_OF_CHECKPOINT_THREADS,
};

use ic_base_types::CanisterId;
use ic_config::state_manager::Config;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{
    difference, CanisterIdRange, CanisterIdRanges, RoutingTable, WellFormedError,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    page_map::PageAllocatorFileDescriptor, page_map::TestPageAllocatorFileDescriptorImpl,
    ReplicatedState,
};
use ic_state_layout::{CheckpointLayout, ReadOnly, StateLayout};
use ic_types::{malicious_flags::MaliciousFlags, PrincipalId, SubnetId, Time};
use scoped_threadpool::Pool;
use std::{iter::once, path::PathBuf, sync::Arc};

#[cfg(test)]
mod tests;

/// Loads the latest checkpoint under the given root; splits off the state of
/// `subnet_id`, retaining or dropping the provided canister ID ranges (exactly
/// one of which must be non-empty); and writes back the split state as a new
/// checkpoint, under the same root.
pub fn resolve_ranges_and_split(
    root: PathBuf,
    subnet_id: PrincipalId,
    retain: Vec<CanisterIdRange>,
    drop: Vec<CanisterIdRange>,
    new_subnet_batch_time: Option<Time>,
    metrics_registry: &MetricsRegistry,
    log: ReplicaLogger,
) -> Result<(), String> {
    let canister_id_ranges = resolve(retain, drop).map_err(|e| format!("{:?}", e))?;

    split(
        root,
        subnet_id,
        canister_id_ranges,
        new_subnet_batch_time,
        metrics_registry,
        log,
    )
}

/// Loads the latest checkpoint under the given root; splits off the state of
/// `subnet_id`, hosting the provided canister ID ranges; and writes back the
/// split state as a new checkpoint, under the same root.
pub fn split(
    root: PathBuf,
    subnet_id: PrincipalId,
    canister_id_ranges: CanisterIdRanges,
    new_subnet_batch_time: Option<Time>,
    metrics_registry: &MetricsRegistry,
    log: ReplicaLogger,
) -> Result<(), String> {
    // Load latest checkpoint under `root`.
    let config = Config::new(root);
    let state_layout =
        StateLayout::try_new(log.clone(), config.state_root.clone(), metrics_registry).unwrap();

    // A thread pool to use for reading and writing checkpoints.
    let mut thread_pool = Pool::new(NUMBER_OF_CHECKPOINT_THREADS);

    // Create the file descriptor factory that is used to create files for PageMaps.
    let fd_factory: Arc<dyn PageAllocatorFileDescriptor> =
        Arc::new(TestPageAllocatorFileDescriptorImpl::new());

    let metrics = StateManagerMetrics::new(metrics_registry, log.clone());
    let (cp, state) = read_checkpoint(
        &state_layout,
        &mut thread_pool,
        fd_factory.clone(),
        &metrics,
    )?;

    // Set up the split.
    let subnet_id: SubnetId = subnet_id.into();
    let mut routing_table = RoutingTable::new();
    routing_table
        .assign_ranges(canister_id_ranges, subnet_id)
        .map_err(|e| format!("{:?}", e))?;

    // Split the state.
    let mut split_state = state.split(subnet_id, &routing_table, new_subnet_batch_time)?;

    // Write the split state as a new checkpoint.
    write_checkpoint(
        &mut split_state,
        state_layout,
        &cp,
        &mut thread_pool,
        fd_factory,
        &config,
        &metrics,
        log,
    )
}

/// Converts a pair of `retain` and `drop` range vectors (exactly one of which
/// is expected to be non-empty) into a well-formed [CanisterIdRanges] covering
/// all canisters to be retained. Returns an error if the provided inputs are
/// not well formed.
///
/// Panics if none or both of the inputs are empty.
fn resolve(
    retain: Vec<CanisterIdRange>,
    drop: Vec<CanisterIdRange>,
) -> Result<CanisterIdRanges, WellFormedError> {
    if !retain.is_empty() && drop.is_empty() {
        // Validate and return `retain`.
        CanisterIdRanges::try_from(retain)
    } else if retain.is_empty() && !drop.is_empty() {
        // Validate `drop` and return the diff between all possible canisters and it.
        let all_canister_ids = CanisterIdRange {
            start: CanisterId::from_u64(0),
            end: CanisterId::from_u64(u64::MAX),
        };
        difference(
            once(&all_canister_ids),
            CanisterIdRanges::try_from(drop)?.iter(),
        )
    } else {
        panic!("Expecting exactly one of `retain` and `drop` to be non-empty");
    }
}

/// Reads the `ReplicatedState` from the latest checkpoint under `state_layout`.
fn read_checkpoint(
    state_layout: &StateLayout,
    thread_pool: &mut Pool,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    metrics: &StateManagerMetrics,
) -> Result<(CheckpointLayout<ReadOnly>, ReplicatedState), String> {
    let height = *state_layout
        .checkpoint_heights()
        .map_err(|e| e.to_string())?
        .last()
        .ok_or(format!(
            "No checkpoints found at {}",
            state_layout.raw_path().display()
        ))?;
    let cp = state_layout
        .checkpoint_verified(height)
        .map_err(|e| e.to_string())?;

    let state = load_checkpoint(
        &cp,
        SubnetType::Application,
        &metrics.checkpoint_metrics,
        Some(thread_pool),
        fd_factory,
    )
    .map_err(|e| {
        format!(
            "Failed to load checkpoint at {}: {}",
            cp.raw_path().display(),
            e
        )
    })?;

    Ok((cp, state))
}

/// Writes the given `ReplicatedState` into a new checkpoint under
/// `state_layout`, based off of `old_cp`.
fn write_checkpoint(
    state: &mut ReplicatedState,
    state_layout: StateLayout,
    old_cp: &CheckpointLayout<ReadOnly>,
    thread_pool: &mut Pool,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    config: &Config,
    metrics: &StateManagerMetrics,
    log: ReplicaLogger,
) -> Result<(), String> {
    let old_height = old_cp.height();

    let mut tip_handler = state_layout.capture_tip_handler();
    tip_handler
        .reset_tip_to(
            &state_layout,
            old_cp,
            config.lsmt_config.lsmt_status,
            Some(thread_pool),
        )
        .map_err(|e| e.to_string())?;
    let (_tip_thread, tip_channel) = spawn_tip_thread(
        log,
        tip_handler,
        state_layout,
        config.lsmt_config.clone(),
        metrics.clone(),
        MaliciousFlags::default(),
    );

    let new_height = old_height.increment();

    // We need to flush to handle the deletion of canister snapshots.
    flush_canister_snapshots_and_page_maps(
        state,
        new_height,
        &tip_channel,
        &metrics.checkpoint_metrics,
    );

    make_checkpoint(
        state,
        new_height,
        &tip_channel,
        &metrics.checkpoint_metrics,
        thread_pool,
        fd_factory,
        config.lsmt_config.lsmt_status,
    )
    .map_err(|e| format!("Failed to write checkpoint: {}", e))?;

    Ok(())
}
