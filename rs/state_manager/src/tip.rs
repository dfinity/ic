use crate::{
    CRITICAL_ERROR_CHUNK_ID_USAGE_NEARING_LIMITS, CheckpointError, NUMBER_OF_CHECKPOINT_THREADS,
    PageMapType, SharedState, StateManagerMetrics,
    checkpoint::validate_and_finalize_checkpoint_and_remove_unverified_marker,
    compute_bundled_manifest,
    manifest::{BaseManifestInfo, RehashManifest},
    release_lock_and_persist_metadata,
    state_sync::types::{
        FILE_GROUP_CHUNK_ID_OFFSET, MANIFEST_CHUNK_ID_OFFSET, MAX_SUPPORTED_STATE_SYNC_VERSION,
    },
};
use crossbeam_channel::{Sender, bounded, unbounded};
use ic_base_types::subnet_id_into_protobuf;
use ic_config::state_manager::LsmtConfig;
use ic_logger::{ReplicaLogger, error, fatal, info, warn};
use ic_protobuf::state::{
    stats::v1::Stats,
    system_metadata::v1::{SplitFrom, SystemMetadata},
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::execution_state::SandboxMemory;
use ic_replicated_state::{
    CanisterState, NumWasmPages, PageMap, ReplicatedState,
    page_map::{PAGE_SIZE, StorageLayout},
};
use ic_replicated_state::{
    canister_snapshots::CanisterSnapshot,
    page_map::{MAX_NUMBER_OF_FILES, MergeCandidate, StorageMetrics, StorageResult},
};
use ic_replicated_state::{
    metadata_state::UnflushedCheckpointOp, page_map::PageAllocatorFileDescriptor,
};
use ic_state_layout::{
    CanisterSnapshotBits, CanisterStateBits, CheckpointLayout, ExecutionStateBits, PageMapLayout,
    ReadOnly, RwPolicy, StateLayout, TipHandler, WasmFile, error::LayoutError,
};
use ic_types::{CanisterId, Height, SnapshotId, malicious_flags::MaliciousFlags};
use ic_utils::thread::parallel_map;
use ic_utils_thread::JoinOnDrop;
use ic_wasm_types::{CanisterModule, ModuleLoadingStatus};
use prometheus::HistogramTimer;
use std::collections::BTreeSet;
use std::convert::identity;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Maximum amount of files per shard. If we exceed this number we merge regardless whether
/// we block checkpointing for the merge duration.
/// If we don't reach the MERGE_SOFT_BUDGET_BYTES, the number of files should not exceed
/// MAX_NUMBER_OF_FILES + 8, since we add at most 2 overlays per checkpoint and iterate over all
/// shards in 4 checkpoints at most.
const NUMBER_OF_FILES_HARD_LIMIT: usize = 20;

const GIB: u64 = 1024 * 1024 * 1024;

/// Maximum amount of data we can safely write during merge without expecting blocking of
/// checkpointing.
const MERGE_SOFT_BUDGET_BYTES: u64 = 250 * GIB;

#[derive(Clone, Debug, Default)]
struct CheckpointState {
    // Latest height of the pagemaps update; Height(0) is always present as the default state.
    page_maps_height: Height,
    has_protos: Option<Height>,
    has_filtered_canisters: bool,
    verified: bool,
    has_manifest: bool,
}

#[derive(Debug, Default)]
struct TipState {
    tip_folder_state: CheckpointState,
    latest_checkpoint_state: CheckpointState,
}

/// A single pagemap to truncate and/or flush.
pub(crate) struct PageMapToFlush {
    pub page_map_type: PageMapType,
    pub truncate: bool,
    pub page_map: Option<PageMap>,
}

/// Request for the Tip directory handling thread.
#[allow(clippy::large_enum_variant)]
pub(crate) enum TipRequest {
    /// Create checkpoint from the current tip for the given height.
    ///
    /// Sends the created checkpoint and the ReplicatedState switched to the
    /// checkpoint or error into the sender.
    /// Serializes protos to the newly created checkpoint after sending to `sender`.
    ///
    /// State:
    /// ```text
    ///     latest_checkpoint_state = tip_folder_state
    ///     tip_folder_state = default
    /// ```
    TipToCheckpointAndSwitch {
        height: Height,
        state: ReplicatedState,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
        #[allow(clippy::type_complexity)]
        sender: Sender<
            Result<
                (Arc<ReplicatedState>, CheckpointLayout<ReadOnly>),
                Box<dyn std::error::Error + Send>,
            >,
        >,
    },
    /// Filter canisters and snapshots in tip. Remove ones not present in the sets.
    ///
    /// State: `tip_folder_state.has_filtered_canisters = true`
    FilterTipCanisters {
        height: Height,
        canister_ids: BTreeSet<CanisterId>,
        snapshot_ids: BTreeSet<SnapshotId>,
    },
    /// Flush PageMaps's unflushed delta on disc.
    ///
    /// State: `tip_folder_state.has_pagemaps = Some(height)`
    FlushPageMapDelta {
        height: Height,
        pagemaps: Vec<PageMapToFlush>,
        unflushed_checkpoint_ops: Vec<UnflushedCheckpointOp>,
    },
    /// Reset tip folder to the checkpoint with given height.
    /// Merge overlays in tip folder if necessary.
    ///
    /// State: `tip_folder_state = latest_checkpoint_state`
    ResetTipAndMerge {
        checkpoint_layout: CheckpointLayout<ReadOnly>,
        pagemaptypes: Vec<PageMapType>,
    },
    /// Compute manifest, store result into states and persist metadata as result.
    ///
    /// State: `latest_checkpoint_state.has_manifest = true`
    ComputeManifest {
        checkpoint_layout: CheckpointLayout<ReadOnly>,
        base_manifest_info: Option<crate::manifest::BaseManifestInfo>,
        states: Arc<parking_lot::RwLock<SharedState>>,
        persist_metadata_guard: Arc<Mutex<()>>,
    },
    /// Validate the checkpointed state is valid and identical to the execution state.
    /// Crash if diverges.
    ///
    /// State: `latest_checkpoint_state.verified = true`
    ValidateReplicatedStateAndFinalize {
        checkpoint_layout: CheckpointLayout<ReadOnly>,
        reference_state: Arc<ReplicatedState>,
        own_subnet_type: SubnetType,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    },
    /// Wait for the message to be executed and notify back via sender.
    ///
    /// State: `*`
    Wait { sender: Sender<()> },
}

fn request_timer(metrics: &StateManagerMetrics, name: &str) -> HistogramTimer {
    metrics
        .checkpoint_metrics
        .tip_handler_request_duration
        .with_label_values(&[name])
        .start_timer()
}

pub(crate) fn flush_tip_channel(tip_channel: &Sender<TipRequest>) {
    let (sender, recv) = bounded(1);
    tip_channel
        .send(TipRequest::Wait { sender })
        .expect("failed to send TipHandler Wait message");
    recv.recv().expect("failed to wait for TipHandler thread");
}

pub(crate) fn spawn_tip_thread(
    log: ReplicaLogger,
    mut tip_handler: TipHandler,
    state_layout: StateLayout,
    lsmt_config: LsmtConfig,
    metrics: StateManagerMetrics,
    malicious_flags: MaliciousFlags,
) -> (JoinOnDrop<()>, Sender<TipRequest>) {
    #[allow(clippy::disallowed_methods)]
    let (tip_sender, tip_receiver) = unbounded();
    let mut thread_pool = scoped_threadpool::Pool::new(NUMBER_OF_CHECKPOINT_THREADS);
    let mut tip_state = TipState::default();
    // Height(0) doesn't need manifest
    tip_state.latest_checkpoint_state.has_manifest = true;
    let mut rehash_divergence = false;
    let tip_handle = JoinOnDrop::new(
        std::thread::Builder::new()
            .name("TipThread".to_string())
            .spawn(move || {
                while let Ok(req) = tip_receiver.recv() {
                    match req {
                        TipRequest::FilterTipCanisters {
                            height,
                            canister_ids,
                            snapshot_ids,
                        } => {
                            let _timer = request_timer(&metrics, "filter_tip_canisters");
                            debug_assert!(!tip_state.tip_folder_state.has_filtered_canisters);
                            tip_state.tip_folder_state.has_filtered_canisters = true;
                            tip_handler
                                .filter_tip_canisters(height, &canister_ids)
                                .unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to filter tip canisters for height @{}: {}",
                                        height,
                                        err
                                    )
                                });
                            tip_handler
                                .filter_tip_snapshots(height, &snapshot_ids)
                                .unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to filter tip snapshots for height @{}: {}",
                                        height,
                                        err
                                    )
                                });
                        }

                        TipRequest::TipToCheckpointAndSwitch {
                            height,
                            state,
                            fd_factory,
                            sender,
                        } => {
                            debug_assert!(tip_state.latest_checkpoint_state.has_manifest);
                            debug_assert_eq!(tip_state.tip_folder_state.page_maps_height, height);
                            debug_assert!(tip_state.tip_folder_state.has_filtered_canisters);
                            // Snapshots and other unflushed changed should have been handled earlier in `flush_canister_snapshots_and_page_maps `.
                            debug_assert!(state.metadata.unflushed_checkpoint_ops.is_empty());
                            tip_state.latest_checkpoint_state = tip_state.tip_folder_state;
                            tip_state.tip_folder_state = Default::default();
                            {
                                let _timer =
                                    request_timer(&metrics, "serialize_wasm_binaries_and_pagemaps");
                                serialize_wasm_binaries_and_pagemaps(
                                    &state,
                                    &tip_handler.tip(height).unwrap(),
                                    &mut thread_pool,
                                    &lsmt_config,
                                    &metrics.storage_metrics,
                                )
                                .unwrap_or_else(|err| {
                                    fatal!(log, "Failed to serialize to tip @{}: {}", height, err);
                                });
                            }
                            let tip_to_checkpoint_result = {
                                let _timer =
                                    request_timer(&metrics, "tip_to_checkpoint_and_switch");
                                tip_to_checkpoint_and_switch(
                                    &log,
                                    &mut tip_handler,
                                    &state_layout,
                                    height,
                                    state,
                                    &fd_factory,
                                )
                            };
                            match tip_to_checkpoint_result {
                                Err(err) => {
                                    sender
                                        .send(Err(err))
                                        .expect("Failed to send TipToCheckpointAndSwitch result");
                                }
                                Ok(result) => {
                                    sender
                                        .send(Ok((
                                            Arc::clone(&result.state),
                                            result.checkpoint_readonly,
                                        )))
                                        .expect("Failed to send TipToCheckpointAndSwitch result");
                                    if let Some(checkpoint_readwrite) = result.checkpoint_readwrite
                                    {
                                        let _timer = request_timer(
                                            &metrics,
                                            "serialize_protos_to_checkpoint_readwrite",
                                        );
                                        serialize_protos_to_checkpoint_readwrite(
                                            &result.state,
                                            &checkpoint_readwrite,
                                            &mut thread_pool,
                                        )
                                        .unwrap_or_else(
                                            |err| {
                                                fatal!(
                                                    log,
                                                    "Failed to serialize protos to cp @{}: {}",
                                                    height,
                                                    err
                                                );
                                            },
                                        );
                                    }
                                }
                            };
                            tip_state.latest_checkpoint_state.has_protos = Some(height);
                        }

                        TipRequest::FlushPageMapDelta {
                            height,
                            pagemaps,
                            unflushed_checkpoint_ops,
                        } => {
                            let _timer = request_timer(&metrics, "flush_unflushed_delta");
                            debug_assert!(tip_state.tip_folder_state.page_maps_height <= height);
                            tip_state.tip_folder_state.page_maps_height = height;

                            // We flush snapshots and canister renamings to disk first.
                            flush_unflushed_checkpoint_ops(
                                &log,
                                &mut tip_handler,
                                height,
                                unflushed_checkpoint_ops,
                            )
                            .unwrap_or_else(|err| {
                                fatal!(log, "Failed to flush snapshot changes: {}", err);
                            });

                            let layout = &tip_handler.tip(height).unwrap_or_else(|err| {
                                fatal!(
                                    log,
                                    "Failed to get tip @{} to serialize to: {}",
                                    height,
                                    err
                                );
                            });

                            parallel_map(
                                &mut thread_pool,
                                pagemaps.into_iter(),
                                |PageMapToFlush {
                                     page_map_type,
                                     truncate,
                                     page_map,
                                 }| {
                                    let page_map_layout =
                                        page_map_type.layout(layout).unwrap_or_else(|err| {
                                            fatal!(
                                                log,
                                                "Failed to get layout for {:?}: {}",
                                                page_map_type,
                                                err
                                            );
                                        });
                                    if *truncate {
                                        page_map_layout.delete_files().unwrap_or_else(|err| {
                                            fatal!(
                                                log,
                                                "Failed to delete files for {:#?}: {}",
                                                page_map_type,
                                                err
                                            )
                                        });
                                    }
                                    if page_map.is_some()
                                        && !page_map.as_ref().unwrap().unflushed_delta_is_empty()
                                    {
                                        page_map
                                            .as_ref()
                                            .unwrap()
                                            .persist_unflushed_delta(
                                                &page_map_layout,
                                                height,
                                                &lsmt_config,
                                                &metrics.storage_metrics,
                                            )
                                            .unwrap_or_else(|err| {
                                                fatal!(
                                                    log,
                                                    "Failed to persist unflushed delta: {}",
                                                    err
                                                );
                                            });
                                    }
                                },
                            );
                        }

                        TipRequest::ResetTipAndMerge {
                            checkpoint_layout,
                            pagemaptypes,
                        } => {
                            let timer = request_timer(&metrics, "reset_tip_to");
                            tip_state.tip_folder_state = Default::default();
                            tip_state.tip_folder_state.page_maps_height =
                                tip_state.latest_checkpoint_state.page_maps_height;
                            let height = checkpoint_layout.height();
                            tip_handler
                                .reset_tip_to(
                                    &state_layout,
                                    &checkpoint_layout,
                                    Some(&mut thread_pool),
                                )
                                .unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to reset tip to height @{}: {}",
                                        height,
                                        err
                                    );
                                });
                            drop(timer);

                            let _timer = request_timer(&metrics, "merge");
                            merge(
                                &mut tip_handler,
                                &pagemaptypes,
                                height,
                                &mut thread_pool,
                                &log,
                                &lsmt_config,
                                &metrics,
                            );
                        }

                        TipRequest::Wait { sender } => {
                            let _timer = request_timer(&metrics, "wait");
                            let _ = sender.send(());
                        }

                        TipRequest::ComputeManifest {
                            checkpoint_layout,
                            base_manifest_info,
                            states,
                            persist_metadata_guard,
                        } => {
                            let _timer = request_timer(&metrics, "compute_manifest_total");
                            if let Some(base_manifest_info) = &base_manifest_info {
                                info!(
                                    log,
                                    "Computing manifest for checkpoint @{} incrementally \
                                        from checkpoint @{}",
                                    checkpoint_layout.height(),
                                    base_manifest_info.base_height
                                );
                            } else {
                                info!(
                                    log,
                                    "Computing manifest for checkpoint @{} from scratch",
                                    checkpoint_layout.height()
                                );
                            }
                            tip_state.latest_checkpoint_state.has_manifest = true;
                            handle_compute_manifest_request(
                                &mut thread_pool,
                                &metrics,
                                &log,
                                &states,
                                &state_layout,
                                &checkpoint_layout,
                                base_manifest_info,
                                &persist_metadata_guard,
                                &malicious_flags,
                                &mut rehash_divergence,
                            );
                            tip_state.latest_checkpoint_state.has_manifest = true;
                        }
                        TipRequest::ValidateReplicatedStateAndFinalize {
                            checkpoint_layout,
                            reference_state,
                            own_subnet_type,
                            fd_factory,
                        } => {
                            let _timer =
                                request_timer(&metrics, "validate_replicated_state_and_finalize");
                            let start = Instant::now();
                            debug_assert_eq!(
                                tip_state.latest_checkpoint_state.page_maps_height,
                                checkpoint_layout.height()
                            );
                            debug_assert_eq!(
                                tip_state.latest_checkpoint_state.has_protos,
                                Some(checkpoint_layout.height())
                            );
                            tip_state.latest_checkpoint_state.verified = true;

                            if let Err(err) =
                                validate_and_finalize_checkpoint_and_remove_unverified_marker(
                                    &checkpoint_layout,
                                    Some(reference_state.deref()),
                                    own_subnet_type,
                                    Arc::clone(&fd_factory),
                                    &metrics.checkpoint_metrics,
                                    Some(&mut thread_pool),
                                )
                            {
                                fatal!(
                                    &log,
                                    "Checkpoint validation for {} has failed: {:#}",
                                    checkpoint_layout.raw_path().display(),
                                    err
                                )
                            }
                            info!(
                                log,
                                "Validated checkpoint @{} in {:?}",
                                checkpoint_layout.height(),
                                start.elapsed()
                            );
                        }
                    }
                }
            })
            .expect("failed to spawn tip thread"),
    );
    (tip_handle, tip_sender)
}

struct TipToCheckpointResult<'a, T> {
    state: Arc<ReplicatedState>,
    checkpoint_readonly: CheckpointLayout<ReadOnly>,
    // Checkpoint to serialize protos to. None if we don't need to serialize protos, i.e. in case of AlreadyExists
    checkpoint_readwrite: Option<CheckpointLayout<RwPolicy<'a, T>>>,
}

fn tip_to_checkpoint_and_switch<'a>(
    log: &ReplicaLogger,
    tip_handler: &'a mut TipHandler,
    state_layout: &'a StateLayout,
    height: Height,
    mut state: ReplicatedState,
    fd_factory: &Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<TipToCheckpointResult<'a, TipHandler>, Box<dyn std::error::Error + Send>> {
    let tip = tip_handler.tip(height).unwrap();

    match state_layout.promote_scratchpad_to_unverified_checkpoint(tip, height) {
        Ok(checkpoint_readwrite) => {
            let checkpoint_readonly = checkpoint_readwrite.as_readonly();
            switch_to_checkpoint(&mut state, &checkpoint_readonly, fd_factory)?;
            Ok(TipToCheckpointResult::<'a, TipHandler> {
                state: Arc::new(state),
                checkpoint_readonly: checkpoint_readwrite.as_readonly(),
                checkpoint_readwrite: Some(checkpoint_readwrite),
            })
        }

        Err(LayoutError::AlreadyExists(_)) => {
            warn!(
                log,
                "Failed to create checkpoint @{} because it already exists, \
                     re-loading the checkpoint from disk",
                height
            );

            let checkpoint_layout = state_layout
                .checkpoint_in_verification(height)
                .unwrap_or_else(|err| {
                    fatal!(log, "Failed to open checkpoint layout #{}: {}", height, err);
                });
            switch_to_checkpoint(&mut state, &checkpoint_layout, fd_factory)?;
            Ok(TipToCheckpointResult {
                state: Arc::new(state),
                checkpoint_readonly: checkpoint_layout,
                checkpoint_readwrite: None,
            })
        }
        Err(err) => Err(Box::new(err)),
    }
}

/// Switches `tip` to the most recent checkpoint file provided by `layout`.
///
/// Preconditions:
/// 1) `tip` and `layout` mut have exactly the same set of canisters.
/// 2) The page deltas must be empty in `tip`
/// 3) The memory sizes must match.
fn switch_to_checkpoint(
    tip: &mut ReplicatedState,
    layout: &CheckpointLayout<ReadOnly>,
    fd_factory: &Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<(), Box<dyn std::error::Error + Send>> {
    for (tip_id, tip_canister) in tip.canister_states.iter_mut() {
        let canister_layout = layout.canister(tip_id).unwrap();
        tip_canister
            .system_state
            .wasm_chunk_store
            .page_map_mut()
            .switch_to_checkpoint(
                &PageMap::open(
                    Box::new(canister_layout.wasm_chunk_store()),
                    layout.height(),
                    Arc::clone(fd_factory),
                )
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send>)?,
            );

        if let Some(tip_execution) = tip_canister.execution_state.as_mut() {
            tip_execution.wasm_memory.page_map.switch_to_checkpoint(
                &PageMap::open(
                    Box::new(canister_layout.vmemory_0()),
                    layout.height(),
                    Arc::clone(fd_factory),
                )
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send>)?,
            );
            tip_execution.stable_memory.page_map.switch_to_checkpoint(
                &PageMap::open(
                    Box::new(canister_layout.stable_memory()),
                    layout.height(),
                    Arc::clone(fd_factory),
                )
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send>)?,
            );
        }
    }

    for (tip_id, tip_snapshot) in tip.canister_snapshots.iter_mut() {
        let new_snapshot = Arc::make_mut(tip_snapshot);
        let snapshot_layout = layout.snapshot(tip_id).unwrap();

        new_snapshot
            .chunk_store_mut()
            .page_map_mut()
            .switch_to_checkpoint(
                &PageMap::open(
                    Box::new(snapshot_layout.wasm_chunk_store()),
                    layout.height(),
                    Arc::clone(fd_factory),
                )
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send>)?,
            );

        new_snapshot
            .execution_snapshot_mut()
            .wasm_memory
            .page_map
            .switch_to_checkpoint(
                &PageMap::open(
                    Box::new(snapshot_layout.vmemory_0()),
                    layout.height(),
                    Arc::clone(fd_factory),
                )
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send>)?,
            );
        new_snapshot
            .execution_snapshot_mut()
            .stable_memory
            .page_map
            .switch_to_checkpoint(
                &PageMap::open(
                    Box::new(snapshot_layout.stable_memory()),
                    layout.height(),
                    Arc::clone(fd_factory),
                )
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send>)?,
            );

        let new_snapshot_wasm_binary = &new_snapshot.execution_snapshot().wasm_binary;
        let wasm_binary = snapshot_layout
            .wasm()
            .lazy_load_with_module_hash(
                new_snapshot_wasm_binary.module_hash().into(),
                Some(new_snapshot_wasm_binary.len()),
            )
            .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send>)?;
        debug_assert_eq!(
            wasm_binary.module_loading_status(),
            ModuleLoadingStatus::FileNotLoaded
        );
        new_snapshot.execution_snapshot_mut().wasm_binary = wasm_binary;
    }

    for (tip_id, tip_canister) in tip.canister_states.iter_mut() {
        if let Some(tip_state) = &mut tip_canister.execution_state {
            let canister_layout = layout.canister(tip_id).unwrap();

            // We can reuse the cache because the Wasm binary has the same
            // contents, only the storage of that binary changed.
            let embedder_cache = Arc::clone(&tip_state.wasm_binary.embedder_cache);
            let tip_state_wasm_binary = &tip_state.wasm_binary.binary;
            let wasm_binary = canister_layout
                .wasm()
                .lazy_load_with_module_hash(
                    tip_state_wasm_binary.module_hash().into(),
                    Some(tip_state_wasm_binary.len()),
                )
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send>)?;
            debug_assert_eq!(
                tip_state.wasm_binary.binary.as_slice(),
                canister_layout
                    .wasm()
                    .lazy_load_with_module_hash(
                        tip_state.wasm_binary.binary.module_hash().into(),
                        Some(tip_state_wasm_binary.len())
                    )
                    .unwrap()
                    .as_slice()
            );

            debug_assert_eq!(
                wasm_binary.module_loading_status(),
                ModuleLoadingStatus::FileNotLoaded
            );
            tip_state.wasm_binary = Arc::new(
                ic_replicated_state::canister_state::execution_state::WasmBinary {
                    binary: wasm_binary,
                    embedder_cache,
                },
            );

            // Reset the sandbox state to force full synchronization on the next message
            // execution because the checkpoint file of `tip` has changed.
            tip_state.wasm_memory.sandbox_memory = SandboxMemory::new();
            tip_state.stable_memory.sandbox_memory = SandboxMemory::new();
        }
    }
    Ok(())
}

/// Update the tip directory files with the most recent checkpoint operations.
/// `operations` is an ordered list of all created/restored snapshots and renamed canisters since the last flush.
fn flush_unflushed_checkpoint_ops(
    log: &ReplicaLogger,
    tip_handler: &mut TipHandler,
    height: Height,
    operations: Vec<UnflushedCheckpointOp>,
) -> Result<(), LayoutError> {
    // This loop is not parallelized as there are combinations such as creating then restoring from a snapshot within the same flush.
    for op in operations {
        match op {
            UnflushedCheckpointOp::TakeSnapshot(canister_id, snapshot_id) => {
                backup(log, &tip_handler.tip(height)?, canister_id, snapshot_id)?;
            }
            UnflushedCheckpointOp::LoadSnapshot(canister_id, snapshot_id) => {
                restore(log, &tip_handler.tip(height)?, canister_id, snapshot_id)?;
            }
            UnflushedCheckpointOp::RenameCanister(src, dst) => {
                tip_handler.move_canister_directory(height, src, dst)?;
            }
        }
    }

    Ok(())
}

/// Represent a backup operation on disk.
/// When a backup is triggered, execution creates a `CanisterSnapshot` where all the `PageMaps` as well as the wasm binary
/// is a copy of the canister's at the time of the backup.
/// This function will run at an unspecified point afterwards (but before the next checkpoint) and it copies all files the canister had in the tip
/// to the snapshot directory.
/// Note that a `PageMap` might have had unflushed deltas at the point of the backup, which we later flush as part of `FlushPageMapDelta` on top of
/// the files we copy here.
fn backup<T>(
    log: &ReplicaLogger,
    layout: &CheckpointLayout<RwPolicy<T>>,
    canister_id: CanisterId,
    snapshot_id: SnapshotId,
) -> Result<(), LayoutError> {
    let canister_layout = layout.canister(&canister_id)?;
    let snapshot_layout = layout.snapshot(&snapshot_id)?;

    PageMapLayout::copy_or_hardlink_files(
        log,
        &canister_layout.vmemory_0(),
        &snapshot_layout.vmemory_0(),
    )?;
    PageMapLayout::copy_or_hardlink_files(
        log,
        &canister_layout.stable_memory(),
        &snapshot_layout.stable_memory(),
    )?;
    PageMapLayout::copy_or_hardlink_files(
        log,
        &canister_layout.wasm_chunk_store(),
        &snapshot_layout.wasm_chunk_store(),
    )?;

    WasmFile::hardlink_file(&canister_layout.wasm(), &snapshot_layout.wasm())?;

    Ok(())
}

/// Represent a restore operation on disk.
/// When a restore is triggered, execution creates a `CanisterState` from a `CanisterSnapshot` by copying all its `PageMaps` as well as its wasm binary.
/// This function will run at an unspecified point afterwards (but before the next checkpoint) and it copies all files the snapshot had in the tip
/// to the canister directory, deleting what was there before.
fn restore<T>(
    log: &ReplicaLogger,
    layout: &CheckpointLayout<RwPolicy<T>>,
    canister_id: CanisterId,
    snapshot_id: SnapshotId,
) -> Result<(), LayoutError> {
    let canister_layout = layout.canister(&canister_id)?;
    let snapshot_layout = layout.snapshot(&snapshot_id)?;

    canister_layout.vmemory_0().delete_files()?;
    PageMapLayout::copy_or_hardlink_files(
        log,
        &snapshot_layout.vmemory_0(),
        &canister_layout.vmemory_0(),
    )?;
    canister_layout.stable_memory().delete_files()?;
    PageMapLayout::copy_or_hardlink_files(
        log,
        &snapshot_layout.stable_memory(),
        &canister_layout.stable_memory(),
    )?;
    canister_layout.wasm_chunk_store().delete_files()?;
    PageMapLayout::copy_or_hardlink_files(
        log,
        &snapshot_layout.wasm_chunk_store(),
        &canister_layout.wasm_chunk_store(),
    )?;

    canister_layout.wasm().try_delete_file()?;
    WasmFile::hardlink_file(&snapshot_layout.wasm(), &canister_layout.wasm())?;

    Ok(())
}

struct StorageInfo {
    disk_size: u64,
    mem_size: u64,
}

impl StorageInfo {
    fn add(&self, rhs: &StorageInfo) -> StorageInfo {
        StorageInfo {
            disk_size: self.disk_size + rhs.disk_size,
            mem_size: self.mem_size + rhs.mem_size,
        }
    }
}

fn merge_candidates_and_storage_info(
    tip_handler: &mut TipHandler,
    pagemaptypes: &[PageMapType],
    height: Height,
    thread_pool: &mut scoped_threadpool::Pool,
    lsmt_config: &LsmtConfig,
    metrics: &StateManagerMetrics,
) -> StorageResult<(Vec<MergeCandidate>, StorageInfo)> {
    let _timer = request_timer(metrics, "merge_candidates_and_storage_info");
    let layout = &tip_handler
        .tip(height)
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send>)?;
    let merge_candidates_with_storage_info: Vec<StorageResult<(Vec<MergeCandidate>, StorageInfo)>> =
        parallel_map(
            thread_pool,
            pagemaptypes.iter(),
            |page_map_type| -> StorageResult<(Vec<MergeCandidate>, StorageInfo)> {
                let mut storage_info = StorageInfo {
                    disk_size: 0,
                    mem_size: 0,
                };
                let pm_layout = page_map_type
                    .layout(layout)
                    .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send>)?;
                storage_info.disk_size +=
                    (&pm_layout as &dyn StorageLayout).storage_size_bytes()?;
                let num_pages = (&pm_layout as &dyn StorageLayout).memory_size_pages()?;
                storage_info.mem_size += (num_pages * PAGE_SIZE) as u64;
                Ok((
                    MergeCandidate::new(
                        &pm_layout,
                        height,
                        num_pages as u64,
                        lsmt_config,
                        &metrics.storage_metrics,
                    )?,
                    storage_info,
                ))
            },
        );
    let mut merge_candidates = Vec::new();
    let mut storage_info = StorageInfo {
        disk_size: 0,
        mem_size: 0,
    };
    for merge_candidate_with_storage_info in merge_candidates_with_storage_info.into_iter() {
        let mut merge_candidate_with_storage_info = merge_candidate_with_storage_info?;
        merge_candidates.append(&mut merge_candidate_with_storage_info.0);
        storage_info = storage_info.add(&merge_candidate_with_storage_info.1);
    }
    Ok((merge_candidates, storage_info))
}

/// Merge excessive overlays.
///
/// We want to achieve two metrics:
///     1) Total overhead, that is total_size_on_disk / total_size_of_pages_in_pagemaps to be at
///        most 2.5
///     We don't cap overhead of an individual pagemap.
///     2) Number of files in each pagemap to be not too high.
/// Moreover, we don't want to throttle execution. For example, if we have exactly the same load
/// pattern in many canisters, we don't want to merge all the data for all the canisters in the
/// same checkpoint interval but rather to spread the load. The heaviest operation for the system
/// is flushing data to disk, so we try to cap it.
/// We need the merge to be deterministic, i.e. any two instances of the subnet must have exactly
/// the same layout for all pagemaps.
///
///
/// First, sort the vector of MergeCandidates by decreasing `num_files_before`. Schedule for
/// merging the head of the sorted vector, which contains either all MergeCandidates with more than
/// Storage::MAX_NUMBER_OF_FILES or top ones till accumulated write_size_bytes is more than one
/// quarter of `sum(storage_size_bytes_before)`. This way we iterate through all page maps with more
/// than MAX_NUMBER_OF_FILES at most in 4 checkpoint intervals, provided we don't reach MERGE_SOFT_BUDGET_BYTES.
/// Since we produce at most 2 overlays per checkpoint per `PageMap`, we have a cap of
/// `MAX_NUMBER_OF_FILES` + 2 * 4 files per `PageMap` at any checkpoint.
///
/// Then we need to take care of storage overhead. Storage overhead is the ratio
/// `sum(storage_size_bytes_after)` / `sum(page_map_size_bytes)`. In other words, we need
/// `sum(storage_size_bytes_after)` to become <= 2.5 * `sum(page_map_size_bytes)`.
/// Note, that after applying merge any `PageMap` reaches overhead of at most 2.0. This is
/// guaranteed by the `MergeCandidate::new` logic. So we need to schedule enough merge candidates
/// till our overhead goal is met.
/// We already have some merges scheduled that potentially reduce overhead. We calculate the
/// storage size that is going to be after we apply them. If it's more than
/// 2.5 * `sum(page_map_size_bytes)` we extend our list of scheduled merges starting with lowest
/// hanging fruits, that is MergeCandidates with highest
/// (`storage_size_bytes_before` - `storage_size_bytes_after`) / `write_size_bytes`.
///
/// Write size calculation.
/// The merges for number of files are at most 1/4 of allowed state size, capped by MERGE_SOFT_LIMIT_BYTES.
/// Merges for overhead have input with overhead >= 2.5 and output being == 1.0. Meaning by writing
/// 1 MiB to disk during merge, we replace what used to be >= 2.5 MiB on disk with 1 MiB.
/// In other words, 1 MiB of write during merge reduces storage by at least 1.5 MiB.
/// Let's say last checkpoint was 100 GiB of state size with the max overhead, meaning storage size
/// is 250 GiB. During the checkpoint interval we flushed 60 GiB of page delta, now the state size is
/// 310 GiB and the overhead is 3.1. We need to reduce the storage by 60 GiB. We need to write at
/// most 60 GiB / 1.5 = 40 GiB in order to achieve it, with some round off error for a canister
/// size.
/// For a more general estimate, the data written to disk during checkpoint interval is at most
/// max_dirty_pages, meaning we need to write max_dirty_pages / 1.5 + one canister size to reduce
/// the overhead under 2.5 again.
/// The total write is at most
/// min(MERGE_SOFT_BUDGET_BYTES, 1/4 state size) + 2/3 * max_dirty_pages + the size of the last`PageMap`.
/// Note that if canisters are removed, upgraded, or otherwise delete data, this can
/// further increase the amount of data written in order to enforce the storage overhead.
fn merge(
    tip_handler: &mut TipHandler,
    pagemaptypes: &[PageMapType],
    height: Height,
    thread_pool: &mut scoped_threadpool::Pool,
    log: &ReplicaLogger,
    lsmt_config: &LsmtConfig,
    metrics: &StateManagerMetrics,
) {
    // We have a merge candidate for each shard, unless no merge is needed, i. e.
    //   1) Shard forms a pyramid (hence overhead < 2.0)
    //   and
    //   2) number of files is <= MAX_NUMBER_OF_FILES
    let (mut merge_candidates, storage_info) = merge_candidates_and_storage_info(
        tip_handler,
        pagemaptypes,
        height,
        thread_pool,
        lsmt_config,
        metrics,
    )
    .unwrap_or_else(|err| {
        fatal!(log, "Failed to get MergeCandidateAndMetrics: {}", err);
    });

    // Max 2.5 overhead
    let max_storage = storage_info.mem_size * 2 + storage_info.mem_size / 2;

    merge_candidates.sort_by_key(|m| -(m.num_files_before() as i64));
    let storage_to_merge_for_filenum =
        std::cmp::min(MERGE_SOFT_BUDGET_BYTES, storage_info.mem_size / 4);
    let min_storage_to_merge = storage_info.mem_size / 50;
    let merges_by_filenum = merge_candidates
        .iter()
        .scan(0, |state, m| {
            if (*state >= storage_to_merge_for_filenum
                && m.num_files_before() <= NUMBER_OF_FILES_HARD_LIMIT as u64)
                || (m.num_files_before() <= MAX_NUMBER_OF_FILES as u64
                    && (*state + m.page_map_size_bytes() >= min_storage_to_merge))
            {
                None
            } else {
                *state += m.page_map_size_bytes();
                Some(())
            }
        })
        .count();

    // [0; merges_by_filenum) are already scheduled, some of the rest may be necessary to achieve
    // low enough overhead.
    let mut scheduled_merges = merge_candidates;
    let mut merge_candidates = scheduled_merges.split_off(merges_by_filenum);

    // Sort by ratio of saved bytes to write size.
    merge_candidates.sort_by_key(|m| {
        if m.write_size_bytes() != 0 {
            // Fixed point to compute overhead ratio for sort.
            -1000i64 * (m.storage_size_bytes_before() as i64 - m.storage_size_bytes_after() as i64)
                / m.write_size_bytes() as i64
        } else {
            0
        }
    });
    let storage_to_save = storage_info.disk_size as i64 - max_storage as i64;
    // For a full merge the resulting base file can be larger than sum of the overlays,
    // so we need a signed accumulator.
    let mut storage_saved: i64 = scheduled_merges
        .iter()
        .map(|m| m.storage_size_bytes_before() as i64 - m.storage_size_bytes_after() as i64)
        .sum();
    let mut merges_by_storage = 0;
    for m in merge_candidates.into_iter() {
        if storage_saved >= storage_to_save {
            break;
        }

        storage_saved += m.storage_size_bytes_before() as i64 - m.storage_size_bytes_after() as i64;
        merges_by_storage += 1;
        // Only full merges reduce overhead, and there should be enough of them to reach
        // `storage_to_save` before tapping into partial merges.
        debug_assert!(m.is_full_merge());
        scheduled_merges.push(m);
    }
    info!(
        log,
        "Merging {} PageMaps out of {}; mem_size: {}; disk_size: {}; max_storage: {}, storage_saves: {}, merges_by_filenum: {}",
        scheduled_merges.len(),
        pagemaptypes.len(),
        storage_info.mem_size,
        storage_info.disk_size,
        max_storage,
        storage_saved,
        merges_by_filenum,
    );

    metrics
        .merge_metrics
        .disk_size_bytes
        .set(storage_info.disk_size as i64);
    metrics
        .merge_metrics
        .memory_size_bytes
        .set(storage_info.mem_size as i64);
    metrics
        .merge_metrics
        .estimated_storage_savings_bytes
        .observe(storage_saved as f64);
    metrics
        .merge_metrics
        .num_page_maps_merged
        .with_label_values(&["file_num"])
        .observe(merges_by_filenum as f64);
    metrics
        .merge_metrics
        .num_page_maps_merged
        .with_label_values(&["storage"])
        .observe(merges_by_storage as f64);

    parallel_map(thread_pool, scheduled_merges.iter(), |m| {
        m.apply(&metrics.storage_metrics)
    });
}

fn serialize_protos_to_checkpoint_readwrite(
    state: &ReplicatedState,
    checkpoint_readwrite: &CheckpointLayout<RwPolicy<TipHandler>>,
    thread_pool: &mut scoped_threadpool::Pool,
) -> Result<(), CheckpointError> {
    // Serialize ingress history separately. The `SystemMetadata` proto does not
    // encode it.
    //
    // This also makes it possible to validate post-split states simply by comparing
    // manifest file hashes (the ingress history is initially preserved unmodified
    // on both sides of the split, while the system metadata is not).
    let ingress_history = (&state.system_metadata().ingress_history).into();
    checkpoint_readwrite
        .ingress_history()
        .serialize(ingress_history)?;

    let system_metadata: SystemMetadata = state.system_metadata().into();
    checkpoint_readwrite
        .system_metadata()
        .serialize(system_metadata)?;

    // The split marker is also serialized separately from `SystemMetadata` because
    // preserving the latter unmodified during a split makes verification a matter
    // of comparing manifest file hashes.
    match state.system_metadata().split_from {
        Some(subnet_id) => {
            checkpoint_readwrite.split_marker().serialize(SplitFrom {
                subnet_id: Some(subnet_id_into_protobuf(subnet_id)),
            })?;
        }
        None => {
            checkpoint_readwrite.split_marker().try_remove_file()?;
        }
    }

    checkpoint_readwrite
        .subnet_queues()
        .serialize((state.subnet_queues()).into())?;

    checkpoint_readwrite
        .refunds()
        .serialize((state.refunds()).into())?;

    checkpoint_readwrite.stats().serialize(Stats {
        query_stats: state.query_stats().as_query_stats(),
    })?;

    let results = parallel_map(thread_pool, state.canisters_iter(), |canister_state| {
        serialize_canister_protos_to_checkpoint_readwrite(canister_state, checkpoint_readwrite)
    });

    for result in results.into_iter() {
        result?;
    }

    let results = parallel_map(
        thread_pool,
        state.canister_snapshots.iter(),
        |canister_snapshot| {
            serialize_snapshot_protos_to_checkpoint_readwrite(
                canister_snapshot.0,
                canister_snapshot.1,
                checkpoint_readwrite,
            )
        },
    );

    for result in results.into_iter() {
        result?;
    }

    Ok(())
}

fn serialize_wasm_binaries_and_pagemaps(
    state: &ReplicatedState,
    tip: &CheckpointLayout<RwPolicy<TipHandler>>,
    thread_pool: &mut scoped_threadpool::Pool,
    lsmt_config: &LsmtConfig,
    metrics: &StorageMetrics,
) -> Result<(), CheckpointError> {
    parallel_map(thread_pool, state.canisters_iter(), |canister_state| {
        serialize_canister_wasm_binary_and_pagemaps(canister_state, tip, metrics, lsmt_config)
    })
    .into_iter()
    .try_for_each(identity)?;
    parallel_map(
        thread_pool,
        state.canister_snapshots.iter(),
        |(snapshot_id, snapshot)| {
            serialize_snapshot_wasm_binary_and_pagemaps(
                snapshot_id,
                snapshot,
                tip,
                metrics,
                lsmt_config,
            )
        },
    )
    .into_iter()
    .try_for_each(identity)
}

fn serialize_wasm_binary(
    wasm_file: &WasmFile<RwPolicy<TipHandler>>,
    binary: &CanisterModule,
) -> Result<(), CheckpointError> {
    if !binary.is_file() {
        // Canister was installed/upgraded. Persist the new wasm binary.
        wasm_file.serialize(binary)?;
    } else {
        // This if should always be false, as we hardlink the entire checkpoint to the tip
        // It is left in mainly as defensive programming
        if !wasm_file.raw_path().exists() {
            debug_assert!(false);
            wasm_file.serialize(binary)?;
        }
    }
    Ok(())
}

fn serialize_canister_wasm_binary_and_pagemaps(
    canister_state: &CanisterState,
    tip: &CheckpointLayout<RwPolicy<TipHandler>>,
    metrics: &StorageMetrics,
    lsmt_config: &LsmtConfig,
) -> Result<(), CheckpointError> {
    let canister_id = canister_state.canister_id();
    let canister_layout = tip.canister(&canister_id)?;

    match &canister_state.execution_state {
        Some(execution_state) => {
            serialize_wasm_binary(&canister_layout.wasm(), &execution_state.wasm_binary.binary)?;
            execution_state.wasm_memory.page_map.persist_delta(
                &canister_layout.vmemory_0(),
                tip.height(),
                lsmt_config,
                metrics,
            )?;
            execution_state.stable_memory.page_map.persist_delta(
                &canister_layout.stable_memory(),
                tip.height(),
                lsmt_config,
                metrics,
            )?;
        }
        None => {
            // The canister is uninstalled
            canister_layout.vmemory_0().delete_files()?;
            canister_layout.stable_memory().delete_files()?;
            canister_layout.wasm().try_delete_file()?;
        }
    }

    canister_state
        .system_state
        .wasm_chunk_store
        .page_map()
        .persist_delta(
            &canister_layout.wasm_chunk_store(),
            tip.height(),
            lsmt_config,
            metrics,
        )?;
    Ok(())
}

fn serialize_snapshot_wasm_binary_and_pagemaps(
    snapshot_id: &SnapshotId,
    snapshot: &CanisterSnapshot,
    tip: &CheckpointLayout<RwPolicy<TipHandler>>,
    metrics: &StorageMetrics,
    lsmt_config: &LsmtConfig,
) -> Result<(), CheckpointError> {
    let snapshot_layout = tip.snapshot(snapshot_id)?;

    let execution_snapshot = snapshot.execution_snapshot();
    serialize_wasm_binary(&snapshot_layout.wasm(), &execution_snapshot.wasm_binary)?;
    execution_snapshot.wasm_memory.page_map.persist_delta(
        &snapshot_layout.vmemory_0(),
        tip.height(),
        lsmt_config,
        metrics,
    )?;
    execution_snapshot.stable_memory.page_map.persist_delta(
        &snapshot_layout.stable_memory(),
        tip.height(),
        lsmt_config,
        metrics,
    )?;
    snapshot.chunk_store().page_map().persist_delta(
        &snapshot_layout.wasm_chunk_store(),
        tip.height(),
        lsmt_config,
        metrics,
    )?;
    Ok(())
}

fn serialize_canister_protos_to_checkpoint_readwrite(
    canister_state: &CanisterState,
    checkpoint_readwrite: &CheckpointLayout<RwPolicy<TipHandler>>,
) -> Result<(), CheckpointError> {
    let canister_id = canister_state.canister_id();
    let canister_layout = checkpoint_readwrite.canister(&canister_id)?;
    canister_layout
        .queues()
        .serialize(canister_state.system_state.queues().into())?;

    let execution_state_bits = canister_state
        .execution_state
        .as_ref()
        .map(|execution_state| ExecutionStateBits {
            exported_globals: execution_state.exported_globals.clone(),
            heap_size: execution_state.wasm_memory.size,
            exports: execution_state.exports.clone(),
            last_executed_round: execution_state.last_executed_round,
            metadata: execution_state.metadata.clone(),
            binary_hash: execution_state.wasm_binary.binary.module_hash().into(),
            next_scheduled_method: execution_state.next_scheduled_method,
            is_wasm64: execution_state.wasm_execution_mode.is_wasm64(),
        });

    let load_metrics_bits = &canister_state.system_state.canister_metrics.load_metrics;

    canister_layout.canister().serialize(
        CanisterStateBits {
            controllers: canister_state.system_state.controllers.clone(),
            last_full_execution_round: canister_state.scheduler_state.last_full_execution_round,
            compute_allocation: canister_state.scheduler_state.compute_allocation,
            priority_credit: canister_state.scheduler_state.priority_credit,
            long_execution_mode: canister_state.scheduler_state.long_execution_mode,
            accumulated_priority: canister_state.scheduler_state.accumulated_priority,
            memory_allocation: canister_state.system_state.memory_allocation,
            wasm_memory_threshold: canister_state.system_state.wasm_memory_threshold,
            freeze_threshold: canister_state.system_state.freeze_threshold,
            cycles_balance: canister_state.system_state.balance(),
            cycles_debit: canister_state.system_state.ingress_induction_cycles_debit(),
            reserved_balance: canister_state.system_state.reserved_balance(),
            reserved_balance_limit: canister_state.system_state.reserved_balance_limit(),
            execution_state_bits,
            status: canister_state.system_state.get_status().clone(),
            scheduled_as_first: canister_state
                .system_state
                .canister_metrics
                .scheduled_as_first,
            skipped_round_due_to_no_messages: canister_state
                .system_state
                .canister_metrics
                .skipped_round_due_to_no_messages,
            executed: canister_state.system_state.canister_metrics.executed,
            interrupted_during_execution: canister_state
                .system_state
                .canister_metrics
                .interrupted_during_execution,
            certified_data: canister_state.system_state.certified_data.clone(),
            consumed_cycles: canister_state.system_state.canister_metrics.consumed_cycles,
            stable_memory_size: canister_state
                .execution_state
                .as_ref()
                .map(|es| es.stable_memory.size)
                .unwrap_or_else(|| NumWasmPages::from(0)),
            heap_delta_debit: canister_state.scheduler_state.heap_delta_debit,
            install_code_debit: canister_state.scheduler_state.install_code_debit,
            time_of_last_allocation_charge_nanos: canister_state
                .scheduler_state
                .time_of_last_allocation_charge
                .as_nanos_since_unix_epoch(),
            task_queue: canister_state.system_state.task_queue.clone(),
            global_timer_nanos: canister_state
                .system_state
                .global_timer
                .to_nanos_since_unix_epoch(),
            canister_version: canister_state.system_state.canister_version,
            consumed_cycles_by_use_cases: canister_state
                .system_state
                .canister_metrics
                .get_consumed_cycles_by_use_cases()
                .clone(),
            canister_history: canister_state.system_state.get_canister_history().clone(),
            wasm_chunk_store_metadata: canister_state
                .system_state
                .wasm_chunk_store
                .metadata()
                .clone(),
            total_query_stats: canister_state.scheduler_state.total_query_stats.clone(),
            log_visibility: canister_state.system_state.log_visibility.clone(),
            log_memory_limit: canister_state.system_state.log_memory_limit,
            canister_log: canister_state.system_state.canister_log.clone(),
            wasm_memory_limit: canister_state.system_state.wasm_memory_limit,
            next_snapshot_id: canister_state.system_state.next_snapshot_id,
            snapshots_memory_usage: canister_state.system_state.snapshots_memory_usage,
            environment_variables: canister_state
                .system_state
                .environment_variables
                .clone()
                .into(),
            instructions_executed: canister_state
                .system_state
                .canister_metrics
                .instructions_executed,
            ingress_messages_executed: load_metrics_bits.ingress_messages_executed,
            xnet_messages_executed: load_metrics_bits.xnet_messages_executed,
            intranet_messages_executed: load_metrics_bits.intranet_messages_executed,
            http_outcalls_executed: load_metrics_bits.http_outcalls_executed,
            heartbeats_executed: load_metrics_bits.heartbeats_executed,
            global_timers_executed: load_metrics_bits.global_timers_executed,
        }
        .into(),
    )?;
    Ok(())
}

fn serialize_snapshot_protos_to_checkpoint_readwrite(
    snapshot_id: &SnapshotId,
    canister_snapshot: &CanisterSnapshot,
    checkpoint_readwrite: &CheckpointLayout<RwPolicy<TipHandler>>,
) -> Result<(), CheckpointError> {
    let snapshot_layout = checkpoint_readwrite.snapshot(snapshot_id)?;

    // The protobuf is written at each checkpoint.
    snapshot_layout.snapshot().serialize(
        CanisterSnapshotBits {
            snapshot_id: *snapshot_id,
            canister_id: canister_snapshot.canister_id(),
            taken_at_timestamp: *canister_snapshot.taken_at_timestamp(),
            canister_version: canister_snapshot.canister_version(),
            binary_hash: canister_snapshot.canister_module().module_hash().into(),
            certified_data: canister_snapshot.certified_data().clone(),
            wasm_chunk_store_metadata: canister_snapshot.chunk_store().metadata().clone(),
            stable_memory_size: canister_snapshot.stable_memory().size,
            wasm_memory_size: canister_snapshot.wasm_memory().size,
            total_size: canister_snapshot.size(),
            exported_globals: canister_snapshot.exported_globals().clone(),
            source: canister_snapshot.source(),
            global_timer: canister_snapshot.execution_snapshot().global_timer,
            on_low_wasm_memory_hook_status: canister_snapshot
                .execution_snapshot()
                .on_low_wasm_memory_hook_status,
        }
        .into(),
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_compute_manifest_request(
    thread_pool: &mut scoped_threadpool::Pool,
    metrics: &StateManagerMetrics,
    log: &ReplicaLogger,
    states: &parking_lot::RwLock<SharedState>,
    state_layout: &StateLayout,
    checkpoint_layout: &CheckpointLayout<ReadOnly>,
    base_manifest_info: Option<crate::manifest::BaseManifestInfo>,
    persist_metadata_guard: &Arc<Mutex<()>>,
    #[allow(unused_variables)] malicious_flags: &MaliciousFlags,
    rehash_divergence: &mut bool,
) {
    let base_manifest_info = if *rehash_divergence {
        None
    } else {
        base_manifest_info
    };
    let system_metadata = checkpoint_layout
        .system_metadata()
        .deserialize()
        .unwrap_or_else(|err| {
            fatal!(
                log,
                "Failed to decode system metadata @{}: {}",
                checkpoint_layout.height(),
                err
            )
        });

    let state_sync_version = system_metadata.state_sync_version.try_into().unwrap();

    assert!(
        state_sync_version <= MAX_SUPPORTED_STATE_SYNC_VERSION,
        "Unable to compute a manifest with version {state_sync_version:?}. \
                    Maximum supported StateSync version is {MAX_SUPPORTED_STATE_SYNC_VERSION:?}"
    );

    // According to the current checkpointing workflow, encountering a checkpoint with the unverified marker should not happen.
    // Proceeding with manifest computation in such a scenario is risky because replicas might publish the root hash and create a CUP
    // for an unverified checkpoint, which could then be lost.
    // Therefore, crashing the replica is the safest option in this case.
    //
    // Note: In the future, if we decide to allow manifest computation before removing the unverified marker and introduce a mechanism
    // to hide the manifest until the checkpoint is verified, this crash behavior should be re-evaluated accordingly.
    if !checkpoint_layout.is_checkpoint_verified() {
        fatal!(
            log,
            "Trying to compute manifest for unverified checkpoint @{}",
            checkpoint_layout.height()
        );
    }

    let start = Instant::now();
    let manifest_is_incremental = base_manifest_info.is_some();
    let manifest = crate::manifest::compute_manifest(
        thread_pool,
        &metrics.manifest_metrics,
        log,
        state_sync_version,
        checkpoint_layout,
        crate::state_sync::types::DEFAULT_CHUNK_SIZE,
        base_manifest_info.as_ref(),
        RehashManifest::No,
    )
    .unwrap_or_else(|err| {
        fatal!(
            log,
            "Failed to compute manifest for checkpoint @{} after {:?}: {}",
            checkpoint_layout.height(),
            start.elapsed(),
            err
        )
    });

    let elapsed = start.elapsed();
    metrics
        .checkpoint_op_duration
        .with_label_values(&["compute_manifest"])
        .observe(elapsed.as_secs_f64());

    info!(
        log,
        "Computed manifest version {:?} for state @{} in {:?}",
        manifest.version,
        checkpoint_layout.height(),
        elapsed
    );

    let state_size_bytes = manifest.state_size_bytes() as i64;

    metrics.state_size.set(state_size_bytes);
    metrics
        .last_computed_manifest_height
        .set(checkpoint_layout.height().get() as i64);

    // This is where we maliciously alter the root_hash!
    #[cfg(feature = "malicious_code")]
    let malicious_root_hash = crate::maliciously_return_wrong_hash(
        &manifest,
        log,
        malicious_flags,
        checkpoint_layout.height(),
    );

    let bundled_manifest = compute_bundled_manifest(manifest.clone());

    #[cfg(feature = "malicious_code")]
    let bundled_manifest = crate::BundledManifest {
        root_hash: malicious_root_hash,
        ..bundled_manifest
    };

    // Removing or changing the log below could make upgrade system tests fail, as they check for
    // their existence before a reboot. Information about the computed root hash in logs is useful
    // in certain recovery scenarios and should be kept.
    info!(
        log,
        "Computed root hash {:?} of state @{}",
        bundled_manifest.root_hash,
        checkpoint_layout.height()
    );

    let num_sub_manifest_chunks = bundled_manifest.meta_manifest.sub_manifest_hashes.len();
    metrics
        .manifest_metrics
        .sub_manifest_chunks
        .set(num_sub_manifest_chunks as i64);

    let sub_manifest_chunk_id_range_length = u32::MAX - MANIFEST_CHUNK_ID_OFFSET + 1;
    if num_sub_manifest_chunks > sub_manifest_chunk_id_range_length as usize / 2 {
        error!(
            log,
            "{}: The number of sub-manifest chunks is greater than half of the available ID space in state sync. Number of sub-manifest chunks: {}, sub-manifest chunk ID range length: {}",
            CRITICAL_ERROR_CHUNK_ID_USAGE_NEARING_LIMITS,
            num_sub_manifest_chunks,
            sub_manifest_chunk_id_range_length,
        );
        metrics
            .manifest_metrics
            .chunk_id_usage_nearing_limits_critical
            .inc();
    }

    let mut states = states.write();

    if let Some(metadata) = states.states_metadata.get_mut(&checkpoint_layout.height()) {
        metadata.bundled_manifest = Some(bundled_manifest);
    }

    release_lock_and_persist_metadata(log, metrics, state_layout, states, persist_metadata_guard);

    let timer = request_timer(metrics, "observe_build_file_group_chunks");
    let num_file_group_chunks = crate::manifest::build_file_group_chunks(&manifest).len();
    metrics
        .manifest_metrics
        .file_group_chunks
        .set(num_file_group_chunks as i64);

    let file_group_chunk_id_range_length =
        (MANIFEST_CHUNK_ID_OFFSET - FILE_GROUP_CHUNK_ID_OFFSET) as usize;
    if num_file_group_chunks > file_group_chunk_id_range_length / 2 {
        error!(
            log,
            "{}: The number of file group chunks is greater than half of the available ID space in state sync. Number of file group chunks: {}, file group chunk ID range length: {}",
            CRITICAL_ERROR_CHUNK_ID_USAGE_NEARING_LIMITS,
            num_file_group_chunks,
            file_group_chunk_id_range_length,
        );
        metrics
            .manifest_metrics
            .chunk_id_usage_nearing_limits_critical
            .inc();
    }
    drop(timer);

    let timer = request_timer(metrics, "observe_duplicated_chunks");
    crate::manifest::observe_duplicated_chunks(&manifest, &metrics.manifest_metrics);
    drop(timer);

    let timer = request_timer(metrics, "observe_file_sizes");
    if let Some(base_manifest_info) = &base_manifest_info {
        crate::manifest::observe_file_sizes(
            &manifest,
            &base_manifest_info.base_manifest,
            &metrics.manifest_metrics,
        );
    }
    drop(timer);

    if !manifest_is_incremental {
        *rehash_divergence = false;
        return;
    }
    let _timer = request_timer(metrics, "compute_manifest_rehash");
    let start = Instant::now();
    let rehash_manifest_info = BaseManifestInfo {
        base_manifest: manifest.clone(),
        base_checkpoint: checkpoint_layout.clone(),
        base_height: checkpoint_layout.height(),
        target_height: checkpoint_layout.height(),
    };
    let rehashed_manifest = crate::manifest::compute_manifest(
        thread_pool,
        &metrics.manifest_metrics,
        log,
        state_sync_version,
        checkpoint_layout,
        crate::state_sync::types::DEFAULT_CHUNK_SIZE,
        Some(&rehash_manifest_info),
        RehashManifest::Yes,
    )
    .unwrap_or_else(|err| {
        fatal!(
            log,
            "Failed to rehash manifest for checkpoint @{} after {:?}: {}",
            checkpoint_layout.height(),
            start.elapsed(),
            err
        )
    });
    *rehash_divergence = manifest != rehashed_manifest;
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_config::state_manager::lsmt_config_default;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_tmpdir::tmpdir;

    #[test]
    fn dont_crash_or_hang() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();
            let metrics_registry = ic_metrics::MetricsRegistry::new();
            let metrics = StateManagerMetrics::new(&metrics_registry, log.clone());
            let tip_handler = layout.capture_tip_handler();
            let (_h, _s) = spawn_tip_thread(
                log,
                tip_handler,
                layout,
                lsmt_config_default(),
                metrics,
                MaliciousFlags::default(),
            );
        });
    }

    #[test]
    #[should_panic(expected = "compute manifest for unverified checkpoint")]
    fn should_crash_handle_compute_manifest_request() {
        with_test_replica_logger(|log| {
            let tempdir = tmpdir("state_layout");
            let root_path = tempdir.path().to_path_buf();
            let metrics_registry = ic_metrics::MetricsRegistry::new();
            let state_layout =
                StateLayout::try_new(log.clone(), root_path, &metrics_registry).unwrap();
            let metrics = StateManagerMetrics::new(&metrics_registry, log.clone());

            let height = Height::new(42);
            let mut tip_handler = state_layout.capture_tip_handler();
            let tip = tip_handler.tip(height).unwrap();

            // Create a marker in the tip and promote it to a checkpoint.
            let checkpoint_layout = state_layout
                .promote_scratchpad_to_unverified_checkpoint(tip, height)
                .unwrap()
                .as_readonly();

            let dummy_states = Arc::new(parking_lot::RwLock::new(SharedState {
                certifications_metadata: Default::default(),
                states_metadata: Default::default(),
                snapshots: Default::default(),
                last_advertised: Height::new(0),
                fetch_state: None,
                tip: None,
            }));

            // Trying to compute manifest for an unverified checkpoint should crash.
            handle_compute_manifest_request(
                &mut scoped_threadpool::Pool::new(1),
                &metrics,
                &log,
                &dummy_states,
                &state_layout,
                &checkpoint_layout,
                None,
                &Default::default(),
                &Default::default(),
                &mut false,
            );
        });
    }
}
