use crate::{
    compute_bundled_manifest, release_lock_and_persist_metadata,
    state_sync::types::{
        FILE_GROUP_CHUNK_ID_OFFSET, MANIFEST_CHUNK_ID_OFFSET, MAX_SUPPORTED_STATE_SYNC_VERSION,
    },
    CheckpointError, PageMapType, SharedState, StateManagerMetrics,
    CRITICAL_ERROR_CHUNK_ID_USAGE_NEARING_LIMITS, NUMBER_OF_CHECKPOINT_THREADS,
};
use crossbeam_channel::{unbounded, Sender};
use ic_base_types::subnet_id_into_protobuf;
use ic_config::flag_status::FlagStatus;
use ic_config::state_manager::LsmtConfig;
use ic_logger::{error, fatal, info, ReplicaLogger};
use ic_protobuf::state::{
    stats::v1::Stats,
    system_metadata::v1::{SplitFrom, SystemMetadata},
};
use ic_replicated_state::{
    canister_snapshots::{CanisterSnapshot, SnapshotOperation},
    page_map::{MergeCandidate, StorageMetrics, StorageResult, MAX_NUMBER_OF_FILES},
};
use ic_replicated_state::{
    page_map::{StorageLayout, PAGE_SIZE},
    CanisterState, NumWasmPages, PageMap, ReplicatedState,
};
use ic_state_layout::{
    error::LayoutError, CanisterSnapshotBits, CanisterStateBits, CheckpointLayout,
    ExecutionStateBits, FilePermissions, PageMapLayout, ReadOnly, RwPolicy, StateLayout,
    TipHandler, WasmFile,
};
use ic_sys::fs::defrag_file_partially;
use ic_types::{malicious_flags::MaliciousFlags, CanisterId, Height, SnapshotId};
use ic_utils::thread::parallel_map;
use ic_utils_thread::JoinOnDrop;
use prometheus::HistogramTimer;
use rand::prelude::SliceRandom;
use rand::{seq::IteratorRandom, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::collections::BTreeSet;
use std::os::unix::prelude::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const DEFRAG_SIZE: u64 = 1 << 29; // 500 MB
const DEFRAG_SAMPLE: usize = 100;
/// We merge starting from MAX_NUMBER_OF_FILES, we take up to 4 rounds to iterate over whole state,
/// there are 2 overlays created each checkpoint.
const NUMBER_OF_FILES_HARD_LIMIT: usize = MAX_NUMBER_OF_FILES + 8;

/// Tip directory can be in following states:
///    Empty: no data available. The only possible request is ResetTipAndMerge to populate it
///    ReadyForPageDeltas(height): ready to write page deltas. We keep track of height to make sure
///    it never decreases.
///    Serialized(height): all the data for the height `height` is flushed to tip, we can rename it
///    to checkpoint.
/// Height(0) is special, it has no corresponding checkpoint to write on top of. That's why the
/// state of a freshly created TipRequest with empty tip directory is ReadyForPageDeltas(0).
#[derive(Eq, PartialEq, Debug)]
enum TipState {
    Empty,
    ReadyForPageDeltas(Height),
    Serialized(Height),
}

/// A single pagemap to truncate and/or flush.
pub struct PageMapToFlush {
    pub page_map_type: PageMapType,
    pub truncate: bool,
    pub page_map: Option<PageMap>,
}

/// Request for the Tip directory handling thread.
pub(crate) enum TipRequest {
    /// Create checkpoint from the current tip for the given height.
    /// Return the created checkpoint or error into the sender.
    /// State: Serialized(height) -> Empty
    TipToCheckpoint {
        height: Height,
        sender: Sender<Result<(CheckpointLayout<ReadOnly>, HasDowngrade), LayoutError>>,
    },
    /// Filter canisters in tip. Remove ones not present in the set.
    /// State: !Empty
    FilterTipCanisters {
        height: Height,
        ids: BTreeSet<CanisterId>,
    },
    /// Flush PageMaps's unflushed delta on disc.
    /// State: ReadyForPageDeltas(h) -> ReadyForPageDeltas(height), height >= h
    FlushPageMapDelta {
        height: Height,
        pagemaps: Vec<PageMapToFlush>,
        snapshot_operations: Vec<SnapshotOperation>,
    },
    /// Reset tip folder to the checkpoint with given height.
    /// Merge overlays in tip folder if necessary.
    /// If is_initializing, we have a state with potentially different LSMT status.
    /// State: * -> ReadyForPageDeltas(checkpoint_layout.height())
    ResetTipAndMerge {
        checkpoint_layout: CheckpointLayout<ReadOnly>,
        pagemaptypes: Vec<PageMapType>,
        is_initializing_tip: bool,
    },
    /// Run one round of tip defragmentation.
    /// State: ReadyForPageDeltas(h) -> ReadyForPageDeltas(height), height >= h
    DefragTip {
        height: Height,
        page_map_types: Vec<PageMapType>,
    },
    /// State: ReadyForPageDeltas(h) -> Serialized(height), height >= h
    SerializeToTip {
        height: Height,
        replicated_state: Box<ReplicatedState>,
    },
    /// Compute manifest, store result into states and persist metadata as result.
    /// State: *
    ComputeManifest {
        checkpoint_layout: CheckpointLayout<ReadOnly>,
        manifest_delta: Option<crate::manifest::ManifestDelta>,
        states: Arc<parking_lot::RwLock<SharedState>>,
        persist_metadata_guard: Arc<Mutex<()>>,
    },
    /// Validate the checkpointed state is valid and identical to the execution state.
    /// Crash if diverges.
    #[cfg(debug_assertions)]
    ValidateReplicatedState {
        checkpointed_state: Box<ReplicatedState>,
        execution_state: Box<ReplicatedState>,
    },
    /// Wait for the message to be executed and notify back via sender.
    /// State: *
    Wait {
        sender: Sender<()>,
    },
    Noop,
}

fn request_timer(metrics: &StateManagerMetrics, name: &str) -> HistogramTimer {
    metrics
        .checkpoint_metrics
        .tip_handler_request_duration
        .with_label_values(&[name])
        .start_timer()
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum HasDowngrade {
    Yes,
    No,
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
    let mut tip_state = TipState::ReadyForPageDeltas(Height::from(0));
    // On top of tip state transitions, we enforce that each checkpoint gets manifest before we
    // create next one. Height(0) doesn't need manifest, so original state is true.
    let mut have_latest_manifest = true;
    let mut tip_downgrade = HasDowngrade::No;
    let tip_handle = JoinOnDrop::new(
        std::thread::Builder::new()
            .name("TipThread".to_string())
            .spawn(move || {
                while let Ok(req) = tip_receiver.recv() {
                    match req {
                        TipRequest::FilterTipCanisters { height, ids } => {
                            debug_assert_ne!(tip_state, TipState::Empty);

                            let _timer = request_timer(&metrics, "filter_tip_canisters");
                            tip_handler
                                .filter_tip_canisters(height, &ids)
                                .unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to filter tip canisters for height @{}: {}",
                                        height,
                                        err
                                    )
                                });
                        }
                        TipRequest::TipToCheckpoint { height, sender } => {
                            debug_assert_eq!(tip_state, TipState::Serialized(height));
                            debug_assert!(have_latest_manifest);
                            tip_state = TipState::Empty;
                            have_latest_manifest = false;
                            let _timer =
                                request_timer(&metrics, "tip_to_checkpoint_send_checkpoint");
                            let tip = tip_handler.tip(height);
                            match tip {
                                Err(err) => {
                                    sender
                                        .send(Err(err))
                                        .expect("Failed to return TipToCheckpoint error");
                                    continue;
                                }
                                Ok(tip) => {
                                    if let Err(err) = tip.create_unverified_checkpoint_marker() {
                                        sender
                                            .send(Err(err))
                                            .expect("Failed to return TipToCheckpoint error");
                                        continue;
                                    }

                                    let cp_or_err = state_layout.scratchpad_to_checkpoint(
                                        tip,
                                        height,
                                        Some(&mut thread_pool),
                                    );
                                    match cp_or_err {
                                        Err(err) => {
                                            sender
                                                .send(Err(err))
                                                .expect("Failed to return TipToCheckpoint error");
                                            continue;
                                        }
                                        Ok(cp) => {
                                            sender
                                                .send(Ok((cp.clone(), tip_downgrade.clone())))
                                                .expect("Failed to return TipToCheckpoint result");
                                        }
                                    }
                                }
                            }
                        }

                        TipRequest::FlushPageMapDelta {
                            height,
                            pagemaps,
                            snapshot_operations,
                        } => {
                            let _timer = request_timer(&metrics, "flush_unflushed_delta");
                            #[cfg(debug_assertions)]
                            match tip_state {
                                TipState::ReadyForPageDeltas(h) => debug_assert!(height >= h),
                                _ => panic!("Unexpected tip state: {:?}", tip_state),
                            }
                            tip_state = TipState::ReadyForPageDeltas(height);
                            let layout = &tip_handler.tip(height).unwrap_or_else(|err| {
                                fatal!(
                                    log,
                                    "Failed to get tip @{} to serialize to: {}",
                                    height,
                                    err
                                );
                            });

                            // We flush snapshots to disk first.
                            flush_snapshot_changes(&log, layout, snapshot_operations)
                                .unwrap_or_else(|err| {
                                    fatal!(log, "Failed to flush snapshot changes: {}", err);
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
                        TipRequest::SerializeToTip {
                            height,
                            replicated_state,
                        } => {
                            let _timer = request_timer(&metrics, "serialize_to_tip");
                            #[cfg(debug_assertions)]
                            match tip_state {
                                TipState::ReadyForPageDeltas(h) => debug_assert!(height >= h),
                                _ => panic!("Unexpected tip state: {:?}", tip_state),
                            }
                            tip_state = TipState::Serialized(height);
                            serialize_to_tip(
                                &log,
                                &replicated_state,
                                &tip_handler.tip(height).unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to get tip @{} to serialize to: {}",
                                        height,
                                        err
                                    );
                                }),
                                &mut thread_pool,
                                &metrics.storage_metrics,
                                &lsmt_config,
                            )
                            .unwrap_or_else(|err| {
                                fatal!(log, "Failed to serialize to tip @{}: {}", height, err);
                            });
                        }
                        TipRequest::ResetTipAndMerge {
                            checkpoint_layout,
                            pagemaptypes,
                            is_initializing_tip,
                        } => {
                            let _timer = request_timer(&metrics, "reset_tip_to");
                            if tip_downgrade != HasDowngrade::No {
                                info!(
                                    log,
                                    "tip_downgrade changes from {:?} to {:?}",
                                    tip_downgrade,
                                    HasDowngrade::No,
                                );
                                tip_downgrade = HasDowngrade::No;
                            }
                            let height = checkpoint_layout.height();
                            tip_handler
                                .reset_tip_to(
                                    &state_layout,
                                    &checkpoint_layout,
                                    lsmt_config.lsmt_status,
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
                            match lsmt_config.lsmt_status {
                                FlagStatus::Enabled => merge(
                                    &mut tip_handler,
                                    &pagemaptypes,
                                    height,
                                    &mut thread_pool,
                                    &log,
                                    &lsmt_config,
                                    &metrics,
                                ),
                                FlagStatus::Disabled => {
                                    if is_initializing_tip
                                        && merge_to_base(
                                            &mut tip_handler,
                                            &pagemaptypes,
                                            height,
                                            &mut thread_pool,
                                            &log,
                                            &metrics,
                                        )
                                    {
                                        info!(
                                            log,
                                            "tip_downgrade changes from {:?} to {:?}",
                                            tip_downgrade,
                                            HasDowngrade::Yes,
                                        );
                                        tip_downgrade = HasDowngrade::Yes;
                                    }
                                }
                            };
                            tip_state = TipState::ReadyForPageDeltas(height);
                        }
                        TipRequest::DefragTip {
                            height,
                            page_map_types,
                        } => {
                            debug_assert_ne!(tip_state, TipState::Empty);
                            tip_state = TipState::ReadyForPageDeltas(height);
                            let _timer = request_timer(&metrics, "defrag_tip");
                            defrag_tip(
                                &tip_handler.tip(height).unwrap_or_else(|err| {
                                    fatal!(log, "Failed to get tip @{} to defrag: {}", height, err);
                                }),
                                &page_map_types,
                                DEFRAG_SIZE,
                                DEFRAG_SAMPLE,
                                height.get(),
                            )
                            .unwrap_or_else(|err| {
                                fatal!(log, "Failed to defrag tip @{}: {}", height, err);
                            });
                        }

                        TipRequest::Wait { sender } => {
                            let _timer = request_timer(&metrics, "wait");
                            let _ = sender.send(());
                        }

                        TipRequest::ComputeManifest {
                            checkpoint_layout,
                            manifest_delta,
                            states,
                            persist_metadata_guard,
                        } => {
                            let _timer = request_timer(&metrics, "compute_manifest");
                            handle_compute_manifest_request(
                                &mut thread_pool,
                                &metrics,
                                &log,
                                &states,
                                &state_layout,
                                &checkpoint_layout,
                                manifest_delta,
                                &persist_metadata_guard,
                                &malicious_flags,
                            );
                            have_latest_manifest = true;
                        }

                        #[cfg(debug_assertions)]
                        TipRequest::ValidateReplicatedState {
                            checkpointed_state,
                            execution_state,
                        } => {
                            debug_assert!(
                                checkpointed_state == execution_state,
                                "Divergence: checkpointed {:#?}, \nexecution: {:#?}",
                                checkpointed_state,
                                execution_state,
                            );
                        }

                        TipRequest::Noop => {}
                    }
                }
            })
            .expect("failed to spawn tip thread"),
    );
    (tip_handle, tip_sender)
}

/// Update the tip directory files with the most recent snapshot operations.
/// `snapshot_operations` is an ordered list of all created/restores/deleted snapshots since the last flush.
fn flush_snapshot_changes<T>(
    log: &ReplicaLogger,
    layout: &CheckpointLayout<RwPolicy<T>>,
    snapshot_operations: Vec<SnapshotOperation>,
) -> Result<(), LayoutError> {
    // This loop is not parallelized as there are combinations such as creating then restoring from a snapshot within the same flush.
    for op in snapshot_operations {
        match op {
            SnapshotOperation::Delete(snapshot_id) => {
                layout.snapshot(&snapshot_id)?.delete_dir()?;
            }
            SnapshotOperation::Backup(canister_id, snapshot_id) => {
                backup(log, layout, canister_id, snapshot_id)?;
            }
            SnapshotOperation::Restore(canister_id, snapshot_id) => {
                restore(log, layout, canister_id, snapshot_id)?;
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
        FilePermissions::ReadOnly,
    )?;
    PageMapLayout::copy_or_hardlink_files(
        log,
        &canister_layout.stable_memory(),
        &snapshot_layout.stable_memory(),
        FilePermissions::ReadOnly,
    )?;
    PageMapLayout::copy_or_hardlink_files(
        log,
        &canister_layout.wasm_chunk_store(),
        &snapshot_layout.wasm_chunk_store(),
        FilePermissions::ReadOnly,
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
        FilePermissions::ReadOnly,
    )?;
    canister_layout.stable_memory().delete_files()?;
    PageMapLayout::copy_or_hardlink_files(
        log,
        &snapshot_layout.stable_memory(),
        &canister_layout.stable_memory(),
        FilePermissions::ReadOnly,
    )?;
    canister_layout.wasm_chunk_store().delete_files()?;
    PageMapLayout::copy_or_hardlink_files(
        log,
        &snapshot_layout.wasm_chunk_store(),
        &canister_layout.wasm_chunk_store(),
        FilePermissions::ReadOnly,
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
/// than MAX_NUMBER_OF_FILES at most in 4 checkpoint intervals. Since we produce at most 2 overlays
/// per checkpoint per `PageMap`, we have a cap of `MAX_NUMBER_OF_FILES` + 2 * 4 files per `PageMap`
/// at any checkpoint.
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
/// The merges for number of files are at most 1/4 of allowed state size.
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
/// The total write is at most 1/4 state size + 2/3 * max_dirty_pages + the size of the last
/// `PageMap`. Note that if canisters are removed, upgraded, or otherwise delete data, this can
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
    let storage_to_merge_for_filenum = storage_info.mem_size / 4;
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

/// Merge all the overlays (if any) into bases.
/// Return true if any merge was done.
fn merge_to_base(
    tip_handler: &mut TipHandler,
    pagemaptypes: &[PageMapType],
    height: Height,
    thread_pool: &mut scoped_threadpool::Pool,
    log: &ReplicaLogger,
    metrics: &StateManagerMetrics,
) -> bool {
    let layout = &tip_handler.tip(height).unwrap_or_else(|err| {
        fatal!(log, "Failed to get layout for {}: {}", height, err);
    });
    let rewritten = parallel_map(thread_pool, pagemaptypes.iter(), |page_map_type| {
        let pm_layout = page_map_type.layout(layout).unwrap_or_else(|err| {
            fatal!(log, "Failed to get layout for {:?}: {}", page_map_type, err);
        });
        let num_pages = (&pm_layout as &dyn StorageLayout)
            .memory_size_pages()
            .unwrap_or_else(|err| fatal!(log, "Failed to get num storage host pages: {}", err));
        let merge_candidate = MergeCandidate::merge_to_base(&pm_layout, num_pages as u64)
            .unwrap_or_else(|err| fatal!(log, "Failed to merge page map: {}", err));
        if let Some(m) = merge_candidate.as_ref() {
            m.apply(&metrics.storage_metrics).unwrap_or_else(|err| {
                fatal!(log, "Failed to apply MergeCandidate for downgrade: {}", err);
            });
        }
        merge_candidate.is_some()
    });

    return rewritten.iter().any(|b| *b);
}

fn serialize_to_tip(
    log: &ReplicaLogger,
    state: &ReplicatedState,
    tip: &CheckpointLayout<RwPolicy<TipHandler>>,
    thread_pool: &mut scoped_threadpool::Pool,
    metrics: &StorageMetrics,
    lsmt_config: &LsmtConfig,
) -> Result<(), CheckpointError> {
    // Snapshots should have been handled earlier in `flush_page_delta`.
    debug_assert!(state.canister_snapshots.is_unflushed_changes_empty());

    // Serialize ingress history separately. The `SystemMetadata` proto does not
    // encode it.
    //
    // This also makes it possible to validate post-split states simply by comparing
    // manifest file hashes (the ingress history is initially preserved unmodified
    // on both sides of the split, while the system metadata is not).
    let ingress_history = (&state.system_metadata().ingress_history).into();
    tip.ingress_history().serialize(ingress_history)?;

    let system_metadata: SystemMetadata = state.system_metadata().into();
    tip.system_metadata().serialize(system_metadata)?;

    // The split marker is also serialized separately from `SystemMetadata` because
    // preserving the latter unmodified during a split makes verification a matter
    // of comparing manifest file hashes.
    match state.system_metadata().split_from {
        Some(subnet_id) => {
            tip.split_marker().serialize(SplitFrom {
                subnet_id: Some(subnet_id_into_protobuf(subnet_id)),
            })?;
        }
        None => {
            tip.split_marker().try_remove_file()?;
        }
    }

    tip.subnet_queues()
        .serialize((state.subnet_queues()).into())?;

    tip.stats().serialize(Stats {
        query_stats: state.query_stats().as_query_stats(),
    })?;

    let results = parallel_map(thread_pool, state.canisters_iter(), |canister_state| {
        serialize_canister_to_tip(log, canister_state, tip, metrics, lsmt_config)
    });

    for result in results.into_iter() {
        result?;
    }

    let results = parallel_map(
        thread_pool,
        state.canister_snapshots.iter(),
        |canister_snapshot| {
            serialize_snapshot_to_tip(
                canister_snapshot.0,
                canister_snapshot.1,
                tip,
                metrics,
                lsmt_config,
            )
        },
    );

    for result in results.into_iter() {
        result?;
    }

    Ok(())
}

fn serialize_canister_to_tip(
    log: &ReplicaLogger,
    canister_state: &CanisterState,
    tip: &CheckpointLayout<RwPolicy<TipHandler>>,
    metrics: &StorageMetrics,
    lsmt_config: &LsmtConfig,
) -> Result<(), CheckpointError> {
    let canister_id = canister_state.canister_id();
    let canister_layout = tip.canister(&canister_id)?;
    canister_layout
        .queues()
        .serialize(canister_state.system_state.queues().into())?;

    let execution_state_bits = match &canister_state.execution_state {
        Some(execution_state) => {
            let wasm_binary = &execution_state.wasm_binary.binary;
            match wasm_binary.file() {
                Some(path) => {
                    let wasm = canister_layout.wasm();
                    // This if should always be false, as we reflink copy the entire checkpoint to the tip
                    // It is left in mainly as defensive programming
                    if !wasm.raw_path().exists() {
                        ic_state_layout::utils::do_copy(log, path, wasm.raw_path()).map_err(
                            |io_err| CheckpointError::IoError {
                                path: path.to_path_buf(),
                                message: "failed to copy Wasm file".to_string(),
                                io_err: io_err.to_string(),
                            },
                        )?;
                    }
                }
                None => {
                    // Canister was installed/upgraded. Persist the new wasm binary.
                    canister_layout
                        .wasm()
                        .serialize(&execution_state.wasm_binary.binary)?;
                }
            }
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

            Some(ExecutionStateBits {
                exported_globals: execution_state.exported_globals.clone(),
                heap_size: execution_state.wasm_memory.size,
                exports: execution_state.exports.clone(),
                last_executed_round: execution_state.last_executed_round,
                metadata: execution_state.metadata.clone(),
                binary_hash: Some(execution_state.wasm_binary.binary.module_hash().into()),
                next_scheduled_method: execution_state.next_scheduled_method,
            })
        }
        None => {
            canister_layout.vmemory_0().delete_files()?;
            canister_layout.stable_memory().delete_files()?;
            canister_layout.wasm().try_delete_file()?;
            None
        }
    };

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

    // Priority credit must be zero at this point
    assert_eq!(canister_state.scheduler_state.priority_credit.get(), 0);
    canister_layout.canister().serialize(
        CanisterStateBits {
            controllers: canister_state.system_state.controllers.clone(),
            last_full_execution_round: canister_state.scheduler_state.last_full_execution_round,
            call_context_manager: canister_state.system_state.call_context_manager().cloned(),
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
            status: canister_state.system_state.status.clone(),
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
            task_queue: canister_state
                .system_state
                .task_queue
                .clone()
                .into_iter()
                .collect(),
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
            canister_log: canister_state.system_state.canister_log.clone(),
            wasm_memory_limit: canister_state.system_state.wasm_memory_limit,
            next_snapshot_id: canister_state.system_state.next_snapshot_id,
            snapshots_memory_usage: canister_state.system_state.snapshots_memory_usage,
            on_low_wasm_memory_hook_status: canister_state
                .system_state
                .on_low_wasm_memory_hook_status
                .clone(),
        }
        .into(),
    )?;
    Ok(())
}

/// Serialize a single snapshot to disk at checkpoint time.
fn serialize_snapshot_to_tip(
    snapshot_id: &SnapshotId,
    canister_snapshot: &CanisterSnapshot,
    tip: &CheckpointLayout<RwPolicy<TipHandler>>,
    metrics: &StorageMetrics,
    lsmt_config: &LsmtConfig,
) -> Result<(), CheckpointError> {
    let snapshot_layout = tip.snapshot(snapshot_id)?;

    // The protobuf is written at each checkpoint.
    snapshot_layout.snapshot().serialize(
        CanisterSnapshotBits {
            snapshot_id: *snapshot_id,
            canister_id: canister_snapshot.canister_id(),
            taken_at_timestamp: *canister_snapshot.taken_at_timestamp(),
            canister_version: canister_snapshot.canister_version(),
            binary_hash: Some(canister_snapshot.canister_module().module_hash().into()),
            certified_data: canister_snapshot.certified_data().clone(),
            wasm_chunk_store_metadata: canister_snapshot.chunk_store().metadata().clone(),
            stable_memory_size: canister_snapshot.stable_memory().size,
            wasm_memory_size: canister_snapshot.wasm_memory().size,
            total_size: canister_snapshot.size(),
            exported_globals: canister_snapshot.exported_globals().clone(),
        }
        .into(),
    )?;

    // Like for canisters, the wasm binary is either already present on disk, or it is new and needs to be written.
    let wasm_binary = canister_snapshot.canister_module();
    if wasm_binary.file().is_none() {
        snapshot_layout.wasm().serialize(wasm_binary)?;
    } else {
        // During `flush_page_maps` we created copied this file from the canister directory.
        debug_assert!(snapshot_layout.wasm().raw_path().exists());
    }

    canister_snapshot
        .execution_snapshot()
        .wasm_memory
        .page_map
        .persist_delta(
            &snapshot_layout.vmemory_0(),
            tip.height(),
            lsmt_config,
            metrics,
        )?;
    canister_snapshot
        .execution_snapshot()
        .stable_memory
        .page_map
        .persist_delta(
            &snapshot_layout.stable_memory(),
            tip.height(),
            lsmt_config,
            metrics,
        )?;
    canister_snapshot.chunk_store().page_map().persist_delta(
        &snapshot_layout.wasm_chunk_store(),
        tip.height(),
        lsmt_config,
        metrics,
    )?;

    Ok(())
}

/// Defragments part of the tip directory.
///
/// The way we use PageMap files in the tip, namely by having a
/// long-living file, that we alternatively write to in small 4KB
/// pages and reflink copy to the checkpoint folder, the files end up
/// fragmented on disk. In particular, the metadata the file system
/// keeps on which pages are shared between files and which pages are
/// unique to a file grows quite complicated, which noticebly slows
/// down reflink copying of those files. It can therefore be
/// beneficial to defragment files, especially in situations where a
/// file had a lot of writes in the past but is mostly being read now.
///
/// The current defragmentation strategy is to pseudorandomly choose a
/// chunk of size max_size among the eligible files, read it to memory,
/// and write it back to the file. The effect is that this chunk is
/// definitely unique to the tip at the end of defragmentation.
pub fn defrag_tip(
    tip: &CheckpointLayout<RwPolicy<TipHandler>>,
    page_maps: &[PageMapType],
    max_size: u64,
    max_files: usize,
    seed: u64,
) -> Result<(), CheckpointError> {
    let mut rng = ChaChaRng::seed_from_u64(seed);

    // We sample the set of page maps down in order to avoid reading
    // the metadata of each file. This is a compromise between
    // weighting the probabilities by size and picking a uniformly
    // random file.  The former (without subsampling) would be
    // unnecessarily expensive, the latter would perform poorly in a
    // situation with many empty files and a few large ones, doing
    // no-ops on empty files with high probability.
    let page_map_subset = page_maps.iter().choose_multiple(&mut rng, max_files);

    let path_with_sizes: Vec<(PathBuf, u64)> = page_map_subset
        .iter()
        .filter_map(|entry| {
            let path = entry.layout(tip).ok()?.base();
            let size = path.metadata().ok()?.size();
            Some((path, size))
        })
        .collect();

    // We choose a file weighted by its size. This way, every bit in
    // the state has (roughly) the same probability of being
    // defragmented. If we chose the file uniformaly at random, we
    // would end up defragmenting the smallest file too often. The choice
    // failing is not an error, as it will happen if all files are
    // empty
    if let Ok((path, size)) = path_with_sizes.choose_weighted(&mut rng, |entry| entry.1) {
        let write_size = size.min(&max_size);
        let offset = rng.gen_range(0..=size - write_size);

        defrag_file_partially(path, offset, write_size.to_owned() as usize).map_err(|err| {
            CheckpointError::IoError {
                path: path.to_path_buf(),
                message: "failed to defrag file".into(),
                io_err: err.to_string(),
            }
        })?;
    }
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
    manifest_delta: Option<crate::manifest::ManifestDelta>,
    persist_metadata_guard: &Arc<Mutex<()>>,
    #[allow(unused_variables)] malicious_flags: &MaliciousFlags,
) {
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
        "Unable to compute a manifest with version {:?}. \
                    Maximum supported StateSync version is {:?}",
        state_sync_version,
        MAX_SUPPORTED_STATE_SYNC_VERSION
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
    let manifest = crate::manifest::compute_manifest(
        thread_pool,
        &metrics.manifest_metrics,
        log,
        state_sync_version,
        checkpoint_layout,
        crate::state_sync::types::DEFAULT_CHUNK_SIZE,
        manifest_delta,
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

    let state_size_bytes: i64 = manifest
        .file_table
        .iter()
        .map(|f| f.size_bytes as i64)
        .sum();

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

    let num_file_group_chunks = crate::manifest::build_file_group_chunks(&manifest).len();

    let bundled_manifest = compute_bundled_manifest(manifest);

    #[cfg(feature = "malicious_code")]
    let bundled_manifest = crate::BundledManifest {
        root_hash: malicious_root_hash,
        ..bundled_manifest
    };

    info!(
        log,
        "Computed root hash {:?} of state @{}",
        bundled_manifest.root_hash,
        checkpoint_layout.height()
    );

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
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_config::state_manager::lsmt_config_default;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_tmpdir::tmpdir;
    use ic_test_utilities_types::ids::canister_test_id;

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
    fn defrag_is_safe() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let mut tip_handler = StateLayout::try_new(log, root, &MetricsRegistry::new())
                .unwrap()
                .capture_tip_handler();
            let tip = tip_handler.tip(Height::new(42)).unwrap();

            let defrag_size = 1 << 20; // 1MB

            let page_maps: Vec<PageMapType> = vec![
                PageMapType::StableMemory(canister_test_id(100)),
                PageMapType::WasmMemory(canister_test_id(100)),
                PageMapType::WasmMemory(canister_test_id(101)),
            ];

            let paths: Vec<PathBuf> = page_maps
                .iter()
                .map(|page_map_type| page_map_type.layout(&tip).unwrap().base())
                .collect();

            for path in &paths {
                assert!(!path.exists());
            }

            defrag_tip(&tip, &page_maps, defrag_size, 100, 0).unwrap();

            for path in &paths {
                assert!(!path.exists());
            }

            for factor in 1..3 {
                let short_data: Vec<u8> = vec![42; (defrag_size / factor) as usize];
                let long_data: Vec<u8> = vec![43; (defrag_size * factor) as usize];
                let empty: &[u8] = &[];

                std::fs::write(&paths[0], &short_data).unwrap();
                std::fs::write(&paths[1], &long_data).unwrap();
                // third file is an empty file
                std::fs::write(&paths[2], empty).unwrap();

                let check_files = || {
                    assert_eq!(std::fs::read(&paths[0]).unwrap(), short_data);
                    assert_eq!(std::fs::read(&paths[1]).unwrap(), long_data);
                    assert!(paths[2].exists());
                    assert_eq!(std::fs::read(&paths[2]).unwrap(), empty);
                };

                check_files();

                for i in 0..100 {
                    defrag_tip(&tip, &page_maps, defrag_size, i as usize, i).unwrap();
                    check_files();
                }
            }
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
            tip.create_unverified_checkpoint_marker().unwrap();
            let checkpoint_layout = state_layout
                .scratchpad_to_checkpoint(tip, height, None)
                .unwrap();

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
            );
        });
    }
}
