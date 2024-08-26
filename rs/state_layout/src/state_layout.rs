use crate::error::LayoutError;
use crate::utils::do_copy;

use ic_base_types::{NumBytes, NumSeconds};
use ic_config::flag_status::FlagStatus;
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_management_canister_types::{LogVisibility, LogVisibilityV2};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::{
        canister_snapshot_bits::v1 as pb_canister_snapshot_bits,
        canister_state_bits::v1 as pb_canister_state_bits, ingress::v1 as pb_ingress,
        queues::v1 as pb_queues, stats::v1 as pb_stats, system_metadata::v1 as pb_metadata,
    },
};
use ic_replicated_state::{
    canister_state::{
        execution_state::{NextScheduledMethod, WasmMetadata},
        system_state::{wasm_chunk_store::WasmChunkStoreMetadata, CanisterHistory, CyclesUseCase},
    },
    page_map::{Shard, StorageLayout},
    CallContextManager, CanisterStatus, ExecutionTask, ExportedFunctions, Global, NumWasmPages,
};
use ic_sys::{fs::sync_path, mmap::ScopedMmap};
use ic_types::{
    batch::TotalQueryStats, nominal_cycles::NominalCycles, AccumulatedPriority, CanisterId,
    CanisterLog, ComputeAllocation, Cycles, ExecutionRound, Height, LongExecutionMode,
    MemoryAllocation, NumInstructions, PrincipalId, SnapshotId, Time,
};
use ic_utils::thread::parallel_map;
use ic_wasm_types::{CanisterModule, WasmHash};
use prometheus::{Histogram, IntCounterVec};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::{identity, From, TryFrom, TryInto};
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{Error, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[cfg(test)]
mod tests;

// State layout directory and file names.
pub const CHECKPOINTS_DIR: &str = "checkpoints";
pub const CANISTER_STATES_DIR: &str = "canister_states";
pub const SNAPSHOTS_DIR: &str = "snapshots";
pub const SNAPSHOT_FILE: &str = "snapshot.pbuf";
pub const QUEUES_FILE: &str = "queues.pbuf";
pub const CANISTER_FILE: &str = "canister.pbuf";
pub const INGRESS_HISTORY_FILE: &str = "ingress_history.pbuf";
pub const SPLIT_MARKER_FILE: &str = "split_from.pbuf";
pub const SUBNET_QUEUES_FILE: &str = "subnet_queues.pbuf";
pub const SYSTEM_METADATA_FILE: &str = "system_metadata.pbuf";
pub const STATS_FILE: &str = "stats.pbuf";
pub const WASM_FILE: &str = "software.wasm";
pub const UNVERIFIED_CHECKPOINT_MARKER: &str = "unverified_checkpoint_marker";

/// `ReadOnly` is the access policy used for reading checkpoints. We
/// don't want to ever modify persisted states.
pub enum ReadOnly {}

/// `WriteOnly` is the access policy used while we are creating a new
/// checkpoint.
pub enum WriteOnly {}

/// `RwPolicy` is the access policy used for tip on disk state.
pub struct RwPolicy<'a, Owner> {
    lifetime_tag: PhantomData<&'a Owner>,
}

pub trait AccessPolicy {
    /// `check_dir` specifies what to do the first time we enter a
    /// directory while reading/writing a checkpoint.
    ///
    /// The default behavior is to do nothing. This is suitable for
    /// the `ReadOnly` mode because if the directory doesn't exist,
    /// we'll fail anyway when we try to read files from it.
    fn check_dir(_p: &Path) -> Result<(), LayoutError> {
        Ok(())
    }
}

pub trait ReadPolicy: AccessPolicy {}
pub trait WritePolicy: AccessPolicy {}
pub trait ReadWritePolicy: ReadPolicy + WritePolicy {}

impl<T> ReadWritePolicy for T where T: ReadPolicy + WritePolicy {}

impl AccessPolicy for ReadOnly {}
impl ReadPolicy for ReadOnly {}

impl AccessPolicy for WriteOnly {
    /// For `WriteOnly` mode we want to ensure the directory exists
    /// when we visit it for the first time as we'll certainly want to
    /// create new files inside.
    fn check_dir(path: &Path) -> Result<(), LayoutError> {
        std::fs::create_dir_all(path).map_err(|err| LayoutError::IoError {
            path: path.to_path_buf(),
            message: "Failed to create directory".to_string(),
            io_err: err,
        })
    }
}

impl WritePolicy for WriteOnly {}

impl<'a, T> AccessPolicy for RwPolicy<'a, T> {
    fn check_dir(p: &Path) -> Result<(), LayoutError> {
        WriteOnly::check_dir(p)
    }
}

impl<'a, T> ReadPolicy for RwPolicy<'a, T> {}
impl<'a, T> WritePolicy for RwPolicy<'a, T> {}

pub type CompleteCheckpointLayout = CheckpointLayout<ReadOnly>;

/// This struct contains bits of the `ExecutionState` that are not already
/// covered somewhere else and are too small to be serialized separately.
#[derive(Debug)]
pub struct ExecutionStateBits {
    pub exported_globals: Vec<Global>,
    pub heap_size: NumWasmPages,
    pub exports: ExportedFunctions,
    pub last_executed_round: ExecutionRound,
    pub metadata: WasmMetadata,
    pub binary_hash: Option<WasmHash>,
    pub next_scheduled_method: NextScheduledMethod,
}

/// This struct contains bits of the `CanisterState` that are not already
/// covered somewhere else and are too small to be serialized separately.
#[derive(Debug)]
pub struct CanisterStateBits {
    pub controllers: BTreeSet<PrincipalId>,
    pub last_full_execution_round: ExecutionRound,
    pub call_context_manager: Option<CallContextManager>,
    pub compute_allocation: ComputeAllocation,
    pub accumulated_priority: AccumulatedPriority,
    pub priority_credit: AccumulatedPriority,
    pub long_execution_mode: LongExecutionMode,
    pub execution_state_bits: Option<ExecutionStateBits>,
    pub memory_allocation: MemoryAllocation,
    pub wasm_memory_threshold: NumBytes,
    pub freeze_threshold: NumSeconds,
    pub cycles_balance: Cycles,
    pub cycles_debit: Cycles,
    pub reserved_balance: Cycles,
    pub reserved_balance_limit: Option<Cycles>,
    pub status: CanisterStatus,
    pub scheduled_as_first: u64,
    pub skipped_round_due_to_no_messages: u64,
    pub executed: u64,
    pub interrupted_during_execution: u64,
    pub certified_data: Vec<u8>,
    pub consumed_cycles: NominalCycles,
    pub stable_memory_size: NumWasmPages,
    pub heap_delta_debit: NumBytes,
    pub install_code_debit: NumInstructions,
    pub task_queue: Vec<ExecutionTask>,
    pub time_of_last_allocation_charge_nanos: u64,
    pub global_timer_nanos: Option<u64>,
    pub canister_version: u64,
    pub consumed_cycles_by_use_cases: BTreeMap<CyclesUseCase, NominalCycles>,
    pub canister_history: CanisterHistory,
    pub wasm_chunk_store_metadata: WasmChunkStoreMetadata,
    pub total_query_stats: TotalQueryStats,
    pub log_visibility: LogVisibilityV2,
    pub canister_log: CanisterLog,
    pub wasm_memory_limit: Option<NumBytes>,
    pub next_snapshot_id: u64,
    pub snapshots_memory_usage: NumBytes,
}

/// This struct contains bits of the `CanisterSnapshot` that are not already
/// covered somewhere else and are too small to be serialized separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanisterSnapshotBits {
    /// The ID of the canister snapshot.
    pub snapshot_id: SnapshotId,
    /// Identifies the canister to which this snapshot belongs.
    pub canister_id: CanisterId,
    /// The timestamp indicating the moment the snapshot was captured.
    pub taken_at_timestamp: Time,
    /// The canister version at the time of taking the snapshot.
    pub canister_version: u64,
    /// The hash of the canister wasm.
    pub binary_hash: Option<WasmHash>,
    /// The certified data blob belonging to the canister.
    pub certified_data: Vec<u8>,
    /// The metadata required for a wasm chunk store.
    pub wasm_chunk_store_metadata: WasmChunkStoreMetadata,
    /// The size of the stable memory in pages.
    pub stable_memory_size: NumWasmPages,
    /// The size of the wasm memory in pages.
    pub wasm_memory_size: NumWasmPages,
    /// The total size of the snapshot in bytes.
    pub total_size: NumBytes,
}

#[derive(Clone)]
struct StateLayoutMetrics {
    state_layout_error_count: IntCounterVec,
    state_layout_remove_checkpoint_duration: Histogram,
    #[cfg(target_os = "linux")]
    state_layout_syncfs_duration: Histogram,
}

impl StateLayoutMetrics {
    fn new(metric_registry: &MetricsRegistry) -> StateLayoutMetrics {
        StateLayoutMetrics {
            state_layout_error_count: metric_registry.int_counter_vec(
                "state_layout_error_count",
                "Total number of errors encountered in the state layout.",
                &["source"],
            ),
            state_layout_remove_checkpoint_duration: metric_registry.histogram(
                "state_layout_remove_checkpoint_duration",
                "Time elapsed in removing checkpoint.",
                decimal_buckets(-3, 1),
            ),
            #[cfg(target_os = "linux")]
            state_layout_syncfs_duration: metric_registry.histogram(
                "state_layout_syncfs_duration_seconds",
                "Time elapsed in syncfs.",
                decimal_buckets(-2, 2),
            ),
        }
    }
}

struct CheckpointRefData {
    // CheckpointLayouts using this ref that are still alive.
    checkpoint_layout_counter: i32,
    // The ref is scheduled for removal once checkpoint_layout_counter drops to zero.
    mark_deleted: bool,
}

/// `StateLayout` provides convenience functions to construct correct
/// paths to individual components of the replicated execution
/// state and checkpoints.
///
/// ```text
/// <root>
/// ├── states_metadata.pbuf
/// │
/// │── tip
/// │   ├── canister_states
/// │   │   └── <hex(canister_id)>
/// │   │       ├── canister.pbuf
/// │   │       ├── queues.pbuf
/// │   │       ├── software.wasm
/// │   │       ├── stable_memory.bin
/// │   │       └── vmemory_0.bin
/// │   ├── snapshots
/// │   │   └── <hex(canister_id)>
/// │   │       └──  <hex(snapshot_id)>
/// │   │           ├── snapshot.pbuf
/// │   │           ├── software.wasm
/// │   │           ├── stable_memory.bin
/// │   │           └── vmemory_0.bin
/// │   ├── ingress_history.pbuf
/// │   ├── split_from.pbuf
/// │   ├── subnet_queues.pbuf
/// │   └── system_metadata.pbuf
/// │
/// ├── [checkpoints, backups, diverged_checkpoints]
/// │   └──<hex(round)>
/// │      ├── canister_states
/// │      │   └── <hex(canister_id)>
/// │      │       ├── canister.pbuf
/// │      │       ├── queues.pbuf
/// │      │       ├── software.wasm
/// │      │       ├── stable_memory.bin
/// │      │       ├── vmemory_0.bin
/// │      │       └── wasm_chunk_store.bin
/// │      ├── snapshots
/// │      │   └── <hex(canister_id)>
/// │      │       └──  <hex(snapshot_id)>
/// │      │           ├── snapshot.pbuf
/// │      │           ├── software.wasm
/// │      │           ├── stable_memory.bin
/// │      │           └── vmemory_0.bin
/// │      ├── ingress_history.pbuf
/// │      ├── split_from.pbuf
/// │      ├── subnet_queues.pbuf
/// │      └── system_metadata.pbuf
/// │
/// ├── diverged_state_markers
/// │   └──<hex(round)>
/// │
/// ├── tmp
/// └── fs_tmp
/// ```
///
/// Needs to be pub for criterion performance regression tests.
///
/// Checkpoints management
///
/// Checkpoints are created under "checkpoints" directory. fs_tmp directory
/// is used as intermediate scratchpad area. Additional directory structure
/// could be overlaid by state_layout on top of following directory structure.
///
/// For correctness reasons we need to make sure that checkpoints we create are
/// internally consistent and only "publish" them in the `checkpoints` directory
/// once they are fully synced to disk.
///
/// There are 2 ways to construct a checkpoint:
///   1. Compute it locally by applying blocks to an older state.
///   2. Fetch it from a peer using the state sync protocol.
///
/// Let's look at how each case is handled.
///
/// ## Promoting a TIP to a checkpoint
///
///   1. Dump the state to files and directories under "<state_root>/tip", mark
///      readonly and sync all files
///
///   2. Rename tip to checkpoint.
///
///   3. Reflink the checkpoint back to writeable tip
///
/// ## Promoting a State Sync artifact to a checkpoint
///
///   1. Create state files directly in
///      "<state_root>/fs_tmp/state_sync_scratchpad_<height>".
///
///   2. When all the writes are complete, call sync_and_mark_files_readonly()
///      on "<state_root>/fs_tmp/state_sync_scratchpad_<height>".  This function
///      syncs all the files and directories under the scratchpad directory,
///      including the scratchpad directory itself.
///
///   3. Rename "<state_root>/fs_tmp/state_sync_scratchpad_<height>" to
///      "<state_root>/checkpoints/<height>", sync "<state_root>/checkpoints".

#[derive(Clone)]
pub struct StateLayout {
    root: PathBuf,
    log: ReplicaLogger,
    metrics: StateLayoutMetrics,
    tip_handler_captured: Arc<AtomicBool>,
    checkpoint_ref_registry: Arc<Mutex<BTreeMap<Height, CheckpointRefData>>>,
}

pub struct TipHandler {
    tip_path: PathBuf,
}

impl TipHandler {
    pub fn tip_path(&mut self) -> PathBuf {
        self.tip_path.clone()
    }

    /// Returns a layout object representing tip state in "tip"
    /// directory. During round execution this directory may contain
    /// inconsistent state. During full checkpointing this directory contains
    /// full state and is converted to a checkpoint.
    /// This directory is cleaned during restart of a node and reset to
    /// last full checkpoint.
    pub fn tip(&mut self, height: Height) -> Result<CheckpointLayout<RwPolicy<Self>>, LayoutError> {
        CheckpointLayout::new_untracked(self.tip_path(), height)
    }

    /// Resets "tip" to a checkpoint identified by height.
    pub fn reset_tip_to(
        &mut self,
        state_layout: &StateLayout,
        cp: &CheckpointLayout<ReadOnly>,
        lsmt_storage: FlagStatus,
        thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> Result<(), LayoutError> {
        let tip = self.tip_path();
        if tip.exists() {
            std::fs::remove_dir_all(&tip).map_err(|err| LayoutError::IoError {
                path: tip.to_path_buf(),
                message: format!("Cannot remove tip for checkpoint {}", cp.height),
                io_err: err,
            })?;
        }

        debug_assert!(cp.root.exists());

        let file_copy_instruction = |path: &Path| {
            if path.extension() == Some(OsStr::new("pbuf")) {
                // Do not copy protobufs.
                CopyInstruction::Skip
            } else if path == cp.unverified_checkpoint_marker() {
                // With LSMT enabled, the unverified checkpoint marker should already be removed at this point.
                debug_assert_eq!(lsmt_storage, FlagStatus::Disabled);
                // With LSMT disabled, the unverified checkpoint marker is still present in the checkpoint at this point.
                // We should not copy it back to the tip because it will be created later when promoting the tip as the next checkpoint.
                // When we go for asynchronous checkpointing in the future, we should revisit this as the marker file will have a different lifespan.
                CopyInstruction::Skip
            } else if path.extension() == Some(OsStr::new("bin"))
                && lsmt_storage == FlagStatus::Disabled
                && !path.starts_with(cp.root.join(SNAPSHOTS_DIR))
            {
                // PageMap files need to be modified in the tip,
                // but only with non-LSMT storage layer that modifies these files.
                // With LSMT we always write additional overlay files instead.
                // PageMap files that belong to snapshots are not modified even without LSMT.
                CopyInstruction::ReadWrite
            } else {
                // Everything else should be readonly.
                CopyInstruction::ReadOnly
            }
        };

        match copy_recursively(
            &state_layout.log,
            &state_layout.metrics,
            cp.root.as_path(),
            &tip,
            FSync::No,
            file_copy_instruction,
            thread_pool,
        ) {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Err(err) = std::fs::remove_dir_all(&tip) {
                    error!(
                        state_layout.log,
                        "Failed to tip directory. Path: {}, Error: {}.",
                        tip.display(),
                        err
                    )
                }
                Err(LayoutError::IoError {
                    path: tip,
                    message: format!(
                        "Failed to convert reset tip to checkpoint to {} (err kind: {:?})",
                        cp.root.display(),
                        e.kind()
                    ),
                    io_err: e,
                })
            }
        }
    }

    /// Deletes canisters from tip if they are not in ids.
    pub fn filter_tip_canisters(
        &mut self,
        height: Height,
        ids: &BTreeSet<CanisterId>,
    ) -> Result<(), LayoutError> {
        let tip = self.tip(height)?;
        let canisters_on_disk = tip.canister_ids()?;
        for id in canisters_on_disk {
            if !ids.contains(&id) {
                let canister_path = tip.canister(&id)?.raw_path();
                std::fs::remove_dir_all(&canister_path).map_err(|err| LayoutError::IoError {
                    path: canister_path,
                    message: "Cannot remove canister.".to_string(),
                    io_err: err,
                })?;
            }
        }
        Ok(())
    }
}

impl StateLayout {
    /// Needs to be pub for criterion performance regression tests.
    pub fn try_new(
        log: ReplicaLogger,
        root: PathBuf,
        metrics_registry: &MetricsRegistry,
    ) -> Result<Self, LayoutError> {
        let state_layout = Self {
            root,
            log,
            metrics: StateLayoutMetrics::new(metrics_registry),
            tip_handler_captured: Arc::new(false.into()),
            checkpoint_ref_registry: Arc::new(Mutex::new(BTreeMap::new())),
        };
        state_layout.init()?;
        Ok(state_layout)
    }

    fn init(&self) -> Result<(), LayoutError> {
        self.cleanup_tip()?;
        self.cleanup_tmp()?;
        // This is for testing only. In production the Guest OS setup
        // would have already created the page_deltas directory, however
        // in testing the directory does not already exist and we need to
        // create it.
        if !Path::new(&self.page_deltas()).exists() {
            WriteOnly::check_dir(&self.page_deltas())?;
        }

        WriteOnly::check_dir(&self.backups())?;
        WriteOnly::check_dir(&self.checkpoints())?;
        WriteOnly::check_dir(&self.diverged_checkpoints())?;
        WriteOnly::check_dir(&self.diverged_state_markers())?;
        WriteOnly::check_dir(&self.fs_tmp())?;
        WriteOnly::check_dir(&self.tip_path())?;
        WriteOnly::check_dir(&self.tmp())?;
        for path in [
            &self.backups(),
            &self.checkpoints(),
            &self.diverged_checkpoints(),
            &self.diverged_state_markers(),
        ] {
            sync_path(path).map_err(|err| LayoutError::IoError {
                path: path.clone(),
                message: "Could not sync StateLayout during init".to_string(),
                io_err: err,
            })?
        }
        Ok(())
    }

    /// Mark files (but not dirs) in all checkpoints readonly.
    pub fn mark_checkpoint_files_readonly(
        &self,
        thread_pool: &mut Option<scoped_threadpool::Pool>,
    ) -> Result<(), LayoutError> {
        for height in self.checkpoint_heights()? {
            let path = self.checkpoint_verified(height)?.raw_path().to_path_buf();
            sync_and_mark_files_readonly(&self.log, &path, &self.metrics, thread_pool.as_mut())
                .map_err(|err| LayoutError::IoError {
                    path,
                    message: format!("Could not sync and mark readonly checkpoint {}", height),
                    io_err: err,
                })?;
        }
        Ok(())
    }

    /// Create tip handler. Could only be called once as TipHandler is an exclusive owner of the
    /// tip folder.
    pub fn capture_tip_handler(&self) -> TipHandler {
        assert_eq!(
            self.tip_handler_captured.compare_exchange(
                false,
                true,
                Ordering::SeqCst,
                Ordering::SeqCst
            ),
            Ok(false)
        );
        TipHandler {
            tip_path: self.tip_path(),
        }
    }
    /// Returns the the raw root path for state
    pub fn raw_path(&self) -> &Path {
        &self.root
    }

    /// Returns the path to the temporary directory.
    /// This directory is cleaned during restart of a node.
    pub fn tmp(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Returns the path to the temporary directory for checkpoint operations,
    /// aka fs_tmp. This directory is cleaned during restart of a node.
    pub fn fs_tmp(&self) -> PathBuf {
        self.root.join("fs_tmp")
    }

    pub fn page_deltas(&self) -> PathBuf {
        self.root.join("page_deltas")
    }

    /// Removes the tmp directory and all its contents.
    fn cleanup_tmp(&self) -> Result<(), LayoutError> {
        let tmp = self.tmp();
        if tmp.exists() {
            std::fs::remove_dir_all(&tmp).map_err(|err| LayoutError::IoError {
                path: tmp,
                message: "Unable to remove temporary directory".to_string(),
                io_err: err,
            })?
        }
        let fs_tmp = self.fs_tmp();
        if fs_tmp.exists() {
            std::fs::remove_dir_all(&fs_tmp).map_err(|err| LayoutError::IoError {
                path: fs_tmp,
                message: "Unable to remove fs_tmp directory".to_string(),
                io_err: err,
            })?
        }
        // The page deltas directory will always exist because
        // the guest os deployment scripts should have created it.
        // Also, if we delete the directory here and re-create it as
        // it happens for the other sibling dirs then the SELinux
        // settings will be overwritten, which will not grant the sandbox
        // the proper access to the files in the dir.
        let page_deltas = self.page_deltas();
        if page_deltas.exists() {
            for entry in std::fs::read_dir(page_deltas.as_path()).unwrap() {
                let entry = entry.map_err(|err| LayoutError::IoError {
                    path: page_deltas.clone(),
                    message: "Unable to remove content of the page_deltas directory".to_string(),
                    io_err: err,
                });
                std::fs::remove_file(entry.unwrap().path()).unwrap();
            }
        }
        Ok(())
    }

    /// Returns the path to the serialized states metadata.
    pub fn states_metadata(&self) -> PathBuf {
        self.root.join("states_metadata.pbuf")
    }

    /// Returns scratchpad used during statesync
    pub fn state_sync_scratchpad(&self, height: Height) -> Result<PathBuf, LayoutError> {
        Ok(self
            .tmp()
            .join(format!("state_sync_scratchpad_{:016x}", height.get())))
    }

    /// Returns the path to cache an unfinished statesync at `height`
    pub fn state_sync_cache(&self, height: Height) -> Result<PathBuf, LayoutError> {
        let tmp = self.tmp();
        Ok(tmp.join(format!("state_sync_cache_{:016x}", height.get())))
    }

    fn cleanup_tip(&self) -> Result<(), LayoutError> {
        if self.tip_path().exists() {
            std::fs::remove_dir_all(self.tip_path()).map_err(|err| LayoutError::IoError {
                path: self.tip_path(),
                message: "Unable to remove old tip. Tip could be inconsistent".to_string(),
                io_err: err,
            })
        } else {
            Ok(())
        }
    }

    pub fn scratchpad_to_checkpoint<T>(
        &self,
        layout: CheckpointLayout<RwPolicy<'_, T>>,
        height: Height,
        thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> Result<CheckpointLayout<ReadOnly>, LayoutError> {
        debug_assert_eq!(height, layout.height);
        let scratchpad = layout.raw_path();
        let checkpoints_path = self.checkpoints();
        let cp_path = checkpoints_path.join(Self::checkpoint_name(height));
        sync_and_mark_files_readonly(&self.log, scratchpad, &self.metrics, thread_pool).map_err(
            |err| LayoutError::IoError {
                path: scratchpad.to_path_buf(),
                message: format!(
                    "Could not sync and mark readonly scratchpad for checkpoint {}",
                    height
                ),
                io_err: err,
            },
        )?;
        std::fs::rename(scratchpad, cp_path).map_err(|err| {
            if is_already_exists_err(&err) {
                LayoutError::AlreadyExists(height)
            } else {
                LayoutError::IoError {
                    path: scratchpad.to_path_buf(),
                    message: format!("Failed to rename scratchpad to checkpoint {}", height),
                    io_err: err,
                }
            }
        })?;
        sync_path(&checkpoints_path).map_err(|err| LayoutError::IoError {
            path: checkpoints_path,
            message: "Could not sync checkpoints".to_string(),
            io_err: err,
        })?;
        self.checkpoint_in_verification(height)
    }

    pub fn clone_checkpoint(&self, from: Height, to: Height) -> Result<(), LayoutError> {
        let src = self.checkpoints().join(Self::checkpoint_name(from));
        let dst = self.checkpoints().join(Self::checkpoint_name(to));
        self.copy_and_sync_checkpoint(&Self::checkpoint_name(to), &src, &dst, None)
            .map_err(|io_err| {
                if is_already_exists_err(&io_err) {
                    LayoutError::AlreadyExists(to)
                } else {
                    LayoutError::IoError {
                        path: dst,
                        message: format!("Failed to clone checkpoint {} to {}", from, to),
                        io_err,
                    }
                }
            })?;
        Ok(())
    }

    /// Returns the layout of the checkpoint with the given height.
    /// If the checkpoint is not found, an error is returned.
    fn checkpoint(&self, height: Height) -> Result<CheckpointLayout<ReadOnly>, LayoutError> {
        let cp_name = Self::checkpoint_name(height);
        let path = self.checkpoints().join(cp_name);
        if !path.exists() {
            return Err(LayoutError::NotFound(height));
        }
        {
            let mut checkpoint_ref_registry = self.checkpoint_ref_registry.lock().unwrap();
            match checkpoint_ref_registry.get_mut(&height) {
                Some(ref mut ref_data) => {
                    ref_data.checkpoint_layout_counter += 1;
                    #[cfg(debug_assertions)]
                    {
                        let mark_deleted = ref_data.mark_deleted;
                        drop(checkpoint_ref_registry);
                        debug_assert!(!mark_deleted);
                    }
                }
                None => {
                    checkpoint_ref_registry.insert(
                        height,
                        CheckpointRefData {
                            checkpoint_layout_counter: 1,
                            mark_deleted: false,
                        },
                    );
                }
            }
        }
        CheckpointLayout::new(path, height, self.clone())
    }

    /// Returns the layout of a verified checkpoint with the given height.
    /// If the checkpoint is not found or is not verified, an error is returned.
    pub fn checkpoint_verified(
        &self,
        height: Height,
    ) -> Result<CheckpointLayout<ReadOnly>, LayoutError> {
        let cp = self.checkpoint(height)?;
        if !cp.is_checkpoint_verified() {
            return Err(LayoutError::CheckpointUnverified(height));
        };
        Ok(cp)
    }

    /// Returns the layout of a checkpoint with the given height that is in the verification process.
    /// If the checkpoint is not found, an error is returned.
    ///
    /// Note that the unverified marker file may already be removed from the checkpoint by another verification process.
    /// This method does not require that the marker file exists.
    pub fn checkpoint_in_verification(
        &self,
        height: Height,
    ) -> Result<CheckpointLayout<ReadOnly>, LayoutError> {
        self.checkpoint(height)
    }

    /// Returns if a checkpoint with the given height is verified or not.
    /// If the checkpoint is not found, an error is returned.
    pub fn checkpoint_verification_status(&self, height: Height) -> Result<bool, LayoutError> {
        let cp_name = Self::checkpoint_name(height);
        let path = self.checkpoints().join(cp_name);
        if !path.exists() {
            return Err(LayoutError::NotFound(height));
        }
        // An untracked checkpoint layout is acceptable for temporary use here, as it’s only needed briefly to verify the existence of the marker.
        let cp = CheckpointLayout::<ReadOnly>::new_untracked(path, height)?;
        Ok(cp.is_checkpoint_verified())
    }

    fn increment_checkpoint_ref_counter(&self, height: Height) {
        let mut checkpoint_ref_registry = self.checkpoint_ref_registry.lock().unwrap();
        checkpoint_ref_registry
            .entry(height)
            .or_insert(CheckpointRefData {
                checkpoint_layout_counter: 0,
                mark_deleted: false,
            })
            .checkpoint_layout_counter += 1;
    }

    fn remove_checkpoint_ref(&self, height: Height) {
        let mut checkpoint_ref_registry = self.checkpoint_ref_registry.lock().unwrap();
        match checkpoint_ref_registry.get_mut(&height) {
            None => {
                debug_assert!(false, "Double removal at height {}", height);
                return;
            }
            Some(ref mut data) => {
                debug_assert!(data.checkpoint_layout_counter >= 1);
                data.checkpoint_layout_counter -= 1;
                if data.checkpoint_layout_counter != 0 {
                    return;
                }
                let mark_deleted = data.mark_deleted;
                let _removed = checkpoint_ref_registry.remove(&height);
                debug_assert!(_removed.is_some());
                if !mark_deleted {
                    return;
                }
            }
        }
        self.remove_checkpoint_if_not_the_latest(height, checkpoint_ref_registry);
    }

    /// Schedule checkpoint for removal when no CheckpointLayout points to it.
    /// If none then remove immediately.
    pub fn remove_checkpoint_when_unused(&self, height: Height) {
        let mut checkpoint_ref_registry = self.checkpoint_ref_registry.lock().unwrap();
        match checkpoint_ref_registry.get_mut(&height) {
            Some(ref mut data) => data.mark_deleted = true,
            None => self.remove_checkpoint_if_not_the_latest(height, checkpoint_ref_registry),
        }
    }

    /// Returns a sorted list of `Height`s for which a checkpoint is available and verified.
    pub fn checkpoint_heights(&self) -> Result<Vec<Height>, LayoutError> {
        let checkpoint_heights = self
            .unfiltered_checkpoint_heights()?
            .into_iter()
            .filter(|h| self.checkpoint_verification_status(*h).unwrap_or(false))
            .collect();

        Ok(checkpoint_heights)
    }

    /// Returns a sorted list of `Height`s for which a checkpoint is available, regardless of verification status.
    pub fn unfiltered_checkpoint_heights(&self) -> Result<Vec<Height>, LayoutError> {
        let names = dir_file_names(&self.checkpoints()).map_err(|err| LayoutError::IoError {
            path: self.checkpoints(),
            message: format!("Failed to get all checkpoints (err kind: {:?})", err.kind()),
            io_err: err,
        })?;
        parse_and_sort_checkpoint_heights(&names[..])
    }

    /// Returns a sorted in ascended order list of `Height`s of checkpoints that were marked as
    /// diverged.
    pub fn diverged_checkpoint_heights(&self) -> Result<Vec<Height>, LayoutError> {
        let names = dir_file_names(&self.diverged_checkpoints()).map_err(|io_err| {
            LayoutError::IoError {
                path: self.diverged_checkpoints(),
                message: "failed to enumerate diverged checkpoints".to_string(),
                io_err,
            }
        })?;
        parse_and_sort_checkpoint_heights(&names[..])
    }

    /// Returns a sorted in ascending order list of `Height`s of states that were marked as
    /// diverged.
    pub fn diverged_state_heights(&self) -> Result<Vec<Height>, LayoutError> {
        let names = dir_file_names(&self.diverged_state_markers()).map_err(|io_err| {
            LayoutError::IoError {
                path: self.diverged_state_markers(),
                message: "failed to enumerate diverged states".to_string(),
                io_err,
            }
        })?;
        parse_and_sort_checkpoint_heights(&names[..])
    }

    /// Returns a sorted in ascended order list of heights of checkpoints that were "backed up"
    /// for future inspection because they corresponded to diverged states.
    pub fn backup_heights(&self) -> Result<Vec<Height>, LayoutError> {
        let names = dir_file_names(&self.backups()).map_err(|io_err| LayoutError::IoError {
            path: self.backups(),
            message: "failed to enumerate backups".to_string(),
            io_err,
        })?;
        parse_and_sort_checkpoint_heights(&names[..])
    }

    /// Returns a path to a diverged checkpoint given its height.
    ///
    /// If there is no diverged checkpoint with the specified height, the
    /// returned path doesn't exist on the filesystem.
    ///
    /// Precondition:
    ///   h ∈ self.diverged_checkpoint_heights()
    pub fn diverged_checkpoint_path(&self, h: Height) -> PathBuf {
        self.diverged_checkpoints().join(Self::checkpoint_name(h))
    }

    /// Returns a path to a backed up state given its height.
    ///
    /// Precondition:
    ///   h ∈ self.backup_heights()
    pub fn backup_checkpoint_path(&self, h: Height) -> PathBuf {
        self.backups().join(Self::checkpoint_name(h))
    }

    /// Removes a checkpoint for a given height if it exists.
    /// Drops drop_after_rename once the checkpoint is moved to tmp.
    ///
    /// Postcondition:
    ///   height ∉ self.checkpoint_heights()
    fn remove_checkpoint<T>(
        &self,
        height: Height,
        drop_after_rename: T,
    ) -> Result<(), LayoutError> {
        let start = Instant::now();
        let cp_name = Self::checkpoint_name(height);
        let cp_path = self.checkpoints().join(&cp_name);
        let tmp_path = self.fs_tmp().join(&cp_name);

        self.atomically_remove_via_path(&cp_path, &tmp_path, drop_after_rename)
            .map_err(|err| LayoutError::IoError {
                path: cp_path,
                message: format!(
                    "failed to remove checkpoint {} (err kind: {:?})",
                    cp_name,
                    err.kind()
                ),
                io_err: err,
            })?;
        let elapsed = start.elapsed();
        info!(self.log, "Removed checkpoint @{} in {:?}", height, elapsed);
        self.metrics
            .state_layout_remove_checkpoint_duration
            .observe(elapsed.as_secs_f64());
        Ok(())
    }

    pub fn force_remove_checkpoint(&self, height: Height) -> Result<(), LayoutError> {
        self.remove_checkpoint(height, ())
    }

    /// Removes a checkpoint for a given height if it exists and it is not the latest checkpoint.
    /// Crashes in debug if removal of the last checkpoint is ever attempted or the checkpoint is
    /// not found.
    ///
    /// Postcondition:
    ///   height ∉ self.checkpoint_heights()[0:-1]
    fn remove_checkpoint_if_not_the_latest<T>(&self, height: Height, drop_after_rename: T) {
        match self.checkpoint_heights() {
            Err(err) => {
                error!(self.log, "Failed to get checkpoint heights: {}", err);
                self.metrics
                    .state_layout_error_count
                    .with_label_values(&["remove_checkpoint_no_heights"])
                    .inc();
            }
            Ok(mut heights) => {
                if heights.is_empty() {
                    error!(
                        self.log,
                        "Trying to remove non-existing checkpoint {}. The CheckpointLayout was invalid",
                        height,
                    );
                    self.metrics
                        .state_layout_error_count
                        .with_label_values(&["remove_checkpoint_non_existent"])
                        .inc();
                    return;
                }
                if heights.pop() == Some(height) {
                    error!(self.log, "Trying to remove the last checkpoint {}", height);
                    self.metrics
                        .state_layout_error_count
                        .with_label_values(&["remove_last_checkpoint"])
                        .inc();
                    debug_assert!(false);
                    return;
                }
                if let Err(err) = self.remove_checkpoint(height, drop_after_rename) {
                    error!(self.log, "Failed to remove checkpoint: {}", err);
                    debug_assert!(false);
                    self.metrics
                        .state_layout_error_count
                        .with_label_values(&["remove_checkpoint_other"])
                        .inc();
                }
            }
        }
    }

    /// Marks the checkpoint with the specified height as diverged.
    ///
    /// Precondition:
    ///   height ∈ self.checkpoint_heights()
    ///
    /// Postcondition:
    ///   height ∈ self.diverged_checkpoint_heights() ∧
    ///   height ∉ self.checkpoint_heights()
    pub fn mark_checkpoint_diverged(&self, height: Height) -> Result<(), LayoutError> {
        let cp_name = Self::checkpoint_name(height);
        let cp_path = self.checkpoints().join(&cp_name);

        let dst_path = self.diverged_checkpoints().join(&cp_name);

        match std::fs::rename(&cp_path, dst_path) {
            Ok(()) => {
                for path in [&self.checkpoints(), &self.diverged_checkpoints()] {
                    sync_path(path).map_err(|err| LayoutError::IoError {
                        path: path.clone(),
                        message: "Failed to sync checkpoints".to_string(),
                        io_err: err,
                    })?
                }
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other.map_err(|err| LayoutError::IoError {
                path: cp_path,
                message: format!("Failed to mark checkpoint {} diverged", height),
                io_err: err,
            }),
        }
    }

    /// Path of diverged state marker for the given height.
    pub fn diverged_state_marker_path(&self, height: Height) -> PathBuf {
        self.diverged_state_markers()
            .join(Self::checkpoint_name(height))
    }

    /// Creates a diverged state marker for the given height.
    ///
    /// Postcondition:
    ///   h ∈ self.diverged_state_heights()
    pub fn create_diverged_state_marker(&self, height: Height) -> Result<(), LayoutError> {
        open_for_write(&self.diverged_state_marker_path(height))?;
        sync_path(self.diverged_state_markers()).map_err(|err| LayoutError::IoError {
            path: self.diverged_state_markers(),
            message: "Failed to sync diverged state markers".to_string(),
            io_err: err,
        })
    }

    /// Removes a diverged checkpoint given its height.
    ///
    /// Precondition:
    ///   h ∈ self.diverged_state_heights()
    pub fn remove_diverged_state_marker(&self, height: Height) -> Result<(), LayoutError> {
        let path = self.diverged_state_marker_path(height);
        remove_existing_file(&path)
    }

    /// Removes a diverged checkpoint given its height.
    ///
    /// Precondition:
    ///   h ∈ self.diverged_checkpoint_heights()
    pub fn remove_diverged_checkpoint(&self, height: Height) -> Result<(), LayoutError> {
        let checkpoint_name = Self::checkpoint_name(height);
        let cp_path = self.diverged_checkpoints().join(&checkpoint_name);
        let tmp_path = self
            .fs_tmp()
            .join(format!("diverged_checkpoint_{}", &checkpoint_name));
        self.atomically_remove_via_path(&cp_path, &tmp_path, ())
            .map_err(|err| LayoutError::IoError {
                path: cp_path,
                message: format!("failed to remove diverged checkpoint {}", height),
                io_err: err,
            })
    }

    /// Creates a copy of the checkpoint with the specified height and places it
    /// into a location that is not affected by normal state removal requests.
    ///
    /// This is mostly useful for pinning good fetched states with the same
    /// height as the locally computed diverged ones.  This makes it possible to
    /// check the difference between these two states and debug the
    /// non-determinism even if the whole subnet moved forward.
    pub fn backup_checkpoint(&self, height: Height) -> Result<(), LayoutError> {
        let cp_name = Self::checkpoint_name(height);
        let cp_path = self.checkpoints().join(&cp_name);
        if !cp_path.exists() {
            return Err(LayoutError::NotFound(height));
        }

        let backups_dir = self.backups();
        let dst = backups_dir.join(&cp_name);
        self.copy_and_sync_checkpoint(&cp_name, cp_path.as_path(), dst.as_path(), None)
            .map_err(|err| LayoutError::IoError {
                path: cp_path,
                message: format!("Failed to backup checkpoint {}", height),
                io_err: err,
            })?;
        sync_path(&backups_dir).map_err(|err| LayoutError::IoError {
            path: backups_dir,
            message: "Failed to sync backups".to_string(),
            io_err: err,
        })
    }

    /// Removes a backed up state given its height.
    ///
    /// Precondition:
    ///   h ∈ self.backup_heights()
    pub fn remove_backup(&self, height: Height) -> Result<(), LayoutError> {
        let backup_name = Self::checkpoint_name(height);
        let backup_path = self.backups().join(&backup_name);
        let tmp_path = self.fs_tmp().join(format!("backup_{}", &backup_name));
        self.atomically_remove_via_path(backup_path.as_path(), tmp_path.as_path(), ())
            .map_err(|err| LayoutError::IoError {
                path: backup_path,
                message: format!("failed to remove backup {}", height),
                io_err: err,
            })
    }

    /// Moves the checkpoint with the specified height to backup location so
    /// that state manager ignores it on restart.
    ///
    /// If checkpoint at `height` was already backed-up/archived before, it's
    /// removed.
    pub fn archive_checkpoint(&self, height: Height) -> Result<(), LayoutError> {
        let cp_name = Self::checkpoint_name(height);
        let cp_path = self.checkpoints().join(&cp_name);
        if !cp_path.exists() {
            return Err(LayoutError::NotFound(height));
        }

        let backups_dir = self.backups();
        let dst = backups_dir.join(&cp_name);

        if dst.exists() {
            // This might happen if we archived a checkpoint, then
            // recomputed it again, and then restarted again.  We don't need
            // another copy.
            return self.force_remove_checkpoint(height);
        }

        std::fs::rename(&cp_path, &dst).map_err(|err| LayoutError::IoError {
            path: cp_path,
            message: format!("failed to archive checkpoint {}", height),
            io_err: err,
        })?;

        sync_path(&backups_dir).map_err(|err| LayoutError::IoError {
            path: backups_dir,
            message: "Failed to sync backups".to_string(),
            io_err: err,
        })?;
        sync_path(self.checkpoints()).map_err(|err| LayoutError::IoError {
            path: self.checkpoints(),
            message: "Failed to sync checkpoints".to_string(),
            io_err: err,
        })
    }

    /// Returns the name of the checkpoint directory with the given block height.
    pub fn checkpoint_name(height: Height) -> String {
        format!("{:016x}", height.get())
    }

    fn tip_path(&self) -> PathBuf {
        self.raw_path().join("tip")
    }

    /// Returns the directory containing checkpoints.
    /// Pub for testing.
    pub fn checkpoints(&self) -> PathBuf {
        self.root.join(CHECKPOINTS_DIR)
    }

    fn diverged_checkpoints(&self) -> PathBuf {
        self.root.join("diverged_checkpoints")
    }

    fn diverged_state_markers(&self) -> PathBuf {
        self.root.join("diverged_state_markers")
    }

    fn backups(&self) -> PathBuf {
        self.root.join("backups")
    }

    fn ensure_dir_exists(&self, p: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(p)
    }

    /// Atomically copies a checkpoint with the specified name located at src
    /// path into the specified dst path.
    ///
    /// If a thread-pool is provided then files are copied in parallel.
    fn copy_and_sync_checkpoint(
        &self,
        name: &str,
        src: &Path,
        dst: &Path,
        thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> std::io::Result<()> {
        let scratch_name = format!("scratchpad_{}", name);
        let scratchpad = self.fs_tmp().join(scratch_name);
        self.ensure_dir_exists(&scratchpad)?;

        if dst.exists() {
            return Err(Error::new(std::io::ErrorKind::AlreadyExists, name));
        }

        let copy_atomically = || {
            copy_recursively(
                &self.log,
                &self.metrics,
                src,
                scratchpad.as_path(),
                FSync::Yes,
                |_| CopyInstruction::ReadOnly,
                thread_pool,
            )?;
            std::fs::rename(&scratchpad, dst)?;
            match dst.parent() {
                Some(parent) => sync_path(parent),
                None => Ok(()),
            }
        };

        match copy_atomically() {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = std::fs::remove_dir_all(&scratchpad);
                Err(err)
            }
        }
    }

    /// Atomically removes path by first renaming it into tmp_path, and then
    /// deleting tmp_path.
    /// Drops drop_after_rename once the path is renamed to tmp_path.
    fn atomically_remove_via_path<T>(
        &self,
        path: &Path,
        tmp_path: &Path,
        drop_after_rename: T,
    ) -> std::io::Result<()> {
        // We first move the checkpoint directory into a temporary directory to
        // maintain the invariant that <root>/checkpoints/<height> are always
        // internally consistent.
        if let Some(parent) = tmp_path.parent() {
            self.ensure_dir_exists(parent)?;
        }
        match std::fs::rename(path, tmp_path) {
            Ok(_) => {
                if let Some(parent) = path.parent() {
                    sync_path(parent)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                error!(
                    self.log,
                    "Failed to move checkpoint to tmp dir. Source: {}, Destination: {}, Error: {}.",
                    path.display(),
                    tmp_path.display(),
                    err
                );
                return Ok(());
            }
            Err(err) => return Err(err),
        }
        std::mem::drop(drop_after_rename);
        std::fs::remove_dir_all(tmp_path)
    }
}

fn is_already_exists_err(err: &std::io::Error) -> bool {
    // On Unix, if from is a directory, to must also be an (empty) directory.
    // So error code is either EEXISTS or ENOTEMPTY according to man 2 rename.
    err.kind() == std::io::ErrorKind::AlreadyExists || err.raw_os_error() == Some(libc::ENOTEMPTY)
}

/// Iterates over all the children at exact `depth` of the specified directory, applies
/// the provided transformation to each, collects them into a vector and sorts
/// them.
///
/// This function is used to list canister's in the `canister_states` directory as well as snaphots
/// in the `snapshots` directory. Note that canisters are listed at depth 0, but snapshots are at depth 1
/// as they are further grouped by their controlling canister.
fn collect_subdirs<F, T>(dir: &Path, depth: u64, transform: F) -> Result<Vec<T>, LayoutError>
where
    F: Fn(&str) -> Result<T, String>,
    T: Ord,
{
    fn collect_subdirs_recursive<F, T>(
        dir: &Path,
        depth: u64,
        transform: &F,
        result: &mut Vec<T>,
    ) -> Result<(), LayoutError>
    where
        F: Fn(&str) -> Result<T, String>,
    {
        let entries = dir.read_dir().map_err(|err| LayoutError::IoError {
            path: dir.to_path_buf(),
            message: "Failed to read directory".to_string(),
            io_err: err,
        })?;

        for entry in entries {
            let dir = entry.map_err(|err| LayoutError::IoError {
                path: dir.to_path_buf(),
                message: "Failed to get dir entry".to_string(),
                io_err: err,
            })?;

            match dir.file_name().to_str() {
                Some(file_name) => {
                    if depth == 0 {
                        result.push(transform(file_name).map_err(|err| {
                            LayoutError::CorruptedLayout {
                                path: dir.path(),
                                message: err,
                            }
                        })?)
                    } else {
                        collect_subdirs_recursive(&dir.path(), depth - 1, transform, result)?;
                    }
                }
                None => {
                    return Err(LayoutError::CorruptedLayout {
                        path: dir.path(),
                        message: "not UTF-8".into(),
                    })
                }
            }
        }
        Ok(())
    }

    if !dir.exists() {
        return Ok(Vec::default());
    }

    let mut transformed_subdirs = Vec::new();
    collect_subdirs_recursive(dir, depth, &transform, &mut transformed_subdirs)?;
    transformed_subdirs.sort();
    Ok(transformed_subdirs)
}

/// Helper for parsing hex representations of canister IDs, used for the
/// directory names under `canister_states`).
fn parse_canister_id(hex: &str) -> Result<CanisterId, String> {
    let blob = hex::decode(hex).map_err(|err| {
        format!(
            "failed to convert directory name {} into a canister ID: {}",
            hex, err
        )
    })?;

    Ok(CanisterId::unchecked_from_principal(
        PrincipalId::try_from(&blob[..])
            .map_err(|err| format!("failed to parse principal ID: {}", err))?,
    ))
}

/// Helper for parsing hex representations of snapshot IDs, used for the
/// directory names under `snapshots`).
fn parse_snapshot_id(hex: &str) -> Result<SnapshotId, String> {
    let blob = hex::decode(hex).map_err(|err| {
        format!(
            "failed to convert directory name {} into a snapshot ID: {}",
            hex, err
        )
    })?;

    SnapshotId::try_from(&blob).map_err(|err| format!("failed to parse snapshot ID: {}", err))
}

/// Parses the canister ID from a relative path, if it is the path of a canister or snapshot
/// state file (e.g. `canister_states/00000000000000010101/queues.pbuf`).
/// Returns `None` if the path is not under `canister_states` or `snapshots`; or if parsing
/// fails.
pub fn canister_id_from_path(path: &Path) -> Option<CanisterId> {
    let mut path = path.iter();
    let top_level = path.next();
    if top_level == Some(OsStr::new(CANISTER_STATES_DIR))
        || top_level == Some(OsStr::new(SNAPSHOTS_DIR))
    {
        if let Some(hex) = path.next() {
            return parse_canister_id(hex.to_str()?).ok();
        }
    }
    None
}

fn parse_and_sort_checkpoint_heights(names: &[String]) -> Result<Vec<Height>, LayoutError> {
    let mut heights = names
        .iter()
        .map(|name| {
            u64::from_str_radix(name.as_str(), 16)
                .map(Height::new)
                .map_err(|e| LayoutError::CorruptedLayout {
                    path: name.into(),
                    message: format!(
                        "failed to convert checkpoint name {} into a number: {}",
                        name, e
                    ),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    heights.sort_unstable();

    Ok(heights)
}

pub struct CheckpointLayout<Permissions: AccessPolicy> {
    root: PathBuf,
    height: Height,
    // The StateLayout is used to make sure we never remove the CheckpointLayout when still in use.
    // Is not None for CheckpointLayout pointing to "real" checkpoints, that is checkpoints in
    // StateLayout's root/checkpoints/..., that are tracked by StateLayout
    state_layout: Option<StateLayout>,
    permissions_tag: PhantomData<Permissions>,
}

impl<Permissions: AccessPolicy> Drop for CheckpointLayout<Permissions> {
    fn drop(&mut self) {
        if let Some(state_layout) = &self.state_layout {
            state_layout.remove_checkpoint_ref(self.height)
        }
    }
}

impl Clone for CheckpointLayout<ReadOnly> {
    fn clone(&self) -> Self {
        let result = Self {
            root: self.root.clone(),
            height: self.height,
            state_layout: self.state_layout.clone(),
            permissions_tag: self.permissions_tag,
        };
        // Increment after result is constructed in case one of the field clone()'s
        // panics
        if let Some(ref state_layout) = self.state_layout {
            state_layout.increment_checkpoint_ref_counter(self.height);
        }
        result
    }
}

impl<Permissions: AccessPolicy> std::fmt::Debug for CheckpointLayout<Permissions> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "checkpoint layout #{}, path: #{}",
            self.height,
            self.root.display()
        )
    }
}

impl<Permissions: AccessPolicy> CheckpointLayout<Permissions> {
    pub fn new(
        root: PathBuf,
        height: Height,
        state_layout: StateLayout,
    ) -> Result<Self, LayoutError> {
        Permissions::check_dir(&root)?;
        Ok(Self {
            root,
            height,
            state_layout: Some(state_layout),
            permissions_tag: PhantomData,
        })
    }

    pub fn new_untracked(root: PathBuf, height: Height) -> Result<Self, LayoutError> {
        Permissions::check_dir(&root)?;
        Ok(Self {
            root,
            height,
            state_layout: None,
            permissions_tag: PhantomData,
        })
    }

    pub fn system_metadata(&self) -> ProtoFileWith<pb_metadata::SystemMetadata, Permissions> {
        self.root.join(SYSTEM_METADATA_FILE).into()
    }

    pub fn ingress_history(&self) -> ProtoFileWith<pb_ingress::IngressHistoryState, Permissions> {
        self.root.join(INGRESS_HISTORY_FILE).into()
    }

    pub fn subnet_queues(&self) -> ProtoFileWith<pb_queues::CanisterQueues, Permissions> {
        self.root.join(SUBNET_QUEUES_FILE).into()
    }

    pub fn split_marker(&self) -> ProtoFileWith<pb_metadata::SplitFrom, Permissions> {
        self.root.join(SPLIT_MARKER_FILE).into()
    }

    pub fn stats(&self) -> ProtoFileWith<pb_stats::Stats, Permissions> {
        self.root.join(STATS_FILE).into()
    }

    pub fn unverified_checkpoint_marker(&self) -> PathBuf {
        self.root.join(UNVERIFIED_CHECKPOINT_MARKER)
    }

    pub fn canister_ids(&self) -> Result<Vec<CanisterId>, LayoutError> {
        let states_dir = self.root.join(CANISTER_STATES_DIR);
        Permissions::check_dir(&states_dir)?;
        collect_subdirs(states_dir.as_path(), 0, parse_canister_id)
    }

    pub fn canister(
        &self,
        canister_id: &CanisterId,
    ) -> Result<CanisterLayout<Permissions>, LayoutError> {
        CanisterLayout::new(
            self.root
                .join(CANISTER_STATES_DIR)
                .join(hex::encode(canister_id.get_ref().as_slice())),
        )
    }

    /// Lists all snapshots in the checkpoint.
    pub fn snapshot_ids(&self) -> Result<Vec<SnapshotId>, LayoutError> {
        let snapshots_dir = self.root.join(SNAPSHOTS_DIR);
        Permissions::check_dir(&snapshots_dir)?;
        collect_subdirs(snapshots_dir.as_path(), 1, parse_snapshot_id)
    }

    /// Directory where the snapshot for `snapshot_id` is stored.
    /// Note that we store them by canister. This means we have the canister id in the path, which is
    /// necessary in the context of subnet splitting. Also see [`canister_id_from_path`].
    pub fn snapshot(
        &self,
        snapshot_id: &SnapshotId,
    ) -> Result<SnapshotLayout<Permissions>, LayoutError> {
        SnapshotLayout::new(
            self.root
                .join(SNAPSHOTS_DIR)
                .join(hex::encode(
                    snapshot_id.get_canister_id().get_ref().as_slice(),
                ))
                .join(hex::encode(snapshot_id.as_slice())),
        )
    }

    pub fn height(&self) -> Height {
        self.height
    }

    pub fn raw_path(&self) -> &Path {
        &self.root
    }

    /// Returns if the checkpoint is marked as unverified or not.
    pub fn is_checkpoint_verified(&self) -> bool {
        !self.unverified_checkpoint_marker().exists()
    }
}

impl<P> CheckpointLayout<P>
where
    P: WritePolicy,
{
    /// Creates the unverified checkpoint marker.
    /// If the marker already exists, this function does nothing and returns `Ok(())`.
    ///
    /// Only the checkpoint layout with write policy can create the unverified checkpoint marker,
    /// e.g. state sync scratchpad and tip.
    pub fn create_unverified_checkpoint_marker(&self) -> Result<(), LayoutError> {
        let marker = self.unverified_checkpoint_marker();
        if marker.exists() {
            return Ok(());
        }
        open_for_write(&marker)?;
        sync_path(&self.root).map_err(|err| LayoutError::IoError {
            path: self.root.clone(),
            message: "Failed to sync checkpoint directory for the creation of the unverified checkpoint marker".to_string(),
            io_err: err,
        })
    }
}

impl CheckpointLayout<ReadOnly> {
    /// Removes the unverified checkpoint marker.
    /// If the marker does not exist, this function does nothing and returns `Ok(())`.
    ///
    /// A readonly checkpoint typically prevents modification to the files in the checkpoint.
    /// However, the removal of the unverified checkpoint marker is allowed as
    /// the marker is not part the checkpoint conceptually.
    pub fn remove_unverified_checkpoint_marker(&self) -> Result<(), LayoutError> {
        let marker = self.unverified_checkpoint_marker();
        if !marker.exists() {
            return Ok(());
        }
        match std::fs::remove_file(&marker) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                return Err(LayoutError::IoError {
                    path: marker.to_path_buf(),
                    message: "failed to remove file from disk".to_string(),
                    io_err: err,
                });
            }
            _ => {}
        }

        // Sync the directory to make sure the marker is removed from disk.
        // This is strict prerequisite for the manifest computation.
        sync_path(&self.root).map_err(|err| LayoutError::IoError {
            path: self.root.clone(),
            message: "Failed to sync checkpoint directory for the creation of the unverified checkpoint marker".to_string(),
            io_err: err,
        })
    }
}

pub struct PageMapLayout<Permissions: AccessPolicy> {
    root: PathBuf,
    name_stem: String,
    permissions_tag: PhantomData<Permissions>,
}

impl<P> PageMapLayout<P>
where
    P: WritePolicy,
{
    /// Remove the base file and all overlay files.
    pub fn delete_files(&self) -> Result<(), LayoutError> {
        let base = self.base();
        if base.exists() {
            std::fs::remove_file(base.clone()).map_err(|err| LayoutError::IoError {
                path: base,
                message: "Failed to delete file".to_string(),
                io_err: err,
            })?;
        }

        for overlay in self.existing_overlays()? {
            std::fs::remove_file(overlay.clone()).map_err(|err| LayoutError::IoError {
                path: overlay,
                message: "Failed to delete file".to_string(),
                io_err: err,
            })?;
        }

        Ok(())
    }
}

impl<Permissions: AccessPolicy> PageMapLayout<Permissions> {
    /// List of overlay files on disk.
    ///
    /// All overlay files have the format {numbers}{name_stem}.overlay`, where `name_stem` distinguises
    /// between wasm memory, stable memory etc, and the numbers impose an ordering of the
    /// overlay files, with later alphabetically denoting a higher-priority overlay. The numbers are
    /// typically the height when the overlay was written and a shard number.
    ///
    /// Note that this function returns a `LayoutError`. There is a function implementing the `StorageLayout` trait
    /// with the same name, return a `Box<dyn Error>`. Calling `existing_overlays()` on a `PageMapLayout` will call
    /// this function, calling it on a `dyn StorageLayout` will call the trait function. This simplifies error propagation.
    pub fn existing_overlays(&self) -> Result<Vec<PathBuf>, LayoutError> {
        let map_error = |err| LayoutError::IoError {
            path: self.root.clone(),
            message: "Failed list overlays".to_string(),
            io_err: err,
        };

        let name_end = format!("_{}.overlay", self.name_stem);

        let files = std::fs::read_dir(&self.root).map_err(map_error)?;
        let mut result = Vec::default();
        for file in files {
            let path = file.map_err(map_error)?.path();
            match path.to_str() {
                Some(p) if p.ends_with(&name_end) => {
                    result.push(path);
                }
                _ => (),
            }
        }
        result.sort();

        Ok(result)
    }

    /// Helper function to copy the files from `PageMapsLayout` `src` to another `PageMapLayout` `dst`.
    /// This is used in the context of canister snapshots, where files need to be copied from a canister
    /// to a snaphsot or vice versa.
    pub fn copy_or_hardlink_files<W>(
        log: &ReplicaLogger,
        src: &PageMapLayout<Permissions>,
        dst: &PageMapLayout<W>,
        dst_permissions: FilePermissions,
    ) -> Result<(), LayoutError>
    where
        W: WritePolicy,
    {
        debug_assert_eq!(src.name_stem, dst.name_stem);

        if src.base().exists() {
            copy_file_and_set_permissions(log, &src.base(), &dst.base(), dst_permissions).map_err(
                |err| LayoutError::IoError {
                    path: dst.base(),
                    message: format!(
                        "Cannot copy or hardlink file {:?} to {:?}",
                        src.base(),
                        dst.base()
                    ),
                    io_err: err,
                },
            )?;
        }
        for overlay in src.existing_overlays()? {
            let dst_path = dst.root.join(overlay.file_name().unwrap());
            copy_file_and_set_permissions(log, &overlay, &dst_path, dst_permissions).map_err(
                |err| LayoutError::IoError {
                    path: dst.base(),
                    message: format!(
                        "Cannot copy or hardlink file {:?} to {:?}",
                        overlay, dst_path
                    ),
                    io_err: err,
                },
            )?;
        }

        Ok(())
    }
}

impl<Permissions: AccessPolicy> StorageLayout for PageMapLayout<Permissions> {
    // The path to the base file.
    fn base(&self) -> PathBuf {
        self.root.join(format!("{}.bin", self.name_stem))
    }

    /// Overlay path encoding, consistent with `overlay_height()` and `overlay_shard()`
    fn overlay(&self, height: Height, shard: Shard) -> PathBuf {
        self.root.join(format!(
            "{:016x}_{:04x}_{}.overlay",
            height.get(),
            shard.get(),
            self.name_stem,
        ))
    }

    /// List of overlay files on disk.
    fn existing_overlays(&self) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
        Ok(self.existing_overlays()?)
    }

    /// Get overlay height as encoded in the file name.
    fn overlay_height(&self, overlay: &Path) -> Result<Height, Box<dyn std::error::Error>> {
        let file_name = overlay
            .file_name()
            .ok_or(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "No file name".to_owned(),
            })?
            .to_str()
            .ok_or(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "Cannot convert file name to string".to_owned(),
            })?;
        let hex = file_name
            .split('_')
            .next()
            .ok_or(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "Cannot parse file name".to_owned(),
            })?;
        u64::from_str_radix(hex, 16)
            .map(Height::new)
            .map_err(|err| {
                LayoutError::CorruptedLayout {
                    path: overlay.to_path_buf(),
                    message: format!("failed to get height for overlay {}: {}", hex, err),
                }
                .into()
            })
    }

    /// Get overlay shard as encoded in the file name.
    fn overlay_shard(&self, overlay: &Path) -> Result<Shard, Box<dyn std::error::Error>> {
        let file_name = overlay
            .file_name()
            .ok_or(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "No file name".to_owned(),
            })?
            .to_str()
            .ok_or(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "Cannot convert file name to string".to_owned(),
            })?;
        let hex = file_name
            .split('_')
            .nth(1)
            .ok_or(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "Cannot parse file name".to_owned(),
            })?;
        u64::from_str_radix(hex, 16).map(Shard::new).map_err(|err| {
            LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: format!("failed to get shard for overlay {}: {}", hex, err),
            }
            .into()
        })
    }
}

pub struct CanisterLayout<Permissions: AccessPolicy> {
    canister_root: PathBuf,
    permissions_tag: PhantomData<Permissions>,
}

impl<Permissions: AccessPolicy> CanisterLayout<Permissions> {
    pub fn new(canister_root: PathBuf) -> Result<Self, LayoutError> {
        Permissions::check_dir(&canister_root)?;
        Ok(Self {
            canister_root,
            permissions_tag: PhantomData,
        })
    }

    pub fn raw_path(&self) -> PathBuf {
        self.canister_root.clone()
    }

    pub fn queues(&self) -> ProtoFileWith<pb_queues::CanisterQueues, Permissions> {
        self.canister_root.join(QUEUES_FILE).into()
    }

    pub fn wasm(&self) -> WasmFile<Permissions> {
        self.canister_root.join(WASM_FILE).into()
    }

    pub fn canister(
        &self,
    ) -> ProtoFileWith<pb_canister_state_bits::CanisterStateBits, Permissions> {
        self.canister_root.join(CANISTER_FILE).into()
    }

    pub fn vmemory_0(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.canister_root.clone(),
            name_stem: "vmemory_0".into(),
            permissions_tag: PhantomData,
        }
    }

    pub fn stable_memory(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.canister_root.clone(),
            name_stem: "stable_memory".into(),
            permissions_tag: PhantomData,
        }
    }

    pub fn wasm_chunk_store(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.canister_root.clone(),
            name_stem: "wasm_chunk_store".into(),
            permissions_tag: PhantomData,
        }
    }
}

pub struct SnapshotLayout<Permissions: AccessPolicy> {
    snapshot_root: PathBuf,
    permissions_tag: PhantomData<Permissions>,
}

impl<Permissions: AccessPolicy> SnapshotLayout<Permissions> {
    pub fn new(snapshot_root: PathBuf) -> Result<Self, LayoutError> {
        Permissions::check_dir(&snapshot_root)?;
        Ok(Self {
            snapshot_root,
            permissions_tag: PhantomData,
        })
    }

    pub fn raw_path(&self) -> PathBuf {
        self.snapshot_root.clone()
    }

    pub fn wasm(&self) -> WasmFile<Permissions> {
        self.snapshot_root.join(WASM_FILE).into()
    }

    pub fn snapshot(
        &self,
    ) -> ProtoFileWith<pb_canister_snapshot_bits::CanisterSnapshotBits, Permissions> {
        self.snapshot_root.join(SNAPSHOT_FILE).into()
    }

    pub fn vmemory_0(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.snapshot_root.clone(),
            name_stem: "vmemory_0".into(),
            permissions_tag: PhantomData,
        }
    }

    pub fn stable_memory(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.snapshot_root.clone(),
            name_stem: "stable_memory".into(),
            permissions_tag: PhantomData,
        }
    }

    pub fn wasm_chunk_store(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.snapshot_root.clone(),
            name_stem: "wasm_chunk_store".into(),
            permissions_tag: PhantomData,
        }
    }
}

impl<P> SnapshotLayout<P>
where
    P: WritePolicy,
{
    /// Remove the entire directory for the snapshot.
    pub fn delete_dir(&self) -> Result<(), LayoutError> {
        let map_error = |err| LayoutError::IoError {
            path: self.raw_path(),
            message: "Cannot remove snapshot.".to_string(),
            io_err: err,
        };

        std::fs::remove_dir_all(self.raw_path()).map_err(map_error)?;

        // Remove the parent directory named after the canister if this was the last snapshot of that canister.
        // Unwrap is safe as snapshots are not at located at `/`.
        let parent = self.raw_path().parent().unwrap().to_owned();

        if parent.read_dir().map_err(map_error)?.next().is_none() {
            std::fs::remove_dir(&parent).map_err(map_error)?;
        }

        Ok(())
    }
}

fn open_for_write(path: &Path) -> Result<std::fs::File, LayoutError> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|err| LayoutError::IoError {
            path: path.to_path_buf(),
            message: "Failed to open file for write".to_string(),
            io_err: err,
        })
}

fn create_for_write(path: &Path) -> Result<std::fs::File, LayoutError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .truncate(true)
        .open(path)
        .map_err(|err| LayoutError::IoError {
            path: path.to_path_buf(),
            message: "Failed to open file for write".to_string(),
            io_err: err,
        })
}

fn open_for_read(path: &Path) -> Result<std::fs::File, LayoutError> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|err| LayoutError::IoError {
            path: path.to_path_buf(),
            message: "Failed to open file for read".to_string(),
            io_err: err,
        })
}

/// Removes the given file, returning an error if the file does not exist, as
/// well as for any other I/O error.
fn remove_existing_file(path: &Path) -> Result<(), LayoutError> {
    std::fs::remove_file(path).map_err(|err| LayoutError::IoError {
        path: path.to_path_buf(),
        message: "failed to remove file from disk".to_string(),
        io_err: err,
    })
}

/// Tries removing the given file. Returns `Ok(())` if the file was deleted or
/// did not exist; or a `LayoutError::IoError` otherwise.
fn try_remove_file(path: &Path) -> Result<(), LayoutError> {
    if path.exists() {
        remove_existing_file(path)
    } else {
        Ok(())
    }
}

pub struct ProtoFileWith<T, Permissions> {
    path: PathBuf,
    content_tag: PhantomData<T>,
    permissions_tag: PhantomData<Permissions>,
}

impl<T, Permission> ProtoFileWith<T, Permission> {
    pub fn raw_path(&self) -> &Path {
        &self.path
    }

    /// Removes the file if it exists, else does nothing.
    pub fn try_remove_file(&self) -> Result<(), LayoutError> {
        try_remove_file(&self.path)
    }
}

impl<T, P> ProtoFileWith<T, P>
where
    T: prost::Message,
    P: WritePolicy,
{
    pub fn serialize(&self, value: T) -> Result<(), LayoutError> {
        // There should be no existing file, due to how we initialize the tip.
        // We delete just in case.
        self.try_remove_file()?;

        let serialized = value.encode_to_vec();

        if serialized.is_empty() {
            return Ok(());
        }

        let file = create_for_write(&self.path)?;
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(&serialized)
            .map_err(|io_err| LayoutError::IoError {
                path: self.path.clone(),
                message: "failed to write serialized protobuf to disk".to_string(),
                io_err,
            })?;

        writer.into_inner().map_err(|err| LayoutError::IoError {
            path: self.path.clone(),
            message: "failed to flush buffers to file".to_string(),
            io_err: std::io::Error::new(err.error().kind(), err.to_string()),
        })?;

        mark_readonly_if_file(&self.path).map_err(|err| LayoutError::IoError {
            path: self.path.clone(),
            message: "failed to mark protobuf as readonly".to_string(),
            io_err: err,
        })
    }
}

impl<T, P> ProtoFileWith<T, P>
where
    T: prost::Message + std::default::Default,
    P: ReadPolicy,
{
    /// Deserializes the value from the underlying file.
    /// If the file does not exist, deserialize as an empty buffer.
    /// Returns an error for all other I/O errors.
    pub fn deserialize(&self) -> Result<T, LayoutError> {
        match open_for_read(&self.path) {
            Ok(f) => self.deserialize_file(f),
            Err(LayoutError::IoError { io_err, .. })
                if io_err.kind() == std::io::ErrorKind::NotFound =>
            {
                self.deserialize_buffer(&[])
            }
            Err(err) => Err(err),
        }
    }

    fn deserialize_file(&self, f: std::fs::File) -> Result<T, LayoutError> {
        let mmap = ScopedMmap::mmap_file_readonly(f).map_err(|io_err| LayoutError::IoError {
            path: self.path.clone(),
            message: "failed to mmap a file".to_string(),
            io_err,
        })?;
        self.deserialize_buffer(mmap.as_slice())
    }

    fn deserialize_buffer(&self, buf: &[u8]) -> Result<T, LayoutError> {
        T::decode(buf).map_err(|err| LayoutError::CorruptedLayout {
            path: self.path.clone(),
            message: format!(
                "failed to deserialize an object of type {} from protobuf: {}",
                std::any::type_name::<T>(),
                err
            ),
        })
    }
}

impl<T, Permissions> From<PathBuf> for ProtoFileWith<T, Permissions>
where
    T: prost::Message,
{
    fn from(path: PathBuf) -> Self {
        Self {
            path,
            content_tag: PhantomData,
            permissions_tag: PhantomData,
        }
    }
}

/// A value of type `WasmFile` declares that some path should contain
/// a Wasm module and provides a way to read it from disk or write it
/// to disk.
pub struct WasmFile<Permissions> {
    path: PathBuf,
    permissions_tag: PhantomData<Permissions>,
}

impl<T> WasmFile<T> {
    pub fn raw_path(&self) -> &Path {
        &self.path
    }
}

impl<T> WasmFile<T>
where
    T: ReadPolicy,
{
    pub fn deserialize(
        &self,
        module_hash: Option<WasmHash>,
    ) -> Result<CanisterModule, LayoutError> {
        CanisterModule::new_from_file(self.path.clone(), module_hash).map_err(|err| {
            LayoutError::IoError {
                path: self.path.clone(),
                message: "Failed to read file contents".to_string(),
                io_err: err,
            }
        })
    }

    /// Hardlink the (readonly) file from `src` to `dst`.
    pub fn hardlink_file<W>(src: &WasmFile<T>, dst: &WasmFile<W>) -> Result<(), LayoutError>
    where
        W: WritePolicy,
    {
        let src_path = src.raw_path();
        let dst_path = dst.raw_path();

        if !src_path.exists() {
            return Ok(());
        }

        #[cfg(debug_assertions)]
        {
            let src_metadata = src_path.metadata().map_err(|err| LayoutError::IoError {
                path: src_path.to_path_buf(),
                message: "Failed to read metadata".to_string(),
                io_err: err,
            })?;
            debug_assert!(src_metadata.permissions().readonly());
        }

        std::fs::hard_link(src_path, dst_path).map_err(|err| LayoutError::IoError {
            path: src_path.to_path_buf(),
            message: format!(
                "Failed to hardlink {:?} to {:?} while making a canister snapshot",
                src_path, dst_path,
            ),
            io_err: err,
        })?;
        Ok(())
    }
}

impl<T> WasmFile<T>
where
    T: WritePolicy,
{
    pub fn serialize(&self, wasm: &CanisterModule) -> Result<(), LayoutError> {
        // If there already exists a wasm file, delete it first to avoid writing hardlinked/readonly files.
        self.try_delete_file()?;

        let mut file = create_for_write(&self.path)?;
        file.write_all(wasm.as_slice())
            .map_err(|err| LayoutError::IoError {
                path: self.path.clone(),
                message: "failed to write wasm binary to file".to_string(),
                io_err: err,
            })?;

        file.flush().map_err(|err| LayoutError::IoError {
            path: self.path.clone(),
            message: "failed to flush wasm binary to disk".to_string(),
            io_err: err,
        })?;

        file.sync_all().map_err(|err| LayoutError::IoError {
            path: self.path.clone(),
            message: "failed to sync wasm binary to disk".to_string(),
            io_err: err,
        })?;

        mark_readonly_if_file(&self.path).map_err(|err| LayoutError::IoError {
            path: self.path.clone(),
            message: "failed to mark wasm binary as readonly".to_string(),
            io_err: err,
        })
    }

    /// Removes the file if it exists, else does nothing.
    pub fn try_delete_file(&self) -> Result<(), LayoutError> {
        try_remove_file(&self.path)
    }
}

impl<Permissions> From<PathBuf> for WasmFile<Permissions> {
    fn from(path: PathBuf) -> Self {
        Self {
            path,
            permissions_tag: PhantomData,
        }
    }
}

impl From<CanisterStateBits> for pb_canister_state_bits::CanisterStateBits {
    fn from(item: CanisterStateBits) -> Self {
        Self {
            controllers: item
                .controllers
                .into_iter()
                .map(|controller| controller.into())
                .collect(),
            last_full_execution_round: item.last_full_execution_round.get(),
            call_context_manager: item.call_context_manager.as_ref().map(|v| v.into()),
            compute_allocation: item.compute_allocation.as_percent(),
            accumulated_priority: item.accumulated_priority.get(),
            priority_credit: item.priority_credit.get(),
            long_execution_mode: pb_canister_state_bits::LongExecutionMode::from(
                item.long_execution_mode,
            )
            .into(),
            execution_state_bits: item.execution_state_bits.as_ref().map(|v| v.into()),
            memory_allocation: item.memory_allocation.bytes().get(),
            wasm_memory_threshold: Some(item.wasm_memory_threshold.get()),
            freeze_threshold: item.freeze_threshold.get(),
            cycles_balance: Some(item.cycles_balance.into()),
            cycles_debit: Some(item.cycles_debit.into()),
            reserved_balance: Some(item.reserved_balance.into()),
            reserved_balance_limit: item.reserved_balance_limit.map(|v| v.into()),
            canister_status: Some((&item.status).into()),
            scheduled_as_first: item.scheduled_as_first,
            skipped_round_due_to_no_messages: item.skipped_round_due_to_no_messages,
            executed: item.executed,
            interrupted_during_execution: item.interrupted_during_execution,
            certified_data: item.certified_data.clone(),
            consumed_cycles: Some((&item.consumed_cycles).into()),
            stable_memory_size64: item.stable_memory_size.get() as u64,
            heap_delta_debit: item.heap_delta_debit.get(),
            install_code_debit: item.install_code_debit.get(),
            time_of_last_allocation_charge_nanos: Some(item.time_of_last_allocation_charge_nanos),
            task_queue: item.task_queue.iter().map(|v| v.into()).collect(),
            global_timer_nanos: item.global_timer_nanos,
            canister_version: item.canister_version,
            consumed_cycles_by_use_cases: item
                .consumed_cycles_by_use_cases
                .into_iter()
                .map(
                    |(use_case, cycles)| pb_canister_state_bits::ConsumedCyclesByUseCase {
                        use_case: pb_canister_state_bits::CyclesUseCase::from(use_case).into(),
                        cycles: Some((&cycles).into()),
                    },
                )
                .collect(),
            canister_history: Some((&item.canister_history).into()),
            wasm_chunk_store_metadata: Some((&item.wasm_chunk_store_metadata).into()),
            total_query_stats: Some((&item.total_query_stats).into()),
            log_visibility_v2: pb_canister_state_bits::LogVisibilityV2::from(&item.log_visibility)
                .into(),
            canister_log_records: item
                .canister_log
                .records()
                .iter()
                .map(|record| record.into())
                .collect(),
            next_canister_log_record_idx: item.canister_log.next_idx(),
            wasm_memory_limit: item.wasm_memory_limit.map(|v| v.get()),
            next_snapshot_id: item.next_snapshot_id,
            snapshots_memory_usage: item.snapshots_memory_usage.get(),
        }
    }
}

impl TryFrom<pb_canister_state_bits::CanisterStateBits> for CanisterStateBits {
    type Error = ProxyDecodeError;

    fn try_from(value: pb_canister_state_bits::CanisterStateBits) -> Result<Self, Self::Error> {
        let execution_state_bits = value
            .execution_state_bits
            .map(|b| b.try_into())
            .transpose()?;
        let call_context_manager = value
            .call_context_manager
            .map(|c| c.try_into())
            .transpose()?;

        let consumed_cycles = match try_from_option_field(
            value.consumed_cycles,
            "CanisterStateBits::consumed_cycles",
        ) {
            Ok(consumed_cycles) => consumed_cycles,
            Err(_) => NominalCycles::default(),
        };

        let mut controllers = BTreeSet::new();
        for controller in value.controllers.into_iter() {
            controllers.insert(PrincipalId::try_from(controller)?);
        }

        let cycles_balance =
            try_from_option_field(value.cycles_balance, "CanisterStateBits::cycles_balance")?;

        let cycles_debit = value
            .cycles_debit
            .map(|c| c.into())
            .unwrap_or_else(Cycles::zero);

        let reserved_balance = value
            .reserved_balance
            .map(|c| c.into())
            .unwrap_or_else(Cycles::zero);

        let task_queue: Vec<_> = value
            .task_queue
            .into_iter()
            .map(|v| v.try_into())
            .collect::<Result<_, _>>()?;
        if task_queue.len() > 1 {
            return Err(ProxyDecodeError::Other(format!(
                "Expecting at most one task queue entry. Found {:?}",
                task_queue
            )));
        }

        let mut consumed_cycles_by_use_cases = BTreeMap::new();
        for x in value.consumed_cycles_by_use_cases.into_iter() {
            consumed_cycles_by_use_cases.insert(
                CyclesUseCase::try_from(
                    pb_canister_state_bits::CyclesUseCase::try_from(x.use_case).map_err(|_| {
                        ProxyDecodeError::ValueOutOfRange {
                            typ: "CyclesUseCase",
                            err: format!("Unexpected value of cycles use case: {}", x.use_case),
                        }
                    })?,
                )?,
                NominalCycles::try_from(x.cycles.unwrap_or_default()).unwrap_or_default(),
            );
        }

        Ok(Self {
            controllers,
            last_full_execution_round: value.last_full_execution_round.into(),
            call_context_manager,
            compute_allocation: ComputeAllocation::try_from(value.compute_allocation).map_err(
                |e| ProxyDecodeError::ValueOutOfRange {
                    typ: "ComputeAllocation",
                    err: format!("{:?}", e),
                },
            )?,
            accumulated_priority: value.accumulated_priority.into(),
            priority_credit: value.priority_credit.into(),
            long_execution_mode: pb_canister_state_bits::LongExecutionMode::try_from(
                value.long_execution_mode,
            )
            .unwrap_or_default()
            .into(),
            execution_state_bits,
            memory_allocation: MemoryAllocation::try_from(NumBytes::from(value.memory_allocation))
                .map_err(|e| ProxyDecodeError::ValueOutOfRange {
                    typ: "MemoryAllocation",
                    err: format!("{:?}", e),
                })?,
            wasm_memory_threshold: NumBytes::new(value.wasm_memory_threshold.unwrap_or(0)),
            freeze_threshold: NumSeconds::from(value.freeze_threshold),
            cycles_balance,
            cycles_debit,
            reserved_balance,
            reserved_balance_limit: value.reserved_balance_limit.map(|v| v.into()),
            status: try_from_option_field(
                value.canister_status,
                "CanisterStateBits::canister_status",
            )?,
            scheduled_as_first: value.scheduled_as_first,
            skipped_round_due_to_no_messages: value.skipped_round_due_to_no_messages,
            executed: value.executed,
            interrupted_during_execution: value.interrupted_during_execution,
            certified_data: value.certified_data,
            consumed_cycles,
            stable_memory_size: NumWasmPages::from(value.stable_memory_size64 as usize),
            heap_delta_debit: NumBytes::from(value.heap_delta_debit),
            install_code_debit: NumInstructions::from(value.install_code_debit),
            time_of_last_allocation_charge_nanos: try_from_option_field(
                value.time_of_last_allocation_charge_nanos,
                "CanisterStateBits::time_of_last_allocation_charge_nanos",
            )?,
            task_queue,
            global_timer_nanos: value.global_timer_nanos,
            canister_version: value.canister_version,
            consumed_cycles_by_use_cases,
            // TODO(MR-412): replace `unwrap_or_default` by returning an error on missing canister_history field
            canister_history: try_from_option_field(
                value.canister_history,
                "CanisterStateBits::canister_history",
            )
            .unwrap_or_default(),
            wasm_chunk_store_metadata: try_from_option_field(
                value.wasm_chunk_store_metadata,
                "CanisterStateBits::wasm_chunk_store_metadata",
            )
            .unwrap_or_default(),
            total_query_stats: try_from_option_field(
                value.total_query_stats,
                "CanisterStateBits::total_query_stats",
            )
            .unwrap_or_default(),
            log_visibility: try_from_option_field(
                value.log_visibility_v2,
                "CanisterStateBits::log_visibility_v2",
            )
            .unwrap_or_default(),
            canister_log: CanisterLog::new(
                value.next_canister_log_record_idx,
                value
                    .canister_log_records
                    .into_iter()
                    .map(|record| record.into())
                    .collect(),
            ),
            wasm_memory_limit: value.wasm_memory_limit.map(NumBytes::from),
            next_snapshot_id: value.next_snapshot_id,
            snapshots_memory_usage: NumBytes::from(value.snapshots_memory_usage),
        })
    }
}

impl From<&ExecutionStateBits> for pb_canister_state_bits::ExecutionStateBits {
    fn from(item: &ExecutionStateBits) -> Self {
        Self {
            exported_globals: item
                .exported_globals
                .iter()
                .map(|global| global.into())
                .collect(),
            heap_size: item
                .heap_size
                .get()
                .try_into()
                .expect("Canister heap size didn't fit into 32 bits"),
            exports: (&item.exports).into(),
            last_executed_round: item.last_executed_round.get(),
            metadata: Some((&item.metadata).into()),
            binary_hash: item.binary_hash.as_ref().map(|h| h.to_vec()),
            next_scheduled_method: Some(
                pb_canister_state_bits::NextScheduledMethod::from(item.next_scheduled_method)
                    .into(),
            ),
        }
    }
}

impl TryFrom<pb_canister_state_bits::ExecutionStateBits> for ExecutionStateBits {
    type Error = ProxyDecodeError;

    fn try_from(value: pb_canister_state_bits::ExecutionStateBits) -> Result<Self, Self::Error> {
        let mut globals = Vec::with_capacity(value.exported_globals.len());
        for g in value.exported_globals.into_iter() {
            globals.push(g.try_into()?);
        }
        let binary_hash = match value.binary_hash {
            Some(hash) => {
                let hash: [u8; 32] =
                    hash.try_into()
                        .map_err(|e| ProxyDecodeError::ValueOutOfRange {
                            typ: "BinaryHash",
                            err: format!("Expected a 32-byte long module hash, got {:?}", e),
                        })?;
                Some(hash.into())
            }
            None => None,
        };

        Ok(Self {
            exported_globals: globals,
            heap_size: (value.heap_size as usize).into(),
            exports: value.exports.try_into()?,
            last_executed_round: value.last_executed_round.into(),
            metadata: try_from_option_field(value.metadata, "ExecutionStateBits::metadata")
                .unwrap_or_default(),
            binary_hash,
            next_scheduled_method: match value.next_scheduled_method {
                Some(method_id) => pb_canister_state_bits::NextScheduledMethod::try_from(method_id)
                    .unwrap_or_default()
                    .into(),
                None => NextScheduledMethod::default(),
            },
        })
    }
}

impl From<CanisterSnapshotBits> for pb_canister_snapshot_bits::CanisterSnapshotBits {
    fn from(item: CanisterSnapshotBits) -> Self {
        Self {
            snapshot_id: item.snapshot_id.get_local_snapshot_id(),
            canister_id: Some((item.canister_id).into()),
            taken_at_timestamp: item.taken_at_timestamp.as_nanos_since_unix_epoch(),
            canister_version: item.canister_version,
            binary_hash: item.binary_hash.as_ref().map(|h| h.to_vec()),
            certified_data: item.certified_data.clone(),
            wasm_chunk_store_metadata: Some((&item.wasm_chunk_store_metadata).into()),
            stable_memory_size: item.stable_memory_size.get() as u64,
            wasm_memory_size: item.wasm_memory_size.get() as u64,
            total_size: item.total_size.get(),
        }
    }
}

impl TryFrom<pb_canister_snapshot_bits::CanisterSnapshotBits> for CanisterSnapshotBits {
    type Error = ProxyDecodeError;
    fn try_from(
        item: pb_canister_snapshot_bits::CanisterSnapshotBits,
    ) -> Result<Self, Self::Error> {
        let canister_id: CanisterId =
            try_from_option_field(item.canister_id, "CanisterSnapshotBits::canister_id")?;

        let binary_hash = match item.binary_hash {
            Some(hash) => {
                let hash: [u8; 32] =
                    hash.try_into()
                        .map_err(|e| ProxyDecodeError::ValueOutOfRange {
                            typ: "BinaryHash",
                            err: format!("Expected a 32-byte long module hash, got {:?}", e),
                        })?;
                Some(hash.into())
            }
            None => None,
        };
        Ok(Self {
            snapshot_id: SnapshotId::from((canister_id, item.snapshot_id)),
            canister_id,
            taken_at_timestamp: Time::from_nanos_since_unix_epoch(item.taken_at_timestamp),
            canister_version: item.canister_version,
            binary_hash,
            certified_data: item.certified_data,
            wasm_chunk_store_metadata: try_from_option_field(
                item.wasm_chunk_store_metadata,
                "CanisterSnapshotBits::wasm_chunk_store_metadata",
            )
            .unwrap_or_default(),
            stable_memory_size: NumWasmPages::from(item.stable_memory_size as usize),
            wasm_memory_size: NumWasmPages::from(item.wasm_memory_size as usize),
            total_size: NumBytes::from(item.total_size),
        })
    }
}

fn dir_file_names(p: &Path) -> std::io::Result<Vec<String>> {
    if !p.exists() {
        return Ok(vec![]);
    }
    let mut result = vec![];
    for e in p.read_dir()? {
        let string = e?.file_name().into_string().map_err(|file_name| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to convert file name {:?} to string", file_name),
            )
        })?;
        result.push(string);
    }
    Ok(result)
}

#[derive(Clone, Copy, PartialEq)]
pub enum FilePermissions {
    ReadOnly,
    ReadWrite,
}

fn mark_readonly_if_file(path: &Path) -> std::io::Result<()> {
    let metadata = path.metadata()?;
    if !metadata.is_dir() {
        let mut permissions = metadata.permissions();
        if !permissions.readonly() {
            permissions.set_readonly(true);
            std::fs::set_permissions(path, permissions).map_err(|e| {
                Error::new(
                    e.kind(),
                    format!(
                        "failed to set readonly permissions for file {}: {}",
                        path.display(),
                        e
                    ),
                )
            })?;
        }
    }
    Ok(())
}

fn dir_list_recursive(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    fn add_content(path: &Path, result: &mut Vec<PathBuf>) -> std::io::Result<()> {
        result.push(path.to_path_buf());
        let metadata = path.metadata()?;
        if metadata.is_dir() {
            let entries = path.read_dir()?;
            for entry_result in entries {
                let entry = entry_result?;
                add_content(&entry.path(), result)?;
            }
        }
        Ok(())
    }
    add_content(path, &mut result)?;
    Ok(result)
}

/// Recursively set permissions to readonly for all files under the given
/// `path`.
fn sync_and_mark_files_readonly(
    #[allow(unused)] log: &ReplicaLogger,
    path: &Path,
    #[allow(unused)] metrics: &StateLayoutMetrics,
    thread_pool: Option<&mut scoped_threadpool::Pool>,
) -> std::io::Result<()> {
    let paths = dir_list_recursive(path)?;
    if let Some(thread_pool) = thread_pool {
        let results = parallel_map(thread_pool, paths.iter(), |p| {
            mark_readonly_if_file(p)?;
            #[cfg(not(target_os = "linux"))]
            sync_path(p)?;
            Ok::<(), std::io::Error>(())
        });

        results.into_iter().try_for_each(identity)?;
    } else {
        for p in paths {
            mark_readonly_if_file(&p)?;
            #[cfg(not(target_os = "linux"))]
            sync_path(p)?;
        }
    }
    #[cfg(target_os = "linux")]
    {
        let f = std::fs::File::open(path)?;
        use std::os::fd::AsRawFd;
        let start = Instant::now();
        unsafe {
            if libc::syncfs(f.as_raw_fd()) == -1 {
                return Err(std::io::Error::last_os_error());
            }
        }
        let elapsed = start.elapsed();
        metrics
            .state_layout_syncfs_duration
            .observe(elapsed.as_secs_f64());
        info!(log, "syncfs took {:?}", elapsed);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum FSync {
    Yes,
    No,
}

/// Recursively copies `src` to `dst` using the given permission policy for
/// files. If a thread-pool is provided then files are copied in parallel.
/// Syncs the target files if `fsync` is set to true.
///
/// NOTE: If the function returns an error, the changes to the file
/// system applied by this function are not undone.
fn copy_recursively<P>(
    log: &ReplicaLogger,
    metrics: &StateLayoutMetrics,
    root_src: &Path,
    root_dst: &Path,
    fsync: FSync,
    file_copy_instruction: P,
    thread_pool: Option<&mut scoped_threadpool::Pool>,
) -> std::io::Result<()>
where
    P: Fn(&Path) -> CopyInstruction,
{
    let mut copy_plan = CopyPlan {
        create_and_sync_dir: vec![],
        copy_and_sync_file: vec![],
    };

    build_copy_plan(root_src, root_dst, &file_copy_instruction, &mut copy_plan)?;

    // Ensure that the target root directory exists.
    // Note: all the files and directories below the target root (including the
    // target root itself) will be synced after this function returns.  However,
    // create_dir_all might create some parents that won't be synced. It's fine
    // because:
    //   1. We only care about internal consistency of checkpoints, and the
    //   parents create_dir_all might have created do not belong to a
    //   checkpoint.
    //
    //   2. We only invoke this function with DST being a child of a
    //   directory that is wiped out on replica start, so we don't care much
    //   about this temporary directory being properly synced.
    std::fs::create_dir_all(root_dst)?;
    match thread_pool {
        Some(thread_pool) => {
            let results = parallel_map(thread_pool, copy_plan.create_and_sync_dir.iter(), |op| {
                // We keep directories writeable to make sure we can rename
                // them or delete the files.
                std::fs::create_dir_all(&op.dst)
            });
            results.into_iter().try_for_each(identity)?;
            let results = parallel_map(thread_pool, copy_plan.copy_and_sync_file.iter(), |op| {
                copy_checkpoint_file(log, metrics, &op.src, &op.dst, op.dst_permissions, fsync)
            });
            results.into_iter().try_for_each(identity)?;
            if let FSync::Yes = fsync {
                let results =
                    parallel_map(thread_pool, copy_plan.create_and_sync_dir.iter(), |op| {
                        sync_path(&op.dst)
                    });
                results.into_iter().try_for_each(identity)?;
            }
        }
        None => {
            for op in copy_plan.create_and_sync_dir.iter() {
                std::fs::create_dir_all(&op.dst)?;
            }
            for op in copy_plan.copy_and_sync_file.into_iter() {
                copy_checkpoint_file(log, metrics, &op.src, &op.dst, op.dst_permissions, fsync)?;
            }
            if let FSync::Yes = fsync {
                for op in copy_plan.create_and_sync_dir.iter() {
                    sync_path(&op.dst)?;
                }
            }
        }
    }
    Ok(())
}

/// Copies the given file and ensures that the `read/write` permission of the
/// target file match the given permission.
/// This function is used for files inside checkpoints, so the `src` file is intended to be
/// marked readonly.
/// Syncs the target file if `fsync` is true.
fn copy_checkpoint_file(
    log: &ReplicaLogger,
    metrics: &StateLayoutMetrics,
    src: &Path,
    dst: &Path,
    dst_permissions: FilePermissions,
    fsync: FSync,
) -> std::io::Result<()> {
    // We don't expect to copy anything that isn't readonly, but just in case we handle it correctly below.
    if !src.metadata()?.permissions().readonly() {
        warn!(every_n_seconds => 5, log, "Copying writable file {:?}", src);
        metrics
            .state_layout_error_count
            .with_label_values(&["copy_writable_checkpoint"])
            .inc();
        debug_assert!(false);
    }

    copy_file_and_set_permissions(log, src, dst, dst_permissions)?;

    match fsync {
        FSync::Yes => sync_path(dst),
        FSync::No => Ok(()),
    }
}

/// Copies the given file and ensures that the `read/write` permission of the
/// target file match the given permission.
fn copy_file_and_set_permissions(
    log: &ReplicaLogger,
    src: &Path,
    dst: &Path,
    dst_permissions: FilePermissions,
) -> Result<(), Error> {
    if src.metadata()?.permissions().readonly() && dst_permissions == FilePermissions::ReadOnly {
        std::fs::hard_link(src, dst)?
    } else {
        do_copy(log, src, dst)?;
        let dst_metadata = dst.metadata()?;
        // We don't want to change the readonly flag of any files that are hardlinked somewhere else
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            debug_assert_eq!(dst_metadata.nlink(), 1);
        }
        let mut permissions = dst_metadata.permissions();
        match dst_permissions {
            FilePermissions::ReadOnly => permissions.set_readonly(true),
            FilePermissions::ReadWrite => {
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::fs::PermissionsExt;
                    permissions.set_mode(0o640); // Read/write for owner and read for group.
                }

                #[cfg(not(target_os = "linux"))]
                #[allow(clippy::permissions_set_readonly_false)]
                permissions.set_readonly(false)
            }
        }
        std::fs::set_permissions(dst, permissions)?;
    }
    Ok(())
}

// Describes how to copy one directory to another.
// The order of operations is important:
// 1. All directories should be created first.
// 2. After that files can be copied in _any_ order.
// 3. Finally, directories should be synced.
struct CopyPlan {
    create_and_sync_dir: Vec<CreateAndSyncDir>,
    copy_and_sync_file: Vec<CopyAndSyncFile>,
}

// Describes an operation for creating and syncing a directory.
// Note that a directory can be synced only after all its children are created.
struct CreateAndSyncDir {
    dst: PathBuf,
}

// Describes an operation for copying and syncing a file.
struct CopyAndSyncFile {
    src: PathBuf,
    dst: PathBuf,
    dst_permissions: FilePermissions,
}

enum CopyInstruction {
    /// The file doesn't need to be copied
    Skip,
    /// The file needs to be copied and should be writeable at the destination
    ReadWrite,
    /// The file needs to be copied and should be readonly at the destination
    ReadOnly,
}

/// Traverse the source file tree and constructs a copy-plan:
/// a collection of I/O operations that need to be performed to copy the source
/// to the destination.
fn build_copy_plan<P>(
    src: &Path,
    dst: &Path,
    file_copy_instruction: &P,
    plan: &mut CopyPlan,
) -> std::io::Result<()>
where
    P: Fn(&Path) -> CopyInstruction,
{
    let src_metadata = src.metadata()?;

    if src_metadata.is_dir() {
        // First create the target directory.
        plan.create_and_sync_dir.push(CreateAndSyncDir {
            dst: PathBuf::from(dst),
        });

        // Then copy and sync all children.
        let entries = src.read_dir()?;
        for entry_result in entries {
            let entry = entry_result?;
            let dst_entry = dst.join(entry.file_name());
            build_copy_plan(&entry.path(), &dst_entry, file_copy_instruction, plan)?;
        }
    } else {
        let dst_permissions = match file_copy_instruction(src) {
            CopyInstruction::Skip => {
                return Ok(());
            }
            CopyInstruction::ReadWrite => FilePermissions::ReadWrite,
            CopyInstruction::ReadOnly => FilePermissions::ReadOnly,
        };
        plan.copy_and_sync_file.push(CopyAndSyncFile {
            src: PathBuf::from(src),
            dst: PathBuf::from(dst),
            dst_permissions,
        });
    }
    Ok(())
}
