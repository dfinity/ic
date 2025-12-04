use ic_base_types::{NumBytes, NumSeconds};
use ic_logger::{ReplicaLogger, error, info, warn};
use ic_management_canister_types_private::{
    Global, LogVisibilityV2, OnLowWasmMemoryHookStatus, SnapshotSource,
};
use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use ic_protobuf::state::{
    canister_snapshot_bits::v1 as pb_canister_snapshot_bits,
    canister_state_bits::v1 as pb_canister_state_bits, ingress::v1 as pb_ingress,
    queues::v1 as pb_queues, stats::v1 as pb_stats, system_metadata::v1 as pb_metadata,
};
use ic_replicated_state::{
    CanisterStatus, ExportedFunctions, NumWasmPages,
    canister_state::{
        execution_state::{NextScheduledMethod, WasmMetadata},
        system_state::{
            CanisterHistory, CyclesUseCase, TaskQueue, wasm_chunk_store::WasmChunkStoreMetadata,
        },
    },
    page_map::{Shard, StorageLayout, StorageResult},
};
use ic_sys::{fs::sync_path, mmap::ScopedMmap};
use ic_types::{
    AccumulatedPriority, CanisterId, CanisterLog, CanisterTimer, ComputeAllocation, Cycles,
    ExecutionRound, Height, LongExecutionMode, MemoryAllocation, NumInstructions, PrincipalId,
    SnapshotId, Time, batch::TotalQueryStats, nominal_cycles::NominalCycles,
};
use ic_utils::thread::maybe_parallel_map;
use ic_wasm_types::{CanisterModule, MemoryMappableWasmFile, WasmHash};
use prometheus::{Histogram, IntCounterVec, IntGauge};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::{From, TryFrom, identity};
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{Error, Write};

/// Result of marking files readonly, containing counts for monitoring
#[derive(Debug, Clone)]
pub struct ReadonlyMarkingResult {
    pub files_traversed: usize,
    pub files_made_readonly: usize,
}
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::error::LayoutError;
use crate::utils::do_copy;

use crossbeam_channel::{Sender, bounded, unbounded};
use ic_utils_thread::JoinOnDrop;

pub mod proto;

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
pub const REFUNDS_FILE: &str = "refunds.pbuf";
pub const SYSTEM_METADATA_FILE: &str = "system_metadata.pbuf";
pub const STATS_FILE: &str = "stats.pbuf";
pub const WASM_FILE: &str = "software.wasm";
pub const UNVERIFIED_CHECKPOINT_MARKER: &str = "unverified_checkpoint_marker";
pub const OVERLAY: &str = "overlay";
pub const VMEMORY_0: &str = "vmemory_0";
pub const STABLE_MEMORY: &str = "stable_memory";
pub const WASM_CHUNK_STORE: &str = "wasm_chunk_store";
pub const LOG_MEMORY_STORE: &str = "log_memory_store";
pub const BIN_FILE: &str = "bin";

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

impl<T> AccessPolicy for RwPolicy<'_, T> {
    fn check_dir(p: &Path) -> Result<(), LayoutError> {
        WriteOnly::check_dir(p)
    }
}

impl<T> ReadPolicy for RwPolicy<'_, T> {}
impl<T> WritePolicy for RwPolicy<'_, T> {}

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
    pub binary_hash: WasmHash,
    pub next_scheduled_method: NextScheduledMethod,
    pub is_wasm64: bool,
}

/// This struct contains bits of the `CanisterState` that are not already
/// covered somewhere else and are too small to be serialized separately.
#[derive(Debug)]
pub struct CanisterStateBits {
    pub controllers: BTreeSet<PrincipalId>,
    pub last_full_execution_round: ExecutionRound,
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
    pub task_queue: TaskQueue,
    pub environment_variables: BTreeMap<String, String>,
}

/// This struct contains bits of the `CanisterSnapshot` that are not already
/// covered somewhere else and are too small to be serialized separately.
#[derive(Clone, Eq, PartialEq, Debug)]
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
    pub binary_hash: WasmHash,
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
    /// State of the exported Wasm globals.
    pub exported_globals: Vec<Global>,
    /// Whether this snapshot comes from a canister or from a user upload.
    pub source: SnapshotSource,
    /// The state of the global timer.
    pub global_timer: Option<CanisterTimer>,
    /// The state of the low memory hook.
    pub on_low_wasm_memory_hook_status: Option<OnLowWasmMemoryHookStatus>,
}

#[derive(Clone)]
struct StateLayoutMetrics {
    state_layout_error_count: IntCounterVec,
    state_layout_sync_remove_checkpoint_duration: Histogram,
    state_layout_async_remove_checkpoint_duration: Histogram,
    checkpoint_removal_channel_length: IntGauge,
}

impl StateLayoutMetrics {
    fn new(metric_registry: &MetricsRegistry) -> StateLayoutMetrics {
        StateLayoutMetrics {
            state_layout_error_count: metric_registry.int_counter_vec(
                "state_layout_error_count",
                "Total number of errors encountered in the state layout.",
                &["source"],
            ),
            state_layout_sync_remove_checkpoint_duration: metric_registry.histogram(
                "state_layout_sync_remove_checkpoint_duration_seconds",
                "Time elapsed in removing checkpoint synchronously.",
                decimal_buckets(-3, 1),
            ),
            state_layout_async_remove_checkpoint_duration: metric_registry.histogram(
                "state_layout_async_remove_checkpoint_duration_seconds",
                "Time elapsed in removing checkpoint asynchronously in the background thread.",
                decimal_buckets(-3, 1),
            ),
            checkpoint_removal_channel_length: metric_registry.int_gauge(
                "state_layout_checkpoint_removal_channel_length",
                "Number of requests in the checkpoint removal channel.",
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
/// │      │       ├── wasm_chunk_store.bin
/// │      │       └── log_memory_store.bin
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
///   2. When all the writes are complete, call mark_files_readonly_and_sync()
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
    checkpoint_removal_sender: Sender<CheckpointRemovalRequest>,
    _checkpoint_removal_handle: Arc<JoinOnDrop<()>>,
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
    pub fn tip(
        &mut self,
        height: Height,
    ) -> Result<CheckpointLayout<RwPolicy<'_, Self>>, LayoutError> {
        CheckpointLayout::new_untracked(self.tip_path(), height)
    }

    /// Resets "tip" to a checkpoint identified by height.
    pub fn reset_tip_to(
        &mut self,
        state_layout: &StateLayout,
        cp: &CheckpointLayout<ReadOnly>,
        thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> Result<(), LayoutError> {
        let tip = self.tip_path();
        if tip.exists() {
            std::fs::remove_dir_all(&tip).map_err(|err| LayoutError::IoError {
                path: tip.to_path_buf(),
                message: format!("Cannot remove tip for checkpoint {}", cp.height()),
                io_err: err,
            })?;
        }

        debug_assert!(cp.raw_path().exists());

        let file_copy_instruction = |path: &Path| {
            if path.extension() == Some(OsStr::new("pbuf")) {
                // Do not copy protobufs.
                CopyInstruction::Skip
            } else if path == cp.unverified_checkpoint_marker() {
                // The unverified checkpoint marker should already be removed at this point.
                debug_assert!(false);
                CopyInstruction::Skip
            } else {
                // Everything else should be readonly.
                CopyInstruction::ReadOnly
            }
        };

        match copy_recursively(
            &state_layout.log,
            &state_layout.metrics,
            cp.raw_path(),
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
                        cp.raw_path().display(),
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

    /// Moves the entire canister directory from one canister id to another.
    pub fn move_canister_directory(
        &mut self,
        height: Height,
        src: CanisterId,
        dst: CanisterId,
    ) -> Result<(), LayoutError> {
        let tip = self.tip(height)?;
        let src_path = tip.canister(&src)?.raw_path();
        let dst_path = tip.canister(&dst)?.raw_path();
        std::fs::rename(&src_path, &dst_path).map_err(|err| LayoutError::IoError {
            path: src_path,
            message: "Failed to rename canister".to_string(),
            io_err: err,
        })
    }
}

enum CheckpointRemovalRequest {
    Remove(PathBuf),
    Wait { sender: Sender<()> },
}

fn spawn_checkpoint_removal_thread(
    log: ReplicaLogger,
    metrics: StateLayoutMetrics,
) -> (JoinOnDrop<()>, Sender<CheckpointRemovalRequest>) {
    // The number of the requests in the channel is limited by the number of checkpoints created.
    // As we always flush the channel before creating a new checkpoint, there won't be excessive number of requests.
    #[allow(clippy::disallowed_methods)]
    let (checkpoint_removal_sender, checkpoint_removal_receiver) =
        unbounded::<CheckpointRemovalRequest>();
    let checkpoint_removal_handle = JoinOnDrop::new(
        std::thread::Builder::new()
            .name("CheckpointRemovalThread".to_string())
            .spawn(move || {
                while let Ok(req) = checkpoint_removal_receiver.recv() {
                    match req {
                        CheckpointRemovalRequest::Remove(path) => {
                            debug_assert_eq!(path.parent().unwrap().file_name().unwrap(), "fs_tmp",);
                            let start = Instant::now();
                            if let Err(err) = std::fs::remove_dir_all(&path) {
                                error!(
                                    log,
                                    "Failed to remove checkpoint directory. Error: {}.", err
                                )
                            }
                            let elapsed = start.elapsed();
                            metrics
                                .state_layout_async_remove_checkpoint_duration
                                .observe(elapsed.as_secs_f64());
                            let remaining_requests = checkpoint_removal_receiver.len();
                            info!(
                                log,
                                "Asynchronously removed checkpoint from tmp path {} in {:?}. Number of remaining requests: {}",
                                path.display(),
                                elapsed,
                                remaining_requests
                            );
                        }
                        CheckpointRemovalRequest::Wait { sender } => {
                            sender.send(()).expect("Failed to send completion signal");
                        }
                    }
                }
            })
            .expect("failed to spawn checkpoint removal thread"),
    );
    (checkpoint_removal_handle, checkpoint_removal_sender)
}

impl StateLayout {
    /// Create a new StateLayout and initialize it by creating all necessary
    /// directories if they do not exist already and clear all tmp directories
    /// that are expected to be empty when the replica starts.
    /// Needs to be pub for tests.
    pub fn try_new(
        log: ReplicaLogger,
        root: PathBuf,
        metrics_registry: &MetricsRegistry,
    ) -> Result<Self, LayoutError> {
        let state_layout = Self::new_no_init(log, root, metrics_registry);
        state_layout.init()?;
        Ok(state_layout)
    }

    /// Create a new StateLayout without initializing it. Useful for tests and
    /// tools that want to create a StateLayout without interferring with
    /// replicas / state managers that are already running using the same state
    /// directory.
    pub fn new_no_init(
        log: ReplicaLogger,
        root: PathBuf,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        let metrics = StateLayoutMetrics::new(metrics_registry);
        let (checkpoint_removal_handle, checkpoint_removal_sender) =
            spawn_checkpoint_removal_thread(log.clone(), metrics.clone());

        Self {
            root,
            log,
            metrics,
            tip_handler_captured: Arc::new(false.into()),
            checkpoint_ref_registry: Arc::new(Mutex::new(BTreeMap::new())),
            checkpoint_removal_sender,
            _checkpoint_removal_handle: Arc::new(checkpoint_removal_handle),
        }
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
            let cp_layout = self.checkpoint_verified(height)?;
            let result = cp_layout.mark_files_readonly_and_sync(thread_pool.as_mut())?;

            info!(
                &self.log,
                "Marked checkpoint files readonly: made {} files readonly out of {} traversed for checkpoint {}",
                result.files_made_readonly,
                result.files_traversed,
                height
            );
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
    pub fn state_sync_scratchpad(&self, height: Height) -> PathBuf {
        self.tmp()
            .join(format!("state_sync_scratchpad_{:016x}", height.get()))
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

    /// Creates an unverified marker in the scratchpad and promotes it to a checkpoint.
    ///
    /// This function maintains the integrity of the checkpointing process by ensuring that
    /// the scratchpad is properly marked as unverified before transitioning it into a checkpoint.
    pub fn promote_scratchpad_to_unverified_checkpoint<T>(
        &self,
        scratchpad_layout: CheckpointLayout<RwPolicy<T>>,
        height: Height,
    ) -> Result<CheckpointLayout<RwPolicy<'_, T>>, LayoutError> {
        scratchpad_layout.create_unverified_checkpoint_marker()?;
        self.scratchpad_to_checkpoint(scratchpad_layout, height)
    }

    fn scratchpad_to_checkpoint<T>(
        &self,
        layout: CheckpointLayout<RwPolicy<T>>,
        height: Height,
    ) -> Result<CheckpointLayout<RwPolicy<'_, T>>, LayoutError> {
        // The scratchpad must have an unverified marker before it is promoted to a checkpoint.
        debug_assert!(!layout.is_checkpoint_verified());
        debug_assert_eq!(height, layout.height());
        let scratchpad = layout.raw_path();
        let checkpoints_path = self.checkpoints();
        let cp_path = checkpoints_path.join(Self::checkpoint_name(height));

        std::fs::rename(scratchpad, cp_path).map_err(|err| {
            if is_already_exists_err(&err) {
                LayoutError::AlreadyExists(height)
            } else {
                LayoutError::IoError {
                    path: scratchpad.to_path_buf(),
                    message: format!("Failed to rename scratchpad to checkpoint {height}"),
                    io_err: err,
                }
            }
        })?;
        sync_path(&checkpoints_path).map_err(|err| LayoutError::IoError {
            path: checkpoints_path,
            message: "Could not sync checkpoints".to_string(),
            io_err: err,
        })?;
        self.checkpoint(height)
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
                        message: format!("Failed to clone checkpoint {from} to {to}"),
                        io_err,
                    }
                }
            })?;
        Ok(())
    }

    /// Returns the layout of the checkpoint with the given height.
    /// If the checkpoint is not found, an error is returned.
    fn checkpoint<T>(&self, height: Height) -> Result<CheckpointLayout<T>, LayoutError>
    where
        T: AccessPolicy,
    {
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

    fn remove_checkpoint_ref(&self, height: Height) {
        let mut checkpoint_ref_registry = self.checkpoint_ref_registry.lock().unwrap();
        match checkpoint_ref_registry.get_mut(&height) {
            None => {
                debug_assert!(false, "Double removal at height {height}");
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

    /// Asynchronously removes a checkpoint for a given height if it exists.
    /// The checkpoint is first moved to the `fs_tmp` directory, and the actual file deletion
    /// is delegated to a background thread. This offloading helps avoid blocking the calling thread,
    /// such as Consensus's purger.
    fn remove_checkpoint_async<T>(
        &self,
        height: Height,
        drop_after_rename: T,
    ) -> Result<(), LayoutError> {
        let start = Instant::now();
        let cp_name = Self::checkpoint_name(height);
        let cp_path = self.checkpoints().join(&cp_name);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let tmp_path = self
            .fs_tmp()
            .join(format!("{}_{}_async", cp_name, timestamp.as_nanos()));

        // Atomically removes the checkpoint by first renaming it into tmp_path, and then deleting tmp_path.
        // This way maintains the invariant that <root>/checkpoints/<height> are always internally consistent.
        self.rename_to_tmp_path(&cp_path, &tmp_path)
            .map_err(|err| LayoutError::IoError {
                path: cp_path.clone(),
                message: format!(
                    "failed to rename checkpoint {} to tmp path {} (err kind: {:?})",
                    cp_name,
                    tmp_path.display(),
                    err.kind()
                ),
                io_err: err,
            })?;

        // Drops drop_after_rename once the checkpoint path is renamed to tmp_path.
        std::mem::drop(drop_after_rename);

        self.metrics
            .checkpoint_removal_channel_length
            .set(self.checkpoint_removal_sender.len() as i64);

        self.checkpoint_removal_sender
            .send(CheckpointRemovalRequest::Remove(tmp_path))
            .expect("failed to send checkpoint removal request");
        info!(
            self.log,
            "Async checkpoint removal operation moves checkpoint @{} to tmp path and returns in {:?}",
            height,
            start.elapsed()
        );
        Ok(())
    }

    /// Removes a checkpoint for a given height if it exists.
    /// Drops drop_after_rename once the checkpoint is moved to fs_tmp.
    ///
    /// Postcondition:
    ///   height ∉ self.checkpoint_heights()
    fn remove_checkpoint<T>(
        &self,
        height: Height,
        drop_after_rename: T,
    ) -> Result<(), LayoutError> {
        self.remove_checkpoint_async(height, drop_after_rename)
    }

    /// Synchronously removes a checkpoint for a given height if it exists.
    fn remove_checkpoint_sync<T>(
        &self,
        height: Height,
        drop_after_rename: T,
    ) -> Result<(), LayoutError> {
        let start = Instant::now();
        let cp_name = Self::checkpoint_name(height);
        let cp_path = self.checkpoints().join(&cp_name);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let tmp_path = self
            .fs_tmp()
            .join(format!("{}_{}_sync", cp_name, timestamp.as_nanos()));

        // Atomically removes the checkpoint by first renaming it into tmp_path, and then deleting tmp_path.
        // This way maintains the invariant that <root>/checkpoints/<height> are always internally consistent.
        self.rename_to_tmp_path(&cp_path, &tmp_path)
            .map_err(|err| LayoutError::IoError {
                path: cp_path.clone(),
                message: format!(
                    "failed to rename checkpoint {} to tmp path {} (err kind: {:?})",
                    cp_name,
                    tmp_path.display(),
                    err.kind()
                ),
                io_err: err,
            })?;

        // Drops drop_after_rename once the checkpoint path is renamed to tmp_path.
        std::mem::drop(drop_after_rename);
        std::fs::remove_dir_all(&tmp_path).map_err(|err| LayoutError::IoError {
            path: cp_path,
            message: format!(
                "failed to remove checkpoint {} from tmp path {} (err kind: {:?})",
                cp_name,
                tmp_path.display(),
                err.kind()
            ),
            io_err: err,
        })?;
        let elapsed = start.elapsed();
        info!(
            self.log,
            "Synchronously removed checkpoint @{} in {:?}", height, elapsed
        );
        self.metrics
            .state_layout_sync_remove_checkpoint_duration
            .observe(elapsed.as_secs_f64());
        Ok(())
    }

    pub fn force_remove_checkpoint(&self, height: Height) -> Result<(), LayoutError> {
        // Perform a synchronous removal since performance is not a concern for forced removals.
        // it is more suitable to remove the checkpoint immediately and in place for forced removals.
        self.remove_checkpoint_sync(height, ())
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

    pub fn flush_checkpoint_removal_channel(&self) {
        self.metrics
            .checkpoint_removal_channel_length
            .set(self.checkpoint_removal_sender.len() as i64);

        let (sender, receiver) = bounded::<()>(1);
        self.checkpoint_removal_sender
            .send(CheckpointRemovalRequest::Wait { sender })
            .expect("failed to send completion signal");
        receiver
            .recv()
            .expect("failed to receive completion signal");
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
                message: format!("Failed to mark checkpoint {height} diverged"),
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
        self.rename_to_tmp_path(&cp_path, &tmp_path)
            .map_err(|err| LayoutError::IoError {
                path: cp_path.clone(),
                message: format!("failed to rename diverged checkpoint {height} to tmp path"),
                io_err: err,
            })?;
        std::fs::remove_dir_all(&tmp_path).map_err(|err| LayoutError::IoError {
            path: cp_path,
            message: format!("failed to remove diverged checkpoint {height} from tmp path"),
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
                message: format!("Failed to backup checkpoint {height}"),
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
        self.rename_to_tmp_path(&backup_path, &tmp_path)
            .map_err(|err| LayoutError::IoError {
                path: backup_path.clone(),
                message: format!("failed to rename backup {height} to tmp path"),
                io_err: err,
            })?;
        std::fs::remove_dir_all(&tmp_path).map_err(|err| LayoutError::IoError {
            path: backup_path,
            message: format!("failed to remove backup {height} from tmp path"),
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
            message: format!("failed to archive checkpoint {height}"),
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
    pub fn copy_and_sync_checkpoint(
        &self,
        name: &str,
        src: &Path,
        dst: &Path,
        thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> std::io::Result<()> {
        let scratch_name = format!("scratchpad_{name}");
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

    /// Renames a path to a temporary path and synchronizes the parent directory of the original path.
    ///
    /// This helper function is useful when removing a checkpoint because renaming the checkpoint to a temporary path
    /// is an atomic operation. This ensures that the checkpoint will not be left in an inconsistent
    /// state on disk if a crash occurs. After the rename, the parent directory of the original
    /// path is synced to persist the change.
    fn rename_to_tmp_path(&self, path: &Path, tmp_path: &Path) -> std::io::Result<()> {
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
        Ok(())
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
                    });
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
        format!("failed to convert directory name {hex} into a canister ID: {err}")
    })?;

    Ok(CanisterId::unchecked_from_principal(
        PrincipalId::try_from(&blob[..])
            .map_err(|err| format!("failed to parse principal ID: {err}"))?,
    ))
}

/// Helper for parsing hex representations of snapshot IDs, used for the
/// directory names under `snapshots`).
fn parse_snapshot_id(hex: &str) -> Result<SnapshotId, String> {
    let blob = hex::decode(hex).map_err(|err| {
        format!("failed to convert directory name {hex} into a snapshot ID: {err}")
    })?;

    SnapshotId::try_from(&blob).map_err(|err| format!("failed to parse snapshot ID: {err}"))
}

/// Parses the canister ID from a relative path, if it is the path of a canister or snapshot
/// state file (e.g. `canister_states/00000000000000010101/queues.pbuf`).
/// Returns `None` if the path is not under `canister_states` or `snapshots`; or if parsing
/// fails.
pub fn canister_id_from_path(path: &Path) -> Option<CanisterId> {
    let mut path = path.iter();
    let top_level = path.next();
    if (top_level == Some(OsStr::new(CANISTER_STATES_DIR))
        || top_level == Some(OsStr::new(SNAPSHOTS_DIR)))
        && let Some(hex) = path.next()
    {
        return parse_canister_id(hex.to_str()?).ok();
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
                    message: format!("failed to convert checkpoint name {name} into a number: {e}"),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    heights.sort_unstable();

    Ok(heights)
}

struct CheckpointLayoutImpl {
    root: PathBuf,
    height: Height,
    // The StateLayout is used to make sure we never remove the CheckpointLayout when still in use.
    // Is not None for CheckpointLayout pointing to "real" checkpoints, that is checkpoints in
    // StateLayout's root/checkpoints/..., that are tracked by StateLayout
    state_layout: Option<StateLayout>,
}

impl Drop for CheckpointLayoutImpl {
    fn drop(&mut self) {
        if let Some(state_layout) = &self.state_layout {
            state_layout.remove_checkpoint_ref(self.height)
        }
    }
}

pub struct CheckpointLayout<Permissions: AccessPolicy>(
    Arc<CheckpointLayoutImpl>,
    PhantomData<Permissions>,
);

// TODO(MR-676) prevent cloning when Permissions is intentinally non-cloneable
impl<Permissions: AccessPolicy> Clone for CheckpointLayout<Permissions> {
    fn clone(&self) -> Self {
        CheckpointLayout(self.0.clone(), PhantomData)
    }
}

impl<Permissions: ReadPolicy> CheckpointLayout<Permissions> {
    /// Clone CheckpointLayout removing all access but ReadOnly.
    pub fn as_readonly(&self) -> CheckpointLayout<ReadOnly> {
        CheckpointLayout(Arc::clone(&self.0), PhantomData)
    }
}

impl<Permissions: AccessPolicy> std::fmt::Debug for CheckpointLayout<Permissions> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "checkpoint layout #{}, path: #{}",
            self.0.height,
            self.0.root.display()
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
        Ok(Self(
            Arc::new(CheckpointLayoutImpl {
                root,
                height,
                state_layout: Some(state_layout),
            }),
            PhantomData,
        ))
    }

    pub fn new_untracked(root: PathBuf, height: Height) -> Result<Self, LayoutError> {
        Permissions::check_dir(&root)?;
        Ok(Self(
            Arc::new(CheckpointLayoutImpl {
                root,
                height,
                state_layout: None,
            }),
            PhantomData,
        ))
    }

    pub fn system_metadata(&self) -> ProtoFileWith<pb_metadata::SystemMetadata, Permissions> {
        self.0.root.join(SYSTEM_METADATA_FILE).into()
    }

    pub fn ingress_history(&self) -> ProtoFileWith<pb_ingress::IngressHistoryState, Permissions> {
        self.0.root.join(INGRESS_HISTORY_FILE).into()
    }

    pub fn subnet_queues(&self) -> ProtoFileWith<pb_queues::CanisterQueues, Permissions> {
        self.0.root.join(SUBNET_QUEUES_FILE).into()
    }

    pub fn refunds(&self) -> ProtoFileWith<pb_queues::Refunds, Permissions> {
        self.0.root.join(REFUNDS_FILE).into()
    }

    pub fn split_marker(&self) -> ProtoFileWith<pb_metadata::SplitFrom, Permissions> {
        self.0.root.join(SPLIT_MARKER_FILE).into()
    }

    pub fn stats(&self) -> ProtoFileWith<pb_stats::Stats, Permissions> {
        self.0.root.join(STATS_FILE).into()
    }

    pub fn unverified_checkpoint_marker(&self) -> PathBuf {
        self.0.root.join(UNVERIFIED_CHECKPOINT_MARKER)
    }

    pub fn canister_ids(&self) -> Result<Vec<CanisterId>, LayoutError> {
        let states_dir = self.0.root.join(CANISTER_STATES_DIR);
        Permissions::check_dir(&states_dir)?;
        collect_subdirs(states_dir.as_path(), 0, parse_canister_id)
    }

    pub fn canister(
        &self,
        canister_id: &CanisterId,
    ) -> Result<CanisterLayout<Permissions>, LayoutError> {
        CanisterLayout::new(
            self.0
                .root
                .join(CANISTER_STATES_DIR)
                .join(hex::encode(canister_id.get_ref().as_slice())),
            self,
        )
    }

    /// Lists all snapshots in the checkpoint.
    pub fn snapshot_ids(&self) -> Result<Vec<SnapshotId>, LayoutError> {
        let snapshots_dir = self.0.root.join(SNAPSHOTS_DIR);
        Permissions::check_dir(&snapshots_dir)?;
        collect_subdirs(snapshots_dir.as_path(), 1, parse_snapshot_id)
    }

    /// List all PageMaps with at least one file in the Checkpoint, including canister and snapshot
    /// ones.
    pub fn all_existing_pagemaps(&self) -> Result<Vec<PageMapLayout<Permissions>>, LayoutError> {
        Ok(self
            .canister_ids()?
            .into_iter()
            .map(|id| self.canister(&id)?.all_existing_pagemaps())
            .chain(
                self.snapshot_ids()?
                    .into_iter()
                    .map(|id| self.snapshot(&id)?.all_existing_pagemaps()),
            )
            .collect::<Result<Vec<Vec<PageMapLayout<Permissions>>>, LayoutError>>()?
            .into_iter()
            .flatten()
            .collect())
    }

    pub fn all_existing_wasm_files(&self) -> Result<Vec<WasmFile<Permissions>>, LayoutError> {
        let canister_wasm_files = self
            .canister_ids()?
            .into_iter()
            .map(|id| {
                let canister = self.canister(&id)?;
                Ok(canister.wasm())
            })
            .collect::<Result<Vec<_>, LayoutError>>()?;

        let snapshot_wasm_files = self
            .snapshot_ids()?
            .into_iter()
            .map(|id| {
                let snapshot = self.snapshot(&id)?;
                Ok(snapshot.wasm())
            })
            .collect::<Result<Vec<_>, LayoutError>>()?;

        let wasm_files = canister_wasm_files
            .into_iter()
            .chain(snapshot_wasm_files)
            .filter(|wasm| wasm.raw_path().exists())
            .collect();

        Ok(wasm_files)
    }

    /// Directory where the snapshot for `snapshot_id` is stored.
    /// Note that we store them by canister. This means we have the canister id in the path, which is
    /// necessary in the context of subnet splitting. Also see [`canister_id_from_path`].
    pub fn snapshot(
        &self,
        snapshot_id: &SnapshotId,
    ) -> Result<SnapshotLayout<Permissions>, LayoutError> {
        SnapshotLayout::new(
            self.0
                .root
                .join(SNAPSHOTS_DIR)
                .join(hex::encode(
                    snapshot_id.get_canister_id().get_ref().as_slice(),
                ))
                .join(hex::encode(snapshot_id.as_slice())),
            self,
        )
    }

    pub fn height(&self) -> Height {
        self.0.height
    }

    pub fn raw_path(&self) -> &Path {
        &self.0.root
    }

    /// Returns if the checkpoint is marked as unverified or not.
    pub fn is_checkpoint_verified(&self) -> bool {
        !self.unverified_checkpoint_marker().exists()
    }

    /// Recursively set permissions to readonly for all files under the checkpoint
    /// except for the unverified checkpoint marker file.
    /// Returns counts of files traversed and files made readonly for monitoring.
    pub fn mark_files_readonly_and_sync(
        &self,
        mut thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> Result<ReadonlyMarkingResult, LayoutError> {
        let checkpoint_path = self.raw_path();
        let convert_io_err = |err: std::io::Error| -> LayoutError {
            LayoutError::IoError {
                path: checkpoint_path.to_path_buf(),
                message: format!(
                    "Could not mark files readonly and sync for checkpoint {}",
                    self.height()
                ),
                io_err: err,
            }
        };

        let mut paths =
            dir_list_recursive(checkpoint_path, &mut thread_pool).map_err(convert_io_err)?;
        // Remove the unverified checkpoint marker from the list of paths,
        // since another thread might also be validating the checkpoint and may have already deleted the marker.
        // Marking the unverified marker as read-only is unnecessary for this function's purpose and may cause an error.
        paths.retain(|p| p != &self.unverified_checkpoint_marker());

        let files_traversed = paths.len();

        let results = maybe_parallel_map(&mut thread_pool, paths.iter(), |p| {
            let was_made_readonly = mark_readonly_if_file(p)?;
            #[cfg(not(target_os = "linux"))]
            sync_path(p)?;
            Ok::<bool, std::io::Error>(was_made_readonly)
        });

        let files_made_readonly = results
            .into_iter()
            .collect::<Result<Vec<bool>, std::io::Error>>()
            .map_err(convert_io_err)?
            .iter()
            .filter(|&&was_made| was_made)
            .count();

        #[cfg(target_os = "linux")]
        {
            let f = std::fs::File::open(checkpoint_path).map_err(convert_io_err)?;
            use std::os::fd::AsRawFd;
            unsafe {
                if libc::syncfs(f.as_raw_fd()) == -1 {
                    return Err(convert_io_err(std::io::Error::last_os_error()));
                }
            }
        }
        Ok(ReadonlyMarkingResult {
            files_traversed,
            files_made_readonly,
        })
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
        sync_path(&self.0.root).map_err(|err| LayoutError::IoError {
            path: self.0.root.clone(),
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
    fn remove_unverified_checkpoint_marker(&self) -> Result<(), LayoutError> {
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
        sync_path(&self.0.root).map_err(|err| LayoutError::IoError {
            path: self.0.root.clone(),
            message: "Failed to sync checkpoint directory for the creation of the unverified checkpoint marker".to_string(),
            io_err: err,
        })
    }

    /// Finalizes the checkpoint by marking all files as read-only, ensuring
    /// they are fully synchronized to disk, and then removing the unverified checkpoint marker.
    ///
    /// This function is necessary due to the asynchronous checkpoint writing.
    /// Marking the files as read-only and performing a sync operation should be the last step
    /// before removing the unverified checkpoint marker to prevent data inconsistencies.
    pub fn finalize_and_remove_unverified_marker(
        &self,
        thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> Result<(), LayoutError> {
        let _result = self.mark_files_readonly_and_sync(thread_pool)?;
        self.remove_unverified_checkpoint_marker()
    }
}

pub struct PageMapLayout<Permissions: AccessPolicy> {
    root: PathBuf,
    name_stem: String,
    permissions_tag: PhantomData<Permissions>,
    // Keep checkpoint alive so that the PageMap can be loaded asynchronously.
    _checkpoint: Option<CheckpointLayout<Permissions>>,
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
    ) -> Result<(), LayoutError>
    where
        W: WritePolicy,
    {
        debug_assert_eq!(src.name_stem, dst.name_stem);

        if src.base().exists() {
            copy_file_and_set_permissions(log, &src.base(), &dst.base()).map_err(|err| {
                LayoutError::IoError {
                    path: dst.base(),
                    message: format!(
                        "Cannot copy or hardlink file {:?} to {:?}",
                        src.base(),
                        dst.base()
                    ),
                    io_err: err,
                }
            })?;
        }
        for overlay in src.existing_overlays()? {
            let dst_path = dst.root.join(overlay.file_name().unwrap());
            copy_file_and_set_permissions(log, &overlay, &dst_path).map_err(|err| {
                LayoutError::IoError {
                    path: dst.base(),
                    message: format!("Cannot copy or hardlink file {overlay:?} to {dst_path:?}"),
                    io_err: err,
                }
            })?;
        }

        Ok(())
    }

    /// Whether the layout has any files.
    pub fn exists(&self) -> Result<bool, LayoutError> {
        Ok(self.base().exists() || !self.existing_overlays()?.is_empty())
    }
}

impl<Permissions: AccessPolicy> StorageLayout for PageMapLayout<Permissions> {
    // The path to the base file.
    fn base(&self) -> PathBuf {
        self.root.join(format!("{}.{BIN_FILE}", self.name_stem))
    }

    /// Overlay path encoding, consistent with `overlay_height()` and `overlay_shard()`
    fn overlay(&self, height: Height, shard: Shard) -> PathBuf {
        self.root.join(format!(
            "{:016x}_{:04x}_{}.{OVERLAY}",
            height.get(),
            shard.get(),
            self.name_stem,
        ))
    }

    /// List of overlay files on disk.
    fn existing_overlays(&self) -> StorageResult<Vec<PathBuf>> {
        self.existing_overlays()
            .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send>)
    }

    /// Get overlay height as encoded in the file name.
    fn overlay_height(&self, overlay: &Path) -> StorageResult<Height> {
        let file_name = overlay
            .file_name()
            .ok_or(Box::new(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "No file name".to_owned(),
            }) as Box<dyn std::error::Error + Send>)?
            .to_str()
            .ok_or(Box::new(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "Cannot convert file name to string".to_owned(),
            }) as Box<dyn std::error::Error + Send>)?;
        let hex = file_name
            .split('_')
            .next()
            .ok_or(Box::new(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "Cannot parse file name".to_owned(),
            }) as Box<dyn std::error::Error + Send>)?;
        u64::from_str_radix(hex, 16)
            .map(Height::new)
            .map_err(|err| {
                Box::new(LayoutError::CorruptedLayout {
                    path: overlay.to_path_buf(),
                    message: format!("failed to get height for overlay {hex}: {err}"),
                }) as Box<dyn std::error::Error + Send>
            })
    }

    /// Get overlay shard as encoded in the file name.
    fn overlay_shard(&self, overlay: &Path) -> StorageResult<Shard> {
        let file_name = overlay
            .file_name()
            .ok_or(Box::new(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "No file name".to_owned(),
            }) as Box<dyn std::error::Error + Send>)?
            .to_str()
            .ok_or(Box::new(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "Cannot convert file name to string".to_owned(),
            }) as Box<dyn std::error::Error + Send>)?;
        let hex = file_name
            .split('_')
            .nth(1)
            .ok_or(Box::new(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: "Cannot parse file name".to_owned(),
            }) as Box<dyn std::error::Error + Send>)?;
        u64::from_str_radix(hex, 16).map(Shard::new).map_err(|err| {
            Box::new(LayoutError::CorruptedLayout {
                path: overlay.to_path_buf(),
                message: format!("failed to get shard for overlay {hex}: {err}"),
            }) as Box<dyn std::error::Error + Send>
        })
    }
}

pub struct CanisterLayout<Permissions: AccessPolicy> {
    canister_root: PathBuf,
    permissions_tag: PhantomData<Permissions>,
    checkpoint: Option<CheckpointLayout<Permissions>>,
}

impl<Permissions: AccessPolicy> CanisterLayout<Permissions> {
    pub fn new(
        canister_root: PathBuf,
        checkpoint: &CheckpointLayout<Permissions>,
    ) -> Result<Self, LayoutError> {
        Permissions::check_dir(&canister_root)?;
        Ok(Self {
            canister_root,
            permissions_tag: PhantomData,
            checkpoint: Some(checkpoint.clone()),
        })
    }

    pub fn new_untracked(canister_root: PathBuf) -> Result<Self, LayoutError> {
        Permissions::check_dir(&canister_root)?;
        Ok(Self {
            canister_root,
            permissions_tag: PhantomData,
            checkpoint: None,
        })
    }

    pub fn raw_path(&self) -> PathBuf {
        self.canister_root.clone()
    }

    pub fn queues(&self) -> ProtoFileWith<pb_queues::CanisterQueues, Permissions> {
        self.canister_root.join(QUEUES_FILE).into()
    }

    pub fn wasm(&self) -> WasmFile<Permissions> {
        WasmFile {
            path: self.canister_root.join(WASM_FILE),
            permissions_tag: PhantomData,
            _checkpoint: self.checkpoint.clone(),
        }
    }

    pub fn canister(
        &self,
    ) -> ProtoFileWith<pb_canister_state_bits::CanisterStateBits, Permissions> {
        self.canister_root.join(CANISTER_FILE).into()
    }

    /// List all PageMaps with at least one file.
    pub fn all_existing_pagemaps(&self) -> Result<Vec<PageMapLayout<Permissions>>, LayoutError> {
        let mut result = Vec::new();
        for pagemap in [
            self.vmemory_0(),
            self.stable_memory(),
            self.wasm_chunk_store(),
            self.log_memory_store(),
        ]
        .into_iter()
        {
            if pagemap.exists()? {
                result.push(pagemap)
            }
        }
        Ok(result)
    }

    pub fn vmemory_0(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.canister_root.clone(),
            name_stem: VMEMORY_0.into(),
            permissions_tag: PhantomData,
            _checkpoint: self.checkpoint.clone(),
        }
    }

    pub fn stable_memory(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.canister_root.clone(),
            name_stem: STABLE_MEMORY.into(),
            permissions_tag: PhantomData,
            _checkpoint: self.checkpoint.clone(),
        }
    }

    pub fn wasm_chunk_store(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.canister_root.clone(),
            name_stem: WASM_CHUNK_STORE.into(),
            permissions_tag: PhantomData,
            _checkpoint: self.checkpoint.clone(),
        }
    }

    pub fn log_memory_store(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.canister_root.clone(),
            name_stem: LOG_MEMORY_STORE.into(),
            permissions_tag: PhantomData,
            _checkpoint: self.checkpoint.clone(),
        }
    }
}

pub struct SnapshotLayout<Permissions: AccessPolicy> {
    snapshot_root: PathBuf,
    permissions_tag: PhantomData<Permissions>,
    checkpoint: Option<CheckpointLayout<Permissions>>,
}

impl<Permissions: AccessPolicy> SnapshotLayout<Permissions> {
    pub fn new(
        snapshot_root: PathBuf,
        checkpoint: &CheckpointLayout<Permissions>,
    ) -> Result<Self, LayoutError> {
        Permissions::check_dir(&snapshot_root)?;
        Ok(Self {
            snapshot_root,
            permissions_tag: PhantomData,
            checkpoint: Some(checkpoint.clone()),
        })
    }

    pub fn new_untracked(snapshot_root: PathBuf) -> Result<Self, LayoutError> {
        Permissions::check_dir(&snapshot_root)?;
        Ok(Self {
            snapshot_root,
            permissions_tag: PhantomData,
            checkpoint: None,
        })
    }
    pub fn raw_path(&self) -> PathBuf {
        self.snapshot_root.clone()
    }

    pub fn wasm(&self) -> WasmFile<Permissions> {
        WasmFile {
            path: self.snapshot_root.join(WASM_FILE),
            permissions_tag: PhantomData,
            _checkpoint: self.checkpoint.clone(),
        }
    }

    pub fn snapshot(
        &self,
    ) -> ProtoFileWith<pb_canister_snapshot_bits::CanisterSnapshotBits, Permissions> {
        self.snapshot_root.join(SNAPSHOT_FILE).into()
    }

    /// List all PageMaps with at least one file.
    pub fn all_existing_pagemaps(&self) -> Result<Vec<PageMapLayout<Permissions>>, LayoutError> {
        let mut result = Vec::new();
        for pagemap in [
            self.vmemory_0(),
            self.stable_memory(),
            self.wasm_chunk_store(),
            // log_memory_store is not included in canister snapshots.
        ]
        .into_iter()
        {
            if pagemap.exists()? {
                result.push(pagemap)
            }
        }
        Ok(result)
    }

    pub fn vmemory_0(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.snapshot_root.clone(),
            name_stem: VMEMORY_0.into(),
            permissions_tag: PhantomData,
            _checkpoint: self.checkpoint.clone(),
        }
    }

    pub fn stable_memory(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.snapshot_root.clone(),
            name_stem: STABLE_MEMORY.into(),
            permissions_tag: PhantomData,
            _checkpoint: self.checkpoint.clone(),
        }
    }

    pub fn wasm_chunk_store(&self) -> PageMapLayout<Permissions> {
        PageMapLayout {
            root: self.snapshot_root.clone(),
            name_stem: WASM_CHUNK_STORE.into(),
            permissions_tag: PhantomData,
            _checkpoint: self.checkpoint.clone(),
        }
    }

    // log_memory_store is not included in canister snapshots.
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
        })?;
        Ok(())
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
pub struct WasmFile<Permissions: AccessPolicy> {
    path: PathBuf,
    permissions_tag: PhantomData<Permissions>,
    // Keep checkpoint alive so that the WasmFile can be loaded asynchronously.
    _checkpoint: Option<CheckpointLayout<Permissions>>,
}

impl<Permissions: AccessPolicy> WasmFile<Permissions> {
    pub fn raw_path(&self) -> &Path {
        &self.path
    }
}

impl<T> MemoryMappableWasmFile for WasmFile<T>
where
    T: ReadPolicy,
{
    fn path(&self) -> &Path {
        &self.path
    }
}

/// Checks that the given wasm file can be memory-mapped successfully.
pub fn try_mmap_wasm_file(
    wasm_file_layout: &dyn MemoryMappableWasmFile,
) -> Result<(), LayoutError> {
    wasm_file_layout
        .mmap_file()
        .map_err(|err| LayoutError::IoError {
            path: wasm_file_layout.path().to_path_buf(),
            message: "Failed to validate wasm file".to_string(),
            io_err: err,
        })?;
    Ok(())
}

impl<T> WasmFile<T>
where
    T: ReadPolicy,
{
    /// Lazily loads a Wasm file with a known `module_hash` and optionally a known file `len`.
    ///
    /// If the file length is already known before calling this function,
    /// passing it into the function avoids fetching the file's metadata, which can
    /// be a relatively expensive operation when dealing with a large number of files.
    /// This is similar to providing the `module_hash` upfront to avoid recomputing it.
    pub fn lazy_load_with_module_hash(
        self,
        module_hash: WasmHash,
        len: Option<usize>,
    ) -> Result<CanisterModule, LayoutError>
    where
        T: Send + Sync + 'static,
    {
        let path = self.path.clone();
        CanisterModule::new_from_file(Box::new(self), module_hash, len).map_err(|err| {
            LayoutError::IoError {
                path,
                message: "Failed to load wasm file lazily".to_string(),
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
                "Failed to hardlink {src_path:?} to {dst_path:?} while making a canister snapshot",
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
        })?;
        Ok(())
    }

    /// Removes the file if it exists, else does nothing.
    pub fn try_delete_file(&self) -> Result<(), LayoutError> {
        try_remove_file(&self.path)
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
                format!("failed to convert file name {file_name:?} to string"),
            )
        })?;
        result.push(string);
    }
    Ok(result)
}

/// Marks a file as readonly if it's not already readonly.
/// Returns true if the file was actually made readonly (was writable before),
/// false if the file was already readonly or is a directory.
fn mark_readonly_if_file(path: &Path) -> std::io::Result<bool> {
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
            return Ok(true);
        }
    }
    Ok(false)
}

fn dir_list_recursive(
    path: &Path,
    thread_pool: &mut Option<&mut scoped_threadpool::Pool>,
) -> std::io::Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    let mut paths_to_iterate = vec![path.to_path_buf()];
    while !paths_to_iterate.is_empty() {
        let next_paths_to_iterate = maybe_parallel_map(
            thread_pool,
            paths_to_iterate.iter(),
            |path| -> std::io::Result<Vec<PathBuf>> {
                let metadata = path.metadata()?;
                if metadata.is_dir() {
                    path.read_dir()?
                        .map(|entry_result| entry_result.map(|entry| entry.path()))
                        .collect::<Result<Vec<_>, _>>()
                } else {
                    Ok(Vec::new())
                }
            },
        )
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
        result.append(&mut paths_to_iterate);
        paths_to_iterate = next_paths_to_iterate;
    }
    Ok(result)
}

#[derive(Copy, Clone)]
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
    mut thread_pool: Option<&mut scoped_threadpool::Pool>,
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
    let results = maybe_parallel_map(
        &mut thread_pool,
        copy_plan.create_and_sync_dir.iter(),
        |op| {
            // We keep directories writeable to make sure we can rename
            // them or delete the files.
            std::fs::create_dir_all(&op.dst)
        },
    );
    results.into_iter().try_for_each(identity)?;
    let results = maybe_parallel_map(
        &mut thread_pool,
        copy_plan.copy_and_sync_file.iter(),
        |op| copy_checkpoint_file(log, metrics, &op.src, &op.dst, fsync),
    );
    results.into_iter().try_for_each(identity)?;
    if let FSync::Yes = fsync {
        let results = maybe_parallel_map(
            &mut thread_pool,
            copy_plan.create_and_sync_dir.iter(),
            |op| sync_path(&op.dst),
        );
        results.into_iter().try_for_each(identity)?;
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

    copy_file_and_set_permissions(log, src, dst)?;

    match fsync {
        FSync::Yes => sync_path(dst),
        FSync::No => Ok(()),
    }
}

/// Copies the given file and ensures that the `read/write` permission of the
/// target file match the given permission.
fn copy_file_and_set_permissions(log: &ReplicaLogger, src: &Path, dst: &Path) -> Result<(), Error> {
    if src.metadata()?.permissions().readonly() {
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
        permissions.set_readonly(true);
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
}

#[derive(PartialEq, Eq)]
enum CopyInstruction {
    /// The file doesn't need to be copied
    Skip,
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
        if file_copy_instruction(src) == CopyInstruction::Skip {
            return Ok(());
        }
        plan.copy_and_sync_file.push(CopyAndSyncFile {
            src: PathBuf::from(src),
            dst: PathBuf::from(dst),
        });
    }
    Ok(())
}
