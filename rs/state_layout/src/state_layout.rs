use crate::error::LayoutError;
use crate::utils::do_copy;

use bitcoin::{hashes::Hash, Network, OutPoint, Script, TxOut, Txid};
use ic_base_types::{NumBytes, NumSeconds};
use ic_logger::{error, ReplicaLogger};
use ic_protobuf::{
    bitcoin::v1 as pb_bitcoin,
    proxy::{try_from_option_field, ProxyDecodeError},
    state::{
        canister_state_bits::v1 as pb_canister_state_bits, queues::v1 as pb_queues,
        system_metadata::v1 as pb_metadata,
    },
};
use ic_replicated_state::{
    bitcoin_state, canister_state::execution_state::WasmMetadata, CallContextManager,
    CanisterStatus, ExecutionTask, ExportedFunctions, Global, NumWasmPages,
};
use ic_sys::mmap::ScopedMmap;
use ic_types::{
    nominal_cycles::NominalCycles, AccumulatedPriority, CanisterId, ComputeAllocation, Cycles,
    ExecutionRound, Height, MemoryAllocation, NumInstructions, PrincipalId,
};
use ic_utils::fs::sync_path;
use ic_utils::thread::parallel_map;
use ic_wasm_types::{CanisterModule, WasmHash};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::{identity, From, TryFrom, TryInto};
use std::fs::OpenOptions;
use std::io::{Error, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

/// `ReadOnly` is the access policy used for reading checkpoints. We
/// don't want to ever modify persisted states.
pub enum ReadOnly {}

/// `WriteOnly` is the access policy used while we are creating a new
/// checkpoint.
pub enum WriteOnly {}
/// `RwPolicy` is the access policy used for tip on disk state.
pub enum RwPolicy {}
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

impl AccessPolicy for RwPolicy {
    fn check_dir(p: &Path) -> Result<(), LayoutError> {
        WriteOnly::check_dir(p)
    }
}

impl ReadPolicy for RwPolicy {}
impl WritePolicy for RwPolicy {}

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
    pub execution_state_bits: Option<ExecutionStateBits>,
    pub memory_allocation: MemoryAllocation,
    pub freeze_threshold: NumSeconds,
    pub cycles_balance: Cycles,
    pub cycles_debit: Cycles,
    pub status: CanisterStatus,
    pub scheduled_as_first: u64,
    pub skipped_round_due_to_no_messages: u64,
    pub executed: u64,
    pub interruped_during_execution: u64,
    pub certified_data: Vec<u8>,
    pub consumed_cycles_since_replica_started: NominalCycles,
    pub stable_memory_size: NumWasmPages,
    pub heap_delta_debit: NumBytes,
    pub install_code_debit: NumInstructions,
    pub task_queue: Vec<ExecutionTask>,
    pub time_of_last_allocation_charge_nanos: u64,
    pub global_timer_nanos: Option<u64>,
    pub canister_version: u64,
}

/// This struct contains bits of the `BitcoinState` that are not already
/// covered somewhere else and are too small to be serialized separately.
#[derive(Debug)]
pub struct BitcoinStateBits {
    pub adapter_queues: bitcoin_state::AdapterQueues,
    pub unstable_blocks: bitcoin_state::UnstableBlocks,
    pub stable_height: u32,
    pub network: Network,
    pub utxos_large: BTreeMap<OutPoint, (TxOut, u32)>,
}

impl Default for BitcoinStateBits {
    fn default() -> Self {
        Self {
            network: Network::Testnet,
            adapter_queues: bitcoin_state::AdapterQueues::default(),
            unstable_blocks: bitcoin_state::UnstableBlocks::default(),
            stable_height: 0,
            utxos_large: BTreeMap::default(),
        }
    }
}

/// `StateLayout` provides convenience functions to construct correct
/// paths to individual components of the replicated execution
/// state. It also utilizes filesystem specific checkpoint managers
/// to create and manage checkpoints.
///
/// Following layout is overlayed on top of the filesystem specific
/// checkpoint manager's internal layout. "checkpoints" directory
/// is not owned by `StateLayout` and is internal to checkpoint manager
///
/// ```text
/// <root>
/// ├── states_metadata.pbuf
/// │
/// │── tip
/// │   ├── system_metadata.pbuf
/// │   ├── subnet_queues.pbuf
/// │   ├── bitcoin
/// |   |   └── testnet
/// |   |       └── state.pbuf
/// |   |       └── utxos_small.bin
/// |   |       └── utxos_medium.bin
/// |   |       └── address_outpoints.bin
/// │   └── canister_states
/// │       └── <hex(canister_id)>
/// │           ├── queues.pbuf
/// │           ├── vmemory_0.bin
/// │           ├── canister.pbuf
/// │           ├── stable_memory.(pbuf|bin)
/// │           └── software.wasm
/// │
/// ├── [checkpoints, backups, diverged_checkpoints]
/// │   └──<hex(round)>
/// │      ├── system_metadata.pbuf
/// │      ├── subnet_queues.pbuf
/// |      ├── bitcoin
/// |      |   └── testnet
/// |      |       └── state.pbuf
/// |      |       └── utxos_small.bin
/// |      |       └── utxos_medium.bin
/// |      |       └── address_outpoints.bin
/// │      └── canister_states
/// │          └── <hex(canister_id)>
/// │              ├── queues.pbuf
/// │              ├── vmemory_0.bin
/// │              ├── canister.pbuf
/// │              ├── stable_memory.(pbuf|bin)
/// │              └── software.wasm
/// │
/// └── diverged_state_markers
/// │   └──<hex(round)>
/// │
/// └── tmp
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
    checkpoint_remove_guard: Arc<Mutex<()>>,
    tip_handler_captured: Arc<AtomicBool>,
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
    pub fn tip(&mut self, height: Height) -> Result<CheckpointLayout<RwPolicy>, LayoutError> {
        CheckpointLayout::new(self.tip_path(), height)
    }

    /// Resets "tip" to a checkpoint identified by height.
    pub fn reset_tip_to(
        &mut self,
        state_layout: &StateLayout,
        height: Height,
        thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> Result<(), LayoutError> {
        let cp_name = state_layout.checkpoint_name(height);
        let tip = self.tip_path();
        if tip.exists() {
            std::fs::remove_dir_all(&tip).map_err(|err| LayoutError::IoError {
                path: tip.to_path_buf(),
                message: format!("Cannot remove tip for checkpoint {}", height),
                io_err: err,
            })?;
        }

        let cp_path = state_layout.checkpoints().join(&cp_name);
        if !cp_path.exists() {
            return Ok(());
        }

        match copy_recursively(
            &state_layout.log,
            cp_path.as_path(),
            &tip,
            FilePermissions::ReadWrite,
            FSync::No,
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
                        cp_name,
                        e.kind()
                    ),
                    io_err: e,
                })
            }
        }
    }

    /// Creates a checkpoint from the "tip" state returning layout object of
    /// the newly created checkpoint
    pub fn tip_to_checkpoint(
        &mut self,
        state_layout: &StateLayout,
        tip: CheckpointLayout<RwPolicy>,
        mut thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> Result<CheckpointLayout<ReadOnly>, LayoutError> {
        let height = tip.height;
        #[allow(clippy::needless_option_as_deref)]
        let cp = state_layout.scratchpad_to_checkpoint(tip, height, thread_pool.as_deref_mut())?;
        self.reset_tip_to(state_layout, height, thread_pool)?;
        Ok(cp)
    }

    /// Deletes canisters from tip if they are not in ids.
    pub fn filter_tip_canisters(
        &mut self,
        height: Height,
        ids: &BTreeSet<&CanisterId>,
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
    pub fn try_new(log: ReplicaLogger, root: PathBuf) -> Result<Self, LayoutError> {
        let state_layout = Self {
            root,
            log,
            checkpoint_remove_guard: Arc::new(Mutex::new(())),
            tip_handler_captured: Arc::new(false.into()),
        };
        state_layout.init()?;
        Ok(state_layout)
    }

    fn init(&self) -> Result<(), LayoutError> {
        self.cleanup_tip()?;
        self.cleanup_tmp()?;
        WriteOnly::check_dir(&self.backups())?;
        WriteOnly::check_dir(&self.checkpoints())?;
        WriteOnly::check_dir(&self.diverged_checkpoints())?;
        WriteOnly::check_dir(&self.diverged_state_markers())?;
        WriteOnly::check_dir(&self.fs_tmp())?;
        WriteOnly::check_dir(&self.tip_path())?;
        WriteOnly::check_dir(&self.tmp())
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

    pub fn scratchpad_to_checkpoint(
        &self,
        layout: CheckpointLayout<RwPolicy>,
        height: Height,
        thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> Result<CheckpointLayout<ReadOnly>, LayoutError> {
        let scratchpad = layout.raw_path();
        let checkpoints_path = self.checkpoints();
        let cp_path = checkpoints_path.join(self.checkpoint_name(height));
        if cp_path.exists() {
            return Err(LayoutError::AlreadyExists(height));
        }
        sync_and_mark_files_readonly(scratchpad, thread_pool).map_err(|err| {
            LayoutError::IoError {
                path: scratchpad.to_path_buf(),
                message: format!(
                    "Could not sync and mark readonly scratchpad for checkpoint {}",
                    height
                ),
                io_err: err,
            }
        })?;
        std::fs::rename(scratchpad, &cp_path).map_err(|err| LayoutError::IoError {
            path: scratchpad.to_path_buf(),
            message: format!("Failed to rename scratchpad to checkpoint {}", height),
            io_err: err,
        })?;
        sync_path(&checkpoints_path).map_err(|err| LayoutError::IoError {
            path: checkpoints_path,
            message: "Could not sync checkpoints".to_string(),
            io_err: err,
        })?;
        CheckpointLayout::new(cp_path, height)
    }

    pub fn clone_checkpoint(&self, from: Height, to: Height) -> Result<(), LayoutError> {
        let src = self.checkpoints().join(self.checkpoint_name(from));
        let dst = self.checkpoints().join(self.checkpoint_name(to));
        self.copy_and_sync_checkpoint(&self.checkpoint_name(to), &src, &dst, None)
            .map_err(|io_err| LayoutError::IoError {
                path: dst,
                message: format!("Failed to clone checkpoint {} to {}", from, to),
                io_err,
            })?;
        Ok(())
    }

    /// Returns the layout of the checkpoint with the given height (if
    /// there is one).
    pub fn checkpoint(&self, height: Height) -> Result<CheckpointLayout<ReadOnly>, LayoutError> {
        let cp_name = self.checkpoint_name(height);
        let path = self.checkpoints().join(&cp_name);
        if !path.exists() {
            return Err(LayoutError::NotFound(height));
        }
        CheckpointLayout::new(path, height)
    }

    /// Returns a sorted list of `Height`s for which a checkpoint is available.
    pub fn checkpoint_heights(&self) -> Result<Vec<Height>, LayoutError> {
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
        self.diverged_checkpoints().join(self.checkpoint_name(h))
    }

    /// Returns a path to a backed up state given its height.
    ///
    /// Precondition:
    ///   h ∈ self.backup_heights()
    pub fn backup_checkpoint_path(&self, h: Height) -> PathBuf {
        self.backups().join(self.checkpoint_name(h))
    }

    /// Removes a checkpoint for a given height if it exists.
    ///
    /// Postcondition:
    ///   height ∉ self.checkpoint_heights()
    pub fn remove_checkpoint(&self, height: Height) -> Result<(), LayoutError> {
        // Don't ever remove the last checkpoint; in debug, crash
        // Mutex to prevent removing two last checkpoints from two threads.
        let _lock = &mut self.checkpoint_remove_guard.lock().unwrap();
        let heights = self.checkpoint_heights()?;
        // If we have one last state e.g. @4 but we try to remove @3, we should fail with an error
        // different from LastCheckpoint
        if heights.len() == 1 && heights[0] == height {
            debug_assert!(false, "Trying to remove the last checkpoint");
            return Err(LayoutError::LastCheckpoint(height));
        }
        let cp_name = self.checkpoint_name(height);
        let cp_path = self.checkpoints().join(&cp_name);
        let tmp_path = self.fs_tmp().join(&cp_name);

        self.atomically_remove_via_path(&cp_path, &tmp_path)
            .map_err(|err| LayoutError::IoError {
                path: cp_path,
                message: format!(
                    "failed to remove checkpoint {} (err kind: {:?})",
                    cp_name,
                    err.kind()
                ),
                io_err: err,
            })
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
        let cp_name = self.checkpoint_name(height);
        let cp_path = self.checkpoints().join(&cp_name);
        let diverged_checkpoints_dir = self.diverged_checkpoints();

        let dst_path = diverged_checkpoints_dir.join(&cp_name);

        match std::fs::rename(&cp_path, &dst_path) {
            Ok(()) => sync_path(&self.checkpoints()).map_err(|err| LayoutError::IoError {
                path: self.checkpoints(),
                message: "Failed to sync checkpoints".to_string(),
                io_err: err,
            }),
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
            .join(self.checkpoint_name(height))
    }

    /// Creates a diverged state marker for the given height.
    ///
    /// Postcondition:
    ///   h ∈ self.diverged_state_heights()
    pub fn create_diverged_state_marker(&self, height: Height) -> Result<(), LayoutError> {
        open_for_write(&self.diverged_state_marker_path(height))?;
        Ok(())
    }

    /// Removes a diverged checkpoint given its height.
    ///
    /// Precondition:
    ///   h ∈ self.diverged_state_heights()
    pub fn remove_diverged_state_marker(&self, height: Height) -> Result<(), LayoutError> {
        let path = self.diverged_state_marker_path(height);
        std::fs::remove_file(&path).map_err(|err| LayoutError::IoError {
            path,
            message: "Failed to remove diverged state marker.".to_string(),
            io_err: err,
        })
    }

    /// Removes a diverged checkpoint given its height.
    ///
    /// Precondition:
    ///   h ∈ self.diverged_checkpoint_heights()
    pub fn remove_diverged_checkpoint(&self, height: Height) -> Result<(), LayoutError> {
        let checkpoint_name = self.checkpoint_name(height);
        let cp_path = self.diverged_checkpoints().join(&checkpoint_name);
        let tmp_path = self
            .fs_tmp()
            .join(format!("diverged_checkpoint_{}", &checkpoint_name));
        self.atomically_remove_via_path(&cp_path, &tmp_path)
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
        let cp_name = self.checkpoint_name(height);
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
        let backup_name = self.checkpoint_name(height);
        let backup_path = self.backups().join(&backup_name);
        let tmp_path = self.fs_tmp().join(format!("backup_{}", &backup_name));
        self.atomically_remove_via_path(backup_path.as_path(), tmp_path.as_path())
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
        let cp_name = self.checkpoint_name(height);
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
            return self.remove_checkpoint(height);
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
        sync_path(&self.checkpoints()).map_err(|err| LayoutError::IoError {
            path: self.checkpoints(),
            message: "Failed to sync checkpoints".to_string(),
            io_err: err,
        })
    }

    fn checkpoint_name(&self, height: Height) -> String {
        format!("{:016x}", height.get())
    }

    fn tip_path(&self) -> PathBuf {
        self.raw_path().join("tip")
    }

    fn checkpoints(&self) -> PathBuf {
        self.root.join("checkpoints")
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
        let scratchpad = self.fs_tmp().join(&scratch_name);
        self.ensure_dir_exists(&scratchpad)?;

        if dst.exists() {
            return Err(Error::new(std::io::ErrorKind::AlreadyExists, name));
        }

        let copy_atomically = || {
            copy_recursively(
                &self.log,
                src,
                scratchpad.as_path(),
                FilePermissions::ReadOnly,
                FSync::Yes,
                thread_pool,
            )?;
            std::fs::rename(&scratchpad, &dst)?;
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
    fn atomically_remove_via_path(&self, path: &Path, tmp_path: &Path) -> std::io::Result<()> {
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
        std::fs::remove_dir_all(tmp_path)
    }
}

/// Collects all the direct children of the specified directory into a
/// vector and applies the provided transformation to them.  The names
/// are assumed to be hex numbers.
fn collect_subdirs<F, T>(dir: &Path, transform: F) -> Result<Vec<T>, LayoutError>
where
    F: Fn(&str) -> T,
{
    let mut ids = Vec::new();

    if !dir.exists() {
        return Ok(ids);
    }

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

        if let Some(file_name) = dir.file_name().to_str() {
            ids.push(transform(file_name));
        }
    }
    Ok(ids)
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
    permissions_tag: PhantomData<Permissions>,
}

impl<Permissions: AccessPolicy> CheckpointLayout<Permissions> {
    pub fn new(root: PathBuf, height: Height) -> Result<Self, LayoutError> {
        Permissions::check_dir(&root)?;
        Ok(Self {
            root,
            height,
            permissions_tag: PhantomData,
        })
    }

    pub fn system_metadata(&self) -> ProtoFileWith<pb_metadata::SystemMetadata, Permissions> {
        self.root.join("system_metadata.pbuf").into()
    }

    pub fn subnet_queues(&self) -> ProtoFileWith<pb_queues::CanisterQueues, Permissions> {
        self.root.join("subnet_queues.pbuf").into()
    }

    pub fn canister_ids(&self) -> Result<Vec<CanisterId>, LayoutError> {
        let states_dir = self.root.join("canister_states");
        Permissions::check_dir(&states_dir)?;
        collect_subdirs(states_dir.as_path(), |p| {
            let blob = hex::decode(p).unwrap_or_else(|err| {
                panic!(
                    "Failed to convert directory name {} into a canister id: {}",
                    p, err
                )
            });

            CanisterId::new(PrincipalId::try_from(&blob[..]).expect("failed to parse principal id"))
                .unwrap()
        })
    }

    pub fn canister(
        &self,
        canister_id: &CanisterId,
    ) -> Result<CanisterLayout<Permissions>, LayoutError> {
        CanisterLayout::new(
            self.root
                .join("canister_states")
                .join(hex::encode(canister_id.get_ref().as_slice())),
        )
    }

    pub fn bitcoin(&self) -> Result<BitcoinStateLayout<Permissions>, LayoutError> {
        // TODO(EXC-1113): Rename this path to "bitcoin", as it stores data for either network.
        BitcoinStateLayout::new(self.root.join("bitcoin").join("testnet"))
    }

    pub fn height(&self) -> Height {
        self.height
    }

    pub fn raw_path(&self) -> &Path {
        &self.root
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
        self.canister_root.join("queues.pbuf").into()
    }

    pub fn wasm(&self) -> WasmFile<Permissions> {
        self.canister_root.join("software.wasm").into()
    }

    pub fn canister(
        &self,
    ) -> ProtoFileWith<pb_canister_state_bits::CanisterStateBits, Permissions> {
        self.canister_root.join("canister.pbuf").into()
    }

    pub fn vmemory_0(&self) -> PathBuf {
        self.canister_root.join("vmemory_0.bin")
    }

    pub fn stable_memory_blob(&self) -> PathBuf {
        self.canister_root.join("stable_memory.bin")
    }
}

pub struct BitcoinStateLayout<Permissions: AccessPolicy> {
    bitcoin_root: PathBuf,
    permissions_tag: PhantomData<Permissions>,
}

impl<Permissions: AccessPolicy> BitcoinStateLayout<Permissions> {
    pub fn new(bitcoin_root: PathBuf) -> Result<Self, LayoutError> {
        Permissions::check_dir(&bitcoin_root)?;
        Ok(Self {
            bitcoin_root,
            permissions_tag: PhantomData,
        })
    }

    pub fn raw_path(&self) -> PathBuf {
        self.bitcoin_root.clone()
    }

    pub fn bitcoin_state(&self) -> ProtoFileWith<pb_bitcoin::BitcoinStateBits, Permissions> {
        self.bitcoin_root.join("state.pbuf").into()
    }

    pub fn utxos_small(&self) -> PathBuf {
        self.bitcoin_root.join("utxos_small.bin")
    }

    pub fn utxos_medium(&self) -> PathBuf {
        self.bitcoin_root.join("utxos_medium.bin")
    }

    pub fn address_outpoints(&self) -> PathBuf {
        self.bitcoin_root.join("address_outpoints.bin")
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

pub struct ProtoFileWith<T, Permissions> {
    path: PathBuf,
    content_tag: PhantomData<T>,
    permissions_tag: PhantomData<Permissions>,
}

impl<T, Permission> ProtoFileWith<T, Permission> {
    pub fn raw_path(&self) -> &Path {
        &self.path
    }
}

impl<T, P> ProtoFileWith<T, P>
where
    T: prost::Message,
    P: WritePolicy,
{
    pub fn serialize(&self, value: T) -> Result<(), LayoutError> {
        let mut serialized = Vec::new();
        value.encode(&mut serialized).unwrap_or_else(|e| {
            panic!(
                "Failed to serialize an object of type {} to protobuf: {}",
                std::any::type_name::<T>(),
                e
            )
        });

        let file = open_for_write(&self.path)?;
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

        Ok(())
    }
}

impl<T, P> ProtoFileWith<T, P>
where
    T: prost::Message + std::default::Default,
    P: ReadPolicy,
{
    pub fn deserialize(&self) -> Result<T, LayoutError> {
        let file = open_for_read(&self.path)?;
        self.deserialize_file(file)
    }

    fn deserialize_file(&self, f: std::fs::File) -> Result<T, LayoutError> {
        let mmap = ScopedMmap::mmap_file_readonly(f).map_err(|io_err| LayoutError::IoError {
            path: self.path.clone(),
            message: "failed to mmap a file".to_string(),
            io_err,
        })?;
        T::decode(mmap.as_slice()).map_err(|err| LayoutError::CorruptedLayout {
            path: self.path.clone(),
            message: format!(
                "failed to deserialize an object of type {} from protobuf: {}",
                std::any::type_name::<T>(),
                err
            ),
        })
    }

    /// Deserializes the value if the underlying file exists.
    /// If the proto file does not exist, returns Ok(None).
    /// Returns an error for all other I/O errors.
    pub fn deserialize_opt(&self) -> Result<Option<T>, LayoutError> {
        match open_for_read(&self.path) {
            Ok(f) => self.deserialize_file(f).map(Some),
            Err(LayoutError::IoError { io_err, .. })
                if io_err.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
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
}

impl<T> WasmFile<T>
where
    T: WritePolicy,
{
    pub fn serialize(&self, wasm: &CanisterModule) -> Result<(), LayoutError> {
        let mut file = open_for_write(&self.path)?;
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
        })
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
            accumulated_priority: item.accumulated_priority.value(),
            execution_state_bits: item.execution_state_bits.as_ref().map(|v| v.into()),
            memory_allocation: item.memory_allocation.bytes().get(),
            freeze_threshold: item.freeze_threshold.get(),
            cycles_balance: Some(item.cycles_balance.into()),
            cycles_debit: Some(item.cycles_debit.into()),
            canister_status: Some((&item.status).into()),
            scheduled_as_first: item.scheduled_as_first,
            skipped_round_due_to_no_messages: item.skipped_round_due_to_no_messages,
            executed: item.executed,
            interruped_during_execution: item.interruped_during_execution,
            certified_data: item.certified_data.clone(),
            consumed_cycles_since_replica_started: Some(
                (&item.consumed_cycles_since_replica_started).into(),
            ),
            stable_memory_size64: item.stable_memory_size.get() as u64,
            heap_delta_debit: item.heap_delta_debit.get(),
            install_code_debit: item.install_code_debit.get(),
            time_of_last_allocation_charge_nanos: Some(item.time_of_last_allocation_charge_nanos),
            task_queue: item.task_queue.iter().map(|v| v.into()).collect(),
            global_timer_nanos: item.global_timer_nanos,
            canister_version: item.canister_version,
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

        let consumed_cycles_since_replica_started = match try_from_option_field(
            value.consumed_cycles_since_replica_started,
            "CanisterStateBits::consumed_cycles_since_replica_started",
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
            .map(|c| c.try_into())
            .transpose()?
            .unwrap_or_else(Cycles::zero);

        let task_queue = value
            .task_queue
            .into_iter()
            .map(|v| v.try_into())
            .collect::<Result<_, _>>()?;

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
            execution_state_bits,
            memory_allocation: MemoryAllocation::try_from(NumBytes::from(value.memory_allocation))
                .map_err(|e| ProxyDecodeError::ValueOutOfRange {
                    typ: "MemoryAllocation",
                    err: format!("{:?}", e),
                })?,
            freeze_threshold: NumSeconds::from(value.freeze_threshold),
            cycles_balance,
            cycles_debit,
            status: try_from_option_field(
                value.canister_status,
                "CanisterStateBits::canister_status",
            )?,
            scheduled_as_first: value.scheduled_as_first,
            skipped_round_due_to_no_messages: value.skipped_round_due_to_no_messages,
            executed: value.executed,
            interruped_during_execution: value.interruped_during_execution,
            certified_data: value.certified_data,
            consumed_cycles_since_replica_started,
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
        })
    }
}

impl From<&BitcoinStateBits> for pb_bitcoin::BitcoinStateBits {
    fn from(item: &BitcoinStateBits) -> Self {
        pb_bitcoin::BitcoinStateBits {
            adapter_queues: Some((&item.adapter_queues).into()),
            unstable_blocks: Some((&item.unstable_blocks).into()),
            stable_height: item.stable_height,
            network: match item.network {
                Network::Testnet => 1,
                Network::Bitcoin => 2,
                Network::Regtest => 3,
                // TODO(EXC-1096): Define our Network struct to avoid this panic.
                _ => panic!("Invalid network ID"),
            },
            utxos_large: item
                .utxos_large
                .iter()
                .map(|(outpoint, (txout, height))| pb_bitcoin::Utxo {
                    outpoint: Some(pb_bitcoin::OutPoint {
                        txid: outpoint.txid.to_vec(),
                        vout: outpoint.vout,
                    }),
                    txout: Some(pb_bitcoin::TxOut {
                        value: txout.value,
                        script_pubkey: txout.script_pubkey.to_bytes(),
                    }),
                    height: *height,
                })
                .collect(),
        }
    }
}

impl TryFrom<pb_bitcoin::BitcoinStateBits> for BitcoinStateBits {
    type Error = ProxyDecodeError;

    fn try_from(value: pb_bitcoin::BitcoinStateBits) -> Result<Self, Self::Error> {
        let adapter_queues: bitcoin_state::AdapterQueues =
            try_from_option_field(value.adapter_queues, "BitcoinStateBits::adapter_queues")?;

        // NOTE: The `unwrap_or_default` here is needed temporarily for backward compatibility.
        // TODO(EXC-1094): Replace the `unwrap_or_default` with an error once this change
        //                 is deployed to prod.
        let unstable_blocks: bitcoin_state::UnstableBlocks =
            try_from_option_field(value.unstable_blocks, "BitcoinStateBits::unstable_blocks")
                .unwrap_or_default();
        Ok(BitcoinStateBits {
            adapter_queues,
            unstable_blocks,
            stable_height: value.stable_height,
            network: match value.network {
                0 => {
                    // No network specified. Assume "testnet".
                    // NOTE: This is needed temporarily for protobuf backward compatibility.
                    // TODO(EXC-1094): Remove this condition once it has been deployed to prod.
                    Network::Testnet
                }
                1 => Network::Testnet,
                2 => Network::Bitcoin,
                3 => Network::Regtest,
                other => {
                    return Err(ProxyDecodeError::ValueOutOfRange {
                        typ: "Network",
                        err: format!(
                            "Expected 0 or 1 (testnet), 2 (mainnet), 3 (regtest), got {}",
                            other
                        ),
                    })
                }
            },
            utxos_large: value
                .utxos_large
                .into_iter()
                .map(|utxo| {
                    let outpoint = utxo
                        .outpoint
                        .map(|o| {
                            OutPoint::new(
                                Txid::from_hash(Hash::from_slice(&o.txid).unwrap()),
                                o.vout,
                            )
                        })
                        .unwrap();

                    let tx_out = utxo
                        .txout
                        .map(|t| TxOut {
                            value: t.value,
                            script_pubkey: Script::from(t.script_pubkey),
                        })
                        .unwrap();

                    (outpoint, (tx_out, utxo.height))
                })
                .collect(),
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

#[derive(Clone, Copy)]
enum FilePermissions {
    ReadOnly,
    ReadWrite,
}

fn sync_and_mark_readonly_if_file(path: &Path) -> std::io::Result<()> {
    let metadata = path.metadata()?;
    if !metadata.is_dir() {
        let mut permissions = metadata.permissions();
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
    sync_path(path)
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
    path: &Path,
    thread_pool: Option<&mut scoped_threadpool::Pool>,
) -> std::io::Result<()> {
    let paths = dir_list_recursive(path)?;
    if let Some(thread_pool) = thread_pool {
        let results = parallel_map(thread_pool, paths.iter(), |p| {
            sync_and_mark_readonly_if_file(p)
        });
        results.into_iter().try_for_each(identity)?;
    } else {
        for p in paths {
            sync_and_mark_readonly_if_file(&p)?;
        }
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
fn copy_recursively(
    log: &ReplicaLogger,
    root_src: &Path,
    root_dst: &Path,
    dst_permissions: FilePermissions,
    fsync: FSync,
    thread_pool: Option<&mut scoped_threadpool::Pool>,
) -> std::io::Result<()> {
    let mut copy_plan = CopyPlan {
        create_and_sync_dir: vec![],
        copy_and_sync_file: vec![],
    };

    build_copy_plan(root_src, root_dst, &mut copy_plan)?;

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
    std::fs::create_dir_all(&root_dst)?;
    match thread_pool {
        Some(thread_pool) => {
            let results = parallel_map(thread_pool, copy_plan.create_and_sync_dir.iter(), |op| {
                std::fs::create_dir_all(&op.dst)
            });
            results.into_iter().try_for_each(identity)?;
            let results = parallel_map(thread_pool, copy_plan.copy_and_sync_file.iter(), |op| {
                copy_file_and_set_permissions(log, &op.src, &op.dst, dst_permissions, fsync)
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
                copy_file_and_set_permissions(log, &op.src, &op.dst, dst_permissions, fsync)?;
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
/// Syncs the target file if `fsync` is true.
fn copy_file_and_set_permissions(
    log: &ReplicaLogger,
    src: &Path,
    dst: &Path,
    dst_permissions: FilePermissions,
    fsync: FSync,
) -> std::io::Result<()> {
    do_copy(log, src, dst)?;

    // We keep the directory writable though to make sure we can rename
    // them or delete the files.
    let dst_metadata = dst.metadata()?;
    let mut permissions = dst_metadata.permissions();
    match dst_permissions {
        FilePermissions::ReadOnly => permissions.set_readonly(true),
        FilePermissions::ReadWrite => permissions.set_readonly(false),
    }
    std::fs::set_permissions(&dst, permissions)?;
    match fsync {
        FSync::Yes => sync_path(&dst),
        FSync::No => Ok(()),
    }
}

// Describes how to copy one directory to another.
// The order of operations is improtant:
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

/// Traverse the source file tree and constructs a copy-plan:
/// a collection of I/O operations that need to be performed to copy the source
/// to the destination.
fn build_copy_plan(src: &Path, dst: &Path, plan: &mut CopyPlan) -> std::io::Result<()> {
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
            build_copy_plan(&entry.path(), &dst_entry, plan)?;
        }
    } else {
        plan.copy_and_sync_file.push(CopyAndSyncFile {
            src: PathBuf::from(src),
            dst: PathBuf::from(dst),
        });
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    use ic_ic00_types::IC_00;
    use ic_interfaces::messages::{CanisterInputMessage, RequestOrIngress};
    use ic_test_utilities::{
        mock_time,
        types::{
            ids::canister_test_id,
            messages::{IngressBuilder, RequestBuilder, ResponseBuilder},
        },
    };
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_tmpdir::tmpdir;
    use std::sync::Arc;

    fn default_canister_state_bits() -> CanisterStateBits {
        CanisterStateBits {
            controllers: BTreeSet::new(),
            last_full_execution_round: ExecutionRound::from(0),
            call_context_manager: None,
            compute_allocation: ComputeAllocation::try_from(0).unwrap(),
            accumulated_priority: AccumulatedPriority::from(0),
            execution_state_bits: None,
            memory_allocation: MemoryAllocation::default(),
            freeze_threshold: NumSeconds::from(0),
            cycles_balance: Cycles::zero(),
            cycles_debit: Cycles::zero(),
            status: CanisterStatus::Stopped,
            scheduled_as_first: 0,
            skipped_round_due_to_no_messages: 0,
            executed: 0,
            interruped_during_execution: 0,
            certified_data: vec![],
            consumed_cycles_since_replica_started: NominalCycles::from(0),
            stable_memory_size: NumWasmPages::from(0),
            heap_delta_debit: NumBytes::from(0),
            install_code_debit: NumInstructions::from(0),
            time_of_last_allocation_charge_nanos: mock_time().as_nanos_since_unix_epoch(),
            task_queue: vec![],
            global_timer_nanos: None,
            canister_version: 0,
        }
    }

    #[test]
    fn test_state_layout_diverged_state_paths() {
        with_test_replica_logger(|log| {
            let tempdir = tmpdir("state_layout");
            let root_path = tempdir.path().to_path_buf();
            let state_layout = StateLayout::try_new(log, root_path.clone()).unwrap();
            state_layout
                .create_diverged_state_marker(Height::new(1))
                .unwrap();
            assert_eq!(
                state_layout.diverged_state_heights().unwrap(),
                vec![Height::new(1)],
            );
            assert!(state_layout
                .diverged_state_marker_path(Height::new(1))
                .starts_with(root_path.join("diverged_state_markers")));
            state_layout
                .remove_diverged_state_marker(Height::new(1))
                .unwrap();
            assert!(state_layout.diverged_state_heights().unwrap().is_empty());
        });
    }

    #[test]
    fn test_encode_decode_empty_controllers() {
        // A canister state with empty controllers.
        let canister_state_bits = default_canister_state_bits();

        let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
        let canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();

        // Controllers are still empty, as expected.
        assert_eq!(canister_state_bits.controllers, BTreeSet::new());
    }

    #[test]
    fn test_encode_decode_non_empty_controllers() {
        let mut controllers = BTreeSet::new();
        controllers.insert(IC_00.into());
        controllers.insert(canister_test_id(0).get());

        // A canister state with non-empty controllers.
        let canister_state_bits = CanisterStateBits {
            controllers,
            ..default_canister_state_bits()
        };

        let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
        let canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();

        let mut expected_controllers = BTreeSet::new();
        expected_controllers.insert(canister_test_id(0).get());
        expected_controllers.insert(IC_00.into());
        assert_eq!(canister_state_bits.controllers, expected_controllers);
    }

    #[test]
    fn test_encode_decode_task_queue() {
        let ingress = Arc::new(IngressBuilder::new().method_name("test_ingress").build());
        let request = Arc::new(RequestBuilder::new().method_name("test_request").build());
        let response = Arc::new(
            ResponseBuilder::new()
                .respondent(canister_test_id(42))
                .build(),
        );
        let task_queue = vec![
            ExecutionTask::AbortedInstallCode {
                message: RequestOrIngress::Ingress(Arc::clone(&ingress)),
                prepaid_execution_cycles: Cycles::new(1),
            },
            ExecutionTask::AbortedExecution {
                message: CanisterInputMessage::Request(Arc::clone(&request)),
                prepaid_execution_cycles: Cycles::new(2),
            },
            ExecutionTask::AbortedInstallCode {
                message: RequestOrIngress::Request(Arc::clone(&request)),
                prepaid_execution_cycles: Cycles::new(3),
            },
            ExecutionTask::AbortedExecution {
                message: CanisterInputMessage::Response(Arc::clone(&response)),
                prepaid_execution_cycles: Cycles::new(4),
            },
            ExecutionTask::AbortedExecution {
                message: CanisterInputMessage::Ingress(Arc::clone(&ingress)),
                prepaid_execution_cycles: Cycles::new(5),
            },
        ];
        let canister_state_bits = CanisterStateBits {
            task_queue: task_queue.clone(),
            ..default_canister_state_bits()
        };

        let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
        let canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();
        assert_eq!(canister_state_bits.task_queue, task_queue);
    }
}
