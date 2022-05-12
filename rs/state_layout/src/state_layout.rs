use crate::basic_cpmgr::BasicCheckpointManager;
use crate::error::LayoutError;

use bitcoin::{hashes::Hash, Network, OutPoint, Script, TxOut, Txid};
use ic_base_types::{NumBytes, NumSeconds};
use ic_logger::ReplicaLogger;
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
    CanisterStatus, ExportedFunctions, Global, NumWasmPages,
};
use ic_sys::mmap::ScopedMmap;
use ic_types::{
    nominal_cycles::NominalCycles, AccumulatedPriority, CanisterId, ComputeAllocation, Cycles,
    ExecutionRound, Height, MemoryAllocation, NumInstructions, PrincipalId,
};
use ic_wasm_types::CanisterModule;
use std::convert::{From, TryFrom, TryInto};
use std::fs::OpenOptions;
use std::io::Write;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub trait CheckpointManager: Send + Sync {
    /// Returns the base directory path managed by checkpoint manager.
    fn raw_path(&self) -> &Path;

    /// Atomically creates a checkpoint from the "tip" directory.
    /// "name" identifies the name of the checkpoint to be created
    /// and it need not be a directory path.
    ///
    /// If a thread-pool is provided then files are copied in parallel.
    fn tip_to_checkpoint(
        &self,
        tip: &Path,
        name: &str,
        thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> std::io::Result<PathBuf>;

    /// Removes a checkpoint identified by "name".
    fn remove_checkpoint(&self, name: &str) -> std::io::Result<()>;

    /// Promotes the scratchpad at "path" to a checkpoint identified by "name".
    fn scratchpad_to_checkpoint(&self, path: &Path, name: &str) -> std::io::Result<PathBuf>;

    /// Creates a mutable copy of a checkpoint in a the specified path.
    fn checkpoint_to_scratchpad(&self, name: &str, path: &Path) -> std::io::Result<()>;

    /// Gets the path for a checkpoint identified by "name".
    fn get_checkpoint_path(&self, name: &str) -> PathBuf;

    /// Marks checkpoint identified by "name" as diverged.
    ///
    /// Post-condition: name ∉ self.list_checkpoints()
    fn mark_checkpoint_diverged(&self, name: &str) -> std::io::Result<()>;

    /// Creates a backup of the checkpoint identified by "name".
    fn backup_checkpoint(&self, name: &str) -> std::io::Result<()>;

    /// Returns the list of names of diverged checkpoints.
    fn list_diverged_checkpoints(&self) -> std::io::Result<Vec<String>>;

    /// Returns the list of names of checkpoint backups.
    fn list_backups(&self) -> std::io::Result<Vec<String>>;

    /// Returns a path to diverged checkpoint with the specified name.
    fn get_diverged_checkpoint_path(&self, name: &str) -> PathBuf;

    /// Returns a path to a backup the specified name.
    fn get_backup_path(&self, name: &str) -> PathBuf;

    /// Removes the diverged checkpoint with the specified name.
    fn remove_diverged_checkpoint(&self, name: &str) -> std::io::Result<()>;

    /// Removes the backup with the specified name.
    fn remove_backup(&self, name: &str) -> std::io::Result<()>;

    /// List names of all the existing checkpoints.
    fn list_checkpoints(&self) -> std::io::Result<Vec<String>>;

    /// Moves a checkpoint with the specified name into the backup checkpoints
    /// directory.
    fn archive_checkpoint(&self, name: &str) -> std::io::Result<()>;

    /// Atomically resets containts of "tip" directory to that of checkpoint
    fn reset_tip_to(&self, tip: &Path, name: &str) -> std::io::Result<()>;
}

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
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ExecutionStateBits {
    pub exported_globals: Vec<Global>,
    pub heap_size: NumWasmPages,
    pub exports: ExportedFunctions,
    pub last_executed_round: ExecutionRound,
    pub metadata: WasmMetadata,
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
/// ├── [checkpoints] {owned and varies by checkpoint manager}
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
/// └── tmp
/// ```
///
/// Needs to be pub for criterion performance regression tests.
#[derive(Clone)]
pub struct StateLayout {
    cp_manager: Arc<dyn CheckpointManager>,
    _log: ReplicaLogger,
}

impl StateLayout {
    /// Needs to be pub for criterion performance regression tests.
    pub fn new(log: ReplicaLogger, root: PathBuf) -> Self {
        Self {
            cp_manager: Arc::new(BasicCheckpointManager::new(log.clone(), root)),
            _log: log,
        }
    }

    /// Returns the the raw root path for state
    pub fn raw_path(&self) -> &Path {
        self.cp_manager.raw_path()
    }

    /// Returns the path to the temporary directory.
    /// This directory is cleaned during restart of a node.
    pub fn tmp(&self) -> Result<PathBuf, LayoutError> {
        let tmp = self.cp_manager.raw_path().join("tmp");
        WriteOnly::check_dir(&tmp)?;
        Ok(tmp)
    }

    /// Removes the tmp directory and all its contents
    pub fn remove_tmp(&self) -> Result<(), LayoutError> {
        let tmp = self.tmp()?;
        std::fs::remove_dir_all(&tmp).map_err(|err| LayoutError::IoError {
            path: tmp,
            message: "Unable to remove temporary directory".to_string(),
            io_err: err,
        })
    }

    /// Returns a layout object representing tip state in "tip"
    /// directory. During round execution this directory may contain
    /// inconsistent state. During full checkpointing this directory contains
    /// full state and is converted to a checkpoint.
    /// This directory is cleaned during restart of a node and reset to
    /// last full checkpoint.
    pub fn tip(&self, height: Height) -> Result<CheckpointLayout<RwPolicy>, LayoutError> {
        CheckpointLayout::new(self.tip_path(), height)
    }

    /// Returns the path to the serialized states metadata.
    pub fn states_metadata(&self) -> PathBuf {
        self.cp_manager.raw_path().join("states_metadata.pbuf")
    }

    /// Returns scratchpad used during statesync
    pub fn state_sync_scratchpad(&self, height: Height) -> Result<PathBuf, LayoutError> {
        let tmp = self.tmp()?;
        Ok(tmp.join(format!("state_sync_scratchpad_{:016x}", height.get())))
    }

    /// Returns the path to cache an unfinished statesync at `height`
    pub fn state_sync_cache(&self, height: Height) -> Result<PathBuf, LayoutError> {
        let tmp = self.tmp()?;
        Ok(tmp.join(format!("state_sync_cache_{:016x}", height.get())))
    }

    pub fn cleanup_tip(&self) -> Result<(), LayoutError> {
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

    /// Creates a checkpoint from the "tip" state returning layout object of
    /// the newly created checkpoint
    pub fn tip_to_checkpoint(
        &self,
        tip: CheckpointLayout<RwPolicy>,
        thread_pool: Option<&mut scoped_threadpool::Pool>,
    ) -> Result<CheckpointLayout<ReadOnly>, LayoutError> {
        let height = tip.height;
        let cp_name = self.checkpoint_name(height);
        match self
            .cp_manager
            .tip_to_checkpoint(tip.raw_path(), &cp_name, thread_pool)
        {
            Ok(new_cp) => CheckpointLayout::new(new_cp, height),
            Err(err) if is_dir_already_exists_err(&err) => Err(LayoutError::AlreadyExists(height)),
            Err(err) => Err(LayoutError::IoError {
                path: tip.raw_path().to_path_buf(),
                message: format!(
                    "Failed to convert tip to checkpoint to {} (err kind: {:?})",
                    cp_name,
                    err.kind()
                ),
                io_err: err,
            }),
        }
    }

    pub fn scratchpad_to_checkpoint(
        &self,
        layout: CheckpointLayout<RwPolicy>,
        height: Height,
    ) -> Result<CheckpointLayout<ReadOnly>, LayoutError> {
        let cp_name = self.checkpoint_name(height);
        match self
            .cp_manager
            .scratchpad_to_checkpoint(layout.raw_path(), &cp_name)
        {
            Ok(cp_path) => CheckpointLayout::new(cp_path, height),
            Err(err) if is_dir_already_exists_err(&err) => Err(LayoutError::AlreadyExists(height)),
            Err(err) => Err(LayoutError::IoError {
                path: layout.raw_path().to_path_buf(),
                message: format!(
                    "Failed to convert scratchpad to checkpoint {} (err kind: {:?})",
                    height,
                    err.kind()
                ),
                io_err: err,
            }),
        }
    }

    pub fn checkpoint_to_scratchpad(
        &self,
        height: Height,
    ) -> Result<CheckpointLayout<RwPolicy>, LayoutError> {
        let tmp_path = self.tmp()?;
        let scratchpad_dir = tempfile::Builder::new()
            .prefix(&tmp_path)
            .tempdir()
            .map_err(|io_err| LayoutError::IoError {
                path: tmp_path,
                message: "failed to create a temporary directory".to_string(),
                io_err,
            })?;

        let cp_name = self.checkpoint_name(height);
        match self
            .cp_manager
            .checkpoint_to_scratchpad(&cp_name, scratchpad_dir.path())
        {
            Ok(_) => CheckpointLayout::<RwPolicy>::new(scratchpad_dir.into_path(), height),
            Err(io_err) => Err(LayoutError::IoError {
                path: scratchpad_dir.into_path(),
                message: format!("failed to create a copy of checkpoint {}", height),
                io_err,
            }),
        }
    }

    /// Resets "tip" to a checkpoint identified by height.
    pub fn reset_tip_to(&self, height: Height) -> Result<(), LayoutError> {
        let cp_name = self.checkpoint_name(height);
        let tip = self.tip_path();
        match self.cp_manager.reset_tip_to(&tip, &cp_name) {
            Ok(()) => Ok(()),
            Err(err) => Err(LayoutError::IoError {
                path: tip,
                message: format!(
                    "Failed to convert reset tip to checkpoint to {} (err kind: {:?})",
                    cp_name,
                    err.kind()
                ),
                io_err: err,
            }),
        }
    }

    /// Returns the layout of the checkpoint with the given height (if
    /// there is one).
    pub fn checkpoint(&self, height: Height) -> Result<CheckpointLayout<ReadOnly>, LayoutError> {
        let cp_name = self.checkpoint_name(height);
        let path = self.cp_manager.get_checkpoint_path(&cp_name);
        if !path.exists() {
            return Err(LayoutError::NotFound(height));
        }
        CheckpointLayout::new(path, height)
    }

    /// Returns a sorted list of `Height`s for which a checkpoint is available.
    pub fn checkpoint_heights(&self) -> Result<Vec<Height>, LayoutError> {
        let names = self
            .cp_manager
            .list_checkpoints()
            .map_err(|err| LayoutError::IoError {
                path: "NO_PATH".into(),
                message: format!("Failed to get all checkpoints (err kind: {:?})", err.kind()),
                io_err: err,
            })?;

        parse_checkpoint_heights(&names[..])
    }

    /// Returns a sorted list of `Height`s of checkpoints that were marked as
    /// diverged.
    pub fn diverged_checkpoint_heights(&self) -> Result<Vec<Height>, LayoutError> {
        let names = self
            .cp_manager
            .list_diverged_checkpoints()
            .map_err(|io_err| LayoutError::IoError {
                path: "NO_PATH".into(),
                message: "failed to enumerate diverged checkpoints".to_string(),
                io_err,
            })?;
        parse_checkpoint_heights(&names[..])
    }

    /// Returns a sorted list of heights of checkpoints that were "backed up"
    /// for future inspection because they corresponded to diverged states.
    pub fn backup_heights(&self) -> Result<Vec<Height>, LayoutError> {
        let names = self
            .cp_manager
            .list_backups()
            .map_err(|io_err| LayoutError::IoError {
                path: "NO_PATH".into(),
                message: "failed to enumerate backups".to_string(),
                io_err,
            })?;
        parse_checkpoint_heights(&names[..])
    }

    /// Returns a path to a diverged checkpoint given its height.
    ///
    /// If there is no diverged checkpoint with the specified height, the
    /// returned path doesn't exist on the filesystem.
    ///
    /// Precondition:
    ///   h ∈ self.diverged_checkpoint_heights()
    pub fn diverged_checkpoint_path(&self, h: Height) -> PathBuf {
        self.cp_manager
            .get_diverged_checkpoint_path(self.checkpoint_name(h).as_str())
    }

    /// Returns a path to a backed up state given its height.
    ///
    /// Precondition:
    ///   h ∈ self.backup_heights()
    pub fn backup_checkpoint_path(&self, h: Height) -> PathBuf {
        self.cp_manager
            .get_backup_path(self.checkpoint_name(h).as_str())
    }

    /// Removes a checkpoint for a given height if it exists.
    ///
    /// Postcondition:
    ///   height ∉ self.checkpoint_heights()
    pub fn remove_checkpoint(&self, height: Height) -> Result<(), LayoutError> {
        let cp_name = self.checkpoint_name(height);
        self.cp_manager
            .remove_checkpoint(&cp_name)
            .map_err(|err| LayoutError::IoError {
                path: self.cp_manager.get_checkpoint_path(&cp_name),
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
        self.cp_manager
            .mark_checkpoint_diverged(&cp_name)
            .map_err(|err| LayoutError::IoError {
                path: self.cp_manager.get_checkpoint_path(&cp_name),
                message: format!("failed to mark checkpoint {} diverged", height),
                io_err: err,
            })
    }

    /// Removes a diverged checkpoint given its height.
    ///
    /// Precondition:
    ///   h ∈ self.diverged_checkpoint_heights()
    pub fn remove_diverged_checkpoint(&self, height: Height) -> Result<(), LayoutError> {
        let checkpoint_name = self.checkpoint_name(height);
        self.cp_manager
            .remove_diverged_checkpoint(&checkpoint_name)
            .map_err(|err| LayoutError::IoError {
                path: self.cp_manager.get_backup_path(checkpoint_name.as_str()),
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
        self.cp_manager
            .backup_checkpoint(&cp_name)
            .map_err(|err| LayoutError::IoError {
                path: self.cp_manager.get_checkpoint_path(&cp_name),
                message: format!("failed to backup checkpoint {}", height),
                io_err: err,
            })
    }

    /// Removes a backed up state given its height.
    ///
    /// Precondition:
    ///   h ∈ self.backup_heights()
    pub fn remove_backup(&self, height: Height) -> Result<(), LayoutError> {
        let backup_name = self.checkpoint_name(height);
        self.cp_manager
            .remove_backup(&backup_name)
            .map_err(|err| LayoutError::IoError {
                path: self.cp_manager.get_backup_path(backup_name.as_str()),
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
        self.cp_manager
            .archive_checkpoint(&cp_name)
            .map_err(|err| LayoutError::IoError {
                path: self.cp_manager.get_checkpoint_path(&cp_name),
                message: format!("failed to archive checkpoint {}", height),
                io_err: err,
            })
    }

    fn checkpoint_name(&self, height: Height) -> String {
        format!("{:016x}", height.get())
    }

    pub fn tip_path(&self) -> PathBuf {
        self.cp_manager.raw_path().join("tip")
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

fn parse_checkpoint_heights(names: &[String]) -> Result<Vec<Height>, LayoutError> {
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

fn is_dir_already_exists_err(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::AlreadyExists
        || err.raw_os_error() == Some(libc::ENOTEMPTY as i32)
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

    pub fn tombstone(&self) -> PathBuf {
        self.canister_root.join("tombstone")
    }

    /// Marks this canister as deleted by creating a 'tombstone' file in the
    /// canister directory.  Such directories will be excluded when a checkpoint
    /// is created.
    pub fn mark_deleted(&self) -> Result<(), LayoutError> {
        let path = self.tombstone();
        let _ = std::fs::File::create(&path).map_err(|err| LayoutError::IoError {
            path,
            message: "Failed to create a file".to_string(),
            io_err: err,
        })?;
        Ok(())
    }

    pub fn is_marked_deleted(&self) -> bool {
        Path::new(&self.tombstone()).exists()
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
            .write(&serialized)
            .map_err(|io_err| LayoutError::IoError {
                path: self.path.clone(),
                message: "failed to write serialized protobuf to disk".to_string(),
                io_err,
            })?;

        let file = writer.into_inner().map_err(|err| LayoutError::IoError {
            path: self.path.clone(),
            message: "failed to flush buffers to file".to_string(),
            io_err: std::io::Error::new(err.error().kind(), err.to_string()),
        })?;

        file.sync_all().map_err(|err| LayoutError::IoError {
            path: self.path.clone(),
            message: "failed to sync data to disk".to_string(),
            io_err: err,
        })
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
    pub fn deserialize(&self) -> Result<CanisterModule, LayoutError> {
        CanisterModule::new_from_file(self.path.clone()).map_err(|err| LayoutError::IoError {
            path: self.path.clone(),
            message: "Failed to read file contents".to_string(),
            io_err: err,
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
        Ok(Self {
            exported_globals: globals,
            heap_size: (value.heap_size as usize).into(),
            exports: value.exports.try_into()?,
            last_executed_round: value.last_executed_round.into(),
            metadata: try_from_option_field(value.metadata, "ExecutionStateBits::metadata")
                .unwrap_or_default(),
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
                other => {
                    return Err(ProxyDecodeError::ValueOutOfRange {
                        typ: "Network",
                        err: format!("Expected 0 or 1 (testnet), 2 (mainnet), got {}", other),
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

#[cfg(test)]
mod test {
    use super::*;

    use ic_ic00_types::IC_00;
    use ic_test_utilities::types::ids::canister_test_id;

    #[test]
    fn test_encode_decode_empty_controllers() {
        // A canister state with empty controllers.
        let canister_state_bits = CanisterStateBits {
            controllers: BTreeSet::new(),
            last_full_execution_round: ExecutionRound::from(0),
            call_context_manager: None,
            compute_allocation: ComputeAllocation::try_from(0).unwrap(),
            accumulated_priority: AccumulatedPriority::from(0),
            execution_state_bits: None,
            memory_allocation: MemoryAllocation::default(),
            freeze_threshold: NumSeconds::from(0),
            cycles_balance: Cycles::from(0),
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
        };

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

        // A canister state with empty controllers.
        let canister_state_bits = CanisterStateBits {
            controllers,
            last_full_execution_round: ExecutionRound::from(0),
            call_context_manager: None,
            compute_allocation: ComputeAllocation::try_from(0).unwrap(),
            accumulated_priority: AccumulatedPriority::from(0),
            execution_state_bits: None,
            memory_allocation: MemoryAllocation::default(),
            freeze_threshold: NumSeconds::from(0),
            cycles_balance: Cycles::from(0),
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
        };

        let pb_bits = pb_canister_state_bits::CanisterStateBits::from(canister_state_bits);
        let canister_state_bits = CanisterStateBits::try_from(pb_bits).unwrap();

        let mut expected_controllers = BTreeSet::new();
        expected_controllers.insert(canister_test_id(0).get());
        expected_controllers.insert(IC_00.into());
        assert_eq!(canister_state_bits.controllers, expected_controllers);
    }
}
