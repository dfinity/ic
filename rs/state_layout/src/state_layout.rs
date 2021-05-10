use crate::basic_cpmgr::BasicCheckpointManager;
use crate::error::LayoutError;

use ic_base_types::{NumBytes, NumSeconds};
use ic_logger::ReplicaLogger;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::{
        canister_state_bits::v1 as pb_canister_state_bits, queues::v1 as pb_queues,
        system_metadata::v1 as pb_metadata,
    },
};
use ic_replicated_state::{
    CallContextManager, CanisterStatus, CyclesAccount, ExportedFunctions, Global, NumWasmPages,
};
use ic_types::{
    funds::icp, nominal_cycles::NominalCycles, AccumulatedPriority, CanisterId, ComputeAllocation,
    ExecutionRound, Height, MemoryAllocation, PrincipalId, QueryAllocation, ICP,
};
use ic_wasm_types::BinaryEncodedWasm;
use std::convert::{From, TryFrom, TryInto};
use std::fs::OpenOptions;
use std::io::Write;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub trait CheckpointManager: Send + Sync {
    /// Returns the base directory path managed by checkpoint manager.
    fn raw_path(&self) -> &Path;

    /// Atomically creates a checkpoint from the "tip" directory.
    /// "name" identifies the name of the checkpoint to be created
    /// and it need not be a directory path.
    fn tip_to_checkpoint(&self, tip: &Path, name: &str) -> std::io::Result<PathBuf>;

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

    /// Atomically resets containts of "tip" directory to that of checkpoint
    fn reset_tip_to(&self, tip: &PathBuf, name: &str) -> std::io::Result<()>;
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
}

/// This struct contains bits of the `CanisterState` that are not already
/// covered somewhere else and are too small to be serialized separately.
#[derive(Debug)]
pub struct CanisterStateBits {
    pub controller: PrincipalId,
    pub last_full_execution_round: ExecutionRound,
    pub call_context_manager: Option<CallContextManager>,
    pub compute_allocation: ComputeAllocation,
    pub accumulated_priority: AccumulatedPriority,
    pub query_allocation: QueryAllocation,
    pub execution_state_bits: Option<ExecutionStateBits>,
    pub memory_allocation: Option<MemoryAllocation>,
    pub freeze_threshold: NumSeconds,
    pub cycles_account: CyclesAccount,
    pub icp_balance: ICP,
    pub status: CanisterStatus,
    pub scheduled_as_first: u64,
    pub skipped_round_due_to_no_messages: u64,
    pub executed: u64,
    pub interruped_during_execution: u64,
    pub certified_data: Vec<u8>,
    pub consumed_cycles_since_replica_started: NominalCycles,
    pub stable_memory_size: NumWasmPages,
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
    log: ReplicaLogger,
}

impl StateLayout {
    /// Needs to be pub for criterion performance regression tests.
    pub fn new(log: ReplicaLogger, root: PathBuf) -> Self {
        Self {
            cp_manager: Arc::new(BasicCheckpointManager::new(log.clone(), root)),
            log,
        }
    }

    /// Returns the the raw root path for state
    pub fn raw_path(&self) -> &Path {
        &self.cp_manager.raw_path()
    }

    /// Returns the path to the temporary directory.
    /// This directory is cleaned during restart of a node.
    pub fn tmp(&self) -> Result<PathBuf, LayoutError> {
        let tmp = self.cp_manager.raw_path().join("tmp");
        WriteOnly::check_dir(&tmp)?;
        Ok(tmp)
    }

    /// Returns a layout object representing tip state in "tip"
    /// directory. During round execution this directory may contain
    /// inconsistent state. During full checkpointing this directory contains
    /// full state and is converted to a checkpoint.
    /// This directory is cleaned during restart of a node and reset to
    /// last full checkpoint.
    pub fn tip(&self) -> Result<CheckpointLayout<RwPolicy>, LayoutError> {
        CheckpointLayout::new(self.tip_path(), Height::from(0))
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
        height: Height,
    ) -> Result<CheckpointLayout<ReadOnly>, LayoutError> {
        let cp_name = self.checkpoint_name(height);
        match self.cp_manager.tip_to_checkpoint(tip.raw_path(), &cp_name) {
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

    pub fn stable_memory_proto(&self) -> ProtoFileWith<pb_metadata::StableMemory, Permissions> {
        self.canister_root.join("stable_memory.pbuf").into()
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

        writer.flush().map_err(|err| LayoutError::IoError {
            path: self.path.clone(),
            message: "failed to flush data to disk".to_string(),
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

    fn deserialize_file(&self, mut f: std::fs::File) -> Result<T, LayoutError> {
        let mut buffer: Vec<u8> = Vec::new();
        use std::io::prelude::*;

        f.read_to_end(&mut buffer)
            .map_err(|io_err| LayoutError::IoError {
                path: self.path.clone(),
                message: "failed to read file".to_string(),
                io_err,
            })?;
        T::decode(buffer.as_slice()).map_err(|err| LayoutError::CorruptedLayout {
            path: self.path.clone(),
            message: format!(
                "failed to deserialize an object of type {} from protobuf: {}",
                std::any::type_name::<T>(),
                err
            ),
        })
    }

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

impl<T> WasmFile<T>
where
    T: ReadPolicy,
{
    pub fn deserialize(&self) -> Result<BinaryEncodedWasm, LayoutError> {
        Ok(
            BinaryEncodedWasm::new_from_file(self.path.clone()).map_err(|err| {
                LayoutError::IoError {
                    path: self.path.clone(),
                    message: "Failed to read file contents".to_string(),
                    io_err: err,
                }
            })?,
        )
    }
}

impl<T> WasmFile<T>
where
    T: WritePolicy,
{
    pub fn serialize(&self, wasm: &BinaryEncodedWasm) -> Result<(), LayoutError> {
        if wasm.file().is_none() {
            // Canister was installed/upgraded. Persist the new
            // wasm binary
            let mut file = open_for_write(&self.path)?;
            file.write_all(wasm.as_slice())
                .and_then(|_| file.flush())
                .map_err(|err| LayoutError::IoError {
                    path: self.path.clone(),
                    message: "Failed to write wasm binary to file".to_string(),
                    io_err: err,
                })?;

            file.flush().map_err(|err| LayoutError::IoError {
                path: self.path.clone(),
                message: "failed to flush wasm binary to disk".to_string(),
                io_err: err,
            })
        } else {
            // No need to persist as existing wasm binary was used and
            // it did not change since last checkpoint
            Ok(())
        }
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
            controller: Some(item.controller.into()),
            last_full_execution_round: item.last_full_execution_round.get(),
            call_context_manager: item.call_context_manager.as_ref().map(|v| v.into()),
            compute_allocation: item.compute_allocation.as_percent(),
            accumulated_priority: item.accumulated_priority.value(),
            query_allocation: item.query_allocation.get(),
            execution_state_bits: item.execution_state_bits.as_ref().map(|v| v.into()),
            // Per the public spec, a memory allocation of zero = no memory allocation set.
            memory_allocation: match item.memory_allocation {
                Some(memory_allocation) => memory_allocation.get().get(),
                None => 0,
            },
            freeze_threshold: item.freeze_threshold.get(),
            cycles_account: Some((&item.cycles_account).into()),
            icp_balance: item.icp_balance.balance(),
            canister_status: Some((&item.status).into()),
            scheduled_as_first: item.scheduled_as_first,
            skipped_round_due_to_no_messages: item.skipped_round_due_to_no_messages,
            executed: item.executed,
            interruped_during_execution: item.interruped_during_execution,
            certified_data: item.certified_data.clone(),
            consumed_cycles_since_replica_started: Some(
                (&item.consumed_cycles_since_replica_started).into(),
            ),
            stable_memory_size: item.stable_memory_size.get(),
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

        Ok(Self {
            controller: try_from_option_field(value.controller, "CanisterStateBits::controller")?,
            last_full_execution_round: value.last_full_execution_round.into(),
            call_context_manager,
            compute_allocation: ComputeAllocation::try_from(value.compute_allocation).map_err(
                |e| ProxyDecodeError::ValueOutOfRange {
                    typ: "ComputeAllocation",
                    err: format!("{:?}", e),
                },
            )?,
            accumulated_priority: value.accumulated_priority.into(),
            query_allocation: QueryAllocation::try_from(value.query_allocation).map_err(|e| {
                ProxyDecodeError::ValueOutOfRange {
                    typ: "QueryAllocation",
                    err: format!("{:?}", e),
                }
            })?,
            execution_state_bits,
            // Per the public spec, a memory allocation of zero = no memory allocation set.
            memory_allocation: if value.memory_allocation == 0 {
                None
            } else {
                Some(
                    MemoryAllocation::try_from(NumBytes::from(value.memory_allocation)).map_err(
                        |e| ProxyDecodeError::ValueOutOfRange {
                            typ: "MemoryAllocation",
                            err: format!("{:?}", e),
                        },
                    )?,
                )
            },
            freeze_threshold: NumSeconds::from(value.freeze_threshold),
            cycles_account: try_from_option_field(
                value.cycles_account,
                "CanisterStateBits::cycles_account",
            )?,
            icp_balance: icp::Tap::mint(value.icp_balance),
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
            stable_memory_size: NumWasmPages::from(value.stable_memory_size),
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
            heap_size: item.heap_size.get(),
            exports: (&item.exports).into(),
            last_executed_round: item.last_executed_round.get(),
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
            heap_size: value.heap_size.into(),
            exports: value.exports.try_into()?,
            last_executed_round: value.last_executed_round.into(),
        })
    }
}
