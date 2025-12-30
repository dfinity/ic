use crate::{
    CanisterState, NumWasmPages, PageMap,
    canister_state::{
        WASM_PAGE_SIZE_IN_BYTES,
        execution_state::{Memory, WasmExecutionMode},
        system_state::wasm_chunk_store::{self, ValidatedChunk, WasmChunkStore},
    },
    page_map::{Buffer, PageAllocatorFileDescriptor, PersistenceError},
};
use ic_config::embedders::{MAX_GLOBALS, WASM_MAX_SIZE};
use ic_management_canister_types_private::{
    Global, GlobalTimer, OnLowWasmMemoryHookStatus, SnapshotSource,
    UploadCanisterSnapshotMetadataArgs,
};
use ic_sys::PAGE_SIZE;
use ic_types::{
    CanisterId, CanisterTimer, MAX_STABLE_MEMORY_IN_BYTES, MAX_WASM_MEMORY_IN_BYTES,
    MAX_WASM64_MEMORY_IN_BYTES, NumBytes, PrincipalId, SnapshotId, Time,
};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use ic_wasm_types::CanisterModule;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// A collection of canister snapshots and their IDs.
///
/// Additionally, keeps track of all the accumulated changes
/// since the last flush to the disk.
#[derive(Clone, Eq, PartialEq, Debug, Default, ValidateEq)]
pub struct CanisterSnapshots {
    #[validate_eq(CompareWithValidateEq)]
    snapshots: BTreeMap<SnapshotId, Arc<CanisterSnapshot>>,
    /// The set of snapshots ids grouped by canisters.
    snapshot_ids: BTreeMap<CanisterId, BTreeSet<SnapshotId>>,
    /// Memory usage of all canister snapshots in bytes.
    ///
    /// This field is updated whenever a snapshot is added or removed and
    /// is used to report the memory usage of all canister snapshots in
    /// the subnet.
    memory_usage: NumBytes,
}

impl CanisterSnapshots {
    pub fn new(snapshots: BTreeMap<SnapshotId, Arc<CanisterSnapshot>>) -> Self {
        let mut snapshot_ids = BTreeMap::default();
        let mut memory_usage = NumBytes::from(0);
        for (snapshot_id, snapshot) in snapshots.iter() {
            let canister_id = snapshot_id.get_canister_id();
            let canister_snapshot_ids: &mut BTreeSet<SnapshotId> =
                snapshot_ids.entry(canister_id).or_default();
            canister_snapshot_ids.insert(*snapshot_id);
            memory_usage += snapshot.size();
        }
        Self {
            snapshots,
            snapshot_ids,
            memory_usage,
        }
    }

    /// Inserts a chunk into a snaphot's chunk store and updates its `size` and
    /// the `CanisterSnapshots`' `memory_usage` by the maximum chunk size.
    /// Returns an error if the given snapshot ID could not be found. In this case,
    /// the method has no effect.
    #[allow(clippy::result_unit_err)]
    pub fn insert_chunk(
        &mut self,
        snapshot_id: SnapshotId,
        validated_chunk: ValidatedChunk,
    ) -> Result<(), ()> {
        let snapshot = self.get_mut(snapshot_id).ok_or(())?;
        let snapshot_inner = Arc::make_mut(snapshot);
        snapshot_inner
            .chunk_store_mut()
            .insert_chunk(validated_chunk);
        // use the maximum chunk size
        let amount = wasm_chunk_store::chunk_size();
        snapshot_inner.size += amount;
        self.memory_usage += amount;
        Ok(())
    }

    /// Adds new snapshot in the collection and assigns a `SnapshotId`.
    ///
    /// External callers should call `ReplicatedState::take_snapshot` instead.
    pub(crate) fn push(
        &mut self,
        snapshot_id: SnapshotId,
        snapshot: Arc<CanisterSnapshot>,
    ) -> SnapshotId {
        let canister_id = snapshot.canister_id();
        self.memory_usage += snapshot.size();
        self.snapshots.insert(snapshot_id, snapshot);
        let snapshot_ids = self.snapshot_ids.entry(canister_id).or_default();
        snapshot_ids.insert(snapshot_id);
        snapshot_id
    }

    /// Returns a reference of the canister snapshot identified by `snapshot_id`.
    pub fn get(&self, snapshot_id: SnapshotId) -> Option<&Arc<CanisterSnapshot>> {
        self.snapshots.get(&snapshot_id)
    }

    /// Returns a mutable reference of the canister snapshot identified by `snapshot_id`.
    pub fn get_mut(&mut self, snapshot_id: SnapshotId) -> Option<&mut Arc<CanisterSnapshot>> {
        self.snapshots.get_mut(&snapshot_id)
    }

    /// Iterate over all snapshots.
    pub fn iter(&self) -> impl Iterator<Item = (&SnapshotId, &Arc<CanisterSnapshot>)> {
        self.snapshots.iter()
    }

    /// Mutably iterate over all snapshots.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&SnapshotId, &mut Arc<CanisterSnapshot>)> {
        self.snapshots.iter_mut()
    }

    /// Remove snapshot identified by `snapshot_id` from the collection of snapshots.
    pub fn remove(&mut self, snapshot_id: SnapshotId) -> Option<Arc<CanisterSnapshot>> {
        let removed_snapshot = self.snapshots.remove(&snapshot_id);
        match removed_snapshot {
            Some(snapshot) => {
                let canister_id = snapshot.canister_id();

                // The snapshot ID if present in the `self.snapshots`,
                // must also be present in the `self.snapshot_ids`.
                debug_assert!(self.snapshot_ids.contains_key(&canister_id));
                let snapshot_ids = self.snapshot_ids.get_mut(&canister_id).unwrap();
                debug_assert!(snapshot_ids.contains(&snapshot_id));
                snapshot_ids.remove(&snapshot_id);
                if snapshot_ids.is_empty() {
                    self.snapshot_ids.remove(&canister_id);
                }
                self.memory_usage -= snapshot.size();

                Some(snapshot)
            }
            None => {
                // No snapshot found based on the snapshot ID provided.
                None
            }
        }
    }

    /// Remove all snapshots identified by `canister_id` from the collections of snapshots.
    /// Returns the list of deleted snapshots.
    pub fn delete_snapshots(&mut self, canister_id: CanisterId) -> Vec<SnapshotId> {
        let mut result = Vec::default();
        if let Some(snapshot_ids) = self.snapshot_ids.get(&canister_id).cloned() {
            for snapshot_id in snapshot_ids {
                let removed = self.remove(snapshot_id);
                if removed.is_some() {
                    result.push(snapshot_id)
                }
            }
        }
        result
    }

    /// Selects the snapshots associated with the provided canister ID.
    /// Returns a list of tuples containing the ID and the canister snapshot.
    pub fn list_snapshots(
        &self,
        canister_id: CanisterId,
    ) -> Vec<(SnapshotId, Arc<CanisterSnapshot>)> {
        let mut snapshots = vec![];

        if let Some(snapshot_ids) = self.snapshot_ids.get(&canister_id) {
            for snapshot_id in snapshot_ids {
                // The snapshot ID if present in the `self.snapshot_ids`,
                // must also be present in the `self.snapshot`.
                let snapshot = self.snapshots.get(snapshot_id).unwrap();
                snapshots.push((*snapshot_id, snapshot.clone()))
            }
        }
        snapshots
    }

    /// Returns the number of snapshots stored for the given canister id.
    pub fn count_by_canister(&self, canister_id: &CanisterId) -> usize {
        match self.snapshot_ids.get(canister_id) {
            Some(snapshot_ids) => snapshot_ids.len(),
            None => 0,
        }
    }

    /// Returns the total number of snapshots stored in the replicated state.
    pub fn count(&self) -> usize {
        self.snapshots.len()
    }

    /// Computes the total memory usage of all of the specified canister's snapshots.
    ///
    /// Used for testing that `SystemState::snapshots_memory_usage` is updated as needed
    /// whenever taking or deleting a snapshot.
    #[doc(hidden)]
    pub fn compute_memory_usage_by_canister(&self, canister_id: CanisterId) -> NumBytes {
        let mut memory_size = NumBytes::new(0);
        if let Some(snapshot_ids) = self.snapshot_ids.get(&canister_id) {
            for snapshot_id in snapshot_ids {
                debug_assert!(self.snapshots.contains_key(snapshot_id));
                memory_size += self.snapshots.get(snapshot_id).unwrap().size();
            }
        }
        memory_size
    }

    /// Returns true if snapshot ID can be found in the collection.
    pub fn contains(&self, snapshot_id: &SnapshotId) -> bool {
        self.snapshots.contains_key(snapshot_id)
    }

    /// Splits the `CanisterSnapshots` as part of subnet splitting phase 1.
    ///
    /// A subnet split starts with a subnet A and results in two subnets, A' and B.
    /// For the sake of clarity, comments refer to the two resulting subnets as
    /// *subnet A'* and *subnet B*. And to the original subnet as *subnet A*.
    ///
    /// Splitting the canister snapshot is decided based on the new canister list
    /// hosted by the *subnet A'* or *subnet B*.
    /// A snapshot associated with a canister not hosted by the local subnet
    /// will be discarded.
    ///
    /// Returns the list of deleted snapshots.
    pub(crate) fn split<F>(&mut self, is_local_canister: F) -> Vec<SnapshotId>
    where
        F: Fn(CanisterId) -> bool,
    {
        let mut result = Vec::default();
        let old_snapshot_ids = self.snapshots.keys().cloned().collect::<Vec<_>>();
        for snapshot_id in old_snapshot_ids {
            // Unwrapping is safe here because `snapshot_id` is part of the keys collection.
            let snapshot = self.snapshots.get(&snapshot_id).unwrap();
            let canister_id = snapshot.canister_id;
            if !is_local_canister(canister_id) {
                let removed = self.remove(snapshot_id);
                if removed.is_some() {
                    result.push(snapshot_id)
                }
            }
        }

        // Destructure `self`, in order for the compiler to enforce explicit
        // decisions whenever new fields are added.
        let CanisterSnapshots {
            snapshots: _,
            snapshot_ids: _,
            memory_usage: _,
        } = self;

        result
    }

    /// Returns the amount of memory taken by all canister snapshots on
    /// this subnet.
    pub fn memory_taken(&self) -> NumBytes {
        // The running sum of the memory usage of all canister snapshots should
        // be the same as the one computed by iterating over all snapshots.
        debug_assert_eq!(
            self.snapshots
                .values()
                .map(|snapshot| snapshot.size())
                .sum::<NumBytes>(),
            self.memory_usage
        );

        self.memory_usage
    }
}

#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
pub struct PageMemory {
    /// The contents of this memory.
    #[validate_eq(Ignore)]
    pub page_map: PageMap,
    /// The size of the memory in wasm pages. This does not indicate how much
    /// data is stored in the `page_map`, only the number of pages the memory
    /// has access to.
    pub size: NumWasmPages,
}

impl From<&Memory> for PageMemory {
    fn from(memory: &Memory) -> Self {
        Self {
            page_map: memory.page_map.clone(),
            size: memory.size,
        }
    }
}

impl From<&PageMemory> for Memory {
    fn from(pg_memory: &PageMemory) -> Self {
        Memory::new(pg_memory.page_map.clone(), pg_memory.size)
    }
}

impl TryFrom<(&PageMemory, Arc<dyn PageAllocatorFileDescriptor>)> for Memory {
    type Error = PersistenceError;

    fn try_from(
        (pg_memory, fd_factory): (&PageMemory, Arc<dyn PageAllocatorFileDescriptor>),
    ) -> Result<Self, PersistenceError> {
        let new_page_map = pg_memory.page_map.clean_copy(fd_factory)?;
        Ok(Memory::new(new_page_map, pg_memory.size))
    }
}

/// Contains all information related to a canister's execution state.
#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
pub struct ExecutionStateSnapshot {
    /// The raw canister module.
    #[validate_eq(Ignore)]
    pub wasm_binary: CanisterModule,
    /// The Wasm global variables.
    /// Note: The hypervisor instrumentations exports all global variables,
    /// including originally internal global variables.
    #[validate_eq(Ignore)]
    pub exported_globals: Vec<Global>,
    /// Snapshot of stable memory.
    #[validate_eq(CompareWithValidateEq)]
    pub stable_memory: PageMemory,
    /// Snapshot of wasm memory.
    #[validate_eq(CompareWithValidateEq)]
    pub wasm_memory: PageMemory,
    /// Status of global timer
    pub global_timer: Option<CanisterTimer>,
    /// Whether the hook is inactive, ready or executed.
    pub on_low_wasm_memory_hook_status: Option<OnLowWasmMemoryHookStatus>,
}

/// Contains all information related to a canister snapshot.
#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
pub struct CanisterSnapshot {
    /// Identifies the canister to which this snapshot belongs.
    canister_id: CanisterId,
    /// Whether this snapshot was created from the canister or uploaded manually.
    source: SnapshotSource,
    /// The timestamp indicating the moment the snapshot was captured.
    taken_at_timestamp: Time,
    /// The canister version at the time of taking the snapshot.
    canister_version: u64,
    /// Amount of memory used by a snapshot in bytes.
    size: NumBytes,
    /// The certified data blob belonging to the canister.
    certified_data: Vec<u8>,
    /// Snapshot of chunked store.
    #[validate_eq(CompareWithValidateEq)]
    chunk_store: WasmChunkStore,
    #[validate_eq(CompareWithValidateEq)]
    execution_snapshot: ExecutionStateSnapshot,
}

impl CanisterSnapshot {
    pub fn new(
        canister_id: CanisterId,
        source: SnapshotSource,
        taken_at_timestamp: Time,
        canister_version: u64,
        certified_data: Vec<u8>,
        chunk_store: WasmChunkStore,
        execution_snapshot: ExecutionStateSnapshot,
        size: NumBytes,
    ) -> CanisterSnapshot {
        Self {
            canister_id,
            source,
            taken_at_timestamp,
            canister_version,
            certified_data,
            chunk_store,
            execution_snapshot,
            size,
        }
    }

    /// Creates a snapshot from a canister.
    ///
    /// This method fails early, before any expensive computations are
    /// performed. If that changes, the instructions used in this method
    /// have to be accounted for in the caller.
    pub fn from_canister(
        canister: &CanisterState,
        taken_at_timestamp: Time,
    ) -> Result<Self, CanisterSnapshotError> {
        let canister_id = canister.canister_id();

        let execution_state = canister
            .execution_state
            .as_ref()
            .ok_or(CanisterSnapshotError::EmptyExecutionState(canister_id))?;
        let global_timer = canister.system_state.global_timer;
        let hook_status = canister.system_state.task_queue.peek_hook_status();
        let execution_snapshot = ExecutionStateSnapshot {
            wasm_binary: execution_state.wasm_binary.binary.clone(),
            exported_globals: execution_state.exported_globals.clone(),
            stable_memory: PageMemory::from(&execution_state.stable_memory),
            wasm_memory: PageMemory::from(&execution_state.wasm_memory),
            global_timer: Some(global_timer),
            on_low_wasm_memory_hook_status: Some(hook_status),
        };

        Ok(CanisterSnapshot {
            canister_id,
            source: SnapshotSource::taken_from_canister(),
            taken_at_timestamp,
            canister_version: canister.system_state.canister_version,
            certified_data: canister.system_state.certified_data.clone(),
            chunk_store: canister.system_state.wasm_chunk_store.clone(),
            execution_snapshot,
            size: canister.snapshot_size_bytes(),
        })
    }

    pub fn from_metadata(
        metadata: &ValidatedSnapshotMetadata,
        taken_at_timestamp: Time,
        canister_version: u64,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    ) -> Self {
        let stable_memory = PageMemory {
            page_map: PageMap::new(Arc::clone(&fd_factory)),
            size: metadata.stable_memory_size,
        };
        let wasm_memory = PageMemory {
            page_map: PageMap::new(Arc::clone(&fd_factory)),
            size: metadata.wasm_memory_size,
        };
        // A snapshot also contains the instruction counter as the last global
        // (because it is *appended* during WASM instrumentation).
        // We push a default value for that last global of type `i64`
        // (which is merely an implementation detail)
        // to the list of globals provided by the user
        // (who is not expected to care about that implementation detail).
        let mut globals_and_instruction_counter = metadata.exported_globals.clone();
        globals_and_instruction_counter.push(Global::I64(0));
        let execution_snapshot = ExecutionStateSnapshot {
            // This is an invalid module now, but will be written to via `upload_canister_snapshot_data`.
            wasm_binary: CanisterModule::new(vec![0; metadata.wasm_module_size.get() as usize]),
            exported_globals: globals_and_instruction_counter,
            stable_memory,
            wasm_memory,
            global_timer: metadata.global_timer.map(CanisterTimer::from),
            on_low_wasm_memory_hook_status: metadata.on_low_wasm_memory_hook_status,
        };
        let chunk_store = WasmChunkStore::new(Arc::clone(&fd_factory));
        Self {
            canister_id: CanisterId::try_from(metadata.canister_id).unwrap(),
            source: SnapshotSource::metadata_upload(),
            taken_at_timestamp,
            canister_version,
            size: metadata.snapshot_size_bytes(),
            certified_data: metadata.certified_data.clone(),
            chunk_store,
            execution_snapshot,
        }
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    pub fn source(&self) -> SnapshotSource {
        self.source
    }

    pub fn canister_version(&self) -> u64 {
        self.canister_version
    }

    pub fn taken_at_timestamp(&self) -> &Time {
        &self.taken_at_timestamp
    }

    pub fn size(&self) -> NumBytes {
        self.size
    }

    pub fn execution_snapshot(&self) -> &ExecutionStateSnapshot {
        &self.execution_snapshot
    }

    pub fn stable_memory(&self) -> &PageMemory {
        &self.execution_snapshot.stable_memory
    }

    pub fn stable_memory_mut(&mut self) -> &mut PageMemory {
        &mut self.execution_snapshot.stable_memory
    }

    pub fn wasm_memory(&self) -> &PageMemory {
        &self.execution_snapshot.wasm_memory
    }

    pub fn wasm_memory_mut(&mut self) -> &mut PageMemory {
        &mut self.execution_snapshot.wasm_memory
    }

    pub fn canister_module(&self) -> &CanisterModule {
        &self.execution_snapshot.wasm_binary
    }

    pub fn exported_globals(&self) -> &Vec<Global> {
        &self.execution_snapshot.exported_globals
    }

    pub fn chunk_store(&self) -> &WasmChunkStore {
        &self.chunk_store
    }

    pub fn certified_data(&self) -> &Vec<u8> {
        &self.certified_data
    }

    pub fn chunk_store_mut(&mut self) -> &mut WasmChunkStore {
        &mut self.chunk_store
    }

    pub fn execution_snapshot_mut(&mut self) -> &mut ExecutionStateSnapshot {
        &mut self.execution_snapshot
    }

    /// Returns the heap delta produced by this snapshot.
    ///
    /// The heap delta includes the delta of the wasm memory, stable memory and
    /// the chunk store, i.e. the snapshot parts that are backed by `PageMap`s.
    pub fn heap_delta(&self) -> NumBytes {
        let delta_pages = self
            .execution_snapshot
            .wasm_memory
            .page_map
            .num_delta_pages()
            + self
                .execution_snapshot
                .stable_memory
                .page_map
                .num_delta_pages();
        NumBytes::from((delta_pages * PAGE_SIZE) as u64) + self.chunk_store.heap_delta()
    }

    pub fn get_wasm_module_chunk(
        &self,
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>, CanisterSnapshotError> {
        let module_bytes = self.execution_snapshot.wasm_binary.as_slice();
        let end = offset.saturating_add(size);
        if end > module_bytes.len() as u64 {
            return Err(CanisterSnapshotError::InvalidSubslice { offset, size });
        }
        Ok(module_bytes[(offset as usize)..(end as usize)].to_vec())
    }

    /// Get a user-defined chunk of the (stable/main) memory represented by `page_map`.
    /// Returns an error if offset + size exceed the page_map's current size.
    pub fn get_memory_chunk(
        page_memory: PageMemory,
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>, CanisterSnapshotError> {
        let page_map_size_bytes = (page_memory.size.get() * WASM_PAGE_SIZE_IN_BYTES) as u64;
        if offset.saturating_add(size) > page_map_size_bytes {
            return Err(CanisterSnapshotError::InvalidSubslice { offset, size });
        }
        let memory_buffer = Buffer::new(page_memory.page_map);
        let mut dst = vec![0; size as usize];
        memory_buffer.read(&mut dst, offset as usize);
        Ok(dst)
    }
}

/// Errors that can occur when trying to create a `CanisterSnapshot` from a canister.
#[derive(Debug)]
pub enum CanisterSnapshotError {
    /// The canister is missing the execution state because it's empty (newly created or uninstalled).
    EmptyExecutionState(CanisterId),
    /// Offset and size exceed module or memory bounds.
    InvalidSubslice { offset: u64, size: u64 },
    /// Metadata is invalid.
    InvalidMetadata { reason: String },
}

#[derive(Clone, Debug)]
pub struct ValidatedSnapshotMetadata {
    canister_id: PrincipalId,
    replace_snapshot: Option<SnapshotId>,
    wasm_module_size: NumBytes,
    exported_globals: Vec<Global>,
    wasm_memory_size: NumWasmPages,
    stable_memory_size: NumWasmPages,
    certified_data: Vec<u8>,
    global_timer: Option<GlobalTimer>,
    on_low_wasm_memory_hook_status: Option<OnLowWasmMemoryHookStatus>,
}

impl ValidatedSnapshotMetadata {
    pub fn validate(
        raw: UploadCanisterSnapshotMetadataArgs,
        wasm_mode: WasmExecutionMode,
    ) -> Result<Self, MetadataValidationError> {
        if raw.wasm_module_size == 0 {
            return Err(MetadataValidationError::WasmModuleEmpty);
        }
        if raw.wasm_module_size > WASM_MAX_SIZE.get() {
            return Err(MetadataValidationError::WasmModuleTooLarge);
        }
        if !(raw.wasm_memory_size as usize).is_multiple_of(WASM_PAGE_SIZE_IN_BYTES) {
            return Err(MetadataValidationError::WasmMemoryNotPageAligned);
        }
        match wasm_mode {
            WasmExecutionMode::Wasm32 => {
                if raw.wasm_memory_size > MAX_WASM_MEMORY_IN_BYTES {
                    return Err(MetadataValidationError::WasmMemoryTooLarge);
                }
            }
            WasmExecutionMode::Wasm64 => {
                if raw.wasm_memory_size > MAX_WASM64_MEMORY_IN_BYTES {
                    return Err(MetadataValidationError::WasmMemoryTooLarge);
                }
            }
        }
        if !(raw.stable_memory_size as usize).is_multiple_of(WASM_PAGE_SIZE_IN_BYTES) {
            return Err(MetadataValidationError::StableMemoryNotPageAligned);
        }
        if raw.stable_memory_size > MAX_STABLE_MEMORY_IN_BYTES {
            return Err(MetadataValidationError::StableMemoryTooLarge);
        }
        if raw.globals.len() > MAX_GLOBALS {
            return Err(MetadataValidationError::ExportedGlobalsTooLarge);
        }
        // a 32 byte hash
        if raw.certified_data.len() > 32 {
            return Err(MetadataValidationError::CertifiedDataTooLarge);
        }

        Ok(Self {
            canister_id: raw.canister_id,
            replace_snapshot: raw.replace_snapshot,
            wasm_module_size: NumBytes::new(raw.wasm_module_size),
            exported_globals: raw.globals,
            wasm_memory_size: NumWasmPages::new(
                raw.wasm_memory_size as usize / WASM_PAGE_SIZE_IN_BYTES,
            ),
            stable_memory_size: NumWasmPages::new(
                raw.stable_memory_size as usize / WASM_PAGE_SIZE_IN_BYTES,
            ),
            certified_data: raw.certified_data,
            global_timer: raw.global_timer,
            on_low_wasm_memory_hook_status: raw.on_low_wasm_memory_hook_status,
        })
    }

    /// Returns the size of this snapshot, excluding the size of the wasm chunk store.
    pub fn snapshot_size_bytes(&self) -> NumBytes {
        let num_bytes = self.wasm_module_size.get()
            + (self.wasm_memory_size.get() * WASM_PAGE_SIZE_IN_BYTES) as u64
            + (self.stable_memory_size.get() * WASM_PAGE_SIZE_IN_BYTES) as u64
            + self.certified_data.len() as u64
            + self.exported_globals.len() as u64 * size_of::<Global>() as u64;
        NumBytes::new(num_bytes)
    }

    pub fn canister_id(&self) -> PrincipalId {
        self.canister_id
    }

    pub fn replace_snapshot(&self) -> Option<SnapshotId> {
        self.replace_snapshot
    }

    pub fn wasm_module_size(&self) -> NumBytes {
        self.wasm_module_size
    }

    pub fn exported_globals(&self) -> &Vec<Global> {
        &self.exported_globals
    }

    pub fn wasm_memory_size(&self) -> NumWasmPages {
        self.wasm_memory_size
    }

    pub fn stable_memory_size(&self) -> NumWasmPages {
        self.stable_memory_size
    }

    pub fn certified_data(&self) -> &Vec<u8> {
        &self.certified_data
    }

    pub fn global_timer(&self) -> Option<GlobalTimer> {
        self.global_timer
    }

    pub fn on_low_wasm_memory_hook_status(&self) -> Option<OnLowWasmMemoryHookStatus> {
        self.on_low_wasm_memory_hook_status
    }
}

#[derive(Debug, Copy, Clone)]
pub enum MetadataValidationError {
    WasmModuleEmpty,
    WasmModuleTooLarge,
    WasmMemoryNotPageAligned,
    WasmMemoryTooLarge,
    StableMemoryNotPageAligned,
    StableMemoryTooLarge,
    ExportedGlobalsTooLarge,
    CertifiedDataTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{CanisterSnapshot, CanisterSnapshots, PageMap};
    use ic_test_utilities_types::ids::canister_test_id;
    use ic_types::NumBytes;
    use ic_types::time::UNIX_EPOCH;
    use maplit::{btreemap, btreeset};

    fn fake_canister_snapshot(
        canister_id: CanisterId,
        local_id: u64,
    ) -> (SnapshotId, CanisterSnapshot) {
        let execution_snapshot = ExecutionStateSnapshot {
            wasm_binary: CanisterModule::new(vec![1, 2, 3]),
            exported_globals: vec![Global::I32(1), Global::I64(2), Global::F64(0.1)],
            stable_memory: PageMemory {
                page_map: PageMap::new_for_testing(),
                size: NumWasmPages::new(10),
            },
            wasm_memory: PageMemory {
                page_map: PageMap::new_for_testing(),
                size: NumWasmPages::new(10),
            },
            global_timer: Some(CanisterTimer::Inactive),
            on_low_wasm_memory_hook_status: Some(OnLowWasmMemoryHookStatus::ConditionNotSatisfied),
        };
        let snapshot = CanisterSnapshot::new(
            canister_id,
            SnapshotSource::taken_from_canister(),
            UNIX_EPOCH,
            0,
            vec![],
            WasmChunkStore::new_for_testing(),
            execution_snapshot,
            NumBytes::from(0),
        );

        let snapshot_id = SnapshotId::from((canister_id, local_id));

        (snapshot_id, snapshot)
    }

    #[test]
    fn test_push_and_remove_snapshot() {
        let canister_id = canister_test_id(0);
        let (snapshot_id, snapshot) = fake_canister_snapshot(canister_id, 1);
        let mut snapshot_manager = CanisterSnapshots::default();
        assert_eq!(snapshot_manager.snapshots.len(), 0);
        assert_eq!(snapshot_manager.snapshot_ids.len(), 0);

        snapshot_manager.push(snapshot_id, Arc::<CanisterSnapshot>::new(snapshot));
        assert_eq!(snapshot_manager.snapshots.len(), 1);
        assert_eq!(snapshot_manager.snapshot_ids.len(), 1);
        assert_eq!(
            snapshot_manager
                .snapshot_ids
                .get(&canister_id)
                .unwrap()
                .len(),
            1
        );

        assert_eq!(snapshot_manager.snapshots.len(), 1);

        snapshot_manager.remove(snapshot_id);
        assert_eq!(snapshot_manager.snapshots.len(), 0);
        assert_eq!(snapshot_manager.snapshot_ids.len(), 0);
        assert_eq!(snapshot_manager.snapshot_ids.get(&canister_id), None);
    }

    #[test]
    fn test_construct_canister_snapshot_ids() {
        let snapshots: BTreeMap<_, _> = [
            fake_canister_snapshot(canister_test_id(0), 1),
            fake_canister_snapshot(canister_test_id(0), 2),
            fake_canister_snapshot(canister_test_id(1), 0),
        ]
        .into_iter()
        .map(|(i, s)| (i, Arc::new(s)))
        .collect();
        let snapshot_manager = CanisterSnapshots::new(snapshots);

        let expected_snapshot_ids = btreemap! {
            canister_test_id(0) => btreeset!{
                SnapshotId::from((canister_test_id(0), 1)), SnapshotId::from((canister_test_id(0), 2))
            },
            canister_test_id(1) =>  btreeset!{
                SnapshotId::from((canister_test_id(1), 0))
            },
        };

        assert_eq!(snapshot_manager.snapshot_ids, expected_snapshot_ids);
    }

    #[test]
    fn test_memory_usage_correctly_updated_while_adding_and_removing_snapshots() {
        let canister_id = canister_test_id(0);
        let (first_snapshot_id, first_snapshot) = fake_canister_snapshot(canister_id, 1);
        let snapshot1_size = first_snapshot.size();
        let mut snapshots = BTreeMap::new();
        snapshots.insert(
            first_snapshot_id,
            Arc::<CanisterSnapshot>::new(first_snapshot),
        );
        let mut snapshot_manager = CanisterSnapshots::new(snapshots);
        assert_eq!(snapshot_manager.snapshots.len(), 1);
        assert_eq!(snapshot_manager.snapshot_ids.len(), 1);
        assert_eq!(
            snapshot_manager.memory_taken(),
            NumBytes::from(snapshot1_size)
        );
        assert_eq!(
            snapshot_manager.compute_memory_usage_by_canister(canister_id),
            NumBytes::from(snapshot1_size)
        );

        let other_canister_id = canister_test_id(1);
        let (second_snapshot_id, second_snapshot) = fake_canister_snapshot(other_canister_id, 2);
        assert_eq!(
            snapshot_manager.compute_memory_usage_by_canister(other_canister_id),
            NumBytes::from(0)
        );

        // Pushing another snapshot updates the `memory_usage`.
        let snapshot2_size = second_snapshot.size();
        snapshot_manager.push(
            second_snapshot_id,
            Arc::<CanisterSnapshot>::new(second_snapshot),
        );
        assert_eq!(
            snapshot_manager.memory_taken(),
            NumBytes::from(snapshot1_size + snapshot2_size)
        );
        assert_eq!(
            snapshot_manager.compute_memory_usage_by_canister(other_canister_id),
            NumBytes::from(snapshot2_size)
        );

        // Deleting a snapshot updates the `memory_usage`.
        snapshot_manager.remove(first_snapshot_id);
        assert_eq!(
            snapshot_manager.memory_taken(),
            NumBytes::from(snapshot2_size)
        );
        assert_eq!(
            snapshot_manager.compute_memory_usage_by_canister(canister_id),
            NumBytes::from(0)
        );

        // Deleting the second snapshot brings us back to 0 memory taken.
        snapshot_manager.remove(second_snapshot_id);
        assert_eq!(snapshot_manager.memory_taken(), NumBytes::from(0));
        assert_eq!(
            snapshot_manager.compute_memory_usage_by_canister(other_canister_id),
            NumBytes::from(0)
        );
    }
}
