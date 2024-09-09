use crate::{
    canister_state::execution_state::{Global, Memory},
    canister_state::system_state::wasm_chunk_store::WasmChunkStore,
    CanisterState, NumWasmPages, PageMap,
};
use ic_sys::PAGE_SIZE;
use ic_types::{CanisterId, NumBytes, SnapshotId, Time};
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
    /// Snapshot operations are consumed by the `StateManager` in order to
    /// correctly represent backups and restores in the next checkpoint.
    unflushed_changes: Vec<SnapshotOperation>,
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
            unflushed_changes: vec![],
            snapshot_ids,
            memory_usage,
        }
    }

    /// Adds new snapshot in the collection and assigns a `SnapshotId`.
    ///
    /// Additionally, adds a new item to the `unflushed_changes`
    /// which represents the new backup accumulated since the last flush to the disk.
    pub fn push(&mut self, snapshot_id: SnapshotId, snapshot: Arc<CanisterSnapshot>) -> SnapshotId {
        let canister_id = snapshot.canister_id();
        self.unflushed_changes
            .push(SnapshotOperation::Backup(canister_id, snapshot_id));
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
    ///
    /// Additionally, adds a new item to the `unflushed_changes`
    /// which represents the deleted backup since the last flush to the disk.
    pub fn remove(&mut self, snapshot_id: SnapshotId) -> Option<Arc<CanisterSnapshot>> {
        let removed_snapshot = self.snapshots.remove(&snapshot_id);
        match removed_snapshot {
            Some(snapshot) => {
                self.unflushed_changes
                    .push(SnapshotOperation::Delete(snapshot_id));
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
    ///
    /// Additionally, new items are added to the `unflushed_changes`,
    /// representing the deleted backups since the last flush to the disk.
    pub fn delete_snapshots(&mut self, canister_id: CanisterId) {
        if let Some(snapshot_ids) = self.snapshot_ids.remove(&canister_id) {
            for snapshot_id in snapshot_ids {
                debug_assert!(self.snapshots.contains_key(&snapshot_id));
                self.snapshots.remove(&snapshot_id).unwrap();
                self.unflushed_changes
                    .push(SnapshotOperation::Delete(snapshot_id));
            }
        }
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

    /// Adds a new restore snapshot operation in the unflushed changes.
    pub fn add_restore_operation(&mut self, canister_id: CanisterId, snapshot_id: SnapshotId) {
        self.unflushed_changes
            .push(SnapshotOperation::Restore(canister_id, snapshot_id))
    }

    /// Returns true if snapshot ID can be found in the collection.
    pub fn contains(&self, snapshot_id: &SnapshotId) -> bool {
        self.snapshots.contains_key(snapshot_id)
    }

    /// Take the unflushed changes.
    pub fn take_unflushed_changes(&mut self) -> Vec<SnapshotOperation> {
        std::mem::take(&mut self.unflushed_changes)
    }

    /// Returns true if unflushed changes list is empty.
    pub fn is_unflushed_changes_empty(&self) -> bool {
        self.unflushed_changes.is_empty()
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
    /// will be discarded. A delete `SnapshotOperation` will also be triggered to
    /// apply the changes during checkpoint time.
    pub(crate) fn split<F>(&mut self, is_local_canister: F)
    where
        F: Fn(CanisterId) -> bool,
    {
        let old_snapshot_ids = self.snapshots.keys().cloned().collect::<Vec<_>>();
        for snapshot_id in old_snapshot_ids {
            // Unwrapping is safe here because `snapshot_id` is part of the keys collection.
            let snapshot = self.snapshots.get(&snapshot_id).unwrap();
            let canister_id = snapshot.canister_id;
            if !is_local_canister(canister_id) {
                self.remove(snapshot_id);
            }
        }

        // Destructure `self` and put it back together, in order for the compiler to
        // enforce an explicit decision whenever new fields are added.
        let CanisterSnapshots {
            snapshots: _,
            unflushed_changes: _,
            snapshot_ids: _,
            memory_usage: _,
        } = self;
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

#[derive(Eq, PartialEq, Debug, ValidateEq)]
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
}

/// Contains all information related to a canister snapshot.
#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
pub struct CanisterSnapshot {
    /// Identifies the canister to which this snapshot belongs.
    canister_id: CanisterId,
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
        taken_at_timestamp: Time,
        canister_version: u64,
        certified_data: Vec<u8>,
        chunk_store: WasmChunkStore,
        execution_snapshot: ExecutionStateSnapshot,
        size: NumBytes,
    ) -> CanisterSnapshot {
        Self {
            canister_id,
            taken_at_timestamp,
            canister_version,
            certified_data,
            chunk_store,
            execution_snapshot,
            size,
        }
    }

    pub fn from_canister(
        canister: &CanisterState,
        taken_at_timestamp: Time,
    ) -> Result<Self, CanisterSnapshotError> {
        let canister_id = canister.canister_id();

        let execution_state = canister
            .execution_state
            .as_ref()
            .ok_or(CanisterSnapshotError::EmptyExecutionState(canister_id))?;
        let execution_snapshot = ExecutionStateSnapshot {
            wasm_binary: execution_state.wasm_binary.binary.clone(),
            exported_globals: execution_state.exported_globals.clone(),
            stable_memory: PageMemory::from(&execution_state.stable_memory),
            wasm_memory: PageMemory::from(&execution_state.wasm_memory),
        };

        Ok(CanisterSnapshot {
            canister_id,
            taken_at_timestamp,
            canister_version: canister.system_state.canister_version,
            certified_data: canister.system_state.certified_data.clone(),
            chunk_store: canister.system_state.wasm_chunk_store.clone(),
            execution_snapshot,
            size: canister.snapshot_size_bytes(),
        })
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
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

    pub fn wasm_memory(&self) -> &PageMemory {
        &self.execution_snapshot.wasm_memory
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
}

/// Errors that can occur when trying to create a `CanisterSnapshot` from a canister.
#[derive(Debug)]
pub enum CanisterSnapshotError {
    ///  The canister is missing the execution state because it's empty (newly created or uninstalled).
    EmptyExecutionState(CanisterId),
}

/// Describes the types of unflushed changes that can be stored by the `SnapshotManager`.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum SnapshotOperation {
    Delete(SnapshotId),
    Backup(CanisterId, SnapshotId),
    Restore(CanisterId, SnapshotId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{CanisterSnapshot, CanisterSnapshots, PageMap};
    use ic_test_utilities_types::ids::canister_test_id;
    use ic_types::time::UNIX_EPOCH;
    use ic_types::NumBytes;
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
        };
        let snapshot = CanisterSnapshot::new(
            canister_id,
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
        assert_eq!(snapshot_manager.unflushed_changes.len(), 0);
        assert_eq!(snapshot_manager.snapshot_ids.len(), 0);

        // Pushing new snapshot updates the `unflushed_changes` collection.
        snapshot_manager.push(snapshot_id, Arc::<CanisterSnapshot>::new(snapshot));
        assert_eq!(snapshot_manager.snapshots.len(), 1);
        assert_eq!(snapshot_manager.unflushed_changes.len(), 1);
        assert_eq!(snapshot_manager.snapshot_ids.len(), 1);
        assert_eq!(
            snapshot_manager
                .snapshot_ids
                .get(&canister_id)
                .unwrap()
                .len(),
            1
        );

        let unflushed_changes = snapshot_manager.take_unflushed_changes();
        assert_eq!(snapshot_manager.snapshots.len(), 1);
        assert_eq!(snapshot_manager.unflushed_changes.len(), 0);
        assert_eq!(unflushed_changes.len(), 1);

        // Deleting snapshot updates the `unflushed_changes` collection.
        snapshot_manager.remove(snapshot_id);
        assert_eq!(snapshot_manager.snapshots.len(), 0);
        assert_eq!(snapshot_manager.unflushed_changes.len(), 1);
        let unflushed_changes = snapshot_manager.take_unflushed_changes();
        assert_eq!(snapshot_manager.unflushed_changes.len(), 0);
        assert_eq!(unflushed_changes.len(), 1);
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
        assert_eq!(snapshot_manager.unflushed_changes.len(), 0);
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
