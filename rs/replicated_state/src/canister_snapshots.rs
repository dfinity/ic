use ic_types::{CanisterId, NumBytes, SnapshotId, Time};
use ic_wasm_types::CanisterModule;

use crate::{
    canister_state::execution_state::Memory,
    canister_state::system_state::wasm_chunk_store::WasmChunkStore, CanisterState, NumWasmPages,
    PageMap,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// A collection of canister snapshots and their IDs.
///
/// Additionally, keeps track of all the accumulated changes
/// since the last flush to the disk.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CanisterSnapshots {
    pub(crate) snapshots: BTreeMap<SnapshotId, Arc<CanisterSnapshot>>,
    /// Snapshot operations are consumed by the `StateManager` in order to
    /// correctly represent backups and restores in the next checkpoint.
    pub(crate) unflushed_changes: Vec<SnapshotOperation>,
    /// The set of snapshots ids grouped by canisters.
    pub(crate) snapshot_ids: BTreeMap<CanisterId, BTreeSet<SnapshotId>>,
}

impl CanisterSnapshots {
    pub fn new(
        snapshots: BTreeMap<SnapshotId, Arc<CanisterSnapshot>>,
        snapshot_ids: BTreeMap<CanisterId, BTreeSet<SnapshotId>>,
    ) -> Self {
        Self {
            snapshots,
            unflushed_changes: vec![],
            snapshot_ids,
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
        self.snapshots.insert(snapshot_id, snapshot);
        let snapshot_ids = self.snapshot_ids.entry(canister_id).or_default();
        snapshot_ids.insert(snapshot_id);
        snapshot_id
    }

    /// Returns a reference of the canister snapshot identified by `snapshot_id`.
    pub fn get(&self, snapshot_id: SnapshotId) -> Option<&Arc<CanisterSnapshot>> {
        self.snapshots.get(&snapshot_id)
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

                // The snapshot ID if present in the `self.snapshots`,
                // must also be present in the `self.snapshot_ids`.
                let canister_id = snapshot.canister_id();
                debug_assert!(self.snapshot_ids.contains_key(&canister_id));
                let snapshot_ids = self.snapshot_ids.get_mut(&canister_id).unwrap();
                debug_assert!(snapshot_ids.contains(&snapshot_id));
                snapshot_ids.remove(&snapshot_id);

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

    pub(crate) fn split<F>(&mut self, is_local_canister: F)
    where
        F: Fn(CanisterId) -> bool,
    {
        // Destructure `self` and put it back together, in order for the compiler to
        // enforce an explicit decision whenever new fields are added.
        let Self {
            next_snapshot_id,
            mut snapshots,
            mut unflushed_changes,
        } = self;

        let old_snapshot_ids = snapshots.keys().cloned().collect::<Vec<_>>();
        for snapshot_id in old_snapshot_ids {
            // Unwrapping is safe here because `snapshot_id` is part of the keys collection.
            let snapshot = self.snapshots.get(&snapshot_id).unwrap();
            if !is_local_canister(snapshot.canister_id) {
                self.remove(snapshot_id);
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageMemory {
    /// The contents of this memory.
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionStateSnapshot {
    /// The raw canister module.
    pub wasm_binary: CanisterModule,
    /// Snapshot of stable memory.
    pub stable_memory: PageMemory,
    /// Snapshot of wasm memory.
    pub wasm_memory: PageMemory,
}

/// Contains all information related to a canister snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    chunk_store: WasmChunkStore,
    /// May not exist depending on whether or not the canister has
    /// an actual `ExecutionState`.
    execution_snapshot: Option<ExecutionStateSnapshot>,
}

impl CanisterSnapshot {
    pub fn new(
        canister_id: CanisterId,
        taken_at_timestamp: Time,
        canister_version: u64,
        certified_data: Vec<u8>,
        chunk_store: WasmChunkStore,
        execution_snapshot: Option<ExecutionStateSnapshot>,
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

    pub fn from(canister: &CanisterState, taken_at_timestamp: Time) -> Self {
        let execution_snapshot =
            canister
                .execution_state
                .as_ref()
                .map(|execution_state| ExecutionStateSnapshot {
                    wasm_binary: execution_state.wasm_binary.binary.clone(),
                    stable_memory: PageMemory::from(&execution_state.stable_memory),
                    wasm_memory: PageMemory::from(&execution_state.wasm_memory),
                });

        Self {
            canister_id: canister.canister_id(),
            taken_at_timestamp,
            canister_version: canister.system_state.canister_version,
            certified_data: canister.system_state.certified_data.clone(),
            chunk_store: canister.system_state.wasm_chunk_store.clone(),
            execution_snapshot,
            size: canister.snapshot_memory_usage(),
        }
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

    pub fn execution_snapshot(&self) -> Option<&ExecutionStateSnapshot> {
        self.execution_snapshot.as_ref()
    }

    pub fn stable_memory(&self) -> Option<&PageMemory> {
        self.execution_snapshot
            .as_ref()
            .map(|exec| &exec.stable_memory)
    }

    pub fn wasm_memory(&self) -> Option<&PageMemory> {
        self.execution_snapshot
            .as_ref()
            .map(|exec| &exec.wasm_memory)
    }

    pub fn canister_module(&self) -> Option<&CanisterModule> {
        self.execution_snapshot
            .as_ref()
            .map(|exec| &exec.wasm_binary)
    }

    pub fn chunk_store(&self) -> &WasmChunkStore {
        &self.chunk_store
    }

    pub fn certified_data(&self) -> &Vec<u8> {
        &self.certified_data
    }
}

/// Describes the types of unflushed changes that can be stored by the `SnapshotManager`.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    #[test]
    fn test_push_and_remove_snapshot() {
        let execution_snapshot = ExecutionStateSnapshot {
            wasm_binary: CanisterModule::new(vec![1, 2, 3]),
            stable_memory: PageMemory {
                page_map: PageMap::new_for_testing(),
                size: NumWasmPages::new(10),
            },
            wasm_memory: PageMemory {
                page_map: PageMap::new_for_testing(),
                size: NumWasmPages::new(10),
            },
        };
        let canister_id = canister_test_id(0);
        let snapshot = CanisterSnapshot::new(
            canister_id,
            UNIX_EPOCH,
            0,
            vec![],
            WasmChunkStore::new_for_testing(),
            Some(execution_snapshot),
            NumBytes::from(0),
        );
        let mut snapshot_manager = CanisterSnapshots::default();
        assert_eq!(snapshot_manager.snapshots.len(), 0);
        assert_eq!(snapshot_manager.unflushed_changes.len(), 0);
        assert_eq!(snapshot_manager.snapshot_ids.len(), 0);

        // Pushing new snapshot updates the `unflushed_changes` collection.
        let snapshot_id = SnapshotId::from((canister_test_id(0), 1));
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
        assert_eq!(snapshot_manager.snapshot_ids.len(), 1);
        assert_eq!(
            snapshot_manager
                .snapshot_ids
                .get(&canister_id)
                .unwrap()
                .len(),
            0
        );
    }
}
