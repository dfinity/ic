use ic_types::{CanisterId, Time};
use ic_wasm_types::CanisterModule;

use crate::{canister_state::system_state::wasm_chunk_store::WasmChunkStore, PageMap};

use phantom_newtype::Id;
use std::{collections::BTreeMap, sync::Arc};

pub struct SnapshotIdTag;
pub type SnapshotId = Id<SnapshotIdTag, u64>;

/// A collection of canister snapshots and their IDs.
///
/// Additionally, keeps track of all the accumulated changes
/// since the last flush to the disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanisterSnapshots {
    next_snapshot_id: SnapshotId,
    pub(crate) snapshots: BTreeMap<SnapshotId, Arc<CanisterSnapshot>>,
    pub(crate) unflushed_changes: Vec<SnapshotOperation>,
}

impl Default for CanisterSnapshots {
    fn default() -> Self {
        Self {
            next_snapshot_id: SnapshotId::new(0),
            snapshots: BTreeMap::new(),
            unflushed_changes: vec![],
        }
    }
}

impl CanisterSnapshots {
    pub fn new(
        next_snapshot_id: SnapshotId,
        snapshots: BTreeMap<SnapshotId, Arc<CanisterSnapshot>>,
    ) -> Self {
        Self {
            next_snapshot_id,
            snapshots,
            unflushed_changes: vec![],
        }
    }

    /// Adds new snapshot in the collection and assigns a `SnapshotId`.
    ///
    /// Additionally, adds a new item to the `unflushed_changes`
    /// which represents the new backup accumulated since the last flush to the disk.
    pub fn push(&mut self, snapshot: Arc<CanisterSnapshot>) -> SnapshotId {
        let snapshot_id = self.next_snapshot_id;
        self.next_snapshot_id = SnapshotId::new(self.next_snapshot_id.get() + 1);
        self.unflushed_changes.push(SnapshotOperation::Backup(
            *snapshot.canister_id(),
            snapshot_id,
        ));
        self.snapshots.insert(snapshot_id, snapshot);
        snapshot_id
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
                Some(snapshot)
            }
            None => {
                // No snapshot found based on the snapshot ID provided.
                None
            }
        }
    }

    /// Take the unflushed changes.
    pub fn take_unflushed_changes(&mut self) -> Vec<SnapshotOperation> {
        std::mem::take(&mut self.unflushed_changes)
    }
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
    /// The certified data blob belonging to the canister.
    certified_data: Vec<u8>,
    /// Snapshot of chunked store.
    chunk_store: WasmChunkStore,
    /// The raw canister module.
    /// May not exist depending on whether or not the canister has
    /// an actual wasm module.
    wasm_binary: Option<CanisterModule>,
    /// Snapshot of stable memory.
    stable_memory: Option<PageMap>,
    /// Snapshot of wasm memory.
    wasm_memory: Option<PageMap>,
}

impl CanisterSnapshot {
    pub fn new(
        canister_id: CanisterId,
        taken_at_timestamp: Time,
        canister_version: u64,
        certified_data: Vec<u8>,
        stable_memory: Option<PageMap>,
        wasm_memory: Option<PageMap>,
        chunk_store: WasmChunkStore,
        wasm_binary: Option<CanisterModule>,
    ) -> CanisterSnapshot {
        Self {
            canister_id,
            taken_at_timestamp,
            canister_version,
            certified_data,
            stable_memory,
            wasm_memory,
            chunk_store,
            wasm_binary,
        }
    }

    pub fn canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    pub fn canister_version(&self) -> u64 {
        self.canister_version
    }

    pub fn taken_at_timestamp(&self) -> &Time {
        &self.taken_at_timestamp
    }

    pub fn stable_memory(&self) -> &Option<PageMap> {
        &self.stable_memory
    }

    pub fn wasm_memory(&self) -> &Option<PageMap> {
        &self.wasm_memory
    }

    pub fn chunk_store(&self) -> &WasmChunkStore {
        &self.chunk_store
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
    use ic_test_utilities::types::ids::canister_test_id;
    use ic_test_utilities_time::mock_time;
    use ic_types::NumBytes;
    #[test]
    fn test_push_and_remove_snapshot() {
        let snapshot = CanisterSnapshot::new(
            canister_test_id(0),
            mock_time(),
            0,
            vec![],
            Some(PageMap::new_for_testing()),
            Some(PageMap::new_for_testing()),
            WasmChunkStore::new_for_testing(NumBytes::from(20)),
            Some(CanisterModule::new(vec![1, 2, 3])),
        );
        let mut snapshot_manager = CanisterSnapshots::default();
        assert_eq!(snapshot_manager.snapshots.len(), 0);
        assert_eq!(snapshot_manager.unflushed_changes.len(), 0);

        // Pushing new snapshot updates the `unflushed_changes` collection.
        let snapshot_id = snapshot_manager.push(Arc::<CanisterSnapshot>::new(snapshot));
        assert_eq!(snapshot_manager.snapshots.len(), 1);
        assert_eq!(snapshot_manager.unflushed_changes.len(), 1);

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
    }
}
