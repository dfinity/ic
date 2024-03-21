use crate::storage::TaskQueue;
use crate::storage::WasmStore;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use ic_stable_structures::BTreeMap;
use ic_stable_structures::DefaultMemoryImpl;

pub fn empty_wasm_store() -> WasmStore {
    WasmStore::init(MemoryManager::init(DefaultMemoryImpl::default()).get(MemoryId::new(0)))
}

pub fn empty_task_queue() -> TaskQueue {
    TaskQueue {
        queue: BTreeMap::init(
            MemoryManager::init(DefaultMemoryImpl::default()).get(MemoryId::new(0)),
        ),
        deadline_by_task: BTreeMap::init(
            MemoryManager::init(DefaultMemoryImpl::default()).get(MemoryId::new(1)),
        ),
    }
}
