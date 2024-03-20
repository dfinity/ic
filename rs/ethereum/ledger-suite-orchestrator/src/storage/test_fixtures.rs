use crate::storage::WasmStore;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use ic_stable_structures::DefaultMemoryImpl;

pub fn empty_wasm_store() -> WasmStore {
    WasmStore::init(MemoryManager::init(DefaultMemoryImpl::default()).get(MemoryId::new(0)))
}
