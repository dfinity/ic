use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::DefaultMemoryImpl;
use std::cell::RefCell;

/// MemoryId for upgrades, if any.  This is reserved, but probably not going to be used.
const UPGRADES_MEMORY_ID: MemoryId = MemoryId::new(0);

const REGISTRY_STORE_MEMORY_ID: MemoryId = MemoryId::new(1);

type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static REGISTRY_STORE_MEMORY: RefCell<VM> = RefCell::new(MEMORY_MANAGER.with_borrow(|mm| mm.get(REGISTRY_STORE_MEMORY_ID)));
}
