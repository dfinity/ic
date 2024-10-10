use std::cell::RefCell;

use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};

use crate::types::Version;

// Stable Memory
type Memory = VirtualMemory<DefaultMemoryImpl>;

type StableMap<K, V> = StableBTreeMap<K, V, Memory>;
type _StableSet<T> = StableMap<T, ()>;
type StableValue<T> = StableMap<(), T>;

const MEMORY_ID_VERSION: u8 = 0;

// Memory
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

thread_local! {
    pub static VERSION: RefCell<StableValue<Version>> = RefCell::new(
        StableValue::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_VERSION))),
        )
    );
}
