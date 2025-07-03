use ic_registry_canister_client::{
    RegistryDataStableMemory, StorableRegistryKey, StorableRegistryValue,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use std::cell::RefCell;

const REGISTRY_STORE_MEMORY_ID: MemoryId = MemoryId::new(0);

type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static REGISTRY_DATA_STORE_BTREE_MAP: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>>
        = RefCell::new(MEMORY_MANAGER.with_borrow(|mm|
            StableBTreeMap::init(mm.get(REGISTRY_STORE_MEMORY_ID))
        ));
}

pub struct RegistryStoreStableMemoryBorrower;

impl RegistryDataStableMemory for RegistryStoreStableMemoryBorrower {
    fn with_registry_map<R>(
        f: impl FnOnce(&StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R {
        REGISTRY_DATA_STORE_BTREE_MAP.with_borrow(f)
    }
    fn with_registry_map_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R {
        REGISTRY_DATA_STORE_BTREE_MAP.with_borrow_mut(f)
    }
}

pub fn clear_registry_store() {
    MEMORY_MANAGER.with_borrow(|mm| {
        let _cleared: StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM> =
            StableBTreeMap::new(mm.get(REGISTRY_STORE_MEMORY_ID));
    });
}
