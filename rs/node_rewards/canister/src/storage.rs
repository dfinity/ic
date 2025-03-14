use ic_registry_canister_client::stable_memory::{
    RegistryStoreStableMemory, StorableRegistryKey, StorableRegistryValue,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use std::cell::RefCell;

/// MemoryId for upgrades, if any.  This is reserved, but probably not going to be used.
const _UPGRADES_MEMORY_ID: MemoryId = MemoryId::new(0);

const REGISTRY_STORE_MEMORY_ID: MemoryId = MemoryId::new(1);

type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static REGISTRY_DATA_STORE_BTREE_MAP: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>>
        = RefCell::new(MEMORY_MANAGER.with_borrow(|mm|
            StableBTreeMap::new(mm.get(REGISTRY_STORE_MEMORY_ID))
        ));
}

pub struct RegistryStoreStableMemoryBorrower;

impl RegistryStoreStableMemory for RegistryStoreStableMemoryBorrower {
    fn with_registry_map<R>(
        f: impl FnOnce(&StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R {
        REGISTRY_DATA_STORE_BTREE_MAP.with(|btree| f(&btree.borrow()))
    }
    fn with_registry_map_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R {
        REGISTRY_DATA_STORE_BTREE_MAP.with(|btree| f(&mut btree.borrow_mut()))
    }
}
