use ic_registry_canister_client::{
    RegistryDataStableMemory, RegistryVersionsValue, StorableRegistryKey, StorableRegistryValue,
    TimestampKey,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use std::cell::RefCell;

const REGISTRY_STORE_MEMORY_ID: MemoryId = MemoryId::new(0);
const TIMESTAMP_TO_REGISTRY_VERSIONS_MAP_MEMORY_ID: MemoryId = MemoryId::new(1);

type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static REGISTRY_DATA_STORE_BTREE_MAP: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>>
        = RefCell::new(MEMORY_MANAGER.with_borrow(|mm|
            StableBTreeMap::init(mm.get(REGISTRY_STORE_MEMORY_ID))
        ));

    static TIMESTAMP_TO_REGISTRY_VERSIONS_MAP: RefCell<StableBTreeMap<TimestampKey, RegistryVersionsValue, VM>>
        = RefCell::new(MEMORY_MANAGER.with_borrow(|mm|
            StableBTreeMap::init(mm.get(TIMESTAMP_TO_REGISTRY_VERSIONS_MAP_MEMORY_ID))
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
    fn with_timestamp_to_registry_versions_map<R>(
        f: impl FnOnce(&StableBTreeMap<TimestampKey, RegistryVersionsValue, VM>) -> R,
    ) -> R {
        TIMESTAMP_TO_REGISTRY_VERSIONS_MAP.with_borrow_mut(f)
    }
    fn with_timestamp_to_registry_versions_map_mut<R>(
        f: impl FnOnce(&StableBTreeMap<TimestampKey, RegistryVersionsValue, VM>) -> R,
    ) -> R {
        TIMESTAMP_TO_REGISTRY_VERSIONS_MAP.with_borrow_mut(f)
    }
}
