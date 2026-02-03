#[cfg(not(feature = "test"))]
use crate::metrics::ICCanisterClient;
use crate::metrics::MetricsManager;
#[cfg(feature = "test")]
use crate::metrics::management_canister_client_test::ICCanisterClient;
use ic_registry_canister_client::{
    RegistryDataStableMemory, StorableRegistryKey, StorableRegistryValue,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell, Storable};
use std::cell::RefCell;
use std::rc::Rc;

const REGISTRY_STORE_MEMORY_ID: MemoryId = MemoryId::new(0);
const SUBNETS_METRICS_MEMORY_ID: MemoryId = MemoryId::new(1);
const LAST_TIMESTAMP_PER_SUBNET_MEMORY_ID: MemoryId = MemoryId::new(2);
const LAST_DAY_SYNCED_MEMORY_ID: MemoryId = MemoryId::new(3);

pub type VM = VirtualMemory<DefaultMemoryImpl>;

#[derive(Clone)]
pub struct NaiveDateStorable(pub chrono::NaiveDate);

pub fn stable_btreemap_init<K: Storable + Clone + Ord, V: Storable>(
    memory_id: MemoryId,
) -> StableBTreeMap<K, V, VM> {
    with_memory_manager(|mgr| StableBTreeMap::init(mgr.get(memory_id)))
}
fn with_memory_manager<R>(f: impl FnOnce(&MemoryManager<DefaultMemoryImpl>) -> R) -> R {
    MEMORY_MANAGER.with(|memory_manager| f(&memory_manager.borrow()))
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    pub static METRICS_MANAGER: Rc<MetricsManager<VM>> = {
        let metrics_manager = MetricsManager {
            client: Box::new(ICCanisterClient),
            subnets_metrics: RefCell::new(stable_btreemap_init(SUBNETS_METRICS_MEMORY_ID)),
            last_timestamp_per_subnet: RefCell::new(stable_btreemap_init(LAST_TIMESTAMP_PER_SUBNET_MEMORY_ID)),
        };

        Rc::new(metrics_manager)
    };

    pub static LAST_DAY_SYNCED: RefCell<StableCell<Option<NaiveDateStorable>, VM>> = RefCell::new(MEMORY_MANAGER.with_borrow(|mm|
            StableCell::init(mm.get(LAST_DAY_SYNCED_MEMORY_ID), None).expect("Could not initialize last_day_synced")
        ));

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
