// Stable memory for the TVL canister.

use std::cell::RefCell;

use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};

const TVL_TIMESERIES_ID: MemoryId = MemoryId::new(0);
const LOCKED_E8S_TIMESERIES_ID: MemoryId = MemoryId::new(1);
const FX_TIMESERIES_ID: MemoryId = MemoryId::new(2);

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    // Timeseries of total value locked in USD.
    pub static TVL_TIMESERIES: RefCell<StableBTreeMap<u64, u64, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(TVL_TIMESERIES_ID)),
        )
    );

    // Timeseries of total value locked in e8s.
    pub static LOCKED_E8S_TIMESERIES: RefCell<StableBTreeMap<u64, u64, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(LOCKED_E8S_TIMESERIES_ID)),
        )
    );

    // Timeseries of ICP/USD exchange rates.
    pub static FX_TIMESERIES: RefCell<StableBTreeMap<u64, u64, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(FX_TIMESERIES_ID)),
        )
    );

}
