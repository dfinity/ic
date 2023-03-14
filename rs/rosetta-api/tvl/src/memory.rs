// Stable memory for the TVL canister.
use crate::mutate_state;
use candid::{CandidType, Deserialize};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use std::cell::RefCell;

const TIMESERIES: MemoryId = MemoryId::new(0);

#[derive(CandidType, Clone, Debug, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub enum EntryType {
    ICPrice = 0,
    LockedIcp = 1,
}

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );
    // Timeseries of data collected by TVL canister.
    pub static TVL_TIMESERIES: RefCell<StableBTreeMap<(u64,u32), u64, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(TIMESERIES)),
        )
    );
}

pub fn push_entry(ts: u64, entry: EntryType, value: u64) {
    match entry {
        EntryType::ICPrice => {
            TVL_TIMESERIES.with(|m| {
                m.borrow_mut()
                    .insert((ts, EntryType::ICPrice as u32), value);
            });
            mutate_state(|s| s.last_ts_icp_price = ts);
        }
        EntryType::LockedIcp => {
            TVL_TIMESERIES.with(|m| {
                m.borrow_mut()
                    .insert((ts, EntryType::LockedIcp as u32), value);
            });
            mutate_state(|s| s.last_ts_icp_locked = ts);
        }
    }
}

pub fn get_last_icp_price_ts() -> u64 {
    TVL_TIMESERIES.with(|map| {
        let mut latest_ts = 0;
        for ((ts, t), _) in map.borrow().iter() {
            if t == EntryType::ICPrice as u32 {
                latest_ts = ts;
            }
        }
        latest_ts
    })
}

pub fn get_last_locked_icp_ts() -> u64 {
    TVL_TIMESERIES.with(|map| {
        let mut latest_ts = 0;
        for ((ts, t), _) in map.borrow().iter() {
            if t == EntryType::LockedIcp as u32 {
                latest_ts = ts;
            }
        }
        latest_ts
    })
}
