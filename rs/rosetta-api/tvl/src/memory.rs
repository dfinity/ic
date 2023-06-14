// Stable memory for the TVL canister.
use crate::{mutate_state, FiatCurrency};
use candid::{CandidType, Deserialize};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use std::cell::RefCell;

const TIMESERIES: MemoryId = MemoryId::new(0);

// All the exchange rates are expressed with USD as base quote.
#[derive(CandidType, Clone, Debug, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub enum EntryType {
    ICPrice = 0,
    LockedIcp = 1,
    EURExchangeRate = 2,
    CNYExchangeRate = 3,
    JPYExchangeRate = 4,
    GBPExchangeRate = 5,
}

impl From<FiatCurrency> for EntryType {
    fn from(currency: FiatCurrency) -> Self {
        match currency {
            FiatCurrency::USD => panic!("no USD exchange rate expected"),
            FiatCurrency::EUR => EntryType::EURExchangeRate,
            FiatCurrency::CNY => EntryType::CNYExchangeRate,
            FiatCurrency::JPY => EntryType::JPYExchangeRate,
            FiatCurrency::GBP => EntryType::GBPExchangeRate,
        }
    }
}

impl From<u32> for EntryType {
    fn from(num: u32) -> Self {
        match num {
            0 => EntryType::ICPrice,
            1 => EntryType::LockedIcp,
            2 => EntryType::EURExchangeRate,
            3 => EntryType::CNYExchangeRate,
            4 => EntryType::JPYExchangeRate,
            5 => EntryType::GBPExchangeRate,
            _ => panic!("Invalid EntryType value: {}", num),
        }
    }
}

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );
    // Timeseries of data collected by TVL canister.
    // (timestamp, entry type) -> rate
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
            mutate_state(|s| {
                s.last_icp_rate_ts = ts;
                s.last_icp_rate = value;
            });
        }
        EntryType::LockedIcp => {
            TVL_TIMESERIES.with(|m| {
                m.borrow_mut()
                    .insert((ts, EntryType::LockedIcp as u32), value);
            });
            mutate_state(|s| {
                s.last_icp_locked_ts = ts;
                s.last_icp_locked = value;
            });
        }
        _ => {
            TVL_TIMESERIES.with(|m| {
                m.borrow_mut().insert((ts, entry as u32), value);
            });
        }
    }
}
