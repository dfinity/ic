use crate::memory::EntryType;
use crate::FiatCurrency;
use crate::TVL_TIMESERIES;
use ic_base_types::PrincipalId;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub struct TvlState {
    // The principal of the governance canister of the NNS.
    pub governance_principal: PrincipalId,
    // The principal of the exchange rate canister.
    pub xrc_principal: PrincipalId,
    // The time period to wait between two data updates, in seconds.
    pub update_period: Duration,
    // The last ICP rate (e8s).
    pub last_icp_rate: u64,
    pub last_icp_rate_ts: u64,

    // The last amount of ICP locked (e8s).
    pub last_icp_locked: u64,
    pub last_icp_locked_ts: u64,

    // Exchange rate expressed with base asset in USD.
    pub exchange_rate: BTreeMap<FiatCurrency, u64>,

    pub currencies_to_fetch: BTreeSet<FiatCurrency>,
}

impl TvlState {
    pub fn populate_state(&mut self) {
        TVL_TIMESERIES.with(|map| {
            for ((ts, entry_type), value) in map.borrow().iter() {
                match EntryType::from(entry_type) {
                    EntryType::EURExchangeRate => {
                        self.exchange_rate
                            .entry(FiatCurrency::EUR)
                            .and_modify(|curr| *curr = value)
                            .or_insert(value);
                    }
                    EntryType::CNYExchangeRate => {
                        self.exchange_rate
                            .entry(FiatCurrency::CNY)
                            .and_modify(|curr| *curr = value)
                            .or_insert(value);
                    }
                    EntryType::JPYExchangeRate => {
                        self.exchange_rate
                            .entry(FiatCurrency::JPY)
                            .and_modify(|curr| *curr = value)
                            .or_insert(value);
                    }
                    EntryType::GBPExchangeRate => {
                        self.exchange_rate
                            .entry(FiatCurrency::GBP)
                            .and_modify(|curr| *curr = value)
                            .or_insert(value);
                    }
                    EntryType::ICPrice => {
                        self.last_icp_rate = value;
                        self.last_icp_rate_ts = ts;
                    }
                    EntryType::LockedIcp => {
                        self.last_icp_locked = value;
                        self.last_icp_locked_ts = ts;
                    }
                }
            }
        })
    }
}

thread_local! {
    static __STATE: RefCell<Option<TvlState>> = const { RefCell::new(None) };
}

/// Mutates (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut TvlState) -> R,
{
    __STATE.with(|s| f(s.borrow_mut().as_mut().expect("State not initialized!")))
}

/// Read (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn read_state<F, R>(f: F) -> R
where
    F: FnOnce(&TvlState) -> R,
{
    __STATE.with(|s| f(s.borrow().as_ref().expect("State not initialized!")))
}

/// Replaces the current state.
pub fn replace_state(state: TvlState) {
    __STATE.with(|s| {
        *s.borrow_mut() = Some(state);
    });
}
