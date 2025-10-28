//! This module contains the global, stable canister state.
//!
//!

use std::{cell::RefCell, collections::BTreeSet};

use candid::Principal;
use ic_stable_structures::{
    BTreeMap, Cell, DefaultMemoryImpl,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
};

use crate::{DEFAULT_MAX_ACTIVE_REQUESTS, Event, MAX_ONGOING_VALIDATIONS, RequestState};

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static ALLOWLIST: RefCell<Option<Vec<Principal>>> = const { RefCell::new(None) };

    static LOCKS: RefCell<Locks> = const {RefCell::new(Locks{ids: BTreeSet::new()}) };

    static ONGOING_VALIDATIONS: RefCell<u64> = const { RefCell::new(0)};

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static DISABLED: RefCell<Cell<bool, Memory>> =
        RefCell::new(Cell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), false));

    /// Interpreted as: Max number of requests in a 24 hour sliding window.
    static MAX_ACTIVE_REQUESTS: RefCell<Cell<u64, Memory>>
        = RefCell::new(Cell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))), DEFAULT_MAX_ACTIVE_REQUESTS));

    static REQUESTS: RefCell<BTreeMap<RequestState, (), Memory>> =
        RefCell::new(BTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))));

    static HISTORY: RefCell<BTreeMap<Event, (), Memory>> =
        RefCell::new(BTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))));

    // TODO: consider a fail counter for active requests.
    // This way we see if a request never makes progress which would
    // indicate a bug in this canister or a problem with a subnet.
    // BTreeMap<(Request, Reqstate: String), (Counter: u64, FirstTs: Time, LastTs: Time)>
}

pub fn migrations_disabled() -> bool {
    DISABLED.with_borrow(|x| *x.get())
}

/// Excludes failed requests.
pub fn num_active_requests() -> u64 {
    REQUESTS.with_borrow(|req| {
        req.iter()
            .filter(|x| !matches!(x.key(), RequestState::Failed { .. }))
            .count() as u64
    })
}

pub fn max_active_requests() -> u64 {
    MAX_ACTIVE_REQUESTS.with_borrow(|x| *x.get())
}

pub fn set_allowlist(arg: Option<Vec<Principal>>) {
    ALLOWLIST.set(arg);
}

pub fn caller_allowed(id: &Principal) -> bool {
    ALLOWLIST.with_borrow(|allowlist| match allowlist {
        Some(allowlist) => allowlist.contains(id),
        None => true,
    })
}

// ============================== Privileged API ============================== //
pub mod privileged {
    //! This API is only for controllers.
    use crate::canister_state::{DISABLED, MAX_ACTIVE_REQUESTS};

    pub fn set_disabled_flag(flag: bool) {
        DISABLED.with_borrow_mut(|x| x.set(flag));
    }

    pub fn set_max_active_requests(value: u64) {
        MAX_ACTIVE_REQUESTS.with_borrow_mut(|x| x.set(value));
    }
}

// ============================== Request API ============================== //
pub mod requests {
    use candid::Principal;

    use crate::{RequestState, canister_state::REQUESTS};

    pub fn insert_request(request: RequestState) {
        REQUESTS.with_borrow_mut(|r| r.insert(request, ()));
    }

    pub fn remove_request(request: &RequestState) {
        let _ = REQUESTS.with_borrow_mut(|r| r.remove(request));
    }

    /// Retrieves all requests of a given variant.
    /// We return vectors rather than iterators because we have to
    /// borrow REQUESTS mutably while iterating over the result.
    pub fn list_by(predicate: impl FnMut(&RequestState) -> bool) -> Vec<RequestState> {
        REQUESTS.with_borrow(|req| req.keys().filter(predicate).collect())
    }

    pub fn find_request(source: Principal, target: Principal) -> Vec<RequestState> {
        // TODO: should do a range scan for efficiency.
        REQUESTS.with_borrow(|r| {
            r.keys()
                .filter(|x| x.request().source == source && x.request().target == target)
                .collect()
        })
    }
}

// ============================== Events API ============================== //
pub mod events {
    use crate::{Event, EventType, Request, canister_state::HISTORY};
    use candid::Principal;
    use ic_cdk::api::time;

    pub fn insert_event(event: EventType) {
        let time = time();
        let event = Event { time, event };
        HISTORY.with_borrow_mut(|h| h.insert(event, ()));
    }

    pub fn list_events(_page_index: u64, _page_size: u64) -> Vec<Event> {
        // TODO: implement pagination
        HISTORY.with_borrow(|h| h.keys().collect())
    }

    pub fn num_successes_in_past_24_h() -> u64 {
        let now = time();
        let nanos_in_24_h = 24 * 60 * 60 * 1_000_000_000;
        HISTORY.with_borrow(|h| {
            let mut count = 0;
            for event in h.iter_from_prev_key(&Event {
                time: now.saturating_sub(nanos_in_24_h),
                event: EventType::Succeeded {
                    request: Request::low_bound(),
                },
            }) {
                if matches!(event.key().event, EventType::Succeeded { .. }) {
                    count += 1;
                }
            }
            count
        })
    }

    pub fn find_event(source: Principal, target: Principal) -> Vec<Event> {
        // TODO: should do a range scan for efficiency.
        HISTORY.with_borrow(|r| {
            r.keys()
                .filter(|x| {
                    x.event.request().source == source && x.event.request().target == target
                })
                .collect()
        })
    }
}

// ============================== Locks ============================== //

struct Locks {
    pub ids: BTreeSet<String>,
}

/// A way to acquire locks before entering a critical section which may only
/// run once at any given time.
pub struct MethodGuard {
    id: String,
}

impl MethodGuard {
    pub fn new(tag: &str) -> Result<Self, String> {
        let id = String::from(tag);
        LOCKS.with_borrow_mut(|locks| {
            let held_locks = &mut locks.ids;
            if held_locks.contains(&id) {
                return Err("Failed to acquire lock".to_string());
            }
            held_locks.insert(id.clone());
            Ok(Self { id })
        })
    }
}

impl Drop for MethodGuard {
    fn drop(&mut self) {
        LOCKS.with_borrow_mut(|locks| locks.ids.remove(&self.id));
    }
}

pub struct ValidationGuard;

impl ValidationGuard {
    pub fn new() -> Result<Self, String> {
        ONGOING_VALIDATIONS.with_borrow_mut(|num| {
            // Rate limit validations:
            // Validation requires many xnet calls, so we don't want too many validations at once.
            if *num >= MAX_ONGOING_VALIDATIONS {
                Err("Rate limited".to_string())
            } else {
                *num += 1;
                Ok(Self)
            }
        })
    }
}

impl Drop for ValidationGuard {
    fn drop(&mut self) {
        ONGOING_VALIDATIONS.with_borrow_mut(|num| *num -= 1)
    }
}
