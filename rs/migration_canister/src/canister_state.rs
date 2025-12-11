//! This module contains the global, stable canister state.
//!
//!

use std::{cell::RefCell, collections::BTreeSet};

use candid::Principal;
use ic_stable_structures::{
    BTreeMap, Cell, DefaultMemoryImpl,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
};

use crate::{Event, MAX_ONGOING_VALIDATIONS, RequestState};

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static ALLOWLIST: RefCell<Option<Vec<Principal>>> = const { RefCell::new(None) };

    static LOCKS: RefCell<BTreeSet<Lock>> = const {RefCell::new(BTreeSet::new()) };

    static ONGOING_VALIDATIONS: RefCell<u64> = const { RefCell::new(0)};

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static DISABLED: RefCell<Cell<bool, Memory>> =
        RefCell::new(Cell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), false));

    static REQUESTS: RefCell<BTreeMap<RequestState, (), Memory>> =
        RefCell::new(BTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))));

    /// Stores timestamps of all successful events in `HISTORY`
    /// that are within the last 24 hours.
    /// It can also store timestamps beyond the last 24 hours
    /// until they are pruned.
    /// The timestamps are represented as a key-value store
    /// with timestamps as keys and their counts as values.
    static LIMITER: RefCell<BTreeMap<u64, u64, Memory>> = RefCell::new(BTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))));

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

pub fn set_allowlist(arg: Option<Vec<Principal>>) {
    ALLOWLIST.set(arg);
}

pub fn caller_allowed(id: &Principal) -> bool {
    ALLOWLIST.with_borrow(|allowlist| match allowlist {
        Some(allowlist) => allowlist.contains(id),
        None => true,
    })
}

pub fn num_validations() -> u64 {
    ONGOING_VALIDATIONS.with_borrow(|num| *num)
}

// ============================== Privileged API ============================== //
pub mod privileged {
    //! This API is only for controllers.
    use crate::canister_state::DISABLED;

    pub fn set_disabled_flag(flag: bool) {
        DISABLED.with_borrow_mut(|x| x.set(flag));
    }
}

// ============================== Request API ============================== //
pub mod requests {
    use candid::Principal;

    use crate::{RequestState, canister_state::REQUESTS};

    pub fn num_requests() -> u64 {
        REQUESTS.with_borrow(|req| req.len())
    }

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

    pub fn find_request(source: Principal, target: Principal) -> Option<RequestState> {
        // We perform a linear scan here which is fine since
        // there can only be at most `RATE_LIMIT` (50) requests
        // at any time.
        let requests: Vec<_> = REQUESTS.with_borrow(|r| {
            r.keys()
                .filter(|x| x.request().source == source && x.request().target == target)
                .collect()
        });
        assert!(
            requests.len() <= 1,
            "There should only be a single request for a given pair of canister IDs."
        );
        requests.first().cloned()
    }
}

// ============================== Events API ============================== //
pub mod events {
    use crate::{
        Event, EventType,
        canister_state::{HISTORY, LIMITER},
    };
    use candid::Principal;
    use ic_cdk::api::time;

    pub fn insert_event(event: EventType) {
        let time = time();
        if let EventType::Succeeded { .. } = event {
            LIMITER.with_borrow_mut(|l| {
                if let Some(count) = l.remove(&time) {
                    l.insert(time, count + 1);
                } else {
                    l.insert(time, 1);
                }
            });
        }
        let event = Event { time, event };
        HISTORY.with_borrow_mut(|h| h.insert(event, ()));
    }

    pub fn history_len() -> u64 {
        HISTORY.with_borrow(|h| h.len())
    }

    pub fn find_last_event(source: Principal, target: Principal) -> Option<Event> {
        // TODO: should do a range scan for efficiency.
        HISTORY.with_borrow(|r| {
            r.keys()
                .rev()
                .find(|x| x.event.request().source == source && x.event.request().target == target)
        })
    }
}

// ============================== Limiter ============================== //
pub mod limiter {
    use crate::canister_state::LIMITER;
    use ic_cdk::api::time;

    fn past_24_h_cutoff() -> u64 {
        let now = time();
        let nanos_in_24_h = 24 * 60 * 60 * 1_000_000_000;
        now.saturating_sub(nanos_in_24_h)
    }

    fn prune_limiter() {
        let cutoff = past_24_h_cutoff();
        LIMITER.with_borrow_mut(|l| {
            while let Some((time, _)) = l.first_key_value() {
                if time < cutoff {
                    l.pop_first();
                } else {
                    break;
                }
            }
        });
    }

    pub fn num_successes_in_past_24_h() -> u64 {
        prune_limiter();
        LIMITER.with_borrow(|l| {
            let mut total = 0;
            for entry in l.iter() {
                total += entry.value();
            }
            total
        })
    }
}

// ============================== Locks ============================== //

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Lock {
    Canister(Principal),
    Method(String),
}

/// A way to acquire locks before performing async calls referring to a canister.
pub struct CanisterGuard {
    canister_id: Principal,
}

impl CanisterGuard {
    pub fn new(canister_id: Principal) -> Result<Self, String> {
        let lock = Lock::Canister(canister_id);
        LOCKS.with_borrow_mut(|locks| {
            if locks.contains(&lock) {
                return Err("Failed to acquire lock".to_string());
            }
            locks.insert(lock);
            Ok(Self { canister_id })
        })
    }
}

impl Drop for CanisterGuard {
    fn drop(&mut self) {
        let lock = Lock::Canister(self.canister_id);
        LOCKS.with_borrow_mut(|locks| locks.remove(&lock));
    }
}

/// A way to acquire locks before entering a critical section which may only
/// run once at any given time.
pub struct MethodGuard {
    id: String,
}

impl MethodGuard {
    pub fn new(tag: &str) -> Result<Self, String> {
        let id = String::from(tag);
        let lock = Lock::Method(id.clone());
        LOCKS.with_borrow_mut(|locks| {
            if locks.contains(&lock) {
                return Err("Failed to acquire lock".to_string());
            }
            locks.insert(lock);
            Ok(Self { id })
        })
    }
}

impl Drop for MethodGuard {
    fn drop(&mut self) {
        let lock = Lock::Method(self.id.clone());
        LOCKS.with_borrow_mut(|locks| locks.remove(&lock));
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
