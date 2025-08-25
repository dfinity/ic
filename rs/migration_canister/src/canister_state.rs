//! This module contains the global, stable canister state.
//!
//!

use std::{cell::RefCell, collections::BTreeSet};

use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    BTreeMap, Cell, DefaultMemoryImpl,
};

use crate::{RequestState, DEFAULT_MAX_ACTIVE_REQUESTS};

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {

    static LOCKS: RefCell<Locks> = const {RefCell::new(Locks{ids: BTreeSet::new()}) };

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static DISABLED: RefCell<Cell<bool, Memory>> =
        RefCell::new(Cell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), false));

    static MAX_ACTIVE_REQUESTS: RefCell<Cell<u64, Memory>>
        = RefCell::new(Cell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))), DEFAULT_MAX_ACTIVE_REQUESTS));

    static REQUESTS: RefCell<BTreeMap<RequestState, (), Memory>> =
        RefCell::new(BTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))));

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
    use crate::{canister_state::REQUESTS, RequestState};

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
}

// ============================== Locks ============================== //

struct Locks {
    pub ids: BTreeSet<&'static str>,
}

/// A way to acquire locks before entering a critical section which may only
/// run once at any given time.
pub struct MethodGuard {
    id: &'static str,
}

impl MethodGuard {
    pub fn new(tag: &'static str) -> Result<Self, String> {
        let id = tag;
        LOCKS.with_borrow_mut(|locks| {
            let held_locks = &mut locks.ids;
            if held_locks.contains(&id) {
                return Err("Failed to acquire lock".to_string());
            }
            held_locks.insert(id);
            Ok(Self { id })
        })
    }
}

impl Drop for MethodGuard {
    fn drop(&mut self) {
        LOCKS.with_borrow_mut(|locks| locks.ids.remove(&self.id));
    }
}
