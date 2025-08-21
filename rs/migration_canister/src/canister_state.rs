//! This module contains the global, stable canister state.
//!
//!

use std::cell::RefCell;

use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    BTreeMap, Cell, DefaultMemoryImpl,
};

use crate::RequestState;

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static DISABLED: RefCell<Cell<bool, Memory>> =
        RefCell::new(Cell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), false).unwrap());

    static REQUESTS: RefCell<BTreeMap<RequestState, (), Memory>> =
        RefCell::new(BTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))));

}

pub fn insert_request(request: RequestState) {
    REQUESTS.with_borrow_mut(|r| r.insert(request, ()));
}

pub fn remove_request(request: &RequestState) {
    let _ = REQUESTS.with_borrow_mut(|r| r.remove(request));
}

// The following methods retrieve all requests of a given type.
// We return vectors rather than iterators because we have to
// borrow REQUESTS mutably while iterating over the result of
// these methods.

pub fn list_accepted() -> Vec<RequestState> {
    REQUESTS.with_borrow(|req| {
        req.keys()
            .filter(|r| matches!(r, RequestState::Accepted { .. }))
            .collect()
    })
}

pub fn list_controllers_changed() -> Vec<RequestState> {
    REQUESTS.with_borrow(|req| {
        req.keys()
            .filter(|r| matches!(r, RequestState::ControllersChanged { .. }))
            .collect()
    })
}

pub fn list_stopped() -> Vec<RequestState> {
    REQUESTS.with_borrow(|req| {
        req.keys()
            .filter(|r| matches!(r, RequestState::StoppedAndReady { .. }))
            .collect()
    })
}

pub fn list_renamed_target() -> Vec<RequestState> {
    REQUESTS.with_borrow(|req| {
        req.keys()
            .filter(|r| matches!(r, RequestState::RenamedTarget { .. }))
            .collect()
    })
}

pub fn list_updated_routing() -> Vec<RequestState> {
    REQUESTS.with_borrow(|req| {
        req.keys()
            .filter(|r| matches!(r, RequestState::UpdatedRoutingTable { .. }))
            .collect()
    })
}

pub fn list_routing_accepted() -> Vec<RequestState> {
    REQUESTS.with_borrow(|req| {
        req.keys()
            .filter(|r| matches!(r, RequestState::RoutingTableChangeAccepted { .. }))
            .collect()
    })
}

pub fn list_source_deleted() -> Vec<RequestState> {
    REQUESTS.with_borrow(|req| {
        req.keys()
            .filter(|r| matches!(r, RequestState::SourceDeleted { .. }))
            .collect()
    })
}

pub fn list_failed() -> Vec<RequestState> {
    REQUESTS.with_borrow(|req| {
        req.keys()
            .filter(|r| matches!(r, RequestState::Failed { .. }))
            .collect()
    })
}
