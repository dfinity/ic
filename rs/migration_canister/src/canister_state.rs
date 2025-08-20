//! This module contains the global, stable canister state.
//!
//!

use std::cell::RefCell;

use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    BTreeMap, DefaultMemoryImpl,
};

use crate::RequestState;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static REQUESTS: RefCell<BTreeMap<RequestState, (), VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(BTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))));

}
