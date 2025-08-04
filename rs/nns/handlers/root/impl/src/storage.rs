use ic_base_types::CanisterId;
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap, Storable,
};
use std::borrow::Cow;
use std::cell::RefCell;

/// Constants to define memory segments. Must not change. Keep sorted.
/// NOTE: Do not store ANYTHING in Root that cannot be lost.  Root state is considered entirely
/// expendable, and we only have state to help with operations that are queued up for later processing,
/// but which can be lost safely if we have to kill root.

type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

}

/// Reset stable memory for testing
#[cfg(any(feature = "test", test))]
pub fn reset_stable_memory() {
    MEMORY_MANAGER.with(|mm| *mm.borrow_mut() = MemoryManager::init(DefaultMemoryImpl::default()));
    STATE.with(|state| *state.borrow_mut() = State::new());
}
