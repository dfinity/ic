use crate::pb::v1::Ticket;
use candid::Principal;
use ic_base_types::PrincipalId;
use ic_stable_structures::{
    DefaultMemoryImpl, StableBTreeMap, Vec as StableVec,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Blob,
};
use std::cell::RefCell;

const UPGRADES_MEMORY_ID: MemoryId = MemoryId::new(0);
const OPEN_TICKETS_MEMORY_ID: MemoryId = MemoryId::new(1);
const BUYERS_INDEX_LIST_MEMORY_ID: MemoryId = MemoryId::new(2);

thread_local! {

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    // The memory where the swap canister must write and read its state during an upgrade.
    pub static UPGRADES_MEMORY: RefCell<VirtualMemory<DefaultMemoryImpl>> = MEMORY_MANAGER.with(|memory_manager|
        RefCell::new(memory_manager.borrow().get(UPGRADES_MEMORY_ID)));

    // The stable bmap where the swap canister keeps open tickets. The key is the Principal.
    pub static OPEN_TICKETS_MEMORY: RefCell<StableBTreeMap<Blob<{PrincipalId::MAX_LENGTH_IN_BYTES}>, Ticket, VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager| RefCell::new(StableBTreeMap::init(memory_manager.borrow().get(OPEN_TICKETS_MEMORY_ID))));

    /// The `BUYERS_LIST_INDEX` gives an ordered list index of the Swap::buyers map. This is used to
    /// determine which Principals participated in what order, and allows for limit + offset
    /// pagination.
    pub static BUYERS_LIST_INDEX: RefCell<StableVec<Principal, VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager|
            RefCell::new(
                StableVec::init(
                    memory_manager.borrow().get(BUYERS_INDEX_LIST_MEMORY_ID)
                )
                .expect("Expected to initialize the BUYERS_LIST_INDEX without error")
            )
        );
}
