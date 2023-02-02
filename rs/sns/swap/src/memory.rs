use ic_base_types::PrincipalId;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl,
};
use std::cell::RefCell;

const UPGRADES_MEM_ID: MemoryId = MemoryId::new(0);
const BUYERS_INDEX_LIST_MEM_ID: MemoryId = MemoryId::new(2);

thread_local! {

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    // The memory where the swap canister must write and read its state during an upgrade.
    pub static UPGRADES_MEMORY: RefCell<VirtualMemory<DefaultMemoryImpl>> = MEMORY_MANAGER.with(|mm|
        RefCell::new(mm.borrow().get(UPGRADES_MEM_ID)));

    /// The `BUYERS_LIST_INDEX` gives an ordered list index of the Swap::buyers map. This is used to
    /// determine which Principals participated in what order, and allows for limit + offset
    /// pagination.
    pub static BUYERS_LIST_INDEX: RefCell<ic_stable_structures::Vec<PrincipalId, VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager|
            RefCell::new(
                ic_stable_structures::Vec::init(
                    memory_manager.borrow().get(BUYERS_INDEX_LIST_MEM_ID)
                )
                .expect("Expected to initialize the BUYERS_LIST_INDEX without error")
            )
        );
}
