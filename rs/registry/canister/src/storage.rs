use ic_nervous_system_chunks::Chunks;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::DefaultMemoryImpl;
use std::cell::RefCell;

const UPGRADES_MEMORY_ID: MemoryId = MemoryId::new(0);
const CHUNKS_MEMORY_ID: MemoryId = MemoryId::new(1);

type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static UPGRADES_MEMORY: RefCell<VM> = RefCell::new({
        MEMORY_MANAGER.with(|mm| mm.borrow().get(UPGRADES_MEMORY_ID))
    });

    static CHUNKS: RefCell<Chunks<VM>> = RefCell::new({
        MEMORY_MANAGER.with(|mm| Chunks::init(mm.borrow().get(CHUNKS_MEMORY_ID)))
    });
}

pub fn with_upgrades_memory<R>(f: impl FnOnce(&VM) -> R) -> R {
    UPGRADES_MEMORY.with(|um| {
        let upgrades_memory = &um.borrow();
        f(upgrades_memory)
    })
}

pub(crate) fn with_chunks<R>(f: impl FnOnce(&Chunks<VM>) -> R) -> R {
    CHUNKS.with(|chunks| {
        let chunks = chunks.borrow();
        f(&chunks)
    })
}

// TODO(NNS1-3645): with_chunks_mut
