use crate::pb::v1::AuditEvent;

use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableLog,
};
use std::cell::RefCell;

/// Constants to define memory segments.  Must not change.
const UPGRADES_MEMORY_ID: MemoryId = MemoryId::new(0);
const AUDIT_EVENTS_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const AUDIT_EVENTS_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);

type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    // The memory where the governance reads and writes its state during an upgrade.
    pub static UPGRADES_MEMORY: RefCell<VM> = MEMORY_MANAGER
        .with(|memory_manager| RefCell::new(memory_manager.borrow().get(UPGRADES_MEMORY_ID)));

    // Events for audit purposes.
    pub static AUDIT_EVENTS_LOG: RefCell<StableLog<AuditEvent, VM, VM>> =
        MEMORY_MANAGER.with(|memory_manager| {
            RefCell::new(
                StableLog::init(
                    memory_manager.borrow().get(AUDIT_EVENTS_INDEX_MEMORY_ID),
                    memory_manager.borrow().get(AUDIT_EVENTS_DATA_MEMORY_ID),
                )
                .expect("Failed to initialize stable log"),
            )
        });
}
