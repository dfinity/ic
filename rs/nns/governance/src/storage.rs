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

/* TODO(NNS1-2443): Re-enable clippy. */
#[allow(dead_code)]
const MAIN_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(3);
/* TODO(NNS1-2443): Re-enable clippy. */
#[allow(dead_code)]
const HOT_KEYS_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(4);
/* TODO(NNS1-2443): Re-enable clippy. */
#[allow(dead_code)]
const FOLLOWEES_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(5);
/* TODO(NNS1-2443): Re-enable clippy. */
#[allow(dead_code)]
const RECENT_BALLOTS_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(6);
/* TODO(NNS1-2443): Re-enable clippy. */
#[allow(dead_code)]
const KNOWN_NEURON_DATA_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(7);
/* TODO(NNS1-2443): Re-enable clippy. */
#[allow(dead_code)]
const TRANSFER_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(8);

pub mod neurons;

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

    pub(crate) static NEURONS: neurons::StableNeuronStore<VM> =
        MEMORY_MANAGER.with(|memory_manager| {
            neurons::StableNeuronStoreBuilder {
                main: memory_manager.borrow().get(MAIN_NEURONS_MEMORY_ID),

                // Collections
                hot_keys: memory_manager.borrow().get(HOT_KEYS_NEURONS_MEMORY_ID),
                followees : memory_manager.borrow().get(FOLLOWEES_NEURONS_MEMORY_ID),
                recent_ballots : memory_manager.borrow().get(RECENT_BALLOTS_NEURONS_MEMORY_ID),

                // Singletons
                known_neuron_data : memory_manager.borrow().get(KNOWN_NEURON_DATA_NEURONS_MEMORY_ID),
                transfer : memory_manager.borrow().get(TRANSFER_NEURONS_MEMORY_ID),
            }
            .build()
        });
}
