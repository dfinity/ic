use crate::pb::v1::AuditEvent;

use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    BoundedStorable, DefaultMemoryImpl, StableLog, Storable,
};
use std::{borrow::Cow, cell::RefCell};

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
                followees: memory_manager.borrow().get(FOLLOWEES_NEURONS_MEMORY_ID),
                recent_ballots: memory_manager.borrow().get(RECENT_BALLOTS_NEURONS_MEMORY_ID),

                // Singletons
                known_neuron_data: memory_manager.borrow().get(KNOWN_NEURON_DATA_NEURONS_MEMORY_ID),
                transfer: memory_manager.borrow().get(TRANSFER_NEURONS_MEMORY_ID),
            }
            .build()
        });
}

// Implement BoundedStorable
// -------------------------

// ic_stable_structures should implement (Bounded)Storable on i32, but does
// not. Therefore, we do it here. Unfortunately, we must wrap it first, because
// only ic_stable_structures can implement their traits on foreign types (and
// i32 does not blong to us either).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Signed32(pub i32);

impl Signed32 {
    const MIN: Signed32 = Signed32(i32::MIN);
    const MAX: Signed32 = Signed32(i32::MAX);
}

impl From<i32> for Signed32 {
    fn from(source: i32) -> Self {
        Self(source)
    }
}

impl From<Signed32> for i32 {
    fn from(source: Signed32) -> i32 {
        source.0
    }
}

// The choice of little endian is somewhat arbitrary here; native or big endian
// would also be fine. Little endian is chosen simply because that is what WASM
// uses: https://webassembly.org/docs/portability/
impl Storable for Signed32 {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let serialized = Vec::from(self.0.to_le_bytes());
        Cow::from(serialized)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        let bytes = <[u8; Signed32::MAX_SIZE as usize]>::try_from(&bytes[..])
            .expect("Unable to convert to array (of size 4) to i32 for Signed32.");
        Self(i32::from_le_bytes(bytes))
    }
}

impl BoundedStorable for Signed32 {
    const IS_FIXED_SIZE: bool = true;
    const MAX_SIZE: u32 =
        // A very long-winded way of saying "4".
        std::mem::size_of::<i32>() as u32;
}
