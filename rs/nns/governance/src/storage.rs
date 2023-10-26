use crate::{
    governance::LOG_PREFIX,
    pb::v1::{AuditEvent, Topic},
};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    BoundedStorable, DefaultMemoryImpl, Memory, StableLog, Storable,
};
use std::{borrow::Cow, cell::RefCell};

/// Constants to define memory segments.  Must not change.
const UPGRADES_MEMORY_ID: MemoryId = MemoryId::new(0);
const AUDIT_EVENTS_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const AUDIT_EVENTS_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);

const MAIN_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(3);
const HOT_KEYS_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(4);
const FOLLOWEES_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(5);
const RECENT_BALLOTS_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(6);
const KNOWN_NEURON_DATA_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(7);
const TRANSFER_NEURONS_MEMORY_ID: MemoryId = MemoryId::new(8);

const NEURON_SUBACCOUNT_INDEX_MEMORY_ID: MemoryId = MemoryId::new(9);
const NEURON_PRINCIPAL_INDEX_MEMORY_ID: MemoryId = MemoryId::new(10);
const NEURON_FOLLOWING_INDEX_MEMORY_ID: MemoryId = MemoryId::new(11);
const NEURON_KNOWN_NEURON_INDEX_MEMORY_ID: MemoryId = MemoryId::new(12);

pub mod neuron_indexes;
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
            let memory_manager = memory_manager.borrow();
            RefCell::new(
                StableLog::init(
                    memory_manager.get(AUDIT_EVENTS_INDEX_MEMORY_ID),
                    memory_manager.get(AUDIT_EVENTS_DATA_MEMORY_ID),
                )
                .expect("Failed to initialize stable log"),
            )
        });

    pub(crate) static STABLE_NEURON_STORE: RefCell<neurons::StableNeuronStore<VM>> =
        MEMORY_MANAGER.with(|memory_manager| {
            let memory_manager = memory_manager.borrow();

            let stable_neuron_store = neurons::StableNeuronStoreBuilder {
                main: memory_manager.get(MAIN_NEURONS_MEMORY_ID),

                // Collections
                hot_keys: memory_manager.get(HOT_KEYS_NEURONS_MEMORY_ID),
                followees: memory_manager.get(FOLLOWEES_NEURONS_MEMORY_ID),
                recent_ballots: memory_manager.get(RECENT_BALLOTS_NEURONS_MEMORY_ID),

                // Singletons
                known_neuron_data: memory_manager.get(KNOWN_NEURON_DATA_NEURONS_MEMORY_ID),
                transfer: memory_manager.get(TRANSFER_NEURONS_MEMORY_ID),
            }
            .build();

            RefCell::new(stable_neuron_store)
        });

    pub(crate) static NEURON_INDEXES: RefCell<neuron_indexes::StableNeuronIndexes<VM>> = MEMORY_MANAGER
        .with(|memory_manager| {
            let memory_manager = memory_manager.borrow();
            RefCell::new(
                neuron_indexes::StableNeuronIndexesBuilder {
                    subaccount: memory_manager.get(NEURON_SUBACCOUNT_INDEX_MEMORY_ID),
                    principal: memory_manager.get(NEURON_PRINCIPAL_INDEX_MEMORY_ID),
                    following: memory_manager.get(NEURON_FOLLOWING_INDEX_MEMORY_ID),
                    known_neuron: memory_manager.get(NEURON_KNOWN_NEURON_INDEX_MEMORY_ID),
                }
                .build(),
            )
        });
}

pub fn grow_upgrades_memory_to(target_pages: u64) {
    UPGRADES_MEMORY.with(|upgrades_memory| {
        let upgrades_memory = upgrades_memory.borrow();
        let current_size = upgrades_memory.size();
        let diff = target_pages.saturating_sub(current_size);
        if diff == 0 {
            return;
        }

        let previous_size = upgrades_memory.grow(diff);
        if previous_size == -1 {
            println!(
                "{}WARNING: failed to grow upgrades memory by {} pages while current size is {}",
                LOG_PREFIX, diff, current_size
            );
        } else {
            let size_after_growth = upgrades_memory.size();
            println!(
                "{}Successfully grew upgrades memory by {} pages, size after growth: {}",
                LOG_PREFIX, diff, size_after_growth
            );
        }
    });
}

// Implement BoundedStorable
// =========================

// Signed32
// --------

// ic_stable_structures should implement (Bounded)Storable on i32, but does not. Therefore, we do it
// here. Unfortunately, we must wrap it first, because only ic_stable_structures can implement their
// traits on foreign types, such as i32.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signed32(pub i32);

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

// The choice of little endian is somewhat arbitrary here; native or big endian would also be fine.
// Little endian is chosen simply because that is what WASM uses:
// https://webassembly.org/docs/portability/
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

// Types used in both NeuronStore and NeuronIndexes.  This indicates the need for some refactoring
// so that neuron indexes are correctly owned by NeuronStore, which is blocked by changes needed in
// Governance.
pub type NeuronIdU64 = u64;
pub type TopicSigned32 = Signed32;

impl From<Topic> for TopicSigned32 {
    fn from(topic: Topic) -> Self {
        Self(topic as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grow_upgrades_memory_to_success() {
        grow_upgrades_memory_to(10);
        UPGRADES_MEMORY.with(|upgrades_memory| {
            assert_eq!(upgrades_memory.borrow().size(), 10);
        });
    }

    #[test]
    fn grow_upgrades_memory_to_smaller_no_op() {
        grow_upgrades_memory_to(20);
        UPGRADES_MEMORY.with(|upgrades_memory| {
            assert_eq!(upgrades_memory.borrow().size(), 20);
        });

        grow_upgrades_memory_to(10);
        UPGRADES_MEMORY.with(|upgrades_memory| {
            assert_eq!(upgrades_memory.borrow().size(), 20);
        });
    }

    #[test]
    fn grow_upgrades_memory_to_fails() {
        grow_upgrades_memory_to(10);
        UPGRADES_MEMORY.with(|upgrades_memory| {
            assert_eq!(upgrades_memory.borrow().size(), 10);
        });

        // Try to grow to 2^22 + 1, where 2^22 is the max number of pages allowed by stable
        // structures memory manager. It's very unlikely that we want to grow to this number, but
        // this test is just to make sure that we do not panic here.
        grow_upgrades_memory_to(4_194_305);
        UPGRADES_MEMORY.with(|upgrades_memory| {
            assert_eq!(upgrades_memory.borrow().size(), 10);
        });
    }
}
