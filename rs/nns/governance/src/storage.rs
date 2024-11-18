use crate::{governance::LOG_PREFIX, pb::v1::AuditEvent};

use crate::{pb::v1::ArchivedMonthlyNodeProviderRewards, voting::VotingStateMachines};
use ic_cdk::println;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, Memory, StableBTreeMap, StableLog, Storable,
};
use std::cell::RefCell;

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
const NEURON_ACCOUNT_ID_INDEX_MEMORY_ID: MemoryId = MemoryId::new(13);

const NODE_PROVIDER_REWARDS_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(14);
const NODE_PROVIDER_REWARDS_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(15);

const VOTING_STATE_MACHINES_MEMORY_ID: MemoryId = MemoryId::new(16);

pub mod neuron_indexes;
pub mod neurons;

type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static STATE: RefCell<State> = RefCell::new(State::new());

    // Cannot be part of STATE because it also needs to borrow things in STATE
    // when being used.
    static VOTING_STATE_MACHINES: RefCell<VotingStateMachines<VM>> = RefCell::new({
       MEMORY_MANAGER.with(|memory_manager| {
            let memory = memory_manager.borrow().get(VOTING_STATE_MACHINES_MEMORY_ID);
            VotingStateMachines::new(memory)
        })
    })
}

struct State {
    // The memory where the governance reads and writes its state during an upgrade.
    upgrades_memory: VM,

    // Events for audit purposes.
    audit_events_log: StableLog<AuditEvent, VM, VM>,

    // Neurons stored in stable storage.
    stable_neuron_store: neurons::StableNeuronStore<VM>,

    // Neuron indexes stored in stable storage.
    stable_neuron_indexes: neuron_indexes::StableNeuronIndexes<VM>,

    node_provider_rewards_log: StableLog<ArchivedMonthlyNodeProviderRewards, VM, VM>,
}

impl State {
    pub fn new() -> Self {
        let upgrades_memory =
            MEMORY_MANAGER.with(|memory_manager| memory_manager.borrow().get(UPGRADES_MEMORY_ID));
        let audit_events_log = MEMORY_MANAGER.with(|memory_manager| {
            let memory_manager = memory_manager.borrow();
            StableLog::init(
                memory_manager.get(AUDIT_EVENTS_INDEX_MEMORY_ID),
                memory_manager.get(AUDIT_EVENTS_DATA_MEMORY_ID),
            )
            .expect("Failed to initialize stable log for Audit Events")
        });
        let stable_neuron_store = MEMORY_MANAGER.with(|memory_manager| {
            let memory_manager = memory_manager.borrow();
            neurons::StableNeuronStoreBuilder {
                main: memory_manager.get(MAIN_NEURONS_MEMORY_ID),

                // Collections
                hot_keys: memory_manager.get(HOT_KEYS_NEURONS_MEMORY_ID),
                followees: memory_manager.get(FOLLOWEES_NEURONS_MEMORY_ID),
                recent_ballots: memory_manager.get(RECENT_BALLOTS_NEURONS_MEMORY_ID),

                // Singletons
                known_neuron_data: memory_manager.get(KNOWN_NEURON_DATA_NEURONS_MEMORY_ID),
                transfer: memory_manager.get(TRANSFER_NEURONS_MEMORY_ID),
            }
            .build()
        });

        let stable_neuron_indexes = MEMORY_MANAGER.with(|memory_manager| {
            let memory_manager = memory_manager.borrow();
            neuron_indexes::StableNeuronIndexesBuilder {
                subaccount: memory_manager.get(NEURON_SUBACCOUNT_INDEX_MEMORY_ID),
                principal: memory_manager.get(NEURON_PRINCIPAL_INDEX_MEMORY_ID),
                following: memory_manager.get(NEURON_FOLLOWING_INDEX_MEMORY_ID),
                known_neuron: memory_manager.get(NEURON_KNOWN_NEURON_INDEX_MEMORY_ID),
                account_id: memory_manager.get(NEURON_ACCOUNT_ID_INDEX_MEMORY_ID),
            }
            .build()
        });

        let node_provider_rewards_log = MEMORY_MANAGER.with(|memory_manager| {
            let memory_manager = memory_manager.borrow();
            StableLog::init(
                memory_manager.get(NODE_PROVIDER_REWARDS_LOG_INDEX_MEMORY_ID),
                memory_manager.get(NODE_PROVIDER_REWARDS_LOG_DATA_MEMORY_ID),
            )
            .expect("Failed to initialize stable log for NP Rewards")
        });

        Self {
            upgrades_memory,
            audit_events_log,
            stable_neuron_store,
            stable_neuron_indexes,
            node_provider_rewards_log,
        }
    }

    /// Validates that some of the data in stable storage can be read, in order to prevent broken
    /// schema. Should only be called in post_upgrade.
    fn validate(&self) {
        self.stable_neuron_store.validate();
        self.stable_neuron_indexes.validate();
        validate_stable_log(&self.audit_events_log);
        validate_stable_log(&self.node_provider_rewards_log);
    }
}

pub fn with_upgrades_memory<R>(f: impl FnOnce(&VM) -> R) -> R {
    STATE.with(|state| {
        let upgrades_memory = &state.borrow().upgrades_memory;
        f(upgrades_memory)
    })
}

pub(crate) fn with_audit_events_log<R>(f: impl FnOnce(&StableLog<AuditEvent, VM, VM>) -> R) -> R {
    STATE.with(|state| {
        let audit_events_log = &state.borrow().audit_events_log;
        f(audit_events_log)
    })
}

pub(crate) fn with_stable_neuron_store<R>(
    f: impl FnOnce(&neurons::StableNeuronStore<VM>) -> R,
) -> R {
    STATE.with(|state| {
        let stable_neuron_store = &state.borrow().stable_neuron_store;
        f(stable_neuron_store)
    })
}

pub(crate) fn with_stable_neuron_store_mut<R>(
    f: impl FnOnce(&mut neurons::StableNeuronStore<VM>) -> R,
) -> R {
    STATE.with(|state| {
        let stable_neuron_store = &mut state.borrow_mut().stable_neuron_store;
        f(stable_neuron_store)
    })
}

pub(crate) fn with_stable_neuron_indexes<R>(
    f: impl FnOnce(&neuron_indexes::StableNeuronIndexes<VM>) -> R,
) -> R {
    STATE.with(|state| {
        let stable_neuron_indexes = &state.borrow().stable_neuron_indexes;
        f(stable_neuron_indexes)
    })
}

pub(crate) fn with_stable_neuron_indexes_mut<R>(
    f: impl FnOnce(&mut neuron_indexes::StableNeuronIndexes<VM>) -> R,
) -> R {
    STATE.with(|state| {
        let stable_neuron_indexes = &mut state.borrow_mut().stable_neuron_indexes;
        f(stable_neuron_indexes)
    })
}

pub(crate) fn with_node_provider_rewards_log<R>(
    f: impl FnOnce(&StableLog<ArchivedMonthlyNodeProviderRewards, VM, VM>) -> R,
) -> R {
    STATE.with(|state| {
        let node_provider_rewards_log = &state.borrow().node_provider_rewards_log;
        f(node_provider_rewards_log)
    })
}

pub(crate) fn with_voting_state_machines_mut<R>(
    f: impl FnOnce(&mut VotingStateMachines<VM>) -> R,
) -> R {
    VOTING_STATE_MACHINES.with(|voting_state_machines| {
        let voting_state_machines = &mut voting_state_machines.borrow_mut();
        f(voting_state_machines)
    })
}

/// Validates that some of the data in stable storage can be read, in order to prevent broken
/// schema. Should only be called in post_upgrade.
pub fn validate_stable_storage() {
    STATE.with_borrow(|state| state.validate());
}

pub(crate) fn validate_stable_btree_map<Key, Value, M>(btree_map: &StableBTreeMap<Key, Value, M>)
where
    Key: Storable + Ord + Clone,
    Value: Storable,
    M: Memory,
{
    // This is just to verify that any key-value pair can be deserialized without panicking. It is
    // guaranteed to catch all deserialization errors, but should help.
    let _ = btree_map.first_key_value();
}

pub(crate) fn validate_stable_log<Value, M>(log: &StableLog<Value, M, M>)
where
    Value: Storable,
    M: Memory,
{
    // This is just to verify that an early value can be deserialized without panicking. It is not
    // guaranteed to catch all deserialization errors, but should help.
    let _ = log.get(0);
}

// Clears and initializes stable memory and stable structures before testing. Typically only needed
// in proptest! where stable storage data needs to be accessed in multiple iterations within one
// thread.
#[cfg(any(feature = "test", test))]
pub fn reset_stable_memory() {
    MEMORY_MANAGER.with(|mm| *mm.borrow_mut() = MemoryManager::init(DefaultMemoryImpl::default()));
    STATE.with(|cell| *cell.borrow_mut() = State::new());
}

pub fn grow_upgrades_memory_to(target_pages: u64) {
    with_upgrades_memory(|upgrades_memory| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grow_upgrades_memory_to_success() {
        grow_upgrades_memory_to(10);
        with_upgrades_memory(|memory| {
            assert_eq!(memory.size(), 10);
        });
    }

    #[test]
    fn grow_upgrades_memory_to_smaller_no_op() {
        grow_upgrades_memory_to(20);
        with_upgrades_memory(|memory| {
            assert_eq!(memory.size(), 20);
        });

        grow_upgrades_memory_to(10);
        with_upgrades_memory(|memory| {
            assert_eq!(memory.size(), 20);
        });
    }

    #[test]
    fn grow_upgrades_memory_to_fails() {
        grow_upgrades_memory_to(10);
        with_upgrades_memory(|memory| {
            assert_eq!(memory.size(), 10);
        });

        // Try to grow to 2^22 + 1, where 2^22 is the max number of pages allowed by stable
        // structures memory manager. It's very unlikely that we want to grow to this number, but
        // this test is just to make sure that we do not panic here.
        grow_upgrades_memory_to(4_194_305);
        with_upgrades_memory(|memory| {
            assert_eq!(memory.size(), 10);
        });
    }
}
