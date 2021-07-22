use crate::{
    embedders::{PersistenceType, MAX_FUNCTIONS, MAX_GLOBALS},
    subnet_config::MAX_INSTRUCTIONS_PER_MESSAGE,
};
use ic_base_types::NumSeconds;
use ic_types::{Cycles, NumBytes, NumInstructions};
use serde::{Deserialize, Serialize};

/// This is the upper limit on how much logical storage canisters can request to
/// be store on a given subnet.
///
/// Logical storage is the amount of storage being used from the point of view
/// of the canister. The actual storage used by the nodes can be higher as the
/// IC protocol requires storing copies of the canister state.
///
/// The gen 1 machines in production will have 3TiB disks. We offer 300GiB to
/// canisters. The rest will be used to for storing additional copies of the
/// canister's data and the deltas.
const SUBNET_MEMORY_CAPACITY: NumBytes = NumBytes::new(300 * 1024 * 1024 * 1024);

/// This is the upper limit on how big heap deltas all the canisters together
/// can produce on a subnet in between checkpoints. Once, the total delta size
/// is above this limit, no more canisters will be executed till the next
/// checkpoint is taken. This is a soft limit in the sense that the actual delta
/// size can grow above this limit but no new execution will be done if the the
/// current size is above this limit.
///
/// The gen 1 machines in production will have 3TiB disks. As this is a soft
/// limit, we do not want to set it too high. The remainder of the storage can
/// be used for storing other copies of the canister states.
pub(crate) const SUBNET_HEAP_DELTA_CAPACITY: NumBytes = NumBytes::new(1024 * 1024 * 1024 * 1024);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default)]
pub struct Config {
    pub persistence_type: PersistenceType,
    /// This is no longer used in the code.  It is not removed yet as removing
    /// this option will be a breaking change.
    pub create_funds_whitelist: String,

    /// The maximum number of instructions that the methods that are invoked to
    /// check message acceptance can run for.
    pub max_instructions_for_message_acceptance_calls: NumInstructions,

    /// The maximum amount of logical storage available to all the canisters on
    /// the subnet.
    pub subnet_memory_capacity: NumBytes,

    /// The maximum amount of memory that can be utilized by a single canister.
    pub max_canister_memory_size: NumBytes,

    /// The maximum amount of cycles a canister can hold.
    /// If set to None, the canisters have no upper limit.
    pub max_cycles_per_canister: Option<Cycles>,

    /// The default value used when provisioning a canister
    /// if amount of cycles was not specified.
    pub default_provisional_cycles_balance: Cycles,

    /// The default number of seconds after which a canister will freeze.
    pub default_freeze_threshold: NumSeconds,

    /// Maximum number of globals allowed in a Wasm module.
    pub max_globals: usize,

    /// Maximum number of functions allowed in a Wasm module.
    pub max_functions: usize,

    /// Maximum number of controllers a canister can have.
    pub max_controllers: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            persistence_type: PersistenceType::Sigsegv,
            create_funds_whitelist: String::default(),
            max_instructions_for_message_acceptance_calls: MAX_INSTRUCTIONS_PER_MESSAGE,
            subnet_memory_capacity: SUBNET_MEMORY_CAPACITY,
            // A canister's memory size can be at most 8GiB (4GiB heap + 4GiB stable memory).
            max_canister_memory_size: NumBytes::new(8 * 1024 * 1024 * 1024),
            // Canisters on the system subnet are not capped.
            // They can hold an amount of cycles that goes above this limit.
            // If this limit is set to None, canisters can hold any amount of cycles.
            max_cycles_per_canister: None,
            default_provisional_cycles_balance: Cycles::new(100_000_000_000_000),
            // The default freeze threshold is 30 days.
            default_freeze_threshold: NumSeconds::from(30 * 24 * 60 * 60),
            max_globals: MAX_GLOBALS,
            max_functions: MAX_FUNCTIONS,
            // Maximum number of controllers allowed in a request (specified in the public
            // Spec).
            max_controllers: 10,
        }
    }
}
