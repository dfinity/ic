use crate::{
    embedders::{PersistenceType, QUERY_EXECUTION_THREADS},
    flag_status::FlagStatus,
    subnet_config::MAX_INSTRUCTIONS_PER_MESSAGE,
};
use ic_base_types::NumSeconds;
use ic_types::{
    Cycles, NumBytes, NumInstructions, MAX_STABLE_MEMORY_IN_BYTES, MAX_WASM_MEMORY_IN_BYTES,
};
use serde::{Deserialize, Serialize};

const GB: u64 = 1024 * 1024 * 1024;

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
const SUBNET_MEMORY_CAPACITY: NumBytes = NumBytes::new(300 * GB);

/// This is the upper limit on how big heap deltas all the canisters together
/// can produce on a subnet in between checkpoints. Once, the total delta size
/// is above this limit, no more canisters will be executed till the next
/// checkpoint is taken. This is a soft limit in the sense that the actual delta
/// size can grow above this limit but no new execution will be done if the the
/// current size is above this limit.
///
/// Currently heap delta pages are stored in memory and not backed by a file.
/// The gen 1 machines in production have 500GiB of RAM available to replica.
/// Set the upper limit to 200GiB to reserve memory for other components and
/// potential fragmentation. This limit should be larger than the maximum
/// canister memory size to guarantee that a message that overwrites the whole
/// memory can succeed.
pub(crate) const SUBNET_HEAP_DELTA_CAPACITY: NumBytes = NumBytes::new(200 * GB);

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

    /// The default value used when provisioning a canister
    /// if amount of cycles was not specified.
    pub default_provisional_cycles_balance: Cycles,

    /// The default number of seconds after which a canister will freeze.
    pub default_freeze_threshold: NumSeconds,

    /// Maximum number of controllers a canister can have.
    pub max_controllers: usize,

    /// Indicates whether canisters sandboxing is enabled or not.
    pub canister_sandboxing_flag: FlagStatus,

    /// The number of threads to use for query execution.
    pub query_execution_threads: usize,
}

impl Default for Config {
    fn default() -> Self {
        // Change this value to enable/disable canister sandboxing by default.
        // EXC-523: Sandboxing is currently available only on Linux because it
        // uses `memfd` files.
        #[cfg(target_os = "linux")]
        let canister_sandboxing_flag = FlagStatus::Enabled;
        #[cfg(not(target_os = "linux"))]
        let canister_sandboxing_flag = FlagStatus::Disabled;

        Self {
            persistence_type: PersistenceType::Sigsegv,
            create_funds_whitelist: String::default(),
            max_instructions_for_message_acceptance_calls: MAX_INSTRUCTIONS_PER_MESSAGE,
            subnet_memory_capacity: SUBNET_MEMORY_CAPACITY,
            max_canister_memory_size: NumBytes::new(
                MAX_STABLE_MEMORY_IN_BYTES + MAX_WASM_MEMORY_IN_BYTES,
            ),
            default_provisional_cycles_balance: Cycles::new(100_000_000_000_000),
            // The default freeze threshold is 30 days.
            default_freeze_threshold: NumSeconds::from(30 * 24 * 60 * 60),
            // Maximum number of controllers allowed in a request (specified in the public
            // Spec).
            max_controllers: 10,
            canister_sandboxing_flag,
            query_execution_threads: QUERY_EXECUTION_THREADS,
        }
    }
}
