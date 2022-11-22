//! This module implements support for static configurations for components that
//! can be different for different subnet types.

use std::time::Duration;

use crate::execution_environment::SUBNET_HEAP_DELTA_CAPACITY;
use ic_base_types::NumBytes;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Cycles, NumInstructions};
use serde::{Deserialize, Serialize};

const B: u64 = 1_000_000_000;
const M: u64 = 1_000_000;

// The limit on the number of instructions a message is allowed to executed.
// Going above the limit results in an `InstructionLimitExceeded` error.
pub(crate) const MAX_INSTRUCTIONS_PER_MESSAGE: NumInstructions = NumInstructions::new(10 * B);

// The limit on the number of instructions a message is allowed to execute
// without deterministic time slicing.
// Going above the limit results in an `InstructionLimitExceeded` error.
pub(crate) const MAX_INSTRUCTIONS_PER_MESSAGE_WITHOUT_DTS: NumInstructions =
    NumInstructions::new(5 * B);

// The limit on the number of instructions a slice is allowed to executed.
// If deterministic time slicing is enabled, then going above this limit
// causes the Wasm execution to pause until the next slice.
// If deterministic time slicing is disabled, then this limit is ignored and
// `MAX_INSTRUCTIONS_PER_MESSAGE` is used for execution of the single slice.
// We assume 1 cycles unit ≅ 1 CPU cycle, so on a 2 GHz CPU one slice has
// approximately 1 second to be processed.
const MAX_INSTRUCTIONS_PER_SLICE: NumInstructions = NumInstructions::new(2 * B);

// We assume 1 cycles unit ≅ 1 CPU cycle, so on a 2 GHz CPU it takes
// at most 1ms to enter and exit the Wasm engine.
const INSTRUCTION_OVERHEAD_PER_MESSAGE: NumInstructions = NumInstructions::new(2 * M);

// Metrics show that finalization can take 13ms when there were 5000 canisters
// in a subnet. This comes out to about 3us per canister which comes out to
// 6_000 instructions based on the 1 cycles unit ≅ 1 CPU cycle, 2 GHz CPU
// calculations. Round this up to 12_000 to be on the safe side.
const INSTRUCTION_OVERHEAD_PER_CANISTER_FOR_FINALIZATION: NumInstructions =
    NumInstructions::new(12_000);

// If messages are short, then we expect about 2B=(7B - 5B) instructions to run
// in a round in about 1 second. Short messages followed by one long message
// would cause the longest possible round of 7B instructions or 3.5 seconds.
//
// In general, the round limit should be close to
// `message_limit + 2B * (1 / finalization_rate)` which ensures that
// 1) execution does not slow down finalization.
// 2) execution does not waste the time available per round.
const MAX_INSTRUCTIONS_PER_ROUND: NumInstructions = NumInstructions::new(7 * B);

// Limit per `install_code` message. It's bigger than the limit for a regular
// update call to allow for canisters with bigger state to be upgraded.
// This is a temporary measure until a longer term solution that alleviates the
// limitations with the current upgrade process is implemented.
//
// The value is picked to allow roughly for 4GB of state to be stored to stable
// memory during upgrade. We know that we hit `MAX_INSTRUCTIONS_PER_MESSAGE`
// with roughly 100MB of state, so we set the limit to 40x.
const MAX_INSTRUCTIONS_PER_INSTALL_CODE: NumInstructions = NumInstructions::new(40 * 5 * B);

// The limit on the number of instructions a slice of an `install_code` message
// is allowed to executed.
//
// If deterministic time slicing is enabled, then going above this limit
// causes the Wasm execution to pause until the next slice.
//
// If deterministic time slicing is disabled, then this limit is ignored and
// `MAX_INSTRUCTIONS_PER_INSTALL_CODE` is used for execution of the
// single slice.
const MAX_INSTRUCTIONS_PER_INSTALL_CODE_SLICE: NumInstructions = NumInstructions::new(2 * B);

// The factor to bump the instruction limit for system subnets.
const SYSTEM_SUBNET_FACTOR: u64 = 10;

// The maximum amount of heap delta per iteration. Data from production shows
// memory throughput of 100MB/s. Subnets run with different finalization rate,
// so a round may take 1 to 4 seconds. To avoid regressing the throughput of
// slow subnets while maintaining the speed of fast subnets, we use the middle
// value of 200MB.
const MAX_HEAP_DELTA_PER_ITERATION: NumBytes = NumBytes::new(200 * M);

// Log all messages that took more than this value to execute.
pub const MAX_MESSAGE_DURATION_BEFORE_WARN_IN_SECONDS: f64 = 5.0;

// The gen 1 production machines should have 64 cores.
// We could in theory use 32 threads, leaving other threads for query handling,
// Wasm compilation, and other replica components. We currently use only four
// threads for two reasons:
// 1) Due to poor scaling of syscalls and signals with the number of threads
//    in a process, four threads yield the maximum overall execution throughput.
// 2) The memory capacity of a subnet is divided between the number of threads.
//    We needs to ensure:
//    `SUBNET_MEMORY_CAPACITY / number_of_threads >= max_canister_memory`
//    If you change this number please adjust other constants as well.
const NUMBER_OF_EXECUTION_THREADS: usize = 4;

/// Maximum number of concurrent long-running executions.
/// In the worst case there will be no more than 11 running canisters during the round:
///
///   long installs + long updates + scheduler cores + query threads = 1 + 4 + 4 + 2 = 11
///
/// And no more than 7 running canisters in between the rounds:
///
///   long installs + long updates + query threads = 1 + 4 + 2 = 7
///
const MAX_PAUSED_EXECUTIONS: usize = 4;

/// 10B cycles corresponds to 1 SDR cent. Assuming we can create 1 signature per
/// second, that would come to  26k SDR per month if we spent the whole time
/// creating signatures. At 13 nodes and 2k SDR per node per month this would
/// cover the cost of the subnet.
pub const ECDSA_SIGNATURE_FEE: Cycles = Cycles::new(10 * B as u128);

/// Default subnet size which is used to scale cycles cost according to a subnet replication factor.
///
/// All initial costs were calculated with the assumption that a subnet had 13 replicas.
const DEFAULT_REFERENCE_SUBNET_SIZE: usize = 13;

/// Costs for each newly created dirty page in stable memory.
const DEFAULT_DIRTY_PAGE_OVERHEAD: NumInstructions = NumInstructions::new(1_000);
const SYSTEM_SUBNET_DIRTY_PAGE_OVERHEAD: NumInstructions = NumInstructions::new(0);

/// The per subnet type configuration for the scheduler component
#[derive(Clone)]
pub struct SchedulerConfig {
    /// Number of canisters that the scheduler is allowed to schedule in
    /// parallel.
    pub scheduler_cores: usize,

    /// Maximum number of concurrent paused long-running install updates.
    /// After each round there might be some pending long update executions.
    /// Pending executions above this limit will be aborted and restarted later,
    /// once scheduled.
    ///
    /// Note: this number does not limit the number of queries or short executions.
    pub max_paused_executions: usize,

    /// Maximum amount of instructions a single round can consume (on one
    /// thread).
    pub max_instructions_per_round: NumInstructions,

    /// Maximum amount of instructions a single message execution can consume.
    pub max_instructions_per_message: NumInstructions,

    /// Maximum amount of instructions a single message execution can consume
    /// without deterministic time slicing.
    pub max_instructions_per_message_without_dts: NumInstructions,

    /// Maximum amount of instructions a single slice of execution can consume.
    /// This should not exceed `max_instructions_per_round`.
    pub max_instructions_per_slice: NumInstructions,

    /// The overhead of entering and exiting the Wasm engine to execute a
    /// message. The overhead is measured in instructions that are counted
    /// towards the round limit.
    pub instruction_overhead_per_message: NumInstructions,

    /// The overhead (per canister) of running the finalization code at the end
    /// of an iteration. This overhead is counted toward the round limit at the
    /// end of each iteration. Since finalization is mostly looping over all
    /// canisters, we estimate the cost per canister and multiply by the number
    /// of active canisters to get the total overhead.
    pub instruction_overhead_per_canister_for_finalization: NumInstructions,

    /// Maximum number of instructions an `install_code` message can consume.
    pub max_instructions_per_install_code: NumInstructions,

    /// Maximum number of instructions a single slice of `install_code` message
    /// can consume. This should not exceed `max_instructions_per_install_code`.
    pub max_instructions_per_install_code_slice: NumInstructions,

    /// This specifies the upper limit on how much heap delta all the canisters
    /// together on the subnet can produce in between checkpoints. This is a
    /// soft limit in the sense, that we will continue to execute canisters as
    /// long the current delta size is below this limit and stop if the current
    /// size is above this limit. Hence, it is possible that the actual usage of
    /// the subnet goes above this limit.
    pub subnet_heap_delta_capacity: NumBytes,

    /// The maximum amount of heap delta per iteration. This number if checked
    /// after each iteration in an execution round to decided whether to
    /// continue iterations or not. This serves as a proxy for memory bound
    /// instructions that are more expensive and may slow down finalization.
    pub max_heap_delta_per_iteration: NumBytes,

    /// This value is used to decide whether to emit a warn log after
    /// message execution or not.
    /// Once execution duration of a message exceeds this value,
    /// specific information about the message is logged as a warn.
    pub max_message_duration_before_warn_in_seconds: f64,

    /// Denotes how much heap delta each canister is allowed to generate per
    /// round. Canisters may go over this limit in a single round, but will
    /// then not run for several rounds until they are back under the allowed
    /// rate.
    pub heap_delta_rate_limit: NumBytes,

    /// Denotes how many instructions each canister is allowed to execute in
    /// install_code messages per round. Canisters may go over this limit in a
    /// single round, but will then reject install_code messages for several
    /// rounds until they are back under the allowed rate.
    pub install_code_rate_limit: NumInstructions,

    /// Cost for each newly created dirty page in stable memory.
    pub dirty_page_overhead: NumInstructions,
}

impl SchedulerConfig {
    pub fn application_subnet() -> Self {
        Self {
            scheduler_cores: NUMBER_OF_EXECUTION_THREADS,
            max_paused_executions: MAX_PAUSED_EXECUTIONS,
            subnet_heap_delta_capacity: SUBNET_HEAP_DELTA_CAPACITY,
            max_instructions_per_round: MAX_INSTRUCTIONS_PER_ROUND,
            max_instructions_per_message: MAX_INSTRUCTIONS_PER_MESSAGE,
            max_instructions_per_message_without_dts: MAX_INSTRUCTIONS_PER_MESSAGE_WITHOUT_DTS,
            max_instructions_per_slice: MAX_INSTRUCTIONS_PER_SLICE,
            instruction_overhead_per_message: INSTRUCTION_OVERHEAD_PER_MESSAGE,
            instruction_overhead_per_canister_for_finalization:
                INSTRUCTION_OVERHEAD_PER_CANISTER_FOR_FINALIZATION,
            max_instructions_per_install_code: MAX_INSTRUCTIONS_PER_INSTALL_CODE,
            max_instructions_per_install_code_slice: MAX_INSTRUCTIONS_PER_INSTALL_CODE_SLICE,
            max_heap_delta_per_iteration: MAX_HEAP_DELTA_PER_ITERATION,
            max_message_duration_before_warn_in_seconds:
                MAX_MESSAGE_DURATION_BEFORE_WARN_IN_SECONDS,
            heap_delta_rate_limit: NumBytes::from(75 * 1024 * 1024),
            install_code_rate_limit: MAX_INSTRUCTIONS_PER_SLICE,
            dirty_page_overhead: DEFAULT_DIRTY_PAGE_OVERHEAD,
        }
    }

    pub fn system_subnet() -> Self {
        let max_instructions_per_message_without_dts =
            MAX_INSTRUCTIONS_PER_MESSAGE_WITHOUT_DTS * SYSTEM_SUBNET_FACTOR;
        let max_instructions_per_install_code = NumInstructions::from(1_000 * B);
        Self {
            scheduler_cores: NUMBER_OF_EXECUTION_THREADS,
            max_paused_executions: MAX_PAUSED_EXECUTIONS,
            subnet_heap_delta_capacity: SUBNET_HEAP_DELTA_CAPACITY,
            max_instructions_per_round: MAX_INSTRUCTIONS_PER_ROUND * SYSTEM_SUBNET_FACTOR,
            // Effectively disable DTS on system subnets.
            max_instructions_per_message: max_instructions_per_message_without_dts,
            max_instructions_per_message_without_dts,
            // Effectively disable DTS on system subnets.
            max_instructions_per_slice: max_instructions_per_message_without_dts,
            instruction_overhead_per_message: INSTRUCTION_OVERHEAD_PER_MESSAGE,
            instruction_overhead_per_canister_for_finalization:
                INSTRUCTION_OVERHEAD_PER_CANISTER_FOR_FINALIZATION,
            max_instructions_per_install_code,
            // Effectively disable DTS on system subnets.
            max_instructions_per_install_code_slice: max_instructions_per_install_code,
            max_heap_delta_per_iteration: MAX_HEAP_DELTA_PER_ITERATION * SYSTEM_SUBNET_FACTOR,
            max_message_duration_before_warn_in_seconds:
                MAX_MESSAGE_DURATION_BEFORE_WARN_IN_SECONDS,
            // This limit should be high enough (1000T) to effectively disable
            // rate-limiting for the system subnets.
            heap_delta_rate_limit: NumBytes::from(1_000_000_000_000_000),
            // This limit should be high enough (1000T) to effectively disable
            // rate-limiting for the system subnets.
            install_code_rate_limit: NumInstructions::from(1_000_000_000_000_000),
            dirty_page_overhead: SYSTEM_SUBNET_DIRTY_PAGE_OVERHEAD,
        }
    }

    pub fn verified_application_subnet() -> Self {
        Self {
            scheduler_cores: NUMBER_OF_EXECUTION_THREADS,
            max_paused_executions: MAX_PAUSED_EXECUTIONS,
            subnet_heap_delta_capacity: SUBNET_HEAP_DELTA_CAPACITY,
            max_instructions_per_round: MAX_INSTRUCTIONS_PER_ROUND,
            max_instructions_per_message: MAX_INSTRUCTIONS_PER_MESSAGE,
            max_instructions_per_message_without_dts: MAX_INSTRUCTIONS_PER_MESSAGE_WITHOUT_DTS,
            max_instructions_per_slice: MAX_INSTRUCTIONS_PER_SLICE,
            instruction_overhead_per_message: INSTRUCTION_OVERHEAD_PER_MESSAGE,
            instruction_overhead_per_canister_for_finalization:
                INSTRUCTION_OVERHEAD_PER_CANISTER_FOR_FINALIZATION,
            max_instructions_per_install_code: MAX_INSTRUCTIONS_PER_INSTALL_CODE,
            max_instructions_per_install_code_slice: MAX_INSTRUCTIONS_PER_INSTALL_CODE_SLICE,
            max_heap_delta_per_iteration: MAX_HEAP_DELTA_PER_ITERATION,
            max_message_duration_before_warn_in_seconds:
                MAX_MESSAGE_DURATION_BEFORE_WARN_IN_SECONDS,
            heap_delta_rate_limit: NumBytes::from(75 * 1024 * 1024),
            install_code_rate_limit: MAX_INSTRUCTIONS_PER_SLICE,
            dirty_page_overhead: DEFAULT_DIRTY_PAGE_OVERHEAD,
        }
    }

    pub fn default_for_subnet_type(subnet_type: SubnetType) -> Self {
        match subnet_type {
            SubnetType::Application => Self::application_subnet(),
            SubnetType::System => Self::system_subnet(),
            SubnetType::VerifiedApplication => Self::verified_application_subnet(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct CyclesAccountManagerConfig {
    /// Reference value of a subnet size that all the fees below are calculated for.
    /// Fees for a real subnet are calculated proportionally to this reference value.
    pub reference_subnet_size: usize,

    /// Fee for creating canisters on a subnet
    pub canister_creation_fee: Cycles,

    /// Fee for every update message executed
    pub update_message_execution_fee: Cycles,

    /// Fee for every 10 instructions executed when executing update type
    /// messages. The reason for using 10 and not 1 is so support fees of less
    /// than 1 cycles per instruction.
    pub ten_update_instructions_execution_fee: Cycles,

    /// Fee for every inter-canister call performed. This includes the fee for
    /// sending the request and receiving the response.
    pub xnet_call_fee: Cycles,

    /// Fee for every byte sent in an inter-canister call. The fee is for bytes
    /// sent in the request and response.
    pub xnet_byte_transmission_fee: Cycles,

    /// Fee for every ingress message received.
    pub ingress_message_reception_fee: Cycles,

    /// Fee for every byte received in an ingress message.
    pub ingress_byte_reception_fee: Cycles,

    /// Fee for storing a GiB of data per second.
    pub gib_storage_per_second_fee: Cycles,

    /// Fee for each percent of the reserved compute allocation. Note that
    /// reserved compute allocation is a scarce resource, and should be
    /// appropriately charged for.
    pub compute_percent_allocated_per_second_fee: Cycles,

    /// How often to charge canisters for memory and compute allocations.
    pub duration_between_allocation_charges: Duration,

    /// Amount to charge for an ECDSA signature.
    pub ecdsa_signature_fee: Cycles,

    /// Baseline cost to charge for HTTP request.
    pub http_request_baseline_fee: Cycles,

    /// Fee per byte for networking and consensus work done for a http request or response.
    pub http_request_per_byte_fee: Cycles,
}

impl CyclesAccountManagerConfig {
    pub fn application_subnet() -> Self {
        Self::verified_application_subnet()
    }

    pub fn verified_application_subnet() -> Self {
        Self {
            reference_subnet_size: DEFAULT_REFERENCE_SUBNET_SIZE,
            canister_creation_fee: Cycles::new(100_000_000_000),
            compute_percent_allocated_per_second_fee: Cycles::new(10_000_000),

            // The following fields are set based on a thought experiment where
            // we estimated how many resources a representative benchmark on a
            // verified subnet is using.
            update_message_execution_fee: Cycles::new(590_000),
            ten_update_instructions_execution_fee: Cycles::new(4),
            xnet_call_fee: Cycles::new(260_000),
            xnet_byte_transmission_fee: Cycles::new(1_000),
            ingress_message_reception_fee: Cycles::new(1_200_000),
            ingress_byte_reception_fee: Cycles::new(2_000),
            // 4 SDR per GiB per year => 4e12 Cycles per year
            gib_storage_per_second_fee: Cycles::new(127_000),
            duration_between_allocation_charges: Duration::from_secs(10),
            ecdsa_signature_fee: ECDSA_SIGNATURE_FEE,
            http_request_baseline_fee: Cycles::new(400_000_000),
            http_request_per_byte_fee: Cycles::new(100_000),
        }
    }

    /// All processing is free on system subnets
    pub fn system_subnet() -> Self {
        Self {
            reference_subnet_size: DEFAULT_REFERENCE_SUBNET_SIZE,
            canister_creation_fee: Cycles::new(0),
            compute_percent_allocated_per_second_fee: Cycles::new(0),
            update_message_execution_fee: Cycles::new(0),
            ten_update_instructions_execution_fee: Cycles::new(0),
            xnet_call_fee: Cycles::new(0),
            xnet_byte_transmission_fee: Cycles::new(0),
            ingress_message_reception_fee: Cycles::new(0),
            ingress_byte_reception_fee: Cycles::new(0),
            gib_storage_per_second_fee: Cycles::new(0),
            duration_between_allocation_charges: Duration::from_secs(10),
            /// The ECDSA signature fee is the fee charged when creating a
            /// signature on this subnet. The request likely came from a
            /// different subnet which is not a system subnet. There is an
            /// explicit exception for requests originating from the NNS when the
            /// charging occurs.
            ecdsa_signature_fee: ECDSA_SIGNATURE_FEE,
            http_request_baseline_fee: Cycles::new(0),
            http_request_per_byte_fee: Cycles::new(0),
        }
    }
}

/// The per subnet type configuration for CoW Memory Manager
#[derive(Clone)]
pub struct CowMemoryManagerConfig {
    /// Flag to enable or disable the feature
    pub enabled: bool,
}

impl CowMemoryManagerConfig {
    pub fn application_subnet() -> Self {
        Self { enabled: false }
    }

    pub fn system_subnet() -> Self {
        Self { enabled: false }
    }

    pub fn verified_application_subnet() -> Self {
        Self { enabled: false }
    }
}

/// If a component has at least one static configuration that is different for
/// different subnet types, then it is included in this struct.
#[derive(Clone)]
pub struct SubnetConfig {
    pub scheduler_config: SchedulerConfig,
    pub cycles_account_manager_config: CyclesAccountManagerConfig,
    pub cow_memory_manager_config: CowMemoryManagerConfig,
}

impl SubnetConfig {
    /// Returns the subnet configuration for the application subnet type.
    pub fn default_application_subnet() -> Self {
        Self {
            scheduler_config: SchedulerConfig::application_subnet(),
            cycles_account_manager_config: CyclesAccountManagerConfig::application_subnet(),
            cow_memory_manager_config: CowMemoryManagerConfig::application_subnet(),
        }
    }

    /// Returns the subnet configuration for the system subnet type.
    pub fn default_system_subnet() -> Self {
        Self {
            scheduler_config: SchedulerConfig::system_subnet(),
            cycles_account_manager_config: CyclesAccountManagerConfig::system_subnet(),
            cow_memory_manager_config: CowMemoryManagerConfig::system_subnet(),
        }
    }

    /// Returns the subnet configuration for the verified application subnet
    /// type.
    pub fn default_verified_application_subnet() -> Self {
        Self {
            scheduler_config: SchedulerConfig::verified_application_subnet(),
            cycles_account_manager_config: CyclesAccountManagerConfig::verified_application_subnet(
            ),
            cow_memory_manager_config: CowMemoryManagerConfig::verified_application_subnet(),
        }
    }
}

/// A struct that holds the per subnet configuration for all the subnet types on
/// the internet computer.
pub struct SubnetConfigs {
    system_subnet: SubnetConfig,
    application_subnet: SubnetConfig,
    verified_application_subnet: SubnetConfig,
}

impl Default for SubnetConfigs {
    fn default() -> Self {
        Self {
            system_subnet: SubnetConfig::default_system_subnet(),
            application_subnet: SubnetConfig::default_application_subnet(),
            verified_application_subnet: SubnetConfig::default_verified_application_subnet(),
        }
    }
}

impl SubnetConfigs {
    /// Returns the appropriate subnet configuration based on the subnet type.
    pub fn own_subnet_config(&self, own_subnet_type: SubnetType) -> SubnetConfig {
        match own_subnet_type {
            SubnetType::Application => self.application_subnet.clone(),
            SubnetType::System => self.system_subnet.clone(),
            SubnetType::VerifiedApplication => self.verified_application_subnet.clone(),
        }
    }
}
