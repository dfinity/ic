//! This module implements support for static configurations for components that
//! can be different for different subnet types.

use std::time::Duration;

use crate::{
    execution_environment::{NUMBER_OF_EXECUTION_THREADS, SUBNET_HEAP_DELTA_CAPACITY},
    flag_status::FlagStatus,
};
use ic_base_types::NumBytes;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    Cycles, ExecutionRound, NumInstructions, consensus::idkg::STORE_PRE_SIGNATURES_IN_STATE,
};
use serde::{Deserialize, Serialize};

const GIB: u64 = 1024 * 1024 * 1024;
const M: u64 = 1_000_000;
const B: u64 = 1_000_000_000;
const T: u128 = 1_000_000_000_000;

// The limit on the number of instructions a message is allowed to executed.
// Going above the limit results in an `InstructionLimitExceeded` error.
pub(crate) const MAX_INSTRUCTIONS_PER_MESSAGE: NumInstructions = NumInstructions::new(40 * B);

// The limit on the number of instructions a message is allowed to execute
// for a single query or composite query method.
// Going above the limit results in an `InstructionLimitExceeded` error.
pub(crate) const MAX_INSTRUCTIONS_PER_QUERY_MESSAGE: NumInstructions = NumInstructions::new(5 * B);

// The limit on the number of instructions a slice is allowed to executed.
// If deterministic time slicing is enabled, then going above this limit
// causes the Wasm execution to pause until the next slice.
// If deterministic time slicing is disabled, then this limit is ignored and
// `MAX_INSTRUCTIONS_PER_MESSAGE` is used for execution of the single slice.
// We assume 1 cycles unit ≅ 1 CPU cycle, so on a 2 GHz CPU one slice has
// approximately 1 second to be processed.
const MAX_INSTRUCTIONS_PER_SLICE: NumInstructions = NumInstructions::new(2 * B);

// We assume 1 cycles unit ≅ 1 CPU cycle, so on a 2 GHz CPU it takes about 1ms
// to enter and exit the Wasm engine.
const INSTRUCTION_OVERHEAD_PER_EXECUTION: NumInstructions = NumInstructions::new(2 * M);

// We assume 1 cycles unit ≅ 1 CPU cycle, so on a 2 GHz CPU it takes about 4ms
// to prepare execution of a canister.
const INSTRUCTION_OVERHEAD_PER_CANISTER: NumInstructions = NumInstructions::new(8 * M);

// Metrics show that finalization can take 13ms when there were 5000 canisters
// in a subnet. This comes out to about 3us per canister which comes out to
// 6_000 instructions based on the 1 cycles unit ≅ 1 CPU cycle, 2 GHz CPU
// calculations. Round this up to 12_000 to be on the safe side.
const INSTRUCTION_OVERHEAD_PER_CANISTER_FOR_FINALIZATION: NumInstructions =
    NumInstructions::new(12_000);

// The round instruction limit should be close to
// `2B * (1 / finalization_rate)` which ensures that
// 1) execution does not slow down finalization.
// 2) execution does not waste the time available per round.
//
// On application subnets, we expect a finalization rate of around 1 block per second
// and thus we set the round instruction limit to
// `MAX_INSTRUCTIONS_PER_SLICE.max(MAX_INSTRUCTIONS_PER_INSTALL_CODE_SLICE) + NumInstructions::from(2 * B)`.
// We have to hard-code it here due to `const` requirements.
//
// This way, if messages are short (the slice limit is not exhausted),
// then we expect about `2B` instructions to run in a round in about 1 second.
// Short messages followed by one long message (exhausting the slice limit)
// would cause the longest possible round of 4B instructions or 2 seconds.
const MAX_INSTRUCTIONS_PER_ROUND: NumInstructions = NumInstructions::new(4 * B);

// Limit per `install_code` message. It's bigger than the limit for a regular
// update call to allow for canisters with bigger state to be upgraded.
const MAX_INSTRUCTIONS_PER_INSTALL_CODE: NumInstructions = NumInstructions::new(300 * B);

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

/// The reserve represents the freely available portion of the
/// `subnet_heap_delta_capacity` that can be used as a heap delta burst
/// during the initial rounds following a checkpoint.
const HEAP_DELTA_INITIAL_RESERVE: NumBytes = NumBytes::new(32 * GIB);

// Log all messages that took more than this value to execute.
pub const MAX_MESSAGE_DURATION_BEFORE_WARN_IN_SECONDS: f64 = 5.0;

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

/// 10B cycles corresponds to 1 SDR cent. Assuming we can create 1 signature per
/// second, that would come to  26k SDR per month if we spent the whole time
/// creating signatures. At 13 nodes and 2k SDR per node per month this would
/// cover the cost of the subnet.
pub const SCHNORR_SIGNATURE_FEE: Cycles = Cycles::new(10 * B as u128);

/// 10B cycles corresponds to 1 SDR cent. Assuming we can create 1 signature per
/// second, that would come to  26k SDR per month if we spent the whole time
/// creating key derivations. At 13 nodes and 2k SDR per node per month this would
/// cover the cost of the subnet.
pub const VETKD_FEE: Cycles = Cycles::new(10 * B as u128);

/// Default subnet size which is used to scale cycles cost according to a subnet replication factor.
///
/// All initial costs were calculated with the assumption that a subnet had 13 replicas.
/// IMPORTANT: never set this value to zero.
pub const DEFAULT_REFERENCE_SUBNET_SIZE: usize = 13;

/// Costs for each newly created dirty page in stable memory.
const DEFAULT_DIRTY_PAGE_OVERHEAD: NumInstructions = NumInstructions::new(1_000);

/// Accumulated priority reset interval, rounds.
///
/// Note, if the interval is too low, the accumulated priority becomes less relevant.
/// But if the interval is too high, the total accumulated priority might drift
/// too much from zero, and the newly created canisters might have have a
/// superior or inferior priority comparing to other canisters on the subnet.
///
/// Arbitrary chosen number to reset accumulated priority every ~24 hours on
/// all subnet types.
const ACCUMULATED_PRIORITY_RESET_INTERVAL: ExecutionRound = ExecutionRound::new(24 * 3600);

/// The default value of the reserved balance limit for the case when the
/// canister doesn't have it set in the settings.
const DEFAULT_RESERVED_BALANCE_LIMIT: Cycles = Cycles::new(5 * T);

/// Instructions used to upload a chunk (1MiB) to the wasm chunk store. This is
/// 1/10th of a round.
pub const DEFAULT_UPLOAD_CHUNK_INSTRUCTIONS: NumInstructions = NumInstructions::new(200_000_000);

/// Baseline cost for creating or loading a canister snapshot (2B instructions).
/// The cost is based on the benchmarks: rs/execution_environment/benches/management_canister/
pub const DEFAULT_CANISTERS_SNAPSHOT_BASELINE_INSTRUCTIONS: NumInstructions =
    NumInstructions::new(2_000_000_000);

/// Baseline cost for up/downloading binary snapshot data (5M instructions).
/// The cost is based on the benchmarks: rs/execution_environment/benches/management_canister/
pub const DEFAULT_CANISTERS_SNAPSHOT_DATA_BASELINE_INSTRUCTIONS: NumInstructions =
    NumInstructions::new(5_000_000);

/// The cycle cost overhead of executing canister instructions when running in Wasm64 mode.
/// This overhead is a multiplier over the cost of executing the same instructions
/// in Wasm32 mode. The overhead comes from the bound checks performed in Wasm64 mode
/// as well as larger heap sizes that lead to larger application working sets.
pub const WASM64_INSTRUCTION_COST_OVERHEAD: u128 = 2;

/// The per subnet type configuration for the scheduler component
#[derive(Clone, Deserialize, Serialize)]
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
    /// for a single query or composite query method.
    pub max_instructions_per_query_message: NumInstructions,

    /// Maximum amount of instructions a single slice of execution can consume.
    /// This should not exceed `max_instructions_per_round`.
    pub max_instructions_per_slice: NumInstructions,

    /// The overhead of entering and exiting the Wasm engine for a single
    /// execution. The overhead is measured in instructions that are counted
    /// towards the round limit.
    pub instruction_overhead_per_execution: NumInstructions,

    /// The overhead of preparing execution of a canister. The overhead is
    /// measured in instructions that are counted towards the round limit.
    pub instruction_overhead_per_canister: NumInstructions,

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

    /// The reserve represents the freely available portion of the
    /// `subnet_heap_delta_capacity` that can be used as a heap delta burst
    /// during the initial rounds following a checkpoint.
    pub heap_delta_initial_reserve: NumBytes,

    /// The maximum amount of heap delta per iteration. This number is checked
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

    /// Accumulated priority reset interval, rounds.
    pub accumulated_priority_reset_interval: ExecutionRound,

    /// Number of instructions to count when uploading a chunk to the wasm store.
    pub upload_wasm_chunk_instructions: NumInstructions,

    /// Number of instructions to count when creating or loading a canister snapshot.
    pub canister_snapshot_baseline_instructions: NumInstructions,

    /// Number of instructions to count when uploading or downloading binary snapshot data.
    pub canister_snapshot_data_baseline_instructions: NumInstructions,

    /// Whether to store pre-signatures in the replicated state.
    pub store_pre_signatures_in_state: FlagStatus,
}

impl SchedulerConfig {
    pub fn application_subnet() -> Self {
        Self {
            scheduler_cores: NUMBER_OF_EXECUTION_THREADS,
            max_paused_executions: MAX_PAUSED_EXECUTIONS,
            subnet_heap_delta_capacity: SUBNET_HEAP_DELTA_CAPACITY,
            heap_delta_initial_reserve: HEAP_DELTA_INITIAL_RESERVE,
            max_instructions_per_round: MAX_INSTRUCTIONS_PER_ROUND,
            max_instructions_per_message: MAX_INSTRUCTIONS_PER_MESSAGE,
            max_instructions_per_query_message: MAX_INSTRUCTIONS_PER_QUERY_MESSAGE,
            max_instructions_per_slice: MAX_INSTRUCTIONS_PER_SLICE,
            instruction_overhead_per_execution: INSTRUCTION_OVERHEAD_PER_EXECUTION,
            instruction_overhead_per_canister: INSTRUCTION_OVERHEAD_PER_CANISTER,
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
            accumulated_priority_reset_interval: ACCUMULATED_PRIORITY_RESET_INTERVAL,
            upload_wasm_chunk_instructions: DEFAULT_UPLOAD_CHUNK_INSTRUCTIONS,
            canister_snapshot_baseline_instructions:
                DEFAULT_CANISTERS_SNAPSHOT_BASELINE_INSTRUCTIONS,
            canister_snapshot_data_baseline_instructions:
                DEFAULT_CANISTERS_SNAPSHOT_DATA_BASELINE_INSTRUCTIONS,
            store_pre_signatures_in_state: if STORE_PRE_SIGNATURES_IN_STATE {
                FlagStatus::Enabled
            } else {
                FlagStatus::Disabled
            },
        }
    }

    pub fn system_subnet() -> Self {
        let max_instructions_per_message = NumInstructions::from(50 * B);
        let max_instructions_per_query_message = max_instructions_per_message;
        let max_instructions_per_install_code = NumInstructions::from(1_000 * B);
        let max_instructions_per_slice = NumInstructions::from(2 * B);
        let max_instructions_per_install_code_slice = NumInstructions::from(5 * B);
        Self {
            scheduler_cores: NUMBER_OF_EXECUTION_THREADS,
            max_paused_executions: MAX_PAUSED_EXECUTIONS,
            subnet_heap_delta_capacity: SUBNET_HEAP_DELTA_CAPACITY,
            // TODO(RUN-993): Enable heap delta rate limiting for system subnets.
            // Setting initial reserve to capacity effectively disables the rate limiting.
            heap_delta_initial_reserve: SUBNET_HEAP_DELTA_CAPACITY,
            // Round limit is set to allow on average 2B instructions.
            // See also comment about `MAX_INSTRUCTIONS_PER_ROUND`.
            max_instructions_per_round: max_instructions_per_slice
                .max(max_instructions_per_install_code_slice)
                + NumInstructions::from(2 * B),
            max_instructions_per_message,
            max_instructions_per_query_message,
            max_instructions_per_slice,
            instruction_overhead_per_execution: INSTRUCTION_OVERHEAD_PER_EXECUTION,
            instruction_overhead_per_canister: INSTRUCTION_OVERHEAD_PER_CANISTER,
            instruction_overhead_per_canister_for_finalization:
                INSTRUCTION_OVERHEAD_PER_CANISTER_FOR_FINALIZATION,
            max_instructions_per_install_code,
            max_instructions_per_install_code_slice,
            max_heap_delta_per_iteration: MAX_HEAP_DELTA_PER_ITERATION * SYSTEM_SUBNET_FACTOR,
            max_message_duration_before_warn_in_seconds:
                MAX_MESSAGE_DURATION_BEFORE_WARN_IN_SECONDS,
            // This limit should be high enough (1000T) to effectively disable
            // rate-limiting for the system subnets.
            heap_delta_rate_limit: NumBytes::from(1_000_000_000_000_000),
            // This limit should be high enough (1000T) to effectively disable
            // rate-limiting for the system subnets.
            install_code_rate_limit: NumInstructions::from(1_000_000_000_000_000),
            dirty_page_overhead: DEFAULT_DIRTY_PAGE_OVERHEAD,
            accumulated_priority_reset_interval: ACCUMULATED_PRIORITY_RESET_INTERVAL,
            upload_wasm_chunk_instructions: NumInstructions::from(0),
            canister_snapshot_baseline_instructions: NumInstructions::from(0),
            canister_snapshot_data_baseline_instructions: NumInstructions::from(0),
            store_pre_signatures_in_state: if STORE_PRE_SIGNATURES_IN_STATE {
                FlagStatus::Enabled
            } else {
                FlagStatus::Disabled
            },
        }
    }

    pub fn verified_application_subnet() -> Self {
        Self::application_subnet()
    }

    pub fn default_for_subnet_type(subnet_type: SubnetType) -> Self {
        match subnet_type {
            SubnetType::Application => Self::application_subnet(),
            SubnetType::System => Self::system_subnet(),
            SubnetType::VerifiedApplication => Self::verified_application_subnet(),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
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

    /// Fee for every 10 instructions executed when executing update type
    /// messages on a Wasm64 canister.
    pub ten_update_instructions_execution_fee_wasm64: Cycles,

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

    /// Amount to charge for a Schnorr signature.
    pub schnorr_signature_fee: Cycles,

    /// Amount to charge for vet KD.
    pub vetkd_fee: Cycles,

    /// A linear factor of the baseline cost to be charged for HTTP requests per node.
    /// The cost of an HTTP request is represented by a quadratic function due to the communication complexity of the subnet.
    pub http_request_linear_baseline_fee: Cycles,

    /// A quadratic factor of the baseline cost to be charged for HTTP requests per node.
    /// The cost of an HTTP request is represented by a quadratic function due to the communication complexity of the subnet.
    pub http_request_quadratic_baseline_fee: Cycles,

    /// Fee per byte for networking and consensus work done for an HTTP request per node.
    pub http_request_per_byte_fee: Cycles,

    /// Fee per byte for networking and consensus work done for an HTTP response per node.
    pub http_response_per_byte_fee: Cycles,

    /// The upper bound on the storage reservation period.
    pub max_storage_reservation_period: Duration,

    /// The default value of the reserved balance limit for the case when the
    /// canister doesn't have it set in the settings.
    pub default_reserved_balance_limit: Cycles,

    /// Base fee for fetching canister logs.
    pub fetch_canister_logs_base_fee: Cycles,

    /// Fee per byte for fetching canister logs.
    pub fetch_canister_logs_per_byte_fee: Cycles,
}

impl CyclesAccountManagerConfig {
    pub fn application_subnet() -> Self {
        let ten_update_instructions_execution_fee_in_cycles = 10;
        Self {
            reference_subnet_size: DEFAULT_REFERENCE_SUBNET_SIZE,
            canister_creation_fee: Cycles::new(500_000_000_000),
            compute_percent_allocated_per_second_fee: Cycles::new(10_000_000),

            // The following fields are set based on a thought experiment where
            // we estimated how many resources a representative benchmark on a
            // verified subnet is using.
            update_message_execution_fee: Cycles::new(5_000_000),
            ten_update_instructions_execution_fee: Cycles::new(
                ten_update_instructions_execution_fee_in_cycles,
            ),
            ten_update_instructions_execution_fee_wasm64: Cycles::new(
                WASM64_INSTRUCTION_COST_OVERHEAD * ten_update_instructions_execution_fee_in_cycles,
            ),
            xnet_call_fee: Cycles::new(260_000),
            xnet_byte_transmission_fee: Cycles::new(1_000),
            ingress_message_reception_fee: Cycles::new(1_200_000),
            ingress_byte_reception_fee: Cycles::new(2_000),
            // 4 SDR per GiB per year => 4e12 Cycles per year
            gib_storage_per_second_fee: Cycles::new(127_000),
            duration_between_allocation_charges: Duration::from_secs(10),
            ecdsa_signature_fee: ECDSA_SIGNATURE_FEE,
            schnorr_signature_fee: SCHNORR_SIGNATURE_FEE,
            vetkd_fee: VETKD_FEE,
            http_request_linear_baseline_fee: Cycles::new(3_000_000),
            http_request_quadratic_baseline_fee: Cycles::new(60_000),
            http_request_per_byte_fee: Cycles::new(400),
            http_response_per_byte_fee: Cycles::new(800),
            max_storage_reservation_period: Duration::from_secs(300_000_000),
            default_reserved_balance_limit: DEFAULT_RESERVED_BALANCE_LIMIT,
            fetch_canister_logs_base_fee: Cycles::new(1_000_000),
            fetch_canister_logs_per_byte_fee: Cycles::new(800),
        }
    }

    pub fn verified_application_subnet() -> Self {
        Self::application_subnet()
    }

    /// All processing is free on system subnets
    pub fn system_subnet() -> Self {
        Self {
            reference_subnet_size: DEFAULT_REFERENCE_SUBNET_SIZE,
            canister_creation_fee: Cycles::new(0),
            compute_percent_allocated_per_second_fee: Cycles::new(0),
            update_message_execution_fee: Cycles::new(0),
            ten_update_instructions_execution_fee: Cycles::new(0),
            ten_update_instructions_execution_fee_wasm64: Cycles::new(0),
            xnet_call_fee: Cycles::new(0),
            xnet_byte_transmission_fee: Cycles::new(0),
            ingress_message_reception_fee: Cycles::new(0),
            ingress_byte_reception_fee: Cycles::new(0),
            gib_storage_per_second_fee: Cycles::new(0),
            duration_between_allocation_charges: Duration::from_secs(10),
            // ECDSA and Schnorr signature fees are the fees charged when creating a
            // signature on this subnet. The request likely came from a
            // different subnet which is not a system subnet. There is an
            // explicit exception for requests originating from the NNS when the
            // charging occurs.
            // Costs:
            // - zero cost if called from NNS subnet
            // - non-zero cost if called from any other subnet which is not NNS subnet
            ecdsa_signature_fee: ECDSA_SIGNATURE_FEE,
            schnorr_signature_fee: SCHNORR_SIGNATURE_FEE,
            vetkd_fee: VETKD_FEE,
            http_request_linear_baseline_fee: Cycles::new(0),
            http_request_quadratic_baseline_fee: Cycles::new(0),
            http_request_per_byte_fee: Cycles::new(0),
            http_response_per_byte_fee: Cycles::new(0),
            // This effectively disables the storage reservation mechanism on system subnets.
            max_storage_reservation_period: Duration::from_secs(0),
            default_reserved_balance_limit: DEFAULT_RESERVED_BALANCE_LIMIT,
            fetch_canister_logs_base_fee: Cycles::new(0),
            fetch_canister_logs_per_byte_fee: Cycles::new(0),
        }
    }

    pub fn zero_cost(subnet_size: usize) -> Self {
        Self {
            reference_subnet_size: subnet_size,
            canister_creation_fee: Cycles::zero(),
            update_message_execution_fee: Cycles::zero(),
            ten_update_instructions_execution_fee: Cycles::zero(),
            ten_update_instructions_execution_fee_wasm64: Cycles::zero(),
            xnet_call_fee: Cycles::zero(),
            xnet_byte_transmission_fee: Cycles::zero(),
            ingress_message_reception_fee: Cycles::zero(),
            ingress_byte_reception_fee: Cycles::zero(),
            gib_storage_per_second_fee: Cycles::zero(),
            compute_percent_allocated_per_second_fee: Cycles::zero(),
            duration_between_allocation_charges: Duration::from_secs(u64::MAX),
            ecdsa_signature_fee: Cycles::zero(),
            schnorr_signature_fee: Cycles::zero(),
            vetkd_fee: Cycles::zero(),
            http_request_linear_baseline_fee: Cycles::zero(),
            http_request_quadratic_baseline_fee: Cycles::zero(),
            http_request_per_byte_fee: Cycles::zero(),
            http_response_per_byte_fee: Cycles::zero(),
            max_storage_reservation_period: Duration::from_secs(u64::MAX),
            default_reserved_balance_limit: Cycles::zero(),
            fetch_canister_logs_base_fee: Cycles::zero(),
            fetch_canister_logs_per_byte_fee: Cycles::zero(),
        }
    }
}

/// If a component has at least one static configuration that is different for
/// different subnet types, then it is included in this struct.
#[derive(Clone)]
pub struct SubnetConfig {
    pub scheduler_config: SchedulerConfig,
    pub cycles_account_manager_config: CyclesAccountManagerConfig,
}

impl SubnetConfig {
    pub fn new(own_subnet_type: SubnetType) -> Self {
        match own_subnet_type {
            SubnetType::Application => Self::default_application_subnet(),
            SubnetType::System => Self::default_system_subnet(),
            SubnetType::VerifiedApplication => Self::default_verified_application_subnet(),
        }
    }

    /// Returns the subnet configuration for the application subnet type.
    fn default_application_subnet() -> Self {
        Self {
            scheduler_config: SchedulerConfig::application_subnet(),
            cycles_account_manager_config: CyclesAccountManagerConfig::application_subnet(),
        }
    }

    /// Returns the subnet configuration for the system subnet type.
    fn default_system_subnet() -> Self {
        Self {
            scheduler_config: SchedulerConfig::system_subnet(),
            cycles_account_manager_config: CyclesAccountManagerConfig::system_subnet(),
        }
    }

    /// Returns the subnet configuration for the verified application subnet
    /// type.
    fn default_verified_application_subnet() -> Self {
        Self {
            scheduler_config: SchedulerConfig::verified_application_subnet(),
            cycles_account_manager_config: CyclesAccountManagerConfig::verified_application_subnet(
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        B, MAX_INSTRUCTIONS_PER_INSTALL_CODE_SLICE, MAX_INSTRUCTIONS_PER_ROUND,
        MAX_INSTRUCTIONS_PER_SLICE,
    };
    use ic_types::NumInstructions;

    #[test]
    fn max_instructions_per_round() {
        assert_eq!(
            MAX_INSTRUCTIONS_PER_ROUND,
            MAX_INSTRUCTIONS_PER_SLICE.max(MAX_INSTRUCTIONS_PER_INSTALL_CODE_SLICE)
                + NumInstructions::from(2 * B)
        );
    }
}
