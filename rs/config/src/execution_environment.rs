use crate::embedders::Config as EmbeddersConfig;
use crate::flag_status::FlagStatus;
use ic_base_types::{CanisterId, NumSeconds};
use ic_types::{
    Cycles, NumBytes, NumInstructions, MAX_STABLE_MEMORY_IN_BYTES, MAX_WASM_MEMORY_IN_BYTES,
};
use serde::{Deserialize, Serialize};
use std::{str::FromStr, time::Duration};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = MIB * 1024;

/// This specifies the threshold in bytes at which the subnet memory usage is
/// considered to be high. If this value is greater or equal to the subnet
/// capacity, then the subnet is never considered to have high usage.
const SUBNET_MEMORY_THRESHOLD: NumBytes = NumBytes::new(450 * GIB);

/// This is the upper limit on how much logical storage canisters can request to
/// be store on a given subnet.
///
/// Logical storage is the amount of storage being used from the point of view
/// of the canister. The actual storage used by the nodes can be higher as the
/// IC protocol requires storing copies of the canister state.
const SUBNET_MEMORY_CAPACITY: NumBytes = NumBytes::new(700 * GIB);

/// This is the upper limit on how much memory can be used by all canister
/// messages on a given subnet.
///
/// Message memory usage is calculated as the total size of enqueued canister
/// responses; plus the maximum allowed response size per queue reservation.
const SUBNET_MESSAGE_MEMORY_CAPACITY: NumBytes = NumBytes::new(25 * GIB);

/// This is the upper limit on how much memory can be used by the ingress
/// history on a given subnet. It is lower than the subnet message memory
/// capacity because here we count actual memory consumption as opposed to
/// memory plus reservations.
const INGRESS_HISTORY_MEMORY_CAPACITY: NumBytes = NumBytes::new(4 * GIB);

/// This is the upper limit on how much memory can be used by wasm custom
/// sections on a given subnet.
const SUBNET_WASM_CUSTOM_SECTIONS_MEMORY_CAPACITY: NumBytes = NumBytes::new(2 * GIB);

/// The number of bytes reserved for response callback executions.
const SUBNET_MEMORY_RESERVATION: NumBytes = NumBytes::new(10 * GIB);

/// The duration a stop_canister has to stop the canister before timing out.
pub const STOP_CANISTER_TIMEOUT_DURATION: Duration = Duration::from_secs(5 * 60); // 5 minutes

/// This is the upper limit on how big heap deltas all the canisters together
/// can produce on a subnet in between checkpoints. Once, the total delta size
/// is above this limit, no more canisters will be executed till the next
/// checkpoint is taken. This is a soft limit in the sense that the actual delta
/// size can grow above this limit but no new execution will be done if the the
/// current size is above this limit.
///
/// Currently heap delta pages are stored in memory and not backed by a file.
/// The gen 1 machines in production have 500GiB of RAM available to replica.
/// Set the upper limit to 140GiB to reserve memory for other components and
/// potential fragmentation. This limit should be larger than the maximum
/// canister memory size to guarantee that a message that overwrites the whole
/// memory can succeed.
pub(crate) const SUBNET_HEAP_DELTA_CAPACITY: NumBytes = NumBytes::new(140 * GIB);

/// The maximum number of instructions for inspect_message calls.
const MAX_INSTRUCTIONS_FOR_MESSAGE_ACCEPTANCE_CALLS: NumInstructions =
    NumInstructions::new(200_000_000);

/// The maximum depth of call graphs allowed for composite query calls
pub(crate) const MAX_QUERY_CALL_DEPTH: usize = 6;
/// Equivalent to MAX_INSTRUCTIONS_PER_MESSAGE_WITHOUT_DTS for now
pub(crate) const MAX_INSTRUCTIONS_PER_COMPOSITE_QUERY_CALL: u64 = 5_000_000_000;
/// The maximum time in seconds a query call is allowed to run.
pub(crate) const MAX_TIME_PER_COMPOSITE_QUERY_CALL: Duration = Duration::from_secs(10);

/// This would allow 100 calls with the current MAX_INSTRUCTIONS_PER_COMPOSITE_QUERY_CALL
pub const INSTRUCTION_OVERHEAD_PER_QUERY_CALL: u64 = 50_000_000;

/// The number of query execution threads overall for all canisters.
/// See also `QUERY_EXECUTION_THREADS_PER_CANISTER`.
pub(crate) const QUERY_EXECUTION_THREADS_TOTAL: usize = 4;

/// When a canister is scheduled for query execution, it is allowed to run for
/// this amount of time. This limit controls how many queries the canister
/// executes when it is scheduled. The limit does not control the duration of an
/// individual query. In the worst case, a single query may exceed this limit if
/// it executes the maximum number of instructions. In that case, the canister
/// would execute only that one query. Generally, we expect queries to finish in
/// a few milliseconds, so multiple queries will run in a slice.
///
/// The current value of 20ms is chosen arbitrarily. Any value between 10ms and
/// 100ms would work reasonably well. Reducing the value increases the overhead
/// of synchronization to fetch queries and also increases "unfairness" in the
/// presence of canisters that execute long-running queries. Increasing the
/// value increases the user-visible latency of the queries.
const QUERY_SCHEDULING_TIME_SLICE_PER_CANISTER: Duration = Duration::from_millis(20);

/// The upper limit on how much memory query cache can occupy.
///
/// The limit includes both cache keys and values, for successful query
/// executions and user errors.
const QUERY_CACHE_CAPACITY: NumBytes = NumBytes::new(200 * MIB);

/// The upper limit on how long the cache entry stays valid in the query cache.
const QUERY_CACHE_MAX_EXPIRY_TIME: Duration = Duration::from_secs(600);
/// The upper limit on how long the data certificate stays valid in the query cache.
///
/// The [HTTP Gateway Protocol Specification](https://internetcomputer.org/docs/current/references/http-gateway-protocol-spec#certificate-validation)
/// states that the certified timestamp must be recent, e.g. 5 minutes.
/// So queries using the `ic0.data_certificate_copy()` System API call
/// should not be cached for more than 5 minutes.
const QUERY_CACHE_DATA_CERTIFICATE_EXPIRY_TIME: Duration = Duration::from_secs(60);

/// Length of an epoch of query statistics in blocks
pub const QUERY_STATS_EPOCH_LENGTH: u64 = 600;

// The ID of the Bitcoin testnet canister.
pub const BITCOIN_TESTNET_CANISTER_ID: &str = "g4xu7-jiaaa-aaaan-aaaaq-cai";

// The ID of the Bitcoin mainnet canister.
pub const BITCOIN_MAINNET_CANISTER_ID: &str = "ghsi2-tqaaa-aaaan-aaaca-cai";

// The ID of the "soft launch" Bitcoin mainnet canister.
// This is a canister that will be used to run the bitcoin mainnet state pre-launch
// for final validation. Once the validation is complete, this canister will be uninstalled
// in favour of the "real" Bitcoin mainnet canister defined above.
// TODO(EXC-1298): Uninstall this canister once the bitcoin mainnet canister is live.
const BITCOIN_MAINNET_SOFT_LAUNCH_CANISTER_ID: &str = "gsvzx-syaaa-aaaan-aaabq-cai";

/// The capacity of the Wasm compilation cache.
pub const MAX_COMPILATION_CACHE_SIZE: NumBytes = NumBytes::new(10 * GIB);

/// Maximum number of controllers allowed in a request (specified in the interface spec).
pub const MAX_ALLOWED_CONTROLLERS_COUNT: usize = 10;

/// Maximum number of canister snapshots that can be stored for a single canister.
pub const MAX_NUMBER_OF_SNAPSHOTS_PER_CANISTER: usize = 1;

/// Maximum number of http outcall requests in-flight on a subnet.
/// To support 100 req/s with a worst case request latency of 30s the queue size needs buffer 100 req/s * 30s = 3000 req.
/// The worst case request latency used here should be equivalent to the request timeout in the adapter.
pub const MAX_CANISTER_HTTP_REQUESTS_IN_FLIGHT: usize = 3000;

/// The default value of `wasm_memory_limit` in the canister settings:
/// - this value is used directly for newly created canisters.
/// - existing canisters will get their field initialized as follows:
///   - let `halfway_to_max = (memory_usage + 4GiB) / 2`
///   - use the maximum of `default_wasm_memory_limit` and `halfway_to_max`.
pub const DEFAULT_WASM_MEMORY_LIMIT: NumBytes = NumBytes::new(3 * GIB);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub embedders_config: EmbeddersConfig,

    /// This is no longer used in the code.  It is not removed yet as removing
    /// this option will be a breaking change.
    pub create_funds_whitelist: String,

    /// The maximum number of instructions that the methods that are invoked to
    /// check message acceptance can run for.
    pub max_instructions_for_message_acceptance_calls: NumInstructions,

    /// This specifies the threshold in bytes at which the subnet memory usage is
    /// considered to be high. If this value is greater or equal to the subnet
    /// capacity, then the subnet is never considered to have high usage.
    pub subnet_memory_threshold: NumBytes,

    /// The maximum amount of logical storage available to all the canisters on
    /// the subnet.
    pub subnet_memory_capacity: NumBytes,

    /// The maximum amount of logical storage available to canister messages
    /// across the whole subnet.
    pub subnet_message_memory_capacity: NumBytes,

    /// The maximum amount of logical storage available to the ingress history
    /// across the whole subnet.
    pub ingress_history_memory_capacity: NumBytes,

    /// The maximum amount of logical storage available to wasm custom sections
    /// across the whole subnet.
    pub subnet_wasm_custom_sections_memory_capacity: NumBytes,

    /// The number of bytes reserved for response callback execution.
    pub subnet_memory_reservation: NumBytes,

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

    /// The number of threads to use for query execution overall.
    pub query_execution_threads_total: usize,

    /// When a canister is scheduled for query execution, it is allowed to run for
    /// this amount of time.
    pub query_scheduling_time_slice_per_canister: Duration,

    /// The maximum depth of a query call graph.
    pub max_query_call_graph_depth: usize,

    /// The maximum number of instructions allowed for a query call graph.
    pub max_query_call_graph_instructions: NumInstructions,

    /// The maximum time a query call in non-replicated mode is allowed to run.
    /// In replicated code we cannot rely on the walltime, since that is not
    /// deterministic.
    pub max_query_call_walltime: Duration,

    /// Instructions to charge for each composite query call in addition to the
    /// instructions in the actual query call. This is meant to protect from
    /// cases where we have many calls into canister that execute little work.
    /// This cost is meant to cover for some of the overhead associated with
    /// the actual call.
    pub instruction_overhead_per_query_call: NumInstructions,

    /// If this flag is enabled, then message execution of canisters will be
    /// rate limited based on the amount of modified memory.
    pub rate_limiting_of_heap_delta: FlagStatus,

    /// If this flag is enabled, then message execution of canisters will be
    /// rate limited based on the number of executed instructions per round.
    pub rate_limiting_of_instructions: FlagStatus,

    /// Specifies the percentage of subnet compute capacity that is allocatable
    /// by canisters.
    pub allocatable_compute_capacity_in_percent: usize,

    /// Indicates whether deterministic time slicing is enabled or not.
    pub deterministic_time_slicing: FlagStatus,

    /// Bitcoin configuration.
    pub bitcoin: BitcoinConfig,

    /// Indicates whether composite queries are available or not.
    pub composite_queries: FlagStatus,

    /// Indicates whether replica side query caching is enabled.
    pub query_caching: FlagStatus,

    /// Query cache capacity in bytes
    pub query_cache_capacity: NumBytes,

    /// The upper limit on how long the cache entry stays valid in the query cache.
    pub query_cache_max_expiry_time: Duration,

    /// The upper limit on how long the data certificate stays valid in the query cache.
    pub query_cache_data_certificate_expiry_time: Duration,

    /// The capacity of the Wasm compilation cache.
    pub max_compilation_cache_size: NumBytes,

    /// Indicate whether query stats should be collected or not.
    pub query_stats_aggregation: FlagStatus,

    /// Length of an epoch for query stats collection.
    pub query_stats_epoch_length: u64,

    /// The duration a stop_canister has to stop the canister before timing out.
    pub stop_canister_timeout_duration: Duration,

    /// Indicates whether canister backup and restore feature is enabled or not.
    pub canister_snapshots: FlagStatus,

    /// Indicates whether dirty page logging is enabled or not.
    pub dirty_page_logging: FlagStatus,

    // TODO(EXC-1633): remove this flag once the feature is enabled by default.
    /// Indicates whether `Ic00Method::ComputeInitialIDkgDealings` is enabled.
    pub ic00_compute_initial_i_dkg_dealings: FlagStatus,

    // TODO(EXC-1633): remove this flag once the feature is enabled by default.
    /// Indicates whether `Ic00Method::SchnorrPublicKey` is enabled.
    pub ic00_schnorr_public_key: FlagStatus,

    // TODO(EXC-1633): remove this flag once the feature is enabled by default.
    /// Indicates whether `Ic00Method::SignWithSchnorr` is enabled.
    pub ic00_sign_with_schnorr: FlagStatus,

    pub max_canister_http_requests_in_flight: usize,

    /// The default value of `wasm_memory_limit` in the canister settings:
    /// - this value is used directly for newly created canisters.
    /// - existing canisters will get their field initialized as follows:
    ///   - let `halfway_to_max = (memory_usage + 4GiB) / 2`
    ///   - use the maximum of `default_wasm_memory_limit` and `halfway_to_max`.
    pub default_wasm_memory_limit: NumBytes,
}

impl Default for Config {
    fn default() -> Self {
        let bitcoin_testnet_canister_id = CanisterId::from_str(BITCOIN_TESTNET_CANISTER_ID)
            .expect("bitcoin testnet canister id must be a valid principal");

        let bitcoin_mainnet_canister_id = CanisterId::from_str(BITCOIN_MAINNET_CANISTER_ID)
            .expect("bitcoin mainnet canister id must be a valid principal");

        let bitcoin_mainnet_soft_launch_canister_id =
            CanisterId::from_str(BITCOIN_MAINNET_SOFT_LAUNCH_CANISTER_ID)
                .expect("bitcoin mainnet soft-launch canister id must be a valid principal");

        Self {
            embedders_config: EmbeddersConfig::default(),
            create_funds_whitelist: String::default(),
            max_instructions_for_message_acceptance_calls:
                MAX_INSTRUCTIONS_FOR_MESSAGE_ACCEPTANCE_CALLS,
            subnet_memory_threshold: SUBNET_MEMORY_THRESHOLD,
            subnet_memory_capacity: SUBNET_MEMORY_CAPACITY,
            subnet_message_memory_capacity: SUBNET_MESSAGE_MEMORY_CAPACITY,
            ingress_history_memory_capacity: INGRESS_HISTORY_MEMORY_CAPACITY,
            subnet_wasm_custom_sections_memory_capacity:
                SUBNET_WASM_CUSTOM_SECTIONS_MEMORY_CAPACITY,
            subnet_memory_reservation: SUBNET_MEMORY_RESERVATION,
            max_canister_memory_size: NumBytes::new(
                MAX_STABLE_MEMORY_IN_BYTES + MAX_WASM_MEMORY_IN_BYTES,
            ),
            default_provisional_cycles_balance: Cycles::new(100_000_000_000_000),
            // The default freeze threshold is 30 days.
            default_freeze_threshold: NumSeconds::from(30 * 24 * 60 * 60),
            max_controllers: MAX_ALLOWED_CONTROLLERS_COUNT,
            canister_sandboxing_flag: FlagStatus::Enabled,
            query_execution_threads_total: QUERY_EXECUTION_THREADS_TOTAL,
            query_scheduling_time_slice_per_canister: QUERY_SCHEDULING_TIME_SLICE_PER_CANISTER,
            max_query_call_graph_depth: MAX_QUERY_CALL_DEPTH,
            max_query_call_graph_instructions: NumInstructions::from(
                MAX_INSTRUCTIONS_PER_COMPOSITE_QUERY_CALL,
            ),
            max_query_call_walltime: MAX_TIME_PER_COMPOSITE_QUERY_CALL,
            instruction_overhead_per_query_call: NumInstructions::from(
                INSTRUCTION_OVERHEAD_PER_QUERY_CALL,
            ),
            rate_limiting_of_heap_delta: FlagStatus::Enabled,
            rate_limiting_of_instructions: FlagStatus::Enabled,
            // The allocatable compute capacity is capped at 50% to ensure that
            // best-effort canisters have sufficient compute to make progress.
            allocatable_compute_capacity_in_percent: 50,
            deterministic_time_slicing: FlagStatus::Enabled,
            bitcoin: BitcoinConfig {
                privileged_access: vec![
                    bitcoin_testnet_canister_id,
                    bitcoin_mainnet_canister_id,
                    bitcoin_mainnet_soft_launch_canister_id,
                ],
                testnet_canister_id: Some(bitcoin_testnet_canister_id),
                mainnet_canister_id: Some(bitcoin_mainnet_canister_id),
            },
            composite_queries: FlagStatus::Enabled,
            query_caching: FlagStatus::Enabled,
            query_cache_capacity: QUERY_CACHE_CAPACITY,
            query_cache_max_expiry_time: QUERY_CACHE_MAX_EXPIRY_TIME,
            query_cache_data_certificate_expiry_time: QUERY_CACHE_DATA_CERTIFICATE_EXPIRY_TIME,
            max_compilation_cache_size: MAX_COMPILATION_CACHE_SIZE,
            query_stats_aggregation: FlagStatus::Enabled,
            query_stats_epoch_length: QUERY_STATS_EPOCH_LENGTH,
            stop_canister_timeout_duration: STOP_CANISTER_TIMEOUT_DURATION,
            canister_snapshots: FlagStatus::Disabled,
            dirty_page_logging: FlagStatus::Disabled,
            ic00_compute_initial_i_dkg_dealings: FlagStatus::Enabled,
            ic00_schnorr_public_key: FlagStatus::Enabled,
            ic00_sign_with_schnorr: FlagStatus::Enabled,
            max_canister_http_requests_in_flight: MAX_CANISTER_HTTP_REQUESTS_IN_FLIGHT,
            default_wasm_memory_limit: DEFAULT_WASM_MEMORY_LIMIT,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct BitcoinConfig {
    /// Canisters that have access to privileged bitcoin API (e.g. `bitcoin_get_successors`)
    /// This list is intentionally separate from the bitcoin canister IDs below because it
    /// allows us to spin up new bitcoin canisters without necessarily routing requests to them.
    pub privileged_access: Vec<CanisterId>,

    /// The bitcoin testnet canister to forward requests to.
    pub testnet_canister_id: Option<CanisterId>,

    /// The bitcoin mainnet canister to forward requests to.
    pub mainnet_canister_id: Option<CanisterId>,
}
