use std::{collections::BTreeMap, time::Duration};

use ic_metrics::{
    MetricsRegistry,
    buckets::{
        binary_buckets_with_zero, decimal_buckets, decimal_buckets_with_zero, linear_buckets,
    },
};
use ic_replicated_state::canister_state::system_state::CyclesUseCase;
use ic_types::nominal_cycles::NominalCycles;
use prometheus::{
    Gauge, GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};

use crate::{
    metrics::{
        ScopedMetrics, cycles_histogram, dts_pause_or_abort_histogram, duration_histogram,
        instructions_histogram, memory_histogram, messages_histogram, slices_histogram,
        unique_sorted_buckets,
    },
    scheduler::threshold_signatures::THRESHOLD_SIGNATURE_SCHEME_MISMATCH,
};

pub(crate) const CANISTER_INVARIANT_BROKEN: &str = "scheduler_canister_invariant_broken";
pub(crate) const SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN: &str =
    "scheduler_compute_allocation_invariant_broken";
pub(crate) const SCHEDULER_CORES_INVARIANT_BROKEN: &str = "scheduler_cores_invariant_broken";
pub(crate) const SUBNET_MEMORY_USAGE_INVARIANT_BROKEN: &str =
    "scheduler_subnet_memory_usage_invariant_broken";

pub(super) struct SchedulerMetrics {
    pub(super) canister_age: Histogram,
    pub(super) canister_compute_allocation_violation: IntCounter,
    pub(super) canister_balance: Histogram,
    pub(super) canister_binary_size: Histogram,
    pub(super) canister_log_memory_usage_v2: Histogram,
    pub(super) canister_log_memory_usage_v3: Histogram,
    pub(super) canister_log_delta_memory_usage: Histogram,
    pub(super) canister_wasm_memory_usage: Histogram,
    pub(super) canister_stable_memory_usage: Histogram,
    pub(super) canister_memory_allocation: Histogram,
    pub(super) canister_compute_allocation: Histogram,
    pub(super) canister_ingress_queue_latencies: Histogram,
    pub(super) compute_utilization_per_core: Histogram,
    pub(super) instructions_consumed_per_message: Histogram,
    pub(super) instructions_consumed_per_round: Histogram,
    pub(super) executable_canisters_per_round: Histogram,
    pub(super) executed_canisters_per_round: Histogram,
    pub(super) expired_ingress_messages_count: IntCounter,
    pub(super) ingress_history_length: IntGauge,
    pub(super) msg_execution_duration: Histogram,
    pub(super) registered_canisters: IntGaugeVec,
    pub(super) available_canister_ids: IntGauge,
    /// Metric `consumed_cycles` is not monotonically increasing. Cycles
    /// consumed are increasing the value of the metric while refunding
    /// cycles are decreasing it.
    ///
    /// `f64` gauge because cycles values are `u128`: converting them
    /// into `u64` would result in truncation when the value overflows
    /// 64 bits (which would be indistinguishable from a huge refund);
    /// whereas conversion to `f64` merely results in loss of precision
    /// when dealing with values > 2^53.
    pub(super) consumed_cycles: Gauge,
    pub(super) consumed_cycles_by_use_case: GaugeVec,
    pub(super) input_queue_messages: IntGaugeVec,
    pub(super) input_queues_size_bytes: IntGaugeVec,
    pub(super) queues_response_bytes: IntGauge,
    pub(super) queues_memory_reservations: IntGauge,
    pub(super) queues_oversized_requests_extra_bytes: IntGauge,
    pub(super) queues_best_effort_message_bytes: IntGauge,
    pub(super) canister_messages_where_cycles_were_charged: IntCounter,
    pub(super) current_heap_delta: IntGauge,
    pub(super) round_skipped_due_to_current_heap_delta_above_limit: IntCounter,
    pub(super) execute_round_called: IntCounter,
    pub(super) inner_loop_consumed_non_zero_instructions_count: IntCounter,
    pub(super) inner_round_loop_consumed_max_instructions: IntCounter,
    pub(super) num_canisters_uninstalled_out_of_cycles: IntCounter,
    pub(super) round: ScopedMetrics,
    pub(super) round_preparation_duration: Histogram,
    pub(super) round_preparation_ingress: Histogram,
    pub(super) round_consensus_queue: ScopedMetrics,
    pub(super) round_postponed_raw_rand_queue: ScopedMetrics,
    pub(super) round_subnet_queue: ScopedMetrics,
    pub(super) round_advance_long_install_code: ScopedMetrics,
    pub(super) round_scheduling_duration: Histogram,
    pub(super) round_update_signature_request_contexts_duration: Histogram,
    pub(super) round_inner: ScopedMetrics,
    pub(super) round_inner_heartbeat_overhead_duration: Histogram,
    pub(super) round_inner_iteration: ScopedMetrics,
    pub(super) round_inner_iteration_prep: Histogram,
    pub(super) round_inner_iteration_exe: Histogram,
    pub(super) round_inner_iteration_thread: ScopedMetrics,
    pub(super) round_inner_iteration_thread_message: ScopedMetrics,
    pub(super) round_inner_iteration_fin: Histogram,
    pub(super) round_inner_iteration_fin_induct: Histogram,
    pub(super) round_finalization_duration: Histogram,
    pub(super) round_finalization_stop_canisters: Histogram,
    pub(super) round_finalization_ingress: Histogram,
    pub(super) round_finalization_charge: Histogram,
    pub(super) canister_heap_delta_debits: Histogram,
    pub(super) heap_delta_rate_limited_canisters_per_round: Histogram,
    pub(super) canisters_not_in_routing_table: IntGauge,
    pub(super) canister_install_code_debits: Histogram,
    pub(super) old_open_call_contexts: IntGaugeVec,
    pub(super) canisters_with_old_open_call_contexts: IntGaugeVec,
    pub(super) canister_invariants: IntCounter,
    pub(super) scheduler_compute_allocation_invariant_broken: IntCounter,
    pub(super) scheduler_cores_invariant_broken: IntCounter,
    pub(super) scheduler_accumulated_priority_invariant: IntGauge,
    pub(super) scheduler_accumulated_priority_deviation: Gauge,
    pub(super) subnet_memory_usage_invariant: IntCounter,
    pub(super) total_canister_balance: Gauge,
    pub(super) total_canister_reserved_balance: Gauge,
    pub(super) canister_paused_execution: Histogram,
    pub(super) canister_aborted_execution: Histogram,
    pub(super) canister_paused_install_code: Histogram,
    pub(super) canister_aborted_install_code: Histogram,
    pub(super) inducted_messages: IntCounterVec,
    pub(super) threshold_signature_agreements: IntGaugeVec,
    pub(super) delivered_pre_signatures: HistogramVec,
    pub(super) exceeding_pre_signatures: IntCounterVec,
    pub(super) in_flight_signature_request_contexts: HistogramVec,
    pub(super) completed_signature_request_contexts: IntCounterVec,
    pub(super) pre_signature_stash_size: IntGaugeVec,
    pub(super) threshold_signature_scheme_mismatch: IntCounter,
    // TODO(EXC-1466): Remove metric once all calls have `call_id` present.
    pub(super) stop_canister_calls_without_call_id: IntGauge,
    pub(super) canister_snapshots_memory_usage: IntGauge,
    pub(super) num_canister_snapshots: IntGauge,
    pub(super) zero_instruction_messages: IntCounter,
}

const LABEL_MESSAGE_KIND: &str = "kind";
pub(super) const MESSAGE_KIND_INGRESS: &str = "ingress";
pub(super) const MESSAGE_KIND_CANISTER: &str = "canister";

/// Alert for call contexts older than this cutoff (one day).
pub(super) const OLD_CALL_CONTEXT_CUTOFF_ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);
pub(super) const OLD_CALL_CONTEXT_LABEL_ONE_DAY: &str = "1d";

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

impl SchedulerMetrics {
    pub(super) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            canister_age: metrics_registry.histogram(
                "scheduler_canister_age_rounds",
                "Number of rounds for which a canister was not scheduled.",
                // 1, 2, 5, …, 1000, 2000, 5000
                decimal_buckets(0, 3),
            ),
            canister_compute_allocation_violation: metrics_registry.int_counter(
                "scheduler_compute_allocation_violations",
                "Total number of canister allocation violations.",
            ),
            canister_balance: cycles_histogram(
                "canister_balance_cycles",
                "Canisters balance distribution in Cycles.",
                metrics_registry,
            ),
            canister_binary_size: memory_histogram(
                "canister_binary_size_bytes",
                "Canisters Wasm binary size distribution in bytes.",
                metrics_registry,
            ),
            canister_log_memory_usage_v2: metrics_registry.histogram(
                "canister_log_memory_usage_bytes_v2",
                "Canisters log memory usage distribution in bytes.",
                unique_sorted_buckets(&[
                    0,
                    KIB,
                    2 * KIB,
                    5 * KIB,
                    10 * KIB,
                    20 * KIB,
                    50 * KIB,
                    100 * KIB,
                    200 * KIB,
                    500 * KIB,
                    MIB,
                    2 * MIB,
                    5 * MIB,
                    10 * MIB,
                ])
            ),
            canister_log_memory_usage_v3: metrics_registry.histogram(
                "canister_log_memory_usage_bytes_v3",
                "Canisters log memory usage distribution in bytes.",
                // 4 KiB (2^12) .. 8 GiB (2^33), plus zero — 23 total buckets (0 + 22 powers).
                binary_buckets_with_zero(12, 33)
            ),
            canister_log_delta_memory_usage: metrics_registry.histogram(
                "canister_log_delta_memory_usage_bytes",
                "Canisters log delta (per single execution) memory usage distribution in bytes.",
                // 1 KiB (2^10) .. 8 MiB (2^23), plus zero — 15 total buckets (0 + 14 powers).
                binary_buckets_with_zero(10, 23)
            ),
            canister_wasm_memory_usage: memory_histogram(
                "canister_wasm_memory_usage_bytes",
                "Canisters Wasm memory usage distribution in bytes.",
                metrics_registry,
            ),
            canister_stable_memory_usage: memory_histogram(
                "canister_stable_memory_usage_bytes",
                "Canisters stable memory usage distribution in bytes.",
                metrics_registry,
            ),
            canister_memory_allocation: memory_histogram(
                "canister_memory_allocation_bytes",
                "Canisters memory allocation distribution in bytes.",
                metrics_registry,
            ),
            canister_compute_allocation: metrics_registry.histogram(
                "canister_compute_allocation_ratio",
                "Canisters compute allocation distribution ratio (0-1).",
                linear_buckets(0.0, 0.1, 11),
            ),
            canister_ingress_queue_latencies: metrics_registry.histogram(
                "scheduler_canister_ingress_queue_latencies_seconds",
                "Per-canister mean IC clock duration spent by messages in the ingress queue.",
                // 10ms, 20ms, 50ms, …, 100s, 200s, 500s
                decimal_buckets(-2, 2),
            ),
            compute_utilization_per_core: metrics_registry.histogram(
                "scheduler_compute_utilization_per_core",
                "The Internet Computer's compute utilization as a percent per cpu core.",
                linear_buckets(0.0, 0.05, 21),
            ),
            instructions_consumed_per_message: metrics_registry.histogram(
                "scheduler_instructions_consumed_per_message",
                "Wasm instructions consumed per message.",
                // 1, 2, 5, …, 1M, 2M, 5M
                decimal_buckets(0, 6),
            ),
            instructions_consumed_per_round: metrics_registry.histogram(
                "scheduler_instructions_consumed_per_round",
                "Wasm instructions consumed per round.",
                // 1, 2, 5, …, 1M, 2M, 5M
                decimal_buckets(0, 6),
            ),
            executable_canisters_per_round: metrics_registry.histogram(
                "scheduler_executable_canisters_per_round",
                "Number of canisters that can be executed per round.",
                // 1, 2, 5, …, 10000, 20000, 50000
                decimal_buckets(0, 4),
            ),
            executed_canisters_per_round: metrics_registry.histogram(
                "scheduler_executed_canisters_per_round",
                "Number of canisters that were actually executed in the last round.",
                // 1, 2, 5, …, 10000, 20000, 50000
                decimal_buckets(0, 4),
            ),
            expired_ingress_messages_count: metrics_registry.int_counter(
                "scheduler_expired_ingress_messages_count",
                "Total number of ingress messages that expired before \
                      reaching a terminal state.",
            ),
            ingress_history_length: metrics_registry.int_gauge(
                "replicated_state_ingress_history_length",
                "Total number of entries kept in the ingress history.",
            ),
            msg_execution_duration: duration_histogram(
                "scheduler_message_execution_duration_seconds",
                "The duration of single message execution in seconds.",
                metrics_registry,
            ),
            registered_canisters: metrics_registry.int_gauge_vec(
                "replicated_state_registered_canisters",
                "Total number of canisters keyed by their current status.",
                &["status"],
            ),
            available_canister_ids: metrics_registry.int_gauge(
                "replicated_state_available_canister_ids",
                "Number of allocated canister IDs that can still be generated.",
            ),
            consumed_cycles: metrics_registry.gauge(
                "replicated_state_consumed_cycles_since_replica_started",
                "Number of cycles consumed",
            ),
            consumed_cycles_by_use_case: metrics_registry.gauge_vec(
                "replicated_state_consumed_cycles_from_replica_start",
                "Number of cycles consumed by use cases.",
                &["use_case"],
            ),
            threshold_signature_agreements: metrics_registry.int_gauge_vec(
                "replicated_state_threshold_signature_agreements_total",
                "Total number of threshold signature agreements created by key Id",
                &["key_id"],
            ),
            delivered_pre_signatures: metrics_registry.histogram_vec(
                "execution_idkg_delivered_pre_signatures",
                "Number of IDkg pre-signatures delivered to execution by key ID",
                vec![0.0, 1.0, 2.0, 5.0, 10.0, 15.0, 20.0],
                &["key_id"],
            ),
            exceeding_pre_signatures: metrics_registry.int_counter_vec(
                "execution_idkg_exceeding_pre_signatures",
                "Number of IDkg pre-signatures delivered to execution that exceeded the maximum stash size",
                &["key_id"],
            ),
            in_flight_signature_request_contexts: metrics_registry.histogram_vec(
                "execution_in_flight_signature_request_contexts",
                "Number of in flight signature request contexts by key ID",
                vec![1.0, 2.0, 3.0, 5.0, 10.0, 15.0, 20.0, 50.0],
                &["key_id"],
            ),
            completed_signature_request_contexts: metrics_registry.int_counter_vec(
                "execution_completed_signature_request_contexts_total",
                "Total number of completed signature request contexts by key ID",
                &["key_id"],
            ),
            pre_signature_stash_size: metrics_registry.int_gauge_vec(
                "execution_pre_signature_stash_size",
                "Number of pre-signatures currently stored in the pre-signature stash, by key ID.",
                &["key_id"],
            ),
            threshold_signature_scheme_mismatch: metrics_registry.error_counter(THRESHOLD_SIGNATURE_SCHEME_MISMATCH),
            input_queue_messages: metrics_registry.int_gauge_vec(
                "execution_input_queue_messages",
                "Count of messages currently enqueued in input queues, by message kind.",
                &[LABEL_MESSAGE_KIND],
            ),
            input_queues_size_bytes: metrics_registry.int_gauge_vec(
                "execution_input_queue_size_bytes",
                "Byte size of input queues, by message kind.",
                &[LABEL_MESSAGE_KIND],
            ),
            queues_response_bytes: metrics_registry.int_gauge(
                "execution_queues_response_size_bytes",
                "Total byte size of all responses in input and output queues.",
            ),
            queues_memory_reservations: metrics_registry.int_gauge(
                "execution_queues_reservations",
                "Total number of memory reservations for guaranteed responses in input and output queues.",
            ),
            queues_oversized_requests_extra_bytes: metrics_registry.int_gauge(
                "execution_queues_oversized_requests_extra_bytes",
                "Total bytes above `MAX_RESPONSE_COUNT_BYTES` across oversized local-subnet requests.",
            ),
            queues_best_effort_message_bytes: metrics_registry.int_gauge(
                "execution_queues_best_effort_message_bytes",
                "Total byte size of all best-effort messages in canister queues.",
            ),
            canister_messages_where_cycles_were_charged: metrics_registry.int_counter(
                "scheduler_canister_messages_where_cycles_were_charged",
                "Total number of canister messages which resulted in cycles being charged.",
            ),
            current_heap_delta: metrics_registry.int_gauge(
                "current_heap_delta",
                "Estimate of the current size of the heap delta since the last checkpoint",
            ),
            round_skipped_due_to_current_heap_delta_above_limit: metrics_registry.int_counter(
                "round_skipped_due_to_current_heap_delta_above_limit",
                "The number of rounds that were skipped because the current \
                      heap delta size exceeded the allowed max",
            ),
            execute_round_called: metrics_registry.int_counter(
                "execute_round_called",
                "The number of times execute_round has been called.",
            ),
            // comparing this metric with the `execute_round_called` metric
            // allows one to estimate how often we manage to execute multiple
            // loops of inner_round(), i.e. how often we manage to successfully
            // induct messages on the same subnet and make progress on them.
            inner_loop_consumed_non_zero_instructions_count: metrics_registry.int_counter(
                "inner_loop_consumed_non_zero_instructions_count",
                "The number of times inner_round()'s loop consumed at least 1 instruction.",
            ),
            inner_round_loop_consumed_max_instructions: metrics_registry.int_counter(
                "inner_round_loop_consumed_max_instructions",
                "The number of times inner_rounds()'s loop exited because \
                      max allowed instructions were consumed.",
            ),
            num_canisters_uninstalled_out_of_cycles: metrics_registry.int_counter(
                "scheduler_num_canisters_uninstalled_out_of_cycles",
                "The number of canisters that were uninstalled because \
                      they ran out of cycles.",
            ),
            round: ScopedMetrics {
                duration: duration_histogram(
                    "execution_round_duration_seconds",
                    "The duration of an execution round",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_round_instructions",
                    "The number of instructions executed in an execution round",
                    metrics_registry,
                ),
                slices: slices_histogram(
                    "execution_round_slices",
                    "The number of slices executed in an execution round",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_round_messages",
                    "The number of messages executed in an execution round",
                    metrics_registry,
                ),
            },
            round_preparation_duration: duration_histogram(
                "execution_round_preparation_duration_seconds",
                "The duration of execution round preparation in seconds.",
                metrics_registry,
            ),
            round_preparation_ingress: duration_histogram(
                "execution_round_preparation_ingress_pruning_duration_seconds",
                "The duration of purging ingress during execution round \
                      preparation in seconds.",
                metrics_registry,
            ),
            round_consensus_queue: ScopedMetrics {
                duration: duration_histogram(
                    "execution_round_consensus_queue_duration_seconds",
                    "The duration of consensus queue processing in \
                          an execution round",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_round_consensus_queue_instructions",
                    "The number of instructions executed during consensus \
                          queue processing in an execution round",
                    metrics_registry,
                ),
                slices: slices_histogram(
                    "execution_round_consensus_queue_slices",
                    "The number of slices executed during consensus \
                          queue processing in an execution round",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_round_consensus_queue_messages",
                    "The number of messages executed during consensus \
                          queue processing in an execution round",
                    metrics_registry,
                ),
            },
            round_postponed_raw_rand_queue: ScopedMetrics {
                duration: duration_histogram(
                    "execution_round_postponed_raw_rand_queue_duration_seconds",
                    "The duration of postponed raw rand queue processing in \
                          an execution round",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_round_postponed_raw_rand_queue_instructions",
                    "The number of instructions executed during postponed \
                          raw rand queue processing in an execution round",
                    metrics_registry,
                ),
                slices: slices_histogram(
                    "execution_round_postponed_raw_rand_queue_slices",
                    "The number of slices executed during postponed \
                          raw rand queue processing in an execution round",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_round_postponed_raw_rand_queue_messages",
                    "The number of messages executed during postponed \
                          raw rand queue processing in an execution round",
                    metrics_registry,
                ),
            },
            round_subnet_queue: ScopedMetrics {
                duration: duration_histogram(
                    "execution_round_subnet_queue_duration_seconds",
                    "The duration of subnet queue processing in \
                          an execution round",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_round_subnet_queue_instructions",
                    "The number of instructions executed during subnet \
                          queue processing in an execution round",
                    metrics_registry,
                ),
                slices: slices_histogram(
                    "execution_round_subnet_queue_slices",
                    "The number of slices executed during subnet \
                          queue processing in an execution round",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_round_subnet_queue_messages",
                    "The number of messages executed during subnet \
                          queue processing in an execution round",
                    metrics_registry,
                ),
            },
            round_advance_long_install_code: ScopedMetrics {
                duration: duration_histogram(
                    "execution_round_advance_long_install_code_duration_seconds",
                    "The duration of advancing an in progress long install code in \
                          an execution round",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_round_advance_long_install_code_instructions",
                    "The number of instructions executed during advancing \
                        an in progress install code in an execution round",
                    metrics_registry,
                ),
                slices: slices_histogram(
                    "execution_round_advance_long_install_code_slices",
                    "The number of slices executed executed during advancing \
                        an in progress install code in an execution round",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_round_advance_long_install_code_messages",
                    "The number of messages executed during advancing \
                        an in progress install code in an execution round",
                    metrics_registry,
                ),
            },
            round_scheduling_duration: duration_histogram(
                "execution_round_scheduling_duration_seconds",
                "The duration of execution round scheduling in seconds.",
                metrics_registry,
            ),
            round_update_signature_request_contexts_duration: duration_histogram(
                "execution_round_update_signature_request_contexts_duration_seconds",
                "The duration of updating signature request contexts in seconds.",
                metrics_registry,
            ),
            round_inner: ScopedMetrics {
                duration: duration_histogram(
                    "execution_round_inner_duration_seconds",
                    "The duration of an inner round",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_round_inner_instructions",
                    "The number of instructions executed in an inner round",
                    metrics_registry,
                ),
                slices: slices_histogram(
                    "execution_round_inner_slices",
                    "The number of slices executed in an inner round",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_round_inner_messages",
                    "The number of messages executed in an inner round",
                    metrics_registry,
                ),
            },
            round_inner_heartbeat_overhead_duration: duration_histogram(
                "execution_round_inner_heartbeat_overhead_duration_seconds",
                "The duration of iterating canisters to prepare/remove heartbeat and global timer tasks",
                metrics_registry,
            ),
            round_inner_iteration: ScopedMetrics {
                duration: duration_histogram(
                    "execution_round_inner_iteration_duration_seconds",
                    "The duration of an iteration of an inner round",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_round_inner_iteration_instructions",
                    "The number of instructions executed in an iteration of an inner round",
                    metrics_registry,
                ),
                slices: slices_histogram(
                    "execution_round_inner_iteration_slices",
                    "The number of messages executed in an iteration of an inner round",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_round_inner_iteration_messages",
                    "The number of messages executed in an iteration of an inner round",
                    metrics_registry,
                ),
            },
            round_inner_iteration_prep: duration_histogram(
                "execution_round_inner_preparation_duration_seconds",
                "The duration of inner execution round preparation in seconds.",
                metrics_registry,
            ),
            round_inner_iteration_exe: duration_histogram(
                "execution_round_inner_execution_duration_seconds",
                "The duration of inner execution round of all the threads in seconds.",
                metrics_registry,
            ),
            round_inner_iteration_thread: ScopedMetrics {
                duration: duration_histogram(
                    "execution_round_inner_iteration_thread_duration_seconds",
                    "The duration of a thread spawned by an iteration of \
                          an inner round",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_round_inner_iteration_thread_instructions",
                    "The number of instructions executed in a thread spawned \
                          by an iteration of an inner round",
                    metrics_registry,
                ),
                slices: slices_histogram(
                    "execution_round_inner_iteration_thread_slices",
                    "The number of messages executed in a thread spawned \
                          by an iteration of an inner round",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_round_inner_iteration_thread_messages",
                    "The number of messages executed in a thread spawned \
                          by an iteration of an inner round",
                    metrics_registry,
                ),
            },
            round_inner_iteration_thread_message: ScopedMetrics {
                duration: duration_histogram(
                    "execution_round_inner_iteration_thread_message_duration_seconds",
                    "The duration of executing a message in a thread \
                          spawned by an iteration of an inner round",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_round_inner_iteration_thread_message_instructions",
                    "The number of instructions executed in a message \
                          in a thread spawned by an iteration of an inner round",
                    metrics_registry,
                ),
                slices: slices_histogram(
                    "execution_round_inner_iteration_thread_message_slices",
                    "The number of slices executed in a message in a \
                          thread spawned by an iteration of an inner round",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_round_inner_iteration_thread_message_messages",
                    "The number of messages executed in a message in a \
                          thread spawned by an iteration of an inner round",
                    metrics_registry,
                ),
            },
            round_inner_iteration_fin: duration_histogram(
                "execution_round_inner_finalization_duration_seconds",
                "The duration of inner execution round finalization in seconds.",
                metrics_registry,
            ),
            round_inner_iteration_fin_induct: duration_histogram(
                "execution_round_inner_finalization_message_induction_duration_seconds",
                "The duration of message induction during inner execution \
                      round finalization in seconds.",
                metrics_registry,
            ),
            round_finalization_duration: duration_histogram(
                "execution_round_finalization_duration_seconds",
                "The duration of execution round finalization in seconds.",
                metrics_registry,
            ),
            round_finalization_stop_canisters: duration_histogram(
                "execution_round_finalization_stop_canisters_duration_seconds",
                "The duration of stopping canisters during execution \
                      round finalization in seconds.",
                metrics_registry,
            ),
            round_finalization_ingress: duration_histogram(
                "execution_round_finalization_ingress_history_prune_duration_seconds",
                "The duration of pruning ingress during execution round \
                      finalization in seconds.",
                metrics_registry,
            ),
            round_finalization_charge: duration_histogram(
                "execution_round_finalization_charge_resources_duration_seconds",
                "The duration of charging for resources during execution \
                      round finalization in seconds.",
                metrics_registry,
            ),
            canister_heap_delta_debits: metrics_registry.histogram(
                "scheduler_canister_heap_delta_debits",
                "The heap delta debit of a canister at the end of the round, before \
                subtracting the rate limit allowed amount.",
                // 1 MB, 2 MB, 5 MB, ..., 10 GB, 20 GB, 50 GB
                decimal_buckets(6, 10),
            ),
            heap_delta_rate_limited_canisters_per_round: metrics_registry.histogram(
                "scheduler_heap_delta_rate_limited_canisters_per_round",
                "Number of canisters that were heap delta rate limited in a given round.",
                // 0, 1, 2, 5, …, 1000, 2000, 5000
                decimal_buckets_with_zero(0, 3),
            ),
            canisters_not_in_routing_table: metrics_registry.int_gauge(
                "replicated_state_canisters_not_in_routing_table",
                "Number of canisters in the state not assigned to the subnet range in the routing table."
            ),
            canister_install_code_debits: instructions_histogram(
                "scheduler_canister_install_code_debits",
                "The install code debit of a canister at the end of the round, before \
                subtracting the rate limit allowed amount",
                metrics_registry,
            ),
            old_open_call_contexts: metrics_registry.int_gauge_vec(
                "scheduler_old_open_call_contexts",
                "Number of call contexts that have been open for more than the given age.",
                &["age"]
            ),
            canisters_with_old_open_call_contexts: metrics_registry.int_gauge_vec(
                "scheduler_canisters_with_old_open_call_contexts",
                "Number of canisters with call contexts that have been open for more than the given age.",
                &["age"]
            ),
            canister_invariants: metrics_registry.error_counter(CANISTER_INVARIANT_BROKEN),
            scheduler_compute_allocation_invariant_broken: metrics_registry.error_counter(SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN),
            scheduler_cores_invariant_broken: metrics_registry.error_counter(SCHEDULER_CORES_INVARIANT_BROKEN),
            scheduler_accumulated_priority_invariant: metrics_registry.int_gauge(
                "scheduler_accumulated_priority_invariant",
                "The sum of all accumulated priorities on the subnet."
            ),
            scheduler_accumulated_priority_deviation: metrics_registry.gauge(
                "scheduler_accumulated_priority_deviation",
                "The standard deviation of accumulated priorities on the subnet."
            ),
            subnet_memory_usage_invariant: metrics_registry.error_counter(SUBNET_MEMORY_USAGE_INVARIANT_BROKEN),
            total_canister_balance: metrics_registry.gauge(
                "scheduler_canister_balance_cycles_total",
                "Total canister balance in Cycles.",
            ),
            total_canister_reserved_balance: metrics_registry.gauge(
                "scheduler_canister_reserved_balance_cycles_total",
                "Total canister reserved balance in Cycles.",
            ),
            canister_paused_execution: dts_pause_or_abort_histogram(
                "scheduler_canister_paused_execution",
                "Number of canisters that have a paused execution.",
                metrics_registry,
            ),
            canister_aborted_execution: dts_pause_or_abort_histogram(
                "scheduler_canister_aborted_execution",
                "Number of canisters that have an aborted execution.",
                metrics_registry,
            ),
            canister_paused_install_code: dts_pause_or_abort_histogram(
                "scheduler_canister_paused_install_code",
                "Number of canisters that have a paused install code.",
                metrics_registry,
            ),
            canister_aborted_install_code: dts_pause_or_abort_histogram(
                "scheduler_canister_aborted_install_code",
                "Number of canisters that have an aborted install code.",
                metrics_registry,
            ),
            inducted_messages: metrics_registry.int_counter_vec(
                "scheduler_inducted_messages_total",
                "Number of messages inducted, by destination.",
                &["destination"],
            ),
            stop_canister_calls_without_call_id:  metrics_registry.int_gauge(
                "scheduler_stop_canister_calls_without_call_id",
                "Number of stop canister calls with missing call ID.",
            ),
            canister_snapshots_memory_usage: metrics_registry.int_gauge(
                "scheduler_canister_snapshots_memory_usage_bytes",
                "Canisters total snapshots memory usage in bytes.",
            ),
            num_canister_snapshots: metrics_registry.int_gauge(
                "scheduler_num_canister_snapshots",
                "Total number of canister snapshots on this subnet.",
            ),
            zero_instruction_messages: metrics_registry.int_counter(
                "scheduler_zero_instruction_messages",
                "Number of messages that were scheduled to be \
                executed, but didn't end up using any cycles. Possibly \
                because the canister couldn't prepay for the execution."
            )
        }
    }

    pub(super) fn observe_consumed_cycles(&self, consumed_cycles: NominalCycles) {
        self.consumed_cycles.set(consumed_cycles.get() as f64);
    }

    pub(super) fn observe_consumed_cycles_by_use_case(
        &self,
        consumed_cycles_by_use_case: &BTreeMap<CyclesUseCase, NominalCycles>,
    ) {
        for (use_case, cycles) in consumed_cycles_by_use_case.iter() {
            self.consumed_cycles_by_use_case
                .with_label_values(&[use_case.as_str()])
                .set(cycles.get() as f64);
        }
    }

    pub(super) fn observe_input_messages(&self, kind: &str, message_count: usize) {
        self.input_queue_messages
            .with_label_values(&[kind])
            .set(message_count as i64);
    }

    pub(super) fn observe_input_queues_size_bytes(&self, kind: &str, message_bytes: usize) {
        self.input_queues_size_bytes
            .with_label_values(&[kind])
            .set(message_bytes as i64);
    }

    pub(super) fn observe_queues_response_bytes(&self, size_bytes: usize) {
        self.queues_response_bytes.set(size_bytes as i64);
    }

    pub(super) fn observe_queues_memory_reservations(&self, reservations: usize) {
        self.queues_memory_reservations.set(reservations as i64);
    }

    pub(super) fn observe_oversized_requests_extra_bytes(&self, size_bytes: usize) {
        self.queues_oversized_requests_extra_bytes
            .set(size_bytes as i64);
    }

    pub(super) fn observe_queues_best_effort_message_bytes(&self, size_bytes: usize) {
        self.queues_best_effort_message_bytes.set(size_bytes as i64);
    }
}
