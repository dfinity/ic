use crate::metrics::ScopedMetrics;
use crate::scheduler::threshold_signatures::THRESHOLD_SIGNATURE_SCHEME_MISMATCH;
use ic_metrics::MetricsRegistry;
use ic_metrics::buckets::{
    binary_buckets_with_zero, decimal_buckets, decimal_buckets_with_zero, linear_buckets,
};
use ic_replicated_state::metrics::{
    duration_histogram, instructions_buckets, instructions_histogram, messages_buckets,
    messages_histogram, slices_histogram,
};
use prometheus::{Gauge, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec};

pub(crate) const CANISTER_INVARIANT_BROKEN: &str = "scheduler_canister_invariant_broken";
pub(crate) const SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN: &str =
    "scheduler_compute_allocation_invariant_broken";
pub(crate) const SCHEDULER_CORES_INVARIANT_BROKEN: &str = "scheduler_cores_invariant_broken";

pub(super) struct SchedulerMetrics {
    pub(super) canister_age: Histogram,
    pub(super) canister_compute_allocation_violation: IntCounter,
    pub(super) canister_log_delta_memory_usage: Histogram,
    pub(super) canister_ingress_queue_latencies: Histogram,
    pub(super) compute_utilization_per_core: Histogram,
    pub(super) msg_execution_duration: Histogram,
    pub(super) instructions_consumed_per_message: Histogram,
    pub(super) executable_canisters_per_round: Histogram,
    pub(super) executed_canisters_per_round: Histogram,
    pub(super) expired_ingress_messages_count: IntCounter,
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
    pub(super) round_inner_iteration_scheduling: Histogram,
    pub(super) round_inner_iteration_exe: Histogram,
    pub(super) round_inner_iteration_thread: ScopedMetrics,
    pub(super) round_inner_iteration_fin: Histogram,
    pub(super) round_inner_iteration_fin_induct: Histogram,
    pub(super) round_finalization_duration: Histogram,
    pub(super) round_finalization_stop_canisters: Histogram,
    pub(super) round_finalization_ingress: Histogram,
    pub(super) round_finalization_charge: Histogram,
    pub(super) heap_delta_rate_limited_canisters_per_round: Histogram,
    pub(super) canister_invariants: IntCounter,
    pub(super) scheduler_compute_allocation_invariant_broken: IntCounter,
    pub(super) scheduler_cores_invariant_broken: IntCounter,
    pub(super) scheduler_accumulated_priority_deviation: Gauge,
    pub(super) inducted_messages: IntCounterVec,
    pub(super) delivered_pre_signatures: HistogramVec,
    pub(super) exceeding_pre_signatures: IntCounterVec,
    pub(super) completed_signature_request_contexts: IntCounterVec,
    pub(super) threshold_signature_scheme_mismatch: IntCounter,
}

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
            canister_log_delta_memory_usage: metrics_registry.histogram(
                "canister_log_delta_memory_usage_bytes",
                "Canisters log delta (per single execution) memory usage distribution in bytes.",
                // 1 KiB (2^10) .. 8 MiB (2^23), plus zero — 15 total buckets (0 + 14 powers).
                binary_buckets_with_zero(10, 23)
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
            msg_execution_duration: duration_histogram(
                "scheduler_message_execution_duration_seconds",
                "Durations of single replicated message executions in seconds.",
                metrics_registry,
            ),
            instructions_consumed_per_message: instructions_histogram(
                "scheduler_instructions_consumed_per_message",
                "Wasm instructions consumed per message. Also includes zero instruction message executions (i.e. too few cycles to execute).",
                metrics_registry,
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
            completed_signature_request_contexts: metrics_registry.int_counter_vec(
                "execution_completed_signature_request_contexts_total",
                "Total number of completed signature request contexts by key ID",
                &["key_id"],
            ),
            threshold_signature_scheme_mismatch: metrics_registry.error_counter(THRESHOLD_SIGNATURE_SCHEME_MISMATCH),
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
            round_preparation_duration: round_phase_duration_histogram("preparation", metrics_registry),
            // Expiration of messages in the ingress queue.
            round_preparation_ingress: round_preparation_phase_duration_histogram("expire ingress", metrics_registry),
            // Processing of messages in the consensus queue.
            round_consensus_queue: ScopedMetrics {
                duration: round_phase_duration_histogram("consensus", metrics_registry),
                instructions: round_phase_instructions_histogram("consensus", metrics_registry),
                slices: round_phase_slices_histogram("consensus", metrics_registry),
                messages: round_phase_messages_histogram("consensus", metrics_registry),
            },
            // Processing of postponed `raw_rand` calls.
            round_postponed_raw_rand_queue: ScopedMetrics {
                duration: round_phase_duration_histogram("raw_rand", metrics_registry),
                instructions: round_phase_instructions_histogram("raw_rand", metrics_registry),
                slices: round_phase_slices_histogram("raw_rand", metrics_registry),
                messages: round_phase_messages_histogram("raw_rand", metrics_registry),
            },
            // Subnet queue processing happens in `inner_round()`, so in terms of
            // instrumentation it is an inner round phase.
            round_subnet_queue: ScopedMetrics {
                duration: round_inner_phase_duration_histogram("subnet", metrics_registry),
                instructions: round_inner_phase_instructions_histogram("subnet", metrics_registry),
                slices: round_inner_phase_slices_histogram("subnet", metrics_registry),
                messages: round_inner_phase_messages_histogram("subnet", metrics_registry),
            },
            // Advancing in-progress long install code.
            round_advance_long_install_code: ScopedMetrics {
                duration: round_phase_duration_histogram("long install", metrics_registry),
                instructions: round_phase_instructions_histogram("long install", metrics_registry),
                slices: round_phase_slices_histogram("long install", metrics_registry),
                messages: round_phase_messages_histogram("long install", metrics_registry),
            },
            round_scheduling_duration: round_phase_duration_histogram("scheduling", metrics_registry),
            round_update_signature_request_contexts_duration: round_phase_duration_histogram("threshold sign", metrics_registry),
            // `inner_round()` processing.
            round_inner: ScopedMetrics {
                duration: round_phase_duration_histogram("inner", metrics_registry),
                instructions: round_phase_instructions_histogram("inner", metrics_registry),
                slices: round_phase_slices_histogram("inner", metrics_registry),
                messages: round_phase_messages_histogram("inner", metrics_registry),
            },
            round_inner_heartbeat_overhead_duration: round_inner_phase_duration_histogram("heartbeat overhead", metrics_registry),
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
            round_inner_iteration_prep: round_inner_phase_duration_histogram("preparation", metrics_registry),
            round_inner_iteration_scheduling: round_inner_phase_duration_histogram("scheduling", metrics_registry),
            round_inner_iteration_exe: round_inner_phase_duration_histogram("execution", metrics_registry),
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
            round_inner_iteration_fin: round_inner_phase_duration_histogram("finalization", metrics_registry),
            round_inner_iteration_fin_induct: duration_histogram(
                "execution_round_inner_finalization_message_induction_duration_seconds",
                "The duration of message induction during inner execution \
                      round finalization in seconds.",
                metrics_registry,
            ),
            round_finalization_duration: round_phase_duration_histogram("finalization", metrics_registry),
            round_finalization_stop_canisters: round_finalization_phase_duration_histogram("stop canisters", metrics_registry),
            // Pruning of expired messages from the ingress history.
            round_finalization_ingress: round_finalization_phase_duration_histogram("prune ingress", metrics_registry),
            round_finalization_charge: round_finalization_phase_duration_histogram("charge canisters", metrics_registry),
            heap_delta_rate_limited_canisters_per_round: metrics_registry.histogram(
                "scheduler_heap_delta_rate_limited_canisters_per_round",
                "Number of canisters that were heap delta rate limited in a given round.",
                // 0, 1, 2, 5, …, 1000, 2000, 5000
                decimal_buckets_with_zero(0, 3),
            ),
            canister_invariants: metrics_registry.error_counter(CANISTER_INVARIANT_BROKEN),
            scheduler_compute_allocation_invariant_broken: metrics_registry.error_counter(SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN),
            scheduler_cores_invariant_broken: metrics_registry.error_counter(SCHEDULER_CORES_INVARIANT_BROKEN),
            scheduler_accumulated_priority_deviation: metrics_registry.gauge(
                "scheduler_accumulated_priority_deviation",
                "The standard deviation of accumulated priorities on the subnet."
            ),
            inducted_messages: metrics_registry.int_counter_vec(
                "scheduler_inducted_messages_total",
                "Number of messages inducted, by destination.",
                &["destination"],
            ),
        }
    }
}

fn round_phase_duration_histogram(phase: &str, metrics_registry: &MetricsRegistry) -> Histogram {
    phase_duration_histogram(
        "execution_round_phase_duration_seconds",
        "Durations of specific execute_round() phases, in seconds.",
        phase,
        metrics_registry,
    )
}

fn round_phase_instructions_histogram(
    phase: &str,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    phase_instructions_histogram(
        "execution_round_phase_instructions",
        "Number of instructions executed in specific execute_round() phases.",
        phase,
        metrics_registry,
    )
}

fn round_phase_slices_histogram(phase: &str, metrics_registry: &MetricsRegistry) -> Histogram {
    phase_messages_histogram(
        "execution_round_phase_slices",
        "Number of slices executed in specific execute_round() phases.",
        phase,
        metrics_registry,
    )
}

fn round_phase_messages_histogram(phase: &str, metrics_registry: &MetricsRegistry) -> Histogram {
    phase_messages_histogram(
        "execution_round_phase_messages",
        "Number of messages executed in specific execute_round() phases.",
        phase,
        metrics_registry,
    )
}

fn round_preparation_phase_duration_histogram(
    phase: &str,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    phase_duration_histogram(
        "execution_round_preparation_phase_duration_seconds",
        "Durations of specific round preparation phases, in seconds.",
        phase,
        metrics_registry,
    )
}

fn round_inner_phase_duration_histogram(
    phase: &str,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    phase_duration_histogram(
        "execution_round_inner_phase_duration_seconds",
        "Durations of specific inner_round() phases, in seconds.",
        phase,
        metrics_registry,
    )
}

fn round_inner_phase_instructions_histogram(
    phase: &str,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    phase_instructions_histogram(
        "execution_round_inner_phase_instructions",
        "Number of instructions executed in specific inner_round() phases.",
        phase,
        metrics_registry,
    )
}

fn round_inner_phase_slices_histogram(
    phase: &str,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    phase_messages_histogram(
        "execution_round_inner_phase_slices",
        "Number of slices executed in specific inner_round() phases.",
        phase,
        metrics_registry,
    )
}

fn round_inner_phase_messages_histogram(
    phase: &str,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    phase_messages_histogram(
        "execution_round_inner_phase_messages",
        "Number of messages executed in specific inner_round() phases.",
        phase,
        metrics_registry,
    )
}

fn round_finalization_phase_duration_histogram(
    phase: &str,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    phase_duration_histogram(
        "execution_round_finalization_phase_duration_seconds",
        "Durations of specific round finalization phases, in seconds.",
        phase,
        metrics_registry,
    )
}

/// Returns a histogram with a `phase` const label and buckets appropriate for
/// durations.
fn phase_duration_histogram(
    name: &str,
    help: &str,
    phase: &str,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    metrics_registry.register(
        Histogram::with_opts(
            HistogramOpts::new(name, help)
                .const_label("phase", phase)
                .buckets(decimal_buckets_with_zero(-4, 1)),
        )
        .unwrap(),
    )
}

/// Returns a histogram with a `phase` const label and buckets appropriate for
/// instructions.
fn phase_instructions_histogram(
    name: &str,
    help: &str,
    phase: &str,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    metrics_registry.register(
        Histogram::with_opts(
            HistogramOpts::new(name, help)
                .const_label("phase", phase)
                .buckets(instructions_buckets()),
        )
        .unwrap(),
    )
}

/// Returns a histogram with a `phase` const label and buckets appropriate for
/// messages or slices.
fn phase_messages_histogram(
    name: &str,
    help: &str,
    phase: &str,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    metrics_registry.register(
        Histogram::with_opts(
            HistogramOpts::new(name, help)
                .const_label("phase", phase)
                .buckets(messages_buckets()),
        )
        .unwrap(),
    )
}
