use ic_metrics::{
    buckets::{decimal_buckets, decimal_buckets_with_zero, linear_buckets},
    MetricsRegistry,
};
use ic_types::nominal_cycles::NominalCycles;
use prometheus::{Gauge, Histogram, IntCounter, IntGauge, IntGaugeVec};

use crate::metrics::{
    duration_histogram, instructions_histogram, messages_histogram, ScopedMetrics,
};

pub(super) struct SchedulerMetrics {
    pub(super) canister_age: Histogram,
    pub(super) canister_compute_allocation_violation: IntCounter,
    pub(super) compute_utilization_per_core: Histogram,
    pub(super) instructions_consumed_per_message: Histogram,
    pub(super) instructions_consumed_per_round: Histogram,
    pub(super) executable_canisters_per_round: Histogram,
    pub(super) expired_ingress_messages_count: IntCounter,
    pub(super) ingress_history_length: IntGauge,
    pub(super) msg_execution_duration: Histogram,
    pub(super) registered_canisters: IntGaugeVec,
    pub(super) consumed_cycles_since_replica_started: Gauge,
    pub(super) input_queue_messages: IntGaugeVec,
    pub(super) input_queues_size_bytes: IntGaugeVec,
    pub(super) queues_response_bytes: IntGauge,
    pub(super) queues_reservations: IntGauge,
    pub(super) streams_response_bytes: IntGauge,
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
    pub(super) round_subnet_queue: ScopedMetrics,
    pub(super) round_scheduling_duration: Histogram,
    pub(super) round_inner: ScopedMetrics,
    pub(super) round_inner_iteration: ScopedMetrics,
    pub(super) round_inner_iteration_prep: Histogram,
    pub(super) round_inner_iteration_thread: ScopedMetrics,
    pub(super) round_inner_iteration_thread_heartbeat: ScopedMetrics,
    pub(super) round_inner_iteration_thread_message: ScopedMetrics,
    pub(super) round_inner_iteration_fin: Histogram,
    pub(super) round_inner_iteration_fin_induct: Histogram,
    pub(super) round_finalization_duration: Histogram,
    pub(super) round_finalization_stop_canisters: Histogram,
    pub(super) round_finalization_ingress: Histogram,
    pub(super) round_finalization_charge: Histogram,
    pub(super) execution_round_failed_heartbeat_executions: IntCounter,
    pub(super) canister_heap_delta_debits: Histogram,
    pub(super) heap_delta_rate_limited_canisters_per_round: Histogram,
}

const LABEL_MESSAGE_KIND: &str = "kind";
pub(super) const MESSAGE_KIND_INGRESS: &str = "ingress";
pub(super) const MESSAGE_KIND_CANISTER: &str = "canister";

impl SchedulerMetrics {
    pub(super) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            canister_age: metrics_registry.histogram(
                "scheduler_canister_age_rounds",
                "Number of rounds for which a canister was not scheduled.",
                // 1, 2, 5, …, 100, 200, 500
                decimal_buckets(0, 2),
            ),
            canister_compute_allocation_violation: metrics_registry.int_counter(
                "scheduler_compute_allocation_violations",
                "Total number of canister allocation violations.",
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
                // 1, 2, 5, …, 1000, 2000, 5000
                decimal_buckets(0, 3),
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
            /// Metric `consumed_cycles_since_replica_started` is not
            /// monotonically increasing. Cycles consumed are increasing the
            /// value of the metric while refunding cycles are decreasing it.
            ///
            /// `f64` gauge because cycles values are `u128`: converting them
            /// into `u64` would result in truncation when the value overflows
            /// 64 bits (which would be indistinguishable from a huge refund);
            /// whereas conversion to `f64` merely results in loss of precision
            /// when dealing with values > 2^53.
            consumed_cycles_since_replica_started: metrics_registry.gauge(
                "replicated_state_consumed_cycles_since_replica_started",
                "Number of cycles consumed since replica started",
            ),
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
            queues_reservations: metrics_registry.int_gauge(
                "execution_queues_reservations",
                "Total number of reserved slots for responses in input and output queues.",
            ),
            streams_response_bytes: metrics_registry.int_gauge(
                "execution_streams_response_size_bytes",
                "Total byte size of all responses in subnet streams.",
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
                messages: messages_histogram(
                    "execution_round_consensus_queue_messages",
                    "The number of messages executed during consensus \
                          queue processing in an execution round",
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
                messages: messages_histogram(
                    "execution_round_subnet_queue_messages",
                    "The number of messages executed during subnet \
                          queue processing in an execution round",
                    metrics_registry,
                ),
            },
            round_scheduling_duration: duration_histogram(
                "execution_round_scheduling_duration_seconds",
                "The duration of execution round scheduling in seconds.",
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
                messages: messages_histogram(
                    "execution_round_inner_messages",
                    "The number of messages executed in an inner round",
                    metrics_registry,
                ),
            },
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
                messages: messages_histogram(
                    "execution_round_inner_iteration_thread_messages",
                    "The number of messages executed in a thread spawned \
                          by an iteration of an inner round",
                    metrics_registry,
                ),
            },
            round_inner_iteration_thread_heartbeat: ScopedMetrics {
                duration: duration_histogram(
                    "execution_round_inner_iteration_thread_heartbeat_duration_seconds",
                    "The duration of executing a heartbeat in a thread \
                          spawned by an iteration of an inner round",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_round_inner_iteration_thread_heartbeat_instructions",
                    "The number of instructions executed in a heartbeat \
                          in a thread spawned by an iteration of an inner round",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_round_inner_iteration_thread_heartbeat_messages",
                    "The number of messages executed in a heartbeat in a \
                          thread spawned by an iteration of an inner round",
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
            execution_round_failed_heartbeat_executions: metrics_registry.int_counter(
                "execution_round_failed_heartbeat_executions",
                "Total number of heartbeat executions that completed in error",
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
        }
    }

    pub(super) fn observe_consumed_cycles(&self, consumed_cycles: NominalCycles) {
        self.consumed_cycles_since_replica_started
            .set(consumed_cycles.get() as f64);
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

    pub(super) fn observe_queues_reservations(&self, reservations: usize) {
        self.queues_reservations.set(reservations as i64);
    }

    pub(super) fn observe_streams_response_bytes(&self, size_bytes: usize) {
        self.streams_response_bytes.set(size_bytes as i64);
    }
}
