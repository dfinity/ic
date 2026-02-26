use crate::canister_state::system_state::CyclesUseCase;
use crate::{
    CallOrigin, CanisterState, CanisterStatus, ExecutionTask, ReplicatedState, num_bytes_try_from,
};
use ic_base_types::SubnetId;
use ic_config::execution_environment::LOG_MEMORY_STORE_FEATURE_ENABLED;
use ic_logger::{ReplicaLogger, warn};
use ic_management_canister_types_private::{CanisterStatusType, MasterPublicKeyId};
use ic_metrics::MetricsRegistry;
use ic_metrics::buckets::{
    binary_buckets_with_zero, decimal_buckets, decimal_buckets_with_zero, linear_buckets,
};
use ic_types::nominal_cycles::NominalCycles;
use ic_types::{
    Cycles, Height, MAX_STABLE_MEMORY_IN_BYTES, MAX_WASM_MEMORY_IN_BYTES, NumInstructions, Time,
};
use prometheus::{Gauge, GaugeVec, Histogram, HistogramVec, IntGauge, IntGaugeVec};
use std::collections::BTreeMap;
use std::time::Duration;

const LABEL_MESSAGE_KIND: &str = "kind";
const MESSAGE_KIND_INGRESS: &str = "ingress";
const MESSAGE_KIND_CANISTER: &str = "canister";

/// Alert for call contexts older than this cutoff (one day).
const OLD_CALL_CONTEXT_CUTOFF_ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);
const OLD_CALL_CONTEXT_LABEL_ONE_DAY: &str = "1d";

/// Only log potentially spammy messages this often (in rounds). With a block
/// rate around 1.0, this will result in logging about once every 10 minutes.
const SPAMMY_LOG_INTERVAL_ROUNDS: u64 = 10 * 60;

pub struct ReplicatedStateMetrics {
    canister_balance: Histogram,
    canister_binary_size: Histogram,
    canister_log_memory_usage_v2: Histogram,
    canister_log_memory_usage_v3: Histogram,
    canister_wasm_memory_usage: Histogram,
    canister_stable_memory_usage: Histogram,
    canister_memory_allocation: Histogram,
    canister_compute_allocation: Histogram,
    ingress_history_length: IntGauge,
    registered_canisters: IntGaugeVec,
    available_canister_ids: IntGauge,
    consumed_cycles: Gauge,
    consumed_cycles_by_use_case: GaugeVec,
    input_queue_messages: IntGaugeVec,
    input_queues_size_bytes: IntGaugeVec,
    queues_response_bytes: IntGauge,
    queues_memory_reservations: IntGauge,
    queues_oversized_requests_extra_bytes: IntGauge,
    queues_best_effort_message_bytes: IntGauge,
    current_heap_delta: IntGauge,
    canisters_not_in_routing_table: IntGauge,
    old_open_call_contexts: IntGaugeVec,
    canisters_with_old_open_call_contexts: IntGaugeVec,
    total_canister_balance: Gauge,
    total_canister_reserved_balance: Gauge,
    canister_paused_execution: Histogram,
    canister_aborted_execution: Histogram,
    canister_paused_install_code: Histogram,
    canister_aborted_install_code: Histogram,
    threshold_signature_agreements: IntGaugeVec,
    in_flight_signature_request_contexts: HistogramVec,
    pre_signature_stash_size: IntGaugeVec,
    stop_canister_calls_without_call_id: IntGauge,
    canister_snapshots_memory_usage: IntGauge,
    num_canister_snapshots: IntGauge,
}

impl ReplicatedStateMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
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
            ingress_history_length: metrics_registry.int_gauge(
                "replicated_state_ingress_history_length",
                "Total number of entries kept in the ingress history.",
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
            current_heap_delta: metrics_registry.int_gauge(
                "current_heap_delta",
                "Estimate of the current size of the heap delta since the last checkpoint",
            ),
            canisters_not_in_routing_table: metrics_registry.int_gauge(
                "replicated_state_canisters_not_in_routing_table",
                "Number of canisters in the state not assigned to the subnet range in the routing table."
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
            threshold_signature_agreements: metrics_registry.int_gauge_vec(
                "replicated_state_threshold_signature_agreements_total",
                "Total number of threshold signature agreements created by key Id",
                &["key_id"],
            ),
            in_flight_signature_request_contexts: metrics_registry.histogram_vec(
                "execution_in_flight_signature_request_contexts",
                "Number of in flight signature request contexts by key ID",
                vec![1.0, 2.0, 3.0, 5.0, 10.0, 15.0, 20.0, 50.0],
                &["key_id"],
            ),
            pre_signature_stash_size: metrics_registry.int_gauge_vec(
                "execution_pre_signature_stash_size",
                "Number of pre-signatures currently stored in the pre-signature stash, by key ID.",
                &["key_id"],
            ),
            stop_canister_calls_without_call_id: metrics_registry.int_gauge(
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
        }
    }

    fn observe_consumed_cycles_by_use_case(
        &self,
        consumed_cycles_by_use_case: &BTreeMap<CyclesUseCase, NominalCycles>,
    ) {
        for (use_case, cycles) in consumed_cycles_by_use_case.iter() {
            self.consumed_cycles_by_use_case
                .with_label_values(&[use_case.as_str()])
                .set(cycles.get() as f64);
        }
    }

    fn observe_input_messages(&self, kind: &str, message_count: usize) {
        self.input_queue_messages
            .with_label_values(&[kind])
            .set(message_count as i64);
    }

    fn observe_input_queues_size_bytes(&self, kind: &str, message_bytes: usize) {
        self.input_queues_size_bytes
            .with_label_values(&[kind])
            .set(message_bytes as i64);
    }

    pub fn current_heap_delta(&self) -> usize {
        self.current_heap_delta.get() as usize
    }

    pub fn old_open_call_contexts(&self) -> &IntGaugeVec {
        &self.old_open_call_contexts
    }

    pub fn canisters_with_old_open_call_contexts(&self) -> &IntGaugeVec {
        &self.canisters_with_old_open_call_contexts
    }

    pub fn canister_paused_execution(&self) -> &Histogram {
        &self.canister_paused_execution
    }

    pub fn canister_aborted_execution(&self) -> &Histogram {
        &self.canister_aborted_execution
    }

    pub fn canister_paused_install_code(&self) -> &Histogram {
        &self.canister_paused_install_code
    }

    pub fn canister_aborted_install_code(&self) -> &Histogram {
        &self.canister_aborted_install_code
    }

    pub fn stop_canister_calls_without_call_id(&self) -> usize {
        self.stop_canister_calls_without_call_id.get() as usize
    }

    /// Updates end-of-round replicated state metrics (canisters, queues, cycles,
    /// etc.).
    pub fn observe(
        &self,
        own_subnet_id: SubnetId,
        state: &ReplicatedState,
        height: Height,
        logger: &ReplicaLogger,
    ) {
        // Observe the number of registered canisters keyed by their status.
        let mut num_running_canisters = 0;
        let mut num_stopping_canisters = 0;
        let mut num_stopped_canisters = 0;

        let mut num_paused_exec = 0;
        let mut num_aborted_exec = 0;
        let mut num_paused_install = 0;
        let mut num_aborted_install = 0;

        let mut consumed_cycles_total = NominalCycles::new(0);
        let mut consumed_cycles_total_by_use_case = BTreeMap::new();

        let mut ingress_queue_message_count = 0;
        let mut ingress_queue_size_bytes = 0;
        let mut input_queues_message_count = 0;
        let mut input_queues_size_bytes = 0;
        let mut queues_response_bytes = 0;
        let mut queues_memory_reservations = 0;
        let mut queues_oversized_requests_extra_bytes = 0;
        let mut queues_best_effort_message_bytes = 0;
        let mut canisters_not_in_routing_table = 0;
        let mut canisters_with_old_open_call_contexts = 0;
        let mut old_call_contexts_count = 0;
        let mut num_stop_canister_calls_without_call_id = 0;
        let mut in_flight_signature_request_contexts_by_key_id =
            BTreeMap::<MasterPublicKeyId, u32>::new();

        let mut total_canister_balance = Cycles::zero();
        let mut total_canister_reserved_balance = Cycles::zero();

        let canister_id_ranges = state.routing_table().ranges(own_subnet_id);
        state.canisters_iter().for_each(|canister| {
            match canister.system_state.get_status() {
                CanisterStatus::Running { .. } => num_running_canisters += 1,
                CanisterStatus::Stopping { stop_contexts, .. } => {
                    num_stopping_canisters += 1;
                    // TODO(EXC-1466): Remove once all calls have `call_id` present.
                    num_stop_canister_calls_without_call_id += stop_contexts
                        .iter()
                        .take_while(|stop_context| stop_context.call_id().is_none())
                        .count();
                }
                CanisterStatus::Stopped => num_stopped_canisters += 1,
            }
            match canister.next_task() {
                Some(&ExecutionTask::PausedExecution { .. }) => {
                    num_paused_exec += 1;
                }
                Some(&ExecutionTask::PausedInstallCode(_)) => {
                    num_paused_install += 1;
                }
                Some(&ExecutionTask::AbortedExecution { .. }) => {
                    num_aborted_exec += 1;
                }
                Some(&ExecutionTask::AbortedInstallCode { .. }) => {
                    num_aborted_install += 1;
                }
                Some(&ExecutionTask::Heartbeat)
                | Some(&ExecutionTask::GlobalTimer)
                | Some(&ExecutionTask::OnLowWasmMemory)
                | None => {}
            }
            consumed_cycles_total += canister.system_state.canister_metrics().consumed_cycles();
            join_consumed_cycles_by_use_case(
                &mut consumed_cycles_total_by_use_case,
                canister
                    .system_state
                    .canister_metrics()
                    .consumed_cycles_by_use_cases(),
            );
            let queues = canister.system_state.queues();
            ingress_queue_message_count += queues.ingress_queue_message_count();
            ingress_queue_size_bytes += queues.ingress_queue_size_bytes();
            input_queues_message_count += queues.input_queues_message_count();
            input_queues_size_bytes += queues.input_queues_size_bytes();
            queues_response_bytes += queues.guaranteed_responses_size_bytes();
            queues_memory_reservations += queues.guaranteed_response_memory_reservations();
            queues_oversized_requests_extra_bytes +=
                queues.oversized_guaranteed_requests_extra_bytes();
            queues_best_effort_message_bytes += queues.best_effort_message_memory_usage();
            if !canister_id_ranges.contains(&canister.canister_id()) {
                canisters_not_in_routing_table += 1;
            }

            total_canister_balance += canister.system_state.balance();
            total_canister_reserved_balance += canister.system_state.reserved_balance();

            if let Some(manager) = canister.system_state.call_context_manager() {
                // Log all old call contexts, but not (nearly) every round.
                let maybe_log_old_call_contexts = |origin: &CallOrigin, origin_time: Time| {
                    if height.get().is_multiple_of(SPAMMY_LOG_INTERVAL_ROUNDS) {
                        warn!(
                            logger,
                            "Call context on canister {} with origin {:?} has been open for {:?}",
                            canister.canister_id(),
                            origin,
                            state.time().saturating_duration_since(origin_time),
                        );
                    }
                };
                let old_call_contexts = manager.call_contexts_older_than(
                    state.time().saturating_sub(OLD_CALL_CONTEXT_CUTOFF_ONE_DAY),
                    maybe_log_old_call_contexts,
                );
                if old_call_contexts > 0 {
                    old_call_contexts_count += old_call_contexts;
                    canisters_with_old_open_call_contexts += 1;
                }
            }
        });

        self.old_open_call_contexts
            .with_label_values(&[OLD_CALL_CONTEXT_LABEL_ONE_DAY])
            .set(old_call_contexts_count as i64);
        self.canisters_with_old_open_call_contexts
            .with_label_values(&[OLD_CALL_CONTEXT_LABEL_ONE_DAY])
            .set(canisters_with_old_open_call_contexts as i64);

        self.current_heap_delta
            .set(state.metadata.heap_delta_estimate.get() as i64);

        // Add the consumed cycles by canisters that were deleted.
        consumed_cycles_total += state
            .metadata
            .subnet_metrics
            .consumed_cycles_by_deleted_canisters;

        join_consumed_cycles_by_use_case(
            &mut consumed_cycles_total_by_use_case,
            state
                .metadata
                .subnet_metrics
                .get_consumed_cycles_by_use_case(),
        );

        // Add the consumed cycles in ecdsa outcalls.
        consumed_cycles_total += state.metadata.subnet_metrics.consumed_cycles_ecdsa_outcalls;

        // Add the consumed cycles in http outcalls.
        consumed_cycles_total += state.metadata.subnet_metrics.consumed_cycles_http_outcalls;

        self.consumed_cycles.set(consumed_cycles_total.get() as f64);

        self.observe_consumed_cycles_by_use_case(&consumed_cycles_total_by_use_case);

        for (key_id, count) in &state.metadata.subnet_metrics.threshold_signature_agreements {
            self.threshold_signature_agreements
                .with_label_values(&[&key_id.to_string()])
                .set(*count as i64);
        }

        for context in state.signature_request_contexts().values() {
            *in_flight_signature_request_contexts_by_key_id
                .entry(context.key_id())
                .or_default() += 1;
        }
        for (key_id, count) in in_flight_signature_request_contexts_by_key_id {
            self.in_flight_signature_request_contexts
                .with_label_values(&[&key_id.to_string()])
                .observe(count as f64);
        }

        for (key_id, stash) in state.pre_signature_stashes() {
            self.pre_signature_stash_size
                .with_label_values(&[&key_id.to_string()])
                .set(stash.pre_signatures.len() as i64);
        }

        let observe_reading = |status: CanisterStatusType, num: i64| {
            self.registered_canisters
                .with_label_values(&[&status.to_string()])
                .set(num);
        };
        observe_reading(CanisterStatusType::Running, num_running_canisters);
        observe_reading(CanisterStatusType::Stopping, num_stopping_canisters);
        observe_reading(CanisterStatusType::Stopped, num_stopped_canisters);

        self.canister_paused_execution
            .observe(num_paused_exec as f64);
        self.canister_aborted_execution
            .observe(num_aborted_exec as f64);
        self.canister_paused_install_code
            .observe(num_paused_install as f64);
        self.canister_aborted_install_code
            .observe(num_aborted_install as f64);

        self.available_canister_ids
            .set(state.metadata.available_canister_ids() as i64);

        self.observe_input_messages(MESSAGE_KIND_INGRESS, ingress_queue_message_count);
        self.observe_input_queues_size_bytes(MESSAGE_KIND_INGRESS, ingress_queue_size_bytes);
        self.observe_input_messages(MESSAGE_KIND_CANISTER, input_queues_message_count);
        self.observe_input_queues_size_bytes(MESSAGE_KIND_CANISTER, input_queues_size_bytes);

        self.queues_response_bytes.set(queues_response_bytes as i64);
        self.queues_memory_reservations
            .set(queues_memory_reservations as i64);
        self.queues_oversized_requests_extra_bytes
            .set(queues_oversized_requests_extra_bytes as i64);
        self.queues_best_effort_message_bytes
            .set(queues_best_effort_message_bytes as i64);

        self.ingress_history_length
            .set(state.metadata.ingress_history.len() as i64);
        self.canisters_not_in_routing_table
            .set(canisters_not_in_routing_table);
        self.stop_canister_calls_without_call_id
            .set(num_stop_canister_calls_without_call_id as i64);

        self.total_canister_balance
            .set(total_canister_balance.get() as f64);

        self.total_canister_reserved_balance
            .set(total_canister_reserved_balance.get() as f64);

        self.canister_snapshots_memory_usage
            .set(state.canister_snapshots.memory_taken().get() as i64);
        self.num_canister_snapshots
            .set(state.canister_snapshots.count() as i64);

        // TODO: Consider only doing this every Nth round.
        for canister in state.canisters_iter() {
            self.observe_canister_metrics(canister);
        }
    }

    /// Instruments canister balance, memory sizes and memory and compute allocation.
    fn observe_canister_metrics(&self, canister: &CanisterState) {
        self.canister_balance
            .observe(canister.system_state.balance().get() as f64);
        if let Some(es) = &canister.execution_state {
            self.canister_binary_size
                .observe(es.wasm_binary.binary.len() as f64);
            self.canister_wasm_memory_usage
                .observe(num_bytes_try_from(es.wasm_memory.size).unwrap().get() as f64);
            self.canister_stable_memory_usage
                .observe(num_bytes_try_from(es.stable_memory.size).unwrap().get() as f64);
        }
        self.canister_memory_allocation
            .observe(canister.memory_allocation().pre_allocated_bytes().get() as f64);
        self.canister_compute_allocation
            .observe(canister.compute_allocation().as_percent() as f64 / 100.0);

        let log_memory_usage = if LOG_MEMORY_STORE_FEATURE_ENABLED {
            canister.system_state.log_memory_store.memory_usage()
        } else {
            canister.system_state.canister_log.bytes_used()
        };
        self.canister_log_memory_usage_v2
            .observe(log_memory_usage as f64);
        self.canister_log_memory_usage_v3
            .observe(log_memory_usage as f64);
    }
}

fn join_consumed_cycles_by_use_case(
    destination_map: &mut BTreeMap<CyclesUseCase, NominalCycles>,
    source_map: &BTreeMap<CyclesUseCase, NominalCycles>,
) {
    for (use_case, cycles) in source_map.iter() {
        *destination_map
            .entry(*use_case)
            .or_insert_with(|| NominalCycles::from(0)) += *cycles;
    }
}

/// One kibibyte (1024 bytes).
///
/// ```
/// use ic_execution_environment::units::KIB;
/// assert_eq!(KIB, 1024);
/// ```
pub const KIB: u64 = 1024;

/// One mebibyte (1024 kibibytes).
///
/// ```
/// use ic_execution_environment::units::{MIB, KIB};
/// assert_eq!(MIB, 1024 * KIB);
/// ```
pub const MIB: u64 = 1024 * KIB;

/// One gibibyte (1024 mebibytes).
///
/// ```
/// use ic_execution_environment::units::{GIB, MIB};
/// assert_eq!(GIB, 1024 * MIB);
/// ```
pub const GIB: u64 = 1024 * MIB;

/// Returns a histogram with buckets appropriate for durations.
pub fn duration_histogram<S: Into<String>>(
    name: S,
    help: S,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    let mut buckets = decimal_buckets_with_zero(-4, 1);
    buckets.push(100.0);
    // Buckets are [0, 100µs, 200µs, 500µs, ..., 10s, 20s, 50s, 100s].
    metrics_registry.histogram(name, help, buckets)
}

/// Returns buckets appropriate for instructions.
pub fn instructions_buckets() -> Vec<f64> {
    let mut buckets: Vec<NumInstructions> = decimal_buckets_with_zero(4, 11)
        .into_iter()
        .map(|x| NumInstructions::from(x as u64))
        .collect();

    // Add buckets for counting no-op and small messages.
    buckets.push(NumInstructions::from(10));
    buckets.push(NumInstructions::from(1000));
    for value in (1_000_000_000..10_000_000_000).step_by(1_000_000_000) {
        buckets.push(NumInstructions::from(value));
    }

    // Add buckets for counting install_code messages
    for value in (100_000_000_000..=1_000_000_000_000).step_by(100_000_000_000) {
        buckets.push(NumInstructions::from(value));
    }

    // Ensure that all buckets are unique.
    buckets.sort_unstable();
    buckets.dedup();
    // Buckets are [0, 10, 1K, 10K, 20K, ..., 100B, 200B, 500B, 1T] + [1B, 2B, 3B, ..., 9B] + [100B,
    // 200B, 300B, ..., 900B].
    buckets.into_iter().map(|x| x.get() as f64).collect()
}

/// Returns a histogram with buckets appropriate for dts pause/abort executions.
pub fn dts_pause_or_abort_histogram<S: Into<String>>(
    name: S,
    help: S,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    let mut buckets: Vec<f64> = (0..10).map(f64::from).collect();
    buckets.extend(decimal_buckets(1, 4));
    metrics_registry.histogram(name, help, buckets)
}

/// Returns a histogram with buckets appropriate for instructions.
pub fn instructions_histogram<S: Into<String>>(
    name: S,
    help: S,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    metrics_registry.histogram(name, help, instructions_buckets())
}

/// Returns a histogram with buckets appropriate for Cycles.
pub fn cycles_histogram<S: Into<String>>(
    name: S,
    help: S,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    metrics_registry.histogram(name, help, decimal_buckets_with_zero(6, 15))
}

/// Returns unique and sorted buckets.
pub fn unique_sorted_buckets(buckets: &[u64]) -> Vec<f64> {
    // Ensure that all buckets are unique
    let mut buckets = buckets.to_vec();
    buckets.sort_unstable();
    buckets.dedup();
    buckets.into_iter().map(|x| x as f64).collect()
}

/// Returns buckets appropriate for Wasm and Stable memories
pub fn memory_buckets() -> Vec<f64> {
    unique_sorted_buckets(&[
        0,
        4 * KIB,
        64 * KIB,
        MIB,
        10 * MIB,
        50 * MIB,
        100 * MIB,
        500 * MIB,
        GIB,
        2 * GIB,
        3 * GIB,
        4 * GIB,
        5 * GIB,
        6 * GIB,
        7 * GIB,
        8 * GIB,
        MAX_STABLE_MEMORY_IN_BYTES,
        MAX_WASM_MEMORY_IN_BYTES,
    ])
}

/// Returns a histogram with buckets appropriate for Canister memory.
pub fn memory_histogram<S: Into<String>>(
    name: S,
    help: S,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    metrics_registry.histogram(name, help, memory_buckets())
}

/// Returns buckets appropriate for messages and slices.
pub fn messages_buckets() -> Vec<f64> {
    decimal_buckets_with_zero(0, 3)
}

/// Returns a histogram with buckets appropriate for messages.
pub fn messages_histogram<S: Into<String>>(
    name: S,
    help: S,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    // Buckets are [0, 1, 2, 5, ..., 1K, 2K, 5K].
    metrics_registry.histogram(name, help, messages_buckets())
}

/// Returns a histogram with buckets appropriate for slices.
pub fn slices_histogram<S: Into<String>>(
    name: S,
    help: S,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    // Re-use the messages histogram.
    messages_histogram(name, help, metrics_registry)
}
