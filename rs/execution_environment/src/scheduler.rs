use crate::{
    canister_manager::uninstall_canister, execution_environment::ExecutionEnvironment,
    util::process_responses,
};
use ic_config::subnet_config::SchedulerConfig;
use ic_crypto::prng::{Csprng, RandomnessPurpose::ExecutionThread};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_ic00_types::Method as Ic00Method;
use ic_interfaces::{
    execution_environment::{IngressHistoryWriter, Scheduler, SubnetAvailableMemory},
    messages::CanisterInputMessage,
};
use ic_logger::{debug, info, new_logger, warn, ReplicaLogger};
use ic_metrics::{
    buckets::{decimal_buckets, linear_buckets},
    MetricsRegistry,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, CanisterStatus, ReplicatedState};
use ic_types::nominal_cycles::NominalCycles;
use ic_types::{
    ic00::{EmptyBlob, InstallCodeArgs, Payload as _, IC_00},
    ingress::{IngressStatus, WasmResult},
    messages::{Ingress, MessageId, Payload, Response, StopCanisterContext},
    user_error::{ErrorCode, UserError},
    AccumulatedPriority, CanisterId, CanisterStatusType, ComputeAllocation, ExecutionRound,
    InstallCodeContext, NumBytes, NumInstructions, Randomness, SubnetId, Time,
};
use num_rational::Ratio;
use prometheus::{Gauge, Histogram, IntCounter, IntGauge, IntGaugeVec};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    mem,
    str::FromStr,
    sync::Arc,
};

#[cfg(test)]
pub(crate) mod tests;

struct SchedulerMetrics {
    canister_age: Histogram,
    canister_compute_allocation_violation: IntCounter,
    charge_resource_allocation_and_use_duration: Histogram,
    compute_utilization_per_core: Histogram,
    instructions_consumed_per_message: Histogram,
    instructions_consumed_per_round: Histogram,
    executable_canisters_per_round: Histogram,
    expired_ingress_messages_count: IntCounter,
    ingress_history_length: IntGauge,
    msg_execution_duration: Histogram,
    registered_canisters: IntGaugeVec,
    consumed_cycles_since_replica_started: Gauge,
    input_queue_messages: IntGaugeVec,
    input_queues_size_bytes: IntGaugeVec,
    canister_messages_where_cycles_were_charged: IntCounter,
    current_heap_delta: IntGauge,
    round_skipped_due_to_current_heap_delta_above_limit: IntCounter,
    execute_round_called: IntCounter,
    inner_loop_consumed_non_zero_instructions_count: IntCounter,
    inner_round_loop_consumed_max_instructions: IntCounter,
    num_canisters_uninstalled_out_of_cycles: IntCounter,
}

pub const LABEL_MESSAGE_KIND: &str = "kind";
pub const MESSAGE_KIND_INGRESS: &str = "ingress";
pub const MESSAGE_KIND_CANISTER: &str = "canister";

impl SchedulerMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
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
            charge_resource_allocation_and_use_duration: metrics_registry.histogram(
                "scheduler_charge_resource_allocation_and_use_duration",
                "Duration of charging canisters for the resource allocation and use in seconds.",
                // 10µs, 20µs, 50µs, 100µs, ..., 1s, 2s, 5s
                decimal_buckets(-5, 0),
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
                // 1, 2, 5, …, 100, 200, 500
                decimal_buckets(0, 2),
            ),
            expired_ingress_messages_count: metrics_registry.int_counter(
                "scheduler_expired_ingress_messages_count",
                "Total number of ingress messages that expired before reaching a terminal state.",
            ),
            ingress_history_length: metrics_registry.int_gauge(
                "replicated_state_ingress_history_length",
                "Total number of entries kept in the ingress history.",
            ),
            msg_execution_duration: metrics_registry.histogram(
                "scheduler_message_execution_duration_seconds",
                "Duration of single message execution in seconds.",
                // 10µs, 20µs, 50µs, 100µs, ..., 1s, 2s, 5s
                decimal_buckets(-5, 0),
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
                "The number of rounds that were skipped because the current heap delta size exceeded the allowed max",
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
                "The number of times inner_rounds()'s loop exitted because max allowed instructions were consumed.",
            ),
            num_canisters_uninstalled_out_of_cycles:metrics_registry.int_counter(
                "scheduler_num_canisters_uninstalled_out_of_cycles",
                "The number of canisters that were uninstalled because they ran out of cycles."
            ),
        }
    }

    fn observe_consumed_cycles(&self, consumed_cycles: NominalCycles) {
        self.consumed_cycles_since_replica_started
            .set(consumed_cycles.get() as f64);
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
}

pub(crate) struct SchedulerImpl {
    config: SchedulerConfig,
    own_subnet_id: SubnetId,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    exec_env: Arc<dyn ExecutionEnvironment>,
    cycles_account_manager: Arc<CyclesAccountManager>,
    metrics: Arc<SchedulerMetrics>,
    log: ReplicaLogger,
    thread_pool: RefCell<scoped_threadpool::Pool>,
}

// Indicates whether the heartbeat method of a canister should be run on not.
//
// An execution round consists of multiple iterations. The heartbeat should
// run only in the first iteration. Another temporary restriction is that
// only system subnets are currently supported.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum HeartbeatHandling {
    Execute,
    Skip,
}

// Orders the canisters and updates their accumulated priorities according to
// the strategy described in the Scheduler Analysis document:
// https://drive.google.com/file/d/1hSmUphdQv0zyB9sohOk8GhfVVlS5TjHo
// A shorter description of the scheduling strategy is available in the note
// section about [Scheduler and AccumulatedPriority] in types/src/lib.rs
fn apply_scheduler_strategy(
    scheduler_cores: usize,
    current_round: ExecutionRound,
    all_canister_states: &mut BTreeMap<CanisterId, CanisterState>,
) -> Vec<CanisterId> {
    let number_of_canisters = all_canister_states.len() as i64;

    if number_of_canisters <= scheduler_cores as i64 {
        return all_canister_states
            .iter()
            .map(|(canister_id, _canister)| *canister_id)
            .collect();
    }

    // Capacity of this CanisterManager is 100 * scheduler_cores.
    let capacity = 100 * scheduler_cores as i64;

    // This corresponds to |a| in Scheduler Analysis.
    let mut total_compute_allocation: i64 = 0;

    // Use this multiplier to achieve the following two: 1) The sum of all the
    // values we add to accumulated priorities to calculate the round priorities
    // must be divisible by the number of canisters that are given top priority
    // in this round. 2) The free compute_allocation (the difference between
    // capacity and total_compute_allocation) can be distributed to all the
    // canisters evenly.
    let multiplier = scheduler_cores as i64 * number_of_canisters;

    // This corresponds to the vector p in the Scheduler Analysis document.
    let mut round_priorities = Vec::<(CanisterId, i64)>::new();

    // Reset the accumulated priorities every 100 rounds (times the multiplier).
    // We want to reset the scheduler regularly to safely support changes in the set
    // of canisters and their compute allocations.
    let reset_round = (current_round.get() as i64 % (100 * multiplier)) == 0;

    // Compute the priority of the canisters for this round.
    for (canister_id, canister) in all_canister_states.iter_mut() {
        let compute_allocation = canister.scheduler_state.compute_allocation.as_percent() as i64;
        let accumulated_priority: i64 = if reset_round {
            0
        } else {
            canister.scheduler_state.accumulated_priority.value()
        };

        round_priorities.push((
            *canister_id,
            accumulated_priority + (multiplier * compute_allocation),
        ));

        total_compute_allocation += compute_allocation;
    }

    // Distribute the free capacity to all the canisters evenly:
    let free_capacity = capacity - total_compute_allocation;
    // bonus_priority_per_core is (multiplier * free_capacity) /
    // number_of_canisters. This is equal to scheduler_cores * free_capacity.
    let bonus_priority_per_core = scheduler_cores as i64 * free_capacity;
    for round_priority in round_priorities.iter_mut() {
        round_priority.1 += bonus_priority_per_core;
    }

    // Sort canisters according to their priorities for this round in descending
    // order. The higher the value, the higher the priority.
    //
    // all_canister_states is a BTreeMap. Looping over its iter_mut above returns
    // its elements sorted by key (i.e. canister_id) in an ascending order.
    // Since we populate round_priorities (a vector) in that loop, it keeps the
    // same order. "sort" preserves the order when there is a tie. As a result,
    // in case of a tie, the priority is given to the canister with the smaller
    // canister id.
    round_priorities.sort_by(|left, right| right.1.cmp(&left.1));

    // Update the canisters' accumulated priorities.
    for (i, (canister_id, priority)) in round_priorities.iter().enumerate() {
        if let Some(canister) = all_canister_states.get_mut(canister_id) {
            // Update the accumulated priority.
            if i < scheduler_cores {
                // When handling top canisters, decrese their priority by
                // multiplier * capacity / scheduler_cores
                // which is equal to capacity * number_of_canisters.
                canister.scheduler_state.accumulated_priority =
                    AccumulatedPriority::from(priority - (capacity * number_of_canisters));
            } else {
                canister.scheduler_state.accumulated_priority =
                    AccumulatedPriority::from(*priority);
            }
        }
    }

    // Return the ordered canister ids.
    round_priorities
        .iter()
        .map(|(canister_id, _priority)| *canister_id)
        .collect()
}

// Returns a list of canisters that can be executed.
// Does not alter the order of canisters.
fn filter_idle_canisters(
    ordered_canister_ids: &[CanisterId],
    all_canister_states: &BTreeMap<CanisterId, CanisterState>,
    heartbeat_handling: HeartbeatHandling,
) -> Vec<CanisterId> {
    // Consider only canisters with some input messages for execution.
    ordered_canister_ids
        .iter()
        .filter(|canister_id| {
            let canister = all_canister_states.get(canister_id).unwrap();
            canister.has_input()
                || (heartbeat_handling == HeartbeatHandling::Execute
                    && canister.exports_heartbeat_method())
        })
        .cloned()
        .collect()
}

// Partitions the executable canisters to the available cores for execution.
//
// Returns the executable canisters partitioned by cores and the
// non-executable canisters.
//
// ## Example
//
// Given a list of 8 executable canisters and 3 cpu cores, then we have the
// following assignment:
// * Core 1 takes `CanisterId1`, `CanisterId4`, `CanisterId7`
// * Core 2 takes CanisterId2`, `CanisterId5`, `CanisterId8`
// * Core 3 takes CanisterId3`, `CanisterId6`
fn partition_canisters_to_cores(
    scheduler_cores: usize,
    executable_canister_ids: &[CanisterId],
    mut canisters: BTreeMap<CanisterId, CanisterState>,
) -> (Vec<Vec<CanisterState>>, BTreeMap<CanisterId, CanisterState>) {
    let mut res = vec![Vec::<CanisterState>::new(); scheduler_cores];
    for (i, canister_id) in executable_canister_ids.iter().enumerate() {
        res[i % scheduler_cores].push(canisters.remove(canister_id).unwrap());
    }
    (res, canisters)
}

impl SchedulerImpl {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: SchedulerConfig,
        own_subnet_id: SubnetId,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
        exec_env: Arc<dyn ExecutionEnvironment>,
        cycles_account_manager: Arc<CyclesAccountManager>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        let scheduler_cores = config.scheduler_cores as u32;
        Self {
            config,
            thread_pool: RefCell::new(scoped_threadpool::Pool::new(scheduler_cores)),
            own_subnet_id,
            ingress_history_writer,
            exec_env,
            cycles_account_manager,
            metrics: Arc::new(SchedulerMetrics::new(metrics_registry)),
            log,
        }
    }

    // Performs multiple iterations of canister execution until the instruction
    // limit per round is reached or the canisters become idle. The canisters
    // are executed in parallel using the thread pool.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn inner_round(
        &self,
        mut state: ReplicatedState,
        ordered_canister_ids: &[CanisterId],
        current_round: ExecutionRound,
        mut total_instructions_consumed: NumInstructions,
    ) -> ReplicatedState {
        let mut executable_canister_ids = BTreeSet::new();
        let mut ingress_execution_results = Vec::new();
        let mut is_first_iteration = true;

        // Keep executing till either the execution of a round does not actually
        // consume any additional instructions or the maximum allowed instructions
        // per round have been consumed.
        let mut state = loop {
            let mut loop_config = self.config.clone();

            // Depending on what was executed before `inner_round`,
            // `total_instructions_consumed` can be already larger than the limit.
            // That's why we take `min` here to avoid underflows.
            loop_config.max_instructions_per_round -= std::cmp::min(
                total_instructions_consumed,
                loop_config.max_instructions_per_round,
            );

            // We execute heartbeat methods only in the first iteration.
            let heartbeat_handling = if is_first_iteration {
                HeartbeatHandling::Execute
            } else {
                HeartbeatHandling::Skip
            };

            let canisters = state.take_canister_states();

            let loop_executable_canister_ids =
                filter_idle_canisters(ordered_canister_ids, &canisters, heartbeat_handling);

            let (mut executable_canisters_partitioned_by_cores, inactive_canisters) =
                partition_canisters_to_cores(
                    self.config.scheduler_cores,
                    &loop_executable_canister_ids,
                    canisters,
                );

            if is_first_iteration {
                for partition in executable_canisters_partitioned_by_cores.iter_mut() {
                    if let Some(canister) = partition.first_mut() {
                        canister.system_state.canister_metrics.scheduled_as_first += 1;
                    }
                }
            }
            let subnet_records: Arc<BTreeMap<SubnetId, SubnetType>> = Arc::new(
                state
                    .metadata
                    .network_topology
                    .subnets
                    .iter()
                    .map(|(subnet_id, subnet_topology)| (*subnet_id, subnet_topology.subnet_type))
                    .collect(),
            );

            let (
                executed_canisters,
                mut loop_ingress_execution_results,
                instructions_consumed,
                heap_delta,
            ) = self.execute_canisters_in_inner_round(
                executable_canisters_partitioned_by_cores,
                loop_config.clone(),
                current_round,
                state.time(),
                self.exec_env.subnet_available_memory(&state) / self.config.scheduler_cores as u64,
                Arc::new(state.metadata.network_topology.routing_table.clone()),
                subnet_records,
                heartbeat_handling,
            );

            state.metadata.heap_delta_estimate += heap_delta;
            state.put_canister_states(
                executed_canisters
                    .into_iter()
                    .map(|canister| (canister.canister_id(), canister))
                    .chain(inactive_canisters)
                    .collect(),
            );
            ingress_execution_results.append(&mut loop_ingress_execution_results);

            // We only export metrics for "executable" canisters to ensure that the metrics
            // are not polluted by canisters that haven't had any messages for a long time.
            for loop_executable_canister_id in loop_executable_canister_ids.iter() {
                if executable_canister_ids.contains(loop_executable_canister_id) {
                    continue;
                }
                let loop_executable_canister_state =
                    state.canister_state(&loop_executable_canister_id).unwrap();
                let canister_age = current_round.get()
                    - loop_executable_canister_state
                        .scheduler_state
                        .last_full_execution_round
                        .get();
                self.metrics.canister_age.observe(canister_age as f64);
                // If `canister_age` > 1 / `compute_allocation` the canister ought to have been
                // scheduled.
                let allocation = Ratio::new(
                    loop_executable_canister_state
                        .scheduler_state
                        .compute_allocation
                        .as_percent(),
                    100,
                );
                if *allocation.numer() > 0 && Ratio::from_integer(canister_age) > allocation.recip()
                {
                    self.metrics.canister_compute_allocation_violation.inc();
                }
            }

            for loop_executable_canister_id in loop_executable_canister_ids {
                executable_canister_ids.insert(loop_executable_canister_id);
            }
            total_instructions_consumed += instructions_consumed;
            if instructions_consumed == NumInstructions::from(0) {
                break state;
            } else {
                self.metrics
                    .inner_loop_consumed_non_zero_instructions_count
                    .inc();
            }
            if total_instructions_consumed >= self.config.max_instructions_per_round {
                self.metrics
                    .inner_round_loop_consumed_max_instructions
                    .inc();
                break state;
            }
            state.induct_messages_on_same_subnet(&self.log);
            is_first_iteration = false;
        };

        for (message_id, status) in ingress_execution_results {
            self.ingress_history_writer
                .set_status(&mut state, message_id, status);
        }
        self.metrics
            .executable_canisters_per_round
            .observe(executable_canister_ids.len() as f64);

        state
    }

    // Executes canisters in parallel using the thread pool.
    //
    // The function is invoked in each iteration of `inner_round`.
    // The given `canisters_by_thread` defines the priority of canisters.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn execute_canisters_in_inner_round(
        &self,
        canisters_by_thread: Vec<Vec<CanisterState>>,
        current_config: SchedulerConfig,
        round_id: ExecutionRound,
        time: Time,
        subnet_available_memory: NumBytes,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        heartbeat_handling: HeartbeatHandling,
    ) -> (
        Vec<CanisterState>,
        Vec<(MessageId, IngressStatus)>,
        NumInstructions,
        NumBytes,
    ) {
        let thread_pool = &mut self.thread_pool.borrow_mut();
        let exec_env = self.exec_env.as_ref();
        let max_instructions_per_round = current_config.max_instructions_per_round;
        let max_instructions_per_message = current_config.max_instructions_per_message;

        // If we don't have enough instructions to execute a single message,
        // then skip execution and return unchanged canisters.
        if max_instructions_per_round < max_instructions_per_message {
            return (
                canisters_by_thread.into_iter().flatten().collect(),
                vec![],
                NumInstructions::from(0),
                NumBytes::from(0),
            );
        }

        // Reserve the space for holding the result of each execution thread.
        let mut results_by_thread: Vec<ExecutionThreadResult> = canisters_by_thread
            .iter()
            .map(|_| Default::default())
            .collect();

        // Run canisters in parallel. The results will be stored in `results_by_thread`.
        thread_pool.scoped(|scope| {
            // Zip together the input and the output of each thread.
            // The input is a vector of canisters.
            // The output is a reference to the corresponding item in `results_by_thread`.
            let execution_data_by_thread = canisters_by_thread
                .into_iter()
                .zip(results_by_thread.iter_mut());

            // Start execution of the canisters on each thread.
            for (canisters, result) in execution_data_by_thread {
                let routing_table = Arc::clone(&routing_table);
                let subnet_records = Arc::clone(&subnet_records);
                let metrics = Arc::clone(&self.metrics);
                scope.execute(move || {
                    *result = execute_canisters_on_thread(
                        canisters,
                        exec_env,
                        max_instructions_per_round,
                        max_instructions_per_message,
                        metrics,
                        round_id,
                        time,
                        SubnetAvailableMemory::new(subnet_available_memory),
                        routing_table,
                        subnet_records,
                        heartbeat_handling,
                    );
                });
            }
        });

        // At this point all threads completed and stored their results.
        // Aggregate `results_by_thead` to get the result of this function.
        let mut canisters = Vec::new();
        let mut ingress_results = Vec::new();
        let mut instructions_consumed = NumInstructions::from(0);
        let mut heap_delta = NumBytes::from(0);
        for mut result in results_by_thread.into_iter() {
            canisters.append(&mut result.canisters);
            ingress_results.append(&mut result.ingress_results);
            instructions_consumed += result.instructions_consumed;
            heap_delta += result.heap_delta;
        }
        self.metrics
            .instructions_consumed_per_round
            .observe(instructions_consumed.get() as f64);
        (
            canisters,
            ingress_results,
            instructions_consumed,
            heap_delta,
        )
    }

    // Checks for stopping canisters and, if any of them are ready to stop,
    // transitions them to be fully stopped. Responses to the pending stop
    // message(s) are written to ingress history.
    fn process_stopping_canisters(&self, mut state: ReplicatedState) -> ReplicatedState {
        let mut canister_states = state.take_canister_states();
        let time = state.time();

        for canister in canister_states.values_mut() {
            if !(canister.status() == CanisterStatusType::Stopping
                && canister.system_state.ready_to_stop())
            {
                // Canister is either not stopping or isn't ready to be stopped yet. Nothing to
                // do.
                continue;
            }

            // Transition the canister to "stopped".
            let stopping_status =
                mem::replace(&mut canister.system_state.status, CanisterStatus::Stopped);

            if let CanisterStatus::Stopping { stop_contexts, .. } = stopping_status {
                // Respond to the stop messages.
                for stop_context in stop_contexts {
                    match stop_context {
                        StopCanisterContext::Ingress { sender, message_id } => {
                            // Responding to stop_canister request from a user.
                            self.ingress_history_writer.set_status(
                                &mut state,
                                message_id,
                                IngressStatus::Completed {
                                    receiver: IC_00.get(),
                                    user_id: sender,
                                    result: WasmResult::Reply(EmptyBlob::encode()),
                                    time,
                                },
                            )
                        }
                        StopCanisterContext::Canister {
                            sender,
                            reply_callback,
                            funds,
                        } => {
                            // Responding to stop_canister request from a canister.
                            let subnet_id_as_canister_id = CanisterId::from(self.own_subnet_id);
                            let response = Response {
                                originator: sender,
                                respondent: subnet_id_as_canister_id,
                                originator_reply_callback: reply_callback,
                                refund: funds,
                                response_payload: Payload::Data(EmptyBlob::encode()),
                            };
                            state.subnet_queues.push_output_response(response);
                        }
                    }
                }
            }
        }
        state.put_canister_states(canister_states);
        state
    }

    fn purge_expired_ingress_messages(&self, state: &mut ReplicatedState) {
        let current_time = state.time();
        let mut canisters = state.take_canister_states();
        for canister in canisters.values_mut() {
            let closure = |ingress: &Arc<Ingress>| {
                if ingress.expiry_time >= current_time {
                    true
                } else {
                    self.metrics.expired_ingress_messages_count.inc();
                    let error = UserError::new(
                        ErrorCode::IngressMessageTimeout,
                        format!(
                            "Ingress message {} timed out waiting to start executing.",
                            ingress.message_id
                        ),
                    );
                    self.ingress_history_writer.set_status(
                        state,
                        ingress.message_id.clone(),
                        IngressStatus::Failed {
                            receiver: ingress.receiver.get(),
                            user_id: ingress.source,
                            error,
                            time: current_time,
                        },
                    );
                    false
                }
            };
            canister.system_state.filter_ingress_messages(closure);
        }
        state.put_canister_states(canisters);
    }

    // Charge canisters for their resource allocation and usage. Canisters
    // that did not manage to pay are uninstalled.
    fn charge_canisters_for_resource_allocation_and_usage(
        &self,
        state: &mut ReplicatedState,
        time_of_previous_batch: Time,
    ) {
        let timer = self
            .metrics
            .charge_resource_allocation_and_use_duration
            .start_timer();
        let duration_between_blocks = state
            .metadata
            .duration_between_batches(time_of_previous_batch);

        let canisters = state.take_canister_states();
        let mut canisters_to_keep = BTreeMap::new();

        for (_, canister) in canisters.into_iter() {
            match self
                .cycles_account_manager
                .charge_canister_for_resource_allocation_and_usage(
                    &self.log,
                    canister,
                    duration_between_blocks,
                ) {
                Ok(canister) => {
                    canisters_to_keep.insert(canister.canister_id(), canister);
                }
                Err(mut canister) => {
                    info!(
                        self.log,
                        "Uninstalling canister {} because it ran out of cycles",
                        canister.canister_id()
                    );
                    self.metrics.num_canisters_uninstalled_out_of_cycles.inc();
                    let rejects =
                        uninstall_canister(&self.log, &mut canister, state.path(), state.time());
                    process_responses(rejects, state, Arc::clone(&self.ingress_history_writer));
                    canister.scheduler_state.compute_allocation = ComputeAllocation::zero();
                    canister.system_state.memory_allocation = None;
                    canisters_to_keep.insert(canister.canister_id(), canister);
                }
            }
        }

        state.put_canister_states(canisters_to_keep);
        drop(timer);
    }
}

impl Scheduler for SchedulerImpl {
    type State = ReplicatedState;

    fn execute_round(
        &self,
        mut state: ReplicatedState,
        randomness: Randomness,
        time_of_previous_batch: Time,
        current_round: ExecutionRound,
        provisional_whitelist: ProvisionalWhitelist,
    ) -> ReplicatedState {
        let round_log = new_logger!(self.log; messaging.round => current_round.get());
        let subnet_available_memory =
            SubnetAvailableMemory::new(self.exec_env.subnet_available_memory(&state));
        self.metrics
            .current_heap_delta
            .set(state.metadata.heap_delta_estimate.get() as i64);
        self.metrics.execute_round_called.inc();

        debug!(
            round_log,
            "Executing Round {} @ time {}.  Current heap delta size {}.",
            current_round,
            state.time(),
            state.metadata.heap_delta_estimate,
        );

        self.purge_expired_ingress_messages(&mut state);

        // See documentation around definition of `heap_delta_estimate` for an
        // explanation.
        if state.metadata.heap_delta_estimate >= self.config.subnet_heap_delta_capacity / 2 {
            warn!(
                round_log,
                "At Round {} @ time {}, current heap delta {} exceeds allowed capacity {}, so not executing any messages.",
                current_round,
                state.time(),
                state.metadata.heap_delta_estimate,
                self.config.subnet_heap_delta_capacity
            );
            self.metrics
                .round_skipped_due_to_current_heap_delta_above_limit
                .inc();
            return state;
        }

        // Execute subnet messages.
        //
        // Once the subnet messages are executed in threads, each thread will
        // need its own Csprng instance which is initialized with a distinct
        // "ExecutionThread". Otherwise, two Csprng instances that are
        // initialized with the same Randomness and ExecutionThread would
        // reveal the same bytes and break the guarantees that we provide for
        // raw_rand method of the virtual canister.
        let mut csprng = Csprng::from_seed_and_purpose(
            &randomness,
            &ExecutionThread(self.config.scheduler_cores as u32),
        );

        // The consensus queue has to be emptied in each round, so we process
        // it fully without applying the per-round instruction limit.
        // For now, we assume all subnet messages need the entire replicated
        // state. That can be changed in the future as we optimize scheduling.
        while let Some(response) = state.consensus_queue.pop() {
            let (new_state, _) = self.exec_env.execute_subnet_message(
                CanisterInputMessage::Response(response),
                state,
                self.config.max_instructions_per_message,
                &mut csprng,
                &provisional_whitelist,
                subnet_available_memory.clone(),
            );
            state = new_state;
        }

        // To ensure progress for both subnet messages and canister messages, we give
        // subnet messages half of the per-round instruction limit.
        let max_instructions_per_round_for_subnet_messages =
            self.config.max_instructions_per_round / 2;
        let mut total_instructions_consumed = NumInstructions::from(0);

        while let Some(msg) = state.subnet_queues.pop_input() {
            let instructions_limit_per_message =
                get_instructions_limit_for_subnet_message(&self.config, &msg);
            let (new_state, instructions_left) = self.exec_env.execute_subnet_message(
                msg,
                state,
                instructions_limit_per_message,
                &mut csprng,
                &provisional_whitelist,
                subnet_available_memory.clone(),
            );
            state = new_state;
            total_instructions_consumed += instructions_limit_per_message - instructions_left;
            // We check for the limit after the subnet message execution to ensure progress
            // in the case when `instruction_limit_per_message` >
            // `max_instructions_per_round_for_subnet_messages`.
            // This means that we will exceed the limit by at most
            // `instruction_limit_per_message` and that is okay since the limit was set as
            // a heuristic anyway.
            if total_instructions_consumed >= max_instructions_per_round_for_subnet_messages {
                break;
            }
        }

        let ordered_canister_ids = {
            let mut canisters = state.take_canister_states();
            let ordered_canister_ids = apply_scheduler_strategy(
                self.config.scheduler_cores,
                current_round,
                &mut canisters,
            );

            for canister_id in &ordered_canister_ids {
                let canister_state = canisters.get_mut(&canister_id).unwrap();
                if !canister_state.has_input() {
                    canister_state
                        .system_state
                        .canister_metrics
                        .skipped_round_due_to_no_messages += 1;
                }
            }
            state.put_canister_states(canisters);
            ordered_canister_ids
        };

        let state = self.inner_round(
            state,
            &ordered_canister_ids,
            current_round,
            total_instructions_consumed,
        );

        // NOTE: The logic for deleting canisters assumes that transitioning
        // canisters from `Stopping` to `Stopped` happens at the end of the round
        // as is currently the case. If this logic is moved elsewhere (e.g. at the
        // beginning of the round), then canister deletion logic should be revised.
        let mut state = self.process_stopping_canisters(state);
        state.prune_ingress_history();
        self.charge_canisters_for_resource_allocation_and_usage(&mut state, time_of_previous_batch);
        observe_replicated_state_metrics(&state, &self.metrics);
        state
    }
}

fn observe_instructions_consumed_per_message(
    metrics: &SchedulerMetrics,
    consumed_instructions: NumInstructions,
    instruction_limit_per_message: NumInstructions,
) {
    // If the message consumed any non-zero instructions, count it towards the
    // messages we are going to charge cycles for.
    if consumed_instructions.get() > 0 {
        metrics.canister_messages_where_cycles_were_charged.inc();
    }
    metrics
        .instructions_consumed_per_message
        .observe(consumed_instructions.get() as f64);
    assert!(
        consumed_instructions <= instruction_limit_per_message,
        "Execution consumed too many instructions: limit={} consumed={}",
        instruction_limit_per_message,
        consumed_instructions
    );
}

// This struct holds the result of a single execution thread.
#[derive(Default)]
struct ExecutionThreadResult {
    canisters: Vec<CanisterState>,
    ingress_results: Vec<(MessageId, IngressStatus)>,
    instructions_consumed: NumInstructions,
    heap_delta: NumBytes,
}

// Executes the given canisters one by one. For each canister it
// - runs the heartbeat handler of the canister if needed,
// - executes all messages of the canister.
// The execution stops if `total_instruction_limit` is reached
// or all canisters are processed.
#[allow(clippy::too_many_arguments)]
fn execute_canisters_on_thread(
    canisters_to_execute: Vec<CanisterState>,
    exec_env: &dyn ExecutionEnvironment,
    total_instruction_limit: NumInstructions,
    instruction_limit_per_message: NumInstructions,
    metrics: Arc<SchedulerMetrics>,
    round_id: ExecutionRound,
    time: Time,
    subnet_available_memory: SubnetAvailableMemory,
    routing_table: Arc<RoutingTable>,
    subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
    heartbeat_handling: HeartbeatHandling,
) -> ExecutionThreadResult {
    // These variables accumulate the results and will be returned at the end.
    let mut canisters = vec![];
    let mut ingress_results = vec![];
    let mut total_instructions_consumed = NumInstructions::from(0);
    let mut total_heap_delta = NumBytes::from(0);

    for (rank, mut canister) in canisters_to_execute.into_iter().enumerate() {
        // If there are not enough instructions to execute a message,
        // then skip the execution of the canister and keep its old state.
        if total_instructions_consumed + instruction_limit_per_message > total_instruction_limit {
            canisters.push(canister);
            continue;
        }

        // Run heartbeat before processing the messages. Otherwise, if there are many
        // messages, we may reach the instruciton limit before running heartbeat.
        if heartbeat_handling == HeartbeatHandling::Execute && canister.exports_heartbeat_method() {
            let timer = metrics.msg_execution_duration.start_timer();
            let (new_canister, num_instructions_left, result) = exec_env
                .execute_canister_heartbeat(
                    canister,
                    instruction_limit_per_message,
                    Arc::clone(&routing_table),
                    Arc::clone(&subnet_records),
                    time,
                    subnet_available_memory.clone(),
                );
            let heap_delta = match result {
                Ok(heap_delta) => heap_delta,
                Err(_) => NumBytes::from(0),
            };
            let instructions_consumed = instruction_limit_per_message - num_instructions_left;
            observe_instructions_consumed_per_message(
                &metrics,
                instructions_consumed,
                instruction_limit_per_message,
            );
            canister = new_canister;
            total_instructions_consumed += instructions_consumed;
            total_heap_delta += heap_delta;
            drop(timer);
        }

        // Process all messages of the canister until
        // - either its input queue is empty.
        // - or the instruction limit is reached.
        while canister.has_input() {
            if total_instructions_consumed + instruction_limit_per_message > total_instruction_limit
            {
                canister
                    .system_state
                    .canister_metrics
                    .interruped_during_execution += 1;
                break;
            }
            let message = canister.pop_input().unwrap();
            let timer = metrics.msg_execution_duration.start_timer();
            let result = exec_env.execute_canister_message(
                canister,
                instruction_limit_per_message,
                message,
                time,
                Arc::clone(&routing_table),
                Arc::clone(&subnet_records),
                subnet_available_memory.clone(),
            );
            let instructions_consumed =
                instruction_limit_per_message - result.num_instructions_left;
            observe_instructions_consumed_per_message(
                &metrics,
                instructions_consumed,
                instruction_limit_per_message,
            );
            canister = result.canister;
            ingress_results.extend(result.ingress_status);
            total_instructions_consumed += instructions_consumed;
            total_heap_delta += result.heap_delta;
            drop(timer);
        }
        if let Some(es) = &mut canister.execution_state {
            es.last_executed_round = round_id;
        }
        if !canister.has_input() || rank == 0 {
            // The very first canister is considered to have a full execution round for
            // scheduling purposes even if it did not complete within the round.
            canister.scheduler_state.last_full_execution_round = round_id;
        }
        canister.system_state.canister_metrics.executed += 1;
        canisters.push(canister);
    }

    metrics
        .compute_utilization_per_core
        .observe(total_instructions_consumed.get() as f64 / total_instruction_limit.get() as f64);

    ExecutionThreadResult {
        canisters,
        ingress_results,
        instructions_consumed: total_instructions_consumed,
        heap_delta: total_heap_delta,
    }
}

fn observe_replicated_state_metrics(state: &ReplicatedState, metrics: &SchedulerMetrics) {
    // Observe the number of registered canisters keyed by their status.
    let mut num_running_canisters = 0;
    let mut num_stopping_canisters = 0;
    let mut num_stopped_canisters = 0;

    let mut consumed_cycles_total = NominalCycles::new(0);

    let mut ingress_queue_message_count = 0;
    let mut ingress_queue_size_bytes = 0;
    let mut input_queues_message_count = 0;
    let mut input_queues_size_bytes = 0;

    state.canisters_iter().for_each(|canister| {
        match canister.status() {
            CanisterStatusType::Running => num_running_canisters += 1,
            CanisterStatusType::Stopping { .. } => num_stopping_canisters += 1,
            CanisterStatusType::Stopped => num_stopped_canisters += 1,
        }
        consumed_cycles_total += canister
            .system_state
            .canister_metrics
            .consumed_cycles_since_replica_started;
        let queues = &canister.system_state.queues;
        ingress_queue_message_count += queues.ingress_queue_message_count();
        ingress_queue_size_bytes += queues.ingress_queue_size_bytes();
        input_queues_message_count += queues.input_queues_message_count();
        input_queues_size_bytes += queues.input_queues_size_bytes();
    });

    metrics.observe_consumed_cycles(consumed_cycles_total);

    let observe_reading = |status: CanisterStatusType, num: i64| {
        metrics
            .registered_canisters
            .with_label_values(&[&status.to_string()])
            .set(num);
    };
    observe_reading(CanisterStatusType::Running, num_running_canisters);
    observe_reading(CanisterStatusType::Stopping, num_stopping_canisters);
    observe_reading(CanisterStatusType::Stopped, num_stopped_canisters);

    metrics.observe_input_messages(MESSAGE_KIND_INGRESS, ingress_queue_message_count);
    metrics.observe_input_queues_size_bytes(MESSAGE_KIND_INGRESS, ingress_queue_size_bytes);
    metrics.observe_input_messages(MESSAGE_KIND_CANISTER, input_queues_message_count);
    metrics.observe_input_queues_size_bytes(MESSAGE_KIND_CANISTER, input_queues_size_bytes);

    metrics
        .ingress_history_length
        .set(state.metadata.ingress_history.len() as i64);
}

/// Based on the type of the subnet message to execute, figure out its
/// instruction limit.
///
/// This is primarily done because upgrading a canister might need to
/// (de)-serialize a large state and thus consume a lot of instructions.
fn get_instructions_limit_for_subnet_message(
    config: &SchedulerConfig,
    msg: &CanisterInputMessage,
) -> NumInstructions {
    let (method_name, payload, sender) = match &msg {
        CanisterInputMessage::Response(_) => return config.max_instructions_per_message,
        CanisterInputMessage::Ingress(ingress) => (
            &ingress.method_name,
            &ingress.method_payload,
            ingress.source.get(),
        ),
        CanisterInputMessage::Request(request) => (
            &request.method_name,
            &request.method_payload,
            request.sender.get(),
        ),
    };

    use Ic00Method::*;
    match Ic00Method::from_str(&method_name) {
        Ok(method) => match method {
            CanisterStatus
            | CreateCanister
            | DeleteCanister
            | DepositCycles
            | RawRand
            | SetController
            | SetupInitialDKG
            | StartCanister
            | StopCanister
            | UninstallCode
            | UpdateSettings
            | ProvisionalCreateCanisterWithCycles
            | ProvisionalTopUpCanister => config.max_instructions_per_message,
            InstallCode => match InstallCodeArgs::decode(payload) {
                Err(_) => config.max_instructions_per_message,
                Ok(args) => match InstallCodeContext::try_from((sender, args)) {
                    Err(_) => config.max_instructions_per_message,
                    Ok(_) => config.max_instructions_per_install_code,
                },
            },
        },
        Err(_) => config.max_instructions_per_message,
    }
}
