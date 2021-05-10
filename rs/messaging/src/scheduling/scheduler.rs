use ic_config::subnet_config::SchedulerConfig;
use ic_crypto::prng::{Csprng, RandomnessPurpose::ExecutionThread};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::ExecSelect;
use ic_execution_environment::{uninstall_canister, util::process_responses};
use ic_interfaces::{
    execution_environment::{
        EarlyResult, ExecResult, ExecResultVariant, ExecuteMessageResult, ExecutionEnvironment,
        IngressHistoryWriter, SubnetAvailableMemory,
    },
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
    ic00::{EmptyBlob, IC_00},
    ingress::{IngressStatus, WasmResult},
    messages::{Ingress, MessageId, Payload, Response, StopCanisterContext},
    user_error::{ErrorCode, UserError},
    AccumulatedPriority, CanisterId, CanisterStatusType, ComputeAllocation, ExecutionRound,
    NumBytes, NumInstructions, Randomness, SubnetId, Time,
};
#[cfg(test)]
use mockall::automock;
use num_rational::Ratio;
use prometheus::{Gauge, Histogram, IntCounter, IntGauge, IntGaugeVec};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::{mem, sync::Arc};

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
    canister_messages_where_cycles_were_charged: IntCounter,
    current_heap_delta: IntGauge,
    round_skipped_due_to_current_heap_delta_above_limit: IntCounter,
    execute_round_called: IntCounter,
    inner_loop_consumed_non_zero_instructions_count: IntCounter,
    inner_round_loop_consumed_max_instructions: IntCounter,
    num_canisters_uninstalled_out_of_cycles: IntCounter,
}

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
}

#[cfg_attr(test, automock)]
pub(crate) trait Scheduler: Send {
    /// Executes a list of messages. Triggered by the Coordinator as part of
    /// processing a batch.
    ///
    /// # Configuration parameters that might affect a round's execution
    ///
    /// * `scheduler_cores`: number of concurrent threads that the scheduler can
    ///   use during an execution round.
    /// * `max_instructions_per_round`: max number of instructions a single
    ///   round on a single thread can
    /// consume.
    /// * `max_instructions_per_message`: max number of instructions a single
    ///   message execution can consume.
    ///
    /// # Walkthrough of a round
    ///
    /// The scheduler decides on a deterministic and fair order of canisters to
    /// execute on each thread (not fully implemented yet).
    /// For each thread we want to schedule **at least** a `pulse` for the first
    /// canister. The canister's `pulse` can consume the entire round of the
    /// thread if it has enough messages or, if not, we can give a `pulse` to
    /// the next canister. Similarly, the second canister can use the rest
    /// of the round of the thread if it has enough messages or we can give
    /// a `pulse` to the next canister and so on.
    ///
    /// # Constraints
    ///
    /// * To be able to start a pulse for a canister we need to have at least
    ///   `max_instructions_per_message` left in the current round (basically we
    ///   need a guarantee that we are able to execute successfully at least one
    ///   message).
    /// * The round (and thus the first `pulse`) starts with a limit of
    ///   `max_instructions_per_round`. When the `pulse` ends it returns how
    ///   many instructions is left which is used to update the limit for the
    ///   next `pulse` and if the above constraint is satisfied, we can start
    ///   the `pulse`. And so on.
    fn execute_round(
        &self,
        state: ReplicatedState,
        randomness: Randomness,
        time_of_previous_batch: Time,
        current_round: ExecutionRound,
        provisional_whitelist: ProvisionalWhitelist,
    ) -> ReplicatedState;
}

pub(crate) struct SchedulerImpl {
    config: SchedulerConfig,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    exec_env: Arc<dyn ExecutionEnvironment<State = ReplicatedState, CanisterState = CanisterState>>,
    cycles_account_manager: Arc<CyclesAccountManager>,
    metrics: Arc<SchedulerMetrics>,
    log: ReplicaLogger,
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
) -> Vec<CanisterId> {
    // Consider only canisters with some input messages for execution.
    ordered_canister_ids
        .iter()
        .filter(|canister_id| all_canister_states.get(canister_id).unwrap().has_input())
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

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn inner_round(
    log: &ReplicaLogger,
    metrics: &Arc<SchedulerMetrics>,
    exec_env: &dyn ExecutionEnvironment<State = ReplicatedState, CanisterState = CanisterState>,
    ingress_history_writer: &dyn IngressHistoryWriter<State = ReplicatedState>,
    config: &SchedulerConfig,
    mut state: ReplicatedState,
    ordered_canister_ids: &[CanisterId],
    current_round: ExecutionRound,
) -> ReplicatedState {
    let mut executable_canister_ids = BTreeSet::new();
    let mut ingress_execution_results = Vec::new();
    let mut recorded_scheduled_as_first_metric = false;

    // Keep executing till either the execution of a round does not actually
    // consume any additional instructions or the maximum allowed instructions
    // per round have been consumed.
    let mut total_instructions_consumed = NumInstructions::from(0);
    let mut state = loop {
        let mut loop_config = config.clone();
        loop_config.max_instructions_per_round -= total_instructions_consumed;
        let canisters = state.take_canister_states();
        let loop_executable_canister_ids = filter_idle_canisters(ordered_canister_ids, &canisters);

        let (mut executable_canisters_partitioned_by_cores, inactive_canisters) =
            partition_canisters_to_cores(
                config.scheduler_cores,
                &loop_executable_canister_ids,
                canisters,
            );

        if !recorded_scheduled_as_first_metric {
            for partition in executable_canisters_partitioned_by_cores.iter_mut() {
                if let Some(canister) = partition.first_mut() {
                    canister.system_state.canister_metrics.scheduled_as_first += 1;
                }
            }
            recorded_scheduled_as_first_metric = true;
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

        // Exec round takes initial canister states and produces new canister states
        // together with statuses for the ingress messages that were executed.
        let exec_round = ExecRound::new(
            executable_canisters_partitioned_by_cores,
            loop_config.clone(),
            current_round,
            metrics,
            &log,
            exec_env.subnet_available_memory(&state) / config.scheduler_cores as u64,
        );
        let (
            executed_canisters,
            mut loop_ingress_execution_results,
            instructions_consumed,
            heap_delta,
        ) = exec_round.execute(
            exec_env,
            state.time(),
            Arc::new(state.metadata.network_topology.routing_table.clone()),
            subnet_records,
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
            metrics.canister_age.observe(canister_age as f64);
            // If `canister_age` > 1 / `compute_allocation` the canister ought to have been
            // scheduled.
            let allocation = Ratio::new(
                loop_executable_canister_state
                    .scheduler_state
                    .compute_allocation
                    .as_percent(),
                100,
            );
            if *allocation.numer() > 0 && Ratio::from_integer(canister_age) > allocation.recip() {
                metrics.canister_compute_allocation_violation.inc();
            }
        }

        for loop_executable_canister_id in loop_executable_canister_ids {
            executable_canister_ids.insert(loop_executable_canister_id);
        }
        total_instructions_consumed += instructions_consumed;
        if instructions_consumed == NumInstructions::from(0) {
            break state;
        } else {
            metrics
                .inner_loop_consumed_non_zero_instructions_count
                .inc();
        }
        if total_instructions_consumed >= config.max_instructions_per_round {
            metrics.inner_round_loop_consumed_max_instructions.inc();
            break state;
        }
        state.induct_messages_on_same_subnet(&log);
    };

    for (message_id, status) in ingress_execution_results {
        ingress_history_writer.set_status(&mut state, message_id, status);
    }
    metrics
        .executable_canisters_per_round
        .observe(executable_canister_ids.len() as f64);

    state
}

impl SchedulerImpl {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: SchedulerConfig,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
        exec_env: Arc<
            dyn ExecutionEnvironment<State = ReplicatedState, CanisterState = CanisterState>,
        >,
        cycles_account_manager: Arc<CyclesAccountManager>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            config,
            own_subnet_id,
            own_subnet_type,
            ingress_history_writer,
            exec_env,
            cycles_account_manager,
            metrics: Arc::new(SchedulerMetrics::new(metrics_registry)),
            log,
        }
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

    /// Executes canister heartbeat on all running canisters.
    // TODO(EXC-201): Integrate this with `execute_round()`.
    fn execute_heartbeat(&self, mut state: ReplicatedState) -> ReplicatedState {
        // execute_heartbeat is currently only supported on system subnets.
        match self.own_subnet_type {
            SubnetType::System => {}
            SubnetType::Application | SubnetType::VerifiedApplication => return state,
        }

        let routing_table = Arc::new(state.metadata.network_topology.routing_table.clone());
        let subnet_records: Arc<BTreeMap<SubnetId, SubnetType>> = Arc::new(
            state
                .metadata
                .network_topology
                .subnets
                .iter()
                .map(|(subnet_id, subnet_topology)| (*subnet_id, subnet_topology.subnet_type))
                .collect(),
        );
        let subnet_available_memory =
            SubnetAvailableMemory::new(self.exec_env.subnet_available_memory(&state));
        let canisters = state.take_canister_states();
        let canisters = canisters
            .into_iter()
            .map(|(canister_id, canister)| {
                self.exec_env
                    .execute_canister_heartbeat(
                        canister,
                        self.config.max_instructions_per_message,
                        Arc::clone(&routing_table),
                        Arc::clone(&subnet_records),
                        state.time(),
                        subnet_available_memory.clone(),
                    )
                    .and_then(move |(canister, _num_instructions_left, _res)| {
                        // TODO(EXE-155): We need to put some thought into how to expose
                        // these errors to the canister developer. For now, these errors
                        // are unreported.
                        (canister_id, canister)
                    })
                    .get_no_pause()
            })
            .collect();

        state.put_canister_states(canisters);

        state
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
                }
            }
        }

        state.put_canister_states(canisters_to_keep);
        drop(timer);
    }
}

impl Scheduler for SchedulerImpl {
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
        // For now, we assume all subnet messages need the entire replicated
        // state. That can be changed in the future as we optimize scheduling.
        while let Some(response) = state.consensus_queue.pop() {
            state = self.exec_env.execute_subnet_message(
                CanisterInputMessage::Response(response),
                state,
                self.config.max_instructions_per_message,
                &mut csprng,
                &provisional_whitelist,
                subnet_available_memory.clone(),
            );
        }
        while let Some(msg) = state.subnet_queues.pop_input() {
            state = self.exec_env.execute_subnet_message(
                msg,
                state,
                self.config.max_instructions_per_message,
                &mut csprng,
                &provisional_whitelist,
                subnet_available_memory.clone(),
            );
        }

        // Execute heartbeat messages before the round begins.
        state = self.execute_heartbeat(state);

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

        let state = inner_round(
            &round_log,
            &self.metrics,
            self.exec_env.as_ref(),
            self.ingress_history_writer.as_ref(),
            &self.config,
            state,
            &ordered_canister_ids,
            current_round,
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

/// Represents an execution round over a list of `ExecStreams`.
///
/// The execution streams are independent chunks of work that can be executed in
/// parallel and the results are gathered at the end of the execution round.
struct ExecRound {
    exec_streams: Vec<ExecStream>,
    config: SchedulerConfig,
}

impl ExecRound {
    fn new(
        execution_ordering: Vec<Vec<CanisterState>>,
        config: SchedulerConfig,
        round_id: ExecutionRound,
        metrics: &Arc<SchedulerMetrics>,
        log: &ReplicaLogger,
        subnet_available_memory: NumBytes,
    ) -> Self {
        let exec_streams = execution_ordering
            .into_iter()
            .enumerate()
            .map(|(idx, canister_ord)| {
                let core_log = new_logger!(log; messaging.core => idx as u64);
                ExecStream::new(
                    canister_ord,
                    &config,
                    core_log,
                    metrics.clone(),
                    round_id,
                    SubnetAvailableMemory::new(subnet_available_memory),
                )
            })
            .collect();

        Self {
            exec_streams,
            config,
        }
    }

    fn execute(
        mut self,
        exec_env: &dyn ExecutionEnvironment<State = ReplicatedState, CanisterState = CanisterState>,
        time: Time,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
    ) -> (
        Vec<CanisterState>,
        Vec<(MessageId, IngressStatus)>,
        NumInstructions,
        NumBytes,
    ) {
        if self.config.max_instructions_per_round >= self.config.max_instructions_per_message {
            let rs = self
                .exec_streams
                .drain(..)
                .map(|s| {
                    s.exec_next(
                        exec_env,
                        time,
                        Arc::clone(&routing_table),
                        Arc::clone(&subnet_records),
                    )
                })
                .collect();
            let mut sel = ExecSelect::new(rs);

            while let Some(res) = sel.select() {
                // ExecRound/ExecStream needs to be restructured to really support
                // pausing. For now we always cancel. However this pauses the whole stream,
                // not just one canister. With real pausing, a canister can no longer
                // belong explicitly to an ExecStream, because streams exists only within
                // one round, and a paused canister could be carried over to the next round
                // where it would belong to a different stream.
                let (finished, stream) = match res {
                    ExecResultVariant::Completed(x) => x,
                    ExecResultVariant::Interrupted(resume_token) => {
                        // For now we always cancel.
                        if let ExecResultVariant::Completed(x) = resume_token.cancel().get() {
                            x
                        } else {
                            panic!("Unexpected response from execution cancel request");
                        }
                    }
                };
                if finished {
                    self.exec_streams.push(stream);
                } else {
                    sel.add(stream.exec_next(
                        exec_env,
                        time,
                        Arc::clone(&routing_table),
                        Arc::clone(&subnet_records),
                    ))
                }
            }
        }

        let mut all_canister_states = Vec::new();
        let mut all_ingress_execution_results = Vec::new();
        let mut heap_delta = NumBytes::from(0);

        let mut total_instructions_consumed = NumInstructions::from(0);
        for mut stream in self.exec_streams {
            let consumed_instructions =
                self.config.max_instructions_per_round - stream.total_instructions_limit;
            stream.metrics.compute_utilization_per_core.observe(
                consumed_instructions.get() as f64
                    / self.config.max_instructions_per_round.get() as f64,
            );
            stream
                .metrics
                .instructions_consumed_per_round
                .observe(consumed_instructions.get() as f64);
            stream.update_round_info();
            all_canister_states.append(&mut stream.finished_canisters);
            all_canister_states.append(&mut stream.interrupted_canisters);
            for c in stream.canisters {
                all_canister_states.push(c);
            }

            all_ingress_execution_results.append(&mut stream.ingress_results);
            total_instructions_consumed += consumed_instructions;
            heap_delta += stream.heap_delta;
        }

        (
            all_canister_states,
            all_ingress_execution_results,
            total_instructions_consumed,
            heap_delta,
        )
    }
}

/// An execution stream contains a list of canisters with input messages that
/// are scheduled for execution. The execution of a stream ends either when
/// there are not any more instructions left or if the list of canisters is
/// exhausted.
struct ExecStream {
    // input
    canisters: VecDeque<CanisterState>,
    // Total instructions limit assigned to this execution stream.
    total_instructions_limit: NumInstructions,
    // Per message instructions limit.
    msg_instructions_limit: NumInstructions,
    subnet_available_memory: SubnetAvailableMemory,

    // output
    ingress_results: Vec<(MessageId, IngressStatus)>,
    interrupted_canisters: Vec<CanisterState>,
    finished_canisters: Vec<CanisterState>,
    heap_delta: NumBytes,

    log: ReplicaLogger,
    metrics: Arc<SchedulerMetrics>,
    round_id: ExecutionRound,
}

impl ExecStream {
    pub fn new(
        canisters: Vec<CanisterState>,
        config: &SchedulerConfig,
        log: ReplicaLogger,
        metrics: Arc<SchedulerMetrics>,
        round_id: ExecutionRound,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> Self {
        Self {
            canisters: canisters.into(),
            total_instructions_limit: config.max_instructions_per_round,
            msg_instructions_limit: config.max_instructions_per_message,
            ingress_results: Vec::new(),
            interrupted_canisters: Vec::new(),
            finished_canisters: Vec::new(),
            heap_delta: NumBytes::from(0),
            metrics,
            log,
            round_id,
            subnet_available_memory,
        }
    }

    fn on_msg_processed(
        &mut self,
        ExecuteMessageResult {
            canister,
            num_instructions_left,
            ingress_status,
            heap_delta,
        }: ExecuteMessageResult<CanisterState>,
    ) -> CanisterState {
        let consumed = self.msg_instructions_limit - num_instructions_left;
        // If the message consumed any non-zero instructions, count it towards the
        // messages we are going to charge cycles for.
        if consumed.get() > 0 {
            self.metrics
                .canister_messages_where_cycles_were_charged
                .inc();
        }
        self.metrics
            .instructions_consumed_per_message
            .observe(consumed.get() as f64);
        assert!(
            consumed <= self.msg_instructions_limit,
            "Execution consumed too many instructions: limit={} consumed={}",
            self.msg_instructions_limit,
            consumed
        );
        self.total_instructions_limit -= consumed;
        self.ingress_results.extend(ingress_status);
        self.heap_delta += heap_delta;
        canister
    }

    // Returns true if the execution on this stream is considered finished
    // (there is nothing more to execute or we ran out of instructions).
    fn exec_next(
        mut self,
        exec_env: &dyn ExecutionEnvironment<State = ReplicatedState, CanisterState = CanisterState>,
        time: Time,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
    ) -> ExecResult<(bool, Self)> {
        let mut canister = match self.canisters.pop_front() {
            Some(c) => c,
            None => return EarlyResult::new((true, self)),
        };

        if !canister.has_input() {
            self.finished_canisters.push(canister);
            EarlyResult::new((self.canisters.is_empty(), self))
        } else if self.total_instructions_limit >= self.msg_instructions_limit {
            debug!(
                self.log,
                "Executing message on canister with rank = {}. Round instructions left {}", self.finished_canisters.len(), self.total_instructions_limit;
                messaging.canister_id => canister.canister_id().to_string()
            );
            let msg = canister.pop_input().unwrap();
            let timer = self.metrics.msg_execution_duration.start_timer();
            let res = exec_env.execute_canister_message(
                canister,
                self.msg_instructions_limit,
                msg,
                time,
                routing_table,
                subnet_records,
                self.subnet_available_memory.clone(),
            );
            res.and_then(move |res| {
                let canister = self.on_msg_processed(res);
                if canister.has_input() {
                    self.canisters.push_front(canister);
                } else {
                    self.finished_canisters.push(canister);
                }
                drop(timer);
                (self.canisters.is_empty(), self)
            })
        } else {
            self.interrupted_canisters.push(canister);
            EarlyResult::new((true, self))
        }
    }

    fn update_round_info(&mut self) {
        if self.finished_canisters.is_empty() && self.interrupted_canisters.len() == 1 {
            // no other canisters executed anything so the whole round was ours
            let c = self.interrupted_canisters.first_mut().unwrap();
            c.scheduler_state.last_full_execution_round = self.round_id;
        }
        for c in &mut self.finished_canisters {
            if let Some(es) = &mut c.execution_state {
                es.last_executed_round = self.round_id;
            }
            c.scheduler_state.last_full_execution_round = self.round_id;
            c.system_state.canister_metrics.executed += 1;
        }
        for c in &mut self.interrupted_canisters {
            if let Some(es) = &mut c.execution_state {
                es.last_executed_round = self.round_id;
            }
            c.system_state.canister_metrics.executed += 1;
            c.system_state.canister_metrics.interruped_during_execution += 1;
        }
    }
}

fn observe_replicated_state_metrics(state: &ReplicatedState, metrics: &SchedulerMetrics) {
    // Observe the number of registered canisters keyed by their status.
    let mut num_running_canisters = 0;
    let mut num_stopping_canisters = 0;
    let mut num_stopped_canisters = 0;

    let mut consumed_cycles_total = NominalCycles::new(0);
    state.canisters_iter().for_each(|canister| {
        match canister.status() {
            CanisterStatusType::Running => num_running_canisters += 1,
            CanisterStatusType::Stopping { .. } => num_stopping_canisters += 1,
            CanisterStatusType::Stopped => num_stopped_canisters += 1,
        }
        consumed_cycles_total += canister
            .system_state
            .cycles_account
            .consumed_cycles_since_replica_started;
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

    metrics
        .ingress_history_length
        .set(state.metadata.ingress_history.len() as i64);
}
