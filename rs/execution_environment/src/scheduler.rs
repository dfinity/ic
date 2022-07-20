use crate::{
    canister_manager::{uninstall_canister, InstallCodeContext},
    execution_environment::{
        as_num_instructions, as_round_instructions, execute_canister, ExecuteCanisterResult,
        ExecutionEnvironment, RoundInstructions, RoundLimits,
    },
    metrics::MeasurementScope,
    util::{self, process_responses},
};
use ic_btc_canister::BitcoinCanister;
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SchedulerConfig;
use ic_crypto::prng::{Csprng, RandomnessPurpose::ExecutionThread};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::{
    CanisterStatusType, EcdsaKeyId, InstallCodeArgs, Method as Ic00Method, Payload as _,
};
use ic_interfaces::execution_environment::{ExecutionRoundType, RegistryExecutionSettings};
use ic_interfaces::{
    execution_environment::{IngressHistoryWriter, Scheduler},
    messages::CanisterInputMessage,
};
use ic_logger::{debug, error, fatal, info, new_logger, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{
    bitcoin_state::BitcoinState, canister_state::QUEUE_INDEX_NONE, CanisterState, ExecutionTask,
    InputQueueType, NetworkTopology, ReplicatedState,
};
use ic_system_api::InstructionLimits;
use ic_types::{
    crypto::canister_threshold_sig::MasterEcdsaPublicKey,
    ingress::{IngressState, IngressStatus},
    messages::{Ingress, MessageId},
    AccumulatedPriority, CanisterId, ComputeAllocation, Cycles, ExecutionRound, MemoryAllocation,
    NumBytes, NumInstructions, Randomness, SubnetId, Time,
};
use ic_types::{nominal_cycles::NominalCycles, NumMessages};
use num_rational::Ratio;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    str::FromStr,
    sync::Arc,
};

mod scheduler_metrics;
use scheduler_metrics::*;

/// Maximum number of allowed bitcoin requests per round. If this number is
/// reached we stop executing more bitcoin requests for this round.
const MAX_BITCOIN_REQUESTS_PER_ROUND: usize = 5;

#[cfg(test)]
pub(crate) mod test_utilities;
#[cfg(test)]
pub(crate) mod tests;

pub(crate) struct SchedulerImpl {
    config: SchedulerConfig,
    own_subnet_id: SubnetId,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    exec_env: Arc<ExecutionEnvironment>,
    cycles_account_manager: Arc<CyclesAccountManager>,
    bitcoin_canister: Arc<BitcoinCanister>,
    metrics: Arc<SchedulerMetrics>,
    log: ReplicaLogger,
    thread_pool: RefCell<scoped_threadpool::Pool>,
    rate_limiting_of_heap_delta: FlagStatus,
    rate_limiting_of_instructions: FlagStatus,
    deterministic_time_slicing: FlagStatus,
}

/// Orders the canisters and updates their accumulated priorities according to
/// the strategy described in the Scheduler Analysis document:
/// https://drive.google.com/file/d/1hSmUphdQv0zyB9sohOk8GhfVVlS5TjHo
/// A shorter description of the scheduling strategy is available in the note
/// section about [Scheduler and AccumulatedPriority] in types/src/lib.rs
fn apply_scheduling_strategy(
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
                // When handling top canisters, decrease their priority by
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

/// This struct represents a collection of canister IDs.
struct FilteredCanisters {
    /// Active canisters during the execution of the inner round.
    active_canister_ids: BTreeSet<CanisterId>,

    /// Canisters that were heap delta rate-limited during the execution of the inner round.
    rate_limited_canister_ids: BTreeSet<CanisterId>,
}

impl FilteredCanisters {
    fn new() -> Self {
        Self {
            active_canister_ids: BTreeSet::new(),
            rate_limited_canister_ids: BTreeSet::new(),
        }
    }

    fn add_canisters(
        &mut self,
        active_canister_ids: &[CanisterId],
        rate_limited_ids: &BTreeSet<CanisterId>,
    ) {
        self.active_canister_ids.extend(active_canister_ids.iter());
        self.rate_limited_canister_ids
            .extend(rate_limited_ids.iter());
    }
}

/// Separates the ordered canisters into a list of active canisters and a set of canisters that
/// were heap delta rate limited. Does not alter the order of canisters to be executed.
///
/// Returns the filtered canisters.
fn filter_canisters(
    ordered_canister_ids: &[CanisterId],
    canisters: &BTreeMap<CanisterId, CanisterState>,
    heap_delta_rate_limit: NumBytes,
    rate_limiting_of_heap_delta: FlagStatus,
) -> (Vec<CanisterId>, BTreeSet<CanisterId>) {
    let mut rate_limited_ids = BTreeSet::new();

    // Consider only canisters with some input messages for execution.
    let active_canister_ids = ordered_canister_ids
        .iter()
        .filter(|canister_id| {
            let canister = canisters.get(canister_id).unwrap();
            let is_under_limit = canister.scheduler_state.heap_delta_debit < heap_delta_rate_limit
                || rate_limiting_of_heap_delta == FlagStatus::Disabled;
            if !is_under_limit {
                rate_limited_ids.insert(**canister_id);
            }
            canister.is_active() && is_under_limit
        })
        .cloned()
        .collect();

    (active_canister_ids, rate_limited_ids)
}

/// Partitions the executable canisters to the available cores for execution.
///
/// Returns the executable canisters partitioned by cores and the
/// non-executable canisters.
///
/// ## Example
///
/// Given a list of 8 executable canisters and 3 cpu cores, then we have the
/// following assignment:
/// * Core 1 takes `CanisterId1`, `CanisterId4`, `CanisterId7`
/// * Core 2 takes `CanisterId2`, `CanisterId5`, `CanisterId8`
/// * Core 3 takes `CanisterId3`, `CanisterId6`
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
        exec_env: Arc<ExecutionEnvironment>,
        cycles_account_manager: Arc<CyclesAccountManager>,
        bitcoin_canister: Arc<BitcoinCanister>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
        rate_limiting_of_heap_delta: FlagStatus,
        rate_limiting_of_instructions: FlagStatus,
        deterministic_time_slicing: FlagStatus,
    ) -> Self {
        let scheduler_cores = config.scheduler_cores as u32;
        Self {
            config,
            thread_pool: RefCell::new(scoped_threadpool::Pool::new(scheduler_cores)),
            own_subnet_id,
            ingress_history_writer,
            exec_env,
            cycles_account_manager,
            bitcoin_canister,
            metrics: Arc::new(SchedulerMetrics::new(metrics_registry)),
            log,
            rate_limiting_of_heap_delta,
            rate_limiting_of_instructions,
            deterministic_time_slicing,
        }
    }

    // Performs multiple iterations of canister execution until the instruction
    // limit per round is reached or the canisters become idle. The canisters
    // are executed in parallel using the thread pool.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn inner_round<'a>(
        &'a self,
        mut state: ReplicatedState,
        ordered_canister_ids: &[CanisterId],
        current_round: ExecutionRound,
        measurement_scope: &MeasurementScope<'a>,
        round_limits: &mut RoundLimits,
    ) -> (ReplicatedState, BTreeSet<CanisterId>) {
        let measurement_scope =
            MeasurementScope::nested(&self.metrics.round_inner, measurement_scope);
        let mut ingress_execution_results = Vec::new();
        let mut is_first_iteration = true;
        let mut round_filtered_canisters = FilteredCanisters::new();

        let mut total_heap_delta = NumBytes::from(0);

        // Add `Heartbeat` tasks to be executed before input messages.
        {
            let _timer = self
                .metrics
                .round_inner_heartbeat_overhead_duration
                .start_timer();
            for canister in state.canisters_iter_mut() {
                if canister.exports_heartbeat_method() {
                    if let Some(execution_state) = canister.execution_state.as_mut() {
                        execution_state
                            .task_queue
                            .push_back(ExecutionTask::Heartbeat);
                    }
                }
            }
        }

        // Start iteration loop
        let mut state = loop {
            let measurement_scope =
                MeasurementScope::nested(&self.metrics.round_inner_iteration, &measurement_scope);
            let preparation_timer = self.metrics.round_inner_iteration_prep.start_timer();

            // Update subnet available memory before taking out the canisters.
            round_limits.subnet_available_memory =
                self.exec_env.subnet_available_memory(&state).into();
            let canisters = state.take_canister_states();
            // Obtain the active canisters and update the collection of heap delta rate-limited canisters.
            let (active_canister_ids, rate_limited_canister_ids) = filter_canisters(
                ordered_canister_ids,
                &canisters,
                self.config.heap_delta_rate_limit,
                self.rate_limiting_of_heap_delta,
            );
            round_filtered_canisters
                .add_canisters(&active_canister_ids, &rate_limited_canister_ids);

            let (mut active_canisters_partitioned_by_cores, inactive_canisters) =
                partition_canisters_to_cores(
                    self.config.scheduler_cores,
                    &active_canister_ids,
                    canisters,
                );

            if is_first_iteration {
                for partition in active_canisters_partitioned_by_cores.iter_mut() {
                    if let Some(canister) = partition.first_mut() {
                        canister.system_state.canister_metrics.scheduled_as_first += 1;
                    }
                }
            }
            drop(preparation_timer);

            let instructions_before = round_limits.instructions;
            let (executed_canisters, mut loop_ingress_execution_results, heap_delta) = self
                .execute_canisters_in_inner_round(
                    active_canisters_partitioned_by_cores,
                    current_round,
                    state.time(),
                    Arc::new(state.metadata.network_topology.clone()),
                    &measurement_scope,
                    round_limits,
                );
            let instructions_consumed = instructions_before - round_limits.instructions;

            let finalization_timer = self.metrics.round_inner_iteration_fin.start_timer();
            total_heap_delta += heap_delta;
            state.metadata.heap_delta_estimate += heap_delta;
            state.put_canister_states(
                executed_canisters
                    .into_iter()
                    .map(|canister| (canister.canister_id(), canister))
                    .chain(inactive_canisters)
                    .collect(),
            );
            ingress_execution_results.append(&mut loop_ingress_execution_results);

            round_limits.instructions -= as_round_instructions(
                self.config
                    .instruction_overhead_per_canister_for_finalization
                    * state.num_canisters() as u64,
            );

            if instructions_consumed == RoundInstructions::from(0) {
                break state;
            } else {
                self.metrics
                    .inner_loop_consumed_non_zero_instructions_count
                    .inc();
            }

            if round_limits.instructions <= RoundInstructions::from(0) {
                self.metrics
                    .inner_round_loop_consumed_max_instructions
                    .inc();
                break state;
            }

            if total_heap_delta >= self.config.max_heap_delta_per_iteration {
                break state;
            }
            {
                let _induction_timer = self.metrics.round_inner_iteration_fin_induct.start_timer();
                self.induct_messages_on_same_subnet(&mut state);
            }
            is_first_iteration = false;
            drop(finalization_timer);
        }; // end iteration loop.

        {
            let _timer = self
                .metrics
                .round_inner_heartbeat_overhead_duration
                .start_timer();
            // Remove all remaining `Heartbeat` tasks because they will be added
            // again in the next round.
            for canister in state.canisters_iter_mut() {
                if let Some(execution_state) = canister.execution_state.as_mut() {
                    execution_state.task_queue.retain(|task| match task {
                        ExecutionTask::Heartbeat => false,
                    });
                }
            }
        }

        // We only export metrics for "executable" canisters to ensure that the metrics
        // are not polluted by canisters that haven't had any messages for a long time.
        for canister_id in &round_filtered_canisters.active_canister_ids {
            let canister_state = state.canister_state(canister_id).unwrap();
            let canister_age = current_round.get()
                - canister_state
                    .scheduler_state
                    .last_full_execution_round
                    .get();
            self.metrics.canister_age.observe(canister_age as f64);
            // If `canister_age` > 1 / `compute_allocation` the canister ought to have been
            // scheduled.
            let allocation = Ratio::new(
                canister_state
                    .scheduler_state
                    .compute_allocation
                    .as_percent(),
                100,
            );
            if *allocation.numer() > 0 && Ratio::from_integer(canister_age) > allocation.recip() {
                self.metrics.canister_compute_allocation_violation.inc();
            }
        }

        for (message_id, status) in ingress_execution_results {
            self.ingress_history_writer
                .set_status(&mut state, message_id, status);
        }
        self.metrics
            .executable_canisters_per_round
            .observe(round_filtered_canisters.active_canister_ids.len() as f64);

        self.metrics
            .heap_delta_rate_limited_canisters_per_round
            .observe(round_filtered_canisters.rate_limited_canister_ids.len() as f64);

        (state, round_filtered_canisters.active_canister_ids)
    }

    /// Executes canisters in parallel using the thread pool.
    ///
    /// The function is invoked in each iteration of `inner_round`.
    /// The given `canisters_by_thread` defines the priority of canisters.
    /// Returns:
    /// - the new states of the canisters,
    /// - the ingress results,
    /// - the maximum number of instructions executed on a thread,
    /// - the total heap delta.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn execute_canisters_in_inner_round(
        &self,
        canisters_by_thread: Vec<Vec<CanisterState>>,
        round_id: ExecutionRound,
        time: Time,
        network_topology: Arc<NetworkTopology>,
        measurement_scope: &MeasurementScope,
        round_limits: &mut RoundLimits,
    ) -> (
        Vec<CanisterState>,
        Vec<(MessageId, IngressStatus)>,
        NumBytes,
    ) {
        let thread_pool = &mut self.thread_pool.borrow_mut();
        let exec_env = self.exec_env.as_ref();

        // If there are no more instructions left, then skip execution and
        // return unchanged canisters.
        if round_limits.instructions <= RoundInstructions::from(0) {
            return (
                canisters_by_thread.into_iter().flatten().collect(),
                vec![],
                NumBytes::from(0),
            );
        }

        // Reserve the space for holding the result of each execution thread.
        let mut results_by_thread: Vec<ExecutionThreadResult> = canisters_by_thread
            .iter()
            .map(|_| Default::default())
            .collect();

        // Distribute subnet available memory equaly between the threads.
        let round_limits_per_thread = RoundLimits {
            instructions: round_limits.instructions,
            subnet_available_memory: (round_limits.subnet_available_memory.get()
                / self.config.scheduler_cores as i64)
                .into(),
        };
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
                let network_topology = Arc::clone(&network_topology);
                let metrics = Arc::clone(&self.metrics);
                let logger = new_logger!(self.log; messaging.round => round_id.get());
                let rate_limiting_of_heap_delta = self.rate_limiting_of_heap_delta;
                let deterministic_time_slicing = self.deterministic_time_slicing;
                let round_limits = RoundLimits {
                    instructions: round_limits.instructions,
                    subnet_available_memory: round_limits_per_thread
                        .subnet_available_memory
                        .get()
                        .into(),
                };
                let config = &self.config;
                scope.execute(move || {
                    *result = execute_canisters_on_thread(
                        canisters,
                        exec_env,
                        config,
                        metrics,
                        round_id,
                        time,
                        network_topology,
                        logger,
                        rate_limiting_of_heap_delta,
                        deterministic_time_slicing,
                        round_limits,
                    );
                });
            }
        });

        // At this point all threads completed and stored their results.
        // Aggregate `results_by_thread` to get the result of this function.
        let mut canisters = Vec::new();
        let mut ingress_results = Vec::new();
        let mut total_instructions_executed = NumInstructions::from(0);
        let mut max_instructions_executed_per_thread = NumInstructions::from(0);
        let mut heap_delta = NumBytes::from(0);
        for mut result in results_by_thread.into_iter() {
            canisters.append(&mut result.canisters);
            ingress_results.append(&mut result.ingress_results);
            let instructions_executed = as_num_instructions(
                round_limits_per_thread.instructions - result.round_limits.instructions,
            );
            total_instructions_executed += instructions_executed;
            max_instructions_executed_per_thread =
                max_instructions_executed_per_thread.max(instructions_executed);

            self.metrics.compute_utilization_per_core.observe(
                instructions_executed.get() as f64
                    / round_limits_per_thread.instructions.get() as f64,
            );

            // Propagate the metrics from `execution_round_inner_iteration_thread`
            // to `execution_round_inner_iteration`.
            measurement_scope.add(instructions_executed, result.messages_executed);
            heap_delta += result.heap_delta;
        }

        // Since there are multiple threads, we update the global limit using
        // the thread that executed the most instructions.
        round_limits.instructions -= as_round_instructions(max_instructions_executed_per_thread);

        self.metrics
            .instructions_consumed_per_round
            .observe(total_instructions_executed.get() as f64);
        (canisters, ingress_results, heap_delta)
    }

    fn process_stopping_canisters(&self, state: ReplicatedState) -> ReplicatedState {
        util::process_stopping_canisters(
            state,
            self.ingress_history_writer.as_ref(),
            self.own_subnet_id,
        )
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
                        IngressStatus::Known {
                            receiver: ingress.receiver.get(),
                            user_id: ingress.source,
                            time: current_time,
                            state: IngressState::Failed(error),
                        },
                    );
                    false
                }
            };
            canister.system_state.filter_ingress_messages(closure);
        }
        state.put_canister_states(canisters);
    }

    // Observe different Canister metrics
    fn observe_canister_metrics(&self, canister: &CanisterState) {
        self.metrics
            .canister_balance
            .observe(canister.system_state.balance().get() as f64);
        if let Some(es) = &canister.execution_state {
            self.metrics
                .canister_binary_size
                .observe(es.wasm_binary.binary.len() as f64);
            self.metrics.canister_wasm_memory_usage.observe(
                ic_replicated_state::num_bytes_try_from(es.wasm_memory.size)
                    .unwrap()
                    .get() as f64,
            );
            self.metrics.canister_stable_memory_usage.observe(
                ic_replicated_state::num_bytes_try_from(es.stable_memory.size)
                    .unwrap()
                    .get() as f64,
            );
        }
        self.metrics
            .canister_memory_allocation
            .observe(match canister.memory_allocation() {
                MemoryAllocation::Reserved(bytes) => bytes.get() as f64,
                MemoryAllocation::BestEffort => 0.0,
            });
        self.metrics
            .canister_compute_allocation
            .observe(canister.compute_allocation().as_percent() as f64 / 100.0);
    }

    /// Charge canisters for their resource allocation and usage. Canisters
    /// that did not manage to pay are uninstalled.
    fn charge_canisters_for_resource_allocation_and_usage(
        &self,
        state: &mut ReplicatedState,
        subnet_size: usize,
    ) {
        let duration_since_last_charge = state
            .metadata
            .duration_between_batches(state.metadata.time_of_last_allocation_charge);

        if state.time()
            < state.metadata.time_of_last_allocation_charge
                + self
                    .cycles_account_manager
                    .duration_between_allocation_charges()
        {
            return;
        } else {
            state.metadata.time_of_last_allocation_charge = state.time();
        }

        let state_path = state.root.clone();
        let state_time = state.time();
        let mut all_rejects = Vec::new();
        for canister in state.canisters_iter_mut() {
            self.observe_canister_metrics(canister);
            if self
                .cycles_account_manager
                .charge_canister_for_resource_allocation_and_usage(
                    &self.log,
                    canister,
                    duration_since_last_charge,
                    subnet_size,
                )
                .is_err()
            {
                all_rejects.push(uninstall_canister(
                    &self.log,
                    canister,
                    &state_path,
                    state_time,
                ));
                canister.scheduler_state.compute_allocation = ComputeAllocation::zero();
                canister.system_state.memory_allocation = MemoryAllocation::BestEffort;

                info!(
                    self.log,
                    "Uninstalling canister {} because it ran out of cycles",
                    canister.canister_id()
                );
                self.metrics.num_canisters_uninstalled_out_of_cycles.inc();
            }
        }

        // Send rejects to any requests that were forcibly closed while uninstalling.
        for rejects in all_rejects.into_iter() {
            process_responses(
                rejects,
                state,
                Arc::clone(&self.ingress_history_writer),
                self.log.clone(),
            );
        }
    }

    /// Iterates over all canisters on the subnet, checking if a source canister
    /// has output messages for a destination canister on the same subnet and
    /// moving them from the source to the destination canister if the
    /// destination canister has room for them.
    ///
    /// This method only handles messages sent to self and to other canisters.
    /// Messages sent to the subnet are not handled i.e. they take the slow path
    /// through message routing.
    pub fn induct_messages_on_same_subnet(&self, state: &mut ReplicatedState) {
        // Compute subnet available memory *before* taking out the canisters.
        let mut subnet_available_memory = self
            .exec_env
            .subnet_available_memory(state)
            .max_available_message_memory();

        let max_canister_memory_size = self.exec_env.max_canister_memory_size();

        let mut canisters = state.take_canister_states();

        // Get a list of canisters in the map before we iterate over the map.
        // This is because we cannot hold an immutable reference to the map
        // while trying to simultaneously mutate it.
        let canisters_with_outputs: Vec<CanisterId> = canisters
            .iter()
            .filter(|(_, canister)| canister.has_output())
            .map(|(canister_id, _)| *canister_id)
            .collect();

        for source_canister_id in canisters_with_outputs {
            // Remove the source canister from the map so that we can
            // `get_mut()` on the map further below for the destination canister.
            // Borrow rules do not allow us to hold multiple mutable references.
            let mut source_canister = match canisters.remove(&source_canister_id) {
                None => fatal!(
                    self.log,
                    "Should be guaranteed that the canister exists in the map."
                ),
                Some(canister) => canister,
            };

            source_canister.induct_messages_to_self(
                max_canister_memory_size,
                &mut subnet_available_memory,
                state.metadata.own_subnet_type,
            );

            source_canister
                .system_state
                .output_queues_for_each(|canister_id, msg| match canisters.get_mut(canister_id) {
                    Some(dest_canister) => dest_canister
                        .push_input(
                            QUEUE_INDEX_NONE,
                            (*msg).clone(),
                            max_canister_memory_size,
                            &mut subnet_available_memory,
                            state.metadata.own_subnet_type,
                            InputQueueType::LocalSubnet,
                        )
                        .map_err(|(err, msg)| {
                            error!(
                                self.log,
                                "Inducting {:?} on same subnet failed with error '{}'.", &msg, &err
                            );
                        }),

                    None => Err(()),
                });

            canisters.insert(source_canister_id, source_canister);
        }
        state.put_canister_states(canisters);
    }

    // Iterates through the provided canisters and checks if the invariants are still valid.
    //
    // Returns `true` if all canisters are valid, `false` otherwise.
    fn check_canister_invariants(
        &self,
        round_log: &ReplicaLogger,
        current_round: &ExecutionRound,
        state: &ReplicatedState,
        canister_ids: &BTreeSet<CanisterId>,
    ) -> bool {
        for canister_id in canister_ids {
            let canister = state.canister_states.get(canister_id).unwrap();
            if let Err(err) = canister.check_invariants(
                state.metadata.own_subnet_type,
                self.exec_env.max_canister_memory_size(),
            ) {
                self.metrics.canister_invariants.inc();
                warn!(
                    round_log,
                    "{}: At Round {} @ time {}, canister {} has invalid state after execution. Invariants check failed with err: {}",
                    CANISTER_INVARIANT_BROKEN,
                    current_round,
                    state.time(),
                    canister_id,
                    err
                );
                return false;
            }
        }
        true
    }
}

impl Scheduler for SchedulerImpl {
    type State = ReplicatedState;

    fn execute_round(
        &self,
        mut state: ReplicatedState,
        randomness: Randomness,
        ecdsa_subnet_public_keys: BTreeMap<EcdsaKeyId, MasterEcdsaPublicKey>,
        current_round: ExecutionRound,
        current_round_type: ExecutionRoundType,
        registry_settings: &RegistryExecutionSettings,
    ) -> ReplicatedState {
        let measurement_scope = MeasurementScope::root(&self.metrics.round);

        let mut cycles_in_sum = Cycles::zero();
        let round_log;
        let mut csprng;
        {
            let _timer = self.metrics.round_preparation_duration.start_timer();
            round_log = new_logger!(self.log; messaging.round => current_round.get());
            debug!(
                round_log,
                "Executing Round {} @ time {}.  Current heap delta size {}.",
                current_round,
                state.time(),
                state.metadata.heap_delta_estimate,
            );
            self.metrics.execute_round_called.inc();
            observe_replicated_state_metrics(self.own_subnet_id, &state, &self.metrics, &round_log);

            {
                let _timer = self.metrics.round_preparation_ingress.start_timer();
                self.purge_expired_ingress_messages(&mut state);
            }

            // See documentation around definition of `heap_delta_estimate` for an
            // explanation.
            if state.metadata.heap_delta_estimate >= self.config.subnet_heap_delta_capacity {
                warn!(
                    round_log,
                    "At Round {} @ time {}, current heap delta {} exceeds allowed capacity {}, so not executing any messages.",
                    current_round,
                    state.time(),
                    state.metadata.heap_delta_estimate,
                    self.config.subnet_heap_delta_capacity
                );
                match current_round_type {
                    ExecutionRoundType::CheckpointRound => {
                        state.metadata.heap_delta_estimate = NumBytes::from(0);
                    }
                    ExecutionRoundType::OrdinaryRound => {}
                }
                self.metrics
                    .round_skipped_due_to_current_heap_delta_above_limit
                    .inc();
                return state;
            }

            // Once the subnet messages are executed in threads, each thread will
            // need its own Csprng instance which is initialized with a distinct
            // "ExecutionThread". Otherwise, two Csprng instances that are
            // initialized with the same Randomness and ExecutionThread would
            // reveal the same bytes and break the guarantees that we provide for
            // raw_rand method of the virtual canister.
            csprng = Csprng::from_seed_and_purpose(
                &randomness,
                &ExecutionThread(self.config.scheduler_cores as u32),
            );

            for canister in state.canisters_iter_mut() {
                cycles_in_sum += canister.system_state.balance();
                cycles_in_sum += canister.system_state.queues().input_queue_cycles();
            }
        }

        // Invoke the heartbeat of the bitcoin canister.
        {
            let bitcoin_state: BitcoinState = state.take_bitcoin_state();
            let bitcoin_state = {
                let _timer = self
                    .metrics
                    .round_bitcoin_canister_heartbeat_duration
                    .start_timer();
                self.bitcoin_canister
                    .heartbeat(bitcoin_state, state.metadata.own_subnet_features.bitcoin())
            };
            state.put_bitcoin_state(bitcoin_state);
        }

        // Ideally we would split the per-round limit between subnet messages and
        // canister messages, so that their sum cannot exceed the limit. That would
        // make the limit for canister messages variable, which would break assumptions
        // of the scheduling algorithm. The next best thing we can do is to limit
        // subnet messages on top of the fixed limit for canister messages.
        // The value of the limit for subnet messages is chosen quite arbitrarily
        // as 1/16 of the fixed limit. Any other value in the same ballpark would
        // work here.
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(self.config.max_instructions_per_round / 16),
            subnet_available_memory: self.exec_env.subnet_available_memory(&state).into(),
        };

        // Execute subnet messages.
        {
            // Drain the consensus queue.
            let measurement_scope =
                MeasurementScope::nested(&self.metrics.round_consensus_queue, &measurement_scope);

            // The consensus queue has to be emptied in each round, so we process
            // it fully without applying the per-round instruction limit.
            // For now, we assume all subnet messages need the entire replicated
            // state. That can be changed in the future as we optimize scheduling.
            while let Some(response) = state.consensus_queue.pop() {
                let instruction_limits = InstructionLimits::new(
                    self.deterministic_time_slicing,
                    self.config.max_instructions_per_message,
                    self.config.max_instructions_per_slice,
                );
                let instructions_before = round_limits.instructions;
                state = self.exec_env.execute_subnet_message(
                    CanisterInputMessage::Response(response.into()),
                    state,
                    instruction_limits,
                    &mut csprng,
                    &ecdsa_subnet_public_keys,
                    registry_settings,
                    &mut round_limits,
                );
                let instructions_executed =
                    as_num_instructions(instructions_before - round_limits.instructions);
                measurement_scope.add(instructions_executed, NumMessages::from(1));
                if round_limits.instructions <= RoundInstructions::from(0) {
                    break;
                }
            }
        }

        {
            // Drain the subnet queues.
            let measurement_scope =
                MeasurementScope::nested(&self.metrics.round_subnet_queue, &measurement_scope);

            let mut total_bitcoin_requests = 0;

            while let Some(msg) = state.pop_subnet_input() {
                let max_instructions_per_message =
                    get_instructions_limit_for_subnet_message(&self.config, &msg);
                let instruction_limits = InstructionLimits::new(
                    self.deterministic_time_slicing,
                    max_instructions_per_message,
                    self.config.max_instructions_per_slice,
                );

                if is_bitcoin_request(&msg) {
                    total_bitcoin_requests += 1;
                }

                let instructions_before = round_limits.instructions;
                state = self.exec_env.execute_subnet_message(
                    msg,
                    state,
                    instruction_limits,
                    &mut csprng,
                    &ecdsa_subnet_public_keys,
                    registry_settings,
                    &mut round_limits,
                );
                let instructions_executed =
                    as_num_instructions(instructions_before - round_limits.instructions);
                measurement_scope.add(instructions_executed, NumMessages::from(1));
                if round_limits.instructions <= RoundInstructions::from(0) {
                    break;
                }

                // Stop after executing at most `MAX_BITCOIN_REQUESTS_PER_ROUND`.
                //
                // Note that this is a rather crude measure to ensure that we
                // do not exceed a "reasonable" amount of work in a round. We
                // rely on the assumption that no other subnet messages can
                // exist on bitcoin enabled subnets, so blocking the subnet
                // message progress does not affect other types of messages.
                // On the other hand, on non-bitcoin enabled subnets, there
                // should be no bitcoin related requests, so this should be
                // a no-op for those subnets.
                if total_bitcoin_requests >= MAX_BITCOIN_REQUESTS_PER_ROUND {
                    break;
                }
            }
        }

        // Reset the round limit after executing all subnet messages.
        //
        // The round will stop as soon as the counter reaches zero.
        // We can compute the initial value `X` of the counter based on:
        // - `R = max_instructions_per_round`,
        // - `M = max_instructions_per_message`.
        // In the worst case, we start a new Wasm execution when then counter
        // reaches 1 and the execution uses the maximum `M` instructions. After
        // the execution the counter will be set to `1 - M`.
        //
        // We want the total number executed instructions to not exceed `R`,
        // which gives us: `X - (1 - M) <= R` or `X <= R - M + 1`.
        round_limits.instructions = as_round_instructions(self.config.max_instructions_per_round)
            - as_round_instructions(self.config.max_instructions_per_message)
            + RoundInstructions::from(1);

        let ordered_canister_ids;
        {
            let _timer = self.metrics.round_scheduling_duration.start_timer();
            ordered_canister_ids = {
                let mut canisters = state.take_canister_states();
                let ordered_canister_ids = apply_scheduling_strategy(
                    self.config.scheduler_cores,
                    current_round,
                    &mut canisters,
                );

                for canister_id in &ordered_canister_ids {
                    let canister_state = canisters.get_mut(canister_id).unwrap();
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
        }

        let (mut state, active_canister_ids) = self.inner_round(
            state,
            &ordered_canister_ids,
            current_round,
            &measurement_scope,
            &mut round_limits,
        );

        let mut final_state;
        {
            let mut cycles_out_sum = Cycles::zero();
            let mut total_canister_balance = Cycles::zero();
            let mut total_canister_memory_usage = NumBytes::new(0);
            let _timer = self.metrics.round_finalization_duration.start_timer();
            let own_subnet_type = state.metadata.own_subnet_type;
            for canister in state.canisters_iter_mut() {
                let heap_delta_debit = canister.scheduler_state.heap_delta_debit.get();
                self.metrics
                    .canister_heap_delta_debits
                    .observe(heap_delta_debit as f64);
                canister.scheduler_state.heap_delta_debit = match self.rate_limiting_of_heap_delta {
                    FlagStatus::Enabled => NumBytes::from(
                        heap_delta_debit.saturating_sub(self.config.heap_delta_rate_limit.get()),
                    ),
                    FlagStatus::Disabled => NumBytes::from(0),
                };

                let install_code_debit = canister.scheduler_state.install_code_debit.get();
                self.metrics
                    .canister_install_code_debits
                    .observe(install_code_debit as f64);
                canister.scheduler_state.install_code_debit =
                    match self.rate_limiting_of_instructions {
                        FlagStatus::Enabled => NumInstructions::from(
                            install_code_debit
                                .saturating_sub(self.config.install_code_rate_limit.get()),
                        ),
                        FlagStatus::Disabled => NumInstructions::from(0),
                    };
                total_canister_memory_usage += canister.memory_usage(own_subnet_type);
                total_canister_balance += canister.system_state.balance();
                cycles_out_sum += canister.system_state.queues().output_queue_cycles();
            }
            cycles_out_sum += total_canister_balance;

            self.metrics
                .total_canister_balance
                .set(total_canister_balance.get() as f64);

            // TODO(EXC-1124): Re-enable the check below once it's fixed.
            //
            // Check that amount of cycles at the beginning of the round (balances and cycles from input messages) is bigger or equal
            // than the amount of cycles at the end of the round (balances and cycles from output messages).
            // if cycles_in_sum < cycles_out_sum {
            //     warn!(
            //         round_log,
            //         "At Round {} @ time {}, the resulted state after execution does not hold the in-out cycles invariant: cycles at beginning of round {} were fewer than cycles at end of round {}",
            //         current_round,
            //         state.time(),
            //         cycles_in_sum,
            //         cycles_out_sum,
            //     );
            // }

            // Check replicated state invariants still hold after the round execution.
            if total_canister_memory_usage > self.exec_env.subnet_memory_capacity() {
                self.metrics.subnet_memory_usage_invariant.inc();
                warn!(
                    round_log,
                    "{}: At Round {} @ time {}, the resulted state after execution does not hold the invariants. Exceeding capacity subnet memory allowed: used {} allowed {}",
                    SUBNET_MEMORY_USAGE_INVARIANT_BROKEN,
                    current_round,
                    state.time(),
                    total_canister_memory_usage,
                    self.exec_env.subnet_memory_capacity()
                );
            }

            // Check if the invariants are still valid after the execution for active canisters.
            self.check_canister_invariants(
                &round_log,
                &current_round,
                &state,
                &active_canister_ids,
            );

            // NOTE: The logic for deleting canisters assumes that transitioning
            // canisters from `Stopping` to `Stopped` happens at the end of the round
            // as is currently the case. If this logic is moved elsewhere (e.g. at the
            // beginning of the round), then canister deletion logic should be revised.
            {
                let _timer = self.metrics.round_finalization_stop_canisters.start_timer();
                final_state = self.process_stopping_canisters(state);
            }
            {
                let _timer = self.metrics.round_finalization_ingress.start_timer();
                final_state.prune_ingress_history();
            }
            {
                let _timer = self.metrics.round_finalization_charge.start_timer();
                self.charge_canisters_for_resource_allocation_and_usage(
                    &mut final_state,
                    registry_settings.subnet_size,
                );
            }
        }
        match current_round_type {
            ExecutionRoundType::CheckpointRound => {
                final_state.metadata.heap_delta_estimate = NumBytes::from(0);
                // `expected_compiled_wasms` will be cleared upon store and load
                // of a checkpoint because it doesn't exist in the protobuf
                // metadata, but we make it explicit here anyway.
                final_state.metadata.expected_compiled_wasms.clear();
            }
            ExecutionRoundType::OrdinaryRound => {}
        }

        final_state
    }
}

fn observe_instructions_consumed_per_message(
    logger: &ReplicaLogger,
    metrics: &SchedulerMetrics,
    canister: &CanisterState,
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
    if consumed_instructions > instruction_limit_per_message {
        warn!(
            logger,
            "Execution consumed too many instructions: limit={} consumed={}, canister_id={}",
            instruction_limit_per_message,
            consumed_instructions,
            canister.canister_id()
        );
    }
}

/// This struct holds the result of a single execution thread.
#[derive(Default)]
struct ExecutionThreadResult {
    canisters: Vec<CanisterState>,
    ingress_results: Vec<(MessageId, IngressStatus)>,
    messages_executed: NumMessages,
    heap_delta: NumBytes,
    round_limits: RoundLimits,
}

/// Executes the given canisters one by one. For each canister it
/// - runs the heartbeat handler of the canister if needed,
/// - executes all messages of the canister.
/// The execution stops if `total_instruction_limit` is reached
/// or all canisters are processed.
#[allow(clippy::too_many_arguments)]
fn execute_canisters_on_thread(
    canisters_to_execute: Vec<CanisterState>,
    exec_env: &ExecutionEnvironment,
    config: &SchedulerConfig,
    metrics: Arc<SchedulerMetrics>,
    round_id: ExecutionRound,
    time: Time,
    network_topology: Arc<NetworkTopology>,
    logger: ReplicaLogger,
    rate_limiting_of_heap_delta: FlagStatus,
    deterministic_time_slicing: FlagStatus,
    mut round_limits: RoundLimits,
) -> ExecutionThreadResult {
    // Since this function runs on a helper thread, we cannot use a nested scope
    // here. Instead, we propagate metrics to the outer scope manually via
    // `ExecutionThreadResult`.
    let measurement_scope =
        MeasurementScope::root(&metrics.round_inner_iteration_thread).dont_record_zeros();
    // These variables accumulate the results and will be returned at the end.
    let mut canisters = vec![];
    let mut ingress_results = vec![];
    let mut total_messages_executed = NumMessages::from(0);
    let mut total_heap_delta = NumBytes::from(0);

    let instruction_limits = InstructionLimits::new(
        deterministic_time_slicing,
        config.max_instructions_per_message,
        config.max_instructions_per_slice,
    );

    for (rank, mut canister) in canisters_to_execute.into_iter().enumerate() {
        // If no more instructions are left or if heap delta is already too
        // large, then skip execution of the canister and keep its old state.
        if round_limits.instructions <= RoundInstructions::from(0)
            || total_heap_delta >= config.max_heap_delta_per_iteration
        {
            canisters.push(canister);
            continue;
        }

        // Process all messages of the canister until
        // - it has not tasks and input messages to execute
        // - or the instruction limit is reached.
        while canister.is_active() {
            if round_limits.instructions <= RoundInstructions::from(0) {
                canister
                    .system_state
                    .canister_metrics
                    .interruped_during_execution += 1;
                break;
            }
            let measurement_scope = MeasurementScope::nested(
                &metrics.round_inner_iteration_thread_message,
                &measurement_scope,
            );
            let timer = metrics.msg_execution_duration.start_timer();

            let instructions_before = round_limits.instructions;
            let ExecuteCanisterResult {
                canister: new_canister,
                heap_delta,
                ingress_status,
                description,
            } = execute_canister(
                exec_env,
                canister,
                instruction_limits.clone(),
                Arc::clone(&network_topology),
                time,
                &mut round_limits,
            );
            ingress_results.extend(ingress_status);
            let instructions_executed =
                as_num_instructions(instructions_before - round_limits.instructions);
            measurement_scope.add(instructions_executed, NumMessages::from(1));
            observe_instructions_consumed_per_message(
                &logger,
                &metrics,
                &new_canister,
                instructions_executed,
                instruction_limits.message(),
            );
            canister = new_canister;
            round_limits.instructions -=
                as_round_instructions(config.instruction_overhead_per_message);
            total_messages_executed.inc_assign();
            total_heap_delta += heap_delta;
            if rate_limiting_of_heap_delta == FlagStatus::Enabled {
                canister.scheduler_state.heap_delta_debit += heap_delta;
            }
            let msg_execution_duration = timer.stop_and_record();
            if msg_execution_duration > config.max_message_duration_before_warn_in_seconds {
                warn!(
                    logger,
                    "Finished executing message type {:?} on canister {:?} after {:?} seconds",
                    description.unwrap_or_default(),
                    canister.canister_id(),
                    msg_execution_duration;
                    messaging.canister_id => canister.canister_id().to_string(),
                );
            }
            if total_heap_delta >= config.max_heap_delta_per_iteration {
                break;
            }
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

    ExecutionThreadResult {
        canisters,
        ingress_results,
        messages_executed: total_messages_executed,
        heap_delta: total_heap_delta,
        round_limits,
    }
}

fn observe_replicated_state_metrics(
    own_subnet_id: SubnetId,
    state: &ReplicatedState,
    metrics: &SchedulerMetrics,
    logger: &ReplicaLogger,
) {
    // Observe the number of registered canisters keyed by their status.
    let mut num_running_canisters = 0;
    let mut num_stopping_canisters = 0;
    let mut num_stopped_canisters = 0;

    let mut consumed_cycles_total = NominalCycles::new(0);

    let mut ingress_queue_message_count = 0;
    let mut ingress_queue_size_bytes = 0;
    let mut input_queues_message_count = 0;
    let mut input_queues_size_bytes = 0;
    let mut queues_response_bytes = 0;
    let mut queues_reservations = 0;
    let mut queues_oversized_requests_extra_bytes = 0;
    let mut canisters_not_in_routing_table = 0;
    let mut canisters_with_old_open_call_contexts = 0;
    let mut old_call_contexts_count = 0;

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
        let queues = canister.system_state.queues();
        ingress_queue_message_count += queues.ingress_queue_message_count();
        ingress_queue_size_bytes += queues.ingress_queue_size_bytes();
        input_queues_message_count += queues.input_queues_message_count();
        input_queues_size_bytes += queues.input_queues_size_bytes();
        queues_response_bytes += queues.responses_size_bytes();
        queues_reservations += queues.reserved_slots();
        queues_oversized_requests_extra_bytes += queues.oversized_requests_extra_bytes();
        if state.routing_table().route(canister.canister_id().into()) != Some(own_subnet_id) {
            canisters_not_in_routing_table += 1;
        }
        if let Some(manager) = canister.system_state.call_context_manager() {
            let old_call_contexts =
                manager.call_contexts_older_than(state.time(), OLD_CALL_CONTEXT_CUTOFF_ONE_DAY);
            for (origin, origin_time) in &old_call_contexts {
                error!(
                    logger,
                    "Call context has been open for {:?}: origin: {:?}, respondent: {}",
                    state.time() - *origin_time,
                    origin,
                    canister.canister_id()
                );
            }
            old_call_contexts_count += old_call_contexts.len();
            if !old_call_contexts.is_empty() {
                canisters_with_old_open_call_contexts += 1;
            }
        }
    });
    metrics
        .old_open_call_contexts
        .with_label_values(&[OLD_CALL_CONTEXT_LABEL_ONE_DAY])
        .set(old_call_contexts_count as i64);
    metrics
        .canisters_with_old_open_call_contexts
        .with_label_values(&[OLD_CALL_CONTEXT_LABEL_ONE_DAY])
        .set(canisters_with_old_open_call_contexts as i64);
    let streams_response_bytes = state
        .metadata
        .streams()
        .responses_size_bytes()
        .values()
        .sum();

    metrics
        .current_heap_delta
        .set(state.metadata.heap_delta_estimate.get() as i64);

    // Add the consumed cycles by canisters that were deleted.
    consumed_cycles_total += state
        .metadata
        .subnet_metrics
        .consumed_cycles_by_deleted_canisters;
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

    metrics.observe_queues_response_bytes(queues_response_bytes);
    metrics.observe_queues_reservations(queues_reservations);
    metrics.observe_oversized_requests_extra_bytes(queues_oversized_requests_extra_bytes);
    metrics.observe_streams_response_bytes(streams_response_bytes);

    metrics
        .ingress_history_length
        .set(state.metadata.ingress_history.len() as i64);
    metrics
        .canisters_not_in_routing_table
        .set(canisters_not_in_routing_table);
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
    match Ic00Method::from_str(method_name) {
        Ok(method) => match method {
            CanisterStatus
            | CreateCanister
            | DeleteCanister
            | DepositCycles
            | ECDSAPublicKey
            | RawRand
            | SetController
            | HttpRequest
            | SetupInitialDKG
            | SignWithECDSA
            | ComputeInitialEcdsaDealings
            | StartCanister
            | StopCanister
            | UninstallCode
            | UpdateSettings
            | BitcoinGetBalance
            | BitcoinGetUtxos
            | BitcoinSendTransaction
            | BitcoinGetCurrentFeePercentiles
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

fn is_bitcoin_request(msg: &CanisterInputMessage) -> bool {
    use Ic00Method::*;

    match msg {
        CanisterInputMessage::Ingress(_) => false,
        CanisterInputMessage::Request(req) => match Ic00Method::from_str(&req.method_name) {
            Ok(method) => match method {
                BitcoinGetBalance
                | BitcoinGetUtxos
                | BitcoinSendTransaction
                | BitcoinGetCurrentFeePercentiles => true,
                CanisterStatus
                | CreateCanister
                | DeleteCanister
                | DepositCycles
                | ECDSAPublicKey
                | RawRand
                | SetController
                | HttpRequest
                | SetupInitialDKG
                | SignWithECDSA
                | ComputeInitialEcdsaDealings
                | StartCanister
                | StopCanister
                | UninstallCode
                | UpdateSettings
                | ProvisionalCreateCanisterWithCycles
                | ProvisionalTopUpCanister
                | InstallCode => false,
            },
            Err(_) => false,
        },
        CanisterInputMessage::Response(_) => false,
    }
}
