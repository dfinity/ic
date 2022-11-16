use crate::{
    canister_manager::uninstall_canister,
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
use ic_crypto_prng::{Csprng, RandomnessPurpose::ExecutionThread};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::{CanisterStatusType, EcdsaKeyId, Method as Ic00Method};
use ic_interfaces::execution_environment::{ExecutionRoundType, RegistryExecutionSettings};
use ic_interfaces::{
    execution_environment::{IngressHistoryWriter, Scheduler},
    messages::CanisterInputMessage,
};
use ic_logger::{debug, error, fatal, info, new_logger, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{
    bitcoin_state::BitcoinState, canister_state::NextExecution, CanisterState, ExecutionTask,
    InputQueueType, NetworkTopology, ReplicatedState,
};
use ic_system_api::InstructionLimits;
use ic_types::{
    crypto::canister_threshold_sig::MasterEcdsaPublicKey,
    ingress::{IngressState, IngressStatus},
    messages::{Ingress, MessageId},
    CanisterId, ComputeAllocation, Cycles, ExecutionRound, LongExecutionMode, MemoryAllocation,
    NumBytes, NumInstructions, NumSlices, Randomness, SubnetId, Time,
};
use ic_types::{nominal_cycles::NominalCycles, NumMessages};
use num_rational::Ratio;
use std::cmp::Reverse;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};

mod scheduler_metrics;
use scheduler_metrics::*;
mod round_schedule;
pub use round_schedule::RoundSchedule;
use round_schedule::*;

/// Maximum number of allowed bitcoin requests per round. If this number is
/// reached we stop executing more bitcoin requests for this round.
const MAX_BITCOIN_REQUESTS_PER_ROUND: usize = 5;

/// Only log potentially spammy messages this often (in rounds). With a block
/// rate around 1.0, this will result in logging about once every 10 minutes.
const SPAMMY_LOG_INTERVAL_ROUNDS: u64 = 10 * 60;

#[cfg(test)]
pub(crate) mod test_utilities;
#[cfg(test)]
pub(crate) mod tests;

////////////////////////////////////////////////////////////////////////
/// Scheduler Implementation

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

impl SchedulerImpl {
    /// Returns scheduler compute capacity.
    /// For the DTS scheduler it's (number of cores - 1) * 100%
    pub fn compute_capacity(scheduler_cores: usize) -> usize {
        // Note: the DTS scheduler requires at least 2 scheduler cores
        if scheduler_cores >= 2 {
            (scheduler_cores - 1) * 100
        } else {
            0
        }
    }

    /// Orders canister round states according to the scheduling strategy.
    /// The function is to keep in sync `apply_scheduling_strategy()` and
    /// `abort_paused_executions_above_limit()`
    fn order_canister_round_states(&self, round_states: &mut [CanisterRoundState]) {
        round_states.sort_by_key(|rs| {
            (
                Reverse(rs.long_execution_mode),
                Reverse(rs.has_aborted_or_paused_execution),
                Reverse(rs.accumulated_priority),
                rs.canister_id,
            )
        });
    }

    /// Orders the canisters and updates their accumulated priorities according to
    /// the strategy described in RUN-58.
    ///
    /// A shorter description of the scheduling strategy is available in the note
    /// section about [Scheduler and AccumulatedPriority] in types/src/lib.rs
    fn apply_scheduling_strategy(
        &self,
        scheduler_cores: usize,
        current_round: ExecutionRound,
        canister_states: &mut BTreeMap<CanisterId, CanisterState>,
    ) -> RoundSchedule {
        let number_of_canisters = canister_states.len();

        // DTS Scheduler: Compute the free allocation as F = N * 100 - 𝚺RCi (>= 1).
        let compute_capacity = Self::compute_capacity(scheduler_cores) as i64;

        // This corresponds to |a| in Scheduler Analysis.
        let mut total_compute_allocation: i64 = 0;

        // Use this multiplier to achieve the following two: 1) The sum of all the
        // values we add to accumulated priorities to calculate the round priorities
        // must be divisible by the number of canisters that are given top priority
        // in this round. 2) The free compute_allocation (the difference between
        // capacity and total_compute_allocation) can be distributed to all the
        // canisters evenly.
        // The `max(1)` is the corner case when there are no Canisters
        let multiplier = (scheduler_cores * number_of_canisters).max(1) as i64;

        // This corresponds to the vector p in the Scheduler Analysis document.
        let mut round_states = Vec::with_capacity(number_of_canisters);

        // Reset the accumulated priorities every 100 rounds (times the multiplier).
        // We want to reset the scheduler regularly to safely support changes in the set
        // of canisters and their compute allocations.
        let reset_round = (current_round.get() as i64 % (100 * multiplier)) == 0;

        // Compute the priority of the canisters for this round.
        for (&canister_id, canister) in canister_states.iter_mut() {
            if reset_round {
                canister.scheduler_state.accumulated_priority = 0.into();
                canister.scheduler_state.priority_credit = 0.into();
            }

            let has_aborted_or_paused_execution =
                canister.has_aborted_execution() || canister.has_paused_execution();
            if !has_aborted_or_paused_execution {
                canister.scheduler_state.long_execution_mode = LongExecutionMode::Opportunistic;
            }

            let compute_allocation =
                canister.scheduler_state.compute_allocation.as_percent() as i64;
            round_states.push(CanisterRoundState {
                canister_id,
                accumulated_priority: canister.scheduler_state.accumulated_priority.value(),
                compute_allocation,
                long_execution_mode: canister.scheduler_state.long_execution_mode,
                has_aborted_or_paused_execution,
            });

            total_compute_allocation += compute_allocation;
        }
        // DTS Scheduler: (Always ensure 𝚺RCi <= N * 100 - 1)
        debug_assert!(total_compute_allocation < compute_capacity);

        // Distribute the free capacity to all the canisters evenly:
        // DTS Scheduler: Compute the free allocation as F = N * 100 - 𝚺RCi (>= 1).
        let free_capacity_per_canister =
            (compute_capacity.saturating_sub(total_compute_allocation)) * scheduler_cores as i64;

        // Fully divide the free allocation across all canisters.
        let mut long_executions_compute_allocation = 0;
        let mut total_long_executions = 0;
        for rs in round_states.iter_mut() {
            // De-facto compute allocation includes bonus allocation
            let factual = rs.compute_allocation * multiplier + free_capacity_per_canister;
            let canister = canister_states.get_mut(&rs.canister_id).unwrap();
            // DTS Scheduler: round priority = accumulated priority + ACi
            rs.accumulated_priority += factual;
            canister.scheduler_state.accumulated_priority = rs.accumulated_priority.into();
            if rs.has_aborted_or_paused_execution {
                long_executions_compute_allocation += factual;
                total_long_executions += 1;
            }
        }

        // DTS Scheduler: long execution cores = round_up(𝚺ACi / 100)
        let long_execution_cores = ((long_executions_compute_allocation + 100 * multiplier - 1)
            / (100 * multiplier)) as usize;

        self.order_canister_round_states(&mut round_states);

        let round_schedule = RoundSchedule::new(
            scheduler_cores,
            long_execution_cores,
            round_states
                .iter()
                .skip(total_long_executions)
                .map(|rs| rs.canister_id)
                .collect(),
            round_states
                .iter()
                .take(total_long_executions)
                .map(|rs| rs.canister_id)
                .collect(),
        );

        {
            let scheduling_order = round_schedule.scheduling_order();
            let scheduling_order = scheduling_order
                .prioritized_long_canister_ids
                .chain(scheduling_order.new_canister_ids)
                .chain(scheduling_order.opportunistic_long_canister_ids);
            // The number of active scheduler cores is limited by the number of Canisters to schedule.
            let active_cores = scheduler_cores.min(number_of_canisters);
            for (i, canister_id) in scheduling_order.take(active_cores).enumerate() {
                let canister_state = canister_states.get_mut(canister_id).unwrap();
                // When handling top canisters, decrease their priority by
                // `multiplier * capacity / scheduler_cores`
                // DTS Scheduler: postpone the decrease until the end of the round.
                canister_state.scheduler_state.priority_credit =
                    (canister_state.scheduler_state.priority_credit.value()
                        + compute_capacity * multiplier / active_cores as i64)
                        .into();
                if i < round_schedule.long_execution_cores {
                    canister_state.scheduler_state.long_execution_mode =
                        LongExecutionMode::Prioritized;
                }
            }
        }

        round_schedule
    }

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

    /// Makes progress in executing long-running `install_code` messages.
    fn advance_long_running_install_code(
        &self,
        mut state: ReplicatedState,
        round_limits: &mut RoundLimits,
        long_running_canister_ids: &BTreeSet<CanisterId>,
        measurement_scope: &MeasurementScope,
        subnet_size: usize,
    ) -> (ReplicatedState, bool) {
        let mut ongoing_long_install_code = false;
        for canister_id in long_running_canister_ids.iter() {
            match state.canister_state(canister_id) {
                None => continue,
                Some(canister) => match canister.next_execution() {
                    NextExecution::None | NextExecution::StartNew | NextExecution::ContinueLong => {
                        continue
                    }
                    NextExecution::ContinueInstallCode => {}
                },
            }
            let instruction_limits = InstructionLimits::new(
                self.deterministic_time_slicing,
                self.config.max_instructions_per_install_code,
                self.config.max_instructions_per_install_code_slice,
            );
            let instructions_before = round_limits.instructions;
            let (new_state, message_instructions) = self.exec_env.resume_install_code(
                state,
                canister_id,
                instruction_limits,
                round_limits,
                subnet_size,
            );
            state = new_state;
            ongoing_long_install_code = state
                .canister_state(canister_id)
                .map_or(false, |canister| canister.has_paused_install_code());

            let round_instructions_executed =
                as_num_instructions(instructions_before - round_limits.instructions);

            let messages = NumMessages::from(message_instructions.map(|_| 1).unwrap_or(0));
            measurement_scope.add(round_instructions_executed, NumSlices::from(1), messages);

            // Break when reached the instructions limit or
            // found a canister that has a long install code message in progress.
            if round_limits.instructions <= RoundInstructions::from(0) || ongoing_long_install_code
            {
                break;
            }
        }
        (state, ongoing_long_install_code)
    }

    /// Drains the subnet queues, executing all messages not blocked by long executions.
    /// It consumes the `long_running_canister_ids` set instead of borrowing it
    /// because after the function execution the set is no longer valid.
    fn drain_subnet_queues(
        &self,
        mut state: ReplicatedState,
        csprng: &mut Csprng,
        round_limits: &mut RoundLimits,
        measurement_scope: &MeasurementScope,
        ongoing_long_install_code: bool,
        long_running_canister_ids: BTreeSet<CanisterId>,
        registry_settings: &RegistryExecutionSettings,
        ecdsa_subnet_public_keys: &BTreeMap<EcdsaKeyId, MasterEcdsaPublicKey>,
    ) -> ReplicatedState {
        let mut total_bitcoin_requests = 0;

        loop {
            let mut available_subnet_messages = false;
            let mut loop_detector = state.subnet_queues_loop_detector();
            while let Some(msg) = state.peek_subnet_input() {
                if can_execute_msg(&msg, ongoing_long_install_code, &long_running_canister_ids) {
                    available_subnet_messages = true;
                    break;
                }
                state.skip_subnet_input(&mut loop_detector);
                if loop_detector.detected_loop(state.subnet_queues()) {
                    break;
                }
            }

            if !available_subnet_messages {
                break;
            }
            if let Some(msg) = state.pop_subnet_input() {
                let instruction_limits = get_instructions_limits_for_subnet_message(
                    self.deterministic_time_slicing,
                    &self.config,
                    &msg,
                );

                if is_bitcoin_request(&msg) {
                    total_bitcoin_requests += 1;
                }

                let instructions_before = round_limits.instructions;
                let (new_state, message_instructions) = self.exec_env.execute_subnet_message(
                    msg,
                    state,
                    instruction_limits,
                    csprng,
                    ecdsa_subnet_public_keys,
                    registry_settings,
                    round_limits,
                );
                state = new_state;
                let round_instructions_executed =
                    as_num_instructions(instructions_before - round_limits.instructions);
                let messages = NumMessages::from(message_instructions.map(|_| 1).unwrap_or(0));
                measurement_scope.add(round_instructions_executed, NumSlices::from(1), messages);

                if message_instructions.is_none() {
                    // This may happen only if the message execution was paused,
                    // which means that there should not be any instructions
                    // remaining in the round. Since we do not update
                    // `long_running_canister_ids` and `ongoing_long_install_code`,
                    // we need to break the loop here to ensure correctness in
                    // the unlikely case of some instructions still remaining
                    // in the round.
                    break;
                }

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
        state
    }

    /// Performs multiple iterations of canister execution until the instruction
    /// limit per round is reached or the canisters become idle. The canisters
    /// are executed in parallel using the thread pool.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn inner_round<'a>(
        &'a self,
        mut state: ReplicatedState,
        round_schedule: &RoundSchedule,
        current_round: ExecutionRound,
        measurement_scope: &MeasurementScope<'a>,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
    ) -> (ReplicatedState, BTreeSet<CanisterId>) {
        let measurement_scope =
            MeasurementScope::nested(&self.metrics.round_inner, measurement_scope);
        let mut ingress_execution_results = Vec::new();
        let mut is_first_iteration = true;
        let mut round_filtered_canisters = FilteredCanisters::new();

        let mut total_heap_delta = NumBytes::from(0);

        // Add `Heartbeat` and `GlobalTimer` tasks to be executed before input messages.
        {
            let _timer = self
                .metrics
                .round_inner_heartbeat_overhead_duration
                .start_timer();
            let now = state.time();
            for canister in state.canisters_iter_mut() {
                let global_timer_has_reached_deadline =
                    canister.system_state.global_timer.has_reached_deadline(now);
                match canister.next_execution() {
                    NextExecution::ContinueLong | NextExecution::ContinueInstallCode => {
                        // Do not add a heartbeat task if a long execution
                        // is pending.
                    }
                    NextExecution::None | NextExecution::StartNew => {
                        if canister.exports_heartbeat_method() {
                            canister
                                .system_state
                                .task_queue
                                .push_front(ExecutionTask::Heartbeat);
                        }
                        if global_timer_has_reached_deadline
                            && canister.exports_global_timer_method()
                        {
                            canister
                                .system_state
                                .task_queue
                                .push_front(ExecutionTask::GlobalTimer);
                        }
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
            round_limits.subnet_available_memory = self.exec_env.subnet_available_memory(&state);
            let canisters = state.take_canister_states();
            // Obtain the active canisters and update the collection of heap delta rate-limited canisters.
            let (active_round_schedule, rate_limited_canister_ids) = round_schedule
                .filter_canisters(
                    &canisters,
                    self.config.heap_delta_rate_limit,
                    self.rate_limiting_of_heap_delta,
                );
            round_filtered_canisters
                .add_canisters(&active_round_schedule, &rate_limited_canister_ids);

            let (mut active_canisters_partitioned_by_cores, inactive_canisters) =
                active_round_schedule.partition_canisters_to_cores(canisters);

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
                    subnet_size,
                );
            let instructions_consumed = instructions_before - round_limits.instructions;

            let finalization_timer = self.metrics.round_inner_iteration_fin.start_timer();
            total_heap_delta += heap_delta;
            state.metadata.heap_delta_estimate += heap_delta;

            // Put back the executed canisters into the canisters map. Since usually most
            // canisters have no messages to execute, this is likely to be more efficient
            // than rebuilding the map from scratch.
            let mut canisters = inactive_canisters;
            canisters.extend(
                executed_canisters
                    .into_iter()
                    .map(|canister| (canister.canister_id(), canister)),
            );
            state.put_canister_states(canisters);

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
            // Remove all remaining `Heartbeat` and `GlobalTimer` tasks
            // because they will be added again in the next round.
            for canister in state.canisters_iter_mut() {
                canister.system_state.task_queue.retain(|task| match task {
                    ExecutionTask::Heartbeat | ExecutionTask::GlobalTimer => false,
                    ExecutionTask::PausedExecution(..)
                    | ExecutionTask::PausedInstallCode(..)
                    | ExecutionTask::AbortedExecution { .. }
                    | ExecutionTask::AbortedInstallCode { .. } => true,
                });
                // Also, apply priority credit for all the finished executions
                match canister.next_execution() {
                    NextExecution::None
                    | NextExecution::StartNew
                    | NextExecution::ContinueInstallCode => canister.apply_priority_credit(),
                    NextExecution::ContinueLong => {}
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
        subnet_size: usize,
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
            subnet_available_memory: (round_limits.subnet_available_memory
                / self.config.scheduler_cores as i64),
            compute_allocation_used: round_limits.compute_allocation_used,
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
                    subnet_available_memory: round_limits_per_thread.subnet_available_memory,
                    compute_allocation_used: round_limits.compute_allocation_used,
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
                        subnet_size,
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
            measurement_scope.add(
                instructions_executed,
                result.slices_executed,
                result.messages_executed,
            );
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
        let state_time = state.time();
        let mut all_rejects = Vec::new();
        for canister in state.canisters_iter_mut() {
            // Postpone charging for resources when a canister has a paused execution
            // to avoid modifying the balance of a canister during an unfinished operation.
            if canister.has_paused_execution() || canister.has_paused_install_code() {
                continue;
            }

            if state_time
                < canister.scheduler_state.time_of_last_allocation_charge
                    + self
                        .cycles_account_manager
                        .duration_between_allocation_charges()
            {
                // Skip charging for the resources in this round because not enough time has passed
                // since the last charge happened.
                continue;
            } else {
                self.observe_canister_metrics(canister);
                let duration_since_last_charge =
                    canister.duration_since_last_allocation_charge(state_time);
                canister.scheduler_state.time_of_last_allocation_charge = state_time;
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
                    all_rejects.push(uninstall_canister(&self.log, canister, state_time));
                    canister.scheduler_state.compute_allocation = ComputeAllocation::zero();
                    canister.system_state.memory_allocation = MemoryAllocation::BestEffort;
                    // Burn the remaining balance of the canister.
                    let remaining_cycles = canister.system_state.balance_mut().take();
                    canister
                        .system_state
                        .canister_metrics
                        .consumed_cycles_since_replica_started +=
                        NominalCycles::from(remaining_cycles);

                    info!(
                        self.log,
                        "Uninstalling canister {} because it ran out of cycles",
                        canister.canister_id()
                    );
                    self.metrics.num_canisters_uninstalled_out_of_cycles.inc();
                }
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
                // Crash in debug mode if any invariant fails.
                debug_assert!(false,
                    "{}: At Round {} @ time {}, canister {} has invalid state after execution. Invariants check failed with err: {}",
                    CANISTER_INVARIANT_BROKEN,
                    current_round,
                    state.time(),
                    canister_id,
                    err
                );
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

    /// Aborts paused execution above `max_paused_executions` based on scheduler priority.
    fn abort_paused_executions_above_limit(&self, state: &mut ReplicatedState) {
        let mut paused_round_states = state
            .canisters_iter()
            .filter_map(|canister| {
                if canister.has_paused_execution() {
                    Some(CanisterRoundState {
                        canister_id: canister.canister_id(),
                        accumulated_priority: canister.scheduler_state.accumulated_priority.value(),
                        compute_allocation: 0, // not used
                        long_execution_mode: canister.scheduler_state.long_execution_mode,
                        has_aborted_or_paused_execution: true,
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        self.order_canister_round_states(&mut paused_round_states);

        paused_round_states
            .iter()
            .skip(self.config.max_paused_executions)
            .for_each(|rs| {
                let canister = state.canister_states.get_mut(&rs.canister_id).unwrap();
                self.exec_env.abort_canister(canister, &self.log);
            });
    }

    // Code that must be executed unconditionally after each round.
    fn finish_round(&self, state: &mut ReplicatedState, current_round_type: ExecutionRoundType) {
        match current_round_type {
            ExecutionRoundType::CheckpointRound => {
                state.metadata.heap_delta_estimate = NumBytes::from(0);
                // `expected_compiled_wasms` will be cleared upon store and load
                // of a checkpoint because it doesn't exist in the protobuf
                // metadata, but we make it explicit here anyway.
                state.metadata.expected_compiled_wasms.clear();

                if self.deterministic_time_slicing == FlagStatus::Enabled {
                    // Abort all paused execution before the checkpoint.
                    self.exec_env.abort_all_paused_executions(state, &self.log);
                }
            }
            ExecutionRoundType::OrdinaryRound => {
                if self.deterministic_time_slicing == FlagStatus::Enabled {
                    self.abort_paused_executions_above_limit(state);
                }
            }
        }
        self.check_dts_invariants(state, current_round_type);
    }

    /// Checks the deterministic time slicing invariant after round execution.
    fn check_dts_invariants(
        &self,
        state: &ReplicatedState,
        current_round_type: ExecutionRoundType,
    ) {
        let canisters_with_tasks = state
            .canister_states
            .iter()
            .filter(|(_, canister)| !canister.system_state.task_queue.is_empty());

        // 1. Heartbeat and GlobalTimer tasks exist only during the round
        //    and must not exist after the round.
        // 2. Paused executions can exist only in ordinary rounds (not checkpoint rounds).
        // 3. If deterministic time slicing is disabled, then there are no paused tasks.
        //    Aborted tasks may still exist if DTS was disabled in recent checkpoints.
        for (id, canister) in canisters_with_tasks {
            for task in canister.system_state.task_queue.iter() {
                match task {
                    ExecutionTask::AbortedExecution { .. }
                    | ExecutionTask::AbortedInstallCode { .. } => {}
                    ExecutionTask::Heartbeat => {
                        panic!(
                            "Unexpected heartbeat task after a round in canister {:?}",
                            id
                        );
                    }
                    ExecutionTask::GlobalTimer => {
                        panic!(
                            "Unexpected global timer task after a round in canister {:?}",
                            id
                        );
                    }
                    ExecutionTask::PausedExecution(_) | ExecutionTask::PausedInstallCode(_) => {
                        assert_eq!(
                            self.deterministic_time_slicing,
                            FlagStatus::Enabled,
                            "Unexpected paused execution {:?} with disabled DTS in canister: {:?}",
                            task,
                            id
                        );
                        assert_eq!(
                            current_round_type,
                            ExecutionRoundType::OrdinaryRound,
                            "Unexpected paused execution {:?} after a checkpoint round in canister {:?}",
                            task,
                            id
                        );
                    }
                }
            }
        }
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
        let long_running_canister_ids;
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
            observe_replicated_state_metrics(
                self.own_subnet_id,
                &state,
                current_round,
                &self.metrics,
                &round_log,
            );

            long_running_canister_ids = state
                .canister_states
                .iter()
                .filter_map(|(&canister_id, canister)| match canister.next_execution() {
                    NextExecution::None | NextExecution::StartNew => None,
                    NextExecution::ContinueLong | NextExecution::ContinueInstallCode => {
                        Some(canister_id)
                    }
                })
                .collect();

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
                self.finish_round(&mut state, current_round_type);
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
            subnet_available_memory: self.exec_env.subnet_available_memory(&state),
            compute_allocation_used: state.total_compute_allocation(),
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
                    FlagStatus::Disabled,
                    self.config.max_instructions_per_message_without_dts,
                    self.config.max_instructions_per_message_without_dts,
                );
                let instructions_before = round_limits.instructions;
                let (new_state, message_instructions) = self.exec_env.execute_subnet_message(
                    CanisterInputMessage::Response(response.into()),
                    state,
                    instruction_limits,
                    &mut csprng,
                    &ecdsa_subnet_public_keys,
                    registry_settings,
                    &mut round_limits,
                );
                state = new_state;
                let round_instructions_executed =
                    as_num_instructions(instructions_before - round_limits.instructions);
                let messages = NumMessages::from(message_instructions.map(|_| 1).unwrap_or(0));
                measurement_scope.add(round_instructions_executed, NumSlices::from(1), messages);
                if round_limits.instructions <= RoundInstructions::from(0) {
                    break;
                }
            }
        }

        {
            let measurement_scope =
                MeasurementScope::nested(&self.metrics.round_subnet_queue, &measurement_scope);

            let ongoing_long_install_code;
            (state, ongoing_long_install_code) = self.advance_long_running_install_code(
                state,
                &mut round_limits,
                &long_running_canister_ids,
                &measurement_scope,
                registry_settings.subnet_size,
            );

            // If we have executed a long-running install code above, then it is
            // very likely that `round_limits.instructions <= 0` at this point.
            // However, we would like to make progress with other subnet
            // messages that do not consume instructions. To allow that, we set
            // the number available instructions to 1 if it is not positive.
            round_limits.instructions = round_limits.instructions.max(RoundInstructions::from(1));

            state = self.drain_subnet_queues(
                state,
                &mut csprng,
                &mut round_limits,
                &measurement_scope,
                ongoing_long_install_code,
                long_running_canister_ids,
                registry_settings,
                &ecdsa_subnet_public_keys,
            );
        }

        // Reset the round limit after executing all subnet messages.
        //
        // The round will stop as soon as the counter reaches zero.
        // We can compute the initial value `X` of the counter based on:
        // - `R = max_instructions_per_round`,
        // - `S = max(max_instructions_per_slice, max_instructions_per_message_without_dts)`.
        // In the worst case, we start a new Wasm execution when then counter
        // reaches 1 and the execution uses the maximum `S` instructions. After
        // the execution the counter will be set to `1 - S`.
        //
        // We want the total number executed instructions to not exceed `R`,
        // which gives us: `X - (1 - S) <= R` or `X <= R - S + 1`.
        let max_instructions_per_slice = std::cmp::max(
            self.config.max_instructions_per_slice,
            self.config.max_instructions_per_message_without_dts,
        );
        round_limits.instructions = as_round_instructions(self.config.max_instructions_per_round)
            - as_round_instructions(max_instructions_per_slice)
            + RoundInstructions::from(1);

        let round_schedule;
        {
            let _timer = self.metrics.round_scheduling_duration.start_timer();
            round_schedule = {
                let mut canisters = state.take_canister_states();
                let round_schedule = self.apply_scheduling_strategy(
                    self.config.scheduler_cores,
                    current_round,
                    &mut canisters,
                );

                for canister_id in round_schedule.iter() {
                    let canister_state = canisters.get_mut(canister_id).unwrap();
                    if !canister_state.has_input() {
                        canister_state
                            .system_state
                            .canister_metrics
                            .skipped_round_due_to_no_messages += 1;
                    }
                }

                state.put_canister_states(canisters);
                round_schedule
            };
        }

        let (mut state, active_canister_ids) = self.inner_round(
            state,
            &round_schedule,
            current_round,
            &measurement_scope,
            &mut round_limits,
            registry_settings.subnet_size,
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
        self.finish_round(&mut final_state, current_round_type);
        final_state
    }
}

////////////////////////////////////////////////////////////////////////
/// Filtered Canisters

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
        active_round_schedule: &RoundSchedule,
        rate_limited_ids: &[CanisterId],
    ) {
        self.active_canister_ids
            .extend(active_round_schedule.iter());
        self.rate_limited_canister_ids
            .extend(rate_limited_ids.iter());
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
    slices_executed: NumSlices,
    messages_executed: NumMessages,
    heap_delta: NumBytes,
    round_limits: RoundLimits,
}

/// Executes the given canisters one by one. For each canister it
/// - runs the heartbeat or timer handlers of the canister if needed,
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
    subnet_size: usize,
) -> ExecutionThreadResult {
    // Since this function runs on a helper thread, we cannot use a nested scope
    // here. Instead, we propagate metrics to the outer scope manually via
    // `ExecutionThreadResult`.
    let measurement_scope =
        MeasurementScope::root(&metrics.round_inner_iteration_thread).dont_record_zeros();
    // These variables accumulate the results and will be returned at the end.
    let mut canisters = vec![];
    let mut ingress_results = vec![];
    let mut total_slices_executed = NumSlices::from(0);
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
        // - or the canister is blocked by a long-running install code.
        // - or the instruction limit is reached.
        // - or the canister finishes a long execution
        loop {
            match canister.next_execution() {
                NextExecution::None | NextExecution::ContinueInstallCode => {
                    break;
                }
                NextExecution::StartNew | NextExecution::ContinueLong => {}
            }

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
            let canister_had_paused_execution = canister.has_paused_execution();
            let ExecuteCanisterResult {
                canister: new_canister,
                instructions_used,
                heap_delta,
                ingress_status,
                description,
            } = execute_canister(
                exec_env,
                canister,
                instruction_limits.clone(),
                config.max_instructions_per_message_without_dts,
                Arc::clone(&network_topology),
                time,
                &mut round_limits,
                subnet_size,
            );
            ingress_results.extend(ingress_status);
            let round_instructions_executed =
                as_num_instructions(instructions_before - round_limits.instructions);
            let messages = NumMessages::from(instructions_used.map(|_| 1).unwrap_or(0));
            measurement_scope.add(round_instructions_executed, NumSlices::from(1), messages);
            if let Some(instructions_used) = instructions_used {
                total_messages_executed.inc_assign();
                observe_instructions_consumed_per_message(
                    &logger,
                    &metrics,
                    &new_canister,
                    instructions_used,
                    instruction_limits.message(),
                );
            }
            total_slices_executed.inc_assign();
            canister = new_canister;
            round_limits.instructions -=
                as_round_instructions(config.instruction_overhead_per_message);
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
            if canister_had_paused_execution && !canister.has_paused_execution() {
                // Break the loop, as the canister just finished its long execution
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
        slices_executed: total_slices_executed,
        messages_executed: total_messages_executed,
        heap_delta: total_heap_delta,
        round_limits,
    }
}

/// Updates end-of-round replicated state metrics (canisters, queues, cycles,
/// etc.).
fn observe_replicated_state_metrics(
    own_subnet_id: SubnetId,
    state: &ReplicatedState,
    current_round: ExecutionRound,
    metrics: &SchedulerMetrics,
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
        match canister.next_task() {
            Some(&ExecutionTask::PausedExecution(_)) => {
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
            Some(&ExecutionTask::Heartbeat) | Some(&ExecutionTask::GlobalTimer) | None => {}
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
            // Log all old call contexts, but not (nearly) every round.
            if current_round.get() % SPAMMY_LOG_INTERVAL_ROUNDS == 0 {
                for (origin, origin_time) in &old_call_contexts {
                    error!(
                        logger,
                        "Call context has been open for {:?}: origin: {:?}, respondent: {}",
                        state.time() - *origin_time,
                        origin,
                        canister.canister_id()
                    );
                }
            }
            if !old_call_contexts.is_empty() {
                old_call_contexts_count += old_call_contexts.len();
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

    metrics
        .canister_paused_execution
        .observe(num_paused_exec as f64);
    metrics
        .canister_aborted_execution
        .observe(num_aborted_exec as f64);
    metrics
        .canister_paused_install_code
        .observe(num_paused_install as f64);
    metrics
        .canister_aborted_install_code
        .observe(num_aborted_install as f64);

    metrics
        .available_canister_ids
        .set(state.metadata.available_canister_ids() as i64);

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

/// Helper function that checks if a message can be executed:
///     1. A message cannot be executed if it is directed to a canister
///     with another long-running execution in progress.
///     2. Install code messages can only be executed sequentially.
fn can_execute_msg(
    msg: &CanisterInputMessage,
    ongoing_long_install_code: bool,
    long_running_canister_ids: &BTreeSet<CanisterId>,
) -> bool {
    if let Some(effective_canister_id) = msg.effective_canister_id() {
        if long_running_canister_ids.contains(&effective_canister_id) {
            return false;
        }
    }

    if ongoing_long_install_code {
        let maybe_instal_code_method = match msg {
            CanisterInputMessage::Ingress(ingress) => {
                Ic00Method::from_str(ingress.method_name.as_str()).ok()
            }
            CanisterInputMessage::Request(request) => {
                Ic00Method::from_str(request.method_name.as_str()).ok()
            }
            CanisterInputMessage::Response(_) => None,
        };

        // Only one install code message allowed at a time.
        if let Some(Ic00Method::InstallCode) = maybe_instal_code_method {
            return false;
        }
    }

    true
}

/// Based on the type of the subnet message to execute, figure out its
/// instruction limits.
///
/// This is primarily done because upgrading a canister might need to
/// (de)-serialize a large state and thus consume a lot of instructions.
fn get_instructions_limits_for_subnet_message(
    dts: FlagStatus,
    config: &SchedulerConfig,
    msg: &CanisterInputMessage,
) -> InstructionLimits {
    let default_limits = InstructionLimits::new(
        FlagStatus::Disabled,
        config.max_instructions_per_message_without_dts,
        config.max_instructions_per_message_without_dts,
    );
    let method_name = match &msg {
        CanisterInputMessage::Response(_) => {
            return default_limits;
        }
        CanisterInputMessage::Ingress(ingress) => &ingress.method_name,
        CanisterInputMessage::Request(request) => &request.method_name,
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
            | BitcoinSendTransactionInternal
            | BitcoinGetCurrentFeePercentiles
            | BitcoinGetSuccessors
            | ProvisionalCreateCanisterWithCycles
            | ProvisionalTopUpCanister => default_limits,
            InstallCode => InstructionLimits::new(
                dts,
                config.max_instructions_per_install_code,
                config.max_instructions_per_install_code_slice,
            ),
        },
        Err(_) => default_limits,
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
                | BitcoinSendTransactionInternal
                | BitcoinGetSuccessors
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
