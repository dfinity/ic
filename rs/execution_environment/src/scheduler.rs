use crate::{
    canister_manager::{uninstall_canister, AddCanisterChangeToHistory},
    execution_environment::{
        as_num_instructions, as_round_instructions, execute_canister, ExecuteCanisterResult,
        ExecutionEnvironment, RoundInstructions, RoundLimits,
    },
    metrics::MeasurementScope,
    util::process_responses,
};
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SchedulerConfig;
use ic_crypto_prng::{Csprng, RandomnessPurpose::ExecutionThread};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::{
    ExecutionRoundSummary, ExecutionRoundType, RegistryExecutionSettings,
};
use ic_interfaces::execution_environment::{
    IngressHistoryWriter, Scheduler, SubnetAvailableMemory,
};
use ic_logger::{debug, error, fatal, info, new_logger, warn, ReplicaLogger};
use ic_management_canister_types::{CanisterStatusType, MasterPublicKeyId, Method as Ic00Method};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{
    canister_state::{
        execution_state::NextScheduledMethod, system_state::CyclesUseCase, NextExecution,
    },
    num_bytes_try_from,
    page_map::PageAllocatorFileDescriptor,
    CanisterState, CanisterStatus, ExecutionTask, InputQueueType, NetworkTopology, NumWasmPages,
    ReplicatedState,
};
use ic_system_api::InstructionLimits;
use ic_types::{
    consensus::idkg::PreSigId,
    crypto::canister_threshold_sig::MasterPublicKey,
    ingress::{IngressState, IngressStatus},
    messages::{CanisterMessage, Ingress, MessageId, Response, StopCanisterContext, NO_DEADLINE},
    AccumulatedPriority, CanisterId, ComputeAllocation, Cycles, ExecutionRound, LongExecutionMode,
    MemoryAllocation, NumBytes, NumInstructions, NumSlices, Randomness, SubnetId, Time,
    MAX_WASM_MEMORY_IN_BYTES,
};
use ic_types::{nominal_cycles::NominalCycles, NumMessages};
use num_rational::Ratio;
use std::{
    cell::RefCell,
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};
use strum::IntoEnumIterator;

mod scheduler_metrics;
use scheduler_metrics::*;
mod round_schedule;
use crate::util::debug_assert_or_critical_error;
pub use round_schedule::RoundSchedule;
use round_schedule::*;
mod threshold_signatures;
use threshold_signatures::*;

/// Only log potentially spammy messages this often (in rounds). With a block
/// rate around 1.0, this will result in logging about once every 10 minutes.
const SPAMMY_LOG_INTERVAL_ROUNDS: u64 = 10 * 60;

/// Ideally we would split the per-round limit between subnet messages and
/// canister messages, so that their sum cannot exceed the limit. That would
/// make the limit for canister messages variable, which would break assumptions
/// of the scheduling algorithm. The next best thing we can do is to limit
/// subnet messages on top of the fixed limit for canister messages.
/// The value of the limit for subnet messages is chosen quite arbitrarily
/// as 1/16 of the fixed limit. Any other value in the same ballpark would
/// work here.
const SUBNET_MESSAGES_LIMIT_FRACTION: u64 = 16;

#[cfg(test)]
pub(crate) mod test_utilities;
#[cfg(test)]
pub(crate) mod tests;

/// Contains limits (or budget) for various resources that affect duration of
/// an execution round.
#[derive(Clone, Debug, Default)]
struct SchedulerRoundLimits {
    /// Keeps track of remaining instructions in this execution round.
    instructions: RoundInstructions,

    /// Keeps track of remaining instruction to be used by subnet messages in this execution round.
    subnet_instructions: RoundInstructions,

    /// Keeps track of the available storage memory. It decreases if
    /// - Wasm execution grows the Wasm/stable memory.
    /// - Wasm execution pushes a new request to the output queue.
    subnet_available_memory: SubnetAvailableMemory,

    // Keeps track of the compute allocation limit.
    compute_allocation_used: u64,
}

impl SchedulerRoundLimits {
    fn subnet_round_limits(&self) -> RoundLimits {
        RoundLimits {
            instructions: self.subnet_instructions,
            subnet_available_memory: self.subnet_available_memory,
            compute_allocation_used: self.compute_allocation_used,
        }
    }

    fn canister_round_limits(&self) -> RoundLimits {
        RoundLimits {
            instructions: self.instructions,
            subnet_available_memory: self.subnet_available_memory,
            compute_allocation_used: self.compute_allocation_used,
        }
    }

    fn update_subnet_round_limits(&mut self, round_limits: &RoundLimits) {
        self.subnet_instructions = round_limits.instructions;
        self.subnet_available_memory = round_limits.subnet_available_memory;
        self.compute_allocation_used = round_limits.compute_allocation_used;
    }

    pub fn update_canister_round_limits(&mut self, round_limits: &RoundLimits) {
        self.instructions = round_limits.instructions;
        self.subnet_available_memory = round_limits.subnet_available_memory;
        self.compute_allocation_used = round_limits.compute_allocation_used;
    }
}

////////////////////////////////////////////////////////////////////////
/// Scheduler Implementation

pub(crate) struct SchedulerImpl {
    config: SchedulerConfig,
    own_subnet_id: SubnetId,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    exec_env: Arc<ExecutionEnvironment>,
    cycles_account_manager: Arc<CyclesAccountManager>,
    metrics: Arc<SchedulerMetrics>,
    log: ReplicaLogger,
    thread_pool: RefCell<scoped_threadpool::Pool>,
    rate_limiting_of_heap_delta: FlagStatus,
    rate_limiting_of_instructions: FlagStatus,
    deterministic_time_slicing: FlagStatus,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
}

impl SchedulerImpl {
    /// Returns scheduler compute capacity in percent.
    /// For the DTS scheduler, it's `(number of cores - 1) * 100%`
    pub fn compute_capacity_percent(scheduler_cores: usize) -> usize {
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
        logger: &ReplicaLogger,
        scheduler_cores: usize,
        current_round: ExecutionRound,
        accumulated_priority_reset_interval: ExecutionRound,
        canister_states: &mut BTreeMap<CanisterId, CanisterState>,
    ) -> RoundSchedule {
        let number_of_canisters = canister_states.len();

        // Total allocatable compute capacity in percent.
        // As one scheduler core is reserved to guarantee long executions progress,
        // compute capacity is `(scheduler_cores - 1) * 100`
        let compute_capacity_percent = Self::compute_capacity_percent(scheduler_cores) as i64;

        // Sum of all canisters compute allocation in percent.
        // It's guaranteed to be less than `compute_capacity_percent`
        // by `validate_compute_allocation()`.
        // This corresponds to |a| in Scheduler Analysis.
        let mut total_compute_allocation_percent: i64 = 0;

        // Use this multiplier to achieve the following two:
        // 1) The sum of all the values we add to accumulated priorities
        //    to calculate the round priorities must be divisible by the number
        //    of canisters that are given top priority in this round.
        // 2) The free capacity (the difference between `compute_capacity_percent`
        //    and `total_compute_allocation_percent`) can be distributed to all
        //    the canisters evenly.
        // The `max(1)` is the corner case when there are no Canisters.
        let multiplier = (scheduler_cores * number_of_canisters).max(1) as i64;

        // This corresponds to the vector p in the Scheduler Analysis document.
        let mut round_states = Vec::with_capacity(number_of_canisters);

        // Reset the accumulated priorities periodically.
        // We want to reset the scheduler regularly to safely support changes in the set
        // of canisters and their compute allocations.
        let is_reset_round = (current_round.get() % accumulated_priority_reset_interval.get()) == 0;

        // Compute the priority of the canisters for this round.
        let mut accumulated_priority_invariant = AccumulatedPriority::default();
        let mut accumulated_priority_deviation = 0;
        for (&canister_id, canister) in canister_states.iter_mut() {
            if is_reset_round {
                canister.scheduler_state.accumulated_priority = Default::default();
                canister.scheduler_state.priority_credit = Default::default();
            }

            let has_aborted_or_paused_execution =
                canister.has_aborted_execution() || canister.has_paused_execution();
            if !has_aborted_or_paused_execution {
                canister.scheduler_state.long_execution_mode = Default::default();
            }

            let compute_allocation = canister.scheduler_state.compute_allocation;
            let accumulated_priority = canister.scheduler_state.accumulated_priority;
            round_states.push(CanisterRoundState {
                canister_id,
                accumulated_priority,
                compute_allocation,
                long_execution_mode: canister.scheduler_state.long_execution_mode,
                has_aborted_or_paused_execution,
            });

            total_compute_allocation_percent += compute_allocation.as_percent() as i64;
            accumulated_priority_invariant += accumulated_priority;
            accumulated_priority_deviation +=
                accumulated_priority.get() * accumulated_priority.get();
        }
        // Assert there is at least `1%` of free capacity to distribute across canisters.
        // It's guaranteed by `validate_compute_allocation()`
        debug_assert_or_critical_error!(
            total_compute_allocation_percent < compute_capacity_percent,
            self.metrics.scheduler_compute_allocation_invariant_broken,
            logger,
            "{}: Total compute allocation {}% must be less than compute capacity {}%",
            SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN,
            total_compute_allocation_percent,
            compute_capacity_percent
        );
        // Observe accumulated priority metrics
        self.metrics
            .scheduler_accumulated_priority_invariant
            .set(accumulated_priority_invariant.get());
        self.metrics
            .scheduler_accumulated_priority_deviation
            .set((accumulated_priority_deviation as f64 / number_of_canisters as f64).sqrt());

        // Free capacity per canister in multiplied percent.
        // Note, to avoid division by zero when there are no canisters
        // and having `multiplier == number_of_canisters * scheduler_cores`, the
        // `(compute_capacity - total_compute_allocation) * multiplier / number_of_canisters`
        // can be simplified to just
        // `(compute_capacity - total_compute_allocation) * scheduler_cores`
        let free_capacity_per_canister = (compute_capacity_percent
            .saturating_sub(total_compute_allocation_percent))
            * scheduler_cores as i64;

        // Fully divide the free allocation across all canisters.
        let mut long_executions_compute_allocation = 0;
        let mut number_of_long_executions = 0;
        for rs in round_states.iter_mut() {
            // De-facto compute allocation includes bonus allocation
            let factual =
                rs.compute_allocation.as_percent() as i64 * multiplier + free_capacity_per_canister;
            // Increase accumulated priority by de-facto compute allocation.
            rs.accumulated_priority += factual.into();
            // Count long executions and sum up their compute allocation.
            if rs.has_aborted_or_paused_execution {
                // Note: factual compute allocation is multiplied by `multiplier`
                long_executions_compute_allocation += factual;
                number_of_long_executions += 1;
            }
        }

        // Optimization that makes use of accessing a canister state without an extra canister id lookup.
        // IMPORTANT! Optimization relies on the fact that elements in `canister_states` and `round_states` follow in the same order.
        for ((&_, canister), rs) in canister_states.iter_mut().zip(round_states.iter()) {
            debug_assert!(
                canister.canister_id() == rs.canister_id,
                "Elements in canister_states and round_states must follow in the same order",
            );
            // Update canister state with a new accumulated_priority.
            canister.scheduler_state.accumulated_priority = rs.accumulated_priority;

            // Record a canister metric.
            if !canister.has_input() {
                canister
                    .system_state
                    .canister_metrics
                    .skipped_round_due_to_no_messages += 1;
            }
        }

        // Count long execution cores by dividing `long_execution_compute_allocation`
        // by `100%` and rounding up (as one scheduler core is reserved to guarantee
        // long executions progress).
        // Note, the `long_execution_compute_allocation` is in percent multiplied
        // by the `multiplier`.
        let long_execution_cores = ((long_executions_compute_allocation + 100 * multiplier - 1)
            / (100 * multiplier)) as usize;
        // If there are long executions, the `long_execution_cores` must be non-zero.
        debug_assert_or_critical_error!(
            number_of_long_executions == 0 || long_execution_cores > 0,
            self.metrics.scheduler_cores_invariant_broken,
            logger,
            "{}: Number of long execution cores {} must be more than 0",
            SCHEDULER_CORES_INVARIANT_BROKEN,
            long_execution_cores,
        );
        // As one scheduler core is reserved, the `long_execution_cores` is always
        // less than `scheduler_cores`
        debug_assert_or_critical_error!(
            long_execution_cores < scheduler_cores,
            self.metrics.scheduler_cores_invariant_broken,
            logger,
            "{}: Number of long execution cores {} must be less than scheduler cores {}",
            SCHEDULER_CORES_INVARIANT_BROKEN,
            long_execution_cores,
            scheduler_cores
        );

        self.order_canister_round_states(&mut round_states);

        let round_schedule = RoundSchedule::new(
            scheduler_cores,
            long_execution_cores,
            round_states
                .iter()
                .skip(number_of_long_executions)
                .map(|rs| rs.canister_id)
                .collect(),
            round_states
                .iter()
                .take(number_of_long_executions)
                .map(|rs| rs.canister_id)
                .collect(),
        );

        {
            let scheduling_order = round_schedule.scheduling_order();
            let scheduling_order = scheduling_order
                .prioritized_long_canister_ids
                .chain(scheduling_order.new_canister_ids)
                .chain(scheduling_order.opportunistic_long_canister_ids);
            // The number of active scheduler cores is limited by the number
            // of canisters to schedule.
            let active_cores = scheduler_cores.min(number_of_canisters);
            for (i, canister_id) in scheduling_order.take(active_cores).enumerate() {
                let canister_state = canister_states.get_mut(canister_id).unwrap();
                // As top `scheduler_cores` canisters are guaranteed to be scheduled
                // this round, their accumulated priorities must be decreased here
                // by `capacity * multiplier / scheduler_cores`. But instead this
                // value is accumulated in the `priority_credit`, and applied later:
                // * For short executions, the `priority_credit` is deducted from
                //   the `accumulated_priority` at the end of the round.
                // * For long executions, the `priority_credit` is accumulated
                //   for a few rounds, and deducted from the `accumulated_priority`
                //   at the end of the long execution.
                canister_state.scheduler_state.priority_credit +=
                    (compute_capacity_percent * multiplier / active_cores as i64).into();
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
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
        rate_limiting_of_heap_delta: FlagStatus,
        rate_limiting_of_instructions: FlagStatus,
        deterministic_time_slicing: FlagStatus,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
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
            rate_limiting_of_heap_delta,
            rate_limiting_of_instructions,
            deterministic_time_slicing,
            fd_factory,
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
    ) -> ReplicatedState {
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
            ongoing_long_install_code |= state
                .canister_state(canister_id)
                .map_or(false, |canister| canister.has_paused_install_code());

            let round_instructions_executed =
                as_num_instructions(instructions_before - round_limits.instructions);

            let messages = NumMessages::from(message_instructions.map(|_| 1).unwrap_or(0));
            measurement_scope.add(round_instructions_executed, NumSlices::from(1), messages);

            // Break when round limits are reached or found a canister
            // that has a long install code message in progress.
            if round_limits.reached() || ongoing_long_install_code {
                break;
            }
        }
        state
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
        idkg_subnet_public_keys: &BTreeMap<MasterPublicKeyId, MasterPublicKey>,
    ) -> ReplicatedState {
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
                let (new_state, message_instructions) = self.execute_subnet_message(
                    msg,
                    state,
                    csprng,
                    round_limits,
                    registry_settings,
                    measurement_scope,
                    idkg_subnet_public_keys,
                );
                state = new_state;

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

                if round_limits.reached() {
                    break;
                }
            }
        }
        state
    }

    /// Invokes `ExecutionEnvironment` to execute a subnet message.
    fn execute_subnet_message(
        &self,
        msg: CanisterMessage,
        state: ReplicatedState,
        csprng: &mut Csprng,
        round_limits: &mut RoundLimits,
        registry_settings: &RegistryExecutionSettings,
        measurement_scope: &MeasurementScope,
        idkg_subnet_public_keys: &BTreeMap<MasterPublicKeyId, MasterPublicKey>,
    ) -> (ReplicatedState, Option<NumInstructions>) {
        let instruction_limits = get_instructions_limits_for_subnet_message(
            self.deterministic_time_slicing,
            &self.config,
            &msg,
        );

        let instructions_before = round_limits.instructions;
        let (new_state, message_instructions) = self.exec_env.execute_subnet_message(
            msg,
            state,
            instruction_limits,
            csprng,
            idkg_subnet_public_keys,
            registry_settings,
            round_limits,
        );
        let round_instructions_executed =
            as_num_instructions(instructions_before - round_limits.instructions);
        let messages = NumMessages::from(message_instructions.map(|_| 1).unwrap_or(0));
        measurement_scope.add(round_instructions_executed, NumSlices::from(1), messages);
        (new_state, message_instructions)
    }

    /// Invoked in the first iteration of the inner round to add the `Heartbeat`
    /// and `GlobalTimer` tasks that are carried out prior to processing
    /// any input messages.
    /// It also returns the list of canisters that have non-zero priority credit.
    fn initialize_inner_round(
        &self,
        state: &mut ReplicatedState,
    ) -> (BTreeSet<CanisterId>, BTreeSet<CanisterId>) {
        let _timer = self
            .metrics
            .round_inner_heartbeat_overhead_duration
            .start_timer();

        let mut heartbeat_and_timer_canister_ids = BTreeSet::new();
        let mut non_zero_priority_credit_canister_ids = BTreeSet::new();

        let now = state.time();
        for canister in state.canisters_iter_mut() {
            // Remember all non-zero priority_credit canisters to apply it after the round.
            if canister.scheduler_state.priority_credit != AccumulatedPriority::default() {
                non_zero_priority_credit_canister_ids.insert(canister.system_state.canister_id);
            }

            // Add `Heartbeat` or `GlobalTimer` for running canisters only.
            match canister.system_state.status {
                CanisterStatus::Running { .. } => {}
                CanisterStatus::Stopping { .. } | CanisterStatus::Stopped => {
                    continue;
                }
            }

            let may_schedule_heartbeat = canister.exports_heartbeat_method();
            let may_schedule_global_timer = canister.exports_global_timer_method()
                && canister.system_state.global_timer.has_reached_deadline(now);

            if !may_schedule_heartbeat && !may_schedule_global_timer {
                // Canister has no heartbeat and no (schedulable) global timer.
                continue;
            }

            match canister.next_execution() {
                NextExecution::ContinueLong | NextExecution::ContinueInstallCode => {
                    // Do not add a heartbeat task if a long execution
                    // is pending.
                }
                NextExecution::None | NextExecution::StartNew => {
                    for _ in 0..NextScheduledMethod::iter().count() {
                        let method_chosen = is_next_method_chosen(
                            canister,
                            &mut heartbeat_and_timer_canister_ids,
                            may_schedule_heartbeat,
                            may_schedule_global_timer,
                        );

                        canister.inc_next_scheduled_method();

                        if method_chosen {
                            break;
                        }
                    }
                }
            }
        }
        (
            heartbeat_and_timer_canister_ids,
            non_zero_priority_credit_canister_ids,
        )
    }

    /// Performs multiple iterations of canister execution until the instruction
    /// limit per round is reached or the canisters become idle. The canisters
    /// are executed in parallel using the thread pool.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn inner_round<'a>(
        &'a self,
        mut state: ReplicatedState,
        csprng: &mut Csprng,
        round_schedule: &RoundSchedule,
        current_round: ExecutionRound,
        root_measurement_scope: &MeasurementScope<'a>,
        scheduler_round_limits: &mut SchedulerRoundLimits,
        registry_settings: &RegistryExecutionSettings,
        idkg_subnet_public_keys: &BTreeMap<MasterPublicKeyId, MasterPublicKey>,
    ) -> (ReplicatedState, BTreeSet<CanisterId>) {
        let measurement_scope =
            MeasurementScope::nested(&self.metrics.round_inner, root_measurement_scope);
        let mut ingress_execution_results = Vec::new();
        let mut is_first_iteration = true;
        let mut round_filtered_canisters = FilteredCanisters::new();

        let mut total_heap_delta = NumBytes::from(0);

        let mut heartbeat_and_timer_canister_ids = BTreeSet::new();
        let mut non_zero_priority_credit_canister_ids = BTreeSet::new();

        // Start iteration loop:
        //      - Execute subnet messages.
        //      - Execute heartbeat and global timer tasks.
        //      - Execute canisters input messages in parallel.
        //      - Induct messages on the same subnet.
        let mut state = loop {
            // Execute subnet messages.
            // If new messages are inducted into the subnet input queues,
            // they are processed until the subbnet messages' instruction limit is reached.
            {
                let subnet_measurement_scope = MeasurementScope::nested(
                    &self.metrics.round_subnet_queue,
                    root_measurement_scope,
                );

                // TODO(EXC-1517): Improve inner loop preparation.
                let mut ongoing_long_install_code = false;
                let long_running_canister_ids = state
                    .canister_states
                    .iter()
                    .filter_map(|(&canister_id, canister)| match canister.next_execution() {
                        NextExecution::None | NextExecution::StartNew => None,
                        NextExecution::ContinueLong => Some(canister_id),
                        NextExecution::ContinueInstallCode => {
                            ongoing_long_install_code = true;
                            Some(canister_id)
                        }
                    })
                    .collect();

                let mut subnet_round_limits = scheduler_round_limits.subnet_round_limits();
                if !subnet_round_limits.reached() {
                    state = self.drain_subnet_queues(
                        state,
                        csprng,
                        &mut subnet_round_limits,
                        &subnet_measurement_scope,
                        ongoing_long_install_code,
                        long_running_canister_ids,
                        registry_settings,
                        idkg_subnet_public_keys,
                    );
                    scheduler_round_limits.update_subnet_round_limits(&subnet_round_limits);
                }
            }

            let measurement_scope =
                MeasurementScope::nested(&self.metrics.round_inner_iteration, &measurement_scope);
            let mut round_limits = scheduler_round_limits.canister_round_limits();
            let preparation_timer = self.metrics.round_inner_iteration_prep.start_timer();

            // Add `Heartbeat` and `GlobalTimer` tasks to be executed before input messages.
            if is_first_iteration {
                (
                    heartbeat_and_timer_canister_ids,
                    non_zero_priority_credit_canister_ids,
                ) = self.initialize_inner_round(&mut state)
            }

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

            let execution_timer = self.metrics.round_inner_iteration_exe.start_timer();
            let instructions_before = round_limits.instructions;
            let (executed_canisters, mut loop_ingress_execution_results, heap_delta) = self
                .execute_canisters_in_inner_round(
                    active_canisters_partitioned_by_cores,
                    current_round,
                    state.time(),
                    Arc::new(state.metadata.network_topology.clone()),
                    &measurement_scope,
                    &mut round_limits,
                    registry_settings.subnet_size,
                );
            let instructions_consumed = instructions_before - round_limits.instructions;
            drop(execution_timer);

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
            scheduler_round_limits.update_canister_round_limits(&round_limits);

            if instructions_consumed == RoundInstructions::from(0) {
                break state;
            } else {
                self.metrics
                    .inner_loop_consumed_non_zero_instructions_count
                    .inc();
            }

            if round_limits.reached() {
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
            // Remove all remaining `Heartbeat`, `GlobalTimer`, and `OnLowWasmMemory` tasks
            // because they will be added again in the next round.
            for canister_id in &heartbeat_and_timer_canister_ids {
                let canister = state.canister_state_mut(canister_id).unwrap();
                canister.system_state.task_queue.retain(|task| match task {
                    ExecutionTask::Heartbeat
                    | ExecutionTask::GlobalTimer
                    | ExecutionTask::OnLowWasmMemory => false,
                    ExecutionTask::PausedExecution { .. }
                    | ExecutionTask::PausedInstallCode(..)
                    | ExecutionTask::AbortedExecution { .. }
                    | ExecutionTask::AbortedInstallCode { .. } => true,
                });
            }
            // Apply priority credit for all the finished executions.
            for canister_id in &non_zero_priority_credit_canister_ids {
                let canister = state.canister_state_mut(canister_id).unwrap();
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
        if round_limits.reached() {
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

        // Distribute subnet available memory equally between the threads.
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

    fn purge_expired_ingress_messages(&self, state: &mut ReplicatedState) {
        let current_time = state.time();
        let not_expired_yet = |ingress: &Arc<Ingress>| ingress.expiry_time >= current_time;
        let mut expired_ingress_messages =
            state.filter_subnet_queues_ingress_messages(not_expired_yet);
        let mut canisters = state.take_canister_states();
        for canister in canisters.values_mut() {
            expired_ingress_messages.extend(
                canister
                    .system_state
                    .filter_ingress_messages(not_expired_yet),
            );
        }
        for ingress in expired_ingress_messages.iter() {
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
        let mut uninstalled_canisters = Vec::new();
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
                    uninstalled_canisters.push(canister.canister_id());
                    all_rejects.push(uninstall_canister(
                        &self.log,
                        canister,
                        state_time,
                        AddCanisterChangeToHistory::No,
                        Arc::clone(&self.fd_factory),
                    ));
                    canister.scheduler_state.compute_allocation = ComputeAllocation::zero();
                    canister.system_state.memory_allocation = MemoryAllocation::BestEffort;
                    canister.system_state.clear_canister_history();
                    // Burn the remaining balance of the canister.
                    canister.system_state.burn_remaining_balance_for_uninstall();

                    info!(
                        self.log,
                        "Uninstalling canister {} because it ran out of cycles",
                        canister.canister_id()
                    );
                    self.metrics.num_canisters_uninstalled_out_of_cycles.inc();
                }
            }
        }

        // Delete any snapshots associated with the canister
        // that ran out of cycles.
        for canister_id in uninstalled_canisters {
            state.canister_snapshots.delete_snapshots(canister_id);
        }

        // Send rejects to any requests that were forcibly closed while uninstalling.
        for rejects in all_rejects.into_iter() {
            process_responses(
                rejects,
                state,
                Arc::clone(&self.ingress_history_writer),
                self.log.clone(),
                self.exec_env.canister_not_found_error(),
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
        let mut subnet_available_memory = self.exec_env.subnet_available_message_memory(state);

        let mut canisters = state.take_canister_states();

        // Get a list of canisters in the map before we iterate over the map.
        // This is because we cannot hold an immutable reference to the map
        // while trying to simultaneously mutate it.
        let canisters_with_outputs: Vec<CanisterId> = canisters
            .iter()
            .filter(|(_, canister)| canister.has_output())
            .map(|(canister_id, _)| *canister_id)
            .collect();

        let mut inducted_messages_to_self = 0;
        let mut inducted_messages_to_others = 0;
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

            let messages_before_induction = source_canister
                .system_state
                .queues()
                .output_queues_message_count();
            source_canister.induct_messages_to_self(
                &mut subnet_available_memory,
                state.metadata.own_subnet_type,
            );
            let messages_after_induction = source_canister
                .system_state
                .queues()
                .output_queues_message_count();
            inducted_messages_to_self +=
                messages_before_induction.saturating_sub(messages_after_induction);

            let messages_before_induction = source_canister
                .system_state
                .queues()
                .output_queues_message_count();
            source_canister
                .system_state
                .output_queues_for_each(|canister_id, msg| match canisters.get_mut(canister_id) {
                    Some(dest_canister) => dest_canister
                        .push_input(
                            (*msg).clone(),
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
            let messages_after_induction = source_canister
                .system_state
                .queues()
                .output_queues_message_count();
            inducted_messages_to_others +=
                messages_before_induction.saturating_sub(messages_after_induction);
            canisters.insert(source_canister_id, source_canister);
        }
        state.put_canister_states(canisters);
        self.metrics
            .inducted_messages
            .with_label_values(&["self"])
            .inc_by(inducted_messages_to_self as u64);
        self.metrics
            .inducted_messages
            .with_label_values(&["others"])
            .inc_by(inducted_messages_to_others as u64);
    }

    /// Iterates through the provided canisters and checks if the invariants are still valid.
    ///
    /// Returns `true` if all canisters are valid, `false` otherwise.
    fn check_canister_invariants(
        &self,
        round_log: &ReplicaLogger,
        current_round: &ExecutionRound,
        state: &ReplicatedState,
        canister_ids: &BTreeSet<CanisterId>,
    ) -> bool {
        for canister_id in canister_ids {
            let canister = state.canister_states.get(canister_id).unwrap();
            if let Err(err) = canister.check_invariants(self.exec_env.max_canister_memory_size()) {
                let msg = format!(
                    "{}: At Round {} @ time {}, canister {} has invalid state after execution. Invariant check failed with err: {}",
                    CANISTER_INVARIANT_BROKEN,
                    current_round,
                    state.time(),
                    canister_id,
                    err
                );

                // Crash in debug mode if any invariant fails.
                debug_assert!(false, "{}", msg);

                self.metrics.canister_invariants.inc();
                warn!(round_log, "{}", msg);
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
                        accumulated_priority: canister.scheduler_state.accumulated_priority,
                        compute_allocation: Default::default(), // not used
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

    /// Code that must be executed unconditionally after each round.
    fn finish_round(&self, state: &mut ReplicatedState, current_round_type: ExecutionRoundType) {
        match current_round_type {
            ExecutionRoundType::CheckpointRound => {
                state.metadata.heap_delta_estimate = NumBytes::from(0);
                // The set of compiled Wasms must be cleared when taking a
                // checkpoint to keep it in sync with the protobuf serialization
                // of `ReplicatedState` which doesn't store this field.
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
        self.initialize_wasm_memory_limit(state);
        self.check_dts_invariants(state, current_round_type);
    }

    fn initialize_wasm_memory_limit(&self, state: &mut ReplicatedState) {
        fn compute_default_wasm_memory_limit(default: NumBytes, usage: NumBytes) -> NumBytes {
            // Returns the larger of the two:
            // - the default value
            // - the average between the current usage and the hard limit.
            default.max(NumBytes::new(
                MAX_WASM_MEMORY_IN_BYTES.saturating_add(usage.get()) / 2,
            ))
        }

        let default_wasm_memory_limit = self.exec_env.default_wasm_memory_limit();
        for (_id, canister) in state.canister_states.iter_mut() {
            if canister.system_state.wasm_memory_limit.is_none() {
                let num_wasm_pages = canister
                    .execution_state
                    .as_ref()
                    .map_or_else(|| NumWasmPages::new(0), |es| es.wasm_memory.size);
                if let Ok(wasm_memory_usage) = num_bytes_try_from(num_wasm_pages) {
                    canister.system_state.wasm_memory_limit =
                        Some(compute_default_wasm_memory_limit(
                            default_wasm_memory_limit,
                            wasm_memory_usage,
                        ));
                }
            }
        }
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

        // 1. Heartbeat, GlobalTimer, and OnLowWasmMemory tasks exist only during the round
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
                    // TODO [EXC-1666]
                    // For now, since OnLowWasmMemory is not used we will copy behaviour similar
                    // to Heartbeat and GlobalTimer, but when the feature is implemented we will
                    // come back to it, to revisit if we should keep it after the round ends.
                    ExecutionTask::OnLowWasmMemory => {
                        panic!(
                            "Unexpected on low wasm memory task after a round in canister {:?}",
                            id
                        );
                    }
                    ExecutionTask::PausedExecution { .. } | ExecutionTask::PausedInstallCode(_) => {
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

            // There should be at most one paused or aborted task left in the task queue.
            assert!(
                canister.system_state.task_queue.len() <= 1,
                "Unexpected tasks left in the task queue of canister {} after a round in canister {:?}",
                id, canister.system_state.task_queue
            );
        }
    }
}

impl Scheduler for SchedulerImpl {
    type State = ReplicatedState;

    fn execute_round(
        &self,
        mut state: ReplicatedState,
        randomness: Randomness,
        idkg_subnet_public_keys: BTreeMap<MasterPublicKeyId, MasterPublicKey>,
        idkg_pre_signature_ids: BTreeMap<MasterPublicKeyId, BTreeSet<PreSigId>>,
        current_round: ExecutionRound,
        round_summary: Option<ExecutionRoundSummary>,
        current_round_type: ExecutionRoundType,
        registry_settings: &RegistryExecutionSettings,
    ) -> ReplicatedState {
        // IMPORTANT!
        // When making changes to this method, please make sure each piece of code is covered by duration metrics.
        // The goal is to ensure that we can track the performance of `execute_round` and its individual components.
        let root_measurement_scope = MeasurementScope::root(&self.metrics.round);

        let round_log;
        let mut csprng;
        let long_running_canister_ids: BTreeSet<_>;

        // Round preparation.
        let mut scheduler_round_limits = {
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

            // Check if any of the long-running canisters has a paused
            // execution. Note that a long-running canister has either
            // a paused execution or an aborted execution.
            let has_any_paused_execution = long_running_canister_ids.iter().any(|canister_id| {
                state
                    .canister_state(canister_id)
                    .map(|canister| {
                        canister.has_paused_execution() || canister.has_paused_install_code()
                    })
                    .unwrap_or(false)
            });

            if !has_any_paused_execution {
                // It is possible that the replica has abandoned the replicated
                // state with paused executions and switched to a new replicated
                // state that was obtained via the state sync.
                // In such a case we need to abort all paused executions to avoid
                // deadlocking the round execution.
                self.exec_env.abandon_paused_executions();
            }

            {
                let _timer = self.metrics.round_preparation_ingress.start_timer();
                self.purge_expired_ingress_messages(&mut state);
            }

            // In the future, subnet messages might be executed in threads. In
            // that case each thread will need its own Csprng instance which
            // is initialized with a distinct "ExecutionThread". Otherwise,
            // two Csprng instances that are initialized with the same Randomness
            // and ExecutionThread would reveal the same bytes and break the
            // guarantees that we provide for raw_rand method of the virtual canister.
            //
            // Currently subnet messages are still executed in a single thread so
            // passing the number of scheduler cores is ok. It would need to be
            // updated in case the execution of subnet messages is running across
            // many threads to ensure a unique execution thread id.
            csprng = Csprng::from_seed_and_purpose(
                &randomness,
                &ExecutionThread(self.config.scheduler_cores as u32),
            );

            // TODO(EXC-1124): Re-enable once the cycle balance check is fixed.
            // for canister in state.canisters_iter_mut() {
            //     cycles_in_sum += canister.system_state.balance();
            //     cycles_in_sum += canister.system_state.queues().input_queue_cycles();
            // }

            // Set the round limits used when executing canister messages.
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
            let round_instructions = as_round_instructions(self.config.max_instructions_per_round)
                - as_round_instructions(max_instructions_per_slice)
                + RoundInstructions::from(1);

            SchedulerRoundLimits {
                instructions: round_instructions,
                subnet_instructions: as_round_instructions(
                    self.config.max_instructions_per_round / SUBNET_MESSAGES_LIMIT_FRACTION,
                ),
                subnet_available_memory: self.exec_env.subnet_available_memory(&state),
                compute_allocation_used: state.total_compute_allocation(),
            }
        };

        // Execute subnet messages.
        {
            // Drain the consensus queue.
            let measurement_scope = MeasurementScope::nested(
                &self.metrics.round_consensus_queue,
                &root_measurement_scope,
            );
            let mut subnet_round_limits = scheduler_round_limits.subnet_round_limits();

            // The consensus queue has to be emptied in each round, so we process
            // it fully without applying the per-round instruction limit.
            // For now, we assume all subnet messages need the entire replicated
            // state. That can be changed in the future as we optimize scheduling.
            while let Some(response) = state.consensus_queue.pop() {
                let (new_state, _) = self.execute_subnet_message(
                    // Wrap the callback ID and payload into a Response, to make it easier for
                    // `execute_subnet_message()` to deal with. All other fields will be ignored by
                    // `execute_subnet_message()`.
                    CanisterMessage::Response(
                        Response {
                            originator: CanisterId::ic_00(),
                            respondent: CanisterId::ic_00(),
                            originator_reply_callback: response.callback,
                            refund: Cycles::zero(),
                            response_payload: response.payload,
                            deadline: NO_DEADLINE,
                        }
                        .into(),
                    ),
                    state,
                    &mut csprng,
                    &mut subnet_round_limits,
                    registry_settings,
                    &measurement_scope,
                    &idkg_subnet_public_keys,
                );
                state = new_state;
            }
            scheduler_round_limits.update_subnet_round_limits(&subnet_round_limits);

            let scheduled_heap_delta_limit = scheduled_heap_delta_limit(
                current_round,
                round_summary,
                self.config.subnet_heap_delta_capacity,
                self.config.heap_delta_initial_reserve,
            );
            if state.metadata.heap_delta_estimate >= scheduled_heap_delta_limit {
                warn!(
                    round_log,
                    "At Round {} @ time {}, current heap delta estimate {} \
                        exceeds scheduled limit {} out of {}, so not executing any messages.",
                    current_round,
                    state.time(),
                    state.metadata.heap_delta_estimate,
                    scheduled_heap_delta_limit,
                    self.config.subnet_heap_delta_capacity,
                );
                self.finish_round(&mut state, current_round_type);
                self.metrics
                    .round_skipped_due_to_current_heap_delta_above_limit
                    .inc();
                return state;
            }
        }

        // Execute postponed `raw_rand` subnet messages.
        {
            // Drain the queue holding postponed `raw_rand`` queue.
            let measurement_scope = MeasurementScope::nested(
                &self.metrics.round_postponed_raw_rand_queue,
                &root_measurement_scope,
            );
            let mut subnet_round_limits = scheduler_round_limits.subnet_round_limits();

            // Each round, we check for any postponed `raw_rand` requests.
            // If found, they are processed immediately. Raw rand is not
            // consuming instructions, so all existing raw_rand requests
            // will be processed.
            while let Some(raw_rand_context) = state
                .metadata
                .subnet_call_context_manager
                .raw_rand_contexts
                .pop_front()
            {
                debug_assert!(raw_rand_context.execution_round_id < current_round);
                let (new_state, _) = self.execute_subnet_message(
                    CanisterMessage::Request(raw_rand_context.request.into()),
                    state,
                    &mut csprng,
                    &mut subnet_round_limits,
                    registry_settings,
                    &measurement_scope,
                    &idkg_subnet_public_keys,
                );
                state = new_state;
            }
            scheduler_round_limits.update_subnet_round_limits(&subnet_round_limits);
        }

        // Subnet queues: execute long running install code call if present.
        {
            let measurement_scope = MeasurementScope::nested(
                &self.metrics.round_advance_long_install_code,
                &root_measurement_scope,
            );

            let mut subnet_round_limits = scheduler_round_limits.subnet_round_limits();
            state = self.advance_long_running_install_code(
                state,
                &mut subnet_round_limits,
                &long_running_canister_ids,
                &measurement_scope,
                registry_settings.subnet_size,
            );

            // If we have executed a long-running install code above, then it is
            // very likely that `round_limits.instructions <= 0` at this point.
            // However, we would like to make progress with other subnet
            // messages that do not consume instructions. To allow that, we set
            // the number available instructions to 1 if it is not positive.
            subnet_round_limits.instructions = subnet_round_limits
                .instructions
                .max(RoundInstructions::from(1));
            scheduler_round_limits.update_subnet_round_limits(&subnet_round_limits);
        };

        // Scheduling.
        let round_schedule = {
            let _timer = self.metrics.round_scheduling_duration.start_timer();

            let mut canisters = state.take_canister_states();
            let round_schedule_candidate = self.apply_scheduling_strategy(
                &round_log,
                self.config.scheduler_cores,
                current_round,
                self.config.accumulated_priority_reset_interval,
                &mut canisters,
            );
            state.put_canister_states(canisters);
            round_schedule_candidate
        };

        // Inner round.
        let (mut state, active_canister_ids) = self.inner_round(
            state,
            &mut csprng,
            &round_schedule,
            current_round,
            &root_measurement_scope,
            &mut scheduler_round_limits,
            registry_settings,
            &idkg_subnet_public_keys,
        );

        // Update [`SignWithThresholdContext`]s by assigning randomness and matching pre-signatures.
        {
            let contexts = state
                .metadata
                .subnet_call_context_manager
                .sign_with_threshold_contexts
                .values_mut()
                .collect();

            update_signature_request_contexts(
                current_round,
                idkg_pre_signature_ids,
                contexts,
                &mut csprng,
                registry_settings,
                self.metrics.as_ref(),
            );
        }

        // Finalization.
        {
            let _timer = self.metrics.round_finalization_duration.start_timer();

            let mut final_state;
            {
                let mut total_canister_balance = Cycles::zero();
                let mut total_canister_reserved_balance = Cycles::zero();
                let mut total_canister_history_memory_usage = NumBytes::new(0);
                let mut total_canister_memory_usage = NumBytes::new(0);
                for canister in state.canisters_iter_mut() {
                    let heap_delta_debit = canister.scheduler_state.heap_delta_debit.get();
                    self.metrics
                        .canister_heap_delta_debits
                        .observe(heap_delta_debit as f64);
                    canister.scheduler_state.heap_delta_debit =
                        match self.rate_limiting_of_heap_delta {
                            FlagStatus::Enabled => NumBytes::from(
                                heap_delta_debit
                                    .saturating_sub(self.config.heap_delta_rate_limit.get()),
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
                    self.metrics
                        .canister_log_memory_usage
                        .observe(canister.system_state.canister_log.used_space() as f64);
                    total_canister_history_memory_usage += canister.canister_history_memory_usage();
                    total_canister_memory_usage += canister.memory_usage();
                    total_canister_balance += canister.system_state.balance();
                    total_canister_reserved_balance += canister.system_state.reserved_balance();

                    // TODO(EXC-1124): Re-enable once the cycle balance check is fixed.
                    // cycles_out_sum += canister.system_state.queues().output_queue_cycles();
                }
                // TODO(EXC-1124): Re-enable once the cycle balance check is fixed.
                // cycles_out_sum += total_canister_balance;

                self.metrics
                    .total_canister_balance
                    .set(total_canister_balance.get() as f64);

                self.metrics
                    .total_canister_reserved_balance
                    .set(total_canister_reserved_balance.get() as f64);

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
                // We allow `total_canister_memory_usage` to exceed the subnet memory capacity
                // by `total_canister_history_memory_usage` because the canister history
                // memory usage is not tracked during a round in `SubnetAvailableMemory`.
                if total_canister_memory_usage
                    > self.exec_env.subnet_memory_capacity() + total_canister_history_memory_usage
                {
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
                    final_state = self.exec_env.process_stopping_canisters(state);
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
                .metadata
                .subnet_metrics
                .update_transactions_total += root_measurement_scope.messages().get();
            final_state.metadata.subnet_metrics.num_canisters =
                final_state.canister_states.len() as u64;
            final_state
        }
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
///
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
        if round_limits.reached() || total_heap_delta >= config.max_heap_delta_per_iteration {
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

            if round_limits.reached() {
                canister
                    .system_state
                    .canister_metrics
                    .interrupted_during_execution += 1;
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
                as_round_instructions(config.instruction_overhead_per_execution);
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
        round_limits.instructions -=
            as_round_instructions(config.instruction_overhead_per_canister);
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
    let mut consumed_cycles_total_by_use_case = BTreeMap::new();

    let mut ingress_queue_message_count = 0;
    let mut ingress_queue_size_bytes = 0;
    let mut input_queues_message_count = 0;
    let mut input_queues_size_bytes = 0;
    let mut queues_response_bytes = 0;
    let mut queues_memory_reservations = 0;
    let mut queues_oversized_requests_extra_bytes = 0;
    let mut canisters_not_in_routing_table = 0;
    let mut canisters_with_old_open_call_contexts = 0;
    let mut old_call_contexts_count = 0;
    let mut num_stop_canister_calls_without_call_id = 0;

    let canister_id_ranges = state.routing_table().ranges(own_subnet_id);
    state.canisters_iter().for_each(|canister| {
        match &canister.system_state.status {
            CanisterStatus::Running { .. } => num_running_canisters += 1,
            CanisterStatus::Stopping { stop_contexts, .. } => {
                num_stopping_canisters += 1;
                // TODO(EXC-1466): Remove once all calls have `call_id` present.
                let stop_contexts_with_missing_call_id: Vec<&StopCanisterContext> = stop_contexts
                    .iter()
                    .take_while(|stop_context| stop_context.call_id().is_none())
                    .collect();
                num_stop_canister_calls_without_call_id += stop_contexts_with_missing_call_id.len();
            }
            CanisterStatus::Stopped { .. } => num_stopped_canisters += 1,
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
        consumed_cycles_total += canister.system_state.canister_metrics.consumed_cycles;
        join_consumed_cycles_by_use_case(
            &mut consumed_cycles_total_by_use_case,
            canister
                .system_state
                .canister_metrics
                .get_consumed_cycles_by_use_cases(),
        );
        let queues = canister.system_state.queues();
        ingress_queue_message_count += queues.ingress_queue_message_count();
        ingress_queue_size_bytes += queues.ingress_queue_size_bytes();
        input_queues_message_count += queues.input_queues_message_count();
        input_queues_size_bytes += queues.input_queues_size_bytes();
        queues_response_bytes += queues.guaranteed_responses_size_bytes();
        queues_memory_reservations += queues.guaranteed_response_memory_reservations();
        queues_oversized_requests_extra_bytes += queues.oversized_guaranteed_requests_extra_bytes();
        if !canister_id_ranges.contains(&canister.canister_id()) {
            canisters_not_in_routing_table += 1;
        }
        if let Some(manager) = canister.system_state.call_context_manager() {
            let old_call_contexts =
                manager.call_contexts_older_than(state.time(), OLD_CALL_CONTEXT_CUTOFF_ONE_DAY);
            // Log all old call contexts, but not (nearly) every round.
            if current_round.get() % SPAMMY_LOG_INTERVAL_ROUNDS == 0 {
                for (origin, origin_time) in &old_call_contexts {
                    warn!(
                        logger,
                        "Call context on canister {} with origin {:?} has been open for {:?}",
                        canister.canister_id(),
                        origin,
                        state.time().saturating_duration_since(*origin_time),
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

    metrics.observe_consumed_cycles(consumed_cycles_total);

    metrics.observe_consumed_cycles_by_use_case(&consumed_cycles_total_by_use_case);

    for (key_id, count) in &state.metadata.subnet_metrics.threshold_signature_agreements {
        metrics
            .threshold_signature_agreements
            .with_label_values(&[&key_id.to_string()])
            .set(*count as i64);
    }

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
    metrics.observe_queues_memory_reservations(queues_memory_reservations);
    metrics.observe_oversized_requests_extra_bytes(queues_oversized_requests_extra_bytes);
    metrics.observe_streams_response_bytes(streams_response_bytes);

    metrics
        .ingress_history_length
        .set(state.metadata.ingress_history.len() as i64);
    metrics
        .canisters_not_in_routing_table
        .set(canisters_not_in_routing_table);
    metrics
        .stop_canister_calls_without_call_id
        .set(num_stop_canister_calls_without_call_id as i64);
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

/// Helper function that checks if a message can be executed:
///     1. A message cannot be executed if it is directed to a canister
///     with another long-running execution in progress.
///     2. Install code messages can only be executed sequentially.
fn can_execute_msg(
    msg: &CanisterMessage,
    ongoing_long_install_code: bool,
    long_running_canister_ids: &BTreeSet<CanisterId>,
) -> bool {
    if let Some(effective_canister_id) = msg.effective_canister_id() {
        if long_running_canister_ids.contains(&effective_canister_id) {
            return false;
        }
    }

    if ongoing_long_install_code {
        let maybe_install_code_method = match msg {
            CanisterMessage::Ingress(ingress) => {
                Ic00Method::from_str(ingress.method_name.as_str()).ok()
            }
            CanisterMessage::Request(request) => {
                Ic00Method::from_str(request.method_name.as_str()).ok()
            }
            CanisterMessage::Response(_) => None,
        };

        // Only one install code message allowed at a time.
        match maybe_install_code_method {
            Some(Ic00Method::InstallCode) | Some(Ic00Method::InstallChunkedCode) => return false,
            _ => {}
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
    msg: &CanisterMessage,
) -> InstructionLimits {
    let default_limits = InstructionLimits::new(
        FlagStatus::Disabled,
        config.max_instructions_per_message_without_dts,
        config.max_instructions_per_message_without_dts,
    );
    let method_name = match &msg {
        CanisterMessage::Response(_) => {
            return default_limits;
        }
        CanisterMessage::Ingress(ingress) => &ingress.method_name,
        CanisterMessage::Request(request) => &request.method_name,
    };

    use Ic00Method::*;
    match Ic00Method::from_str(method_name) {
        Ok(method) => match method {
            CanisterStatus
            | CanisterInfo
            | CreateCanister
            | DeleteCanister
            | DepositCycles
            | ECDSAPublicKey
            | RawRand
            | HttpRequest
            | SetupInitialDKG
            | SignWithECDSA
            | ComputeInitialIDkgDealings
            | SchnorrPublicKey
            | SignWithSchnorr
            | StartCanister
            | StopCanister
            | UninstallCode
            | UpdateSettings
            | BitcoinGetBalance
            | BitcoinGetUtxos
            | BitcoinGetBlockHeaders
            | BitcoinSendTransaction
            | BitcoinSendTransactionInternal
            | BitcoinGetCurrentFeePercentiles
            | BitcoinGetSuccessors
            | NodeMetricsHistory
            | FetchCanisterLogs
            | ProvisionalCreateCanisterWithCycles
            | ProvisionalTopUpCanister
            | UploadChunk
            | StoredChunks
            | ClearChunkStore
            | TakeCanisterSnapshot
            | LoadCanisterSnapshot
            | ListCanisterSnapshots
            | DeleteCanisterSnapshot => default_limits,
            InstallCode | InstallChunkedCode => InstructionLimits::new(
                dts,
                config.max_instructions_per_install_code,
                config.max_instructions_per_install_code_slice,
            ),
        },
        Err(_) => default_limits,
    }
}

/// If the next execution method (`Message`, `Heartbeat` or `GlobalTimer) may be
/// scheduled, it is added to the front of the canister's task queue, the
/// canister ID is added to `heartbeat_and_timer_canister_ids` and `true` is
/// returned. Otherwise, no mutations are made and `false` is returned.
///
/// If either `Heartbeat` or `GlobalTimer` is enqueued, then the other one is
/// also enqueued in the second position, if it may be scheduled.
fn is_next_method_chosen(
    canister: &mut CanisterState,
    heartbeat_and_timer_canister_ids: &mut BTreeSet<CanisterId>,
    may_schedule_heartbeat: bool,
    may_schedule_global_timer: bool,
) -> bool {
    match canister.get_next_scheduled_method() {
        NextScheduledMethod::Message => canister.has_input(),

        NextScheduledMethod::Heartbeat => {
            if may_schedule_heartbeat {
                enqueue_tasks(
                    ExecutionTask::Heartbeat,
                    may_schedule_global_timer.then_some(ExecutionTask::GlobalTimer),
                    canister,
                );
                heartbeat_and_timer_canister_ids.insert(canister.canister_id());
            }
            may_schedule_heartbeat
        }

        NextScheduledMethod::GlobalTimer => {
            if may_schedule_global_timer {
                enqueue_tasks(
                    ExecutionTask::GlobalTimer,
                    may_schedule_heartbeat.then_some(ExecutionTask::Heartbeat),
                    canister,
                );
                heartbeat_and_timer_canister_ids.insert(canister.canister_id());
            }
            may_schedule_global_timer
        }
    }
}

/// Enqueues `task` (optionally followed by `other_task`) at the front of
/// `canister`'s task queue.
fn enqueue_tasks(
    task: ExecutionTask,
    other_task: Option<ExecutionTask>,
    canister: &mut CanisterState,
) {
    // If the conditions for the 'other_task' are satisfied, then we are
    // adding it as well, because we want to execute as many tasks as
    // possible on the single canister to avoid context switching.
    // We first push the 'other_task' to the front of the queue and then
    // in front of it 'task' so that 'task' is executed first.
    if let Some(other_task) = other_task {
        canister.system_state.task_queue.push_front(other_task);
    }

    canister.system_state.task_queue.push_front(task);
}

/// Estimates the heap delta limit for the given round based on the maximum
/// heap delta limit and the number of rounds between checkpoints.
///
/// The scheduler decides whether to execute the current round or not based on
/// the result of this function. The purpose of this function is to distribute
/// the heap delta budget equally over all rounds in order to make execution of
/// rounds more smooth.
///
/// Note that this function computes a heuristic, so any positive number
/// not exceeding the maximum heap delta limit would be a valid result.
/// The result should be reasonably large to ensure faster progress.
fn scheduled_heap_delta_limit(
    current_round: ExecutionRound,
    round_summary: Option<ExecutionRoundSummary>,
    subnet_heap_delta_capacity: NumBytes,
    heap_delta_initial_reserve: NumBytes,
) -> NumBytes {
    let Some(round_summary) = round_summary else {
        // This should happen only in tests.
        return subnet_heap_delta_capacity;
    };
    let next_checkpoint_round = round_summary.next_checkpoint_round;
    // Plus one is because the interval length is normally 499, not 500.
    let current_interval_length = round_summary
        .current_interval_length
        .get()
        .saturating_add(1);
    let remaining_rounds = next_checkpoint_round
        .get()
        .saturating_sub(current_round.get());

    // The initial reserve is always available, so it should not be scaled.
    let heap_delta_capacity_minus_initial_reserve = subnet_heap_delta_capacity
        .get()
        .saturating_sub(heap_delta_initial_reserve.get());
    // The rest of the heap delta capacity is distributed across remaining rounds.
    let remaining_rounds = remaining_rounds.min(current_interval_length);
    let remaining_heap_delta_reserve = heap_delta_capacity_minus_initial_reserve
        .saturating_mul(remaining_rounds)
        .saturating_div(current_interval_length);

    // The scheduled limit is the capacity minus reserve for the remaining rounds.
    subnet_heap_delta_capacity
        .get()
        .saturating_sub(remaining_heap_delta_reserve)
        .into()
}
