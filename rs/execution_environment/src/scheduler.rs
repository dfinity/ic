use crate::{
    canister_manager::uninstall_canister,
    execution_environment::{
        ExecuteCanisterResult, ExecutionEnvironment, RoundInstructions, RoundLimits,
        as_num_instructions, as_round_instructions, execute_canister,
    },
    ic00_permissions::Ic00MethodPermissions,
    metrics::MeasurementScope,
    util::process_responses,
};
use ic_config::embedders::Config as HypervisorConfig;
use ic_config::execution_environment::LOG_MEMORY_STORE_FEATURE_ENABLED;
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SchedulerConfig;
use ic_crypto_prng::{Csprng, RandomnessPurpose::ExecutionThread};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::wasmtime_embedder::system_api::InstructionLimits;
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::{
    ExecutionRoundSummary, ExecutionRoundType, RegistryExecutionSettings,
};
use ic_interfaces::execution_environment::{
    IngressHistoryWriter, Scheduler, SubnetAvailableMemory,
};
use ic_logger::{ReplicaLogger, debug, error, fatal, info, new_logger, warn};
use ic_management_canister_types_private::{
    CanisterStatusType, MasterPublicKeyId, Method as Ic00Method,
};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::{
    CallOrigin, CanisterState, CanisterStatus, ExecutionTask, InputQueueType, NetworkTopology,
    ReplicatedState,
    canister_state::{
        NextExecution, execution_state::NextScheduledMethod, system_state::CyclesUseCase,
    },
    page_map::PageAllocatorFileDescriptor,
};
use ic_types::{
    CanisterId, ComputeAllocation, Cycles, ExecutionRound, MemoryAllocation, NumBytes,
    NumInstructions, NumSlices, PrincipalId, Randomness, ReplicaVersion, SubnetId, Time,
    batch::{CanisterCyclesCostSchedule, ChainKeyData},
    ingress::{IngressState, IngressStatus},
    messages::{Ingress, MessageId, NO_DEADLINE, Response, SubnetMessage},
};
use ic_types::{NumMessages, nominal_cycles::NominalCycles};
use more_asserts::{debug_assert_ge, debug_assert_le, debug_assert_lt};
use num_rational::Ratio;
use prometheus::Histogram;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};
use strum::IntoEnumIterator;

pub mod scheduler_metrics;
use scheduler_metrics::*;
mod round_schedule;
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

    /// Keeps track of the number of outgoing calls that can still be made across
    /// the subnet before canisters are limited to their own callback quota only.
    subnet_available_callbacks: i64,

    /// Keeps track of the compute allocation limit.
    compute_allocation_used: u64,

    /// Keeps track of the memory reserved for executing response handlers.
    subnet_memory_reservation: NumBytes,
}

impl SchedulerRoundLimits {
    fn subnet_round_limits(&self) -> RoundLimits {
        RoundLimits {
            instructions: self.subnet_instructions,
            subnet_available_memory: self.subnet_available_memory,
            subnet_available_callbacks: self.subnet_available_callbacks,
            compute_allocation_used: self.compute_allocation_used,
            subnet_memory_reservation: self.subnet_memory_reservation,
        }
    }

    fn canister_round_limits(&self) -> RoundLimits {
        RoundLimits {
            instructions: self.instructions,
            subnet_available_memory: self.subnet_available_memory,
            subnet_available_callbacks: self.subnet_available_callbacks,
            compute_allocation_used: self.compute_allocation_used,
            subnet_memory_reservation: self.subnet_memory_reservation,
        }
    }

    fn update_subnet_round_limits(&mut self, round_limits: &RoundLimits) {
        self.subnet_instructions = round_limits.instructions;
        self.subnet_available_memory = round_limits.subnet_available_memory;
        self.subnet_available_callbacks = round_limits.subnet_available_callbacks;
        self.compute_allocation_used = round_limits.compute_allocation_used;
        self.subnet_memory_reservation = round_limits.subnet_memory_reservation;
    }

    pub fn update_canister_round_limits(&mut self, round_limits: &RoundLimits) {
        self.instructions = round_limits.instructions;
        self.subnet_available_memory = round_limits.subnet_available_memory;
        self.subnet_available_callbacks = round_limits.subnet_available_callbacks;
        self.compute_allocation_used = round_limits.compute_allocation_used;
        self.subnet_memory_reservation = round_limits.subnet_memory_reservation;
    }
}

////////////////////////////////////////////////////////////////////////
/// Scheduler Implementation
pub(crate) struct SchedulerImpl {
    config: SchedulerConfig,
    hypervisor_config: HypervisorConfig,
    own_subnet_id: SubnetId,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    exec_env: Arc<ExecutionEnvironment>,
    cycles_account_manager: Arc<CyclesAccountManager>,
    metrics: Arc<SchedulerMetrics>,
    state_metrics: ReplicatedStateMetrics,
    log: ReplicaLogger,
    thread_pool: RefCell<scoped_threadpool::Pool>,
    rate_limiting_of_heap_delta: FlagStatus,
    rate_limiting_of_instructions: FlagStatus,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
}

impl SchedulerImpl {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: SchedulerConfig,
        hypervisor_config: HypervisorConfig,
        own_subnet_id: SubnetId,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
        exec_env: Arc<ExecutionEnvironment>,
        cycles_account_manager: Arc<CyclesAccountManager>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
        rate_limiting_of_heap_delta: FlagStatus,
        rate_limiting_of_instructions: FlagStatus,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    ) -> Self {
        let scheduler_cores = config.scheduler_cores as u32;
        Self {
            config,
            hypervisor_config,
            thread_pool: RefCell::new(scoped_threadpool::Pool::new(scheduler_cores)),
            own_subnet_id,
            ingress_history_writer,
            exec_env,
            cycles_account_manager,
            metrics: Arc::new(SchedulerMetrics::new(metrics_registry)),
            state_metrics: ReplicatedStateMetrics::new(metrics_registry),
            log,
            rate_limiting_of_heap_delta,
            rate_limiting_of_instructions,
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
                        continue;
                    }
                    NextExecution::ContinueInstallCode => {}
                },
            }
            let instruction_limits = InstructionLimits::new(
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
                .is_some_and(|canister| canister.has_paused_install_code());

            let round_instructions_executed =
                as_num_instructions(instructions_before - round_limits.instructions);

            let messages = NumMessages::from(message_instructions.map(|_| 1).unwrap_or(0));
            measurement_scope.add(round_instructions_executed, NumSlices::from(1), messages);

            // Break when round limits are reached or found a canister
            // that has a long install code message in progress.
            if round_limits.instructions_reached() || ongoing_long_install_code {
                break;
            }
        }
        state
    }

    /// Drains the subnet queues, executing all messages not blocked by long executions.
    fn drain_subnet_queues(
        &self,
        mut state: ReplicatedState,
        csprng: &mut Csprng,
        current_round: ExecutionRound,
        round_limits: &mut RoundLimits,
        measurement_scope: &MeasurementScope,
        registry_settings: &RegistryExecutionSettings,
        replica_version: &ReplicaVersion,
        chain_key_data: &ChainKeyData,
    ) -> ReplicatedState {
        let ongoing_long_install_code =
            state
                .canisters_iter()
                .any(|canister| match canister.next_execution() {
                    NextExecution::None | NextExecution::StartNew | NextExecution::ContinueLong => {
                        false
                    }
                    NextExecution::ContinueInstallCode => true,
                });
        loop {
            let mut available_subnet_messages = false;
            let mut loop_detector = state.subnet_queues_loop_detector();
            while let Some(msg) = state.peek_subnet_input() {
                if can_execute_subnet_msg(
                    &msg,
                    ongoing_long_install_code,
                    state.canister_states(),
                    round_limits,
                ) {
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
                    current_round,
                    round_limits,
                    registry_settings,
                    replica_version,
                    measurement_scope,
                    chain_key_data,
                );
                state = new_state;

                if message_instructions.is_none() {
                    // This may happen only if the message execution was paused,
                    // which means that there should not be any instructions
                    // remaining in the round. Since we do not update
                    // `ongoing_long_install_code`, we need to break the loop
                    // here to ensure correctness in the unlikely case of
                    // some instructions still remaining in the round.
                    break;
                }

                if round_limits.instructions_reached() {
                    break;
                }
            }
        }
        state
    }

    /// Invokes `ExecutionEnvironment` to execute a subnet message.
    fn execute_subnet_message(
        &self,
        msg: SubnetMessage,
        state: ReplicatedState,
        csprng: &mut Csprng,
        current_round: ExecutionRound,
        round_limits: &mut RoundLimits,
        registry_settings: &RegistryExecutionSettings,
        replica_version: &ReplicaVersion,
        measurement_scope: &MeasurementScope,
        chain_key_data: &ChainKeyData,
    ) -> (ReplicatedState, Option<NumInstructions>) {
        let instruction_limits = get_instruction_limits_for_subnet_message(&self.config, &msg);

        let instructions_before = round_limits.instructions;
        let (new_state, message_instructions) = self.exec_env.execute_subnet_message(
            msg,
            state,
            instruction_limits,
            csprng,
            chain_key_data,
            replica_version,
            registry_settings,
            current_round,
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
    ///
    /// Returns the IDs of all canisters that actually had a `Heartbeat` and/or
    /// `GlobalTimer` task enqueued.
    fn add_heartbeat_and_global_timer_tasks(
        &self,
        state: &mut ReplicatedState,
    ) -> BTreeSet<CanisterId> {
        let _timer = self
            .metrics
            .round_inner_heartbeat_overhead_duration
            .start_timer();

        let mut heartbeat_and_timer_canisters = BTreeSet::new();
        let now = state.time();

        for canister in state.canisters_iter_mut() {
            // Add `Heartbeat` or `GlobalTimer` for running canisters only.
            match canister.system_state.status() {
                CanisterStatusType::Running => {}
                CanisterStatusType::Stopping | CanisterStatusType::Stopped => {
                    continue;
                }
            }

            let has_heartbeat = has_heartbeat(canister);
            let has_active_timer = has_active_timer(canister, now);
            if !has_heartbeat && !has_active_timer {
                // Canister has no heartbeat and no active global timer.
                continue;
            }

            match canister.next_execution() {
                NextExecution::ContinueLong | NextExecution::ContinueInstallCode => {
                    // Do not add a heartbeat task if a long execution is pending.
                }
                NextExecution::None | NextExecution::StartNew => {
                    let canister = Arc::make_mut(canister);
                    maybe_add_heartbeat_or_global_timer_tasks(
                        canister,
                        has_heartbeat,
                        has_active_timer,
                        &mut heartbeat_and_timer_canisters,
                    );
                }
            }
        }
        heartbeat_and_timer_canisters
    }

    /// Performs multiple iterations of canister execution until the instruction
    /// limit per round is reached or the canisters become idle. The canisters
    /// are executed in parallel using the thread pool.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn inner_round<'a>(
        &'a self,
        mut state: ReplicatedState,
        current_round: ExecutionRound,
        registry_settings: &RegistryExecutionSettings,
        replica_version: &ReplicaVersion,
        chain_key_data: &ChainKeyData,
        round_schedule: &mut RoundSchedule,
        csprng: &mut Csprng,
        canister_ingress_latencies: &mut CanisterIngressQueueLatencies,
        scheduler_round_limits: &mut SchedulerRoundLimits,
        root_measurement_scope: &MeasurementScope<'a>,
        round_log: &ReplicaLogger,
    ) -> ReplicatedState {
        let cost_schedule = state.get_own_cost_schedule();
        let measurement_scope =
            MeasurementScope::nested(&self.metrics.round_inner, root_measurement_scope);

        let mut ingress_execution_results = Vec::new();
        let mut is_first_iteration = true;
        let mut total_heap_delta = NumBytes::from(0);
        let mut heartbeat_and_timer_canisters = BTreeSet::new();

        // Start iteration loop:
        //      - Execute subnet messages.
        //      - Execute heartbeat and global timer tasks.
        //      - Execute canisters input messages in parallel.
        //      - Induct messages on the same subnet.
        let mut state = loop {
            // Execute subnet messages.
            // If new messages are inducted into the subnet input queues,
            // they are processed until the subnet messages' instruction limit is reached.
            {
                let subnet_measurement_scope = MeasurementScope::nested(
                    &self.metrics.round_subnet_queue,
                    root_measurement_scope,
                );

                // TODO(EXC-1517): Improve inner loop preparation.
                let mut subnet_round_limits = scheduler_round_limits.subnet_round_limits();
                state = self.drain_subnet_queues(
                    state,
                    csprng,
                    current_round,
                    &mut subnet_round_limits,
                    &subnet_measurement_scope,
                    registry_settings,
                    replica_version,
                    chain_key_data,
                );
                scheduler_round_limits.update_subnet_round_limits(&subnet_round_limits);
            }

            let mut round_limits = scheduler_round_limits.canister_round_limits();
            if round_limits.instructions_reached() {
                self.metrics
                    .inner_round_loop_consumed_max_instructions
                    .inc();
                break state;
            }

            // Add `Heartbeat` and `GlobalTimer` tasks to be executed before input messages.
            if is_first_iteration {
                heartbeat_and_timer_canisters =
                    self.add_heartbeat_and_global_timer_tasks(&mut state);
            }

            let measurement_scope =
                MeasurementScope::nested(&self.metrics.round_inner_iteration, &measurement_scope);

            // Update subnet available memory before taking out the canisters.
            let preparation_timer = self.metrics.round_inner_iteration_prep.start_timer();
            round_limits.subnet_available_memory =
                self.exec_env.scaled_subnet_available_memory(&state);
            drop(preparation_timer);

            // Scheduling.
            let scheduling_timer = self.metrics.round_inner_iteration_scheduling.start_timer();
            round_schedule.start_iteration(&mut state, &self.metrics, round_log);
            if round_schedule.schedule_length() == 0 {
                break state;
            }

            let canisters = state.take_canister_states();
            let (mut active_canisters_partitioned_by_cores, inactive_canisters) =
                round_schedule.partition_canisters_to_cores(canisters);

            if is_first_iteration {
                for partition in active_canisters_partitioned_by_cores.iter_mut() {
                    if let Some(canister) = partition.first_mut() {
                        Arc::make_mut(canister)
                            .system_state
                            .canister_metrics_mut()
                            .observe_scheduled_as_first();
                    }
                }
            }
            drop(scheduling_timer);

            let execution_timer = self.metrics.round_inner_iteration_exe.start_timer();
            let instructions_before = round_limits.instructions;
            let (
                active_canisters,
                executed_canisters,
                canisters_with_completed_messages,
                mut loop_ingress_execution_results,
                heap_delta,
            ) = self.execute_canisters_in_inner_round(
                active_canisters_partitioned_by_cores,
                current_round,
                state.time(),
                Arc::new(state.metadata.network_topology.clone()),
                registry_settings.subnet_size,
                cost_schedule,
                &mut round_limits,
                &measurement_scope,
            );
            let instructions_consumed = instructions_before - round_limits.instructions;
            drop(execution_timer);

            let finalization_timer = self.metrics.round_inner_iteration_fin.start_timer();
            // println!("executed_canister_ids: {:?}", executed_canister_ids);
            total_heap_delta += heap_delta;
            state.metadata.heap_delta_estimate += heap_delta;

            // Put back the executed canisters into the canisters map. Since usually most
            // canisters have no messages to execute, this is likely to be more efficient
            // than rebuilding the map from scratch.
            let mut canisters = inactive_canisters;
            canisters.extend(
                active_canisters
                    .into_iter()
                    .map(|canister| (canister.canister_id(), canister)),
            );
            state.put_canister_states(canisters);

            ingress_execution_results.append(&mut loop_ingress_execution_results);

            round_schedule.end_iteration(
                &mut state,
                &executed_canisters,
                &canisters_with_completed_messages,
            );

            round_limits.instructions -= as_round_instructions(
                self.config
                    .instruction_overhead_per_canister_for_finalization
                    * state.num_canisters() as u64,
            );
            scheduler_round_limits.update_canister_round_limits(&round_limits);
            debug_assert_le!(
                scheduler_round_limits.subnet_available_callbacks,
                self.exec_env.subnet_available_callbacks(&state),
                "`subnet_available_callbacks` is a lower bound estimate for the number of available callbacks"
            );

            if instructions_consumed == RoundInstructions::from(0) {
                break state;
            } else {
                self.metrics
                    .inner_loop_consumed_non_zero_instructions_count
                    .inc();
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
            for canister_id in &heartbeat_and_timer_canisters {
                let Some(canister) = state.canister_state_make_mut(canister_id) else {
                    continue;
                };
                // It's OK to indiscriminately `make_mut()` here because we've already mutated
                // this canister state this round.
                canister
                    .system_state
                    .task_queue
                    .remove_heartbeat_and_global_timer();
            }
        }

        for canister_id in round_schedule.fully_executed_canisters().iter() {
            state
                .metadata
                .subnet_schedule
                .get_mut(*canister_id)
                .last_full_execution_round = current_round;
        }

        // We only export metrics for "executable" canisters to ensure that the metrics
        // are not polluted by canisters that haven't had any messages for a long time.
        for canister_id in round_schedule.round_scheduled_canisters() {
            // Newly created canisters have `last_full_execution_round` set to zero,
            // and hence skew the `canister_age` metric.
            let last_full_execution_round = if round_schedule
                .fully_executed_canisters()
                .contains(canister_id)
            {
                // Canister priority might have been dropped, don't look it up.
                current_round
            } else {
                state
                    .canister_priority(canister_id)
                    .last_full_execution_round
            };
            if last_full_execution_round.get() != 0 {
                let canister_age = current_round.get() - last_full_execution_round.get();
                self.metrics.canister_age.observe(canister_age as f64);
                // If `canister_age` > 1 / `compute_allocation` the canister ought to have been
                // scheduled.
                let canister_state = state.canister_state(canister_id).unwrap();
                let allocation = Ratio::new(canister_state.compute_allocation().as_percent(), 100);
                if *allocation.numer() > 0 && Ratio::from_integer(canister_age) > allocation.recip()
                {
                    self.metrics.canister_compute_allocation_violation.inc();
                }
            };
        }

        for (message_id, status) in ingress_execution_results {
            let old_status = self
                .ingress_history_writer
                .set_status(&mut state, message_id, status);
            canister_ingress_latencies.on_ingress_status_changed(old_status);
        }
        self.metrics
            .executable_canisters_per_round
            .observe(round_schedule.round_scheduled_canisters().len() as f64);
        self.metrics
            .executed_canisters_per_round
            .observe(round_schedule.executed_canisters().len() as f64);

        self.metrics
            .heap_delta_rate_limited_canisters_per_round
            .observe(round_schedule.rate_limited_canisters().len() as f64);

        state
    }

    /// Executes canisters in parallel using the thread pool.
    ///
    /// The function is invoked in each iteration of `inner_round`.
    /// The given `canisters_by_thread` defines the priority of canisters.
    /// Returns:
    /// - the new states of the canisters,
    /// - actually executed canisters,
    /// - canisters that completed at least one message execution,
    /// - the ingress results,
    /// - the total heap delta.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn execute_canisters_in_inner_round(
        &self,
        canisters_by_thread: Vec<Vec<Arc<CanisterState>>>,
        round_id: ExecutionRound,
        time: Time,
        network_topology: Arc<NetworkTopology>,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        round_limits: &mut RoundLimits,
        measurement_scope: &MeasurementScope,
    ) -> (
        Vec<Arc<CanisterState>>,
        BTreeSet<CanisterId>,
        BTreeSet<CanisterId>,
        Vec<(MessageId, IngressStatus)>,
        NumBytes,
    ) {
        let thread_pool = &mut self.thread_pool.borrow_mut();
        let exec_env = self.exec_env.as_ref();

        // If there are no more instructions left, then skip execution and
        // return unchanged canisters.
        if round_limits.instructions_reached() {
            return (
                canisters_by_thread.into_iter().flatten().collect(),
                BTreeSet::new(),
                BTreeSet::new(),
                vec![],
                NumBytes::from(0),
            );
        }

        // Reserve the space for holding the result of each execution thread.
        let mut results_by_thread: Vec<ExecutionThreadResult> = canisters_by_thread
            .iter()
            .map(|_| Default::default())
            .collect();

        // Run canisters in parallel. The results will be stored in `results_by_thread`.
        let round_limits_per_thread = round_limits.clone();
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
                let round_limits = round_limits_per_thread.clone();
                let config = &self.config;
                scope.execute(move || {
                    *result = execute_canisters_on_thread(
                        canisters,
                        exec_env,
                        config,
                        round_id,
                        time,
                        network_topology,
                        rate_limiting_of_heap_delta,
                        subnet_size,
                        cost_schedule,
                        round_limits,
                        metrics,
                        logger,
                    );
                });
            }
        });

        // At this point all threads completed and stored their results.
        // Aggregate `results_by_thread` to get the result of this function.
        let mut canisters = Vec::new();
        let mut executed_canisters = BTreeSet::new();
        let mut canisters_with_completed_messages = BTreeSet::new();
        let mut ingress_results = Vec::new();
        let mut max_instructions_executed_per_thread = NumInstructions::from(0);
        let mut heap_delta = NumBytes::from(0);
        let mut callbacks_created = 0;
        for mut result in results_by_thread.into_iter() {
            canisters.append(&mut result.canisters);
            executed_canisters.extend(result.executed_canisters);
            canisters_with_completed_messages.extend(result.canisters_with_completed_messages);
            ingress_results.append(&mut result.ingress_results);
            let instructions_executed = as_num_instructions(
                round_limits_per_thread.instructions - result.round_limits.instructions,
            );
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

            debug_assert_ge!(
                round_limits_per_thread.subnet_available_callbacks,
                result.round_limits.subnet_available_callbacks,
            );
            callbacks_created += round_limits_per_thread.subnet_available_callbacks
                - result.round_limits.subnet_available_callbacks;
        }

        // Since there are multiple threads, we update the global limit using
        // the thread that executed the most instructions.
        round_limits.instructions -= as_round_instructions(max_instructions_executed_per_thread);

        round_limits.subnet_available_callbacks -= callbacks_created;

        (
            canisters,
            executed_canisters,
            canisters_with_completed_messages,
            ingress_results,
            heap_delta,
        )
    }

    fn purge_expired_ingress_messages(
        &self,
        state: &mut ReplicatedState,
        canister_ingress_latencies: &mut CanisterIngressQueueLatencies,
    ) {
        let current_time = state.time();
        let not_expired = |ingress: &Ingress| ingress.expiry_time >= current_time;
        let mut expired_ingress_messages = state.subnet_queues_retain_ingress_messages(not_expired);
        for canister in state.canisters_iter_mut() {
            if !canister.system_state.all_ingress_messages(not_expired) {
                let canister = Arc::make_mut(canister);
                expired_ingress_messages
                    .extend(canister.system_state.retain_ingress_messages(not_expired));
            }
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
            let old_status = self.ingress_history_writer.set_status(
                state,
                ingress.message_id.clone(),
                IngressStatus::Known {
                    receiver: ingress.receiver.get(),
                    user_id: ingress.source,
                    time: current_time,
                    state: IngressState::Failed(error),
                },
            );
            canister_ingress_latencies.on_ingress_status_changed(old_status);
        }
    }

    /// Charge canisters for their resource allocation and usage. Canisters
    /// that did not manage to pay are uninstalled.
    /// This function is expected to be called at the end of a round.
    fn charge_canisters_for_resource_allocation_and_usage(
        &self,
        state: &mut ReplicatedState,
        subnet_size: usize,
    ) {
        let cost_schedule = state.get_own_cost_schedule();
        let state_time = state.time();
        let threshold_last_allocation_charge = state_time.saturating_sub(
            self.cycles_account_manager
                .duration_between_allocation_charges(),
        );
        let mut all_rejects = Vec::new();
        let mut uninstalled_canisters = Vec::new();
        for canister in state.canisters_iter_mut() {
            if canister.system_state.time_of_last_allocation_charge
                > threshold_last_allocation_charge
            {
                // Skip charging for the resources in this round because not enough time has passed
                // since the last charge happened.
                continue;
            }

            // Postpone charging for resources when a canister has a paused execution
            // to avoid modifying the balance of a canister during an unfinished operation.
            if canister.has_paused_execution() || canister.has_paused_install_code() {
                continue;
            }

            let canister = Arc::make_mut(canister);
            let duration_since_last_charge =
                canister.duration_since_last_allocation_charge(state_time);
            canister.system_state.time_of_last_allocation_charge = state_time;
            if self
                .cycles_account_manager
                .charge_canister_for_resource_allocation_and_usage(
                    &self.log,
                    canister,
                    duration_since_last_charge,
                    subnet_size,
                    cost_schedule,
                )
                .is_err()
            {
                uninstalled_canisters.push(canister.canister_id());
                all_rejects.push(uninstall_canister(
                    &self.log,
                    canister,
                    None, /* we're at the end of a round so no need to update round limits */
                    state_time,
                    Arc::clone(&self.fd_factory),
                ));
                canister.system_state.compute_allocation = ComputeAllocation::zero();
                canister.system_state.memory_allocation = MemoryAllocation::default();
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
        let mut subnet_available_guaranteed_response_memory = self
            .exec_env
            .subnet_available_guaranteed_response_message_memory(state);

        // Get a list of canisters in the map before we iterate over the map.
        // This is because we cannot hold an immutable reference to the map
        // while trying to simultaneously mutate it.
        let canisters_with_outputs: Vec<CanisterId> = state
            .canisters_iter()
            .filter(|canister| canister.has_output())
            .map(|canister| canister.canister_id())
            .collect();

        let mut inducted_messages_to_self = 0;
        let mut inducted_messages_to_others = 0;
        for source_canister_id in canisters_with_outputs {
            // Remove the source canister from the map so that we can
            // `get_mut()` on the map further below for the destination canister.
            // Borrow rules do not allow us to hold multiple mutable references.
            let mut source_canister_arc = match state.take_canister_state(&source_canister_id) {
                None => fatal!(
                    self.log,
                    "Should be guaranteed that the canister exists in the map."
                ),
                Some(canister) => canister,
            };
            // TODO(DSM-102): Consider checking whether the canister has output messages for
            // local canisters before calling `make_mut()`.
            let source_canister = Arc::make_mut(&mut source_canister_arc);

            let messages_before_induction = source_canister
                .system_state
                .queues()
                .output_queues_message_count();
            source_canister.induct_messages_to_self(
                &mut subnet_available_guaranteed_response_memory,
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
                .output_queues_for_each(|canister_id, msg| {
                    let own_subnet_type = state.metadata.own_subnet_type;
                    match state.canister_state_make_mut(canister_id) {
                        Some(dest_canister) => dest_canister
                            .push_input(
                                (*msg).clone(),
                                &mut subnet_available_guaranteed_response_memory,
                                own_subnet_type,
                                InputQueueType::LocalSubnet,
                            )
                            .map(|_| ())
                            .map_err(|(err, msg)| {
                                error!(
                                    self.log,
                                    "Inducting {:?} on same subnet failed with error '{}'.",
                                    &msg,
                                    &err
                                );
                            }),
                        None => Err(()),
                    }
                });
            let messages_after_induction = source_canister
                .system_state
                .queues()
                .output_queues_message_count();
            inducted_messages_to_others +=
                messages_before_induction.saturating_sub(messages_after_induction);
            state.put_canister_state(source_canister_arc);
        }

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
            let canister = state.canister_state(canister_id).unwrap();

            if let Err(err) = canister.check_invariants(&self.hypervisor_config) {
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
                    let canister_priority = state.canister_priority(&canister.canister_id());
                    Some(CanisterRoundState::new(canister, canister_priority))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        paused_round_states.sort();

        let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();
        paused_round_states
            .iter()
            .skip(self.config.max_paused_executions)
            .for_each(|rs| {
                let canister = canister_states.get_mut(&rs.canister_id()).unwrap();
                self.exec_env
                    .abort_canister(canister, subnet_schedule, &self.log);
            });
    }

    /// Code that must be executed unconditionally after each round.
    ///
    /// NOTE: This is also called by `checkpoint_round_with_no_execution()`, so it
    /// must be safe to call even when no execution has taken place.
    //
    // TODO(DSM-103): Consider only aborting / checking DTS invariants for actually
    // scheduled canisters.
    fn finish_round(
        &self,
        state: &mut ReplicatedState,
        current_round: ExecutionRound,
        current_round_type: ExecutionRoundType,
        logger: &ReplicaLogger,
    ) {
        match current_round_type {
            ExecutionRoundType::CheckpointRound => {
                state.metadata.heap_delta_estimate = NumBytes::from(0);
                // The set of compiled Wasms must be cleared when taking a
                // checkpoint to keep it in sync with the protobuf serialization
                // of `ReplicatedState` which doesn't store this field.
                state.metadata.expected_compiled_wasms.clear();

                // Abort all paused execution before the checkpoint.
                self.exec_env.abort_all_paused_executions(state, &self.log);
            }
            ExecutionRoundType::OrdinaryRound => {
                self.abort_paused_executions_above_limit(state);
            }
        }

        observe_replicated_state_metrics(
            self.own_subnet_id,
            state,
            current_round,
            self.exec_env.subnet_memory_capacity(),
            &self.state_metrics,
            logger,
        );

        self.check_dts_invariants(state, current_round_type);
    }

    /// Checks the deterministic time slicing invariant after round execution.
    fn check_dts_invariants(
        &self,
        state: &ReplicatedState,
        current_round_type: ExecutionRoundType,
    ) {
        let canisters_with_tasks = state
            .canisters_iter()
            .filter(|canister| !canister.system_state.task_queue.is_empty());

        for canister in canisters_with_tasks {
            canister
                .system_state
                .task_queue
                .check_dts_invariants(current_round_type, &canister.canister_id());
        }
    }
}

impl Scheduler for SchedulerImpl {
    type State = ReplicatedState;

    fn execute_round(
        &self,
        mut state: ReplicatedState,
        randomness: Randomness,
        chain_key_data: ChainKeyData,
        replica_version: &ReplicaVersion,
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
        let mut canister_ingress_latencies = CanisterIngressQueueLatencies::new(
            state.time(),
            self.metrics.canister_ingress_queue_latencies.clone(),
        );

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

            long_running_canister_ids = state
                .canister_priorities()
                .iter()
                .filter_map(|(&canister_id, _)| {
                    match state.canister_state(&canister_id)?.next_execution() {
                        NextExecution::None | NextExecution::StartNew => None,
                        NextExecution::ContinueLong | NextExecution::ContinueInstallCode => {
                            Some(canister_id)
                        }
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
                self.purge_expired_ingress_messages(&mut state, &mut canister_ingress_latencies);
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
            csprng = Csprng::from_randomness_and_purpose(
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
            // - `S = max(max_instructions_per_slice, max_instructions_per_install_code_slice)`.
            // In the worst case, we start a new Wasm execution when then counter
            // reaches 1 and the execution uses the maximum `S` instructions. After
            // the execution the counter will be set to `1 - S`.
            //
            // We want the total number executed instructions to not exceed `R`,
            // which gives us: `X - (1 - S) <= R` or `X <= R - S + 1`.
            let max_instructions_per_slice = std::cmp::max(
                self.config.max_instructions_per_slice,
                self.config.max_instructions_per_install_code_slice,
            );
            let round_instructions = as_round_instructions(self.config.max_instructions_per_round)
                - as_round_instructions(max_instructions_per_slice)
                + RoundInstructions::from(1);

            SchedulerRoundLimits {
                instructions: round_instructions,
                subnet_instructions: as_round_instructions(
                    self.config.max_instructions_per_round / SUBNET_MESSAGES_LIMIT_FRACTION,
                ),
                subnet_available_memory: self.exec_env.scaled_subnet_available_memory(&state),
                subnet_available_callbacks: self.exec_env.subnet_available_callbacks(&state),
                compute_allocation_used: state.total_compute_allocation(),
                subnet_memory_reservation: self.exec_env.scaled_subnet_memory_reservation(),
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
                    SubnetMessage::Response(
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
                    current_round,
                    &mut subnet_round_limits,
                    registry_settings,
                    replica_version,
                    &measurement_scope,
                    &chain_key_data,
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
                self.finish_round(&mut state, current_round, current_round_type, &round_log);
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
                debug_assert_lt!(raw_rand_context.execution_round_id, current_round);
                let (new_state, _) = self.execute_subnet_message(
                    SubnetMessage::Request(raw_rand_context.request.into()),
                    state,
                    &mut csprng,
                    current_round,
                    &mut subnet_round_limits,
                    registry_settings,
                    replica_version,
                    &measurement_scope,
                    &chain_key_data,
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
            // very likely that `round_limits.instructions < 0` at this point.
            // However, we would like to make progress with other subnet
            // messages that do not consume instructions. To allow that, we set
            // the number available instructions to 0 if it is not positive.
            subnet_round_limits.instructions = subnet_round_limits
                .instructions
                .max(RoundInstructions::from(0));
            scheduler_round_limits.update_subnet_round_limits(&subnet_round_limits);
        }

        // TODO: Consider routing messages from subnet output queues to local canisters.

        // Inner round.
        let mut round_schedule = RoundSchedule::new(
            self.config.scheduler_cores,
            self.config.heap_delta_rate_limit,
            self.rate_limiting_of_heap_delta,
        );
        let mut state = self.inner_round(
            state,
            current_round,
            registry_settings,
            replica_version,
            &chain_key_data,
            &mut round_schedule,
            &mut csprng,
            &mut canister_ingress_latencies,
            &mut scheduler_round_limits,
            &root_measurement_scope,
            &round_log,
        );

        // Update [`SignWithThresholdContext`]s by assigning randomness and matching pre-signatures.
        {
            let subnet_call_context_manager = &mut state.metadata.subnet_call_context_manager;

            let contexts = subnet_call_context_manager
                .sign_with_threshold_contexts
                .values_mut()
                .collect();

            let pre_signature_stashes = &mut subnet_call_context_manager.pre_signature_stashes;

            update_signature_request_contexts(
                current_round,
                chain_key_data.idkg_pre_signatures,
                contexts,
                pre_signature_stashes,
                &mut csprng,
                registry_settings,
                self.metrics.as_ref(),
                &round_log,
            );
        }

        // Finalization.
        {
            let _timer = self.metrics.round_finalization_duration.start_timer();

            let mut final_state;
            {
                let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();
                for (canister_id, _) in subnet_schedule.iter() {
                    let Some(canister) = canister_states.get_mut(canister_id) else {
                        continue;
                    };

                    let heap_delta_debit = canister.scheduler_state.heap_delta_debit.get();
                    self.metrics
                        .canister_heap_delta_debits
                        .observe(heap_delta_debit as f64);
                    if heap_delta_debit > 0 {
                        let canister = Arc::make_mut(canister);
                        canister.scheduler_state.heap_delta_debit =
                            match self.rate_limiting_of_heap_delta {
                                FlagStatus::Enabled => NumBytes::from(
                                    heap_delta_debit
                                        .saturating_sub(self.config.heap_delta_rate_limit.get()),
                                ),
                                FlagStatus::Disabled => NumBytes::from(0),
                            };
                    }

                    let install_code_debit = canister.scheduler_state.install_code_debit.get();
                    self.metrics
                        .canister_install_code_debits
                        .observe(install_code_debit as f64);
                    if install_code_debit > 0 {
                        let canister = Arc::make_mut(canister);
                        canister.scheduler_state.install_code_debit =
                            match self.rate_limiting_of_instructions {
                                FlagStatus::Enabled => NumInstructions::from(
                                    install_code_debit
                                        .saturating_sub(self.config.install_code_rate_limit.get()),
                                ),
                                FlagStatus::Disabled => NumInstructions::from(0),
                            };
                    }
                }

                for canister_id in round_schedule.round_scheduled_canisters() {
                    let Some(canister) = state.canister_state_mut_arc(canister_id) else {
                        continue;
                    };

                    let new_log = &canister.system_state.log_memory_store;
                    let old_log = &canister.system_state.canister_log;
                    let delta_log_sizes = if LOG_MEMORY_STORE_FEATURE_ENABLED {
                        new_log.delta_log_sizes()
                    } else {
                        old_log.delta_log_sizes()
                    };
                    if new_log.has_delta_log_sizes() || old_log.has_delta_log_sizes() {
                        // Only clone state if delta log sizes are not empty.
                        let canister = Arc::make_mut(canister);
                        let new_log = &mut canister.system_state.log_memory_store;
                        let old_log = &mut canister.system_state.canister_log;
                        // IMPORTANT: Ensure `clear_delta_log_sizes()` is called
                        // so the delta log sizes are empty at the end of the round.
                        // This guarantees states remain consistent before and after a checkpoint.
                        new_log.clear_delta_log_sizes();
                        old_log.clear_delta_log_sizes();
                    }
                    for size in delta_log_sizes {
                        self.metrics
                            .canister_log_delta_memory_usage
                            .observe(size as f64);
                    }

                    // TODO(EXC-1124): Re-enable once the cycle balance check is fixed.
                    // cycles_out_sum += canister.system_state.queues().output_queue_cycles();
                }
                // TODO(EXC-1124): Re-enable once the cycle balance check is fixed.
                // cycles_out_sum += total_canister_balance;

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

                // Check if the invariants are still valid after the execution for active canisters.
                self.check_canister_invariants(
                    &round_log,
                    &current_round,
                    &state,
                    round_schedule.round_scheduled_canisters(),
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

            {
                let _timer = self.metrics.round_scheduling_duration.start_timer();
                round_schedule.finish_round(&mut final_state, current_round, &self.metrics);
            }
            self.finish_round(
                &mut final_state,
                current_round,
                current_round_type,
                &round_log,
            );

            final_state
                .metadata
                .subnet_metrics
                .update_transactions_total += root_measurement_scope.messages().get();
            final_state.metadata.subnet_metrics.num_canisters =
                final_state.canister_states().len() as u64;
            final_state
        }
    }

    fn checkpoint_round_with_no_execution(&self, state: &mut ReplicatedState) {
        self.finish_round(
            state,
            // TODO(DSM-106) This is a workaround to avoid having to temporarily change the
            // `Scheduler` trait. The round number is only used to decide whether to log
            // warnings about long open call contexts. When `ReplicatedState`
            // instrumentation moves to MessageRouting, this argument will be dropped.
            ExecutionRound::from(0),
            ExecutionRoundType::CheckpointRound,
            &self.log,
        );
    }
}

fn observe_instructions_consumed_per_message(
    canister: &CanisterState,
    consumed_instructions: NumInstructions,
    instruction_limit_per_message: NumInstructions,
    metrics: &SchedulerMetrics,
    logger: &ReplicaLogger,
) {
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
    canisters: Vec<Arc<CanisterState>>,
    /// Canisters that advanced or completed a message execution.
    executed_canisters: BTreeSet<CanisterId>,
    /// Canisters that completed at least one message execution (advancing a long
    /// execution does not count).
    canisters_with_completed_messages: BTreeSet<CanisterId>,
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
    canisters_to_execute: Vec<Arc<CanisterState>>,
    exec_env: &ExecutionEnvironment,
    config: &SchedulerConfig,
    round_id: ExecutionRound,
    time: Time,
    network_topology: Arc<NetworkTopology>,
    rate_limiting_of_heap_delta: FlagStatus,
    subnet_size: usize,
    cost_schedule: CanisterCyclesCostSchedule,
    mut round_limits: RoundLimits,
    metrics: Arc<SchedulerMetrics>,
    logger: ReplicaLogger,
) -> ExecutionThreadResult {
    // Since this function runs on a helper thread, we cannot use a nested scope
    // here. Instead, we propagate metrics to the outer scope manually via
    // `ExecutionThreadResult`.
    let measurement_scope =
        MeasurementScope::root(&metrics.round_inner_iteration_thread).dont_record_zeros();
    // These variables accumulate the results and will be returned at the end.
    let mut canisters = vec![];
    let mut executed_canisters = BTreeSet::new();
    let mut canisters_with_completed_messages = BTreeSet::new();
    let mut ingress_results = vec![];
    let mut total_slices_executed = NumSlices::from(0);
    let mut total_messages_executed = NumMessages::from(0);
    let mut total_heap_delta = NumBytes::from(0);

    let instruction_limits = InstructionLimits::new(
        config.max_instructions_per_message,
        config.max_instructions_per_slice,
    );

    for mut canister_arc in canisters_to_execute.into_iter() {
        // If no more instructions are left or if heap delta is already too
        // large, then skip execution of the canister and keep its old state.
        if round_limits.instructions_reached()
            || total_heap_delta >= config.max_heap_delta_per_iteration
        {
            canisters.push(canister_arc);
            continue;
        }

        // Process all messages of the canister until
        // - it has no tasks or input messages to execute
        // - or the canister is blocked by a long-running install code.
        // - or the instruction limit is reached.
        // - or the canister finishes a long execution
        let mut canister = Arc::make_mut(&mut canister_arc);
        let mut total_instructions_used = NumInstructions::new(0);
        loop {
            match canister.next_execution() {
                NextExecution::None | NextExecution::ContinueInstallCode => {
                    break;
                }
                NextExecution::StartNew | NextExecution::ContinueLong => {}
            }

            if round_limits.instructions_reached() {
                canister
                    .system_state
                    .canister_metrics_mut()
                    .observe_interrupted_during_execution();
                break;
            }
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
                canister_arc,
                instruction_limits.clone(),
                config.max_instructions_per_query_message,
                Arc::clone(&network_topology),
                time,
                &mut round_limits,
                subnet_size,
                cost_schedule,
            );
            ingress_results.extend(ingress_status);
            let round_instructions_executed =
                as_num_instructions(instructions_before - round_limits.instructions);

            // A message was executed iff a non-zero number of instructions was consumed.
            // A paused execution outputs `instructions_used == None` and it also counts as
            // an executed message slice.
            let mut messages = NumMessages::from(0);
            match instructions_used {
                // Message completed.
                Some(instructions) => {
                    if instructions.get() > 0 {
                        // Message actually executed.
                        messages = NumMessages::from(1);
                        total_slices_executed.inc_assign();
                        executed_canisters.insert(new_canister.canister_id());
                        canisters_with_completed_messages.insert(new_canister.canister_id());
                        total_instructions_used += instructions;
                    }

                    observe_instructions_consumed_per_message(
                        &new_canister,
                        instructions,
                        instruction_limits.message(),
                        &metrics,
                        &logger,
                    );
                }
                // Paused execution.
                None => {
                    total_slices_executed.inc_assign();
                    executed_canisters.insert(new_canister.canister_id());
                }
            }
            measurement_scope.add(round_instructions_executed, NumSlices::from(1), messages);
            total_messages_executed += messages;
            canister_arc = new_canister;
            canister = Arc::make_mut(&mut canister_arc);
            round_limits.instructions -=
                as_round_instructions(config.instruction_overhead_per_execution);
            total_heap_delta += heap_delta;
            if rate_limiting_of_heap_delta == FlagStatus::Enabled {
                canister.scheduler_state.heap_delta_debit += heap_delta;
            }
            if messages.get() > 0 {
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
            } else {
                timer.stop_and_discard();
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
        canister
            .system_state
            .canister_metrics_mut()
            .observe_executed(total_instructions_used);
        canisters.push(canister_arc);
        // Skip per-canister overhead for canisters with not enough cycles.
        if total_instructions_used > 0.into() {
            round_limits.instructions -=
                as_round_instructions(config.instruction_overhead_per_canister);
        }
    }

    ExecutionThreadResult {
        canisters,
        executed_canisters,
        canisters_with_completed_messages,
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
    subnet_memory_capacity: NumBytes,
    metrics: &ReplicatedStateMetrics,
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
    let mut total_canister_history_memory_usage = NumBytes::new(0);
    let mut total_canister_memory_allocated_bytes = NumBytes::new(0);

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
        queues_oversized_requests_extra_bytes += queues.oversized_guaranteed_requests_extra_bytes();
        queues_best_effort_message_bytes += queues.best_effort_message_memory_usage();
        if !canister_id_ranges.contains(&canister.canister_id()) {
            canisters_not_in_routing_table += 1;
        }

        total_canister_history_memory_usage += canister.canister_history_memory_usage();
        total_canister_memory_allocated_bytes += canister
            .memory_allocation()
            .allocated_bytes(canister.memory_usage());
        total_canister_balance += canister.system_state.balance();
        total_canister_reserved_balance += canister.system_state.reserved_balance();

        if let Some(manager) = canister.system_state.call_context_manager() {
            // Log all old call contexts, but not (nearly) every round.
            let maybe_log_old_call_contexts = |origin: &CallOrigin, origin_time: Time| {
                if current_round
                    .get()
                    .is_multiple_of(SPAMMY_LOG_INTERVAL_ROUNDS)
                {
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
    metrics
        .old_open_call_contexts
        .with_label_values(&[OLD_CALL_CONTEXT_LABEL_ONE_DAY])
        .set(old_call_contexts_count as i64);
    metrics
        .canisters_with_old_open_call_contexts
        .with_label_values(&[OLD_CALL_CONTEXT_LABEL_ONE_DAY])
        .set(canisters_with_old_open_call_contexts as i64);

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

    for context in state.signature_request_contexts().values() {
        *in_flight_signature_request_contexts_by_key_id
            .entry(context.key_id())
            .or_default() += 1;
    }
    for (key_id, count) in in_flight_signature_request_contexts_by_key_id {
        metrics
            .in_flight_signature_request_contexts
            .with_label_values(&[&key_id.to_string()])
            .observe(count as f64);
    }

    for (key_id, stash) in state.pre_signature_stashes() {
        metrics
            .pre_signature_stash_size
            .with_label_values(&[&key_id.to_string()])
            .set(stash.pre_signatures.len() as i64);
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
    metrics.observe_queues_best_effort_message_bytes(queues_best_effort_message_bytes);

    metrics
        .ingress_history_length
        .set(state.metadata.ingress_history.len() as i64);
    metrics
        .canisters_not_in_routing_table
        .set(canisters_not_in_routing_table);
    metrics
        .stop_canister_calls_without_call_id
        .set(num_stop_canister_calls_without_call_id as i64);

    metrics
        .total_canister_balance
        .set(total_canister_balance.get() as f64);

    metrics
        .total_canister_reserved_balance
        .set(total_canister_reserved_balance.get() as f64);

    // Check replicated state invariants still hold after the round execution.
    // We allow `total_canister_memory_allocated_bytes` to exceed the subnet memory capacity
    // by `total_canister_history_memory_usage` because the canister history
    // memory usage is not tracked during a round in `SubnetAvailableMemory`.
    if total_canister_memory_allocated_bytes
        > subnet_memory_capacity + total_canister_history_memory_usage
    {
        metrics.subnet_memory_usage_invariant.inc();
        warn!(
            logger,
            "{}: At Round {} @ time {}, the resulted state after execution does not hold the invariants. Total canister memory allocated bytes {} exceeded subnet memory capacity {}",
            SUBNET_MEMORY_USAGE_INVARIANT_BROKEN,
            current_round,
            state.time(),
            total_canister_memory_allocated_bytes,
            subnet_memory_capacity
        );
    }

    metrics
        .canister_snapshots_memory_usage
        .set(state.canister_snapshots.memory_taken().get() as i64);
    metrics
        .num_canister_snapshots
        .set(state.canister_snapshots.count() as i64);

    for canister in state.canisters_iter() {
        let log_memory_usage = if LOG_MEMORY_STORE_FEATURE_ENABLED {
            canister.system_state.log_memory_store.memory_usage()
        } else {
            canister.system_state.canister_log.bytes_used()
        };
        metrics
            .canister_log_memory_usage_v2
            .observe(log_memory_usage as f64);
        metrics
            .canister_log_memory_usage_v3
            .observe(log_memory_usage as f64);
    }

    // TODO: Consider only doing this every Nth round.
    for canister in state.canisters_iter() {
        observe_canister_metrics(metrics, canister);
    }
}

/// Instruments canister balance, memory sizes and memory and compute allocation.
fn observe_canister_metrics(metrics: &ReplicatedStateMetrics, canister: &CanisterState) {
    metrics
        .canister_balance
        .observe(canister.system_state.balance().get() as f64);
    if let Some(es) = &canister.execution_state {
        metrics
            .canister_binary_size
            .observe(es.wasm_binary.binary.len() as f64);
        metrics.canister_wasm_memory_usage.observe(
            ic_replicated_state::num_bytes_try_from(es.wasm_memory.size)
                .unwrap()
                .get() as f64,
        );
        metrics.canister_stable_memory_usage.observe(
            ic_replicated_state::num_bytes_try_from(es.stable_memory.size)
                .unwrap()
                .get() as f64,
        );
    }
    metrics
        .canister_memory_allocation
        .observe(canister.memory_allocation().pre_allocated_bytes().get() as f64);
    metrics
        .canister_compute_allocation
        .observe(canister.compute_allocation().as_percent() as f64 / 100.0);
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

/// Helper function that checks if a subnet message can be executed:
///     1. A message cannot be executed if it is directed to a canister
///     with another long-running execution in progress.
///     2. Install code messages can only be executed sequentially.
fn can_execute_subnet_msg(
    msg: &SubnetMessage,
    ongoing_long_install_code: bool,
    canister_states: &BTreeMap<CanisterId, Arc<CanisterState>>,
    round_limits: &mut RoundLimits,
) -> bool {
    let Some(effective_canister_id) = msg.effective_canister_id() else {
        // If there is no effective canister ID, we can execute the subnet message.
        return true;
    };
    let Some(effective_canister_state) = canister_states.get(&effective_canister_id) else {
        // If there is no effective canister state, we can execute the subnet message.
        return true;
    };
    let maybe_method = match msg {
        SubnetMessage::Ingress(ingress) => Ic00Method::from_str(ingress.method_name.as_str()).ok(),
        SubnetMessage::Request(request) => Ic00Method::from_str(request.method_name.as_str()).ok(),
        SubnetMessage::Response { .. } => None,
    };
    let Some(method) = maybe_method else {
        // If there is no method name, we can execute the subnet message.
        return true;
    };

    // Adding a full match here to catch any further task queue changes.
    let (effective_canister_is_paused, effective_canister_is_aborted) =
        match effective_canister_state.system_state.task_queue.front() {
            None
            | Some(ExecutionTask::Heartbeat)
            | Some(ExecutionTask::GlobalTimer)
            | Some(ExecutionTask::OnLowWasmMemory) => (false, false),
            Some(ExecutionTask::PausedExecution { .. })
            | Some(ExecutionTask::PausedInstallCode(_)) => (true, false),
            Some(ExecutionTask::AbortedExecution { .. })
            | Some(ExecutionTask::AbortedInstallCode { .. }) => (false, true),
        };

    if effective_canister_is_paused {
        // If there is a DTS execution in progress, we can't execute the subnet message.
        // Note, it does NOT include aborted executions.
        return false;
    }

    // Some heavy methods use round instructions.
    let instructions_reached = round_limits.instructions_reached();

    let permissions = Ic00MethodPermissions::new(method);
    permissions.can_be_executed(
        instructions_reached,
        ongoing_long_install_code,
        effective_canister_is_aborted,
    )
}

/// Based on the type of the subnet message to execute, figure out its
/// instruction limits.
///
/// This is primarily done because upgrading a canister might need to
/// (de)-serialize a large state and thus consume a lot of instructions.
fn get_instruction_limits_for_subnet_message(
    config: &SchedulerConfig,
    msg: &SubnetMessage,
) -> InstructionLimits {
    // The default limits are unused since instruction limits only matter
    // for install code in which case the default limits are overriden.
    let default_limits = InstructionLimits::new(NumInstructions::from(0), NumInstructions::from(0));
    let method_name = match &msg {
        SubnetMessage::Response { .. } => {
            return default_limits;
        }
        SubnetMessage::Ingress(ingress) => &ingress.method_name,
        SubnetMessage::Request(request) => &request.method_name,
    };

    use Ic00Method::*;
    match Ic00Method::from_str(method_name) {
        Ok(method) => match method {
            CanisterStatus
            | CanisterInfo
            | CanisterMetadata
            | CreateCanister
            | DeleteCanister
            | DepositCycles
            | ECDSAPublicKey
            | RawRand
            | HttpRequest
            | FlexibleHttpRequest
            | SetupInitialDKG
            | SignWithECDSA
            | ReshareChainKey
            | SchnorrPublicKey
            | SignWithSchnorr
            | VetKdPublicKey
            | VetKdDeriveKey
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
            | SubnetInfo
            | FetchCanisterLogs
            | ProvisionalCreateCanisterWithCycles
            | ProvisionalTopUpCanister
            | UploadChunk
            | StoredChunks
            | ClearChunkStore
            | TakeCanisterSnapshot
            | LoadCanisterSnapshot
            | ListCanisterSnapshots
            | DeleteCanisterSnapshot
            | ReadCanisterSnapshotMetadata
            | ReadCanisterSnapshotData
            | UploadCanisterSnapshotMetadata
            | UploadCanisterSnapshotData
            | RenameCanister => default_limits,
            InstallCode | InstallChunkedCode => InstructionLimits::new(
                config.max_instructions_per_install_code,
                config.max_instructions_per_install_code_slice,
            ),
        },
        Err(_) => default_limits,
    }
}

/// If the canister has a heartbeat method or an active global timer; and the
/// "next scheduled method" is `Heartbeat` or `GlobalTimer`, respectively; then
/// it enqueues the respective task and the other of the two tasks, if
/// applicable; and adds the canister ID to `heartbeat_and_timer_canisters`.
/// Otherwise, or if the task at the front of the queue is a hook, does nothing.
fn maybe_add_heartbeat_or_global_timer_tasks(
    canister: &mut CanisterState,
    has_heartbeat: bool,
    has_active_timer: bool,
    heartbeat_and_timer_canisters: &mut BTreeSet<CanisterId>,
) {
    for _ in 0..NextScheduledMethod::iter().count() {
        let method_chosen = is_next_method_chosen(
            canister,
            has_heartbeat,
            has_active_timer,
            heartbeat_and_timer_canisters,
        );

        canister.inc_next_scheduled_method();

        if method_chosen {
            break;
        }
    }
}

/// If the next execution method (`Message`, `Heartbeat` or `GlobalTimer) may be
/// scheduled, it is added to the front of the canister's task queue, the
/// canister ID is added to `heartbeat_and_timer_canisters` and `true` is
/// returned. Otherwise, no mutations are made and `false` is returned.
///
/// If either `Heartbeat` or `GlobalTimer` is enqueued, then the other one is
/// also enqueued in the second position, if it may be scheduled.
///
/// If the task on the front of the task queue is hook, it must be executed next.
fn is_next_method_chosen(
    canister: &mut CanisterState,
    has_heartbeat: bool,
    has_active_timer: bool,
    heartbeat_and_timer_canisters: &mut BTreeSet<CanisterId>,
) -> bool {
    if canister
        .system_state
        .task_queue
        .front()
        .is_some_and(|task| task.is_hook())
    {
        return true;
    }

    match canister.get_next_scheduled_method() {
        NextScheduledMethod::Message => canister.has_input(),

        NextScheduledMethod::Heartbeat => {
            if has_heartbeat {
                enqueue_tasks(
                    ExecutionTask::Heartbeat,
                    has_active_timer.then_some(ExecutionTask::GlobalTimer),
                    canister,
                );
                heartbeat_and_timer_canisters.insert(canister.canister_id());
            }
            has_heartbeat
        }

        NextScheduledMethod::GlobalTimer => {
            if has_active_timer {
                enqueue_tasks(
                    ExecutionTask::GlobalTimer,
                    has_heartbeat.then_some(ExecutionTask::Heartbeat),
                    canister,
                );
                heartbeat_and_timer_canisters.insert(canister.canister_id());
            }
            has_active_timer
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
        canister.system_state.task_queue.enqueue(other_task);
    }

    canister.system_state.task_queue.enqueue(task);
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

/// Aggregator and observer of per-canister ingress queue latencies.
struct CanisterIngressQueueLatencies {
    /// Per canister observed ingress message latency sum and count.
    latencies: BTreeMap<PrincipalId, (f64, usize)>,
    /// Current block time.
    time: Time,
    /// Histogram to observe the latencies.
    histogram: Histogram,
}

impl CanisterIngressQueueLatencies {
    fn new(time: Time, histogram: Histogram) -> Self {
        Self {
            latencies: BTreeMap::new(),
            time,
            histogram,
        }
    }

    /// Records the ingress queue latency of a message iff it is transitioning from
    /// `Received` to some other state (i.e. when popped from the ingress queue).
    fn on_ingress_status_changed(&mut self, old_status: Arc<IngressStatus>) {
        if let IngressStatus::Known {
            receiver,
            user_id: _,
            time,
            state: IngressState::Received,
        } = &*old_status
        {
            let (latency, count) = self.latencies.entry(*receiver).or_default();
            *latency += self.time.saturating_duration_since(*time).as_secs_f64();
            *count += 1;
        }
    }
}

impl Drop for CanisterIngressQueueLatencies {
    /// Observes the average ingress queue latency of each canister at the end of
    /// the round.
    fn drop(&mut self) {
        for (latency, count) in self.latencies.values() {
            self.histogram.observe(*latency / *count as f64);
        }
    }
}
