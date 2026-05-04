use super::{
    SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN, SCHEDULER_CORES_INVARIANT_BROKEN,
    SchedulerMetrics,
};
use crate::util::debug_assert_or_critical_error;
use ic_base_types::{CanisterId, NumBytes};
use ic_config::flag_status::FlagStatus;
use ic_logger::{ReplicaLogger, error};
use ic_replicated_state::canister_state::NextExecution;
use ic_replicated_state::{CanisterPriority, CanisterState, ReplicatedState};
use ic_types::{AccumulatedPriority, ComputeAllocation, ExecutionRound, NumInstructions};
use ic_utils::iter::left_outer_join;
use more_asserts::debug_assert_gt;
use num_traits::SaturatingSub;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A fixed multiplier for accumulated priority, one order of magnitude larger
/// than the maximum number of canisters, so we can meaningfully divide 1% of
/// free capacity among them.
pub(super) const MULTIPLIER: i64 = 1_000_000;

const ZERO: AccumulatedPriority = AccumulatedPriority::new(0);

/// 1% in accumulated priority.
#[allow(clippy::identity_op)]
const ONE_PERCENT: AccumulatedPriority = AccumulatedPriority::new(1 * MULTIPLIER);

/// 100% in accumulated priority.
pub(super) const ONE_HUNDRED_PERCENT: AccumulatedPriority =
    AccumulatedPriority::new(100 * MULTIPLIER);

const fn from_ca(ca: ComputeAllocation) -> AccumulatedPriority {
    AccumulatedPriority::new(ca.as_percent() as i64 * MULTIPLIER)
}

/// Round metrics required to prioritize a canister.
#[derive(Clone, Eq, PartialEq, Debug)]
pub(super) struct CanisterRoundState {
    /// Copy of canister ID.
    canister_id: CanisterId,
    /// The canister's `accumulated_priority`. Plus an extra `compute_allocation`,
    /// applied at the beginning of the round to prioritize canisters with higher
    /// compute allocation.
    accumulated_priority: AccumulatedPriority,
    /// Copy of the canister's `SchedulerState::compute_allocation`.
    compute_allocation: AccumulatedPriority,
    /// Number of rounds during which the current long execution has executed at
    /// least one slice.
    executed_rounds: i64,
    /// The round when the current long execution started. `None` means the canister
    /// is not in a long execution.
    long_execution_start_round: Option<ExecutionRound>,
}

impl CanisterRoundState {
    pub fn new(canister: &CanisterState, canister_priority: &CanisterPriority) -> Self {
        // Ensure that `long_execution_start_round` matches the canister state.
        debug_assert_eq!(
            canister.has_long_execution(),
            canister_priority.long_execution_start_round.is_some(),
            "canister: {:?}, task_queue: {:?}, canister_priority: {:?}",
            canister.canister_id(),
            canister.system_state.task_queue,
            canister_priority,
        );

        let compute_allocation = from_ca(canister.compute_allocation());
        Self {
            canister_id: canister.canister_id(),
            accumulated_priority: canister_priority.accumulated_priority + compute_allocation,
            compute_allocation,
            executed_rounds: canister_priority.executed_rounds,
            long_execution_start_round: canister_priority.long_execution_start_round,
        }
    }

    pub(super) fn canister_id(&self) -> CanisterId {
        self.canister_id
    }
}

impl Ord for CanisterRoundState {
    fn cmp(&self, other: &Self) -> Ordering {
        // First, sort long executions before new.
        match (
            self.long_execution_start_round,
            other.long_execution_start_round,
        ) {
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,

            // Among new executions, sort by AP descending and break ties by canister ID.
            (None, None) => other
                .accumulated_priority
                .cmp(&self.accumulated_priority)
                .then_with(|| self.canister_id.cmp(&other.canister_id)),

            // Among long executions, sort by executed rounds; AP descending; start round
            // ascending; then break ties by canister ID.
            //
            // An aborted execution (executed rounds == 0) is considered to have the same
            // priority as a newly started long execution (executed rounds == 1). This is to
            // avoid starvation of aborted executions.
            (Some(self_start_round), Some(other_start_round)) => other
                .executed_rounds
                .max(1)
                .cmp(&self.executed_rounds.max(1))
                .then_with(|| other.accumulated_priority.cmp(&self.accumulated_priority))
                .then_with(|| self_start_round.cmp(&other_start_round))
                .then_with(|| self.canister_id.cmp(&other.canister_id)),
        }
    }
}

impl PartialOrd for CanisterRoundState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Immutable configuration for a round.
#[derive(Debug)]
struct Config {
    /// Total number of scheduler cores.
    scheduler_cores: usize,
    /// Heap delta debit threshold above which a canister is suspended for the round.
    heap_delta_rate_limit: NumBytes,
    /// Install code instruction debit threshold above which a canister is suspended
    /// for the round.
    install_code_rate_limit: NumInstructions,
}

/// Schedule for one iteration: used to partition canisters to cores and to
/// query iteration-specific values.
#[derive(Debug)]
pub struct IterationSchedule {
    /// Ordered canister IDs. First `long_executions_count` are long executions, the
    /// rest are new.
    schedule: Vec<CanisterId>,
    /// Number of scheduler cores.
    scheduler_cores: usize,
    /// Number of cores reserved for long executions.
    long_execution_cores: usize,
    /// Number of canisters with long executions.
    long_executions_count: usize,
}

impl IterationSchedule {
    /// Partitions the executable canisters to the available cores for execution.
    #[allow(clippy::type_complexity)]
    pub fn partition_canisters_to_cores(
        &self,
        mut canisters: BTreeMap<CanisterId, Arc<CanisterState>>,
    ) -> (
        Vec<Vec<Arc<CanisterState>>>,
        BTreeMap<CanisterId, Arc<CanisterState>>,
    ) {
        let mut canisters_partitioned_by_cores = vec![vec![]; self.scheduler_cores];
        let long_execution_cores = self.long_execution_cores.min(self.long_executions_count);
        let mut idx = 0;

        for canister_id in self.schedule.iter().take(long_execution_cores) {
            let canister_state = canisters.remove(canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx += 1;
        }
        let new_execution_cores = self.scheduler_cores - long_execution_cores;
        debug_assert_gt!(new_execution_cores, 0);
        for canister_id in self.schedule.iter().skip(self.long_executions_count) {
            let canister_state = canisters.remove(canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx = long_execution_cores
                + (idx - long_execution_cores + 1) % new_execution_cores.max(1);
        }
        for canister_id in self
            .schedule
            .iter()
            .take(self.long_executions_count)
            .skip(long_execution_cores)
        {
            let canister_state = canisters.remove(canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx = (idx + 1) % self.scheduler_cores;
        }

        (canisters_partitioned_by_cores, canisters)
    }

    /// Returns `true` if no canisters were scheduled this iteration.
    pub fn is_empty(&self) -> bool {
        self.schedule.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &CanisterId> {
        self.schedule.iter()
    }
}

/// Round-level schedule and accounting: builds the iteration schedule each iteration,
/// accumulates round-wide state, and updates priorities at the end of the round.
#[derive(Debug)]
pub struct RoundSchedule {
    /// Immutable configuration for this round.
    config: Config,

    /// Number of cores dedicated for long executions.
    long_execution_cores: usize,
    /// Ordered Canister IDs with new executions.
    ordered_new_execution_canister_ids: Vec<CanisterId>,
    /// Ordered Canister IDs with long executions.
    ordered_long_execution_canister_ids: Vec<CanisterId>,

    /// Canisters that were scheduled.
    scheduled_canisters: BTreeSet<CanisterId>,
    /// Canisters that advanced or completed a message execution.
    executed_canisters: BTreeSet<CanisterId>,
    /// Canisters that completed message executions.
    canisters_with_completed_messages: BTreeSet<CanisterId>,
    /// Canisters that got a "full execution" (scheduled first or consumed all
    /// inputs). This also includes canisters that were scheduled first but whose
    /// long execution was later aborted.
    fully_executed_canisters: BTreeSet<CanisterId>,
    /// Canisters that were heap delta rate-limited in at least one iteration.
    rate_limited_canisters: BTreeSet<CanisterId>,
}

impl RoundSchedule {
    pub fn new(
        scheduler_cores: usize,
        heap_delta_rate_limit: NumBytes,
        rate_limiting_of_heap_delta: FlagStatus,
        install_code_rate_limit: NumInstructions,
        rate_limiting_of_instructions: FlagStatus,
        long_execution_cores: usize,
        ordered_new_execution_canister_ids: Vec<CanisterId>,
        ordered_long_execution_canister_ids: Vec<CanisterId>,
    ) -> Self {
        let config = Config {
            scheduler_cores,
            heap_delta_rate_limit: if rate_limiting_of_heap_delta == FlagStatus::Enabled {
                heap_delta_rate_limit
            } else {
                // Disabled is the same as no rate limit.
                NumBytes::new(u64::MAX)
            },
            install_code_rate_limit: if rate_limiting_of_instructions == FlagStatus::Enabled {
                install_code_rate_limit
            } else {
                // Disabled is the same as no rate limit.
                NumInstructions::new(u64::MAX)
            },
        };
        Self {
            config,
            long_execution_cores: long_execution_cores
                .min(ordered_long_execution_canister_ids.len()),
            ordered_new_execution_canister_ids,
            ordered_long_execution_canister_ids,
            scheduled_canisters: BTreeSet::new(),
            executed_canisters: BTreeSet::new(),
            canisters_with_completed_messages: BTreeSet::new(),
            fully_executed_canisters: BTreeSet::new(),
            rate_limited_canisters: BTreeSet::new(),
        }
    }

    /// Marks idle canisters in front of the schedule as fully executed.
    pub fn charge_idle_canisters(
        &mut self,
        canisters: &mut BTreeMap<CanisterId, Arc<CanisterState>>,
    ) {
        for canister_id in self.ordered_new_execution_canister_ids.iter() {
            let canister = canisters.get(canister_id);
            if let Some(canister) = canister {
                let next_execution = canister.next_execution();
                match next_execution {
                    NextExecution::None => {
                        self.fully_executed_canisters.insert(canister.canister_id());
                    }
                    // Skip install code canisters.
                    NextExecution::ContinueInstallCode => {}

                    NextExecution::StartNew | NextExecution::ContinueLong => {
                        // Stop searching after the first non-idle canister.
                        break;
                    }
                }
            }
        }
    }

    /// Returns an iteration schedule covering active canisters only.
    pub fn start_iteration(
        &mut self,
        state: &mut ReplicatedState,
        is_first_iteration: bool,
    ) -> IterationSchedule {
        let (canister_states, _) = state.canisters_and_schedule_mut();

        // Collect all active canisters and their next executions.
        let canister_next_executions: BTreeMap<_, _> = canister_states
            .iter()
            .filter_map(|(canister_id, canister)| {
                if canister.scheduler_state.heap_delta_debit >= self.config.heap_delta_rate_limit {
                    // Record and filter out rate limited canisters.
                    self.rate_limited_canisters.insert(*canister_id);
                    self.scheduled_canisters.insert(*canister_id);
                    return None;
                }

                let next_execution = canister.next_execution();
                match next_execution {
                    // Filter out canisters with no messages or with paused installations.
                    NextExecution::None | NextExecution::ContinueInstallCode => None,

                    NextExecution::StartNew | NextExecution::ContinueLong => {
                        self.scheduled_canisters.insert(*canister_id);
                        Some((canister_id, next_execution))
                    }
                }
            })
            .collect();

        let mut schedule: Vec<CanisterId> = self
            .ordered_long_execution_canister_ids
            .iter()
            .filter(
                |canister_id| match canister_next_executions.get(canister_id) {
                    Some(NextExecution::ContinueLong) => true,

                    // We expect long execution, but there is none,
                    // so the long execution was finished in the
                    // previous inner round.
                    //
                    // We should avoid scheduling this canister to:
                    // 1. Avoid the canister to bypass the logic in
                    //    `apply_scheduling_strategy()`.
                    // 2. Charge canister for resources at the end
                    //    of the round.
                    Some(NextExecution::StartNew) => false,

                    None // No such canister. Should not happen.
                        | Some(NextExecution::None) // Idle canister.
                        | Some(NextExecution::ContinueInstallCode) // Subnet message.
                         => false,
                },
            )
            .cloned()
            .collect();
        let long_executions_count = schedule.len();
        let long_execution_cores = self.long_execution_cores.min(long_executions_count);

        schedule.extend(
            self.ordered_new_execution_canister_ids
                .iter()
                .filter(|canister_id| canister_next_executions.contains_key(canister_id)),
        );

        if is_first_iteration {
            // First iteration: mark the first canister on each core as fully executed.
            let mut observe_scheduled_as_first = |canister: &CanisterId| {
                self.fully_executed_canisters.insert(*canister);
                Arc::make_mut(canister_states.get_mut(canister).unwrap())
                    .system_state
                    .canister_metrics_mut()
                    .observe_scheduled_as_first();
            };

            schedule
                .iter()
                .take(long_execution_cores)
                .for_each(|canister| {
                    observe_scheduled_as_first(canister);
                });
            schedule
                .iter()
                .skip(long_executions_count)
                .take(self.config.scheduler_cores - long_execution_cores)
                .for_each(|canister| {
                    observe_scheduled_as_first(canister);
                });
        }

        IterationSchedule {
            schedule,
            scheduler_cores: self.config.scheduler_cores,
            long_execution_cores,
            long_executions_count,
        }
    }

    /// Updates round state (executed, fully executed, completed message canisters)
    /// after an iteration.
    pub fn end_iteration(
        &mut self,
        state: &mut ReplicatedState,
        executed_canisters: &BTreeSet<CanisterId>,
        canisters_with_completed_messages: &BTreeSet<CanisterId>,
        low_cycle_balance_canisters: &BTreeSet<CanisterId>,
        current_round: ExecutionRound,
    ) {
        self.executed_canisters.extend(executed_canisters);
        self.canisters_with_completed_messages
            .extend(canisters_with_completed_messages);

        // If a canister has completed a long execution, clear its start round.
        //
        // A canister may run out of cycles while in a long execution (e.g. if making
        // calls). Also include low cycle balance canisters.
        for canister_id in canisters_with_completed_messages.union(low_cycle_balance_canisters) {
            state
                .canister_priority_mut(*canister_id)
                .long_execution_start_round = None;
        }

        for canister_id in executed_canisters.union(low_cycle_balance_canisters) {
            match state
                .canister_state(canister_id)
                .map(|canister| canister.next_execution())
                .unwrap_or(NextExecution::None)
            {
                // Completed all messages.
                NextExecution::None => {
                    self.fully_executed_canisters.insert(*canister_id);
                }
                // Completed a long execution slice.
                NextExecution::ContinueLong => {
                    self.fully_executed_canisters.insert(*canister_id);
                    state
                        .canister_priority_mut(*canister_id)
                        .long_execution_start_round
                        .get_or_insert(current_round);
                }
                NextExecution::StartNew => {}
                NextExecution::ContinueInstallCode => {
                    unreachable!()
                }
            }
        }
    }

    /// Updates canister priorities at the end of the round.
    ///
    /// * Grants canisters their compute allocations; charges for full executions;
    ///   then calculates the subnet-wide free allocation and distributes it.
    /// * Charges for executed rounds where possible (no long execution).
    /// * Observes round-level metrics.
    pub fn finish_round(
        &self,
        state: &mut ReplicatedState,
        current_round: ExecutionRound,
        metrics: &SchedulerMetrics,
    ) {
        let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();

        // Update fully executed canisters' priorities.
        for canister_id in self.fully_executed_canisters.iter() {
            let canister_priority = subnet_schedule.get_mut(*canister_id);
            canister_priority.executed_rounds += 1;
            canister_priority.last_full_execution_round = current_round;
        }

        // Grant all canisters their compute allocation; charge for executed rounds
        // where possible (no long execution); and calculate the subnet-wide free
        // allocation (as the deviation from zero of all canisters' total accumulated
        // priority, including executed rounds).
        let mut free_allocation = ZERO;
        for canister in canister_states.values() {
            // Add the canister to the subnet schedule, if not already there.
            let canister_priority = subnet_schedule.get_mut(canister.canister_id());

            canister_priority.accumulated_priority += from_ca(canister.compute_allocation());

            // On message completion (or short execution), charge for the executed rounds.
            if canister_priority.executed_rounds > 0
                && (!canister.has_long_execution()
                    || self
                        .canisters_with_completed_messages
                        .contains(&canister.canister_id()))
            {
                canister_priority.accumulated_priority -=
                    ONE_HUNDRED_PERCENT * canister_priority.executed_rounds;
                canister_priority.executed_rounds = 0;
            }

            free_allocation -= canister_priority.accumulated_priority
                - ONE_HUNDRED_PERCENT * canister_priority.executed_rounds;
        }

        self.grant_heap_delta_and_install_code_credits(state, metrics);

        // Only ever apply positive free allocation. If the sum of all canisters'
        // accumulated priorities (including executed rounds) is somehow positive
        // (although this should never happen), then there is simply no free allocation
        // to distribute.
        if free_allocation.get() < 0 {
            free_allocation = ZERO;
        }

        // Fully distribute the free allocation among all canisters, ensuring that we
        // end up with exactly zero at the end of the loop.
        let (_, subnet_schedule) = state.canisters_and_schedule_mut();
        let mut remaining_canisters = subnet_schedule.len() as i64;
        // We called `SubnetSchedule::get_mut()` for all canisters above (which inserts
        // a default priority when not found), so this iteration covers all canisters.
        for (_, canister_priority) in subnet_schedule.iter_mut() {
            let canister_free_allocation = free_allocation / remaining_canisters;
            canister_priority.accumulated_priority += canister_free_allocation;
            free_allocation -= canister_free_allocation;

            remaining_canisters -= 1;
        }

        self.observe_round_metrics(state, current_round, metrics);
    }

    /// Deducts the heap delta and install code rate limits from the canisters'
    /// respective debits.
    fn grant_heap_delta_and_install_code_credits(
        &self,
        state: &mut ReplicatedState,
        metrics: &SchedulerMetrics,
    ) {
        let (canister_states, _) = state.canisters_and_schedule_mut();
        for canister in canister_states.values_mut() {
            let heap_delta_debit = canister.scheduler_state.heap_delta_debit.get();
            metrics
                .canister_heap_delta_debits
                .observe(heap_delta_debit as f64);
            if heap_delta_debit > 0 {
                let canister = Arc::make_mut(canister);
                canister.scheduler_state.heap_delta_debit = canister
                    .scheduler_state
                    .heap_delta_debit
                    .saturating_sub(&self.config.heap_delta_rate_limit);
            }

            let install_code_debit = canister.scheduler_state.install_code_debit.get();
            metrics
                .canister_install_code_debits
                .observe(install_code_debit as f64);
            if install_code_debit > 0 {
                let canister = Arc::make_mut(canister);
                canister.scheduler_state.install_code_debit = canister
                    .scheduler_state
                    .install_code_debit
                    .saturating_sub(&self.config.install_code_rate_limit);
            }
        }
    }

    /// Exports round-level metrics derived from this schedule's accumulators.
    fn observe_round_metrics(
        &self,
        state: &ReplicatedState,
        current_round: ExecutionRound,
        metrics: &SchedulerMetrics,
    ) {
        // Export the age of all scheduled canisters.
        for canister_id in self.scheduled_canisters() {
            let last_full_execution_round = if self.fully_executed_canisters.contains(canister_id) {
                // `CanisterPriority` might have been dropped, don't look it up.
                current_round
            } else {
                state
                    .canister_priority(canister_id)
                    .last_full_execution_round
            };
            // Ignore canisters that were just added to the schedule, they skew the metric.
            if last_full_execution_round.get() != 0 {
                let canister_age = current_round.get() - last_full_execution_round.get();
                metrics.canister_age.observe(canister_age as f64);
            }
        }

        metrics
            .executable_canisters_per_round
            .observe(self.scheduled_canisters.len() as f64);
        metrics
            .executed_canisters_per_round
            .observe(self.executed_canisters.len() as f64);
        metrics
            .heap_delta_rate_limited_canisters_per_round
            .observe(self.rate_limited_canisters.len() as f64);
    }

    /// Returns scheduler compute capacity in percent.
    ///
    /// For the DTS scheduler, it's `(number of cores - 1) * 100%`
    pub(crate) fn compute_capacity_percent(scheduler_cores: usize) -> usize {
        // Note: the DTS scheduler requires at least 2 scheduler cores
        (scheduler_cores - 1) * 100
    }

    /// Returns scheduler compute capacity in accumulated priority.
    ///
    /// For the DTS scheduler, it's `(number of cores - 1) * 100%`
    fn compute_capacity(scheduler_cores: usize) -> AccumulatedPriority {
        ONE_HUNDRED_PERCENT * (scheduler_cores as i64 - 1)
    }

    /// Canisters that were scheduled this round.
    pub fn scheduled_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.scheduled_canisters
    }

    /// Orders the canisters and updates their accumulated priorities according to
    /// the strategy described in RUN-58.
    ///
    /// A shorter description of the scheduling strategy is available in the note
    /// section about [Scheduler and AccumulatedPriority] in types/src/lib.rs
    pub(super) fn apply_scheduling_strategy(
        state: &mut ReplicatedState,
        scheduler_cores: usize,
        heap_delta_rate_limit: NumBytes,
        rate_limiting_of_heap_delta: FlagStatus,
        install_code_rate_limit: NumInstructions,
        rate_limiting_of_instructions: FlagStatus,
        current_round: ExecutionRound,
        accumulated_priority_reset_interval: ExecutionRound,
        metrics: &SchedulerMetrics,
        logger: &ReplicaLogger,
    ) -> RoundSchedule {
        let number_of_canisters = state.canister_states().len();

        // Total allocatable compute capacity.
        // As one scheduler core is reserved to guarantee long executions progress,
        // compute capacity is `(scheduler_cores - 1) * 100`
        let compute_capacity = Self::compute_capacity(scheduler_cores);

        // Sum of all canisters compute allocation.
        // It's guaranteed to be less than `compute_capacity`
        // by `validate_compute_allocation()`.
        // This corresponds to |a| in Scheduler Analysis.
        let mut total_compute_allocation = ZERO;

        // This corresponds to the vector p in the Scheduler Analysis document.
        let mut round_states = Vec::with_capacity(number_of_canisters);

        // Reset the accumulated priorities periodically.
        // We want to reset the scheduler regularly to safely support changes in the set
        // of canisters and their compute allocations.
        let is_reset_round = current_round
            .get()
            .is_multiple_of(accumulated_priority_reset_interval.get());
        let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();
        if is_reset_round {
            for &canister_id in canister_states.keys() {
                let canister_priority = subnet_schedule.get_mut(canister_id);
                canister_priority.accumulated_priority = Default::default();
            }
        }

        // Collect the priority of the canisters for this round.
        let mut accumulated_priority_invariant = ZERO;
        let mut accumulated_priority_deviation = 0.0;
        for (_, canister, canister_priority) in
            left_outer_join(canister_states.iter_mut(), subnet_schedule.iter())
        {
            let canister_priority = canister_priority.unwrap_or(&CanisterPriority::DEFAULT);
            let compute_allocation = from_ca(canister.compute_allocation());
            let accumulated_priority = canister_priority.accumulated_priority;
            round_states.push(CanisterRoundState::new(canister, canister_priority));

            total_compute_allocation += compute_allocation;
            accumulated_priority_invariant += accumulated_priority;
            accumulated_priority_deviation +=
                accumulated_priority.get() as f64 * accumulated_priority.get() as f64;
            if canister.has_input() {
                let canister = Arc::make_mut(canister);
                canister
                    .system_state
                    .canister_metrics_mut()
                    .observe_round_scheduled();
            }
        }
        // Assert there is at least `1%` of free capacity to distribute across canisters.
        // It's guaranteed by `validate_compute_allocation()`
        debug_assert_or_critical_error!(
            total_compute_allocation + ONE_PERCENT <= compute_capacity,
            metrics.scheduler_compute_allocation_invariant_broken,
            logger,
            "{}: Total compute allocation {}% must be less than compute capacity {}%",
            SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN,
            total_compute_allocation,
            compute_capacity
        );
        // Observe accumulated priority metrics
        metrics
            .scheduler_accumulated_priority_invariant
            .set(accumulated_priority_invariant.get());
        metrics
            .scheduler_accumulated_priority_deviation
            .set((accumulated_priority_deviation / number_of_canisters as f64).sqrt());

        let free_capacity_per_canister = compute_capacity.saturating_sub(&total_compute_allocation)
            / number_of_canisters.max(1) as i64;

        // Total compute allocation (including free allocation) of all canisters with
        // long executions.
        let mut long_executions_compute_allocation = ZERO;
        let mut number_of_long_executions = 0;
        for rs in round_states.iter_mut() {
            // De-facto compute allocation includes bonus allocation
            let factual = rs.compute_allocation + free_capacity_per_canister;
            // Count long executions and sum up their compute allocation.
            if rs.long_execution_start_round.is_some() {
                long_executions_compute_allocation += factual;
                number_of_long_executions += 1;
            }
        }

        // Compute the number of long execution cores by dividing
        // `long_execution_compute_allocation` by `100%` and rounding up
        // (as one scheduler core is reserved to guarantee long executions progress).
        let long_execution_cores = ((long_executions_compute_allocation + ONE_HUNDRED_PERCENT
            - AccumulatedPriority::new(1))
            / ONE_HUNDRED_PERCENT) as usize;
        // If there are long executions, the `long_execution_cores` must be non-zero.
        debug_assert_or_critical_error!(
            number_of_long_executions == 0 || long_execution_cores > 0,
            metrics.scheduler_cores_invariant_broken,
            logger,
            "{}: Number of long execution cores {} must be more than 0",
            SCHEDULER_CORES_INVARIANT_BROKEN,
            long_execution_cores,
        );
        // As one scheduler core is reserved, the `long_execution_cores` is always
        // less than `scheduler_cores`
        debug_assert_or_critical_error!(
            long_execution_cores < scheduler_cores,
            metrics.scheduler_cores_invariant_broken,
            logger,
            "{}: Number of long execution cores {} must be less than scheduler cores {}",
            SCHEDULER_CORES_INVARIANT_BROKEN,
            long_execution_cores,
            scheduler_cores
        );

        round_states.sort();
        RoundSchedule::new(
            scheduler_cores,
            heap_delta_rate_limit,
            rate_limiting_of_heap_delta,
            install_code_rate_limit,
            rate_limiting_of_instructions,
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
        )
    }
}

/// Returns true if the canister exports the heartbeat method.
pub(super) fn has_heartbeat(canister: &CanisterState) -> bool {
    canister.exports_heartbeat_method()
}

/// Returns true if the canister exports the global timer method and the global
/// timer has reached its deadline.
pub(super) fn has_active_timer(canister: &CanisterState, now: ic_types::Time) -> bool {
    canister.exports_global_timer_method()
        && canister.system_state.global_timer.has_reached_deadline(now)
}
