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
use ic_types::{AccumulatedPriority, ComputeAllocation, ExecutionRound, LongExecutionMode};
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
const ONE_HUNDRED_PERCENT: AccumulatedPriority = AccumulatedPriority::new(100 * MULTIPLIER);

const fn from_ca(ca: ComputeAllocation) -> AccumulatedPriority {
    AccumulatedPriority::new(ca.as_percent() as i64 * MULTIPLIER)
}

/// Round metrics required to prioritize a canister.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CanisterRoundState {
    /// Copy of Canister ID
    canister_id: CanisterId,
    /// Copy of Canister CanisterPriority::accumulated_priority
    accumulated_priority: AccumulatedPriority,
    /// Copy of Canister SchedulerState::compute_allocation
    compute_allocation: AccumulatedPriority,
    /// Copy of Canister CanisterPriority::long_execution_mode
    long_execution_mode: LongExecutionMode,
    /// True when there is an aborted or paused long update execution.
    /// Note: this doesn't include paused or aborted install codes.
    has_aborted_or_paused_execution: bool,
}

impl CanisterRoundState {
    pub fn new(canister: &CanisterState, canister_priority: &CanisterPriority) -> Self {
        let compute_allocation = from_ca(canister.compute_allocation());
        Self {
            canister_id: canister.canister_id(),
            // Compute allocation is applied at the beginning of the round. All
            // else being equal, schedule canisters with higher compute allocation
            // first.
            accumulated_priority: canister_priority.accumulated_priority + compute_allocation,
            compute_allocation,
            long_execution_mode: canister_priority.long_execution_mode,
            has_aborted_or_paused_execution: canister.has_aborted_execution()
                || canister.has_paused_execution(),
        }
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    pub fn is_long_execution(&self) -> bool {
        self.has_aborted_or_paused_execution
    }
}

impl Ord for CanisterRoundState {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort by:
        //  1. Long execution mode, reversed (Prioritized -> Opportunistic)
        other
            .long_execution_mode
            .cmp(&self.long_execution_mode)
            //  2. Long execution (long execution -> new execution)
            .then(other.is_long_execution().cmp(&self.is_long_execution()))
            //  3. Accumulated priority, descending.
            .then(other.accumulated_priority.cmp(&self.accumulated_priority))
            //  4. Canister ID, ascending.
            .then(self.canister_id.cmp(&other.canister_id))
    }
}

impl PartialOrd for CanisterRoundState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Represents three ordered active Canister ID groups to schedule.
#[derive(Debug, Default)]
struct SchedulingOrder<P, N, R> {
    /// Prioritized long executions.
    prioritized_long_canisters: P,
    /// New executions.
    new_canisters: N,
    /// To be executed when the Canisters from previous two groups are idle.
    opportunistic_long_canisters: R,
}

/// Represents the order in which the Canister IDs are be scheduled
/// during the whole current round.
#[derive(Clone, Debug)]
pub struct RoundSchedule {
    /// Total number of scheduler cores.
    scheduler_cores: usize,
    /// Number of cores dedicated for long executions.
    long_execution_cores: usize,
    /// Ordered Canister IDs with new executions.
    ordered_new_execution_canister_ids: Vec<CanisterId>,
    /// Ordered Canister IDs with long executions.
    ordered_long_execution_canister_ids: Vec<CanisterId>,

    /// Canisters that were scheduled.
    round_scheduled_canisters: BTreeSet<CanisterId>,
    /// Full round: canisters that advanced or completed a message execution.
    executed_canisters: BTreeSet<CanisterId>,
    /// Full round: canisters that completed message executions.
    canisters_with_completed_messages: BTreeSet<CanisterId>,
    /// Canisters that got a "full execution" this round (scheduled first or
    /// consumed all inputs).
    fully_executed_canisters: BTreeSet<CanisterId>,
    /// Canisters that were heap delta rate-limited in at least one iteration.
    rate_limited_canisters: BTreeSet<CanisterId>,
}

impl RoundSchedule {
    pub fn new(
        scheduler_cores: usize,
        long_execution_cores: usize,
        ordered_new_execution_canister_ids: Vec<CanisterId>,
        ordered_long_execution_canister_ids: Vec<CanisterId>,
    ) -> Self {
        RoundSchedule {
            scheduler_cores,
            long_execution_cores: long_execution_cores
                .min(ordered_long_execution_canister_ids.len()),
            ordered_new_execution_canister_ids,
            ordered_long_execution_canister_ids,
            round_scheduled_canisters: BTreeSet::new(),
            executed_canisters: BTreeSet::new(),
            canisters_with_completed_messages: BTreeSet::new(),
            fully_executed_canisters: BTreeSet::new(),
            rate_limited_canisters: BTreeSet::new(),
        }
    }

    fn scheduling_order<'a>(
        &'a self,
        active_round_schedule: &'a ActiveRoundSchedule,
    ) -> SchedulingOrder<
        impl Iterator<Item = &'a CanisterId>,
        impl Iterator<Item = &'a CanisterId>,
        impl Iterator<Item = &'a CanisterId>,
    > {
        SchedulingOrder {
            // To guarantee progress and minimize the potential waste of an abort, top
            // `long_execution_cores` canisters with prioritized long execution mode and highest
            // priority get scheduled on long execution cores.
            prioritized_long_canisters: active_round_schedule
                .ordered_long_execution_canister_ids
                .iter()
                .take(self.long_execution_cores),
            // Canisters with no pending long executions get scheduled across new execution
            // cores according to their round priority as the regular scheduler does. This will
            // guarantee their reservations; and ensure low latency except immediately after a long
            // message execution.
            new_canisters: active_round_schedule
                .ordered_new_execution_canister_ids
                .iter(),
            // Remaining canisters with long pending executions get scheduled across
            // all cores according to their priority order, starting from the next available core onto which a new
            // execution canister would have been scheduled.
            opportunistic_long_canisters: active_round_schedule
                .ordered_long_execution_canister_ids
                .iter()
                .skip(self.long_execution_cores),
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
    pub fn filter_canisters(
        &mut self,
        state: &mut ReplicatedState,
        heap_delta_rate_limit: NumBytes,
        rate_limiting_of_heap_delta: FlagStatus,
    ) -> ActiveRoundSchedule {
        let is_first_iteration = self.round_scheduled_canisters.is_empty();

        let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();

        // Collect all active canisters and their next executions.
        let canister_next_executions: BTreeMap<_, _> = canister_states
            .iter()
            .filter_map(|(canister_id, canister)| {
                if rate_limiting_of_heap_delta == FlagStatus::Enabled
                    && canister.scheduler_state.heap_delta_debit >= heap_delta_rate_limit
                {
                    // Record and filter out rate limited canisters.
                    self.rate_limited_canisters.insert(*canister_id);
                    self.round_scheduled_canisters.insert(*canister_id);
                    return None;
                }

                let next_execution = canister.next_execution();
                match next_execution {
                    // Filter out canisters with no messages or with paused installations.
                    NextExecution::None | NextExecution::ContinueInstallCode => None,

                    NextExecution::StartNew | NextExecution::ContinueLong => {
                        Some((canister_id, next_execution))
                    }
                }
            })
            .collect();

        let ordered_new_execution_canister_ids: Vec<CanisterId> = self
            .ordered_new_execution_canister_ids
            .iter()
            .filter(|canister_id| canister_next_executions.contains_key(canister_id))
            .cloned()
            .collect();

        let ordered_long_execution_canister_ids: Vec<CanisterId> = self
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

        if is_first_iteration {
            // TODO(DSM-103): We should not consider an aborted long execution (e.g. due to
            // exceeding the paused execution limit) as fully executed, even if the canister
            // was scheduled first.

            // First iteration: mark the first canisters on each core as fully executed.
            ordered_long_execution_canister_ids
                .iter()
                .take(self.long_execution_cores)
                .for_each(|canister_id| {
                    self.fully_executed_canisters.insert(*canister_id);

                    // And set prioritized long execution mode for the first `long_execution_cores`
                    // canisters.
                    subnet_schedule.get_mut(*canister_id).long_execution_mode =
                        LongExecutionMode::Prioritized;
                });
            ordered_new_execution_canister_ids
                .iter()
                .take(self.scheduler_cores - self.long_execution_cores)
                .for_each(|canister_id| {
                    self.fully_executed_canisters.insert(*canister_id);
                });
        }

        self.round_scheduled_canisters
            .extend(ordered_new_execution_canister_ids.iter());
        self.round_scheduled_canisters
            .extend(ordered_long_execution_canister_ids.iter());

        ActiveRoundSchedule {
            ordered_new_execution_canister_ids,
            ordered_long_execution_canister_ids,
        }
    }

    /// Partitions the executable Canisters to the available cores for execution.
    ///
    /// Returns the executable Canisters partitioned by cores and a map of
    /// the non-executable Canisters.
    ///
    /// ## Example
    ///
    /// Given a round schedule with:
    ///
    /// * 1 long execution core
    /// * 3 Canisters (ids 1-3) with pending long executions
    /// * 5 Canisters (ids 4-8) with new executions
    ///
    /// The function will produce the following result:
    ///
    /// * Core 1 (long execution core) takes: `CanisterId 1`, `CanisterId 3`
    /// * Core 2 takes: `CanisterId 4`,  `CanisterId 6`, `CanisterId 8`
    /// * Core 3 takes: `CanisterId 5`,  `CanisterId 7`, `CanisterId 2`
    #[allow(clippy::type_complexity)]
    pub(super) fn partition_canisters_to_cores(
        &self,
        mut canisters: BTreeMap<CanisterId, Arc<CanisterState>>,
        active_round_schedule: ActiveRoundSchedule,
    ) -> (
        Vec<Vec<Arc<CanisterState>>>,
        BTreeMap<CanisterId, Arc<CanisterState>>,
    ) {
        let mut canisters_partitioned_by_cores = vec![vec![]; self.scheduler_cores];

        let mut idx = 0;
        let scheduling_order = self.scheduling_order(&active_round_schedule);
        for canister_id in scheduling_order.prioritized_long_canisters {
            let canister_state = canisters.remove(canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx += 1;
        }
        let last_prioritized_long = idx;
        let new_execution_cores = self.scheduler_cores - last_prioritized_long;
        debug_assert_gt!(new_execution_cores, 0);
        for canister_id in scheduling_order.new_canisters {
            let canister_state = canisters.remove(canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx = last_prioritized_long
                + (idx - last_prioritized_long + 1) % new_execution_cores.max(1);
        }
        for canister_id in scheduling_order.opportunistic_long_canisters {
            let canister_state = canisters.remove(canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx = (idx + 1) % self.scheduler_cores;
        }

        (canisters_partitioned_by_cores, canisters)
    }

    pub fn end_iteration(
        &mut self,
        state: &mut ReplicatedState,
        executed_canisters: &BTreeSet<CanisterId>,
        canisters_with_completed_messages: &BTreeSet<CanisterId>,
    ) {
        self.executed_canisters.extend(executed_canisters);
        self.canisters_with_completed_messages
            .extend(canisters_with_completed_messages);

        for canister_id in canisters_with_completed_messages {
            // If a canister has completed a long execution, reset its long execution mode.
            state
                .metadata
                .subnet_schedule
                .get_mut(*canister_id)
                .long_execution_mode = LongExecutionMode::Opportunistic;

            match state
                .canister_state(canister_id)
                .map(|canister| canister.next_execution())
                .unwrap_or(NextExecution::None)
            {
                NextExecution::None => {
                    self.fully_executed_canisters.insert(*canister_id);
                }
                NextExecution::StartNew | NextExecution::ContinueLong => {}
                NextExecution::ContinueInstallCode => {
                    unreachable!()
                }
            }
        }
    }

    pub(super) fn finish_round(
        &self,
        state: &mut ReplicatedState,
        current_round: ExecutionRound,
        metrics: &SchedulerMetrics,
    ) {
        let number_of_canisters = state.canister_states().len();
        let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();

        // Charge canisters for full executions in this round.
        for canister_id in self.fully_executed_canisters.iter() {
            let canister_priority = subnet_schedule.get_mut(*canister_id);
            canister_priority.priority_credit += ONE_HUNDRED_PERCENT;
            canister_priority.last_full_execution_round = current_round;
        }

        fn true_priority(canister_priority: &CanisterPriority) -> AccumulatedPriority {
            canister_priority.accumulated_priority - canister_priority.priority_credit
        }

        // Grant all canisters their compute allocation; apply the priority credit
        // where possible (no long execution); and calculate the subnet-wide free
        // allocation (as the deviation from zero of all canisters' total accumulated
        // priority, including priority credit).
        let mut free_allocation = ZERO;
        for canister in canister_states.values() {
            let canister_priority = subnet_schedule.get_mut(canister.canister_id());
            canister_priority.accumulated_priority += from_ca(canister.compute_allocation());

            let has_aborted_or_paused_execution =
                canister.has_aborted_execution() || canister.has_paused_execution();
            if !has_aborted_or_paused_execution {
                RoundSchedule::apply_priority_credit(canister_priority);
            }

            free_allocation -= true_priority(canister_priority);
        }

        // Only ever apply positive free allocation. If the sum of all canisters'
        // accumulated priorities (including priority credit) is somehow positive
        // (although this should never happen), then there is simply no free allocation
        // to distribute.
        if free_allocation.get() < 0 {
            free_allocation = ZERO;
        }

        // Fully distribute the free allocation among all canisters, ensuring that we
        // end up with exactly zero at the end of the loop.
        let mut accumulated_priority_deviation = 0.0;
        let mut remaining_canisters = number_of_canisters as i64;
        // We called `SubnetSchedule::get_mut()` for all canisters above (which inserts
        // a default priority when not found), so this iteration covers all canisters.
        for (_, canister_priority) in subnet_schedule.iter_mut() {
            let canister_free_allocation = free_allocation / remaining_canisters;

            // Max out at an arbitrary 5 rounds of accumulated priority.
            //
            // Without this, a canister with 100 compute allocation will accumulate 100
            // priority it can then never spend for every round of an aborted DTS execution
            // (priority credit is increased by 100 per round, but reset on abort).
            const AP_ROUNDS_MAX: i64 = 5;
            let canister_free_allocation = std::cmp::min(
                canister_free_allocation,
                ONE_HUNDRED_PERCENT * AP_ROUNDS_MAX - true_priority(canister_priority),
            );

            canister_priority.accumulated_priority += canister_free_allocation;
            free_allocation -= canister_free_allocation;

            let accumulated_priority =
                canister_priority.accumulated_priority.get() as f64 / MULTIPLIER as f64;
            accumulated_priority_deviation += accumulated_priority * accumulated_priority;

            remaining_canisters -= 1;
        }

        metrics
            .scheduler_accumulated_priority_deviation
            .set((accumulated_priority_deviation / subnet_schedule.len() as f64).sqrt());
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

    /// Orders the canisters and updates their accumulated priorities according to
    /// the strategy described in RUN-58.
    ///
    /// A shorter description of the scheduling strategy is available in the note
    /// section about [Scheduler and AccumulatedPriority] in types/src/lib.rs
    pub(super) fn apply_scheduling_strategy(
        state: &mut ReplicatedState,
        scheduler_cores: usize,
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
                canister_priority.priority_credit = Default::default();
            }
        }

        // Collect the priority of the canisters for this round.
        for (_, canister, canister_priority) in
            left_outer_join(canister_states.iter_mut(), subnet_schedule.iter())
        {
            let canister_priority = canister_priority.unwrap_or(&CanisterPriority::DEFAULT);
            let compute_allocation = from_ca(canister.compute_allocation());
            round_states.push(CanisterRoundState::new(canister, canister_priority));

            total_compute_allocation += compute_allocation;
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
            if rs.has_aborted_or_paused_execution {
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

        for canister_id in round_schedule
            .ordered_long_execution_canister_ids
            .iter()
            .take(long_execution_cores)
        {
            state
                .canister_priority_mut(*canister_id)
                .long_execution_mode = LongExecutionMode::Prioritized;
        }

        round_schedule
    }

    /// Applies priority credit and resets long execution mode.
    pub fn apply_priority_credit(canister_priority: &mut CanisterPriority) {
        canister_priority.accumulated_priority -=
            std::mem::take(&mut canister_priority.priority_credit);
        // Aborting a long-running execution moves the canister to the
        // default execution mode because the canister does not have a
        // pending execution anymore.
        canister_priority.long_execution_mode = LongExecutionMode::default();
    }

    /// Canisters that were scheduled.
    pub(super) fn round_scheduled_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.round_scheduled_canisters
    }

    pub(super) fn executed_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.executed_canisters
    }

    /// Canisters that got a "full execution" this round (scheduled first or
    /// consumed all inputs).
    pub(super) fn fully_executed_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.fully_executed_canisters
    }

    /// Canisters that were heap delta rate-limited in at least one iteration.
    pub(super) fn rate_limited_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.rate_limited_canisters
    }
}

/// Schedule for the current iteration, consisting of active canisters only.
pub struct ActiveRoundSchedule {
    /// Ordered Canister IDs with new executions.
    ordered_new_execution_canister_ids: Vec<CanisterId>,
    /// Ordered Canister IDs with long executions.
    ordered_long_execution_canister_ids: Vec<CanisterId>,
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
