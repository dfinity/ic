use std::collections::{BTreeMap, BTreeSet, HashMap};

use ic_base_types::{CanisterId, NumBytes};
use ic_config::flag_status::FlagStatus;
use ic_logger::{ReplicaLogger, error};
use ic_replicated_state::{CanisterState, canister_state::NextExecution};
use ic_types::{AccumulatedPriority, ComputeAllocation, ExecutionRound, LongExecutionMode};

use crate::{
    scheduler::{SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN, SCHEDULER_CORES_INVARIANT_BROKEN},
    util::debug_assert_or_critical_error,
};

use super::SchedulerMetrics;

/// Round metrics required to prioritize a canister.
#[derive(Clone, Debug)]
pub(super) struct CanisterRoundState {
    /// Copy of Canister ID
    pub(super) canister_id: CanisterId,
    /// Copy of Canister SchedulerState::accumulated_priority
    pub(super) accumulated_priority: AccumulatedPriority,
    /// Copy of Canister SchedulerState::compute_allocation
    pub(super) compute_allocation: ComputeAllocation,
    /// Copy of Canister SchedulerState::long_execution_mode
    pub(super) long_execution_mode: LongExecutionMode,
    /// True when there is an aborted or paused long update execution.
    /// Note: this doesn't include paused or aborted install codes.
    pub(super) has_aborted_or_paused_execution: bool,
}

/// Represents three ordered active Canister ID groups to schedule.
/// TODO(RUN-320): remove, as it's not required for regular partitioning
#[derive(Debug, Default)]
pub(super) struct SchedulingOrder<P, N, R> {
    /// Prioritized long executions.
    pub prioritized_long_canister_ids: P,
    /// New executions.
    pub new_canister_ids: N,
    /// To be executed when the Canisters from previous two groups are idle.
    pub opportunistic_long_canister_ids: R,
}

/// Represents the order in which the Canister IDs are be scheduled
/// during the whole current round.
/// TODO(RUN-320): remove, as it's not required for regular partitioning
#[derive(Debug, Default)]
pub struct RoundSchedule {
    /// Total number of scheduler cores.
    pub scheduler_cores: usize,
    /// Number of cores dedicated for long executions.
    pub long_execution_cores: usize,
    // Sum of all canisters compute allocation in percent.
    pub total_compute_allocation_percent: i64,
    /// Ordered Canister IDs with new executions.
    pub ordered_new_execution_canister_ids: Vec<CanisterId>,
    /// Ordered Canister IDs with long executions.
    pub ordered_long_execution_canister_ids: Vec<CanisterId>,
}

impl RoundSchedule {
    pub fn new(
        scheduler_cores: usize,
        long_execution_cores: usize,
        total_compute_allocation_percent: i64,
        ordered_new_execution_canister_ids: Vec<CanisterId>,
        ordered_long_execution_canister_ids: Vec<CanisterId>,
    ) -> Self {
        RoundSchedule {
            scheduler_cores,
            long_execution_cores: long_execution_cores
                .min(ordered_long_execution_canister_ids.len()),
            total_compute_allocation_percent,
            ordered_new_execution_canister_ids,
            ordered_long_execution_canister_ids,
        }
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &CanisterId> {
        self.ordered_long_execution_canister_ids
            .iter()
            .chain(self.ordered_new_execution_canister_ids.iter())
    }

    pub(super) fn scheduling_order(
        &self,
    ) -> SchedulingOrder<
        impl Iterator<Item = &CanisterId>,
        impl Iterator<Item = &CanisterId>,
        impl Iterator<Item = &CanisterId>,
    > {
        SchedulingOrder {
            // To guarantee progress and minimize the potential waste of an abort, top
            // `long_execution_cores` canisters with prioritized long execution mode and highest
            // priority get scheduled on long execution cores.
            prioritized_long_canister_ids: self
                .ordered_long_execution_canister_ids
                .iter()
                .take(self.long_execution_cores),
            // Canisters with no pending long executions get scheduled across new execution
            // cores according to their round priority as the regular scheduler does. This will
            // guarantee their reservations; and ensure low latency except immediately after a long
            // message execution.
            new_canister_ids: self.ordered_new_execution_canister_ids.iter(),
            // Remaining canisters with long pending executions get scheduled across
            // all cores according to their priority order, starting from the next available core onto which a new
            // execution canister would have been scheduled.
            opportunistic_long_canister_ids: self
                .ordered_long_execution_canister_ids
                .iter()
                .skip(self.long_execution_cores),
        }
    }

    /// Marks idle canisters in front of the schedule as fully executed.
    pub fn charge_idle_canisters(
        &self,
        canisters: &mut BTreeMap<CanisterId, CanisterState>,
        fully_executed_canister_ids: &mut BTreeSet<CanisterId>,
        round_id: ExecutionRound,
        is_first_iteration: bool,
    ) {
        for canister_id in self.ordered_new_execution_canister_ids.iter() {
            let canister = canisters.get_mut(canister_id);
            if let Some(canister) = canister {
                let next_execution = canister.next_execution();
                match next_execution {
                    NextExecution::None => {
                        Self::finish_canister_execution(
                            canister,
                            fully_executed_canister_ids,
                            round_id,
                            is_first_iteration,
                            0,
                        );
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

    /// Returns a round schedule covering active canisters only; and the set of
    /// rate limited canisters.
    pub fn filter_canisters(
        &self,
        canisters: &BTreeMap<CanisterId, CanisterState>,
        heap_delta_rate_limit: NumBytes,
        rate_limiting_of_heap_delta: FlagStatus,
    ) -> (Self, Vec<CanisterId>) {
        let mut rate_limited_canister_ids = vec![];

        // Collect all active canisters and their next executions.
        //
        // It is safe to use a `HashMap`, as we'll only be doing lookups.
        let canister_next_executions: HashMap<_, _> = canisters
            .iter()
            .filter_map(|(canister_id, canister)| {
                if rate_limiting_of_heap_delta == FlagStatus::Enabled
                    && canister.scheduler_state.heap_delta_debit >= heap_delta_rate_limit
                {
                    // Record and filter out rate limited canisters.
                    rate_limited_canister_ids.push(*canister_id);
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

        let ordered_new_execution_canister_ids = self
            .ordered_new_execution_canister_ids
            .iter()
            .filter(|canister_id| canister_next_executions.contains_key(canister_id))
            .cloned()
            .collect();

        let ordered_long_execution_canister_ids = self
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

        (
            RoundSchedule::new(
                self.scheduler_cores,
                self.long_execution_cores,
                self.total_compute_allocation_percent,
                ordered_new_execution_canister_ids,
                ordered_long_execution_canister_ids,
            ),
            rate_limited_canister_ids,
        )
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
    pub(super) fn partition_canisters_to_cores(
        &self,
        mut canisters: BTreeMap<CanisterId, CanisterState>,
    ) -> (Vec<Vec<CanisterState>>, BTreeMap<CanisterId, CanisterState>) {
        let mut canisters_partitioned_by_cores = vec![vec![]; self.scheduler_cores];

        let mut idx = 0;
        let scheduling_order = self.scheduling_order();
        for canister_id in scheduling_order.prioritized_long_canister_ids {
            let canister_state = canisters.remove(canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx += 1;
        }
        let last_prioritized_long = idx;
        let new_execution_cores = self.scheduler_cores - last_prioritized_long;
        debug_assert!(new_execution_cores > 0);
        for canister_id in scheduling_order.new_canister_ids {
            let canister_state = canisters.remove(canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx = last_prioritized_long
                + (idx - last_prioritized_long + 1) % new_execution_cores.max(1);
        }
        for canister_id in scheduling_order.opportunistic_long_canister_ids {
            let canister_state = canisters.remove(canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx = (idx + 1) % self.scheduler_cores;
        }

        (canisters_partitioned_by_cores, canisters)
    }

    pub fn finish_canister_execution(
        canister: &mut CanisterState,
        fully_executed_canister_ids: &mut BTreeSet<CanisterId>,
        round_id: ExecutionRound,
        is_first_iteration: bool,
        rank: usize,
    ) {
        let full_message_execution = match canister.next_execution() {
            NextExecution::None => true,
            NextExecution::StartNew => false,
            // We just finished a full slice of executions.
            NextExecution::ContinueLong => true,
            NextExecution::ContinueInstallCode => false,
        };
        let scheduled_first = is_first_iteration && rank == 0;

        // The very first canister is considered to have a full execution round for
        // scheduling purposes even if it did not complete within the round.
        if full_message_execution || scheduled_first {
            canister.scheduler_state.last_full_execution_round = round_id;

            // We schedule canisters (as opposed to individual messages),
            // and we charge for every full execution round.
            fully_executed_canister_ids.insert(canister.canister_id());
        }
    }

    pub(crate) fn finish_round(
        &self,
        canister_states: &mut BTreeMap<CanisterId, CanisterState>,
        fully_executed_canister_ids: BTreeSet<CanisterId>,
    ) {
        let scheduler_cores = self.scheduler_cores;
        let number_of_canisters = canister_states.len();
        let multiplier = (scheduler_cores * number_of_canisters).max(1) as i64;

        // Charge canisters for full executions in this round.
        let mut total_charged_priority = 0;
        for canister_id in fully_executed_canister_ids {
            if let Some(canister) = canister_states.get_mut(&canister_id) {
                total_charged_priority += 100 * multiplier;
                canister.scheduler_state.priority_credit += (100 * multiplier).into();
            }
        }

        let total_allocated = self.total_compute_allocation_percent * multiplier;
        // Free capacity per canister in multiplied percent.
        let free_capacity_per_canister = total_charged_priority.saturating_sub(total_allocated)
            / number_of_canisters.max(1) as i64;
        // Fully divide the free allocation across all canisters.
        for canister in canister_states.values_mut() {
            // De-facto compute allocation includes bonus allocation
            let factual = canister.scheduler_state.compute_allocation.as_percent() as i64
                * multiplier
                + free_capacity_per_canister;
            // Increase accumulated priority by de-facto compute allocation.
            canister.scheduler_state.accumulated_priority += factual.into();

            let has_aborted_or_paused_execution =
                canister.has_aborted_execution() || canister.has_paused_execution();
            if !has_aborted_or_paused_execution {
                RoundSchedule::apply_priority_credit(canister);
            }
        }
    }

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
    pub(super) fn order_canister_round_states(round_states: &mut [CanisterRoundState]) {
        round_states.sort_by_key(|rs| {
            (
                std::cmp::Reverse(rs.long_execution_mode),
                std::cmp::Reverse(rs.has_aborted_or_paused_execution),
                std::cmp::Reverse(rs.accumulated_priority),
                rs.canister_id,
            )
        });
    }

    /// Orders the canisters and updates their accumulated priorities according to
    /// the strategy described in RUN-58.
    ///
    /// A shorter description of the scheduling strategy is available in the note
    /// section about [Scheduler and AccumulatedPriority] in types/src/lib.rs
    pub(super) fn apply_scheduling_strategy(
        logger: &ReplicaLogger,
        scheduler_cores: usize,
        current_round: ExecutionRound,
        accumulated_priority_reset_interval: ExecutionRound,
        canister_states: &mut BTreeMap<CanisterId, CanisterState>,
        metrics: &SchedulerMetrics,
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
        let is_reset_round = current_round
            .get()
            .is_multiple_of(accumulated_priority_reset_interval.get());

        // Collect the priority of the canisters for this round.
        let mut accumulated_priority_invariant = AccumulatedPriority::default();
        let mut accumulated_priority_deviation = 0.0;
        for (&canister_id, canister) in canister_states.iter_mut() {
            if is_reset_round {
                // By default, each canister accumulated priority is set to its compute allocation.
                canister.scheduler_state.accumulated_priority =
                    (canister.scheduler_state.compute_allocation.as_percent() as i64 * multiplier)
                        .into();
                canister.scheduler_state.priority_credit = Default::default();
            }

            let has_aborted_or_paused_execution =
                canister.has_aborted_execution() || canister.has_paused_execution();

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
                accumulated_priority.get() as f64 * accumulated_priority.get() as f64;
            if !canister.has_input() {
                canister
                    .system_state
                    .canister_metrics
                    .skipped_round_due_to_no_messages += 1;
            }
        }
        // Assert there is at least `1%` of free capacity to distribute across canisters.
        // It's guaranteed by `validate_compute_allocation()`
        debug_assert_or_critical_error!(
            total_compute_allocation_percent < compute_capacity_percent,
            metrics.scheduler_compute_allocation_invariant_broken,
            logger,
            "{}: Total compute allocation {}% must be less than compute capacity {}%",
            SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN,
            total_compute_allocation_percent,
            compute_capacity_percent
        );
        // Observe accumulated priority metrics
        metrics
            .scheduler_accumulated_priority_invariant
            .set(accumulated_priority_invariant.get());
        metrics
            .scheduler_accumulated_priority_deviation
            .set((accumulated_priority_deviation / number_of_canisters as f64).sqrt());

        // Free capacity per canister in multiplied percent.
        // Note, to avoid division by zero when there are no canisters
        // and having `multiplier == number_of_canisters * scheduler_cores`, the
        // `(compute_capacity - total_compute_allocation) * multiplier / number_of_canisters`
        // can be simplified to just
        // `(compute_capacity - total_compute_allocation) * scheduler_cores`
        let free_capacity_per_canister = compute_capacity_percent
            .saturating_sub(total_compute_allocation_percent)
            * scheduler_cores as i64;

        // Compute `long_execution_compute_allocation`.
        let mut long_executions_compute_allocation = 0;
        let mut number_of_long_executions = 0;
        for rs in round_states.iter_mut() {
            // De-facto compute allocation includes bonus allocation
            let factual =
                rs.compute_allocation.as_percent() as i64 * multiplier + free_capacity_per_canister;
            // Count long executions and sum up their compute allocation.
            if rs.has_aborted_or_paused_execution {
                // Note: factual compute allocation is multiplied by `multiplier`
                long_executions_compute_allocation += factual;
                number_of_long_executions += 1;
            }
        }

        // Compute the number of long execution cores by dividing
        // `long_execution_compute_allocation` by `100%` and rounding up
        // (as one scheduler core is reserved to guarantee long executions progress).
        // The `long_execution_compute_allocation` is in multiplied percent.
        let long_execution_cores = ((long_executions_compute_allocation + 100 * multiplier - 1)
            / (100 * multiplier)) as usize;
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

        Self::order_canister_round_states(&mut round_states);

        let round_schedule = RoundSchedule::new(
            scheduler_cores,
            long_execution_cores,
            total_compute_allocation_percent,
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
            let canister = canister_states.get_mut(canister_id).unwrap();
            canister.scheduler_state.long_execution_mode = LongExecutionMode::Prioritized;
        }

        round_schedule
    }

    /// Applies priority credit and resets long execution mode.
    pub fn apply_priority_credit(canister: &mut CanisterState) {
        canister.scheduler_state.accumulated_priority -=
            std::mem::take(&mut canister.scheduler_state.priority_credit);
        // Aborting a long-running execution moves the canister to the
        // default execution mode because the canister does not have a
        // pending execution anymore.
        canister.scheduler_state.long_execution_mode = LongExecutionMode::default();
    }
}
