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
use more_asserts::debug_assert_gt;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[cfg(test)]
mod tests;

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
    /// Copy of canister ID.
    canister_id: CanisterId,
    /// The canister's `accumulated_priority`. Plus an extra `compute_allocation`,
    /// applied at the beginning of the round to prioritize canisters with higher
    /// compute allocation.
    accumulated_priority: AccumulatedPriority,
    /// Copy of the canister's `SchedulerState::compute_allocation`.
    compute_allocation: AccumulatedPriority,
    /// Copy of the canister's `CanisterPriority::long_execution_mode`.
    long_execution_mode: LongExecutionMode,
    /// The canister's next execution. We're interested in whether that's
    /// `StartNew`, `ContinueLong`, or something else (both `None` and
    /// `ContinueInstallCode` count as idle).
    next_execution: NextExecution,
}

impl CanisterRoundState {
    pub fn new(canister: &CanisterState, canister_priority: &CanisterPriority) -> Self {
        let compute_allocation = from_ca(canister.compute_allocation());
        Self {
            canister_id: canister.canister_id(),
            accumulated_priority: canister_priority.accumulated_priority + compute_allocation,
            compute_allocation,
            long_execution_mode: canister_priority.long_execution_mode,
            next_execution: canister.next_execution(),
        }
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    pub fn is_long_execution(&self) -> bool {
        self.next_execution == NextExecution::ContinueLong
    }
}

impl Ord for CanisterRoundState {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort by:
        //  1. Long execution mode, reversed (Prioritized -> Opportunistic)
        other
            .long_execution_mode
            .cmp(&self.long_execution_mode)
            //  2. Next execution (ContinueLong -> StartNew; there should be no scheduled None)
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

/// Immutable configuration for a round.
#[derive(Debug)]
struct Config {
    /// Total number of scheduler cores.
    scheduler_cores: usize,
    /// Heap delta threshold above which a canister is suspended for the round.
    heap_delta_rate_limit: NumBytes,
    /// Whether heap delta rate limiting is enabled.
    rate_limiting_of_heap_delta: FlagStatus,
}

/// Result of one iteration: the schedule for this iteration only.
/// Use it to partition canisters to cores and to query iteration-specific values.
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
        let long_execution_cores = self.long_execution_cores;
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
}

/// Round-level schedule and accounting: builds the iteration schedule each iteration,
/// accumulates round-wide state, and applies priority credit at end of round.
#[derive(Debug)]
pub struct RoundSchedule {
    /// Immutable configuration for this round.
    config: Config,

    /// Canisters that were scheduled.
    scheduled_canisters: BTreeSet<CanisterId>,
    /// Canisters that had a long execution at round start.
    long_execution_canisters: BTreeSet<CanisterId>,
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
    ) -> Self {
        let config = Config {
            scheduler_cores,
            heap_delta_rate_limit,
            rate_limiting_of_heap_delta,
        };
        Self {
            config,
            scheduled_canisters: BTreeSet::new(),
            executed_canisters: BTreeSet::new(),
            long_execution_canisters: BTreeSet::new(),
            canisters_with_completed_messages: BTreeSet::new(),
            fully_executed_canisters: BTreeSet::new(),
            rate_limited_canisters: BTreeSet::new(),
        }
    }

    /// Builds this iteration's schedule from state, updates round accumulators and state,
    /// and returns the iteration schedule for partitioning and execution.
    pub fn start_iteration(
        &mut self,
        state: &mut ReplicatedState,
        is_first_iteration: bool,
        metrics: &SchedulerMetrics,
        logger: &ReplicaLogger,
    ) -> IterationSchedule {
        // Sum of all scheduled canisters' compute allocations.
        let mut total_compute_allocation = ZERO;
        let mut long_executions_count = 0usize;
        // Sum of all long executions' compute allocations.
        let mut long_executions_compute_allocation = ZERO;

        let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();

        // Collect all active canisters and their next executions.
        let mut schedule: Vec<CanisterRoundState> = canister_states
            .iter()
            .filter_map(|(canister_id, canister)| {
                if self.config.rate_limiting_of_heap_delta == FlagStatus::Enabled
                    && canister.scheduler_state.heap_delta_debit
                        >= self.config.heap_delta_rate_limit
                {
                    // Record and filter out rate limited canisters.
                    self.rate_limited_canisters.insert(*canister_id);
                    self.scheduled_canisters.insert(*canister_id);
                    return None;
                }

                let canister_round_state = match canister.next_execution() {
                    NextExecution::StartNew => {
                        // Don't schedule canisters that started the round with a long execution and
                        // completed it. We need canisters to move between the long execution and new
                        // execution pools, so the two groups' priorities don't drift apart.
                        if self.long_execution_canisters.contains(canister_id) {
                            return None;
                        }
                        CanisterRoundState::new(canister, subnet_schedule.get(canister_id))
                    }
                    NextExecution::ContinueLong => {
                        if is_first_iteration {
                            self.long_execution_canisters.insert(*canister_id);
                        }
                        let rs =
                            CanisterRoundState::new(canister, subnet_schedule.get(canister_id));
                        long_executions_count += 1;
                        long_executions_compute_allocation += rs.compute_allocation;
                        rs
                    }
                    NextExecution::None | NextExecution::ContinueInstallCode => return None,
                };

                total_compute_allocation += canister_round_state.compute_allocation;
                self.scheduled_canisters.insert(*canister_id);

                Some(canister_round_state)
            })
            .collect();
        schedule.sort();

        // Compute the number of long execution cores by dividing
        // `long_executions_compute_allocation` by `100%` and rounding up (as one
        // scheduler core is reserved to guarantee long executions progress).
        let compute_capacity = self.compute_capacity();
        let long_execution_cores = if schedule.is_empty() || long_executions_count == 0 {
            0
        } else {
            let free_compute = compute_capacity - total_compute_allocation;
            let long_executions_compute = long_executions_compute_allocation
                + (free_compute * long_executions_count as i64 / schedule.len() as i64);
            std::cmp::min(
                long_executions_count,
                ((long_executions_compute + ONE_HUNDRED_PERCENT - AccumulatedPriority::new(1))
                    / ONE_HUNDRED_PERCENT) as usize,
            )
        };

        // There is at least `1%` of free capacity to distribute across canisters.
        // This is guaranteed by `validate_compute_allocation()`.
        debug_assert_or_critical_error!(
            total_compute_allocation + ONE_PERCENT <= compute_capacity,
            metrics.scheduler_compute_allocation_invariant_broken,
            logger,
            "{}: Total compute allocation {}% must be less than compute capacity {}%",
            SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN,
            total_compute_allocation,
            compute_capacity
        );
        // If there are long executions, `long_execution_cores` must be non-zero.
        debug_assert_or_critical_error!(
            long_executions_count == 0 || long_execution_cores > 0,
            metrics.scheduler_cores_invariant_broken,
            logger,
            "{}: Number of long execution cores {} must be more than 0",
            SCHEDULER_CORES_INVARIANT_BROKEN,
            long_execution_cores,
        );
        // As one scheduler core is reserved, the `long_execution_cores` is always
        // less than `scheduler_cores`
        debug_assert_or_critical_error!(
            long_execution_cores < self.config.scheduler_cores,
            metrics.scheduler_cores_invariant_broken,
            logger,
            "{}: Number of long execution cores {} must be less than scheduler cores {}",
            SCHEDULER_CORES_INVARIANT_BROKEN,
            long_execution_cores,
            self.config.scheduler_cores
        );

        let schedule: Vec<CanisterId> = schedule.into_iter().map(|rs| rs.canister_id).collect();
        if is_first_iteration {
            // First iteration: mark the first canisters on each core as fully executed.
            schedule
                .iter()
                .take(long_execution_cores)
                .for_each(|canister| {
                    self.fully_executed_canisters.insert(*canister);

                    // And set prioritized long execution mode for the first `long_execution_cores`
                    // canisters.
                    subnet_schedule.get_mut(*canister).long_execution_mode =
                        LongExecutionMode::Prioritized;
                });
            schedule
                .iter()
                .skip(long_executions_count)
                .take(self.config.scheduler_cores - long_execution_cores)
                .for_each(|canister| {
                    self.fully_executed_canisters.insert(*canister);
                });
        }

        IterationSchedule {
            schedule,
            scheduler_cores: self.config.scheduler_cores,
            long_execution_cores,
            long_executions_count,
        }
    }

    pub fn end_iteration(
        &mut self,
        state: &mut ReplicatedState,
        executed_canisters: &BTreeSet<CanisterId>,
        canisters_with_completed_messages: &BTreeSet<CanisterId>,
        low_cycle_balance_canisters: &BTreeSet<CanisterId>,
    ) {
        self.executed_canisters.extend(executed_canisters);
        self.canisters_with_completed_messages
            .extend(canisters_with_completed_messages);

        for canister_id in canisters_with_completed_messages {
            // If a canister has completed a long execution, reset its long execution mode.
            state
                .canister_priority_mut(*canister_id)
                .long_execution_mode = LongExecutionMode::Opportunistic;
        }

        for canister_id in canisters_with_completed_messages.union(low_cycle_balance_canisters) {
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

    pub fn finish_round(
        &self,
        state: &mut ReplicatedState,
        current_round: ExecutionRound,
        metrics: &SchedulerMetrics,
    ) {
        let now = state.time();
        let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();

        // Charge canisters for full executions in this round.
        for canister_id in self.fully_executed_canisters.iter() {
            // Don't re-create `CanisterPriority` for deleted canisters.
            if canister_states.contains_key(canister_id) {
                let canister_priority = subnet_schedule.get_mut(*canister_id);
                canister_priority.priority_credit += ONE_HUNDRED_PERCENT;
                canister_priority.last_full_execution_round = current_round;
            }
            #[cfg(debug_assertions)]
            subnet_schedule
                .fully_executed_canisters
                .insert(*canister_id);
        }

        // Add all canisters that we (tried to) schedule this round to the subnet
        // schedule; and apply their respective priority credits.
        let mut free_allocation = ZERO;
        for canister_id in &self.scheduled_canisters {
            let Some(canister) = canister_states.get_mut(canister_id) else {
                // Canister was deleted.
                subnet_schedule.remove(canister_id);
                continue;
            };

            // Add the canister to the subnet schedule, if not already there.
            let canister_priority = subnet_schedule.get_mut(*canister_id);

            // Apply the priority credit if not in the same long execution as at the
            // beginning of the round.
            if canister_priority.priority_credit != ZERO
                && (canister.next_execution() != NextExecution::ContinueLong
                    || self
                        .canisters_with_completed_messages
                        .contains(&canister_id))
            {
                canister_priority.accumulated_priority -=
                    std::mem::take(&mut canister_priority.priority_credit);
            }

            Arc::make_mut(canister)
                .system_state
                .canister_metrics_mut()
                .observe_round_scheduled();
        }

        // Remove any deleted canisters from the subnet schedule. Beyond this point it
        // is safe to assume that the subnet schedule only refers to existing canisters.
        let deleted_canisters: Vec<_> = subnet_schedule
            .iter()
            .map(|(canister_id, _)| *canister_id)
            .filter(|canister_id| !canister_states.contains_key(canister_id))
            .collect();
        for canister_id in deleted_canisters {
            subnet_schedule.remove(&canister_id);
        }

        // Grant all canisters in the subnet schedule their compute allocation; and
        // calculate the subnet-wide free allocation (as the deviation from zero of the
        // sum of all canisters' accumulated priority).
        for (canister_id, canister_priority) in subnet_schedule.iter_mut() {
            let canister = canister_states.get_mut(canister_id).unwrap();
            canister_priority.accumulated_priority += from_ca(canister.compute_allocation());
            free_allocation -= canister_priority.accumulated_priority;
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
        //
        // Sort the canisters by their accumulated priority in descending order. Credit
        // each its share of the free allocation, dropping it from the schedule if it
        // has no more inputs and has reached zero accumulated priority.
        let mut sorted_canister_priorities = subnet_schedule
            .iter()
            .map(|(c, p)| (*c, p.accumulated_priority))
            .collect::<Vec<_>>();
        sorted_canister_priorities.sort_by_key(|(c, p)| (std::cmp::Reverse(*p), *c));
        let mut accumulated_priority_deviation = 0.0;
        let mut remaining_canisters = sorted_canister_priorities.len() as i64;
        for (canister_id, priority) in sorted_canister_priorities.into_iter() {
            let canister_free_allocation = free_allocation / remaining_canisters;
            let canister_state = canister_states.get(&canister_id).unwrap();
            let next_execution = match canister_state.next_execution() {
                NextExecution::None
                    if has_heartbeat(canister_state) || has_active_timer(canister_state, now) =>
                {
                    NextExecution::StartNew
                }
                other => other,
            };
            if priority >= -canister_free_allocation && next_execution == NextExecution::None {
                // Canister with no inputs that has just reached zero accumulated priority.
                subnet_schedule.get_mut(canister_id).accumulated_priority = ZERO;
                free_allocation += priority;

                // Drop it from the subnet schedule iff it has no heap delta or install code
                // debits.
                if !canister_state.must_be_in_schedule() {
                    subnet_schedule.remove(&canister_id);
                }
            } else {
                // Canister with inputs or with negative AP. Bump its AP and keep it in the
                // schedule.
                let canister_priority = subnet_schedule.get_mut(canister_id);

                // Max out at an arbitrary 5 rounds of accumulated priority.
                //
                // Without this, a canister with 100 compute allocation will accumulate 100
                // priority it can then never spend for every round of an aborted DTS execution
                // (priority credit is increased by 100 per round, but reset on abort).
                const AP_ROUNDS_MAX: i64 = 5;
                let canister_free_allocation = std::cmp::min(
                    canister_free_allocation,
                    ONE_HUNDRED_PERCENT * AP_ROUNDS_MAX - canister_priority.true_priority(),
                );

                canister_priority.accumulated_priority += canister_free_allocation;
                free_allocation -= canister_free_allocation;

                let accumulated_priority =
                    canister_priority.accumulated_priority.get() as f64 / MULTIPLIER as f64;
                accumulated_priority_deviation += accumulated_priority * accumulated_priority;
            }
            remaining_canisters -= 1;
        }

        metrics
            .scheduler_accumulated_priority_deviation
            .set((accumulated_priority_deviation / subnet_schedule.len().max(1) as f64).sqrt());

        self.observe_round_metrics(state, current_round, metrics);

        // TODO(DSM-103): `debug_assert` that all active canisters are in the subnet schedule.
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
    fn compute_capacity(&self) -> AccumulatedPriority {
        ONE_HUNDRED_PERCENT * (self.config.scheduler_cores as i64 - 1)
    }

    /// Canisters that were scheduled this round.
    pub fn scheduled_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.scheduled_canisters
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
