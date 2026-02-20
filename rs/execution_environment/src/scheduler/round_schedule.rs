use super::{
    SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN, SCHEDULER_CORES_INVARIANT_BROKEN,
    SchedulerMetrics,
};
use crate::util::debug_assert_or_critical_error;
use ic_base_types::{CanisterId, NumBytes};
use ic_config::flag_status::FlagStatus;
use ic_logger::{ReplicaLogger, error};
use ic_management_canister_types_private::CanisterStatusType;
use ic_replicated_state::canister_state::NextExecution;
use ic_replicated_state::{CanisterPriority, CanisterState, ReplicatedState};
use ic_types::{AccumulatedPriority, ComputeAllocation, ExecutionRound, LongExecutionMode};
use more_asserts::debug_assert_gt;
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
    /// The canister's next execution. We're interested in whether that's
    /// `StartNew`, `ContinueLong`, or something else (both `None` and
    /// `ContinueInstallCode` count as idle).
    next_execution: NextExecution,
}

impl CanisterRoundState {
    pub fn new(canister: &CanisterState, canister_priority: &CanisterPriority) -> Self {
        let compute_allocation = from_ca(canister.compute_allocation());
        // println!(
        //     "canister {:?} accumulated_priority: {}, priority_credit: {}",
        //     canister.canister_id(),
        //     canister_priority.accumulated_priority + compute_allocation,
        //     canister_priority.priority_credit
        // );
        Self {
            canister_id: canister.canister_id(),
            // Compute allocation is applied at the beginning of the round. All
            // else being equal, schedule canisters with higher compute allocation
            // first.
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

/// Represents the current round schedule. It is updated on every inner loop
/// based on the canisters' current "next executions".
#[derive(Debug)]
pub struct RoundSchedule {
    /// Total number of scheduler cores.
    scheduler_cores: usize,
    heap_delta_rate_limit: NumBytes,
    rate_limiting_of_heap_delta: FlagStatus,

    /// Current iteration: scheduked canisters, ordered by priority.
    schedule: Vec<CanisterRoundState>,
    /// Current iteration: sum of all scheduled canisters' compute allocations.
    total_compute_allocation: AccumulatedPriority,
    /// Current iteration: number of long execution canisters.
    long_executions_count: usize,
    /// Current iteration: sum of all long executions' compute allocations.
    long_executions_compute_allocation: AccumulatedPriority,

    /// Full round: canisters that were scheduled.
    round_scheduled_canisters: BTreeSet<CanisterId>,
    /// Full round: canisters that had a long execution at round start.
    round_long_execution_canisters: BTreeSet<CanisterId>,
    /// Full round: canisters that completed message executions.
    canisters_with_completed_messages: BTreeSet<CanisterId>,
    /// Full round: canisters that got a "full execution" (scheduled first or
    /// consumed all its inputs).
    fully_executed_canisters: BTreeSet<CanisterId>,
    /// Full round: canisters that were heap delta rate-limited.
    rate_limited_canisters: BTreeSet<CanisterId>,
    /// Full round: canisters that have had heartbeat or global timer tasks enqueued.
    heartbeat_and_timer_canisters: BTreeSet<CanisterId>,
}

impl RoundSchedule {
    pub fn new(
        scheduler_cores: usize,
        heap_delta_rate_limit: NumBytes,
        rate_limiting_of_heap_delta: FlagStatus,
    ) -> Self {
        Self {
            scheduler_cores,
            heap_delta_rate_limit,
            rate_limiting_of_heap_delta,
            schedule: vec![],
            total_compute_allocation: ZERO,
            long_executions_count: 0,
            long_executions_compute_allocation: ZERO,
            round_scheduled_canisters: BTreeSet::new(),
            round_long_execution_canisters: BTreeSet::new(),
            canisters_with_completed_messages: BTreeSet::new(),
            fully_executed_canisters: BTreeSet::new(),
            rate_limited_canisters: BTreeSet::new(),
            heartbeat_and_timer_canisters: BTreeSet::new(),
        }
    }

    /// Computes the number of long execution cores by dividing
    /// `long_execution_compute_allocation` by `100%` and rounding up (as one
    /// scheduler core is reserved to guarantee long executions progress).
    fn long_execution_cores(&self) -> usize {
        if self.schedule.is_empty() {
            return 0;
        }
        let compute_capacity = Self::compute_capacity(self.scheduler_cores);
        let free_compute = compute_capacity - self.total_compute_allocation;
        let long_executions_compute = self.long_executions_compute_allocation
            + (free_compute * self.long_executions_count as i64 / self.schedule.len() as i64);
        std::cmp::min(
            self.long_executions_count,
            ((long_executions_compute + ONE_HUNDRED_PERCENT - AccumulatedPriority::new(1))
                / ONE_HUNDRED_PERCENT) as usize,
        )
    }

    fn scheduling_order(
        &self,
    ) -> SchedulingOrder<
        impl Iterator<Item = &CanisterRoundState>,
        impl Iterator<Item = &CanisterRoundState>,
        impl Iterator<Item = &CanisterRoundState>,
    > {
        let long_execution_cores = self.long_execution_cores();

        SchedulingOrder {
            // To guarantee progress and minimize the potential waste of an abort, top
            // `long_execution_cores` canisters with prioritized long execution mode and highest
            // priority get scheduled on long execution cores.
            prioritized_long_canisters: self.schedule.iter().take(long_execution_cores),
            // Canisters with no pending long executions get scheduled across new execution
            // cores according to their round priority as the regular scheduler does. This will
            // guarantee their reservations; and ensure low latency except immediately after a long
            // message execution.
            new_canisters: self.schedule.iter().skip(self.long_executions_count),
            // Remaining canisters with long pending executions get scheduled across
            // all cores according to their priority order, starting from the next available core onto which a new
            // execution canister would have been scheduled.
            opportunistic_long_canisters: self
                .schedule
                .iter()
                .skip(long_execution_cores)
                .take(self.long_executions_count - long_execution_cores),
        }
    }

    pub fn start_iteration(
        &mut self,
        state: &mut ReplicatedState,
        metrics: &SchedulerMetrics,
        logger: &ReplicaLogger,
    ) {
        let is_first_iteration = self.schedule.is_empty();
        let now = state.time();

        self.total_compute_allocation = ZERO;
        self.long_executions_count = 0;
        self.long_executions_compute_allocation = ZERO;

        let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();

        // Collect all active canisters and their next executions.
        self.schedule = canister_states
            .iter_mut()
            .filter_map(|(canister_id, canister)| {
                if self.rate_limiting_of_heap_delta == FlagStatus::Enabled
                    && canister.scheduler_state.heap_delta_debit >= self.heap_delta_rate_limit
                {
                    // Record and filter out rate limited canisters.
                    self.rate_limited_canisters.insert(*canister_id);
                    self.round_scheduled_canisters.insert(*canister_id);
                    return None;
                }

                // If this is the first iteration add `Heartbeat` and/or `GlobalTimer` tasks...
                if is_first_iteration
                    // ...to canisters that are running...
                    && canister.system_state.status() == CanisterStatusType::Running
                {
                    // ...that have a new or no next execution...
                    let next_execution = canister.next_execution();
                    if next_execution == NextExecution::StartNew
                        || next_execution == NextExecution::None
                    {
                        // ... and that have a heartbeat or an active global timer.
                        let has_heartbeat = has_heartbeat(canister);
                        let has_active_timer = has_active_timer(canister, now);
                        if has_heartbeat || has_active_timer {
                            super::maybe_add_heartbeat_or_global_timer_tasks(
                                Arc::make_mut(canister),
                                has_heartbeat,
                                has_active_timer,
                                &mut self.heartbeat_and_timer_canisters,
                            );
                        }
                    }
                }

                let canister_round_state = match canister.next_execution() {
                    NextExecution::StartNew => {
                        // Don't schedule canisters that completed a long execution this round.
                        if self.round_long_execution_canisters.contains(canister_id) {
                            return None;
                        }
                        CanisterRoundState::new(canister, subnet_schedule.get(canister_id))
                    }
                    NextExecution::ContinueLong => {
                        if is_first_iteration {
                            self.round_long_execution_canisters.insert(*canister_id);
                        }
                        let rs =
                            CanisterRoundState::new(canister, subnet_schedule.get(canister_id));
                        self.long_executions_count += 1;
                        self.long_executions_compute_allocation += rs.compute_allocation;
                        rs
                    }
                    NextExecution::None | NextExecution::ContinueInstallCode => return None,
                };

                self.total_compute_allocation += canister_round_state.compute_allocation;
                self.round_scheduled_canisters.insert(*canister_id);

                Some(canister_round_state)
            })
            .collect();
        self.schedule.sort();

        let long_execution_cores = self.long_execution_cores();
        let compute_capacity = Self::compute_capacity(self.scheduler_cores);
        // Assert there is at least `1%` of free capacity to distribute across canisters.
        // It's guaranteed by `validate_compute_allocation()`
        debug_assert_or_critical_error!(
            self.total_compute_allocation + ONE_PERCENT <= compute_capacity,
            metrics.scheduler_compute_allocation_invariant_broken,
            logger,
            "{}: Total compute allocation {}% must be less than compute capacity {}%",
            SCHEDULER_COMPUTE_ALLOCATION_INVARIANT_BROKEN,
            self.total_compute_allocation,
            compute_capacity
        );
        // If there are long executions, the `long_execution_cores` must be non-zero.
        debug_assert_or_critical_error!(
            self.long_executions_count == 0 || long_execution_cores > 0,
            metrics.scheduler_cores_invariant_broken,
            logger,
            "{}: Number of long execution cores {} must be more than 0",
            SCHEDULER_CORES_INVARIANT_BROKEN,
            long_execution_cores,
        );
        // As one scheduler core is reserved, the `long_execution_cores` is always
        // less than `scheduler_cores`
        debug_assert_or_critical_error!(
            long_execution_cores < self.scheduler_cores,
            metrics.scheduler_cores_invariant_broken,
            logger,
            "{}: Number of long execution cores {} must be less than scheduler cores {}",
            SCHEDULER_CORES_INVARIANT_BROKEN,
            long_execution_cores,
            self.scheduler_cores
        );

        if is_first_iteration {
            // First iteration: mark the first canisters on each core as fully executed.
            self.schedule
                .iter_mut()
                .take(long_execution_cores)
                .for_each(|canister| {
                    self.fully_executed_canisters.insert(canister.canister_id);

                    // And set prioritized long execution mode for the first `long_execution_cores`
                    // canisters.
                    canister.long_execution_mode = LongExecutionMode::Prioritized;
                    subnet_schedule
                        .get_mut(canister.canister_id)
                        .long_execution_mode = LongExecutionMode::Prioritized;
                });
            self.schedule
                .iter()
                .skip(self.long_executions_count)
                .take(self.scheduler_cores - long_execution_cores)
                .for_each(|canister| {
                    self.fully_executed_canisters.insert(canister.canister_id);
                });
        }

        // println!("is_first_iteration: {}", is_first_iteration);
        // println!("schedule: {:?}", self.schedule);
        // println!(
        //     "heartbeat_and_timer_canisters: {:?}",
        //     self.heartbeat_and_timer_canisters
        // );
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
    ) -> (
        Vec<Vec<Arc<CanisterState>>>,
        BTreeMap<CanisterId, Arc<CanisterState>>,
    ) {
        let mut canisters_partitioned_by_cores = vec![vec![]; self.scheduler_cores];

        let mut idx = 0;
        let scheduling_order = self.scheduling_order();
        for canister in scheduling_order.prioritized_long_canisters {
            let canister_state = canisters.remove(&canister.canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx += 1;
        }
        let last_prioritized_long = idx;
        let new_execution_cores = self.scheduler_cores - last_prioritized_long;
        debug_assert_gt!(new_execution_cores, 0);
        for canister in scheduling_order.new_canisters {
            let canister_state = canisters.remove(&canister.canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx = last_prioritized_long
                + (idx - last_prioritized_long + 1) % new_execution_cores.max(1);
        }
        for canister in scheduling_order.opportunistic_long_canisters {
            let canister_state = canisters.remove(&canister.canister_id).unwrap();
            canisters_partitioned_by_cores[idx].push(canister_state);
            idx = (idx + 1) % self.scheduler_cores;
        }

        (canisters_partitioned_by_cores, canisters)
    }

    pub fn end_iteration(
        &mut self,
        state: &mut ReplicatedState,
        canisters_with_completed_messages: &BTreeSet<CanisterId>,
    ) {
        for canister_id in canisters_with_completed_messages {
            self.canisters_with_completed_messages.insert(*canister_id);
            // If a canister has completed a long execution, reset its long execution mode.
            state
                .metadata
                .subnet_schedule
                .get_mut(*canister_id)
                .long_execution_mode = LongExecutionMode::Opportunistic;
        }
        for canister in self.schedule.iter() {
            match state
                .canister_state(&canister.canister_id)
                .map(|canister| canister.next_execution())
                .unwrap_or(NextExecution::None)
            {
                NextExecution::None => {
                    self.fully_executed_canisters.insert(canister.canister_id);
                }
                NextExecution::StartNew | NextExecution::ContinueLong => {}
                NextExecution::ContinueInstallCode => {
                    unreachable!()
                }
            }
        }
    }

    pub fn finish_round(&self, state: &mut ReplicatedState, current_round: ExecutionRound) {
        let now = state.time();
        let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();

        // Charge canisters for full executions in this round.
        for canister_id in self.fully_executed_canisters.iter() {
            let canister_priority = subnet_schedule.get_mut(*canister_id);
            if canister_states.get(canister_id).is_some() {
                canister_priority.priority_credit += ONE_HUNDRED_PERCENT;
            }
            canister_priority.last_full_execution_round = current_round;
            #[cfg(debug_assertions)]
            subnet_schedule
                .fully_executed_canisters
                .insert(*canister_id);
        }

        // Remove all remaining `Heartbeat` and `GlobalTimer` tasks
        // because they will be added again in the next round.
        for canister_id in &self.heartbeat_and_timer_canisters {
            let canister = canister_states.get_mut(canister_id).unwrap();
            if canister
                .system_state
                .task_queue
                .has_heartbeat_or_global_timer()
            {
                Arc::make_mut(canister)
                    .system_state
                    .task_queue
                    .remove_heartbeat_and_global_timer();
            }
        }

        fn true_priority(canister_priority: &CanisterPriority) -> AccumulatedPriority {
            canister_priority.accumulated_priority - canister_priority.priority_credit
        }

        // Add all canisters that we (tried to) schedule this round to the subnet
        // schedule; grant them their compute allocation; and calculate the subnet-wide
        // free allocation (as the deviation from zero of all canisters' total
        // accumulated priority, including priority credit).
        let mut free_allocation = ZERO;
        for canister_id in &self.round_scheduled_canisters {
            let Some(canister) = canister_states.get_mut(canister_id) else {
                // Canister was deleted.
                subnet_schedule.remove(canister_id);
                continue;
            };
            let canister_priority = subnet_schedule.get_mut(*canister_id);
            canister_priority.accumulated_priority += from_ca(canister.compute_allocation());
            free_allocation -= true_priority(canister_priority);
            Arc::make_mut(canister)
                .system_state
                .canister_metrics_mut()
                .observe_round_scheduled();
        }

        // Only ever apply positive free allocation. If the sum of all canisters'
        // accumulated priorities (including priority credit) is somehow positive
        // (although this should never happen), then there is simply no free allocation
        // to distribute.
        if free_allocation.get() < 0 {
            free_allocation = ZERO;
        }
        // println!(
        //     "round {}, free_allocation: {}",
        //     current_round.get(),
        //     free_allocation.get()
        // );

        // Fully distribute the free allocation among all canisters, ensuring that we
        // end up with exactly zero at the end of the loop.
        //
        // Sort the canisters by their real accumulated priority in descending order.
        // Credit each its share of the free allocation, dropping it from the schedule
        // if it has no more inputs and has reached zero accumulated priority.
        let mut sorted_canister_priorities = subnet_schedule
            .iter()
            .map(|(c, p)| (*c, true_priority(p)))
            .collect::<Vec<_>>();
        sorted_canister_priorities.sort_by_key(|(c, p)| (std::cmp::Reverse(*p), *c));
        let mut remaining_canisters = subnet_schedule.len() as i64;
        // println!(
        //     "sorted_canister_priorities: {:?}",
        //     sorted_canister_priorities
        // );
        for (canister_id, priority) in sorted_canister_priorities.into_iter() {
            let canister_free_allocation = free_allocation / remaining_canisters;
            let canister_state = canister_states.get(&canister_id);
            let next_execution = match canister_state.map(|c| c.next_execution()) {
                Some(NextExecution::None)
                    if canister_state.is_some_and(|canister| {
                        has_heartbeat(canister) || has_active_timer(canister, now)
                    }) =>
                {
                    NextExecution::StartNew
                }
                Some(other) => other,
                None => NextExecution::None,
            };
            if priority >= -canister_free_allocation && next_execution == NextExecution::None {
                // Canister with no inputs that has just reached zero accumulated priority. Drop
                // it from the subnet schedule.
                subnet_schedule.remove(&canister_id);
                free_allocation += priority;
                // println!(
                //     "Removed canister: {} with priority: {}",
                //     canister_id, priority
                // );
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
                    ONE_HUNDRED_PERCENT * AP_ROUNDS_MAX - true_priority(canister_priority),
                );

                canister_priority.accumulated_priority += canister_free_allocation;
                free_allocation -= canister_free_allocation;

                // Not in the same long execution as at the beginning of the round. Safe to
                // apply the priority credit.
                if next_execution != NextExecution::ContinueLong
                    || self
                        .canisters_with_completed_messages
                        .contains(&canister_id)
                {
                    RoundSchedule::apply_priority_credit(canister_priority);
                }
                // println!(
                //     "Credited canister {} free_allocation {}",
                //     canister_id,
                //     canister_free_allocation.get()
                // );
            }
            remaining_canisters -= 1;
        }
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

    /// Applies priority credit and resets long execution mode.
    pub fn apply_priority_credit(canister_priority: &mut CanisterPriority) {
        canister_priority.accumulated_priority -=
            std::mem::take(&mut canister_priority.priority_credit);
        // Aborting a long-running execution moves the canister to the
        // default execution mode because the canister does not have a
        // pending execution anymore.
        canister_priority.long_execution_mode = LongExecutionMode::default();
    }

    pub fn round_scheduled_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.round_scheduled_canisters
    }

    pub fn schedule_length(&self) -> usize {
        self.schedule.len()
    }

    pub fn canisters_with_completed_messages(&self) -> &BTreeSet<CanisterId> {
        &self.canisters_with_completed_messages
    }

    pub fn fully_executed_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.fully_executed_canisters
    }

    pub fn rate_limited_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.rate_limited_canisters
    }
}

fn has_heartbeat(canister: &CanisterState) -> bool {
    canister.exports_heartbeat_method()
}

fn has_active_timer(canister: &CanisterState, now: ic_types::Time) -> bool {
    canister.exports_global_timer_method()
        && canister.system_state.global_timer.has_reached_deadline(now)
}
