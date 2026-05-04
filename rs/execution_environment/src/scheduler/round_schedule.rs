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
use num_traits::SaturatingSub;
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
pub(super) const ONE_HUNDRED_PERCENT: AccumulatedPriority =
    AccumulatedPriority::new(100 * MULTIPLIER);

const fn from_ca(ca: ComputeAllocation) -> AccumulatedPriority {
    AccumulatedPriority::new(ca.as_percent() as i64 * MULTIPLIER)
}

/// Soft upper bound for accumulated priority (in rounds). We apply an
/// exponential decay to AP values greater than this.
const AP_ROUNDS_MAX: i64 = 5;

/// Soft lower bound for accumulated priority (in rounds). We apply an
/// exponential decay to AP values less than this.
const AP_ROUNDS_MIN: i64 = -20;

/// Exponential decay factor (in percent) for accumulated priorities outside the
/// `[AP_ROUNDS_MIN, AP_ROUNDS_MAX]` soft bounds.
const AP_DECAY_PERCENT: i64 = 80;

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

            // Among long executions, sort by executed rounds descending; AP descending;
            // start round ascending; then break ties by canister ID.
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

        // Completely segregate long and new executions across cores. Opportunistically
        // scheduling long executions on new execution cores results in inversion of
        // priority and potential starvation (lower priority long executions may execute
        // a second round before higher priority ones and become higher priority).
        let long_executions = self.schedule.iter().take(self.long_executions_count);
        let long_execution_cores = self.long_execution_cores.min(self.long_executions_count);
        for (idx, canister_id) in long_executions.enumerate() {
            let canister_state = canisters.remove(canister_id).unwrap();
            canisters_partitioned_by_cores[idx % long_execution_cores].push(canister_state);
        }

        let new_executions = self.schedule.iter().skip(self.long_executions_count);
        let new_execution_cores = (self.scheduler_cores - long_execution_cores).max(1);
        for (idx, canister_id) in new_executions.enumerate() {
            let canister_state = canisters.remove(canister_id).unwrap();
            canisters_partitioned_by_cores[long_execution_cores + idx % new_execution_cores]
                .push(canister_state);
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
    /// Canisters that had a long execution at the start of this round.
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
            long_execution_canisters: BTreeSet::new(),
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

    /// Computes and returns an iteration schedule covering active canisters only.
    ///
    /// Updates round accumulators (scheduled, rate limited, long execution
    /// canisters).
    pub fn start_iteration(
        &mut self,
        state: &mut ReplicatedState,
        is_first_iteration: bool,
    ) -> IterationSchedule {
        let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();

        // Collect all active canisters and their next executions.
        let canister_next_executions: BTreeMap<_, _> = canister_states
            .iter()
            .filter_map(|(canister_id, canister)| {
                // Record and filter out rate limited canisters.
                if canister.scheduler_state.heap_delta_debit >= self.config.heap_delta_rate_limit
                    || canister.scheduler_state.install_code_debit
                        >= self.config.install_code_rate_limit
                {
                    self.rate_limited_canisters.insert(*canister_id);
                    self.scheduled_canisters.insert(*canister_id);
                    if is_first_iteration {
                        // Charge them as if they had executed a full round.
                        subnet_schedule.get_mut(*canister_id).accumulated_priority -=
                            ONE_HUNDRED_PERCENT;
                    }
                    return None;
                }

                let next_execution = canister.next_execution();
                match next_execution {
                    // Filter out canisters with no messages or with paused installations.
                    NextExecution::None | NextExecution::ContinueInstallCode => None,

                    NextExecution::StartNew => {
                        // Don't schedule canisters that completed a long execution this round. We need
                        // canisters to move between the long execution and new execution pools, so the
                        // two groups' priorities don't drift apart.
                        if self.long_execution_canisters.contains(canister_id) {
                            return None;
                        }
                        self.scheduled_canisters.insert(*canister_id);
                        Some((canister_id, next_execution))
                    }

                    NextExecution::ContinueLong => {
                        if is_first_iteration {
                            self.long_execution_canisters.insert(*canister_id);
                        }
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

                    None
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
                // Completed a long execution that had started before this round.
                NextExecution::StartNew if self.long_execution_canisters.contains(canister_id) => {
                    self.fully_executed_canisters.insert(*canister_id);
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
    /// * Charges for completed executions (and the first round of long executions).
    /// * Grants heap delta and install code credits.
    /// * Grants canisters their compute allocations.
    /// * Applies an exponential decay to large AP values, to limit runaway APs.
    /// * Calculates and distributes the subnet-wide free compute.
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

        // Add all canisters to the subnet schedule; and charge any immediate or
        // deferred (on long execution completion) execution rounds.
        for canister in canister_states.values() {
            // Add the canister to the subnet schedule, if not already there.
            let canister_priority = subnet_schedule.get_mut(canister.canister_id());

            // Charge for the first round of every long execution immediately, to properly
            // account for newly started long executions (scheduled as new executions).
            if canister_priority.executed_rounds == 1
                && canister_priority.long_execution_start_round == Some(current_round)
            {
                canister_priority.accumulated_priority -= ONE_HUNDRED_PERCENT;
            }

            // On message completion (or short execution), charge for the remaining rounds.
            if canister_priority.executed_rounds > 0
                && (!canister.has_long_execution()
                    || self
                        .canisters_with_completed_messages
                        .contains(&canister.canister_id()))
            {
                canister_priority.accumulated_priority -=
                    ONE_HUNDRED_PERCENT * (canister_priority.executed_rounds - 1).max(1);
                canister_priority.executed_rounds = 0;
            }
        }

        self.grant_heap_delta_and_install_code_credits(state, metrics);
        let (canister_states, subnet_schedule) = state.canisters_and_schedule_mut();

        // Grant all canisters in the subnet schedule their compute allocation. Collect
        // scheduled canisters' compute allocations; and sum their total AP and CA.
        let mut total_ap = ZERO;
        let mut total_ca = ZERO;
        let mut compute_allocations = Vec::with_capacity(subnet_schedule.len());
        for (_, canister, canister_priority) in
            left_outer_join(canister_states.iter_mut(), subnet_schedule.iter_mut())
        {
            // Safe to unwrap, we called SubnetSchedule::get_mut() above for all canisters.
            let canister_priority = canister_priority.unwrap();

            let compute_allocation = from_ca(canister.compute_allocation());
            canister_priority.accumulated_priority += compute_allocation;

            // Apply an exponential decay to AP values outside the [AP_ROUNDS_MIN,
            // AP_ROUNDS_MAX] range to soft bound any runaway AP.
            const AP_MAX: AccumulatedPriority =
                AccumulatedPriority::new(AP_ROUNDS_MAX * 100 * MULTIPLIER);
            const AP_MIN: AccumulatedPriority =
                AccumulatedPriority::new(AP_ROUNDS_MIN * 100 * MULTIPLIER);
            if canister_priority.accumulated_priority > AP_MAX {
                canister_priority.accumulated_priority = AP_MAX
                    + (canister_priority.accumulated_priority - AP_MAX) * AP_DECAY_PERCENT / 100;
            } else if canister_priority.accumulated_priority < AP_MIN {
                canister_priority.accumulated_priority = AP_MIN
                    + (canister_priority.accumulated_priority - AP_MIN) * AP_DECAY_PERCENT / 100;
            }

            total_ap += canister_priority.accumulated_priority;
            total_ca += compute_allocation;
            compute_allocations.push((canister.canister_id(), compute_allocation));
        }

        // Distribute the "free compute" (negative of total AP) to all canisters.
        //
        // Only ever apply positive free compute. If the total AP is positive (e.g. we
        // granted compute allocations after not having completed any execution this
        // round), then there is simply no free compute to distribute.
        let mut free_compute = -total_ap;
        if free_compute > ZERO {
            // Cap canister grants (including any compute allocation) to 100%, to prevent
            // systematic accumulation of more AP than can be spent.
            //
            // However, if there is more than 100 priority to distribute per canister (e.g.
            // because we have charged for a lot of long executions this round), then simply
            // grant every canister an equal share of that (minus the CA we already granted
            // above).
            let canister_count = compute_allocations.len() as i64;
            let per_canister_cap = if free_compute + total_ca > ONE_HUNDRED_PERCENT * canister_count
            {
                const ONE: AccumulatedPriority = AccumulatedPriority::new(1);
                (free_compute + total_ca - ONE) / canister_count + ONE
            } else {
                ONE_HUNDRED_PERCENT
            };

            // Start with the highest compute allocation canisters, as they require the
            // smallest "top-ups" to reach the per-canister cap, leaving higher shares for
            // lower compute allocation canisters.
            compute_allocations.sort_by_key(|(c, p)| (std::cmp::Reverse(*p), *c));
            let mut remaining = compute_allocations.len() as i64;
            for (canister_id, ca) in compute_allocations {
                let mut share = free_compute / remaining;
                share = std::cmp::min(share, per_canister_cap - ca);

                let canister_priority = subnet_schedule.get_mut(canister_id);
                canister_priority.accumulated_priority += share;

                free_compute -= share;
                remaining -= 1;
            }
        }

        let mut accumulated_priority_deviation = 0.0;
        for (_, canister_priority) in subnet_schedule.iter() {
            let accumulated_priority =
                canister_priority.accumulated_priority.get() as f64 / MULTIPLIER as f64;
            accumulated_priority_deviation += accumulated_priority * accumulated_priority;
        }
        metrics
            .scheduler_accumulated_priority_deviation
            .set((accumulated_priority_deviation / subnet_schedule.len().max(1) as f64).sqrt());

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
        for canister_id in &self.scheduled_canisters {
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

        // Sum of all scheduled canisters' compute allocations.
        // This corresponds to |a| in Scheduler Analysis.
        let mut total_compute_allocation = ZERO;
        // Sum of all long execution canisters' compute allocations.
        let mut long_executions_compute_allocation = ZERO;
        let mut long_executions_count = 0;

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
        for (_, canister, canister_priority) in
            left_outer_join(canister_states.iter_mut(), subnet_schedule.iter())
        {
            let canister_priority = canister_priority.unwrap_or(&CanisterPriority::DEFAULT);
            let compute_allocation = from_ca(canister.compute_allocation());
            let accumulated_priority = canister_priority.accumulated_priority;
            round_states.push(CanisterRoundState::new(canister, canister_priority));

            total_compute_allocation += compute_allocation;
            accumulated_priority_invariant += accumulated_priority;
            if canister_priority.long_execution_start_round.is_some() {
                long_executions_compute_allocation += compute_allocation;
                long_executions_count += 1;
            }
            if canister.has_input() {
                let canister = Arc::make_mut(canister);
                canister
                    .system_state
                    .canister_metrics_mut()
                    .observe_round_scheduled();
            }
        }
        round_states.sort();

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

        let long_execution_cores = if long_executions_count == canister_states.len() {
            // Only long executions.
            std::cmp::min(long_executions_count, scheduler_cores)
        } else {
            // Mix of long and short executions.
            //
            // Compute the number of long execution cores by dividing long executions'
            // compute allocation plus free compute share by `100%` and rounding up (so that
            // both long and new executions get enough cores to cover their respective
            // cumulative compute allocations).
            let free_compute = compute_capacity - total_compute_allocation;
            let long_executions_compute = long_executions_compute_allocation
                + (free_compute * long_executions_count as i64 / canister_states.len() as i64);
            std::cmp::min(
                long_executions_count,
                ((long_executions_compute + ONE_HUNDRED_PERCENT - AccumulatedPriority::new(1))
                    / ONE_HUNDRED_PERCENT) as usize,
            )
        };

        // If there are long executions, `long_execution_cores` must be non-zero.
        debug_assert_or_critical_error!(
            long_executions_count == 0 || long_execution_cores > 0,
            metrics.scheduler_cores_invariant_broken,
            logger,
            "{}: Number of long execution cores {} must be more than 0",
            SCHEDULER_CORES_INVARIANT_BROKEN,
            long_execution_cores,
        );
        // Can't have more long execution cores than scheduler cores.
        debug_assert_or_critical_error!(
            long_execution_cores <= scheduler_cores,
            metrics.scheduler_cores_invariant_broken,
            logger,
            "{}: Number of long execution cores {} must be <= scheduler cores {}",
            SCHEDULER_CORES_INVARIANT_BROKEN,
            long_execution_cores,
            scheduler_cores
        );

        RoundSchedule::new(
            scheduler_cores,
            heap_delta_rate_limit,
            rate_limiting_of_heap_delta,
            install_code_rate_limit,
            rate_limiting_of_instructions,
            long_execution_cores,
            round_states
                .iter()
                .skip(long_executions_count)
                .map(|rs| rs.canister_id)
                .collect(),
            round_states
                .iter()
                .take(long_executions_count)
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
