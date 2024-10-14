use std::collections::{BTreeMap, HashMap};

use ic_base_types::{CanisterId, NumBytes};
use ic_config::flag_status::FlagStatus;
use ic_replicated_state::{canister_state::NextExecution, CanisterState};
use ic_types::{AccumulatedPriority, ComputeAllocation, LongExecutionMode};

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
    /// Ordered Canister IDs with new executions.
    pub ordered_new_execution_canister_ids: Vec<CanisterId>,
    /// Ordered Canister IDs with long executions.
    pub ordered_long_execution_canister_ids: Vec<CanisterId>,
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
}
