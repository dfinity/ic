use super::*;
use crate::scheduler::scheduler_metrics::SchedulerMetrics;
use assert_matches::assert_matches;
use ic_base_types::{CanisterId, NumBytes};
use ic_config::flag_status::FlagStatus;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::execution_state::{
    ExecutionState, ExportedFunctions, Memory, WasmBinary, WasmMetadata,
};
use ic_replicated_state::canister_state::system_state::PausedExecutionId;
use ic_replicated_state::testing::SystemStateTesting;
use ic_replicated_state::{CanisterMetrics, CanisterPriority, ExecutionTask, ReplicatedState};
use ic_test_utilities_state::get_running_canister;
use ic_test_utilities_types::messages::IngressBuilder;
use ic_types::messages::{CanisterMessageOrTask, CanisterTask};
use ic_types::methods::{SystemMethod, WasmMethod};
use ic_types::{AccumulatedPriority, ComputeAllocation, ExecutionRound};
use ic_types_test_utils::ids::{canister_test_id, subnet_test_id};
use ic_wasm_types::CanisterModule;
use itertools::Itertools;
use maplit::btreeset;
use more_asserts::{assert_gt, assert_le};
use proptest::prelude::*;
use std::collections::VecDeque;
use std::sync::Arc;

/// Fixture for testing `RoundSchedule` in isolation: a `RoundSchedule` and a
/// `ReplicatedState`, with helpers to manage canisters and inspect canister metrics
/// and priority.
struct RoundScheduleFixture {
    round_schedule: RoundSchedule,
    state: ReplicatedState,
    current_round: ExecutionRound,
    next_canister_id: u64,
    metrics: SchedulerMetrics,
    logger: ic_logger::ReplicaLogger,
}

impl Default for RoundScheduleFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundScheduleFixture {
    /// Creates a new fixture with a sensible `RoundSchedule` default (4 cores,
    /// large heap delta rate limit), and an empty `ReplicatedState`.
    fn new() -> Self {
        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        let current_round = ExecutionRound::new(1);
        let metrics = SchedulerMetrics::new(&MetricsRegistry::new());
        let logger = ic_logger::replica_logger::test_logger(Some(slog::Level::Info));
        let round_schedule =
            RoundScheduleBuilder::new().build(&mut state, current_round, &metrics, &logger);
        Self {
            round_schedule,
            state,
            current_round,
            next_canister_id: 0,
            metrics,
            logger,
        }
    }

    /// Adds a canister without explicit scheduling priority. Returns the new
    /// canister ID.
    fn canister(&mut self) -> CanisterId {
        let canister_id = canister_test_id(self.next_canister_id);
        self.next_canister_id += 1;
        self.state
            .put_canister_state(Arc::new(get_running_canister(canister_id)));
        canister_id
    }

    /// Adds a canister with an ingress message so its `next_execution()` is
    /// `StartNew`. Returns the new canister ID.
    fn canister_with_input(&mut self) -> CanisterId {
        let canister_id = self.canister();
        self.push_input(canister_id);
        canister_id
    }

    /// Adds a canister with a paused long execution so that `next_execution()`
    /// returns `ContinueLong`. Returns the new canister ID.
    fn canister_with_long_execution(&mut self) -> CanisterId {
        let canister_id = self.canister();
        self.add_long_execution(canister_id);
        let canister_priority = self.state.canister_priority_mut(canister_id);
        canister_priority.long_execution_start_round = Some(self.current_round);
        canister_priority.executed_rounds = 1;
        canister_id
    }

    /// Creates a new `RoundSchedule` around the current `state`.
    fn start_round(
        &mut self,
        current_round: ExecutionRound,
        round_schedule_builder: RoundScheduleBuilder,
    ) {
        self.current_round = current_round;
        self.round_schedule = round_schedule_builder.build(
            &mut self.state,
            current_round,
            &self.metrics,
            &self.logger,
        );
    }

    /// Creates a new `RoundSchedule` around the current `state` and calls
    /// `RoundSchedule::start_iteration` on it.
    fn start_iteration(&mut self, is_first_iteration: bool) -> IterationSchedule {
        self.round_schedule = RoundScheduleBuilder::new().build(
            &mut self.state,
            self.current_round,
            &self.metrics,
            &self.logger,
        );

        self.start_iteration_only(is_first_iteration)
    }

    /// Calls `RoundSchedule::start_iteration`, mutating canister priorities and
    /// returning the iteration schedule.
    fn start_iteration_only(&mut self, is_first_iteration: bool) -> IterationSchedule {
        let iteration = self
            .round_schedule
            .start_iteration(&mut self.state, is_first_iteration);

        // `IterationSchedule` sanity checks.
        assert_eq!(
            iteration.scheduler_cores,
            self.round_schedule.config.scheduler_cores
        );
        assert_le!(
            iteration.long_execution_cores,
            iteration.long_executions_count
        );
        assert_le!(iteration.long_executions_count, iteration.schedule.len());
        for (i, canister_id) in iteration.schedule.iter().enumerate() {
            let canister_state = self.state.canister_state(canister_id).unwrap();
            if i < iteration.long_executions_count {
                assert_eq!(canister_state.next_execution(), NextExecution::ContinueLong);
            } else {
                assert_eq!(canister_state.next_execution(), NextExecution::StartNew);
            }

            let canister_priority = self.state.canister_priority(canister_id);
            // First `long_execution_cores` canisters must have long_execution_progress set.
            if is_first_iteration && i < iteration.long_execution_cores {
                assert!(canister_priority.long_execution_start_round.is_some());
            }
            // New executions must have no long_execution_progress.
            if i >= iteration.long_executions_count {
                assert!(canister_priority.long_execution_start_round.is_none());
            }
        }

        iteration
    }

    /// Calls `partition_canisters_to_cores` on the real canister states and
    /// immediately puts them back. Returns the per-core canister ID assignment.
    fn partition_to_cores(&mut self, iteration: &IterationSchedule) -> Vec<Vec<CanisterId>> {
        let canisters = self.state.take_canister_states();
        let (partitioned, inactive) = iteration.partition_canisters_to_cores(canisters);
        let mut all_canisters = inactive;
        let cores: Vec<Vec<CanisterId>> = partitioned
            .into_iter()
            .map(|core| {
                core.into_iter()
                    .map(|cs| {
                        let id = cs.canister_id();
                        all_canisters.insert(id, cs);
                        id
                    })
                    .collect()
            })
            .collect();
        self.state.put_canister_states(all_canisters);
        cores
    }

    /// Sets the long execution progress for an existing canister.
    fn set_long_execution_progress(
        &mut self,
        canister_id: CanisterId,
        long_execution_start_round: ExecutionRound,
        executed_rounds: i64,
    ) {
        assert!(self.state.canister_state(&canister_id).is_some());
        let canister_priority = self.state.canister_priority_mut(canister_id);
        canister_priority.long_execution_start_round = Some(long_execution_start_round);
        canister_priority.executed_rounds = executed_rounds;
    }

    fn canister_state(&mut self, canister_id: &CanisterId) -> &mut CanisterState {
        self.state.canister_state_make_mut(canister_id).unwrap()
    }

    /// Returns the canister's scheduling priority (or default if not in the subnet
    /// schedule).
    fn canister_priority(&self, canister_id: &CanisterId) -> &CanisterPriority {
        self.state.canister_priority(canister_id)
    }

    /// Returns a mutable reference to the canister's scheduling priority
    /// (initializing it to default if not present).
    fn canister_priority_mut(&mut self, canister_id: CanisterId) -> &mut CanisterPriority {
        self.state.canister_priority_mut(canister_id)
    }

    /// Returns true if the canister has an explicit scheduling priority, false
    /// otherwise.
    fn has_canister_priority(&self, canister_id: &CanisterId) -> bool {
        self.state
            .metadata
            .subnet_schedule
            .iter()
            .any(|(id, _)| *id == *canister_id)
    }

    /// Returns a reference to the canister's metrics (if it exists).
    fn canister_metrics(&self, canister_id: &CanisterId) -> Option<&CanisterMetrics> {
        self.state
            .canister_state(canister_id)
            .map(|c| c.system_state.canister_metrics())
    }

    /// Enqueues an ingress message in the given canister's queue, so that
    /// `next_execution()` returns `StartNew`.
    fn push_input(&mut self, canister_id: CanisterId) {
        let canister = self.canister_state(&canister_id);
        assert!(
            !canister
                .system_state
                .task_queue
                .has_paused_or_aborted_task()
        );

        if !canister.has_input() {
            let ingress = IngressBuilder::new().receiver(canister_id).build();
            canister.system_state.queues_mut().push_ingress(ingress);
        }
    }

    fn pop_input(&mut self, canister_id: CanisterId) {
        self.canister_state(&canister_id).pop_input();
    }

    fn has_input(&self, canister_id: CanisterId) -> bool {
        self.state.canister_state(&canister_id).unwrap().has_input()
    }

    /// Adds a paused long execution to the canister's task queue.
    fn add_long_execution(&mut self, canister_id: CanisterId) {
        let canister = self.canister_state(&canister_id);
        assert!(!canister.has_input());

        canister
            .system_state
            .task_queue
            .enqueue(ExecutionTask::PausedExecution {
                id: PausedExecutionId(0),
                input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
            });
    }

    /// Removes the `PausedExecution` from the front of the canister's task queue,
    /// so the canister can later report `next_execution()` `None` or `StartNew`.
    /// Used to simulate "long execution completed" for tests.
    fn remove_long_execution(&mut self, canister_id: CanisterId) {
        let canister = self.canister_state(&canister_id);
        assert_matches!(
            canister.system_state.task_queue.pop_front(),
            Some(ExecutionTask::PausedExecution { .. })
        );
    }

    /// Returns true if the canister has a paused execution, false otherwise.
    fn has_long_execution(&mut self, canister_id: CanisterId) -> bool {
        self.canister_state(&canister_id)
            .system_state
            .task_queue
            .has_paused_or_aborted_task()
    }

    /// Adds heap delta debit for an existing canister (for rate-limit tests).
    fn add_heap_delta_debit(&mut self, canister_id: CanisterId, bytes: NumBytes) {
        self.canister_state(&canister_id)
            .scheduler_state
            .heap_delta_debit += bytes;
        if bytes.get() > 0 {
            self.state.canister_priority_mut(canister_id);
        }
    }

    /// Adds install code instruction debit for an existing canister (for
    /// rate-limit tests).
    fn add_install_code_debit(&mut self, canister_id: CanisterId, instructions: NumInstructions) {
        self.canister_state(&canister_id)
            .scheduler_state
            .install_code_debit = instructions;
        if instructions.get() > 0 {
            self.state.canister_priority_mut(canister_id);
        }
    }

    /// Sets the compute allocation for an existing canister.
    fn set_compute_allocation(&mut self, canister_id: CanisterId, percent: u64) {
        self.canister_state(&canister_id)
            .system_state
            .compute_allocation = ComputeAllocation::try_from(percent).unwrap();
    }

    /// Sets up an execution state that exports the heartbeat method. This makes
    /// `has_heartbeat()` return true, causing `finish_round` to treat the canister
    /// as always active (even with no input).
    fn set_heartbeat_export(&mut self, canister_id: CanisterId) {
        let exports = ExportedFunctions::new(BTreeSet::from([WasmMethod::System(
            SystemMethod::CanisterHeartbeat,
        )]));
        self.canister_state(&canister_id).execution_state = Some(ExecutionState::new(
            "NOT_USED".into(),
            WasmBinary::new(CanisterModule::new(vec![])),
            exports,
            Memory::new_for_testing(),
            Memory::new_for_testing(),
            vec![],
            WasmMetadata::default(),
        ));
    }

    fn push_heartbeat_task(&mut self, canister_id: CanisterId) {
        self.canister_state(&canister_id)
            .system_state
            .task_queue
            .enqueue(ExecutionTask::Heartbeat);
    }

    fn scheduled_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.round_schedule.scheduled_canisters
    }

    fn long_execution_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.round_schedule.long_execution_canisters
    }

    fn executed_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.round_schedule.executed_canisters
    }

    fn canisters_with_completed_messages(&self) -> &BTreeSet<CanisterId> {
        &self.round_schedule.canisters_with_completed_messages
    }

    fn fully_executed_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.round_schedule.fully_executed_canisters
    }

    fn rate_limited_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.round_schedule.rate_limited_canisters
    }

    /// Calls `RoundSchedule::end_iteration` with the given sets.
    fn end_iteration(
        &mut self,
        executed_canisters: &BTreeSet<CanisterId>,
        canisters_with_completed_messages: &BTreeSet<CanisterId>,
        low_cycle_balance_canisters: &BTreeSet<CanisterId>,
    ) {
        self.round_schedule.end_iteration(
            &mut self.state,
            executed_canisters,
            canisters_with_completed_messages,
            low_cycle_balance_canisters,
            self.current_round,
        );
    }

    /// Calls `RoundSchedule::finish_round` with the given round number.
    fn finish_round(&mut self) {
        self.round_schedule
            .finish_round(&mut self.state, self.current_round, &self.metrics);
    }
}

struct RoundScheduleBuilder {
    cores: usize,
    heap_delta_rate_limit: NumBytes,
    install_code_rate_limit: NumInstructions,
}

impl RoundScheduleBuilder {
    fn new() -> Self {
        Self {
            cores: 4,
            heap_delta_rate_limit: NumBytes::new(u64::MAX / 2),
            install_code_rate_limit: NumInstructions::new(u64::MAX / 2),
        }
    }

    fn with_cores(mut self, cores: usize) -> Self {
        self.cores = cores;
        self
    }

    fn with_heap_delta_rate_limit(mut self, heap_delta_rate_limit: NumBytes) -> Self {
        self.heap_delta_rate_limit = heap_delta_rate_limit;
        self
    }

    fn with_install_code_rate_limit(mut self, install_code_rate_limit: NumInstructions) -> Self {
        self.install_code_rate_limit = install_code_rate_limit;
        self
    }

    fn build(
        self,
        state: &mut ReplicatedState,
        current_round: ExecutionRound,
        metrics: &SchedulerMetrics,
        logger: &ReplicaLogger,
    ) -> RoundSchedule {
        RoundSchedule::apply_scheduling_strategy(
            state,
            self.cores,
            self.heap_delta_rate_limit,
            FlagStatus::Enabled,
            self.install_code_rate_limit,
            FlagStatus::Enabled,
            current_round,
            ExecutionRound::new(u64::MAX / 2),
            metrics,
            logger,
        )
    }
}

/// Creates a `CanisterPriority` with the given accumulated priority.
fn priority(percent: i64) -> CanisterPriority {
    CanisterPriority {
        accumulated_priority: AccumulatedPriority::new(percent * MULTIPLIER),
        ..CanisterPriority::DEFAULT
    }
}

#[test]
fn fixture_add_canister_default_priority() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister();

    let priority = fixture.canister_priority(&canister_id);
    assert_eq!(priority.accumulated_priority.get(), 0);
    assert!(priority.long_execution_start_round.is_none());
}

#[test]
fn fixture_add_canister_with_priority() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister();
    let priority = priority(100);
    *fixture.canister_priority_mut(canister_id) = priority;

    let p = fixture.canister_priority(&canister_id);
    assert_eq!(p.accumulated_priority, priority.accumulated_priority);
}

#[test]
fn fixture_canister_metrics() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister();

    let metrics = fixture.canister_metrics(&canister_id).unwrap();
    assert_eq!(metrics.rounds_scheduled(), 0);
    assert_eq!(metrics.executed(), 0);
}

/// Verifies that the fixture works with RoundSchedule: start_iteration runs and
/// returns an IterationSchedule. An idle canister (no messages/heartbeat/timer)
/// yields an empty schedule.
#[test]
fn fixture_with_round_schedule_start_iteration() {
    let mut fixture = RoundScheduleFixture::new();
    fixture.canister();

    let iteration = fixture.start_iteration(true);

    // Idle canister has NextExecution::None, so schedule is empty.
    assert!(iteration.is_empty());
}

#[test]
fn fixture_add_canister_with_input() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister_with_input();

    let iteration = fixture.start_iteration(true);

    assert!(!iteration.is_empty());
    assert!(fixture.scheduled_canisters().contains(&canister_id));
}

#[test]
fn fixture_add_canister_with_long_execution() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister_with_long_execution();

    let iteration = fixture.start_iteration(true);

    assert!(!iteration.is_empty());
    assert!(fixture.scheduled_canisters().contains(&canister_id));
    assert!(fixture.long_execution_canisters().contains(&canister_id));
    // Canister should report ContinueLong
    let next_execution = fixture.canister_state(&canister_id).next_execution();
    assert_eq!(next_execution, NextExecution::ContinueLong);
}

//
// --- start_iteration tests ---
//

/// Empty state: no canisters at all → empty schedule, empty scheduled_canisters.
#[test]
fn start_iteration_empty_state() {
    let mut fixture = RoundScheduleFixture::new();

    let iteration = fixture.start_iteration(true);

    assert!(iteration.is_empty());
    assert!(fixture.scheduled_canisters().is_empty());
}

/// Idle canisters: no work, so empty schedule and empty scheduled_canisters.
#[test]
fn start_iteration_idle_canisters() {
    let mut fixture = RoundScheduleFixture::new();
    fixture.canister();
    fixture.canister();

    let iteration = fixture.start_iteration(true);

    assert!(iteration.is_empty());
    assert!(fixture.scheduled_canisters().is_empty());
}

/// Single canister with work: in iterationschedule and in scheduled_canisters.
#[test]
fn start_iteration_single_canister_with_work_in_schedule() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister_with_input();

    let iteration = fixture.start_iteration(true);

    assert!(!iteration.is_empty());
    assert_eq!(iteration.schedule.as_slice(), &[canister_id]);
    assert!(fixture.scheduled_canisters().contains(&canister_id));
}

/// Ordering by priority: higher accumulated_priority appears first in schedule.
#[test]
fn start_iteration_ordering_by_priority() {
    let mut fixture = RoundScheduleFixture::new();
    let high_id = fixture.canister_with_input();
    let low_id = fixture.canister_with_input();
    *fixture.canister_priority_mut(high_id) = priority(20);
    *fixture.canister_priority_mut(low_id) = priority(10);

    let iteration = fixture.start_iteration(true);

    assert_eq!(&iteration.schedule, &[high_id, low_id]);
}

/// Ordering long executions by executed rounds: fewer rounds -> higher
/// priority, regardless of start round.
#[test]
fn start_iteration_ordering_executed_rounds() {
    let mut fixture = RoundScheduleFixture::new();
    let fewer_rounds_id = fixture.canister_with_long_execution();
    fixture.set_long_execution_progress(fewer_rounds_id, ExecutionRound::new(1), 2);
    let more_rounds_id = fixture.canister_with_long_execution();
    fixture.set_long_execution_progress(more_rounds_id, ExecutionRound::new(2), 3);

    let iteration = fixture.start_iteration(true);

    // More rounds = higher priority (more invested work, closer to completion).
    assert_eq!(&iteration.schedule, &[more_rounds_id, fewer_rounds_id]);
}

/// Ordering long executions by start round: same number of executed rounds,
/// earlier start -> higher priority.
#[test]
fn start_iteration_ordering_start_round() {
    let mut fixture = RoundScheduleFixture::new();
    let earlier_start_id = fixture.canister_with_long_execution();
    fixture.set_long_execution_progress(earlier_start_id, ExecutionRound::new(1), 2);
    let later_start_id = fixture.canister_with_long_execution();
    fixture.set_long_execution_progress(later_start_id, ExecutionRound::new(2), 2);

    let iteration = fixture.start_iteration(true);

    // Earlier start = higher priority.
    assert_eq!(&iteration.schedule, &[earlier_start_id, later_start_id]);
}

/// Long executions: first long_execution_cores entries are long executions;
/// long_executions_count > 0 and round long_execution_canisters updated.
#[test]
fn start_iteration_long_executions_first_cores() {
    let mut fixture = RoundScheduleFixture::new();
    let long_id = fixture.canister_with_long_execution();

    let iteration = fixture.start_iteration(true);

    assert!(!iteration.is_empty());
    assert!(iteration.long_executions_count > 0);
    assert_eq!(&iteration.schedule, &[long_id]);
    assert!(fixture.long_execution_canisters().contains(&long_id));
}

/// First iteration: first canisters on each core go into
/// `fully_executed_canisters`.
#[test]
fn start_iteration_first_iteration_fully_executed() {
    let mut fixture = RoundScheduleFixture::new();
    let first_long = fixture.canister_with_long_execution();
    let first_new = fixture.canister_with_input();
    let second_long = fixture.canister_with_long_execution();
    let second_new = fixture.canister_with_input();

    fixture.start_round(
        ExecutionRound::new(1),
        RoundScheduleBuilder::new().with_cores(2),
    );
    fixture.start_iteration_only(true);

    assert!(fixture.fully_executed_canisters().contains(&first_long));
    assert!(fixture.fully_executed_canisters().contains(&first_new));
    assert!(!fixture.fully_executed_canisters().contains(&second_long));
    assert!(!fixture.fully_executed_canisters().contains(&second_new));
    assert!(
        fixture
            .canister_priority(&first_long)
            .long_execution_start_round
            .is_some()
    );
    assert!(
        fixture
            .canister_priority(&second_long)
            .long_execution_start_round
            .is_some()
    );
}

/// Later iteration: no canisters are added to `fully_executed_canisters` (yet;
/// they may be added later, by `end_iteration`).
#[test]
fn start_iteration_later_iteration_not_fully_executed() {
    let mut fixture = RoundScheduleFixture::new();
    let long_id = fixture.canister_with_long_execution();
    let new_id = fixture.canister_with_input();

    fixture.start_iteration(false);

    assert!(!fixture.fully_executed_canisters().contains(&long_id));
    assert!(!fixture.fully_executed_canisters().contains(&new_id));
}

/// First iteration: long execution canisters get `long_execution_start_round`
/// initialized.
#[test]
fn start_iteration_first_iteration_long_execution_start_round() {
    let mut fixture = RoundScheduleFixture::new();
    let long_id = fixture.canister_with_long_execution();

    fixture.start_iteration(true);

    assert!(
        fixture
            .canister_priority(&long_id)
            .long_execution_start_round
            .is_some()
    );
}

/// Later iteration: canister that completed a long execution this round (in
/// long_execution_canisters) and now has StartNew is not scheduled again.
#[test]
fn start_iteration_later_iteration_exclude_completed_long() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_a = fixture.canister_with_long_execution();
    let canister_b = fixture.canister_with_input();

    let iter1 = fixture.start_iteration(true);

    assert!(iter1.schedule.contains(&canister_a));
    assert!(iter1.schedule.contains(&canister_b));

    fixture.remove_long_execution(canister_a);
    fixture.push_input(canister_a);
    let iter2 = fixture
        .round_schedule
        .start_iteration(&mut fixture.state, false);

    assert!(
        !iter2.schedule.contains(&canister_a),
        "canister that completed long execution this round should not be scheduled again as StartNew"
    );
    assert!(iter2.schedule.contains(&canister_b));
}

#[test]
fn start_iteration_with_heap_delta_rate_limit() {
    let limit = ic_base_types::NumBytes::new(1000);
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister_with_input();
    fixture.add_heap_delta_debit(canister_id, limit);

    for is_first_iteration in [true, false] {
        fixture.start_round(
            ExecutionRound::new(1),
            RoundScheduleBuilder::new().with_heap_delta_rate_limit(limit),
        );

        let iteration = fixture.start_iteration_only(is_first_iteration);

        // Canister is rate-limited so not in the iteration schedule.
        assert!(iteration.is_empty());
        assert!(fixture.rate_limited_canisters().contains(&canister_id));
        assert!(fixture.scheduled_canisters().contains(&canister_id));
    }
}

#[test]
fn start_iteration_with_install_code_rate_limit() {
    let limit = NumInstructions::new(1000);
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister_with_input();
    fixture.add_install_code_debit(canister_id, limit);

    for is_first_iteration in [true, false] {
        fixture.start_round(
            ExecutionRound::new(1),
            RoundScheduleBuilder::new().with_install_code_rate_limit(limit),
        );

        let iteration = fixture.start_iteration_only(is_first_iteration);

        // Canister is rate-limited so not in the iteration schedule.
        assert!(iteration.is_empty());
        assert!(fixture.rate_limited_canisters().contains(&canister_id));
        assert!(fixture.scheduled_canisters().contains(&canister_id));
    }
}

/// On the first iteration of a round, a rate-limited canister has its
/// accumulated priority charged by `ONE_HUNDRED_PERCENT` (as if it had executed
/// a full round). Later iterations in the same round must not charge it again.
#[test]
fn start_iteration_first_iteration_charges_rate_limited_canisters() {
    let mut fixture = RoundScheduleFixture::new();

    // A heap delta rate-limited canister with a non-trivial starting AP, so we can
    // verify the exact 100% decrement.
    let heap_delta_limit = ic_base_types::NumBytes::new(1000);
    let heap_delta = fixture.canister_with_input();
    fixture.add_heap_delta_debit(heap_delta, heap_delta_limit);
    *fixture.canister_priority_mut(heap_delta) = priority(40);

    // An install code rate-limited canister with a non-trivial starting AP, so we
    // can verify the exact 100% decrement.
    let install_code_limit = NumInstructions::new(2000);
    let install_code = fixture.canister_with_input();
    fixture.add_install_code_debit(install_code, install_code_limit);
    *fixture.canister_priority_mut(install_code) = priority(50);

    // A non-rate-limited control canister; its AP must not be charged.
    let control = fixture.canister_with_input();
    *fixture.canister_priority_mut(control) = priority(60);

    fixture.start_round(
        ExecutionRound::new(1),
        RoundScheduleBuilder::new()
            .with_heap_delta_rate_limit(heap_delta_limit)
            .with_install_code_rate_limit(install_code_limit),
    );

    for is_first_iteration in [true, false] {
        fixture.start_iteration_only(is_first_iteration);

        assert!(fixture.rate_limited_canisters().contains(&heap_delta));
        assert!(fixture.rate_limited_canisters().contains(&install_code));
        // Rate-limited canisters are charged 100% AP only once, in the first iteration.
        // A subsequent iteration in the same round must not charge them again.
        assert_eq!(
            fixture.canister_priority(&heap_delta).accumulated_priority,
            AccumulatedPriority::new((40 - 100) * MULTIPLIER),
        );
        assert_eq!(
            fixture
                .canister_priority(&install_code)
                .accumulated_priority,
            AccumulatedPriority::new((50 - 100) * MULTIPLIER),
        );
        // Non-rate-limited canister is not charged by `start_iteration`.
        assert_eq!(
            fixture.canister_priority(&control).accumulated_priority,
            AccumulatedPriority::new(60 * MULTIPLIER),
        );
    }
}

#[test]
#[should_panic]
fn start_iteration_scheduler_compute_allocation_invariant_broken() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister_with_input();
    fixture
        .canister_state(&canister_id)
        .system_state
        .compute_allocation = ComputeAllocation::try_from(100).unwrap();

    fixture.start_round(
        ExecutionRound::new(1),
        RoundScheduleBuilder::new().with_cores(2),
    );
    let iteration = fixture.start_iteration_only(true);

    // Without debug_assertions, the canister would be scheduled normally.
    assert_eq!(iteration.schedule.as_slice(), &[canister_id]);
    assert!(fixture.scheduled_canisters().contains(&canister_id));
    // And the compute allocation invariant would be broken.
    assert_eq!(
        fixture
            .metrics
            .scheduler_compute_allocation_invariant_broken
            .get(),
        1
    );
}

//
// --- end_iteration tests ---
//

/// end_iteration accumulates executed_canisters and canisters_with_completed_messages.
#[test]
fn end_iteration_accumulates_executed_and_completed() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_a = fixture.canister_with_input();
    let canister_b = fixture.canister_with_input();
    let canister_c = fixture.canister_with_long_execution();

    let executed = btreeset! {canister_a, canister_b};
    let completed = btreeset! {canister_b};
    fixture.end_iteration(&executed, &completed, &btreeset! {canister_c});

    assert_eq!(fixture.executed_canisters(), &executed);
    assert_eq!(fixture.canisters_with_completed_messages(), &completed);

    fixture.end_iteration(
        &btreeset! {canister_b, canister_c},
        &btreeset! {canister_c},
        &btreeset! {},
    );

    assert_eq!(
        fixture.executed_canisters(),
        &btreeset! {canister_a, canister_b, canister_c}
    );
    assert_eq!(
        fixture.canisters_with_completed_messages(),
        &btreeset! {canister_b, canister_c}
    );
}

/// end_iteration sets `long_execution_start_round` for a newly started long
/// execution and marks the canister as fully executed.
#[test]
fn end_iteration_sets_long_execution_start_round() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister_with_input();

    fixture.start_round(ExecutionRound::new(1), RoundScheduleBuilder::new());
    fixture.start_iteration_only(true);

    // Replace the input with a long execution.
    fixture.pop_input(canister_id);
    fixture.add_long_execution(canister_id);

    fixture.end_iteration(&btreeset! {canister_id}, &btreeset! {}, &btreeset! {});

    // `long_execution_start_round` was set to the current round.
    let canister_priority = fixture.canister_priority(&canister_id);
    assert_eq!(
        canister_priority.long_execution_start_round,
        Some(fixture.current_round)
    );
    // `executed_rounds` is still zero, but the canister was marked fully executed.
    assert_eq!(canister_priority.executed_rounds, 0);
    assert!(fixture.fully_executed_canisters().contains(&canister_id));
}

/// end_iteration resets long_execution_start_round for canisters with completed
/// messages.
#[test]
fn end_iteration_resets_long_execution_start_round_for_completed_messages() {
    let mut fixture = RoundScheduleFixture::new();

    // At the end of the round, `canister_a` has an in-progress long execution.
    let canister_a = fixture.canister_with_long_execution();
    fixture.set_long_execution_progress(canister_a, ExecutionRound::new(1), 2);
    // `canister_b` had a long execution, but now has a new input.
    let canister_b = fixture.canister_with_input();
    fixture.set_long_execution_progress(canister_b, ExecutionRound::new(3), 4);

    let executed = btreeset! {canister_a, canister_b};
    let completed = btreeset! {canister_b};
    fixture.end_iteration(&executed, &completed, &btreeset! {});

    assert_eq!(
        fixture
            .canister_priority(&canister_a)
            .long_execution_start_round,
        Some(ExecutionRound::new(1))
    );
    assert_eq!(
        fixture
            .canister_priority(&canister_b)
            .long_execution_start_round,
        None
    );
}

/// end_iteration resets `long_execution_start_round` for canisters with low
/// cycle balance.
#[test]
fn end_iteration_resets_long_execution_start_round_for_low_cycle_balance() {
    let mut fixture = RoundScheduleFixture::new();
    fixture.current_round = ExecutionRound::new(13);

    // Canister has a long execution at round start.
    let canister_id = fixture.canister_with_long_execution();
    fixture.start_iteration(true);

    // Canister runs out of cycles: the long execution terminates...
    fixture.remove_long_execution(canister_id);
    // ...and end_iteration is called with the canister as having low cycle balance.
    fixture.end_iteration(&btreeset! {}, &btreeset! {}, &btreeset! {canister_id});

    // `long_execution_start_round` was reset.
    assert_eq!(
        fixture
            .canister_priority(&canister_id)
            .long_execution_start_round,
        None
    );
}

/// end_iteration adds canisters with completed messages and
/// `next_execution() == None` to fully_executed_canisters.
#[test]
fn end_iteration_adds_idle_completed_to_fully_executed() {
    let mut fixture = RoundScheduleFixture::new();
    let new = fixture.canister_with_input();
    let long = fixture.canister_with_long_execution();
    let fully_executed = fixture.canister();
    let low_cycle_balance = fixture.canister();
    let all = btreeset! {new, long, fully_executed};
    let none = btreeset! {};

    // Only `new` was executed, no canister completed an execution.
    fixture.end_iteration(&btreeset! {new}, &none, &none);

    // No canister got marked as fully executed (as `new` still has inputs).
    assert_eq!(fixture.fully_executed_canisters(), &btreeset! {});

    // All canisters executed, none completed an execution.
    fixture.end_iteration(&all, &none, &none);

    // `long` counts as fully executed, as it executed a slice.
    // `fully_executed` has no more inputs, so it is also fully executed.
    assert_eq!(
        fixture.fully_executed_canisters(),
        &btreeset! {long, fully_executed}
    );

    // All executed, all completed at least one execution, `low_cycle_balance` was
    // skipped.
    fixture.end_iteration(&all, &all, &btreeset! {low_cycle_balance});

    // `low_cycle_balance` now also counts as fully executed, as it has no inputs.
    assert_eq!(
        fixture.fully_executed_canisters(),
        &btreeset! {long,fully_executed, low_cycle_balance}
    );
}

#[test]
fn advance_long_execution_preserves_long_execution_start_round() {
    let mut fixture = RoundScheduleFixture::new();
    fixture.current_round = ExecutionRound::new(13);

    // A canister with a long execution at round start.
    let canister_id = fixture.canister_with_long_execution();
    let long_execution_start_round = ExecutionRound::new(8);
    fixture.set_long_execution_progress(canister_id, long_execution_start_round, 2);

    // Simulate a round of execution where the canister executes in two iterations.
    fixture.start_iteration(true);
    fixture.end_iteration(&btreeset! {canister_id}, &btreeset! {}, &btreeset! {});
    fixture.start_iteration(false);
    fixture.end_iteration(&btreeset! {canister_id}, &btreeset! {}, &btreeset! {});
    fixture.finish_round();

    // `long_execution_start_round` was preserved.
    assert_eq!(
        fixture
            .canister_priority(&canister_id)
            .long_execution_start_round,
        Some(long_execution_start_round)
    );
    // `executed_rounds` was incremented by 1.
    assert_eq!(fixture.canister_priority(&canister_id).executed_rounds, 3);
}

//
// --- finish_round tests ---
//

/// finish_round increments fully_executed canisters' executed_rounds by 1 and
/// sets last_full_execution_round = current_round (the executed_rounds are then
/// charged in the same round, so executed_rounds is cleared by the end of
/// finish_round).
#[test]
fn finish_round_fully_executed_get_executed_rounds_bumped() {
    let mut fixture = RoundScheduleFixture::new();

    let long = fixture.canister_with_long_execution();
    let new = fixture.canister_with_input();

    // Start with positive AP, so that there's no free compute distribution.
    const LONG_AP: AccumulatedPriority = AccumulatedPriority::new(210 * MULTIPLIER);
    fixture.canister_priority_mut(long).accumulated_priority = LONG_AP;
    const NEW_AP: AccumulatedPriority = AccumulatedPriority::new(110 * MULTIPLIER);
    fixture.canister_priority_mut(new).accumulated_priority = NEW_AP;

    let current_round = ExecutionRound::new(1);
    fixture.start_round(current_round, RoundScheduleBuilder::new().with_cores(2));

    fixture.start_iteration_only(true);
    fixture.end_iteration(&btreeset! {long, new}, &btreeset! {new}, &btreeset! {});
    assert_eq!(fixture.fully_executed_canisters(), &btreeset! {long, new});

    fixture.finish_round();

    // Long execution canister has same AP and executed_rounds bumped by 1.
    let long_priority = fixture.canister_priority(&long);
    assert_eq!(long_priority.accumulated_priority, LONG_AP);
    assert_eq!(long_priority.executed_rounds, 2);
    assert_eq!(long_priority.last_full_execution_round, current_round);

    // New execution canister was charged 100 AP.
    let new_priority = fixture.canister_priority(&new);
    assert_eq!(
        new_priority.accumulated_priority,
        NEW_AP - ONE_HUNDRED_PERCENT
    );
    assert_eq!(new_priority.executed_rounds, 0);
    assert_eq!(new_priority.last_full_execution_round, current_round);
}

/// finish_round grants scheduled canisters their compute allocation and
/// calls observe_round_scheduled() on metrics.
#[test]
fn finish_round_scheduled_get_compute_allocation_and_metrics() {
    let mut fixture = RoundScheduleFixture::new();
    // Add three canisters so the one we check is not in the first two (not fully
    // executed), so it does not get executed_rounds bumped, which would reduce its
    // accumulated priority.
    let mut canister_with_compute_allocation = |percent| {
        let canister = fixture.canister_with_input();
        fixture
            .canister_state(&canister)
            .system_state
            .compute_allocation = ComputeAllocation::try_from(percent).unwrap();
        canister
    };
    let canister_a = canister_with_compute_allocation(30);
    let canister_b = canister_with_compute_allocation(20);
    let canister_c = canister_with_compute_allocation(10);

    let current_round = ExecutionRound::new(1);
    fixture.start_round(current_round, RoundScheduleBuilder::new().with_cores(2));

    fixture.start_iteration_only(true);
    let all = btreeset! {canister_a, canister_b, canister_c};
    fixture.end_iteration(&all, &all, &btreeset! {});
    assert_eq!(
        fixture.fully_executed_canisters(),
        &btreeset! {canister_a, canister_b}
    );

    // All three canisters still have `next_execution() == StartNew`.
    fixture.finish_round();

    let priority = fixture.canister_priority(&canister_c);
    assert_gt!(priority.accumulated_priority.get(), 10 * MULTIPLIER);
    assert_eq!(
        fixture
            .canister_metrics(&canister_c)
            .unwrap()
            .rounds_scheduled(),
        1,
        "observe_round_scheduled should have been called"
    );
}

/// finish_round preserves zero sum: sum(accumulated_priority) over
/// subnet_schedule is 0.
#[test]
fn finish_round_accumulated_priority_zero_sum() {
    let mut fixture = RoundScheduleFixture::new();
    let _a = fixture.canister_with_input();
    let _b = fixture.canister_with_input();

    fixture.start_iteration(true);
    fixture.finish_round();

    let sum_accumulated_priority: i64 = fixture
        .state
        .metadata
        .subnet_schedule
        .iter()
        .map(|(_, p)| p.accumulated_priority.get())
        .sum();
    assert_eq!(
        sum_accumulated_priority, 0,
        "sum of accumulated priority over schedule should be 0"
    );
}

/// `finish_round` charges 100% AP up front for any canister that started a
/// long execution this round (`executed_rounds == 1` and
/// `long_execution_start_round == Some(current_round)`). This is in order to
/// charge all canisters scheduled as new executions in the same round,
/// regardless of whether they end up as long executions or not.
#[test]
fn finish_round_charge_first_slice_of_new_long_execution() {
    let mut fixture = RoundScheduleFixture::new();

    // A canister with an input, pre-loaded to > 100 AP so we can observe the charge
    // without free compute distribution kicking in.
    let canister_id = fixture.canister_with_input();
    const INITIAL_AP: AccumulatedPriority = AccumulatedPriority::new(200 * MULTIPLIER);
    fixture
        .canister_priority_mut(canister_id)
        .accumulated_priority = INITIAL_AP;

    fixture.start_iteration_only(true);

    // Consume the input, replacing it with a long execution.
    fixture.pop_input(canister_id);
    fixture.add_long_execution(canister_id);
    fixture.end_iteration(&btreeset! {canister_id}, &btreeset! {}, &btreeset! {});

    // After `end_iteration` the canister is marked as fully executed and its long
    // execution start round is recorded.
    assert!(fixture.fully_executed_canisters().contains(&canister_id));
    let priority = fixture.canister_priority(&canister_id);
    assert_eq!(priority.executed_rounds, 0);
    assert_eq!(
        priority.long_execution_start_round,
        Some(fixture.current_round),
    );

    fixture.finish_round();

    let priority = fixture.canister_priority(&canister_id);
    // The canister still has a long execution, so `executed_rounds` was bumped and
    // `long_execution_start_round` was preserved.
    assert_eq!(priority.executed_rounds, 1);
    assert_eq!(
        priority.long_execution_start_round,
        Some(fixture.current_round),
    );
    // But `finish_round` charged for the first round of execution.
    assert_eq!(
        priority.accumulated_priority,
        INITIAL_AP - ONE_HUNDRED_PERCENT
    );
}

/// `finish_round` does not charge a canister with an in-flight long execution
/// that wasn't scheduled this round (`executed_rounds == 0`): both charge
/// branches in `finish_round` are gated on `executed_rounds > 0`, so neither
/// fires.
#[test]
fn finish_round_in_flight_long_execution_no_charge() {
    let mut fixture = RoundScheduleFixture::new();
    let current_round = fixture.current_round;

    let canister_id = fixture.canister_with_long_execution();
    // Sanity checks.
    let priority = fixture.canister_priority_mut(canister_id);
    assert_eq!(priority.executed_rounds, 1);
    assert_eq!(priority.long_execution_start_round, Some(current_round));
    // Set some initial positive AP, so we can check that it's not charged.
    const INITIAL_AP: AccumulatedPriority = AccumulatedPriority::new(50 * MULTIPLIER);
    priority.accumulated_priority = INITIAL_AP;

    fixture.start_iteration_only(true);
    fixture.end_iteration(&btreeset! {canister_id}, &btreeset! {}, &btreeset! {});

    fixture.finish_round();

    let priority = fixture.canister_priority(&canister_id);
    // AP is unchanged: no charge, no free compute distributed.
    assert_eq!(priority.accumulated_priority, INITIAL_AP);
    // Executed rounds was bumped by 1.
    assert_eq!(priority.executed_rounds, 2);
    // Long execution start round was preserved.
    assert_eq!(priority.long_execution_start_round, Some(current_round),);
}

/// finish_round charges for executed rounds (clears executed_rounds, reduces
/// accumulated_priority, resets long_execution_start_round) for canisters that
/// complete a long execution.
#[test]
fn finish_round_charges_for_executed_rounds() {
    let mut fixture = RoundScheduleFixture::new();
    // A canister with a long execution, 1 executed_round and AP = 210.
    let canister_id = fixture.canister_with_long_execution();
    const INITIAL_AP: AccumulatedPriority = AccumulatedPriority::new(210 * MULTIPLIER);
    let canister_priority = fixture.canister_priority_mut(canister_id);
    canister_priority.accumulated_priority = INITIAL_AP;
    canister_priority.executed_rounds = 2;

    fixture.start_iteration(true);

    // Long execution completes.
    fixture.remove_long_execution(canister_id);
    fixture.end_iteration(
        &btreeset! {canister_id},
        &btreeset! {canister_id},
        &btreeset! {},
    );

    fixture.finish_round();

    let priority = fixture.canister_priority(&canister_id);
    assert_eq!(priority.executed_rounds, 0);
    assert_eq!(priority.long_execution_start_round, None);
    // Charged for all executed rounds except the first, so two rounds.
    assert_eq!(
        priority.accumulated_priority,
        INITIAL_AP - ONE_HUNDRED_PERCENT * 2
    );
}

/// finish_round applies an exponential decay to AP values outside the
/// `[AP_ROUNDS_MIN, AP_ROUNDS_MAX]` window, in both directions; values inside
/// the window are left untouched.
///
/// The setup uses 4 canisters with very high AP plus 1 canister with very low
/// AP, chosen so that the post-decay sum of AP stays strictly positive. That
/// keeps the free-compute distribution at the end of `finish_round` a no-op,
/// so the only thing affecting AP between input and output is the decay
/// itself.
#[test]
fn finish_round_exponential_decay() {
    // Soft bounds in percent.
    const AP_MIN_PERCENT: i64 = AP_ROUNDS_MIN * 100;
    const AP_MAX_PERCENT: i64 = AP_ROUNDS_MAX * 100;

    // Initial APs, well outside the soft bounds.
    const LOW_AP_PERCENT: i64 = AP_MIN_PERCENT - 1000;
    const HIGH_AP_PERCENT: i64 = AP_MAX_PERCENT + 500;

    // Expected AP after decay: bound + (initial - bound) * AP_DECAY_PERCENT / 100.
    const LOW_DECAYED_PERCENT: i64 = AP_MIN_PERCENT - 1000 * AP_DECAY_PERCENT / 100;
    const HIGH_DECAYED_PERCENT: i64 = AP_MAX_PERCENT + 500 * AP_DECAY_PERCENT / 100;

    // Sanity check: post-decay sum is strictly positive, so `finish_round`'s
    // free-compute distribution is a no-op and any AP change we observe is
    // attributable to the decay.
    const POST_DECAY_TOTAL_PERCENT: i64 = 4 * HIGH_DECAYED_PERCENT + LOW_DECAYED_PERCENT;
    const {
        assert!(POST_DECAY_TOTAL_PERCENT > 0);
    }

    let mut fixture = RoundScheduleFixture::new();

    // A canister below AP_MIN.
    let below_min_canister = fixture.canister();
    *fixture.canister_priority_mut(below_min_canister) = priority(LOW_AP_PERCENT);
    // 4 canisters above AP_MAX. With only one, the post-decay sum would be negative
    // (HIGH_DECAYED_PERCENT < |LOW_DECAYED_PERCENT|) and the free-compute
    // distribution would adjust the AP of `below_min_canister`.
    let above_max_canisters: Vec<_> = (0..4)
        .map(|_| {
            let id = fixture.canister();
            *fixture.canister_priority_mut(id) = priority(HIGH_AP_PERCENT);
            id
        })
        .collect();

    fixture.finish_round();

    for canister_id in &above_max_canisters {
        assert_eq!(
            fixture.canister_priority(canister_id).accumulated_priority,
            AccumulatedPriority::new(HIGH_DECAYED_PERCENT * MULTIPLIER)
        );
    }
    assert_eq!(
        fixture
            .canister_priority(&below_min_canister)
            .accumulated_priority,
        AccumulatedPriority::new(LOW_DECAYED_PERCENT * MULTIPLIER)
    );
}

/// Sets up 4 canisters with compute allocations of 100%, 70%, 20% and 0%
/// (sum = 190%, all starting with AP = 0); "charges" the first canister
/// `executed_rounds` rounds (so its pre-CA AP becomes `-executed_rounds * 100%`,
/// while the others remain at 0); calls `finish_round`; and verifies that each
/// canister's resulting AP matches the corresponding entry of `expected_aps`.
///
/// Used to characterize `finish_round`'s free-compute distribution: free
/// compute = `executed_rounds * 100% - 190%` (sum of CAs), distributed in
/// CA-descending order with each canister's share capped at
/// `per_canister_cap - CA`.
fn check_finish_round_free_compute_grants(executed_rounds: i64, expected_aps: [i64; 4]) {
    let mut fixture = RoundScheduleFixture::new();

    const COMPUTE_ALLOCATIONS: [u64; 4] = [100, 70, 20, 0];
    let canisters: [CanisterId; 4] = std::array::from_fn(|i| {
        let id = fixture.canister_with_input();
        fixture.set_compute_allocation(id, COMPUTE_ALLOCATIONS[i]);
        // Add the canister to the subnet schedule with default (0) priority.
        fixture.canister_priority_mut(id);
        id
    });

    // Charge canister 0 for the executed rounds.
    let executed_rounds_cost = ONE_HUNDRED_PERCENT * executed_rounds;
    fixture
        .canister_priority_mut(canisters[0])
        .accumulated_priority = -executed_rounds_cost;

    fixture.finish_round();

    // "Refund" canister 0's AP, to make it easier to compare with its expected AP.
    fixture
        .canister_priority_mut(canisters[0])
        .accumulated_priority += executed_rounds_cost;

    for (i, canister_id) in canisters.iter().enumerate() {
        let canister_priority = fixture.canister_priority(canister_id);
        assert_eq!(
            canister_priority.accumulated_priority.get() / MULTIPLIER,
            expected_aps[i],
            "canister {i} (CA={}%, executed_rounds={executed_rounds}): unexpected AP",
            COMPUTE_ALLOCATIONS[i],
        );
    }
}

/// `finish_round` distributes the free compute (i.e. `-total_AP` after CA
/// grants, when positive) across canisters in CA-descending order, with each
/// canister's share capped at `per_canister_cap - CA`. With sum of CAs = 190%
/// across 4 canisters, the per-canister cap stays at the default 100% until
/// charged compute exceeds 400% (i.e. `100% * canister_count`), at which point
/// it shifts to `ceil((free + total_CA) / canister_count)` to avoid
/// systematically dropping AP below the floor.
#[test]
fn finish_round_free_compute_capped() {
    // 0 executed rounds: no charge; total_AP = +190% (sum of CAs); free_compute
    // is negative; no distribution. Each canister's AP equals its CA.
    check_finish_round_free_compute_grants(0, [100, 70, 20, 0]);

    // 1 executed round: charge 100%; total_AP = +90%; free_compute still
    // negative; no distribution.
    check_finish_round_free_compute_grants(1, [100, 70, 20, 0]);

    // 2 executed rounds: charge 200%; total_AP = -10%; free_compute = +10%.
    // The 100%-CA canister is already at its 100% cap and gets nothing; the
    // remaining 10% is split (with integer-division remainder) among the other
    // three canisters.
    check_finish_round_free_compute_grants(2, [100, 73, 23, 3]);

    // 3 executed rounds: charge 300%; total_AP = -110%; free_compute = +110%.
    // The 100%-CA canister still gets nothing; the 70%-CA canister hits its
    // 100% cap; the remaining 80% is split equally between the last two.
    check_finish_round_free_compute_grants(3, [100, 100, 60, 40]);

    // 4 executed rounds: charge 400%; total_AP = -210%; free_compute = +210%.
    // free + total_CA = 400% = 100% * canister_count exactly (`>` is false), so
    // the per-canister cap stays at 100% and B/C/D all reach it.
    check_finish_round_free_compute_grants(4, [100, 100, 100, 100]);

    // 5 executed rounds: charge 500%; total_AP = -310%; free_compute = +310%.
    // free + total_CA = 500% > 400%, so the per-canister cap shifts to
    // ceil(500% / 4) = 125%. The 100%-CA canister now also receives a 25%
    // top-up, while B/C/D all reach the new 125% cap.
    check_finish_round_free_compute_grants(5, [125, 125, 125, 125]);
}

#[test]
fn finish_round_grant_heap_delta_and_install_code_credits() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_a = fixture.canister_with_input();
    fixture.add_heap_delta_debit(canister_a, NumBytes::new(100));
    let canister_b = fixture.canister();
    fixture.add_install_code_debit(canister_b, NumInstructions::new(200));
    fixture.start_iteration(true);

    fixture.finish_round();

    // `canister_a` is still in the subnet schedule (it has an input), but has no
    // more heap delta debit.
    assert!(fixture.has_canister_priority(&canister_a));
    assert_eq!(
        fixture
            .canister_state(&canister_a)
            .scheduler_state
            .heap_delta_debit
            .get(),
        0
    );
    // We've observed a total of 100 bytes of heap delta debits.
    assert_eq!(
        fixture.metrics.canister_heap_delta_debits.get_sample_sum(),
        100.0
    );

    // `canister_b` is also still in the subnet schedule, even though it no longer
    // has any install code debit.
    assert!(fixture.has_canister_priority(&canister_b));
    assert_eq!(
        fixture
            .canister_state(&canister_b)
            .scheduler_state
            .install_code_debit
            .get(),
        0
    );
    // We've observed a total of 200 instructions of install code debits.
    assert_eq!(
        fixture
            .metrics
            .canister_install_code_debits
            .get_sample_sum(),
        200.0
    );
}

/// After `finish_round`, a canister with a pending heartbeat task receives
/// the same accumulated priority as a canister with a pending input.
#[test]
fn finish_round_heartbeat_treated_same_as_input() {
    let mut fixture = RoundScheduleFixture::new();
    let current_round = ExecutionRound::new(1);

    let canister_a = fixture.canister_with_input();
    let canister_b = fixture.canister_with_input();
    fixture.set_heartbeat_export(canister_b);

    fixture.start_round(current_round, RoundScheduleBuilder::new().with_cores(2));

    fixture.start_iteration_only(true);
    fixture.pop_input(canister_a);
    fixture.pop_input(canister_b);
    fixture.end_iteration(
        &btreeset! {canister_a, canister_b},
        &btreeset! {canister_a, canister_b},
        &btreeset! {},
    );

    // Both have pending work: A has a new input, B has a heartbeat task.
    fixture.push_input(canister_a);
    fixture.push_heartbeat_task(canister_b);

    fixture.finish_round();

    // Both should remain in the subnet schedule with equal priority.
    let ap_a = fixture
        .canister_priority(&canister_a)
        .accumulated_priority
        .get();
    let ap_b = fixture
        .canister_priority(&canister_b)
        .accumulated_priority
        .get();
    assert_eq!(
        ap_a, ap_b,
        "heartbeat canister should get same priority as input canister"
    );
}

//
// --- CanisterRoundState::Ord tests ---
//

/// Creates a `CanisterRoundState`, with parameters in the order in which they
/// are compared by `CanisterRoundState::Ord`.
fn canister_round_state(
    executed_rounds: i64,
    accumulated_priority: AccumulatedPriority,
    long_execution_start_round: Option<u64>,
    canister_id: CanisterId,
) -> CanisterRoundState {
    CanisterRoundState {
        canister_id,
        accumulated_priority,
        compute_allocation: AccumulatedPriority::new(0),
        executed_rounds,
        long_execution_start_round: long_execution_start_round.map(ExecutionRound::new),
    }
}

#[test]
fn canister_round_state_ord() {
    // Reuse canister IDs, to ensure they don't accidentally affect the ordering.
    const CANISTER_1: CanisterId = CanisterId::from_u64(1);
    const CANISTER_2: CanisterId = CanisterId::from_u64(2);

    let rs = [
        canister_round_state(2, ONE_HUNDRED_PERCENT, Some(1), CANISTER_1),
        // Higher canister ID.
        canister_round_state(2, ONE_HUNDRED_PERCENT, Some(1), CANISTER_2),
        // Later start round.
        canister_round_state(2, ONE_HUNDRED_PERCENT, Some(2), CANISTER_1),
        // Lower AP.
        canister_round_state(2, ZERO, Some(1), CANISTER_1),
        // Fewer executed rounds.
        canister_round_state(1, ONE_HUNDRED_PERCENT, Some(1), CANISTER_1),
        // New execution.
        canister_round_state(0, ONE_HUNDRED_PERCENT, None, CANISTER_1),
        // Higher canister ID.
        canister_round_state(0, ONE_HUNDRED_PERCENT, None, CANISTER_2),
        // Lower AP.
        canister_round_state(0, ZERO, None, CANISTER_1),
    ];

    for (lhs, rhs) in rs.iter().zip(rs.iter().skip(1)) {
        assert_eq!(lhs.cmp(rhs), std::cmp::Ordering::Less);
        assert_eq!(rhs.cmp(lhs), std::cmp::Ordering::Greater);
    }
}

/// `CanisterRoundState::Ord` clamps `executed_rounds` to a minimum of 1 when
/// comparing long executions, so an aborted long execution
/// (`executed_rounds == 0`) ranks equally to a freshly started one
/// (`executed_rounds == 1`) on the primary key, falling through to the AP /
/// start round / canister-id tiebreakers. Without the clamp, an aborted long
/// execution would always lose to any long execution that has at least one
/// slice executed, leading to starvation.
#[test]
fn canister_round_state_ord_aborted_equivalent_to_first_round() {
    const CANISTER_ID: CanisterId = CanisterId::from_u64(1);

    let aborted = canister_round_state(0, ONE_HUNDRED_PERCENT, Some(1), CANISTER_ID);
    let first_round = canister_round_state(1, ZERO, Some(1), CANISTER_ID);

    assert_eq!(aborted.cmp(&first_round), std::cmp::Ordering::Less);
    assert_eq!(first_round.cmp(&aborted), std::cmp::Ordering::Greater);
}

//
// === Multi-round proptests ===
//

const HEAP_DELTA_RATE_LIMIT: NumBytes = NumBytes::new(1000);

/// Cyclical rate-limiting pattern: after every `unlimited_rounds` of full
/// execution, the canister produces `limited_rounds` worth of heap delta. This
/// results in a cycle length of `unlimited_rounds + limited_rounds`, where
/// the canister is executed for `unlimited_rounds` and skipped for the next
/// `limited_rounds` where it would otherwise be scheduled first.
#[derive(Clone, Debug)]
struct RateLimitPattern {
    /// Number of consecutive rate-limited potential full rounds.
    limited_rounds: usize,
    /// Size of the heap delta debit produced after `limited_rounds` of full
    /// execution. The scheduler will skip the canister for this number of rounds.
    unlimited_rounds: usize,
}

/// Describes a class of canisters that share the same scheduling behavior.
///
/// In addition to compute allocation, long vs short execution, backlogging and
/// low cycle balance, the archetype is also described by a couple of cycles:
/// its activity cycle (see below), indexed by round number; and a potential
/// rate limiting cycle (see `RateLimitPattern`), indexed by full execution
/// rounds.
///
/// Every `active_rounds + inactive_rounds` rounds, the canister gets the
/// equivalent of `active_rounds` worth of inputs. These may take the form of
/// separate short executions or a continued long execution
/// (`has_long_execution`). In the former case, the inputs may be consumed at
/// the end of every round or not (`consumes_all_inputs`).
#[derive(Clone, Debug)]
struct CanisterArchetype {
    /// Compute allocation in percent (0-100).
    compute_allocation: u64,
    /// Number of active rounds per cycle.
    active_rounds: usize,
    /// Number of inactive rounds per cycle.
    inactive_rounds: usize,
    /// Whether the canister executes one long message for `active_rounds` or
    /// separate short messages.
    has_long_execution: bool,
    /// Whether or not the canister consumes all its inputs when executed (and not
    /// in a long execution).
    consumes_all_inputs: bool,
    /// Optional rate-limiting cycle.
    rate_limiting: Option<RateLimitPattern>,
    /// Whether this canister is treated as having low cycle balance (skipped
    /// during execution but message consumed).
    low_cycles: bool,
}

impl CanisterArchetype {
    /// Returns the length of the activity cycle.
    fn activity_cycle(&self) -> usize {
        self.active_rounds + self.inactive_rounds
    }

    /// Returns true if the given round is the start of a new activity cycle.
    fn is_new_cycle(&self, round: usize) -> bool {
        round.is_multiple_of(self.activity_cycle())
    }

    /// Returns the heap delta debit produced by the canister after the given number
    /// of full rounds, given its rate limiting pattern. Zero if the canister is not
    /// rate limited or this is not the start of a new rate limiting cycle.
    fn heap_delta_produced(&self, full_rounds: usize) -> NumBytes {
        if let Some(ref rl) = self.rate_limiting
            && full_rounds.is_multiple_of(rl.unlimited_rounds)
        {
            return HEAP_DELTA_RATE_LIMIT * rl.limited_rounds as u64;
        }
        NumBytes::new(0)
    }

    /// Expected number of full rounds the canister should have executed out of the
    /// given number of rounds given its mix of compute allocation and free compute.
    fn expected_full_rounds(&self, num_rounds: usize, free_compute: usize) -> usize {
        // Total compute available to canister, capped at 100%.
        let canister_compute = (self.compute_allocation as usize + free_compute).min(100);

        let expected_rounds_from_ca = num_rounds * canister_compute / 100;
        self.max_rounds_from_rate_limiting(expected_rounds_from_ca)
    }

    /// Hard limit on the number of rounds the canister can execute due to rate
    /// limiting.
    ///
    /// As opposed to the number of full rounds expected based on compute allocation
    /// (which may be exceeded due to the capacity of the extra core), this strictly
    /// limits how many rounds the canister will actually execute (as opposed to
    /// being charged for heap delta debits and skipped).
    fn max_rounds_from_rate_limiting(&self, num_rounds: usize) -> usize {
        if let Some(ref rl) = self.rate_limiting {
            // If the canister is rate-limited, it will have only executed in the
            // unlimited rounds.
            num_rounds * rl.unlimited_rounds / (rl.limited_rounds + rl.unlimited_rounds)
        } else {
            num_rounds
        }
    }
}

/// Per-canister mutable state tracked across the simulation.
struct CanisterSim {
    canister_id: CanisterId,
    archetype: CanisterArchetype,

    /// Execution rounds left in the current activity cycle.
    ///
    /// These could be small messages or a continued long execution, depending on
    /// the archetype's `has_long_execution`.
    current_cycle_rounds_left: usize,

    /// Produced but not yet applied heap delta debit.
    ///
    /// We cannot apply heap delta in the middle of a long execution, so we collect
    /// it here and apply it upon completion.
    heap_delta_debit: NumBytes,

    /// Enqueued inputs, as number of rounds needed to execute.
    ///
    /// These could be small messages or single long executions, depending on the
    /// archetype's `has_long_execution`.
    inputs: VecDeque<usize>,

    /// Number of times the canister got a full execution.
    full_rounds: usize,
}

impl CanisterSim {
    /// Returns true if the canister is partway through an activity cycle or has
    /// a backlog.
    fn is_active(&self) -> bool {
        self.current_cycle_rounds_left > 0 || !self.inputs.is_empty()
    }

    /// Simulates the canister having produced some heap delta (based on its rate
    /// limiting pattern) based on the number of full rounds completed. This will be
    /// applied to the canister state when the current message execution completes.
    fn produce_heap_delta_debit_for_full_round(&mut self) {
        self.heap_delta_debit += self.archetype.heap_delta_produced(self.full_rounds);
    }
}

// --- Proptest strategies ---

prop_compose! {
    fn arb_rate_limit_pattern()(
        limited in 1..4_usize,
        unlimited in 1..6_usize,
    ) -> RateLimitPattern {
        RateLimitPattern { limited_rounds: limited, unlimited_rounds: unlimited }
    }
}

prop_compose! {
    fn arb_archetype()(
        raw_compute_allocation in -200..50_i64,
        active_rounds in 1..5_usize,
        inactive_raw in -2..5_i16,
        mut has_long_execution in proptest::bool::ANY,
        mut consumes_all_inputs in proptest::bool::ANY,
        rate_limiting in proptest::option::of(arb_rate_limit_pattern()),
        low_cycles in proptest::bool::weighted(0.2),
    ) -> CanisterArchetype {
        // Low cycle balance canisters always consume all inputs and never do long
        // executions.
        consumes_all_inputs |= low_cycles;
        has_long_execution &= !low_cycles;

        CanisterArchetype {
            compute_allocation: raw_compute_allocation.max(0) as u64,
            active_rounds,
            inactive_rounds: inactive_raw.max(0) as usize,
            has_long_execution,
            consumes_all_inputs,
            rate_limiting,
            low_cycles,
        }
    }
}

prop_compose! {
    fn arb_archetype_with_count()(
        archetype in arb_archetype(),
        count in 1..8_usize,
    ) -> (CanisterArchetype, usize) {
        (archetype, count)
    }
}

/// Runs a multi-round simulation using `RoundScheduleFixture`, returning the
/// resulting replicated state and per-canister simulation states.
///
/// Only does one iteration per round. And one message or slice per canister.
/// But this is sufficient to approximate the full range of scheduler behavior.
fn run_multi_round_simulation(
    scheduler_cores: usize,
    num_rounds: usize,
    archetypes: &[(CanisterArchetype, usize)],
    debug_canister_idx: Option<usize>,
) -> (ReplicatedState, Vec<CanisterSim>) {
    let mut fixture = RoundScheduleFixture::new();

    let mut sims: Vec<CanisterSim> = Vec::new();
    let mut id_to_sim = BTreeMap::new();
    for (archetype, count) in archetypes {
        for _ in 0..*count {
            let canister_id = fixture.canister();
            fixture.set_compute_allocation(canister_id, archetype.compute_allocation);
            id_to_sim.insert(canister_id, sims.len());
            sims.push(CanisterSim {
                canister_id,
                archetype: archetype.clone(),
                current_cycle_rounds_left: 0,
                heap_delta_debit: NumBytes::new(0),
                inputs: VecDeque::new(),
                full_rounds: 0,
            });
        }
    }

    for round in 0..num_rounds {
        // --- Setup phase: prepare canister state based round and inputs ---
        for (idx, sim) in sims.iter_mut().enumerate() {
            let canister_id = sim.canister_id;

            // Every new cycle, enqueue `active_rounds` worth of work.
            if sim.archetype.is_new_cycle(round) {
                sim.inputs.push_back(sim.archetype.active_rounds);
            }

            if sim.current_cycle_rounds_left == 0 {
                // No cycle in progress.
                if let Some(cycle_rounds) = sim.inputs.pop_front() {
                    // We have backlog, begin the next cycle.
                    fixture.push_input(canister_id);
                    sim.current_cycle_rounds_left = cycle_rounds;

                    if Some(idx) == debug_canister_idx {
                        println!(
                            "round {round}, canister {idx}: full rounds {}, starting cycle with {cycle_rounds} rounds",
                            sim.full_rounds
                        );
                    }
                } else {
                    // No more work, ensure no input.
                    fixture.pop_input(canister_id);
                }
            } else if !sim.archetype.has_long_execution {
                // Active new execution canister, ensure it has an input.
                fixture.push_input(canister_id);
            }
        }

        // --- Start round ---
        let current_round = ExecutionRound::new(round as u64);
        fixture.start_round(
            current_round,
            RoundScheduleBuilder::new()
                .with_cores(scheduler_cores)
                .with_heap_delta_rate_limit(HEAP_DELTA_RATE_LIMIT),
        );

        // --- start_iteration ---
        let iteration = fixture.start_iteration_only(true);

        // --- Simulate core assignment and execution ---
        let core_schedules = fixture.partition_to_cores(&iteration);
        if debug_canister_idx.is_some() {
            println!(
                "round {round}: core schedule: {:?}",
                core_schedules
                    .iter()
                    .map(|core| core.iter().map(|id| id_to_sim[id]).collect::<Vec<_>>())
                    .collect::<Vec<_>>()
            );
        }

        let mut executed_canisters = BTreeSet::new();
        let mut canisters_with_completed_messages = BTreeSet::new();
        let mut low_cycle_balance_canisters = BTreeSet::new();

        for core_schedule in &core_schedules {
            for canister_id in core_schedule {
                let idx = id_to_sim[canister_id];
                let sim = &mut sims[idx];

                // Advance cycle by one round: the canister actually executed.
                sim.current_cycle_rounds_left -= 1;

                if fixture.has_long_execution(*canister_id) {
                    debug_assert!(!sim.archetype.low_cycles);

                    executed_canisters.insert(*canister_id);
                    if sim.current_cycle_rounds_left == 0 {
                        fixture.remove_long_execution(*canister_id);
                        canisters_with_completed_messages.insert(*canister_id);

                        // If we have a backlog, reflect it in the input queue.
                        if !sim.inputs.is_empty() {
                            fixture.push_input(*canister_id);
                        }
                    } else {
                        // Complete slice consumed all instructions, no more executions on this core.
                        break;
                    }
                } else if fixture.has_input(*canister_id) {
                    if sim.archetype.low_cycles {
                        // Low cycles. Pop the input and produce a reject response.
                        fixture.pop_input(*canister_id);
                        low_cycle_balance_canisters.insert(*canister_id);
                    } else {
                        // New execution.
                        executed_canisters.insert(*canister_id);

                        // Transition to long execution if the archetype says so.
                        if sim.archetype.has_long_execution && sim.current_cycle_rounds_left > 0 {
                            fixture.pop_input(*canister_id);
                            fixture.add_long_execution(*canister_id);
                            // We've just executed a complete slice and consumed the instruction budget.
                            break;
                        }
                        canisters_with_completed_messages.insert(*canister_id);

                        if !sim.is_active() || sim.archetype.consumes_all_inputs {
                            // No more work or canister consumes all inputs every round.
                            fixture.pop_input(*canister_id);
                        } else {
                            // Some inputs are left, we presumably ran out of instructions.
                            break;
                        }
                    }
                } else {
                    panic!("canister {idx} scheduled without input or long execution");
                }
            }
        }

        // --- end_iteration ---
        fixture.end_iteration(
            &executed_canisters,
            &canisters_with_completed_messages,
            &low_cycle_balance_canisters,
        );

        // --- finish_round ---
        fixture.finish_round();

        if debug_canister_idx.is_some() {
            println!(
                "round {round}: fully executed canisters: {:?}",
                fixture
                    .fully_executed_canisters()
                    .iter()
                    .map(|c| id_to_sim[c])
                    .sorted()
                    .collect::<Vec<_>>()
            );
            println!(
                "round {round}: canister priorities: {:?}",
                fixture
                    .state
                    .metadata
                    .subnet_schedule
                    .iter()
                    .map(|(canister_id, p)| (
                        id_to_sim[canister_id],
                        p.accumulated_priority.get() / MULTIPLIER,
                        -p.executed_rounds,
                        p.long_execution_start_round.map(|r| r.get()).unwrap_or(0)
                    ))
                    .collect::<Vec<_>>()
            );
        }

        for canister_id in fixture.fully_executed_canisters().clone() {
            let sim = &mut sims[id_to_sim[&canister_id]];
            sim.produce_heap_delta_debit_for_full_round();
            if sim.heap_delta_debit.get() > 0 && !fixture.has_long_execution(canister_id) {
                fixture.add_heap_delta_debit(canister_id, sim.heap_delta_debit);
                sim.heap_delta_debit = NumBytes::new(0);
            }

            sim.full_rounds += 1;
        }
    }

    (fixture.state, sims)
}

/// Asserts the post-simulation invariants.
fn assert_multi_round_invariants(
    state: &ReplicatedState,
    sims: &[CanisterSim],
    scheduler_cores: usize,
    num_rounds: usize,
    total_compute_allocation: usize,
    expected_efficiency_percent: usize,
) -> Result<(), TestCaseError> {
    println!(
        "executed rounds: {:?}",
        sims.iter().map(|s| s.full_rounds).collect::<Vec<_>>()
    );
    println!(
        "canister priorities: {:?}",
        sims.iter()
            .map(|sim| state
                .canister_priority(&sim.canister_id)
                .accumulated_priority
                .get()
                / MULTIPLIER)
            .collect::<Vec<_>>()
    );

    // The sum of accumulated priorities should be zero (or slightly positive, in
    // case e.g. we just distributed compute allocation after not having executed
    // anything this round).
    let sum_ap: i64 = state
        .metadata
        .subnet_schedule
        .iter()
        .map(|(_, p)| p.accumulated_priority.get())
        .sum();
    prop_assert!(sum_ap >= 0, "final sum(AP) = {sum_ap}");

    // Accumulated priority decays exponentially outside the `[AP_ROUNDS_MIN,
    // AP_ROUNDS_MAX]` range. Expect at most 5 extra rounds at either end.
    const AP_UPPER_BOUND: i64 = (AP_ROUNDS_MAX + 5) * 100 * MULTIPLIER;
    const AP_LOWER_BOUND: i64 = (AP_ROUNDS_MIN - 5) * 100 * MULTIPLIER;
    for (i, sim) in sims.iter().enumerate() {
        let canister_priority = state.metadata.subnet_schedule.get(&sim.canister_id);
        assert!(
            canister_priority.accumulated_priority.get() <= AP_UPPER_BOUND
                && canister_priority.accumulated_priority.get() >= AP_LOWER_BOUND,
            "canister {i}: accumulated_priority {} exceeds bound",
            canister_priority.accumulated_priority.get() / MULTIPLIER,
        );
    }

    // In most cases, the scheduler will actually fairly share all scheduler cores.
    // There are, however edge cases where the interaction between long and short
    // executions results in contention, so we must be conservative and only account
    // for "guaranteed" free compute.
    let compute_capacity = (scheduler_cores - 1) * 100;
    let free_compute_per_canister = (compute_capacity - total_compute_allocation) / sims.len();

    // Canisters must have either consumed all inputs; or executed proportionally to
    // their compute allocation and rate limiting.
    for (i, sim) in sims.iter().enumerate() {
        let canister_id = sim.canister_id;
        let canister_priority = state.metadata.subnet_schedule.get(&canister_id);

        // If (and only if) the canister has a backlog, check that it got executed as
        // much as its compute allocation and rate limiting allow.
        //
        // Note that we only count full execution rounds, because that is what the
        // scheduler accounts for. Any free "tail executions" (when the canister was not
        // scheduled first and did not consume all its messages) either result in the
        // canister consuming all its inputs; or else don't count for fairness.
        if sim.inputs.len() > 1 {
            let executed_rounds = sim.full_rounds;
            let credit_rounds = canister_priority.accumulated_priority.get() / MULTIPLIER / 100;
            let credit_rounds = credit_rounds.max(0) as usize;
            let mut expected_rounds = sim
                .archetype
                .expected_full_rounds(num_rounds, free_compute_per_canister);

            expected_rounds = expected_rounds * expected_efficiency_percent / 100;
            prop_assert!(
                executed_rounds + credit_rounds + 1 >= expected_rounds,
                "canister {i}: executed_rounds {executed_rounds} + credit_rounds {credit_rounds} < expected_rounds {expected_rounds}"
            );
        }
    }

    Ok(())
}

#[test_strategy::proptest(ProptestConfig { cases: 40, max_shrink_iters: 0, ..ProptestConfig::default() })]
fn multi_round_priority_invariants(
    #[strategy(2..6_usize)] scheduler_cores: usize,
    #[strategy(200..800_usize)] num_rounds: usize,
    #[strategy(proptest::collection::vec(arb_archetype_with_count(), 2..=5))]
    archetype_configs: Vec<(CanisterArchetype, usize)>,
) {
    let total_compute_allocation: usize = archetype_configs
        .iter()
        .map(|(a, c)| a.compute_allocation as usize * *c)
        .sum();
    let capacity = (scheduler_cores - 1) * 100;
    prop_assume!(total_compute_allocation < capacity);

    let (state, sims) =
        run_multi_round_simulation(scheduler_cores, num_rounds, &archetype_configs, None);

    // Expect 80%+ efficient scheduling with a mix of long and short executions.
    //
    // This is due to idle canisters consuming free compute on rounds where not all
    // cores are busy, reducing free compute available to active canisters.
    let expected_efficiency_percent = 80;
    assert_multi_round_invariants(
        &state,
        &sims,
        scheduler_cores,
        num_rounds,
        total_compute_allocation,
        expected_efficiency_percent,
    )?;
}

#[test_strategy::proptest(ProptestConfig { cases: 40, max_shrink_iters: 0, ..ProptestConfig::default() })]
fn multi_round_all_active_short_executions(
    #[strategy(proptest::collection::vec(-100..100_i64, 2..=10))] raw_allocations: Vec<i64>,
) {
    let allocations: Vec<u64> = raw_allocations.iter().map(|&a| a.max(0) as u64).collect();

    // Minimum number of scheduler cores to accomodate the total compute allocation.
    let total_compute_allocation: u64 = allocations.iter().sum();
    let scheduler_cores = total_compute_allocation as usize / 100 + 2;

    let archetype_configs: Vec<(CanisterArchetype, usize)> = allocations
        .into_iter()
        .map(|ca| {
            (
                CanisterArchetype {
                    compute_allocation: ca,
                    active_rounds: 1_000,
                    inactive_rounds: 0,
                    has_long_execution: false,
                    consumes_all_inputs: false,
                    rate_limiting: None,
                    low_cycles: false,
                },
                1,
            )
        })
        .collect();

    let num_rounds = 100;
    let (state, sims) =
        run_multi_round_simulation(scheduler_cores, num_rounds, &archetype_configs, None);

    // Expect 100% efficient scheduling with short executions only.
    let expected_efficiency_percent = 100;
    assert_multi_round_invariants(
        &state,
        &sims,
        scheduler_cores,
        num_rounds,
        total_compute_allocation as usize,
        expected_efficiency_percent,
    )?;
}
