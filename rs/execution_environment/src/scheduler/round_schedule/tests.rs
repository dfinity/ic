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
use ic_types::{AccumulatedPriority, ComputeAllocation, ExecutionRound, LongExecutionMode};
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
    next_canister_id: u64,
    // Keeps MetricsRegistry alive for self.metrics.
    _registry: MetricsRegistry,
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
        Self::with_round_schedule(RoundScheduleBuilder::new().build())
    }

    /// Creates a new fixture with the given `RoundSchedule` and an empty
    /// `ReplicatedState`.
    fn with_round_schedule(round_schedule: RoundSchedule) -> Self {
        let registry = MetricsRegistry::new();
        let metrics = SchedulerMetrics::new(&registry);
        Self {
            round_schedule,
            state: ReplicatedState::new(subnet_test_id(1), SubnetType::Application),
            next_canister_id: 0,
            _registry: registry,
            metrics,
            logger: ic_logger::replica_logger::test_logger(Some(slog::Level::Info)),
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
        canister_id
    }

    /// Calls `RoundSchedule::start_iteration`, mutating canister priorities and
    /// returning the iteration schedule.
    fn start_iteration(&mut self, is_first_iteration: bool) -> IterationSchedule {
        let iteration = self.round_schedule.start_iteration(
            &mut self.state,
            is_first_iteration,
            &self.metrics,
            &self.logger,
        );

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
            // First `long_executions_count` canisters have `next_execution == ContinueLong`,
            // the rest have `next_execution == StartNew`.
            if i < iteration.long_executions_count {
                assert_eq!(canister_state.next_execution(), NextExecution::ContinueLong);
            } else {
                assert_eq!(canister_state.next_execution(), NextExecution::StartNew);
            }

            let canister_priority = self.state.canister_priority(canister_id);
            // First `long_execution_cores` canisters get `Prioritized` long execution mode.
            if is_first_iteration && i < iteration.long_execution_cores {
                assert_eq!(
                    canister_priority.long_execution_mode,
                    LongExecutionMode::Prioritized
                );
            }
            // New executions must have `Opportunistic` long execution mode.
            if i >= iteration.long_executions_count {
                assert_eq!(
                    canister_priority.long_execution_mode,
                    LongExecutionMode::Opportunistic
                );
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

    /// Sets the scheduling priority for an existing canister.
    fn set_priority(&mut self, canister_id: CanisterId, priority: CanisterPriority) {
        assert!(self.state.canister_state(&canister_id).is_some());
        *self.state.canister_priority_mut(canister_id) = priority;
    }

    /// Sets the long execution mode for an existing canister.
    fn set_long_execution_mode(&mut self, canister_id: CanisterId, mode: LongExecutionMode) {
        assert!(self.state.canister_state(&canister_id).is_some());
        self.state
            .canister_priority_mut(canister_id)
            .long_execution_mode = mode;
    }

    fn canister_state(&mut self, canister_id: &CanisterId) -> &mut CanisterState {
        self.state.canister_state_make_mut(canister_id).unwrap()
    }

    /// Returns the canister's scheduling priority (or default if not in the subnet
    /// schedule).
    fn canister_priority(&self, canister_id: &CanisterId) -> &CanisterPriority {
        self.state.canister_priority(canister_id)
    }

    /// Returns true if the canister has an explicit scheduling priority, false
    /// otherwise.
    #[allow(dead_code)]
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
        self.canister_state(&canister_id)
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

    fn scheduled_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.round_schedule.scheduled_canisters
    }

    fn long_execution_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.round_schedule.long_execution_canisters
    }

    #[allow(dead_code)]
    fn executed_canisters(&self) -> &BTreeSet<CanisterId> {
        &self.round_schedule.executed_canisters
    }

    #[allow(dead_code)]
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
        );
    }

    /// Calls `RoundSchedule::finish_round` with the given round number.
    fn finish_round(&mut self, current_round: ExecutionRound) {
        self.round_schedule
            .finish_round(&mut self.state, current_round, &self.metrics);
    }
}

struct RoundScheduleBuilder {
    cores: usize,
    heap_delta_rate_limit: NumBytes,
    rate_limiting_of_heap_delta: FlagStatus,
    install_code_rate_limit: NumInstructions,
    rate_limiting_of_instructions: FlagStatus,
}

#[allow(dead_code)]
impl RoundScheduleBuilder {
    fn new() -> Self {
        Self {
            cores: 4,
            heap_delta_rate_limit: NumBytes::new(u64::MAX / 2),
            rate_limiting_of_heap_delta: FlagStatus::Enabled,
            install_code_rate_limit: NumInstructions::new(u64::MAX / 2),
            rate_limiting_of_instructions: FlagStatus::Enabled,
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

    fn disable_rate_limiting_of_heap_delta(mut self) -> Self {
        self.rate_limiting_of_heap_delta = FlagStatus::Disabled;
        self
    }

    fn build(self) -> RoundSchedule {
        RoundSchedule::new(
            self.cores,
            self.heap_delta_rate_limit,
            self.rate_limiting_of_heap_delta,
            self.install_code_rate_limit,
            self.rate_limiting_of_instructions,
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
    assert_eq!(
        priority.long_execution_mode,
        LongExecutionMode::Opportunistic
    );
}

#[test]
fn fixture_add_canister_with_priority() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister();
    let priority = priority(100);
    fixture.set_priority(canister_id, priority);

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

// --- start_iteration tests (TEST_PLAN §1.1) ---

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
    fixture.set_priority(high_id, priority(20));
    fixture.set_priority(low_id, priority(10));

    let iteration = fixture.start_iteration(true);

    assert_eq!(&iteration.schedule, &[high_id, low_id]);
}

/// Ordering by long execution mode: Prioritized before Opportunistic.
#[test]
fn start_iteration_ordering_long_execution_mode() {
    let mut fixture = RoundScheduleFixture::new();
    let prioritized_id = fixture.canister_with_long_execution();
    fixture.set_long_execution_mode(prioritized_id, LongExecutionMode::Prioritized);
    let opportunistic_id = fixture.canister_with_long_execution();

    let iteration = fixture.start_iteration(true);

    assert_eq!(&iteration.schedule, &[prioritized_id, opportunistic_id]);
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
    let round_schedule = RoundScheduleBuilder::new().with_cores(2).build();
    let mut fixture = RoundScheduleFixture::with_round_schedule(round_schedule);
    let first_long = fixture.canister_with_long_execution();
    let first_new = fixture.canister_with_input();
    let second_long = fixture.canister_with_long_execution();
    let second_new = fixture.canister_with_input();

    fixture.start_iteration(true);

    assert!(fixture.fully_executed_canisters().contains(&first_long));
    assert!(fixture.fully_executed_canisters().contains(&first_new));
    assert!(!fixture.fully_executed_canisters().contains(&second_long));
    assert!(!fixture.fully_executed_canisters().contains(&second_new));
    assert_eq!(
        fixture.canister_priority(&first_long).long_execution_mode,
        LongExecutionMode::Prioritized
    );
    assert_ne!(
        fixture.canister_priority(&second_long).long_execution_mode,
        LongExecutionMode::Prioritized
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
    assert_ne!(
        fixture.canister_priority(&long_id).long_execution_mode,
        LongExecutionMode::Prioritized
    );
}

/// First iteration: first `long_execution_cores` canisters get `Prioritized`
/// long execution mode.
#[test]
fn start_iteration_first_iteration_prioritized_mode() {
    let mut fixture = RoundScheduleFixture::new();
    let long_id = fixture.canister_with_long_execution();

    fixture.start_iteration(true);

    assert_eq!(
        fixture.canister_priority(&long_id).long_execution_mode,
        LongExecutionMode::Prioritized
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
    let iter2 = fixture.start_iteration(false);

    assert!(
        !iter2.schedule.contains(&canister_a),
        "canister that completed long execution this round should not be scheduled again as StartNew"
    );
    assert!(iter2.schedule.contains(&canister_b));
}

#[test]
fn start_iteration_with_heap_delta_rate_limit() {
    let limit = ic_base_types::NumBytes::new(1000);
    let mut fixture = RoundScheduleFixture::with_round_schedule(
        RoundScheduleBuilder::new()
            .with_heap_delta_rate_limit(limit)
            .build(),
    );
    let canister_id = fixture.canister_with_input();
    fixture.add_heap_delta_debit(canister_id, limit);

    let iteration = fixture.start_iteration(true);

    // Canister is rate-limited so not in the iteration schedule.
    assert!(iteration.is_empty());
    assert!(fixture.rate_limited_canisters().contains(&canister_id));
    assert!(fixture.scheduled_canisters().contains(&canister_id));
}

#[test]
#[should_panic]
fn start_iteration_scheduler_compute_allocation_invariant_broken() {
    let round_schedule = RoundScheduleBuilder::new().with_cores(2).build();
    let mut fixture = RoundScheduleFixture::with_round_schedule(round_schedule);
    let canister_id = fixture.canister_with_input();
    fixture
        .canister_state(&canister_id)
        .system_state
        .compute_allocation = ComputeAllocation::try_from(100).unwrap();

    let iteration = fixture.start_iteration(true);

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

// --- end_iteration tests (TEST_PLAN §1.2) ---

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

/// end_iteration resets long_execution_mode to Opportunistic for canisters in
/// canisters_with_completed_messages.
#[test]
fn end_iteration_resets_long_execution_mode_to_opportunistic() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_a = fixture.canister_with_long_execution();
    fixture.set_long_execution_mode(canister_a, LongExecutionMode::Prioritized);
    let canister_b = fixture.canister_with_long_execution();
    fixture.set_long_execution_mode(canister_b, LongExecutionMode::Prioritized);

    let executed = btreeset! {canister_a, canister_b};
    let completed = btreeset! {canister_b};
    fixture.end_iteration(&executed, &completed, &btreeset! {});

    assert_eq!(
        fixture.canister_priority(&canister_a).long_execution_mode,
        LongExecutionMode::Prioritized
    );
    assert_eq!(
        fixture.canister_priority(&canister_b).long_execution_mode,
        LongExecutionMode::Opportunistic
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

    // `long` counts as fully executed, as it executed a full slice.
    // `fully_executed` has no more inputs, so it is also counts as fully executed.
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

// --- finish_round tests (TEST_PLAN §1.3) ---

/// finish_round gives fully_executed canisters priority_credit += 100% and
/// last_full_execution_round = current_round (the credit is then applied in
/// the same round, so priority_credit is cleared by the end of finish_round).
#[test]
fn finish_round_fully_executed_get_credit() {
    let round_schedule = RoundScheduleBuilder::new().with_cores(2).build();
    let mut fixture = RoundScheduleFixture::with_round_schedule(round_schedule);
    let long = fixture.canister_with_long_execution();
    let new = fixture.canister_with_input();

    fixture.start_iteration(true);
    fixture.end_iteration(&btreeset! {long, new}, &btreeset! {new}, &btreeset! {});
    assert_eq!(fixture.fully_executed_canisters(), &btreeset! {long, new});

    let current_round = ExecutionRound::new(1);
    fixture.finish_round(current_round);

    for canister_id in [long, new] {
        let priority = fixture.canister_priority(&canister_id);
        assert_eq!(
            priority.last_full_execution_round, current_round,
            "fully executed canister should have last_full_execution_round set"
        );
    }
}

/// finish_round grants scheduled canisters their compute allocation and
/// observe_round_scheduled() on metrics.
#[test]
fn finish_round_scheduled_get_compute_allocation_and_metrics() {
    let round_schedule = RoundScheduleBuilder::new().with_cores(2).build();
    let mut fixture = RoundScheduleFixture::with_round_schedule(round_schedule);
    // Add three canisters so the one we check is not in the first two (not fully
    // executed), so it does not get priority_credit applied which would reduce its AP.
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

    fixture.start_iteration(true);
    let all = btreeset! {canister_a, canister_b, canister_c};
    fixture.end_iteration(&all, &all, &btreeset! {});
    assert_eq!(
        fixture.fully_executed_canisters(),
        &btreeset! {canister_a, canister_b}
    );

    // All three canisters still have `next_execution() != StartNew`.
    fixture.finish_round(ExecutionRound::new(1));

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

/// finish_round preserves zero sum: sum of (accumulated_priority - priority_credit)
/// over subnet_schedule is 0.
#[test]
fn finish_round_free_allocation_zero_sum() {
    let mut fixture = RoundScheduleFixture::new();
    let _a = fixture.canister_with_input();
    let _b = fixture.canister_with_input();

    fixture.start_iteration(true);
    fixture.finish_round(ExecutionRound::new(1));

    let sum_true_priority: i64 = fixture
        .state
        .metadata
        .subnet_schedule
        .iter()
        .map(|(_, p)| p.true_priority().get())
        .sum();
    assert_eq!(
        sum_true_priority, 0,
        "sum of true_priority over schedule should be 0"
    );
}

/// finish_round drops an idle canister with zero accumulated priority from the
/// subnet schedule when it has no inputs or heap delta / install code debits.
#[test]
fn finish_round_idle_at_zero_dropped_from_schedule() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister_with_input();
    fixture.start_iteration(true);
    // Simulate "canister ran and consumed its input".
    fixture.pop_input(canister_id);
    fixture.end_iteration(
        &btreeset! {canister_id},
        &btreeset! {canister_id},
        &btreeset! {},
    );

    assert!(fixture.fully_executed_canisters().contains(&canister_id));
    assert!(
        fixture
            .state
            .metadata
            .subnet_schedule
            .iter()
            .any(|(id, _)| *id == canister_id),
        "canister should be in schedule before finish_round"
    );

    fixture.finish_round(ExecutionRound::new(1));

    assert!(
        !fixture
            .state
            .metadata
            .subnet_schedule
            .iter()
            .any(|(id, _)| *id == canister_id),
        "idle canister with zero priority should be dropped from schedule"
    );
}

/// finish_round applies priority_credit (clears credit, reduces accumulated_priority,
/// resets long_execution_mode) for canisters not in ContinueLong or in
/// canisters_with_completed_messages.
#[test]
fn finish_round_apply_priority_credit() {
    let mut fixture = RoundScheduleFixture::new();
    // A canister with a long execution and non-zero priority_credit.
    let canister_id = fixture.canister_with_long_execution();
    fixture.set_priority(
        canister_id,
        CanisterPriority {
            priority_credit: AccumulatedPriority::new(1 * MULTIPLIER),
            ..*fixture.canister_priority(&canister_id)
        },
    );

    fixture.start_iteration(true);
    // Set Prioritized and priority_credit; do not add to completed so end_iteration
    // does not reset long_execution_mode — we want finish_round to apply_priority_credit.
    // fixture.set_long_execution_mode(canister_id, LongExecutionMode::Prioritized);
    fixture.remove_long_execution(canister_id);

    fixture.finish_round(ExecutionRound::new(1));

    let priority = fixture.canister_priority(&canister_id);
    assert_eq!(
        priority.priority_credit.get(),
        0,
        "priority_credit should be cleared after apply_priority_credit"
    );
    assert_eq!(
        priority.long_execution_mode,
        LongExecutionMode::Opportunistic,
        "long_execution_mode should be reset to default"
    );
}

#[test]
fn finish_round_grant_heap_delta_and_install_code_credits() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_a = fixture.canister_with_input();
    fixture.add_heap_delta_debit(canister_a, NumBytes::new(100));
    let canister_b = fixture.canister();
    fixture.add_install_code_debit(canister_b, NumInstructions::new(200));
    fixture.start_iteration(true);

    fixture.finish_round(ExecutionRound::new(1));

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

    // `canister_b` is no longer in the subnet schedule, it has no install code
    // debit.
    assert!(!fixture.has_canister_priority(&canister_b));
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

/// Canisters with a heartbeat export and no input behave identically to canisters
/// with an input in `finish_round`: both stay in the subnet schedule and receive
/// free allocation.
#[test]
fn finish_round_heartbeat_treated_same_as_input() {
    let round_schedule = RoundScheduleBuilder::new().with_cores(2).build();
    let mut fixture = RoundScheduleFixture::with_round_schedule(round_schedule);

    // Canister A has input, canister B has heartbeat export (but no input).
    let canister_a = fixture.canister_with_input();
    let canister_b = fixture.canister();
    fixture.set_heartbeat_export(canister_b);
    // Give B an input so it gets scheduled, then we'll pop it before finish_round.
    fixture.push_input(canister_b);

    fixture.start_iteration(true);
    // Simulate execution: both canisters consume their input.
    fixture.pop_input(canister_a);
    fixture.pop_input(canister_b);
    fixture.end_iteration(
        &btreeset! {canister_a, canister_b},
        &btreeset! {canister_a, canister_b},
        &btreeset! {},
    );

    // Push a new input to A so it appears active; B has no input but has heartbeat.
    fixture.push_input(canister_a);

    fixture.finish_round(ExecutionRound::new(1));

    // Both should remain in the subnet schedule.
    let in_schedule = |id: &CanisterId| {
        fixture
            .state
            .metadata
            .subnet_schedule
            .iter()
            .any(|(c, _)| c == id)
    };
    assert!(
        in_schedule(&canister_a),
        "canister with input should stay in schedule"
    );
    assert!(
        in_schedule(&canister_b),
        "canister with heartbeat should stay in schedule"
    );

    // Both should have the same accumulated priority (symmetric treatment).
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

// === Multi-round proptests ===

const HEAP_DELTA_RATE_LIMIT: NumBytes = NumBytes::new(1000);

/// Cyclical rate-limiting pattern.
#[derive(Clone, Debug)]
struct RateLimitPattern {
    /// Number of consecutive rate-limited sim_rounds.
    limited_rounds: usize,
    /// Number of consecutive non-rate-limited sim_rounds.
    unlimited_rounds: usize,
}

/// Describes a class of canisters that share the same scheduling behavior.
///
/// The activity cycle is indexed by round number. The rate limiting pattern is
/// indexed by the number of rounds executed.
#[derive(Clone, Debug)]
struct CanisterArchetype {
    /// Compute allocation in percent (0-100).
    compute_allocation: u64,
    /// Number of consecutive active sim_rounds per cycle.
    active_rounds: usize,
    /// Number of consecutive inactive sim_rounds per cycle.
    inactive_rounds: usize,
    /// Whether or not the canister executes long messages.
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
    fn activity_cycle(&self) -> usize {
        self.active_rounds + self.inactive_rounds
    }

    fn is_new_cycle(&self, round: usize) -> bool {
        round % self.activity_cycle() == 0
    }

    fn heap_delta_produced(&self, round: usize) -> NumBytes {
        if let Some(ref rl) = self.rate_limiting {
            if round % (rl.limited_rounds + rl.unlimited_rounds) == 0 {
                return HEAP_DELTA_RATE_LIMIT * rl.limited_rounds as u64;
            }
        }
        NumBytes::new(0)
    }

    fn expected_full_rounds(&self, num_rounds: usize) -> usize {
        let expected_rounds_from_ca = num_rounds * self.compute_allocation as usize / 100;
        if let Some(ref rl) = self.rate_limiting {
            expected_rounds_from_ca * rl.unlimited_rounds
                / (rl.limited_rounds + rl.unlimited_rounds)
        } else {
            expected_rounds_from_ca
        }
    }
}

/// Per-canister mutable state tracked across the simulation.
struct CanisterSim {
    canister_id: CanisterId,
    archetype: CanisterArchetype,

    /// Execution rounds left in the current cycle.
    ///
    /// These could be small messages or a continued long execution, depending on
    /// the archetype's `has_long_execution`.
    current_cycle_rounds_left: usize,

    /// Not yet applied heap delta debit.
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
    fn is_active(&self) -> bool {
        self.current_cycle_rounds_left > 0 || !self.inputs.is_empty()
    }

    fn produce_heap_delta_debit(&mut self, round: usize) {
        self.heap_delta_debit += self.archetype.heap_delta_produced(round);
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
        compute_allocation in 0..50_u64,
        active_rounds in 1..8_usize,
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
            compute_allocation,
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
/// per-canister simulation state after all rounds.
fn run_multi_round_simulation(
    scheduler_cores: usize,
    num_rounds: usize,
    archetypes: &[(CanisterArchetype, usize)],
) -> (RoundScheduleFixture, Vec<CanisterSim>) {
    const CANISTER_IDX: Option<usize> = None;

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
        fixture.round_schedule = RoundScheduleBuilder::new()
            .with_cores(scheduler_cores)
            .with_heap_delta_rate_limit(HEAP_DELTA_RATE_LIMIT)
            .build();

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

                    if Some(idx) == CANISTER_IDX {
                        println!(
                            "round {round}, canister {idx}: starting cycle with {cycle_rounds} rounds"
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

        // --- start_iteration ---
        let iteration = fixture.start_iteration(true);

        // --- Simulate core assignment and execution ---
        let core_schedules = fixture.partition_to_cores(&iteration);
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
                        canisters_with_completed_messages.insert(*canister_id);

                        // Transition to long execution if the archetype says so.
                        if sim.archetype.has_long_execution && sim.current_cycle_rounds_left > 0 {
                            fixture.pop_input(*canister_id);
                            fixture.add_long_execution(*canister_id);
                            // We've just executed a full slice and consumed the instruction budget.
                            break;
                        }

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
        let current_round = ExecutionRound::new(round as u64);
        fixture.finish_round(current_round);

        if CANISTER_IDX.is_some() {
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
                        p.accumulated_priority.get() / MULTIPLIER
                    ))
                    .collect::<Vec<_>>()
            );
        }

        for canister_id in fixture.fully_executed_canisters().clone() {
            let sim = &mut sims[id_to_sim[&canister_id]];
            sim.produce_heap_delta_debit(round);
            if sim.heap_delta_debit.get() > 0 && !fixture.has_long_execution(canister_id) {
                fixture.add_heap_delta_debit(canister_id, sim.heap_delta_debit);
                sim.heap_delta_debit = NumBytes::new(0);
            }

            sim.full_rounds += 1;
        }
    }

    (fixture, sims)
}

/// Asserts the post-simulation invariants.
fn assert_multi_round_invariants(
    fixture: &RoundScheduleFixture,
    sims: &[CanisterSim],
    num_rounds: usize,
) -> Result<(), TestCaseError> {
    println!(
        "executed rounds: {:?}",
        sims.iter().map(|s| s.full_rounds).collect::<Vec<_>>()
    );
    println!(
        "canister priorities: {:?}",
        sims.iter()
            .map(|sim| fixture
                .state
                .canister_priority(&sim.canister_id)
                .accumulated_priority
                .get()
                / MULTIPLIER)
            .collect::<Vec<_>>()
    );

    // The positive side of accumulated_priority is capped at AP_ROUNDS_MAX *
    // 100% = 500% by finish_round (via the free allocation cap). Negative AP can
    // grow arbitrarily: it simply means the canister got to execute more than its
    // share (because spare compute was available) and will be deprioritized later.
    let ap_upper_bound = 50 * 100 * MULTIPLIER;
    for (i, sim) in sims.iter().enumerate() {
        let canister_priority = fixture.state.metadata.subnet_schedule.get(&sim.canister_id);
        assert!(
            canister_priority.accumulated_priority.get() <= ap_upper_bound,
            "canister {i}: accumulated_priority {} exceeds upper bound",
            canister_priority.accumulated_priority.get() / MULTIPLIER,
        );
    }

    // Sanity check: always-active canisters that also keep an input at the end
    // of each round should never be dropped from the schedule. Their
    // last_full_execution_round must be positive by the end of the simulation.
    for (i, sim) in sims.iter().enumerate() {
        let canister_id = sim.canister_id;
        let canister_priority = fixture.state.metadata.subnet_schedule.get(&canister_id);

        // If (and only if) the canister has a backlog, check that it got executed as
        // much as its compute allocation and rate limiting allow.
        if sim.inputs.len() > 1 {
            let executed_rounds = sim.full_rounds as i64;
            let credit_rounds = canister_priority.accumulated_priority.get() / MULTIPLIER / 100;
            let expected_rounds = sim.archetype.expected_full_rounds(num_rounds);
            prop_assert!(
                executed_rounds + credit_rounds + 1 >= expected_rounds as i64,
                "canister {i}: executed_rounds {executed_rounds} + credit_rounds {credit_rounds} < expected_rounds {expected_rounds}",
            );
        }
    }

    Ok(())
}

#[test_strategy::proptest(ProptestConfig { cases: 400, max_shrink_iters: 0, ..ProptestConfig::default() })]
fn multi_round_priority_invariants(
    #[strategy(2..6_usize)] scheduler_cores: usize,
    #[strategy(200..800_usize)] num_rounds: usize,
    #[strategy(proptest::collection::vec(arb_archetype_with_count(), 2..=5))]
    archetype_configs: Vec<(CanisterArchetype, usize)>,
) {
    let total_compute: u64 = archetype_configs
        .iter()
        .map(|(a, c)| a.compute_allocation * *c as u64)
        .sum();
    let capacity = ((scheduler_cores - 1) * 100) as u64;
    prop_assume!(total_compute < capacity);

    let (fixture, sims) =
        run_multi_round_simulation(scheduler_cores, num_rounds, &archetype_configs);
    assert_multi_round_invariants(&fixture, &sims, num_rounds)?;
}

#[test_strategy::proptest(ProptestConfig { cases: 20, max_shrink_iters: 0, ..ProptestConfig::default() })]
fn multi_round_all_active_proportional_scheduling(
    #[strategy(2..6_usize)] scheduler_cores: usize,
    #[strategy(proptest::collection::vec(0..50_u64, 2..=10))] allocations: Vec<u64>,
) {
    let total: u64 = allocations.iter().sum();
    let capacity = ((scheduler_cores - 1) * 100) as u64;
    prop_assume!(total < capacity);

    let archetype_configs: Vec<(CanisterArchetype, usize)> = allocations
        .into_iter()
        .map(|ca| {
            (
                CanisterArchetype {
                    compute_allocation: ca,
                    active_rounds: 1,
                    inactive_rounds: 0,
                    has_long_execution: false,
                    consumes_all_inputs: true,
                    rate_limiting: None,
                    low_cycles: false,
                },
                1,
            )
        })
        .collect();

    let num_canisters = archetype_configs.len();
    let num_rounds = num_canisters * 10;

    let (fixture, _sims) =
        run_multi_round_simulation(scheduler_cores, num_rounds, &archetype_configs);

    let sum_ap: i64 = fixture
        .state
        .metadata
        .subnet_schedule
        .iter()
        .map(|(_, p)| p.accumulated_priority.get())
        .sum();
    prop_assert!(
        sum_ap.abs() <= num_canisters as i64,
        "final sum(AP) = {sum_ap}"
    );
}
