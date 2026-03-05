use super::*;
use crate::scheduler::scheduler_metrics::SchedulerMetrics;
use assert_matches::assert_matches;
use ic_base_types::{CanisterId, NumBytes};
use ic_config::flag_status::FlagStatus;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::PausedExecutionId;
use ic_replicated_state::testing::SystemStateTesting;
use ic_replicated_state::{CanisterMetrics, CanisterPriority, ExecutionTask, ReplicatedState};
use ic_test_utilities_state::get_running_canister;
use ic_test_utilities_types::messages::IngressBuilder;
use ic_types::messages::{CanisterMessageOrTask, CanisterTask};
use ic_types::{AccumulatedPriority, ComputeAllocation, ExecutionRound, LongExecutionMode};
use ic_types_test_utils::ids::{canister_test_id, subnet_test_id};
use maplit::btreeset;
use more_asserts::{assert_gt, assert_le};
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
        let ingress = IngressBuilder::new().receiver(canister_id).build();
        canister.system_state.queues_mut().push_ingress(ingress);
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

    /// Sets the heap delta debit for an already-added canister (for rate-limit
    /// tests). The canister must exist.
    fn set_heap_delta_debit(&mut self, canister_id: CanisterId, bytes: NumBytes) {
        self.canister_state(&canister_id)
            .scheduler_state
            .heap_delta_debit = bytes;
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
    ) {
        self.round_schedule.end_iteration(
            &mut self.state,
            executed_canisters,
            canisters_with_completed_messages,
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
}

#[allow(dead_code)]
impl RoundScheduleBuilder {
    fn new() -> Self {
        Self {
            cores: 4,
            heap_delta_rate_limit: NumBytes::new(u64::MAX / 2),
            rate_limiting_of_heap_delta: FlagStatus::Enabled,
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
    fixture.set_heap_delta_debit(canister_id, limit);

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
    fixture.end_iteration(&executed, &completed);

    assert_eq!(fixture.executed_canisters(), &executed);
    assert_eq!(fixture.canisters_with_completed_messages(), &completed);

    fixture.end_iteration(&btreeset! {canister_b, canister_c}, &btreeset! {canister_c});

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
    fixture.end_iteration(&executed, &completed);

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
    let all = btreeset! {new, long, fully_executed};
    let none = btreeset! {};

    // All canisters executed, none completed an execution.
    fixture.end_iteration(&all, &none);

    // No canister got marked as fully executed (as none completed an execution).
    assert_eq!(fixture.fully_executed_canisters(), &btreeset! {});

    // All executed, all completed at least one execution.
    fixture.end_iteration(&all, &all);

    // Only the canister with `next_execution() == None` is fully executed.
    assert_eq!(
        fixture.fully_executed_canisters(),
        &btreeset! {fully_executed}
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
    fixture.end_iteration(&btreeset! {long, new}, &btreeset! {new});
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
    fixture.end_iteration(&all, &all);
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
/// subnet schedule when it has no inputs and !must_be_in_schedule().
#[test]
fn finish_round_idle_at_zero_dropped_from_schedule() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = fixture.canister_with_input();
    fixture.start_iteration(true);
    // Simulate "canister ran and consumed its input".
    fixture
        .canister_state(&canister_id)
        .system_state
        .pop_input();
    fixture.end_iteration(&btreeset! {canister_id}, &btreeset! {canister_id});

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
