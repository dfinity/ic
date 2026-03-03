use super::RoundSchedule;
use crate::scheduler::scheduler_metrics::SchedulerMetrics;
use ic_base_types::CanisterId;
use ic_config::flag_status::FlagStatus;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterMetrics, CanisterPriority, CanisterState, ReplicatedState};
use ic_test_utilities_state::get_running_canister;
use ic_types::{AccumulatedPriority, LongExecutionMode};
use ic_types_test_utils::ids::{canister_test_id, subnet_test_id};
use std::sync::Arc;

/// Fixture for testing `RoundSchedule` in isolation: a `ReplicatedState` with
/// helpers to add canisters (with default or custom `CanisterPriority`) and to
/// inspect canister metrics and priority.
pub struct RoundScheduleFixture {
    pub state: ReplicatedState,
}

impl Default for RoundScheduleFixture {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)] // set_canister_priority, state: used by tests moved from scheduler/tests.rs
impl RoundScheduleFixture {
    /// Creates a new fixture with an empty `ReplicatedState` on a default
    /// application subnet.
    pub fn new() -> Self {
        Self {
            state: ReplicatedState::new(subnet_test_id(1), SubnetType::Application),
        }
    }

    /// Adds a canister to the state. Its scheduling priority is the default
    /// until explicitly set (use `set_canister_priority` or
    /// `add_canister_with_priority`).
    pub fn add_canister(&mut self, canister: CanisterState) {
        self.state.put_canister_state(Arc::new(canister));
    }

    /// Adds a canister and sets its scheduling priority in the subnet schedule.
    /// Use this when the test needs a non-default priority (e.g. accumulated
    /// priority, long execution mode).
    pub fn add_canister_with_priority(
        &mut self,
        canister: CanisterState,
        priority: CanisterPriority,
    ) {
        let canister_id = canister.canister_id();
        self.state.put_canister_state(Arc::new(canister));
        *self.state.canister_priority_mut(canister_id) = priority;
    }

    /// Sets the scheduling priority for an already-added canister.
    pub fn set_canister_priority(&mut self, canister_id: CanisterId, priority: CanisterPriority) {
        *self.state.canister_priority_mut(canister_id) = priority;
    }

    /// Returns the scheduling priority for the canister (default if not in the
    /// subnet schedule).
    pub fn canister_priority(&self, canister_id: &CanisterId) -> &CanisterPriority {
        self.state.canister_priority(canister_id)
    }

    /// Returns true if the canister is present in the subnet schedule, false
    /// otherwise.
    pub fn has_canister_priority(&self, canister_id: &CanisterId) -> bool {
        self.state
            .metadata
            .subnet_schedule
            .iter()
            .any(|(id, _)| *id == *canister_id)
    }

    /// Returns a reference to the canister's metrics, if the canister exists.
    pub fn canister_metrics(&self, canister_id: &CanisterId) -> Option<&CanisterMetrics> {
        self.state
            .canister_state(canister_id)
            .map(|c| c.system_state.canister_metrics())
    }

    /// Mutable reference to the underlying state (e.g. for running
    /// `RoundSchedule::start_iteration`).
    pub fn state_mut(&mut self) -> &mut ReplicatedState {
        &mut self.state
    }

    /// Immutable reference to the underlying state.
    pub fn state(&self) -> &ReplicatedState {
        &self.state
    }
}

/// Builds `SchedulerMetrics` and a no-op logger for use in
/// `RoundSchedule::start_iteration` / `finish_round` in tests.
pub fn metrics_and_logger() -> (SchedulerMetrics, ic_logger::ReplicaLogger) {
    let registry = MetricsRegistry::new();
    let metrics = SchedulerMetrics::new(&registry);
    let log = ic_logger::replica_logger::no_op_logger();
    (metrics, log)
}

#[test]
fn fixture_add_canister_default_priority() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = canister_test_id(0);
    fixture.add_canister(get_running_canister(canister_id));

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
    let canister_id = canister_test_id(0);
    let priority = CanisterPriority {
        accumulated_priority: AccumulatedPriority::new(100),
        ..CanisterPriority::DEFAULT
    };
    fixture.add_canister_with_priority(get_running_canister(canister_id), priority);

    let p = fixture.canister_priority(&canister_id);
    assert_eq!(p.accumulated_priority.get(), 100);
}

#[test]
fn fixture_canister_metrics() {
    let mut fixture = RoundScheduleFixture::new();
    let canister_id = canister_test_id(0);
    fixture.add_canister(get_running_canister(canister_id));

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
    fixture.add_canister(get_running_canister(canister_test_id(0)));
    let (metrics, log) = metrics_and_logger();
    let mut round_schedule =
        RoundSchedule::new(2, ic_base_types::NumBytes::new(0), FlagStatus::Disabled);
    let iteration_schedule =
        round_schedule.start_iteration(fixture.state_mut(), true, &metrics, &log);
    // Idle canister has NextExecution::None, so schedule is empty.
    assert!(iteration_schedule.is_empty());
}
