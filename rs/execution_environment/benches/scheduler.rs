use criterion::Criterion;
use ic_base_types::NumSeconds;
use ic_config::flag_status::FlagStatus;
use ic_execution_environment::{RoundSchedule, SchedulerMetrics};
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::canister_snapshots::CanisterSnapshots;
use ic_replicated_state::{CanisterState, ReplicatedState, SchedulerState, SystemState};
use ic_types::{ExecutionRound, NumBytes, NumInstructions};
use ic_types_cycles::Cycles;
use ic_types_test_utils::ids::{canister_test_id, subnet_test_id, user_test_id};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn main() {
    // 100k canisters, 5k active, 1k executed every round.
    let mut canisters = BTreeMap::new();
    let mut ordered_new_execution_canister_ids = Vec::new();
    let mut ordered_long_execution_canister_ids = Vec::new();
    let mut executed_canisters = BTreeSet::new();
    for i in 0..100_000 {
        let canister_id = canister_test_id(i);
        let scheduler_state = SchedulerState::default();
        let system_state = SystemState::new_running_for_testing(
            canister_id,
            user_test_id(24).get(),
            Cycles::from_parts(1, 2),
            NumSeconds::from(100_000),
        );
        let canister_snapshots = CanisterSnapshots::default();
        let canister_state =
            CanisterState::new(system_state, None, scheduler_state, canister_snapshots);
        // 5k active canisters.
        if i < 5_000 {
            // Every 10th canister has a long execution, the rest have new inputs.
            if i % 10 == 0 {
                ordered_long_execution_canister_ids.push(canister_id);
            } else {
                ordered_new_execution_canister_ids.push(canister_id);
            }
        }
        // First 1k canisters complete an execution every round.
        if i < 1_000 {
            executed_canisters.insert(canister_id);
        }
        canisters.insert(canister_id, Arc::new(canister_state));
    }
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    state.put_canister_states(canisters);

    let scheduler_cores = 4;
    let heap_delta_rate_limit = NumBytes::from(1_000_000);
    let rate_limiting_of_heap_delta = FlagStatus::Enabled;
    let install_code_rate_limit = NumInstructions::from(1_000_000);
    let rate_limiting_of_instructions = FlagStatus::Enabled;
    let long_execution_cores = 1;
    let mut round_schedule = RoundSchedule::new(
        scheduler_cores,
        heap_delta_rate_limit,
        rate_limiting_of_heap_delta,
        install_code_rate_limit,
        rate_limiting_of_instructions,
        long_execution_cores,
        ordered_new_execution_canister_ids,
        ordered_long_execution_canister_ids,
    );
    let metrics_registry = MetricsRegistry::new();
    let metrics = SchedulerMetrics::new(&metrics_registry);

    let mut criterion = Criterion::default();
    let mut group = criterion.benchmark_group("RoundSchedule");

    group.bench_function("iteration", |bench| {
        bench.iter(|| {
            round_schedule.start_iteration(&mut state, true);
            round_schedule.end_iteration(
                &mut state,
                &executed_canisters,
                &executed_canisters,
                &BTreeSet::new(),
                ExecutionRound::from(1),
            );
        });
    });

    // Populate the subnet schedule, even if the iteration benchmark is not run.
    round_schedule.start_iteration(&mut state, true);
    round_schedule.end_iteration(
        &mut state,
        &executed_canisters,
        &executed_canisters,
        &BTreeSet::new(),
        ExecutionRound::from(1),
    );

    group.bench_function("finish_round", |bench| {
        bench.iter(|| {
            round_schedule.finish_round(&mut state, ExecutionRound::from(0), &metrics);
        });
    });
}
