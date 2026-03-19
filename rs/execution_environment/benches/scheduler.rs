use criterion::Criterion;
use ic_base_types::NumSeconds;
use ic_config::flag_status::FlagStatus;
use ic_execution_environment::RoundSchedule;
use ic_execution_environment::scheduler::scheduler_metrics::SchedulerMetrics;
use ic_logger::new_replica_logger_from_config;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::canister_snapshots::CanisterSnapshots;
use ic_replicated_state::canister_state::system_state::PausedExecutionId;
use ic_replicated_state::{
    CanisterState, ExecutionTask, InputQueueType, ReplicatedState, SchedulerState, SystemState,
};
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::messages::{CanisterMessageOrTask, CanisterTask};
use ic_types::{ExecutionRound, NumBytes, NumInstructions};
use ic_types_cycles::Cycles;
use ic_types_test_utils::ids::{canister_test_id, subnet_test_id, user_test_id};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn main() {
    let mut canisters = BTreeMap::new();
    let mut executed_canisters = BTreeSet::new();
    for i in 0..50_000 {
        let canister_id = canister_test_id(i);
        let scheduler_state = SchedulerState::default();
        let system_state = SystemState::new_running_for_testing(
            canister_id,
            user_test_id(24).get(),
            Cycles::from_parts(1, 2),
            NumSeconds::from(100_000),
        );
        let canister_snapshots = CanisterSnapshots::default();
        let mut canister_state =
            CanisterState::new(system_state, None, scheduler_state, canister_snapshots);
        // Every 10th canister has a long execution, the rest have new inputs.
        if i % 10 == 0 {
            canister_state
                .system_state
                .task_queue
                .enqueue(ExecutionTask::PausedExecution {
                    id: PausedExecutionId(0),
                    input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
                });
        } else {
            let mut available_memory = i64::MAX;
            canister_state
                .push_input(
                    RequestBuilder::new().receiver(canister_id).build().into(),
                    &mut available_memory,
                    SubnetType::Application,
                    InputQueueType::RemoteSubnet,
                )
                .unwrap();
        }
        // First 1k canisters will complete an execution every round.
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
    let mut round_schedule = RoundSchedule::new(
        scheduler_cores,
        heap_delta_rate_limit,
        rate_limiting_of_heap_delta,
        install_code_rate_limit,
        rate_limiting_of_instructions,
    );
    let metrics_registry = MetricsRegistry::new();
    let metrics = SchedulerMetrics::new(&metrics_registry);
    let (log, _async_guard) = new_replica_logger_from_config(&Default::default());

    let mut criterion = Criterion::default();
    let mut group = criterion.benchmark_group("RoundSchedule");

    group.bench_function("iteration", |bench| {
        bench.iter(|| {
            round_schedule.start_iteration(&mut state, true, &metrics, &log);
            round_schedule.end_iteration(
                &mut state,
                &executed_canisters,
                &executed_canisters,
                &BTreeSet::new(),
            );
        });
    });

    // Populate the subnet schedule, even if the iteration benchmark is not run.
    round_schedule.start_iteration(&mut state, true, &metrics, &log);
    round_schedule.end_iteration(
        &mut state,
        &executed_canisters,
        &executed_canisters,
        &BTreeSet::new(),
    );

    group.bench_function("finish_round", |bench| {
        bench.iter(|| {
            round_schedule.finish_round(&mut state, ExecutionRound::from(0), &metrics);
        });
    });
}
