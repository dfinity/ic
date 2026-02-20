use criterion::Criterion;
use ic_base_types::NumSeconds;
use ic_config::flag_status::FlagStatus;
use ic_execution_environment::RoundSchedule;
use ic_execution_environment::scheduler::scheduler_metrics::SchedulerMetrics;
use ic_logger::new_replica_logger_from_config;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CanisterState, InputQueueType, ReplicatedState, SchedulerState, SystemState,
};
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::{Cycles, ExecutionRound, NumBytes, PrincipalId, SubnetId};
use ic_types_test_utils::ids::{canister_test_id, user_test_id};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn main() {
    let mut canisters = BTreeMap::new();
    let mut canisters_with_completed_messages = BTreeSet::new();
    for i in 0..100_000 {
        let canister_id = canister_test_id(i);
        let scheduler_state = SchedulerState::default();
        let system_state = SystemState::new_running_for_testing(
            canister_id,
            user_test_id(24).get(),
            Cycles::from_parts(1, 2),
            NumSeconds::from(100_000),
        );
        let mut canister_state = CanisterState::new(system_state, None, scheduler_state);
        // First 1k canisters are active and will complete an execution every round.
        if i < 1_000 {
            let mut available_memory = i64::MAX;
            canister_state
                .push_input(
                    RequestBuilder::new().receiver(canister_id).build().into(),
                    &mut available_memory,
                    SubnetType::Application,
                    InputQueueType::RemoteSubnet,
                )
                .unwrap();
            canisters_with_completed_messages.insert(canister_id);
        }
        canisters.insert(canister_id, Arc::new(canister_state));
    }
    let mut state = ReplicatedState::new(
        SubnetId::new(PrincipalId::new_subnet_test_id(0)),
        SubnetType::Application,
    );
    state.put_canister_states(canisters);

    let scheduler_cores = 4;
    let heap_delta_rate_limit = NumBytes::from(1_000_000);
    let rate_limiting_of_heap_delta = FlagStatus::Enabled;
    let mut round_schedule = RoundSchedule::new(
        scheduler_cores,
        heap_delta_rate_limit,
        rate_limiting_of_heap_delta,
    );
    let metrics_registry = MetricsRegistry::new();
    let metrics = SchedulerMetrics::new(&metrics_registry);
    let (log, _async_guard) = new_replica_logger_from_config(&Default::default());

    let mut criterion = Criterion::default();
    let mut group = criterion.benchmark_group("RoundSchedule");

    group.bench_function("iteration", |bench| {
        bench.iter(|| {
            round_schedule.start_iteration(&mut state, &metrics, &log);
            round_schedule.end_iteration(&mut state, &canisters_with_completed_messages);
        });
    });

    // Populate the subnet schedule, even if the iteration benchmark is not run.
    round_schedule.start_iteration(&mut state, &metrics, &log);

    group.bench_function("finish_round", |bench| {
        bench.iter(|| {
            round_schedule.finish_round(&mut state, ExecutionRound::from(0), &metrics);
        });
    });
}
