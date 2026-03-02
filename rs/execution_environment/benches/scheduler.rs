use criterion::Criterion;
use ic_base_types::NumSeconds;
use ic_config::flag_status::FlagStatus;
use ic_execution_environment::RoundSchedule;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, ReplicatedState, SchedulerState, SystemState};
use ic_types::Cycles;
use ic_types_test_utils::ids::{canister_test_id, subnet_test_id, user_test_id};
use std::collections::BTreeMap;
use std::sync::Arc;

fn main() {
    let mut canisters = BTreeMap::new();
    let mut ordered_new_execution_canister_ids = Vec::new();
    let mut ordered_long_execution_canister_ids = Vec::new();
    for i in 0..50_000 {
        let canister_id = canister_test_id(i);
        let scheduler_state = SchedulerState::default();
        let system_state = SystemState::new_running_for_testing(
            canister_id,
            user_test_id(24).get(),
            Cycles::from_parts(1, 2),
            NumSeconds::from(100_000),
        );
        canisters.insert(
            canister_test_id(i),
            Arc::new(CanisterState::new(system_state, None, scheduler_state)),
        );

        if i % 10 == 0 {
            ordered_long_execution_canister_ids.push(canister_id);
        } else {
            ordered_new_execution_canister_ids.push(canister_id);
        }
    }
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
    state.put_canister_states(canisters);

    let scheduler_cores = 4;
    let long_execution_cores = 1;
    let round_schedule = RoundSchedule::new(
        scheduler_cores,
        long_execution_cores,
        ordered_new_execution_canister_ids,
        ordered_long_execution_canister_ids,
    );

    let mut criterion = Criterion::default();
    let mut group = criterion.benchmark_group("RoundSchedule");

    let heap_delta_rate_limit = 1_000_000.into();
    let rate_limiting_of_heap_delta = FlagStatus::Enabled;
    group.bench_function("filter_canisters", |bench| {
        bench.iter(|| {
            let mut schedule = round_schedule.clone();
            let _ = schedule.filter_canisters(
                &mut state,
                heap_delta_rate_limit,
                rate_limiting_of_heap_delta,
            );
        });
    });
}
