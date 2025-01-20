use criterion::Criterion;
use ic_base_types::NumSeconds;
use ic_config::flag_status::FlagStatus;
use ic_execution_environment::RoundSchedule;
use ic_replicated_state::{CanisterState, SchedulerState, SystemState};
use ic_types::Cycles;
use ic_types_test_utils::ids::{canister_test_id, user_test_id};
use std::collections::BTreeMap;

fn main() {
    let mut canisters = BTreeMap::new();
    let mut ordered_canister_ids = Vec::new();
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
            CanisterState::new(system_state, None, scheduler_state),
        );

        ordered_canister_ids.push(canister_id);
    }

    let scheduler_cores = 4;
    let round_schedule = RoundSchedule::new(scheduler_cores, 0, ordered_canister_ids);

    let mut criterion = Criterion::default();
    let mut group = criterion.benchmark_group("RoundSchedule");

    let heap_delta_rate_limit = 1_000_000.into();
    let rate_limiting_of_heap_delta = FlagStatus::Enabled;
    group.bench_function("filter_canisters", |bench| {
        bench.iter(|| {
            let _ = round_schedule.filter_canisters(
                &canisters,
                heap_delta_rate_limit,
                rate_limiting_of_heap_delta,
            );
        });
    });
}
