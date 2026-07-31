use crate::create_canisters::CreateCanistersArgs;
use crate::utils::{CANISTERS_PER_BATCH, expect_reply, test_canister_wasm};
use candid::Encode;
use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_base_types::CanisterId;
use ic_config::execution_environment::Config as HypervisorConfig;
use ic_config::subnet_config::SubnetConfig;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};

/// Canister ID assigned to the subnet-admin test canister. On a fresh subnet
/// the first created canister gets the first ID in the subnet's allocation
/// range (i.e. `0`), so the test canister is created first (before the
/// canisters populating the subnet) to receive this ID.
fn admin_canister_id() -> CanisterId {
    CanisterId::from_u64(0)
}

/// Builds a `StateMachine` whose subnet has subnet admins configured (which
/// requires a `Free` cost schedule on an application subnet), installs the test
/// canister as the sole subnet admin, and populates the subnet with
/// `canisters_number` additional canisters. Returns the `StateMachine` and the
/// test canister ID.
fn setup_with_canisters(canisters_number: u64) -> (StateMachine, CanisterId) {
    let admin = admin_canister_id();
    let env = StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            SubnetConfig::new(SubnetType::Application),
            HypervisorConfig::default(),
        )))
        .with_subnet_type(SubnetType::Application)
        .with_cost_schedule(CanisterCyclesCostSchedule::Free)
        .with_subnet_admins(vec![admin.get()])
        .build();

    // Create the test canister first so that it receives the first canister ID
    // in the subnet's allocation range, which matches the pre-configured
    // subnet-admin ID.
    let test_canister = env.create_canister_with_cycles(None, Cycles::new(u128::MAX / 2), None);
    assert_eq!(test_canister, admin);
    env.install_existing_canister(test_canister, test_canister_wasm(), vec![])
        .expect("failed to install the test canister");

    // Populate the subnet with `canisters_number` additional canisters via the
    // test canister (batched inter-canister calls). The canisters are created
    // with gaps in between so that the subnet's canister IDs form roughly
    // `canisters_number` distinct ranges, which `list_canisters` must report.
    //
    // The work is split into chunks so that no single ingress message exceeds
    // the state machine's per-message tick budget (each chunk creates twice as
    // many canisters and then deletes half of them). Gaps are preserved across
    // chunk boundaries because each chunk ends with a deleted canister ID.
    const CHUNK: u64 = 5_000;
    let mut remaining_to_create = canisters_number;
    let mut created_ranges = 0;
    while remaining_to_create > 0 {
        let chunk = remaining_to_create.min(CHUNK);
        remaining_to_create -= chunk;
        let result = env.execute_ingress(
            test_canister,
            "create_canisters_with_gaps",
            Encode!(&CreateCanistersArgs {
                canisters_number: chunk,
                canisters_per_batch: CANISTERS_PER_BATCH,
                initial_cycles: 0,
            })
            .unwrap(),
        );
        created_ranges += expect_reply::<u64>(result);
    }
    assert_eq!(created_ranges, canisters_number);

    (env, test_canister)
}

fn run_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    canisters_number: u64,
) {
    // `list_canisters` is read-only, so the environment (and its set of
    // canisters) does not change across iterations and can be set up once.
    let (env, test_canister) = setup_with_canisters(canisters_number);
    group.bench_function(bench_name, |b| {
        b.iter(|| {
            let result = env.execute_ingress(test_canister, "list_canisters", Encode!().unwrap());
            let ranges: u64 = expect_reply(result);
            // The canisters are created with gaps, so there is exactly one
            // range per canister on the subnet.
            assert_eq!(ranges, canisters_number);
        });
    });
}

pub fn list_canisters_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("list_canisters");

    run_bench(&mut group, "10", 10);
    run_bench(&mut group, "100", 100);
    run_bench(&mut group, "1k", 1_000);
    run_bench(&mut group, "10k", 10_000);
    run_bench(&mut group, "50k", 50_000);

    group.finish();
}

criterion_group!(benchmarks, list_canisters_benchmark);
criterion_main!(benchmarks);
