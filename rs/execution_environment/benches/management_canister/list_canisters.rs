use crate::create_canisters::CreateCanistersArgs;
use crate::utils::{CANISTERS_PER_BATCH, expect_reply, test_canister_wasm};
use candid::{Encode, Principal};
use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_base_types::CanisterId;
use ic_config::subnet_config::SubnetConfig;
use ic_config::{execution_environment::Config as HypervisorConfig, flag_status::FlagStatus};
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
/// `canisters_number` additional canisters.
fn setup_with_canisters(canisters_number: u64) -> (StateMachine, CanisterId) {
    let hypervisor_config = HypervisorConfig {
        rate_limiting_of_heap_delta: FlagStatus::Disabled,
        ..Default::default()
    };
    let admin = admin_canister_id();
    let env = StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            SubnetConfig::new(SubnetType::Application),
            hypervisor_config,
        )))
        .with_checkpoints_enabled(false)
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
    // test canister (batched inter-canister `create_canister` calls).
    if canisters_number > 0 {
        let result = env.execute_ingress(
            test_canister,
            "create_canisters",
            Encode!(&CreateCanistersArgs {
                canisters_number,
                canisters_per_batch: CANISTERS_PER_BATCH,
                initial_cycles: 0,
            })
            .unwrap(),
        );
        let created: Vec<Principal> = expect_reply(result);
        assert_eq!(created.len(), canisters_number as usize);
    }

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
            // At least the range covering the freshly created canisters.
            assert!(ranges >= 1);
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
