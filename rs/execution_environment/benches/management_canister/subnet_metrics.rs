use crate::create_canisters::CreateCanistersArgs;
use crate::utils::{CANISTERS_PER_BATCH, expect_reply, test_canister_wasm};
use candid::{Encode, Principal};
use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_base_types::{CanisterId, NumBytes, NumSeconds};
use ic_config::execution_environment::Config as HypervisorConfig;
use ic_config::subnet_config::SubnetConfig;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::canister_snapshots::CanisterSnapshots;
use ic_replicated_state::canister_state::system_state::SystemState;
use ic_replicated_state::{CanisterState, CanisterStates, SchedulerState};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities_types::ids::canister_test_id;
use ic_types_cycles::{CanisterCyclesCostSchedule, CompoundCycles, Cycles, Instructions};
use std::sync::Arc;

/// Builds a `StateMachine` and populates the subnet with `canisters_number`
/// canisters, created through a test canister via batched inter-canister calls.
/// Returns the `StateMachine` and the test canister ID.
///
/// `subnet_metrics` is canister-only, so the call must go through the test
/// canister; unlike `list_canisters` it needs no subnet-admin setup.
fn setup_with_canisters(canisters_number: u64) -> (StateMachine, CanisterId) {
    let env = StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            SubnetConfig::new(SubnetType::Application),
            HypervisorConfig::default(),
        )))
        .with_subnet_type(SubnetType::Application)
        .with_cost_schedule(CanisterCyclesCostSchedule::Free)
        .build();

    let test_canister = env.create_canister_with_cycles(None, Cycles::new(u128::MAX / 2), None);
    env.install_existing_canister(test_canister, test_canister_wasm(), vec![])
        .expect("failed to install the test canister");

    const CHUNK: u64 = 5_000;
    let mut remaining_to_create = canisters_number;
    while remaining_to_create > 0 {
        let chunk = remaining_to_create.min(CHUNK);
        remaining_to_create -= chunk;
        let result = env.execute_ingress(
            test_canister,
            "create_canisters",
            Encode!(&CreateCanistersArgs {
                canisters_number: chunk,
                canisters_per_batch: CANISTERS_PER_BATCH,
                initial_cycles: 0,
            })
            .unwrap(),
        );
        let created: Vec<Principal> = expect_reply(result);
        assert_eq!(created.len() as u64, chunk);
    }

    (env, test_canister)
}

/// Measures the end-to-end cost of one `subnet_metrics` call on a subnet with
/// `canisters_number` canisters. This is what `BASE_INSTRUCTIONS` in
/// `subnet_metrics_instructions` must cover: message induction, the reads from
/// `state.metadata.subnet_metrics`, the fold over the hot pool, and the Candid
/// encode.
///
/// Note that the canisters created during setup are demoted to the cold pool
/// after a round of inactivity (`repartition_canister_states` runs on every
/// commit), so this measurement deliberately does *not* capture the
/// per-hot-canister term — which is also why the charge must be keyed on
/// `hot_len()` rather than `num_canisters()`: on a mostly-cold subnet the two
/// differ by orders of magnitude while the work does not. The per-hot-canister
/// term is measured by `bench_consumed_cycles_fold`.
fn bench_end_to_end<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    canisters_number: u64,
) {
    // `subnet_metrics` is read-only, so the environment (and its set of
    // canisters) does not change across iterations and can be set up once.
    let (env, test_canister) = setup_with_canisters(canisters_number);
    let subnet_id: Principal = env.get_subnet_id().get().into();
    group.bench_function(bench_name, |b| {
        b.iter(|| {
            let result = env.execute_ingress(
                test_canister,
                "subnet_metrics",
                Encode!(&subnet_id).unwrap(),
            );
            let _num_canisters: u64 = expect_reply(result);
        });
    });
}

/// Builds one hot canister with non-zero consumed cycles.
///
/// A non-zero `heap_delta_debit` keeps a canister out of the cold pool
/// (`CanisterState::is_cold`), which is what makes a fully hot pool the worst case
/// for `CanisterStates::total_consumed_cycles()`: the fold is `O(|hot|)`, the cold
/// pool being a precomputed aggregate.
fn hot_canister(id: u64) -> Arc<CanisterState> {
    let mut system_state = SystemState::new_running_for_testing(
        canister_test_id(id),
        canister_test_id(u64::MAX).get(),
        Cycles::new(1 << 60),
        NumSeconds::new(100_000),
    );
    system_state.consume_cycles(CompoundCycles::<Instructions>::new(
        Cycles::new(1_000 + id as u128),
        CanisterCyclesCostSchedule::Normal,
    ));
    Arc::new(CanisterState::new(
        system_state,
        None,
        SchedulerState {
            heap_delta_debit: NumBytes::new(1),
            ..SchedulerState::default()
        },
        CanisterSnapshots::default(),
    ))
}

/// Builds a `CanisterStates` holding `canisters_number` hot canisters, allocated
/// and inserted in ascending canister-ID order.
///
/// This is the *favourable* memory layout: the `BTreeMap` nodes and the `Arc`
/// payloads are laid out in the order the fold visits them.
fn hot_canister_states(canisters_number: u64) -> CanisterStates {
    let mut states = CanisterStates::default();
    for id in 0..canisters_number {
        states.insert(hot_canister(id));
    }
    assert_eq!(states.hot_len() as u64, canisters_number);
    states
}

/// As [`hot_canister_states`], but with the allocation and insertion order
/// scrambled and with allocator churn interleaved, so the `BTreeMap` nodes and the
/// `Arc<CanisterState>` payloads are scattered rather than laid out in visit
/// order.
///
/// This is the adversarial-locality variant, and it is the one
/// `INSTRUCTIONS_PER_HOT_CANISTER` is justified against: a production hot pool is
/// built up over a long period from independently allocated, long-lived canisters,
/// not in one tight loop. In practice it measures only ~13% above the favourable
/// layout, because `size_of::<CanisterState>()` is ~2.5KB, so at 100k canisters the
/// pool is ~254MB and the fold is DRAM-bound either way.
fn shuffled_hot_canister_states(canisters_number: u64) -> CanisterStates {
    /// Deterministic pseudo-random value, so the benchmark needs no RNG
    /// dependency and is reproducible run to run.
    fn scramble(i: u64) -> u64 {
        let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        x ^= x >> 31;
        x.wrapping_mul(0xBF58_476D_1CE4_E5B9)
    }

    // Fisher-Yates over `0..n`, rather than rejection-sampling a scrambled index
    // until every residue has been hit: this is `O(n)` with a static termination
    // bound, where the rejection loop terminates only in expectation (~12n
    // iterations by coupon collector, and in principle never).
    let mut order: Vec<u64> = (0..canisters_number).collect();
    for i in (1..order.len()).rev() {
        order.swap(i, (scramble(i as u64) % (i as u64 + 1)) as usize);
    }

    let mut states = CanisterStates::default();
    let mut ballast: Vec<Vec<u8>> = Vec::new();
    for (inserted, id) in order.into_iter().enumerate() {
        // Churn: allocate, keep some, free some, so canister allocations are
        // interleaved with unrelated live objects.
        ballast.push(vec![0_u8; 4096]);
        if ballast.len() > 64 {
            let victim = inserted % ballast.len();
            ballast.swap_remove(victim);
        }
        states.insert(hot_canister(id));
    }
    // Drop the ballast, leaving holes in the heap.
    drop(ballast);
    assert_eq!(states.hot_len() as u64, canisters_number);
    states
}

/// Measures `CanisterStates::total_consumed_cycles()` over a fully hot pool.
/// The slope of this measurement is what `INSTRUCTIONS_PER_HOT_CANISTER` in
/// `subnet_metrics_instructions` must cover.
fn bench_consumed_cycles_fold<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    states: CanisterStates,
) {
    group.bench_function(bench_name, |b| {
        b.iter(|| std::hint::black_box(states.total_consumed_cycles()));
    });
}

pub fn subnet_metrics_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("subnet_metrics");
    bench_end_to_end(&mut group, "end_to_end/10", 10);
    bench_end_to_end(&mut group, "end_to_end/1k", 1_000);
    bench_end_to_end(&mut group, "end_to_end/10k", 10_000);
    group.finish();

    let mut group = c.benchmark_group("subnet_metrics_consumed_cycles_fold");
    for n in [0_u64, 1_000, 10_000, 100_000] {
        let label = match n {
            0 => "0".to_string(),
            n if n % 1_000 == 0 => format!("{}k", n / 1_000),
            n => n.to_string(),
        };
        bench_consumed_cycles_fold(
            &mut group,
            &format!("hot/{label}/sequential"),
            hot_canister_states(n),
        );
        bench_consumed_cycles_fold(
            &mut group,
            &format!("hot/{label}/shuffled"),
            shuffled_hot_canister_states(n),
        );
    }
    group.finish();
}

criterion_group!(benchmarks, subnet_metrics_benchmark);
criterion_main!(benchmarks);
