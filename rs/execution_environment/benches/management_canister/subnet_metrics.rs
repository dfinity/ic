use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_base_types::{NumBytes, NumSeconds};
use ic_replicated_state::canister_state::canister_snapshots::CanisterSnapshots;
use ic_replicated_state::canister_state::system_state::SystemState;
use ic_replicated_state::{CanisterState, CanisterStates, SchedulerState};
use ic_test_utilities_types::ids::canister_test_id;
use ic_types_cycles::{CanisterCyclesCostSchedule, CompoundCycles, Cycles, Instructions};
use std::sync::Arc;

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
