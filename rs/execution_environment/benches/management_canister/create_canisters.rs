use crate::utils::{expect_reply, setup, CANISTERS_PER_BATCH};
use candid::{CandidType, Encode, Principal};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, Criterion};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct CreateCanistersArgs {
    pub canisters_number: u64,
    pub canisters_per_batch: u64,
    pub initial_cycles: u128,
}

fn run_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    canisters_number: u64,
) {
    const T: u128 = 1_000_000_000_000;
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            // Test setup.
            setup,
            // Test measurement.
            |(env, test_canister)| {
                let result = env.execute_ingress(
                    test_canister,
                    "create_canisters",
                    Encode!(&CreateCanistersArgs {
                        canisters_number,
                        canisters_per_batch: CANISTERS_PER_BATCH,
                        initial_cycles: 10 * T,
                    })
                    .unwrap(),
                );
                let canister_ids: Vec<Principal> = expect_reply(result);
                // Assert that expected number of canisters was created.
                assert_eq!(canister_ids.len(), canisters_number as usize);
            },
            BatchSize::SmallInput,
        );
    });
}

pub fn create_canisters_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("create_canisters");

    run_bench(&mut group, "10", 10);
    run_bench(&mut group, "100", 100);
    run_bench(&mut group, "1k", 1_000);

    group.finish();
}

criterion_group!(benchmarks, create_canisters_benchmark);
criterion_main!(benchmarks);
