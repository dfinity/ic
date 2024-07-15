use crate::utils::{expect_error, expect_reply, setup, CANISTERS_PER_BATCH};
use candid::{CandidType, Encode, Principal};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, Criterion};
use ic_state_machine_tests::{ErrorCode, UserError, WasmResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct CreateCanistersArgs {
    pub canisters_number: u64,
    pub canisters_per_batch: u64,
    pub initial_cycles: u128,
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct UpdateSettingsArgs {
    pub canister_ids: Vec<Principal>,
    pub controllers_number: u64,
}

fn run_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    params: (u64, u64),
    process_result_fn: fn(Result<WasmResult, UserError>) -> (),
) {
    let (canisters_number, controllers_number) = params;
    const T: u128 = 1_000_000_000_000;
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            // Test setup.
            || {
                let (env, test_canister) = setup();
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
                // Create canisters before installing code.
                let canister_ids: Vec<Principal> = expect_reply(result);
                (env, test_canister, canister_ids)
            },
            // Test measurement.
            |(env, test_canister, canister_ids)| {
                let result = env.execute_ingress(
                    test_canister,
                    "update_settings",
                    Encode!(&UpdateSettingsArgs {
                        canister_ids,
                        controllers_number,
                    })
                    .unwrap(),
                );
                process_result_fn(result);
            },
            BatchSize::SmallInput,
        );
    });
}

pub fn update_settings_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_settings");

    run_bench(
        &mut group,
        "canisters:10/controllers:10/reply",
        (10, 10),
        expect_reply,
    );
    run_bench(
        &mut group,
        "canisters:10/controllers:20/error",
        (10, 20),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The number of elements exceeds maximum allowed 10",
            );
        },
    );
    run_bench(
        &mut group,
        "canisters:10/controllers:1k/error",
        (10, 1_000),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The number of elements exceeds maximum allowed 10",
            );
        },
    );
    run_bench(
        &mut group,
        "canisters:10/controllers:10k/error",
        (10, 10_000),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The number of elements exceeds maximum allowed 10",
            );
        },
    );
    run_bench(
        &mut group,
        "canisters:10/controllers:100k/error",
        (10, 100_000),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The number of elements exceeds maximum allowed 10",
            );
        },
    );

    group.finish();
}

criterion_group!(benchmarks, update_settings_benchmark);
criterion_main!(benchmarks);
