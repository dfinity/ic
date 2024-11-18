use crate::utils::{expect_error, expect_reply, setup, CANISTERS_PER_BATCH};
use candid::{CandidType, Encode, Principal};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, Criterion};
use ic_state_machine_tests::{ErrorCode, UserError, WasmResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct CreateCanistersArgs {
    pub canisters_number: u64,
    pub canisters_per_batch: u64,
    pub initial_cycles: u128,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct InstallCodeArgs {
    pub canister_ids: Vec<Principal>,
    pub wasm_module_size: u64,
    pub arg_size: u64,
}

fn run_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    params: (u64, u64, u64),
    process_result_fn: fn(Result<WasmResult, UserError>) -> (),
) {
    let (canisters_number, wasm_module_size, arg_size) = params;
    const T: u128 = 1_000_000_000_000;
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            // Test setup.
            || {
                let (env, test_canister) = setup();
                // Create canisters before installing code.
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
                (env, test_canister, canister_ids)
            },
            // Test measurement.
            |(env, test_canister, canister_ids)| {
                let result = env.execute_ingress(
                    test_canister,
                    "install_code",
                    Encode!(&InstallCodeArgs {
                        canister_ids,
                        wasm_module_size,
                        arg_size,
                    })
                    .unwrap(),
                );
                process_result_fn(result);
            },
            BatchSize::SmallInput,
        );
    });
}

pub fn install_code_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("install_code");

    run_bench(
        &mut group,
        "canisters:1/wasm:0B/arg:0B",
        (1, 0, 0),
        expect_reply,
    );
    run_bench(
        &mut group,
        "canisters:1/wasm:2MB/arg:0B",
        (1, 2_000_000, 0),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Failed to decode wasm module: unsupported canister module format",
            );
        },
    );
    run_bench(
        &mut group,
        "canisters:1/wasm:10MB/arg:0B",
        (1, 10_000_000, 0),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Failed to decode wasm module: unsupported canister module format",
            );
        },
    );
    run_bench(
        &mut group,
        "canisters:1/wasm:10B/arg:2MB",
        (1, 10, 2_000_000),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Failed to decode wasm module: unsupported canister module format",
            );
        },
    );

    group.finish();
}

criterion_group!(benchmarks, install_code_benchmark);
criterion_main!(benchmarks);
