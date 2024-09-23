use crate::utils::{expect_error, setup};
use candid::{CandidType, Encode};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, Criterion};
use ic_state_machine_tests::{
    ErrorCode, IngressState, IngressStatus, MessageId, PrincipalId, StateMachine, UserError,
    WasmResult,
};
use serde::{Deserialize, Serialize};

const KIB: usize = 1_024;

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct HttpRequestArgs {
    pub calls: u64,
    pub headers_number: u64,
    pub header: HttpHeader,
    pub cycles: u128,
}

fn await_ingress(env: StateMachine, msg_id: MessageId) -> Result<WasmResult, UserError> {
    let max_ticks = 10;
    for _tick in 0..max_ticks {
        match env.ingress_status(&msg_id) {
            IngressStatus::Known {
                state: IngressState::Completed(result),
                ..
            } => return Ok(result),
            IngressStatus::Known {
                state: IngressState::Failed(error),
                ..
            } => return Err(error),
            _ => {
                env.tick();
            }
        }
    }
    Err(UserError::new(
        ErrorCode::CanisterDidNotReply,
        "Timeout".to_string(),
    ))
}

fn run_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    params: (u64, u64, usize),
    process_result_fn: fn(Result<WasmResult, UserError>) -> (),
) {
    let (calls, headers_number, header_size) = params;
    const T: u128 = 1_000_000_000_000;
    let name_size = header_size / 2;
    let header = HttpHeader {
        name: String::from_utf8(vec![b'a'; name_size]).unwrap(),
        value: String::from_utf8(vec![b'b'; header_size - name_size]).unwrap(),
    };
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            // Test setup.
            setup,
            // Test measurement.
            |(env, test_canister)| {
                let msg_id = env.send_ingress(
                    PrincipalId::new_anonymous(),
                    test_canister,
                    "http_request",
                    Encode!(&HttpRequestArgs {
                        calls,
                        headers_number,
                        header: header.clone(),
                        cycles: 100 * T,
                    })
                    .unwrap(),
                );
                let result = await_ingress(env, msg_id);
                process_result_fn(result);
            },
            BatchSize::SmallInput,
        );
    });
}

pub fn http_request_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_request");

    run_bench(
        &mut group,
        "calls:10/headers_number:1/header_size:16KiB/timeout",
        (10, 1, 16 * KIB),
        |result| expect_error(result, ErrorCode::CanisterDidNotReply, "Timeout"),
    );
    run_bench(
        &mut group,
        "calls:10/headers_number:1/header_size:17KiB/error",
        (10, 1, 17 * KIB),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The single element data size exceeds maximum allowed",
            );
        },
    );
    run_bench(
        &mut group,
        "calls:10/headers_total_size:48KiB/timeout",
        (10, 48, KIB),
        |result| expect_error(result, ErrorCode::CanisterDidNotReply, "Timeout"),
    );
    run_bench(
        &mut group,
        "calls:10/headers_total_size:49KiB/error",
        (10, 49, KIB),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The total data size exceeds maximum allowed",
            );
        },
    );
    run_bench(
        &mut group,
        "calls:10/headers_total_size:64x16KiB/error",
        (10, 64, 16 * KIB),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The total data size exceeds maximum allowed",
            );
        },
    );
    run_bench(
        &mut group,
        "calls:10/headers_number:64/header_size:0/timeout",
        (10, 64, 0),
        |result| expect_error(result, ErrorCode::CanisterDidNotReply, "Timeout"),
    );
    run_bench(
        &mut group,
        "calls:10/headers_number:65/header_size:0/error",
        (10, 65, 0),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The number of elements exceeds maximum allowed",
            );
        },
    );
    run_bench(
        &mut group,
        "calls:10/headers_number:1k/header_size:0/error",
        (10, 1_000, 0),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The number of elements exceeds maximum allowed",
            );
        },
    );

    group.finish();
}

criterion_group!(benchmarks, http_request_benchmark);
criterion_main!(benchmarks);
