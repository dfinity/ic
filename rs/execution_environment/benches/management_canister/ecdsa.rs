use crate::utils::{expect_error, expect_reply, test_canister_wasm};
use candid::{CandidType, Encode};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, Criterion};
use ic_management_canister_types::MasterPublicKeyId;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    Cycles, EcdsaCurve, EcdsaKeyId, ErrorCode, PrincipalId, StateMachineBuilder, SubnetId,
    UserError, WasmResult,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct ECDSAArgs {
    pub ecdsa_key: EcdsaKeyId,
    pub calls: u64,
    pub derivation_paths: u64,
    pub buf_size: u64,
}

fn run_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    method: &str,
    bench_name: &str,
    params: (u64, u64, u64),
    process_result_fn: fn(Result<WasmResult, UserError>) -> (),
) {
    let (calls, derivation_paths, buf_size) = params;
    // This test is testing non-zero cost of ECDSA signature, which happens in 2 cases:
    // - when called from application subnet
    // - when called from system subnet that is not NNS subnet
    let nns_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));
    let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(2));
    // Own subnet and NNS subnet IDs must be different.
    assert_ne!(nns_subnet_id, subnet_id);
    let ecdsa_key = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "key_id_secp256k1".to_string(),
    };
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            // Test setup.
            || {
                let env = StateMachineBuilder::new()
                    .with_checkpoints_enabled(false)
                    .with_subnet_type(SubnetType::Application)
                    .with_nns_subnet_id(nns_subnet_id)
                    .with_subnet_id(subnet_id)
                    .with_idkg_key(MasterPublicKeyId::Ecdsa(ecdsa_key.clone()))
                    .build();
                let test_canister = env
                    .install_canister_with_cycles(
                        test_canister_wasm(),
                        vec![],
                        None,
                        Cycles::new(u128::MAX / 2),
                    )
                    .unwrap();
                (env, test_canister)
            },
            // Test measurement.
            |(env, test_canister)| {
                let result = env.execute_ingress(
                    test_canister,
                    method,
                    Encode!(&ECDSAArgs {
                        ecdsa_key: ecdsa_key.clone(),
                        calls,
                        buf_size,
                        derivation_paths
                    })
                    .unwrap(),
                );
                process_result_fn(result);
            },
            BatchSize::SmallInput,
        );
    });
}

fn ecdsa_public_key_benchmark(c: &mut Criterion) {
    let method = "ecdsa_public_key";
    let mut group = c.benchmark_group(method);

    run_bench(
        &mut group,
        method,
        "calls:10/derivation_paths:1/buf_size:1",
        (10, 1, 1),
        |result| expect_error(result, ErrorCode::CanisterCalledTrap, "InvalidPoint"),
    );
    run_bench(
        &mut group,
        method,
        "calls:10/derivation_paths:1/buf_size:2M",
        (10, 1, 2_000_000),
        |result| expect_error(result, ErrorCode::CanisterCalledTrap, "InvalidPoint"),
    );
    run_bench(
        &mut group,
        method,
        "calls:10/derivation_paths:250/buf_size:8k",
        (10, 250, 8_000),
        |result| expect_error(result, ErrorCode::CanisterCalledTrap, "InvalidPoint"),
    );
    run_bench(
        &mut group,
        method,
        "calls:10/derivation_paths:500/buf_size:0",
        (10, 500, 0),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The number of elements exceeds maximum allowed 255",
            )
        },
    );
    run_bench(
        &mut group,
        method,
        "calls:10/derivation_paths:2M/buf_size:0",
        (10, 2_000_000, 0),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The number of elements exceeds maximum allowed 255",
            );
        },
    );

    group.finish();
}

fn sign_with_ecdsa_benchmark(c: &mut Criterion) {
    let method = "sign_with_ecdsa";
    let mut group = c.benchmark_group(method);

    run_bench(
        &mut group,
        method,
        "calls:10/derivation_paths:1/buf_size:1",
        (10, 1, 1),
        expect_reply,
    );
    run_bench(
        &mut group,
        method,
        "calls:10/derivation_paths:1/buf_size:2M",
        (10, 1, 2_000_000),
        expect_reply,
    );
    run_bench(
        &mut group,
        method,
        "calls:10/derivation_paths:250/buf_size:8k",
        (10, 250, 8_000),
        expect_reply,
    );
    run_bench(
        &mut group,
        method,
        "calls:10/derivation_paths:500/buf_size:0",
        (10, 500, 0),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The number of elements exceeds maximum allowed 255",
            );
        },
    );
    run_bench(
        &mut group,
        method,
        "calls:10/derivation_paths:2M/buf_size:0",
        (10, 2_000_000, 0),
        |result| {
            expect_error(
                result,
                ErrorCode::CanisterCalledTrap,
                "Deserialize error: The number of elements exceeds maximum allowed 255",
            );
        },
    );

    group.finish();
}

pub fn ecdsa_benchmark(c: &mut Criterion) {
    ecdsa_public_key_benchmark(c);
    sign_with_ecdsa_benchmark(c);
}

criterion_group!(benchmarks, ecdsa_benchmark);
criterion_main!(benchmarks);
