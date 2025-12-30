//! The benchmark installs the specified number of `load_simulator` canisters
//! using the `canister_creator` and executes the specified amount of rounds.
//! It measures the total time taken to complete the rounds and the throughput,
//! i.e., the number of rounds executed per second (essentially, the FR).
//!
//! By default, each `load_simulator`` canister runs a periodic timer with
//! a one-second interval and accesses stable memory every fifth call.
//!
//! This benchmark is useful for debugging and benchmarking scheduler
//! and sandbox eviction changes. For more realistic testnet load tests,
//! refer to the `dfinity/subnet-load-tester` project.
//!
//! Quick start:
//!     bazel run //rs/execution_environment:load_simulator_canisters_bench -- --quick 200
//!
//! Example output:
//!     ==> Creating 2 creator canisters...
//!     ==> Creating 200 load simulator canisters...
//!     ==> Awaiting creation to finish...
//!     ==> Installing 200 load simulators...
//!     ==> Awaiting installation to finish...
//!     Load simulator/200 canisters/10 rounds
//!                             time:   [1.9450 s 1.9450 s 1.9450 s]
//!                                      ^ total time taken to complete 10 rounds
//!                             thrpt:  [5.1414  elem/s 5.1414  elem/s 5.1414  elem/s]
//!                                      ^ number of rounds executed per second (the FR)

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use ic_state_machine_tests::StateMachine;
use ic_types::{Cycles, PrincipalId};

const CANISTERS_PER_CREATOR: usize = 100;

fn bytes_to_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| byte.to_string())
        .collect::<Vec<String>>()
        .join(",")
}

fn setup_env(total_canisters: usize) -> StateMachine {
    assert!(total_canisters >= CANISTERS_PER_CREATOR);
    assert!(total_canisters.is_multiple_of(CANISTERS_PER_CREATOR));

    let env = StateMachine::new();
    let wasm = canister_test::Project::cargo_bin_maybe_from_env("canister_creator_canister", &[]);

    let mut creator_ids = vec![];
    let num_creators = total_canisters / CANISTERS_PER_CREATOR;
    println!("==> Creating {num_creators} creator canisters...");
    for _ in 1..=num_creators {
        let canister_id = env
            .install_canister_with_cycles(wasm.clone().bytes(), vec![], None, Cycles::new(1 << 64))
            .unwrap();
        creator_ids.push(canister_id);
    }

    println!("==> Creating {total_canisters} load simulator canisters...");
    let mut ingress_ids = vec![];
    for canister_id in creator_ids.iter() {
        let ingress_id = env.send_ingress(
            PrincipalId::new_anonymous(),
            *canister_id,
            "create_canisters",
            format!("{CANISTERS_PER_CREATOR}").as_bytes().to_vec(),
        );
        ingress_ids.push(ingress_id);
    }

    println!("==> Awaiting creation to finish...");
    for ingress_id in ingress_ids.into_iter() {
        env.await_ingress(ingress_id, 1_000).unwrap();
    }

    println!("==> Installing {total_canisters} load simulators...");
    let wasm = canister_test::Project::cargo_bin_maybe_from_env("load_simulator_canister", &[]);
    let mut ingress_ids = vec![];
    for canister_id in creator_ids.iter() {
        let ingress_id = env.send_ingress(
            PrincipalId::new_anonymous(),
            *canister_id,
            "install_code",
            format!(
                r#"[[{}],[{}]]"#,
                bytes_to_str(&wasm.clone().bytes()),
                bytes_to_str(&[])
            )
            .as_bytes()
            .to_vec(),
        );
        ingress_ids.push(ingress_id);
    }

    println!("==> Awaiting installation to finish...");
    for ingress_id in ingress_ids.into_iter() {
        env.await_ingress(ingress_id, 1_000).unwrap();
    }
    env.set_checkpoints_enabled(false);

    env
}

fn run_load_simulator_canisters(total_canisters: usize, rounds: u64, c: &mut Criterion) {
    let mut group = c.benchmark_group("Load simulator");
    group
        .throughput(criterion::Throughput::Elements(rounds))
        .bench_function(
            format!("{total_canisters} canisters/{rounds} rounds"),
            |bench| {
                bench.iter_batched(
                    || setup_env(total_canisters),
                    |env| {
                        for _ in 1..=rounds {
                            env.advance_time(Duration::from_secs(1));
                            env.tick();
                        }
                    },
                    criterion::BatchSize::PerIteration,
                );
            },
        );
}

fn load_simulator_canisters_bench_200(c: &mut Criterion) {
    run_load_simulator_canisters(200, 10, c);
}
fn load_simulator_canisters_bench_3000(c: &mut Criterion) {
    run_load_simulator_canisters(3_000, 100, c);
}
fn load_simulator_canisters_bench_4000(c: &mut Criterion) {
    run_load_simulator_canisters(4_000, 100, c);
}
fn load_simulator_canisters_bench_4500(c: &mut Criterion) {
    run_load_simulator_canisters(4_500, 100, c);
}
fn load_simulator_canisters_bench_5000(c: &mut Criterion) {
    run_load_simulator_canisters(5_000, 100, c);
}
fn load_simulator_canisters_bench_5500(c: &mut Criterion) {
    run_load_simulator_canisters(5_500, 100, c);
}
fn load_simulator_canisters_bench_6000(c: &mut Criterion) {
    run_load_simulator_canisters(6_000, 100, c);
}
fn load_simulator_canisters_bench_6500(c: &mut Criterion) {
    run_load_simulator_canisters(6_500, 100, c);
}
fn load_simulator_canisters_bench_7000(c: &mut Criterion) {
    run_load_simulator_canisters(7_000, 100, c);
}
fn load_simulator_canisters_bench_7500(c: &mut Criterion) {
    run_load_simulator_canisters(7_500, 100, c);
}
fn load_simulator_canisters_bench_8000(c: &mut Criterion) {
    run_load_simulator_canisters(8_000, 100, c);
}
fn load_simulator_canisters_bench_8500(c: &mut Criterion) {
    run_load_simulator_canisters(8_500, 100, c);
}

criterion_group!(
    benchmarks,
    load_simulator_canisters_bench_200,
    load_simulator_canisters_bench_3000,
    load_simulator_canisters_bench_4000,
    load_simulator_canisters_bench_4500,
    load_simulator_canisters_bench_5000,
    load_simulator_canisters_bench_5500,
    load_simulator_canisters_bench_6000,
    load_simulator_canisters_bench_6500,
    load_simulator_canisters_bench_7000,
    load_simulator_canisters_bench_7500,
    load_simulator_canisters_bench_8000,
    load_simulator_canisters_bench_8500,
);
criterion_main!(benchmarks);
