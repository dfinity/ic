use std::time::Duration;

use criterion::Criterion;
use ic_state_machine_tests::{Cycles, PrincipalId, StateMachine};

const NUM_CREATOR_CANISTERS: usize = 30;
const NUM_CANISTERS_PER_CREATOR_CANISTER: usize = 100;

pub const TIMER_CANISTER_WASM: &[u8] = include_bytes!("data/timer-canister.wasm.gz");

fn bytes_to_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| byte.to_string())
        .collect::<Vec<String>>()
        .join(",")
}

fn main() {
    let env = StateMachine::new();
    let features = [];
    let wasm =
        canister_test::Project::cargo_bin_maybe_from_env("canister_creator_canister", &features);

    let mut canister_ids = vec![];
    for i in 0..NUM_CREATOR_CANISTERS {
        println!("==> creator:{i}");
        let canister_id = env
            .install_canister_with_cycles(wasm.clone().bytes(), vec![], None, Cycles::new(1 << 64))
            .unwrap();
        canister_ids.push(canister_id);
    }

    println!("Creating 100k canisters. It may take a couple of minutes.");

    let mut ingress_ids = vec![];
    for canister_id in canister_ids.iter() {
        println!("==>     sending create canisters to:{canister_id}");
        let ingress_id = env.send_ingress(
            PrincipalId::new_anonymous(),
            *canister_id,
            "create_canisters",
            format!("{}", NUM_CANISTERS_PER_CREATOR_CANISTER)
                .as_bytes()
                .to_vec(),
        );
        ingress_ids.push(ingress_id);
    }

    for ingress_id in ingress_ids.into_iter() {
        println!("==>     awaiting:{ingress_id}");
        env.await_ingress(ingress_id, 1_000).unwrap();
    }

    let mut ingress_ids = vec![];
    for canister_id in canister_ids.iter() {
        println!("==>     sending install code to:{canister_id}");
        let ingress_id = env.send_ingress(
            PrincipalId::new_anonymous(),
            *canister_id,
            "install_code",
            format!(
                r#"[[{}],[{}]]"#,
                bytes_to_str(TIMER_CANISTER_WASM),
                bytes_to_str(&vec![])
            )
            .as_bytes()
            .to_vec(),
        );
        ingress_ids.push(ingress_id);
    }

    for ingress_id in ingress_ids.into_iter() {
        println!("==>     awaiting:{ingress_id}");
        env.await_ingress(ingress_id, 1_000).unwrap();
    }

    for i in 0..3 {
        env.set_checkpoints_enabled(false);
        for r in 0..500 {
            if r % 10 == 0 {
                println!("==> Round:{i}/{r}");
            }
            env.advance_time(Duration::from_secs(1));
            env.tick();
        }
        env.set_checkpoints_enabled(true);
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }

    // let mut criterion = Criterion::default().sample_size(10);
    // let mut group = criterion.benchmark_group("100k canisters");
    // group.bench_function("round", |bench| {
    //     bench.iter_batched(
    //         || {
    //             env.set_checkpoints_enabled(false);
    //         },
    //         |_| {
    //             for _ in 0..500 {
    //                 env.tick();
    //             }
    //         },
    //         criterion::BatchSize::SmallInput,
    //     );
    // });

    // let mut criterion = Criterion::default().sample_size(10);
    // let mut group = criterion.benchmark_group("100k canisters");

    // group.bench_function("checkpoint", |bench| {
    //     bench.iter_batched(
    //         || {
    //             env.set_checkpoints_enabled(true);
    //         },
    //         |_| {
    //             env.tick();
    //         },
    //         criterion::BatchSize::SmallInput,
    //     );
    // });

    let start = std::time::Instant::now();
    drop(env);
    let duration = start.elapsed();

    println!("XXX Time to drop: {:?}", duration);
}
