use criterion::Criterion;
use ic_state_machine_tests::{Cycles, PrincipalId, StateMachine};

const NUM_CREATOR_CANISTERS: usize = 10;
const NUM_CANISTERS_PER_CREATOR_CANISTER: usize = 10_000;

fn main() {
    let env = StateMachine::new();
    let features = [];
    let wasm =
        canister_test::Project::cargo_bin_maybe_from_env("canister_creator_canister", &features);

    let mut canister_ids = vec![];
    for _ in 0..NUM_CREATOR_CANISTERS {
        let canister_id = env
            .install_canister_with_cycles(wasm.clone().bytes(), vec![], None, Cycles::new(1 << 64))
            .unwrap();
        canister_ids.push(canister_id);
    }

    println!("Creating 100k canisters. It may take a couple of minutes.");

    let mut ingress_ids = vec![];
    for canister_id in canister_ids.into_iter() {
        let ingress_id = env.send_ingress(
            PrincipalId::new_anonymous(),
            canister_id,
            "create_canisters",
            format!("{}", NUM_CANISTERS_PER_CREATOR_CANISTER)
                .as_bytes()
                .to_vec(),
        );
        ingress_ids.push(ingress_id);
    }

    for ingress_id in ingress_ids.into_iter() {
        env.await_ingress(ingress_id, 1_000).unwrap();
    }
    let mut criterion = Criterion::default().sample_size(50);
    let mut group = criterion.benchmark_group("100k canisters");
    group.bench_function("round", |bench| {
        bench.iter_batched(
            || {
                env.set_checkpoints_enabled(false);
            },
            |_| {
                env.tick();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    let mut criterion = Criterion::default().sample_size(10);
    let mut group = criterion.benchmark_group("100k canisters");

    group.bench_function("checkpoint", |bench| {
        bench.iter_batched(
            || {
                env.set_checkpoints_enabled(true);
            },
            |_| {
                env.tick();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}
