use candid::Encode;
use criterion::Criterion;

use ic_state_machine_tests::{Cycles, StateMachine};
use ic_types::ingress::WasmResult;

const INITIAL_NUMBER_OF_ENTRIES: u64 = 100_000;
const UPDATE_COUNT: u64 = 10_000;

fn main() {
    let env = StateMachine::new();
    let wasm = canister_test::Project::cargo_bin_maybe_from_env("stable_structures_canister", &[]);

    let canister_id = env
        .install_canister_with_cycles(
            wasm.bytes(),
            Encode!(&INITIAL_NUMBER_OF_ENTRIES).unwrap(),
            None,
            Cycles::new(1 << 64),
        )
        .unwrap();

    let mut criterion = Criterion::default().sample_size(10);
    let mut group = criterion.benchmark_group("btree");
    group.bench_function("update", |bench| {
        bench.iter(|| {
            let result = env
                .execute_ingress(
                    canister_id,
                    "update_increment_values",
                    Encode!(&UPDATE_COUNT).unwrap(),
                )
                .unwrap();
            assert!(matches!(result, WasmResult::Reply(_)))
        });
    });
}
