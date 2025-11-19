use proptest::{
    prelude::*,
    test_runner::{Config, TestRng, TestRunner},
};

use canister_test::{CanisterInstallMode, InstallCodeArgs};
use ic_test_utilities::universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use ic_test_utilities_execution_environment::ExecutionTestBuilder;
use ic_types::{Cycles, ingress::WasmResult};

#[derive(Copy, Clone, Debug)]
enum GrowCommand {
    Stable32(u32),
    Stable64(u64),
}

fn grow_command_strategy() -> impl Strategy<Value = GrowCommand> {
    prop_oneof![
        any::<u32>().prop_map(GrowCommand::Stable32),
        any::<u64>().prop_map(GrowCommand::Stable64),
    ]
}

fn run_memory_grows(grows: &[GrowCommand]) {
    const LARGE_INSTRUCTION_LIMIT: u64 = 1_000_000_000_000;

    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(LARGE_INSTRUCTION_LIMIT)
        .with_instruction_limit_without_dts(LARGE_INSTRUCTION_LIMIT)
        .with_slice_instruction_limit(LARGE_INSTRUCTION_LIMIT)
        .build();
    let canister_id = test.create_canister(Cycles::from(1_u128 << 64));
    let args = InstallCodeArgs::new(
        CanisterInstallMode::Install,
        canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
    );
    let result = test.install_code(args).unwrap();
    if let WasmResult::Reject(s) = result {
        panic!("Installation rejected: {s}")
    }

    let mut wasm = wasm();
    for grow in grows {
        wasm = match grow {
            GrowCommand::Stable32(p) => wasm.stable_grow(*p),
            GrowCommand::Stable64(p) => wasm.stable64_grow(*p),
        };
    }
    let payload = wasm.reply().build();

    let result = test.ingress(canister_id, "update", payload).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
}

#[test]
fn random_stable_grows() {
    let config = Config::with_cases(10);
    let algorithm = config.rng_algorithm;
    let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
    runner
        .run(
            &proptest::collection::vec(grow_command_strategy(), 1_000),
            |n| {
                run_memory_grows(&n);
                Ok(())
            },
        )
        .unwrap();
}
