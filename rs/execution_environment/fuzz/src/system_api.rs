use ic_management_canister_types::{
    CanisterInstallMode, CanisterSettingsArgs, CanisterSettingsArgsBuilder,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_types::{CanisterId, Cycles};
use wasm_fuzzers::ic_wasm::ICWasmModule;

#[inline(always)]
pub fn run_fuzzer(module: ICWasmModule) {
    let wasm = module.module.to_bytes();
    let (env, canister_id) =
        setup_and_install_wasm(CanisterSettingsArgsBuilder::new().build(), wasm);

    let _ = env.execute_ingress(canister_id, "update", vec![]);
}

fn setup_and_install_wasm(
    settings: CanisterSettingsArgs,
    wasm: Vec<u8>,
) -> (StateMachine, CanisterId) {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_checkpoints_enabled(false)
        .build();
    let canister_id =
        env.create_canister_with_cycles(None, Cycles::from(100_000_000_000_u128), Some(settings));
    env.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, wasm, vec![])
        .unwrap();

    (env, canister_id)
}
