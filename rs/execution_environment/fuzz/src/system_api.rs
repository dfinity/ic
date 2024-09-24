use wasm_fuzzers::ic_wasm::ICWasmModule;

#[inline(always)]
pub fn run_fuzzer(module: ICWasmModule) {
    let wasm = module.module.to_bytes();
    let (env, canister_id) =
        setup_and_install_wasm(CanisterSettingsArgsBuilder::new().build(), wasm);

    let _ = env.execute_ingress(canister_id, "update", vec![]);
}

fn setup(settings: CanisterSettingsArgs) -> (StateMachine, CanisterId) {
    let subnet_type = SubnetType::Application;
    let mut subnet_config = SubnetConfig::new(subnet_type);
    subnet_config.scheduler_config.max_instructions_per_round = MAX_INSTRUCTIONS_PER_ROUND;
    subnet_config.scheduler_config.max_instructions_per_message = MAX_INSTRUCTIONS_PER_MESSAGE;
    subnet_config.scheduler_config.max_instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE;
    let config = StateMachineConfig::new(subnet_config, ExecutionConfig::default());
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
        .with_checkpoints_enabled(false)
        .build();
    let canister_id =
        env.create_canister_with_cycles(None, Cycles::from(100_000_000_000_u128), Some(settings));

    (env, canister_id)
}

fn setup_and_install_wasm(
    settings: CanisterSettingsArgs,
    wasm: Vec<u8>,
) -> (StateMachine, CanisterId) {
    let (env, canister_id) = setup(settings);
    env.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, wasm, vec![])
        .unwrap();

    (env, canister_id)
}
