use ic_config::{
    execution_environment::Config as HypervisorConfig,
    flag_status::FlagStatus,
    subnet_config::{SchedulerConfig, SubnetConfig, SubnetConfigs},
};
use ic_ic00_types::{EmptyBlob, InstallCodeArgs, Method, Payload, IC_00};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    CanisterId, CanisterInstallMode, CanisterSettingsArgs, ErrorCode, IngressState, IngressStatus,
    MessageId, PrincipalId, StateMachine, StateMachineConfig,
};
use ic_types::{ingress::WasmResult, Cycles, NumInstructions};
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

/// This is a tentative workaround for the issue that `StateMachine` disables DTS
/// and sandboxing if it cannot find the sandboxing binaries, which happens in
/// local builds with `cargo`.
fn should_skip_test_due_to_disabled_dts() -> bool {
    if !(std::env::var("SANDBOX_BINARY").is_ok() && std::env::var("LAUNCHER_BINARY").is_ok()) {
        eprintln!(
            "Skipping the test because DTS is not supported without \
             canister sandboxing binaries.\n\
             To fix this:\n\
             - either run the test with `bazel test`\n\
             - or define the SANDBOX_BINARY and LAUNCHER_BINARY environment variables \
             with the paths to the corresponding binaries."
        );
        return true;
    }
    false
}

/// Extracts the ingress state from the ingress status.
fn ingress_state(ingress_status: IngressStatus) -> Option<IngressState> {
    match ingress_status {
        IngressStatus::Known { state, .. } => Some(state),
        IngressStatus::Unknown => None,
    }
}

struct DtsInstallCode {
    env: StateMachine,
    canister_id: CanisterId,
    install_code_ingress_id: MessageId,
}

/// A helper that:
/// 1) Creates a `StateMachine` with DTS enabled.
/// 2) Creates a canister.
/// 3) Sends an `install_code` ingress message that will take multiple rounds to
///    complete.
fn setup_dts_install_code(
    initial_balance: Cycles,
    freezing_threshold_in_seconds: usize,
) -> DtsInstallCode {
    const DTS_INSTALL_WAT: &str = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (func (export "canister_query read")
                (call $msg_reply_data_append
                    (i32.const 0) ;; the counter from heap[0]
                    (i32.const 10)) ;; length
                (call $msg_reply)
            )
            (func $start
                (drop (memory.grow (i32.const 1)))
                (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
                (memory.fill (i32.const 0) (i32.const 45) (i32.const 1000))
            )
            (func (export "canister_init")
                (drop (memory.grow (i32.const 1)))
                (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
                (memory.fill (i32.const 0) (i32.const 45) (i32.const 1000))
                (memory.fill (i32.const 0) (i32.const 45) (i32.const 1000))
                (memory.fill (i32.const 0) (i32.const 45) (i32.const 1000))
            )
            (start $start)
            (memory 0 20)
        )"#;

    let subnet_config = SubnetConfigs::default().own_subnet_config(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        SubnetConfig {
            scheduler_config: SchedulerConfig {
                max_instructions_per_install_code: NumInstructions::from(1000000),
                max_instructions_per_install_code_slice: NumInstructions::from(1000),
                ..subnet_config.scheduler_config
            },
            ..subnet_config
        },
        HypervisorConfig {
            deterministic_time_slicing: FlagStatus::Enabled,
            ..Default::default()
        },
    ));

    let canister_id = env.create_canister_with_cycles(
        initial_balance,
        Some(CanisterSettingsArgs {
            controller: None,
            controllers: None,
            compute_allocation: Some(1u32.into()),
            memory_allocation: None,
            freezing_threshold: Some(freezing_threshold_in_seconds.into()),
        }),
    );

    let mut features = wabt::Features::new();
    features.enable_bulk_memory();

    let install_code_ingress_id = env.send_ingress(
        PrincipalId::new_anonymous(),
        IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(
            CanisterInstallMode::Install,
            canister_id,
            wabt::wat2wasm_with_features(DTS_INSTALL_WAT, features).unwrap(),
            vec![],
            None,
            None,
            None,
        )
        .encode(),
    );

    DtsInstallCode {
        env,
        canister_id,
        install_code_ingress_id,
    }
}

#[test]
fn dts_install_code_with_concurrent_ingress_sufficient_cycles() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }
    // These numbers were obtained by running the test and printing the costs.
    // They need to be adjusted if we change fees or the Wasm source code.
    let install_code_ingress_cost = Cycles::new(1846000);
    let normal_ingress_cost = Cycles::new(1224000);
    let max_execution_cost = Cycles::new(990000);
    let actual_execution_cost = Cycles::new(818012);

    // The initial balance is sufficient to run `install_code` and to send an
    // ingress message concurrently.
    let initial_balance = install_code_ingress_cost + normal_ingress_cost + max_execution_cost;

    let DtsInstallCode {
        env,
        canister_id,
        install_code_ingress_id,
    } = setup_dts_install_code(initial_balance, 0);

    // Start execution of `install_code`.
    env.tick();

    // Send a normal ingress message while the execution is paused.
    env.send_ingress(PrincipalId::new_anonymous(), canister_id, "read", vec![]);

    let result = env.await_ingress(install_code_ingress_id, 100).unwrap();

    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));
    assert_eq!(
        env.cycle_balance(canister_id),
        (initial_balance - install_code_ingress_cost - normal_ingress_cost - actual_execution_cost)
            .get()
    );
}

#[test]
fn dts_install_code_with_concurrent_ingress_insufficient_cycles() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }
    // These numbers were obtained by running the test and printing the costs.
    // They need to be adjusted if we change fees or the Wasm source code.
    let install_code_ingress_cost = Cycles::new(1846000);
    let normal_ingress_cost = Cycles::new(1224000);
    let max_execution_cost = Cycles::new(990000);
    let actual_execution_cost = Cycles::new(818012);

    // The initial balance is not sufficient for both execution and concurrent ingress message.
    let initial_balance = install_code_ingress_cost + normal_ingress_cost.max(max_execution_cost);

    let DtsInstallCode {
        env,
        canister_id,
        install_code_ingress_id,
    } = setup_dts_install_code(initial_balance, 0);

    // Start execution of `install_code`.
    env.tick();

    // Send a normal ingress message while the execution is paused.
    let msg_id = env.send_ingress(PrincipalId::new_anonymous(), canister_id, "read", vec![]);

    let err = env.await_ingress(msg_id, 100).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);
    assert_eq!(
        err.description(),
        format!(
            "Canister {} is out of cycles: \
             requested {} cycles but the available balance is \
             {} cycles and the freezing threshold 0 cycles",
            canister_id,
            normal_ingress_cost,
            initial_balance - install_code_ingress_cost - max_execution_cost,
        )
    );

    let result = env.await_ingress(install_code_ingress_id, 100).unwrap();

    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));
    assert_eq!(
        env.cycle_balance(canister_id),
        (initial_balance - install_code_ingress_cost - actual_execution_cost).get()
    );
}

#[test]
fn dts_install_code_with_concurrent_ingress_and_freezing_threshold_insufficient_cycles() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }
    // These numbers were obtained by running the test and printing the costs.
    // They need to be adjusted if we change fees or the Wasm source code.
    let install_code_ingress_cost = Cycles::new(1846000);
    let normal_ingress_cost = Cycles::new(1224000);
    let max_execution_cost = Cycles::new(990000);
    let actual_execution_cost = Cycles::new(818012);
    let freezing_threshold = Cycles::new(10000000);

    // The initial balance is not sufficient for both execution and concurrent ingress message.
    let initial_balance = freezing_threshold
        + install_code_ingress_cost
        + normal_ingress_cost.max(max_execution_cost);

    let DtsInstallCode {
        env,
        canister_id,
        install_code_ingress_id,
    } = setup_dts_install_code(initial_balance, 1);

    // Start execution of `install_code`.
    env.tick();

    // Send a normal ingress message while the execution is paused.
    let msg_id = env.send_ingress(PrincipalId::new_anonymous(), canister_id, "read", vec![]);

    let err = env.await_ingress(msg_id, 1).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);
    assert_eq!(
        err.description(),
        format!(
            "Canister {} is out of cycles: \
             requested {} cycles but the available balance is \
             {} cycles and the freezing threshold {} cycles",
            canister_id,
            normal_ingress_cost,
            initial_balance - install_code_ingress_cost - max_execution_cost,
            freezing_threshold,
        )
    );

    let result = env.await_ingress(install_code_ingress_id, 100).unwrap();
    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));
    assert_eq!(
        env.cycle_balance(canister_id),
        (initial_balance - install_code_ingress_cost - actual_execution_cost).get()
    );
}

#[test]
fn dts_pending_upgrade_with_heartbeat() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let subnet_config = SubnetConfigs::default().own_subnet_config(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        SubnetConfig {
            scheduler_config: SchedulerConfig {
                max_instructions_per_install_code: NumInstructions::from(1_000_000_000),
                max_instructions_per_install_code_slice: NumInstructions::from(10_000),
                max_instructions_per_round: NumInstructions::from(20_000),
                max_instructions_per_message: NumInstructions::from(1_000_000_000),
                max_instructions_per_slice: NumInstructions::from(10_000),
                instruction_overhead_per_message: NumInstructions::from(0),
                ..subnet_config.scheduler_config
            },
            ..subnet_config
        },
        HypervisorConfig {
            deterministic_time_slicing: FlagStatus::Enabled,
            ..Default::default()
        },
    ));

    let wat = r#"
        (module
           (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (func (export "canister_query read")
                (call $msg_reply_data_append
                    (i32.const 0) ;; the counter from heap[0]
                    (i32.const 20)) ;; length
                (call $msg_reply))
            (func (export "canister_post_upgrade")
                (memory.fill (i32.const 0) (i32.const 34) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 45) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 56) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 67) (i32.const 10000))
            )
            (func (export "canister_heartbeat")
                (memory.fill (i32.const 0) (i32.const 12) (i32.const 10))
            )
            (memory 1)
        )"#;

    let mut features = wabt::Features::new();
    features.enable_bulk_memory();
    let binary = wabt::wat2wasm_with_features(wat, features).unwrap();

    let user_id = PrincipalId::new_anonymous();

    let controller = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let settings = Some(CanisterSettingsArgs {
        controller: None,
        controllers: Some(vec![user_id, controller.get()]),
        compute_allocation: None,
        memory_allocation: None,
        freezing_threshold: None,
    });

    let canister = env
        .install_canister_with_cycles(binary.clone(), vec![], settings, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // Enable the checkpoints so that the first install code message is always
    // aborted and doesn't make progress.
    env.set_checkpoints_enabled(true);

    let upgrade = {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Upgrade,
            canister,
            binary,
            vec![],
            None,
            None,
            None,
        );
        let payload = wasm()
            .call_simple(
                IC_00,
                Method::InstallCode,
                call_args()
                    .other_side(args.encode())
                    .on_reject(wasm().reject_message().reject()),
            )
            .build();
        env.send_ingress(user_id, controller, "update", payload)
    };

    for _ in 0..10 {
        // With checkpoints enabled, the update message will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    assert_eq!(
        ingress_state(env.ingress_status(&upgrade)),
        Some(IngressState::Received)
    );

    env.set_checkpoints_enabled(false);

    env.await_ingress(upgrade, 20).unwrap();

    let read = env.send_ingress(user_id, canister, "read", vec![]);
    let result = env.await_ingress(read, 10).unwrap();
    let mut expected = vec![12; 10];
    expected.extend([67; 10].iter());
    assert_eq!(result, WasmResult::Reply(expected));
}
