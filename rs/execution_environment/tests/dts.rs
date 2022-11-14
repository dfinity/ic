use std::time::{Duration, SystemTime};

use candid::Encode;
use ic_config::{
    execution_environment::Config as HypervisorConfig,
    flag_status::FlagStatus,
    subnet_config::{SchedulerConfig, SubnetConfig, SubnetConfigs},
};
use ic_ic00_types::{CanisterIdRecord, EmptyBlob, InstallCodeArgs, Method, Payload, IC_00};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    CanisterId, CanisterInstallMode, CanisterSettingsArgs, ErrorCode, IngressState, IngressStatus,
    MessageId, PrincipalId, StateMachine, StateMachineConfig,
};
use ic_types::{ingress::WasmResult, Cycles, NumInstructions};
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

const DTS_WAT: &str = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (import "ic0" "time" (func $time (result i64)))
            (import "ic0" "global_timer_set"
                (func $global_timer_set (param i64) (result i64))
            )
            (func $work
                (memory.fill (i32.const 0) (i32.const 12) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 23) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 34) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 45) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 56) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 67) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 78) (i32.const 10000))
            )
            (start $work)

            (func (export "canister_pre_upgrade")
                (call $work)
            )

            (func (export "canister_post_upgrade")
                (call $work)
            )

            (func (export "canister_init")
                (call $work)
                (drop (call $global_timer_set
                    (i64.add (call $time) (i64.const 1))
                ))
            )

            (func (export "canister_query read")
                (call $msg_reply_data_append
                    (i32.const 0) ;; the counter from heap[0]
                    (i32.const 20)) ;; length
                (call $msg_reply))

            (func (export "canister_update update")
                (call $work)
                (call $msg_reply_data_append (i32.const 0) (i32.const 0))
                (call $msg_reply)
            )

            (func (export "canister_heartbeat")
                (memory.fill (i32.const 0) (i32.const 12) (i32.const 10))
            )

            (func (export "canister_global_timer")
                (memory.fill (i32.const 10) (i32.const 13) (i32.const 5))
            )

            (memory 1)
        )"#;

fn wat2wasm(wat: &str) -> Vec<u8> {
    let mut features = wabt::Features::new();
    features.enable_bulk_memory();
    wabt::wat2wasm_with_features(wat, features).unwrap()
}

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

fn dts_env(
    message_instruction_limit: NumInstructions,
    slice_instruction_limit: NumInstructions,
) -> StateMachine {
    let subnet_config = SubnetConfigs::default().own_subnet_config(SubnetType::Application);
    StateMachine::new_with_config(StateMachineConfig::new(
        SubnetConfig {
            scheduler_config: SchedulerConfig {
                max_instructions_per_install_code: message_instruction_limit,
                max_instructions_per_install_code_slice: slice_instruction_limit,
                max_instructions_per_round: slice_instruction_limit + slice_instruction_limit,
                max_instructions_per_message: message_instruction_limit,
                max_instructions_per_message_without_dts: slice_instruction_limit,
                max_instructions_per_slice: slice_instruction_limit,
                instruction_overhead_per_message: NumInstructions::from(0),
                ..subnet_config.scheduler_config
            },
            ..subnet_config
        },
        HypervisorConfig {
            deterministic_time_slicing: FlagStatus::Enabled,
            ..Default::default()
        },
    ))
}

fn dts_install_code_env(
    message_instruction_limit: NumInstructions,
    slice_instruction_limit: NumInstructions,
) -> StateMachine {
    let subnet_config = SubnetConfigs::default().own_subnet_config(SubnetType::Application);
    StateMachine::new_with_config(StateMachineConfig::new(
        SubnetConfig {
            scheduler_config: SchedulerConfig {
                max_instructions_per_install_code: message_instruction_limit,
                max_instructions_per_install_code_slice: slice_instruction_limit,
                max_instructions_per_round: message_instruction_limit + message_instruction_limit,
                max_instructions_per_message: message_instruction_limit,
                max_instructions_per_message_without_dts: slice_instruction_limit,
                max_instructions_per_slice: message_instruction_limit,
                instruction_overhead_per_message: NumInstructions::from(0),
                ..subnet_config.scheduler_config
            },
            ..subnet_config
        },
        HypervisorConfig {
            deterministic_time_slicing: FlagStatus::Enabled,
            ..Default::default()
        },
    ))
}

/// Extracts the ingress state from the ingress status.
fn ingress_state(ingress_status: IngressStatus) -> Option<IngressState> {
    match ingress_status {
        IngressStatus::Known { state, .. } => Some(state),
        IngressStatus::Unknown => None,
    }
}

/// Extracts the ingress time from the ingress status.
fn ingress_time(ingress_status: IngressStatus) -> Option<SystemTime> {
    match ingress_status {
        IngressStatus::Known { time, .. } => {
            let time =
                SystemTime::UNIX_EPOCH + Duration::from_nanos(time.as_nanos_since_unix_epoch());
            Some(time)
        }
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

    let env = dts_install_code_env(
        NumInstructions::from(1_000_000),
        NumInstructions::from(1000),
    );

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

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

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

    for _ in 0..5 {
        // With checkpoints enabled, the update message will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    assert_eq!(
        ingress_state(env.ingress_status(&upgrade)),
        Some(IngressState::Processing)
    );

    env.set_checkpoints_enabled(false);

    env.await_ingress(upgrade, 30).unwrap();

    env.advance_time(Duration::from_secs(1));
    let read = env.send_ingress(user_id, canister, "read", vec![]);
    let result = env.await_ingress(read, 10).unwrap();

    let mut expected = vec![12; 10]; // heartbeat
    expected.extend([13; 5].iter()); // global timer
    expected.extend([78; 5].iter()); // work()
    assert_eq!(result, WasmResult::Reply(expected));
}

/// In this test the controller canister sends `n` install code messages to `n`
/// different canisters. Execution of each message requires multiple slices.
/// The test also sends `n` ingress messages to query the canister status of
/// each canister.
///
/// The expectations:
/// - the install code messages run one by one.
/// - the canister status messages are blocked by the corresponding
///   install code messages.
#[test]
fn dts_scheduling_of_install_code() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_install_code_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

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

    let n = 10;
    let mut canister = vec![];

    for i in 0..n {
        let id = env.create_canister_with_cycles(INITIAL_CYCLES_BALANCE, settings.clone());
        eprintln!("canister[{}] = {}", i, id);
        canister.push(id);
    }

    // Enable the checkpoints so that the first install code message is always
    // aborted and doesn't make progress.
    env.set_checkpoints_enabled(true);

    let mut ingress = vec![];
    for c in canister.iter() {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            *c,
            binary.clone(),
            vec![],
            None,
            None,
            None,
        );
        let install = wasm()
            .call_simple(
                IC_00,
                Method::InstallCode,
                call_args()
                    .other_side(args.encode())
                    .on_reject(wasm().reject_message().reject()),
            )
            .build();
        let id = env.send_ingress(user_id, controller, "update", install);
        ingress.push(id);
    }

    for _ in 0..5 {
        // With checkpoints enabled, the first install code will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    // This ingress message is not blocked by the first install code message.
    let status_last = env.send_ingress(
        user_id,
        IC_00,
        Method::CanisterStatus,
        Encode!(&CanisterIdRecord::from(canister[n - 1])).unwrap(),
    );

    let mut status = vec![];

    // All other ingress messages are blocked by the first install code message.
    for c in canister.iter().take(n - 1) {
        let id = env.send_ingress(
            user_id,
            IC_00,
            Method::CanisterStatus,
            Encode!(&CanisterIdRecord::from(*c)).unwrap(),
        );
        status.push(id);
    }

    for _ in 0..5 {
        // With checkpoints enabled, the first install code will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    match ingress_state(env.ingress_status(&status_last)).unwrap() {
        IngressState::Completed(_) => {}
        ingress_state => {
            unreachable!("Expected message to complete, got {:?}", ingress_state)
        }
    }

    for s in status.iter().take(n - 1) {
        assert_eq!(
            ingress_state(env.ingress_status(s)),
            Some(IngressState::Received)
        );
    }

    // All install code messages are pending.
    for i in ingress.iter() {
        assert_eq!(
            ingress_state(env.ingress_status(i)),
            Some(IngressState::Processing)
        );
    }

    env.set_checkpoints_enabled(false);

    // Now install code messages start making progress.
    for k in 0..n {
        env.await_ingress(ingress[k].clone(), 30).unwrap();
        // All subsequent install code messages are still blocked.
        for i in ingress.iter().skip(k + 1) {
            assert_eq!(
                ingress_state(env.ingress_status(i)),
                Some(IngressState::Processing)
            );
        }
    }

    // By this time all canister status messages should be processed.
    for s in status.iter() {
        match ingress_state(env.ingress_status(s)).unwrap() {
            IngressState::Completed(_) => {}
            ingress_state => {
                unreachable!("Expected message to complete, got {:?}", ingress_state)
            }
        }
    }
}

/// This test creates `n` controller canisters and `n` ordinary canisters.
/// The first half of the controllers install code on the first half of the
/// canisters. The second half of the controllers query the canister status
/// of the second half of the canisters.
/// The expectation is that canister status messages are not blocked the
/// long-running install code messages.
#[test]
fn dts_pending_install_code_does_not_block_subnet_messages_of_other_canisters() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_install_code_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let n = 10;

    let mut controller = vec![];
    for _ in 0..n {
        let id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_WASM.into(),
                vec![],
                None,
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        controller.push(id);
    }

    let settings = Some(CanisterSettingsArgs {
        controller: None,
        controllers: Some(controller.iter().map(|x| x.get()).collect()),
        compute_allocation: None,
        memory_allocation: None,
        freezing_threshold: None,
    });

    let mut canister = vec![];

    for _ in 0..n {
        let id = env.create_canister_with_cycles(INITIAL_CYCLES_BALANCE, settings.clone());
        canister.push(id);
    }

    // Enable the checkpoints so that the first install code message is always
    // aborted and doesn't make progress.
    env.set_checkpoints_enabled(true);

    let mut install = vec![];
    for i in 0..n / 2 {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            canister[i],
            binary.clone(),
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
        let id = env.send_ingress(user_id, controller[i], "update", payload);
        install.push(id);
    }

    let mut status = vec![];
    for i in n / 2..n {
        let arg = Encode!(&CanisterIdRecord::from(canister[i])).unwrap();
        let payload = wasm()
            .call_simple(
                IC_00,
                Method::CanisterStatus,
                call_args()
                    .other_side(arg)
                    .on_reject(wasm().reject_message().reject()),
            )
            .build();
        let id = env.send_ingress(user_id, controller[i], "update", payload);
        status.push(id);
    }

    for _ in 0..5 {
        // With checkpoints enabled, the first install code will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    // All install code messages are pending.
    for i in install.iter() {
        assert_eq!(
            ingress_state(env.ingress_status(i)),
            Some(IngressState::Processing)
        );
    }

    // All canister status messages should be processed because they are not
    // blocked by install code messages.
    for s in status.iter() {
        match ingress_state(env.ingress_status(s)).unwrap() {
            IngressState::Completed(_) => {}
            ingress_state => {
                unreachable!("Expected message to complete, got {:?}", ingress_state)
            }
        }
    }

    env.set_checkpoints_enabled(false);

    // Now install code messages start making progress.
    for k in 0..n / 2 {
        env.await_ingress(install[k].clone(), 30).unwrap();
        // All subsequent install code messages are still blocked.
        for i in install.iter().skip(k + 1) {
            assert_eq!(
                ingress_state(env.ingress_status(i)),
                Some(IngressState::Processing)
            );
        }
    }
}

/// This test starts a long-running execution of an update message and sends a
/// canister status and an upgrade subnet messages for the same canisters.
/// The expectation is that the subnet messages are blocked by the
/// long-running update message.
#[test]
fn dts_pending_execution_blocks_subnet_messages_to_the_same_canister() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let settings = Some(CanisterSettingsArgs {
        controller: None,
        controllers: Some(vec![user_id]),
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

    let update = env.send_ingress(user_id, canister, "update", vec![]);

    for _ in 0..5 {
        // With checkpoints enabled, the update message will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    let status = {
        let arg = Encode!(&CanisterIdRecord::from(canister)).unwrap();
        env.send_ingress(user_id, IC_00, Method::CanisterStatus, arg)
    };

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
        env.send_ingress(user_id, IC_00, Method::InstallCode, args.encode())
    };

    for _ in 0..5 {
        // With checkpoints enabled, the update message will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_state(env.ingress_status(&status)),
        Some(IngressState::Received)
    );

    assert_eq!(
        ingress_state(env.ingress_status(&upgrade)),
        Some(IngressState::Received)
    );

    env.set_checkpoints_enabled(false);

    env.await_ingress(update, 30).unwrap();

    env.await_ingress(status, 30).unwrap();

    env.await_ingress(upgrade, 30).unwrap();
}

/// This test starts execution of a long-running install code message
/// and sends an update message to the same canister.
/// The expectation is that the update message is blocked.
#[test]
fn dts_pending_install_code_blocks_update_messages_to_the_same_canister() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let settings = Some(CanisterSettingsArgs {
        controller: None,
        controllers: Some(vec![user_id]),
        compute_allocation: None,
        memory_allocation: None,
        freezing_threshold: None,
    });

    let canister = env.create_canister_with_cycles(INITIAL_CYCLES_BALANCE, settings);

    // Enable the checkpoints so that the first install code message is always
    // aborted and doesn't make progress.
    env.set_checkpoints_enabled(true);

    let install = {
        let payload = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            canister,
            binary,
            vec![],
            None,
            None,
            None,
        );
        env.send_ingress(user_id, IC_00, Method::InstallCode, payload.encode())
    };

    let update = env.send_ingress(user_id, canister, "update", vec![]);

    for _ in 0..5 {
        // With checkpoints enabled, the update message will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    assert_eq!(
        ingress_state(env.ingress_status(&install)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Received)
    );

    env.set_checkpoints_enabled(false);

    env.await_ingress(install, 30).unwrap();
    env.await_ingress(update, 30).unwrap();
}

/// This test runs multiple long-running update and install code messages.
/// It also runs a short message every round.
/// The expectation that all messages eventually complete.
#[test]
fn dts_long_running_install_and_update() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let user_id = PrincipalId::new_anonymous();

    let n = 10;

    let mut controller = vec![];
    for _ in 0..n {
        let id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_WASM.into(),
                vec![],
                None,
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        controller.push(id);
    }

    let mut canister = vec![];

    for controller_id in controller.iter() {
        let settings = Some(CanisterSettingsArgs {
            controller: None,
            controllers: Some(vec![controller_id.get()]),
            compute_allocation: None,
            memory_allocation: None,
            freezing_threshold: None,
        });

        let id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_WASM.into(),
                vec![],
                settings.clone(),
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        canister.push(id);
    }

    let short = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let mut install = vec![];
    for i in 0..n {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Upgrade,
            canister[i],
            UNIVERSAL_CANISTER_WASM.into(),
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
        let id = env.send_ingress(user_id, controller[i], "update", payload);
        install.push(id);
    }

    let mut long_update = vec![];
    let mut short_update = vec![];

    for i in 0..30 {
        let work = wasm()
            .stable64_grow(1)
            .stable64_fill(0, 0, 10_000)
            .message_payload()
            .append_and_reply()
            .build();
        let id = env.send_ingress(user_id, canister[i % n], "update", work);
        long_update.push(id);

        let id = env.send_ingress(
            user_id,
            short,
            "update",
            wasm().push_int(0).reply_int().build(),
        );
        short_update.push(id);

        if i % 20 == 0 {
            env.set_checkpoints_enabled(true);
            env.tick();
            env.set_checkpoints_enabled(false);
        } else {
            env.tick();
        }
    }

    for msg_id in short_update.iter() {
        match ingress_state(env.ingress_status(msg_id)).unwrap() {
            IngressState::Completed(_) => {}
            ingress_state => {
                unreachable!("Expected message to complete, got {:?}", ingress_state)
            }
        }
    }

    for msg_id in long_update.into_iter() {
        env.await_ingress(msg_id, 100).unwrap();
    }

    for msg_id in install.into_iter() {
        env.await_ingress(msg_id, 100).unwrap();
    }
}

/// This test runs long-running update and install code messages. Each update
/// message performs a call with a long-running response callback.
/// It also runs a short message every round.
/// The expectation that all messages eventually complete.
#[test]
fn dts_long_running_calls() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let user_id = PrincipalId::new_anonymous();

    let n = 10;

    let mut canister = vec![];

    for _ in 0..n {
        let id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_WASM.into(),
                vec![],
                None,
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        canister.push(id);
    }

    let short = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let mut long_update = vec![];
    let mut short_update = vec![];

    for i in 0..30 {
        let work = wasm()
            .stable64_grow(1)
            .stable64_fill(0, 0, 10_000)
            .message_payload()
            .append_and_reply()
            .build();
        let payload = wasm()
            .call_simple(
                canister[(i + 1) % n].get(),
                "update",
                call_args().other_side(work.clone()).on_reply(work),
            )
            .build();
        let id = env.send_ingress(user_id, canister[i % n], "update", payload);
        long_update.push(id);

        let id = env.send_ingress(
            user_id,
            short,
            "update",
            wasm().push_int(0).reply_int().build(),
        );
        short_update.push(id);

        if i % 20 == 0 {
            env.set_checkpoints_enabled(true);
            env.tick();
            env.set_checkpoints_enabled(false);
        } else {
            env.tick();
        }
    }

    for msg_id in short_update.iter() {
        match ingress_state(env.ingress_status(msg_id)).unwrap() {
            IngressState::Completed(_) => {}
            ingress_state => {
                unreachable!("Expected message to complete, got {:?}", ingress_state)
            }
        }
    }

    for msg_id in long_update.into_iter() {
        env.await_ingress(msg_id, 100).unwrap();
    }
}

#[test]
fn dts_unrelated_subnet_messages_make_progress() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let settings = Some(CanisterSettingsArgs {
        controller: None,
        controllers: Some(vec![user_id]),
        compute_allocation: None,
        memory_allocation: None,
        freezing_threshold: None,
    });

    let canister = env
        .install_canister_with_cycles(
            binary.clone(),
            vec![],
            settings.clone(),
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let unrelated_canister = env
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
        env.send_ingress(user_id, IC_00, Method::InstallCode, args.encode())
    };

    for _ in 0..5 {
        // With checkpoints enabled, the update message will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    let status = {
        let arg = Encode!(&CanisterIdRecord::from(unrelated_canister)).unwrap();
        env.send_ingress(user_id, IC_00, Method::CanisterStatus, arg)
    };

    env.await_ingress(status, 30).unwrap();

    assert_eq!(
        ingress_state(env.ingress_status(&upgrade)),
        Some(IngressState::Processing)
    );

    env.set_checkpoints_enabled(false);

    env.await_ingress(upgrade, 30).unwrap();
}

#[test]
fn dts_ingress_status_of_update_is_correct() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let canister = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let original_time = env.time();
    let update = env.send_ingress(user_id, canister, "update", vec![]);

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&update)),
        Some(original_time)
    );

    env.advance_time(Duration::from_secs(60));

    env.tick();

    env.advance_time(Duration::from_secs(60));

    // Enable the checkpoints to abort the update message execution.
    env.set_checkpoints_enabled(true);

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&update)),
        Some(original_time)
    );

    env.set_checkpoints_enabled(false);

    // The ingress time must not change during DTS execution.
    while ingress_state(env.ingress_status(&update)) == Some(IngressState::Processing) {
        assert_eq!(
            ingress_time(env.ingress_status(&update)),
            Some(original_time)
        );
        env.tick();
    }

    env.await_ingress(update, 30).unwrap();
}

#[test]
fn dts_ingress_status_of_install_is_correct() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let canister = env
        .install_canister_with_cycles(binary.clone(), vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let original_time = env.time();

    let install = {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Reinstall,
            canister,
            binary,
            vec![],
            None,
            None,
            None,
        );
        env.send_ingress(user_id, IC_00, Method::InstallCode, args.encode())
    };

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&install)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&install)),
        Some(original_time)
    );

    env.advance_time(Duration::from_secs(60));

    env.tick();

    env.advance_time(Duration::from_secs(60));

    // Enable the checkpoints to abort the update message execution.
    env.set_checkpoints_enabled(true);

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&install)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&install)),
        Some(original_time)
    );

    env.set_checkpoints_enabled(false);

    // The ingress time must not change during DTS execution.
    while ingress_state(env.ingress_status(&install)) == Some(IngressState::Processing) {
        assert_eq!(
            ingress_time(env.ingress_status(&install)),
            Some(original_time)
        );
        env.tick();
    }

    env.await_ingress(install, 30).unwrap();
}

#[test]
fn dts_ingress_status_of_upgrade_is_correct() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let canister = env
        .install_canister_with_cycles(binary.clone(), vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let original_time = env.time();

    let install = {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Upgrade,
            canister,
            binary,
            vec![],
            None,
            None,
            None,
        );
        env.send_ingress(user_id, IC_00, Method::InstallCode, args.encode())
    };

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&install)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&install)),
        Some(original_time)
    );

    env.advance_time(Duration::from_secs(60));

    env.tick();

    env.advance_time(Duration::from_secs(60));

    // Enable the checkpoints to abort the update message execution.
    env.set_checkpoints_enabled(true);

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&install)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&install)),
        Some(original_time)
    );

    env.set_checkpoints_enabled(false);

    // The ingress time must not change during DTS execution.
    while ingress_state(env.ingress_status(&install)) == Some(IngressState::Processing) {
        assert_eq!(
            ingress_time(env.ingress_status(&install)),
            Some(original_time)
        );
        env.tick();
    }

    env.await_ingress(install, 30).unwrap();
}

#[test]
fn dts_ingress_status_of_update_with_call_is_correct() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let user_id = PrincipalId::new_anonymous();

    let a_id = env
        .install_canister_with_cycles(binary.clone(), vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let b_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let b = wasm()
        .stable64_grow(1)
        .stable64_fill(0, 0, 10_000)
        .stable64_fill(0, 0, 10_000)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .stable64_grow(1)
        .stable64_fill(0, 0, 10_000)
        .stable64_fill(0, 0, 10_000)
        .call_simple(b_id, "update", call_args().other_side(b))
        .build();

    let original_time = env.time();
    let update = env.send_ingress(user_id, a_id, "update", a);

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&update)),
        Some(original_time)
    );

    env.advance_time(Duration::from_secs(60));

    env.tick();

    env.advance_time(Duration::from_secs(60));

    // Enable the checkpoints to abort the update message execution.
    env.set_checkpoints_enabled(true);

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&update)),
        Some(original_time)
    );

    env.set_checkpoints_enabled(false);

    let mut call_time = None;

    // The ingress time must not change during DTS execution.
    while ingress_state(env.ingress_status(&update)) == Some(IngressState::Processing) {
        if ingress_time(env.ingress_status(&update)) != Some(original_time) {
            // The ingress time in the `Processing` state may change only once
            // when the call is made.
            if let Some(call_time) = call_time {
                assert_eq!(ingress_time(env.ingress_status(&update)), Some(call_time));
            }
            call_time = ingress_time(env.ingress_status(&update));
        }
        env.tick();
    }

    call_time.unwrap();

    env.await_ingress(update, 100).unwrap();
}

#[test]
fn dts_canister_uninstalled_due_to_resource_charges_with_aborted_updrade() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let settings = Some(CanisterSettingsArgs {
        controller: None,
        controllers: None,
        compute_allocation: Some(1u32.into()),
        memory_allocation: None,
        freezing_threshold: None,
    });

    let canister = env
        .install_canister_with_cycles(binary.clone(), vec![], settings, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // Make sure that the upgrade message gets aborted after each round.
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
        env.send_ingress(user_id, IC_00, Method::InstallCode, args.encode())
    };

    env.tick();

    // Advance the time so that the canister gets uninstalled due to the
    // resource usage.
    env.advance_time(Duration::from_secs(10_000_000));

    env.tick();

    // Enable normal message execution.
    env.set_checkpoints_enabled(false);

    let result = env.await_ingress(upgrade, 30).unwrap();

    // The canister is uninstalled after the execution completes because an
    // aborted install_code is always restarted and becomes a paused execution
    // by the time we charge canister for resource allocation.
    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));
}

#[test]
fn dts_canister_uninstalled_due_resource_charges_with_aborted_update() {
    if should_skip_test_due_to_disabled_dts() {
        // Skip this test if DTS is not supported.
        return;
    }

    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let n = 10;

    let mut canisters = vec![];
    for _ in 0..n {
        let settings = Some(CanisterSettingsArgs {
            controller: None,
            controllers: None,
            compute_allocation: Some(1u32.into()),
            memory_allocation: None,
            freezing_threshold: None,
        });

        let id = env
            .install_canister_with_cycles(binary.clone(), vec![], settings, INITIAL_CYCLES_BALANCE)
            .unwrap();
        canisters.push(id);
    }

    // Make sure that the update messages get aborted after each round.
    env.set_checkpoints_enabled(true);

    let mut updates = vec![];
    for canister in canisters.iter() {
        let update = env.send_ingress(user_id, *canister, "update", vec![]);
        updates.push(update);
    }

    // Ensure that each update message starts executing.
    for _ in 0..n {
        env.tick();
    }

    // Advance the time so that the canister gets uninstalled due to the
    // resource usage.
    env.advance_time(Duration::from_secs(10_000_000));

    env.tick();

    // Enable normal message execution.
    env.set_checkpoints_enabled(false);

    let mut errors = 0;

    // Canisters that were chosen for execution before charging for resources
    // become paused and don't get uninstalled until their execution completes.
    // All other canister are uninstalled before resuming their aborted
    // executions.
    for i in 0..n {
        match env.await_ingress(updates[i].clone(), 100) {
            Ok(result) => {
                assert_eq!(result, WasmResult::Reply(vec![]));
            }
            Err(err) => {
                assert_eq!(
                    err.description(),
                    format!(
                        "Attempt to execute a message on canister {} which contains no Wasm module",
                        canisters[i]
                    )
                );
                errors += 1;
            }
        }
    }
    assert!(errors >= 1);
}
