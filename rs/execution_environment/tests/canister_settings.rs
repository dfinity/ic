use assert_matches::assert_matches;
use candid::Nat;
use ic_error_types::ErrorCode;
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterSettingsArgs, CanisterSettingsArgsBuilder, CreateCanisterArgs,
    DefiniteCanisterSettingsArgs, IC_00, Method, Payload, UpdateSettingsArgs,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::NextExecution;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_test_utilities::universal_canister::{
    CallArgs, UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM, UNIVERSAL_CANISTER_WASM, wasm,
};
use ic_test_utilities_execution_environment::{
    ExecutionTestBuilder, check_ingress_status, get_reply,
};
use ic_types::CanisterId;
use ic_types::NumBytes;
use ic_types::ingress::WasmResult;
use ic_types_cycles::Cycles;

fn update_settings(env: &StateMachine, canister_id: CanisterId, settings: CanisterSettingsArgs) {
    let update_settings_args = UpdateSettingsArgs {
        canister_id: canister_id.get(),
        settings,
        sender_canister_version: None,
    };
    env.execute_ingress(IC_00, Method::UpdateSettings, update_settings_args.encode())
        .unwrap();
}

// The following test uses `StateMachine` instead of `ExecutionTest`
// because the compute capacity of the subnet is not initialized
// properly in `ExecutionTest`.
#[test]
fn canister_settings_ranges() {
    let via_update_settings = |settings: CanisterSettingsArgs| {
        let env = StateMachine::new();
        let canister_id = env.create_canister(None);
        let update_settings_args = UpdateSettingsArgs {
            canister_id: canister_id.get(),
            settings,
            sender_canister_version: None,
        };
        let settings_before = env
            .canister_status(canister_id)
            .unwrap()
            .unwrap()
            .settings();
        let res = env.execute_ingress(IC_00, Method::UpdateSettings, update_settings_args.encode());
        let settings_after = env
            .canister_status(canister_id)
            .unwrap()
            .unwrap()
            .settings();
        match res {
            Ok(_) => Ok(settings_after),
            Err(err) => {
                assert_eq!(settings_before, settings_after);
                Err(err)
            }
        }
    };
    let via_provisional_create_canister = |settings: CanisterSettingsArgs| {
        let env = StateMachine::new();
        let res = env.create_canister_with_cycles_impl(None, Cycles::zero(), Some(settings));
        match res {
            Ok(_) => {
                let bytes = get_reply(res);
                let canister_id = CanisterIdRecord::decode(&bytes).unwrap().get_canister_id();
                let settings_after = env
                    .canister_status(canister_id)
                    .unwrap()
                    .unwrap()
                    .settings();
                Ok(settings_after)
            }
            Err(err) => Err(err),
        }
    };
    let via_create_canister = |settings: CanisterSettingsArgs| {
        let env = StateMachine::new();
        let proxy_canister_id = env
            .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
            .unwrap();

        let create_canister_args = CreateCanisterArgs {
            settings: Some(settings),
            sender_canister_version: None,
        };
        let call_args = CallArgs::default()
            .other_side(create_canister_args.encode())
            .on_reject(wasm().reject_message().reject().build());
        let res = env.execute_ingress(
            proxy_canister_id,
            "update",
            wasm()
                .call_simple(IC_00, Method::CreateCanister, call_args)
                .build(),
        );
        match res {
            Ok(WasmResult::Reply(bytes)) => {
                let canister_id = CanisterIdRecord::decode(&bytes).unwrap().get_canister_id();
                let settings_after = env
                    .canister_status_as(proxy_canister_id.get(), canister_id)
                    .unwrap()
                    .unwrap()
                    .settings();
                Ok(settings_after)
            }
            Ok(WasmResult::Reject(msg)) => Err(msg),
            Err(err) => panic!("Unexpected error from proxy canister: {:?}", err),
        }
    };

    let valid_compute_allocation = 100;
    let valid_compute_allocation_settings = CanisterSettingsArgsBuilder::new()
        .with_compute_allocation(valid_compute_allocation)
        .build();
    let test_compute_allocation_settings: Box<dyn Fn(DefiniteCanisterSettingsArgs)> =
        Box::new(|settings: DefiniteCanisterSettingsArgs| {
            assert_eq!(settings.compute_allocation(), valid_compute_allocation);
        });

    let valid_memory_allocation = 1 << 20; // subnet would exceed its memory capacity if we used `u64::MAX` here
    let valid_memory_allocation_settings = CanisterSettingsArgsBuilder::new()
        .with_memory_allocation(valid_memory_allocation)
        .build();
    let test_memory_allocation_settings: Box<dyn Fn(DefiniteCanisterSettingsArgs)> =
        Box::new(|settings: DefiniteCanisterSettingsArgs| {
            assert_eq!(settings.memory_allocation(), valid_memory_allocation);
        });

    let valid_freezing_threshold = u64::MAX;
    let valid_freezing_threshold_settings = CanisterSettingsArgsBuilder::new()
        .with_freezing_threshold(valid_freezing_threshold)
        .build();
    let test_freezing_threshold_settings: Box<dyn Fn(DefiniteCanisterSettingsArgs)> =
        Box::new(|settings: DefiniteCanisterSettingsArgs| {
            assert_eq!(settings.freezing_threshold(), valid_freezing_threshold);
        });

    let valid_minimum_msg_cycles_available = u128::MAX;
    let valid_minimum_msg_cycles_available_settings = CanisterSettingsArgsBuilder::new()
        .with_minimum_msg_cycles_available(valid_minimum_msg_cycles_available)
        .build();
    let test_minimum_msg_cycles_available_settings: Box<dyn Fn(DefiniteCanisterSettingsArgs)> =
        Box::new(|settings: DefiniteCanisterSettingsArgs| {
            assert_eq!(
                settings.minimum_msg_cycles_available(),
                valid_minimum_msg_cycles_available
            );
        });

    for (valid_settings, test_settings_after) in [
        (
            valid_compute_allocation_settings,
            test_compute_allocation_settings,
        ),
        (
            valid_memory_allocation_settings,
            test_memory_allocation_settings,
        ),
        (
            valid_freezing_threshold_settings,
            test_freezing_threshold_settings,
        ),
        (
            valid_minimum_msg_cycles_available_settings,
            test_minimum_msg_cycles_available_settings,
        ),
    ] {
        let settings_after = via_update_settings(valid_settings.clone()).unwrap();
        test_settings_after(settings_after);
        let settings_after = via_provisional_create_canister(valid_settings.clone()).unwrap();
        test_settings_after(settings_after);
        let settings_after = via_create_canister(valid_settings.clone()).unwrap();
        test_settings_after(settings_after);
    }

    let invalid_compute_allocation = 101;
    let invalid_compute_allocation_settings = CanisterSettingsArgsBuilder::new()
        .with_compute_allocation(invalid_compute_allocation)
        .build();
    let expected_invalid_compute_allocation_err_code = ErrorCode::CanisterContractViolation;
    let expected_invalid_compute_allocation_err = format!(
        "ComputeAllocation expected to be in the range [0..100], got {}",
        Nat::from(invalid_compute_allocation)
    );

    let invalid_memory_allocation = 1 << 60; // subnet memory capacity is already exceeded at this value
    let invalid_memory_allocation_settings = CanisterSettingsArgsBuilder::new()
        .with_memory_allocation(invalid_memory_allocation)
        .build();
    let expected_invalid_memory_allocation_err_code = ErrorCode::SubnetOversubscribed;
    let expected_invalid_memory_allocation_err = format!(
        "Canister requested {} of memory",
        NumBytes::from(invalid_memory_allocation).display()
    );

    let invalid_freezing_threshold = 1 << 64;
    let invalid_freezing_threshold_settings = CanisterSettingsArgsBuilder::new()
        .with_freezing_threshold_u128(invalid_freezing_threshold)
        .build();
    let expected_invalid_freezing_threshold_err_code = ErrorCode::CanisterContractViolation;
    let expected_invalid_freezing_threshold_err = format!(
        "Freezing threshold expected to be in the range of [0..2^64-1], got {}",
        Nat::from(invalid_freezing_threshold)
    );

    let invalid_minimum_msg_cycles_available = Nat::from(u128::MAX) + Nat::from(1_u8);
    let invalid_minimum_msg_cycles_available_settings = {
        let mut s = CanisterSettingsArgsBuilder::new().build();
        s.minimum_msg_cycles_available = Some(invalid_minimum_msg_cycles_available.clone());
        s
    };
    let expected_invalid_minimum_msg_cycles_available_err_code =
        ErrorCode::CanisterContractViolation;
    let expected_invalid_minimum_msg_cycles_available_err = format!(
        "Minimum message cycles available expected to be in the range of [0..2^128-1], got {}",
        invalid_minimum_msg_cycles_available
    );

    for (invalid_settings, expected_err_code, expected_err) in [
        (
            invalid_compute_allocation_settings,
            expected_invalid_compute_allocation_err_code,
            expected_invalid_compute_allocation_err,
        ),
        (
            invalid_memory_allocation_settings,
            expected_invalid_memory_allocation_err_code,
            expected_invalid_memory_allocation_err,
        ),
        (
            invalid_freezing_threshold_settings,
            expected_invalid_freezing_threshold_err_code,
            expected_invalid_freezing_threshold_err,
        ),
        (
            invalid_minimum_msg_cycles_available_settings,
            expected_invalid_minimum_msg_cycles_available_err_code,
            expected_invalid_minimum_msg_cycles_available_err,
        ),
    ] {
        let err = via_update_settings(invalid_settings.clone()).unwrap_err();
        assert_eq!(err.code(), expected_err_code);
        assert!(err.description().contains(&expected_err));
        let err = via_provisional_create_canister(invalid_settings.clone()).unwrap_err();
        assert_eq!(err.code(), expected_err_code);
        assert!(err.description().contains(&expected_err));
        let err = via_create_canister(invalid_settings.clone()).unwrap_err();
        assert!(err.contains(&expected_err));
    }
}

#[test]
fn failed_create_canister_does_not_reuse_canister_id() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    // Proxy universal canister gets ID 0.
    let proxy_canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            Cycles::new(100_000_000_000_000),
        )
        .unwrap();

    // On an application subnet, a freezing threshold of 2^60 seconds combined
    // with a 1 MiB memory allocation requires an astronomically large cycle
    // balance, causing the create_canister call to fail.
    let failing_args = CreateCanisterArgs {
        settings: Some(
            CanisterSettingsArgsBuilder::new()
                .with_freezing_threshold(1_u64 << 60)
                .with_memory_allocation(1 << 20)
                .build(),
        ),
        sender_canister_version: None,
    };
    // Send enough cycles to pass the creation fee check so the calls reach
    // the freezing threshold validation (where they are actually rejected).
    let cycles_with_call: u64 = 1_000_000_000_000;

    // Each call is rejected during validation, so no canister ID is consumed.
    for _ in 0..3 {
        let call_args = CallArgs::default()
            .other_side(failing_args.encode())
            .on_reject(wasm().reject_message().reject().build());
        let res = env
            .execute_ingress(
                proxy_canister_id,
                "update",
                wasm()
                    .call_with_cycles(IC_00, Method::CreateCanister, call_args, cycles_with_call)
                    .build(),
            )
            .unwrap();
        assert_matches!(res, WasmResult::Reject(_));
    }

    // Because the failures above consumed no IDs, the next successful call
    // still gets ID 1 (one after the proxy at ID 0).
    let success_args = CreateCanisterArgs {
        settings: None,
        sender_canister_version: None,
    };
    let call_args = CallArgs::default()
        .other_side(success_args.encode())
        .on_reject(wasm().reject_message().reject().build());
    let res = env
        .execute_ingress(
            proxy_canister_id,
            "update",
            wasm()
                .call_with_cycles(IC_00, Method::CreateCanister, call_args, cycles_with_call)
                .build(),
        )
        .unwrap();
    let canister_id = match res {
        WasmResult::Reply(bytes) => CanisterIdRecord::decode(&bytes).unwrap().get_canister_id(),
        WasmResult::Reject(msg) => panic!("Unexpected reject: {}", msg),
    };
    assert_eq!(canister_id, CanisterId::from_u64(1));
}

#[test]
fn minimum_msg_cycles_available_in_canister_status() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    // Default value is 0 when no setting is provided.
    let canister_id = env.create_canister_with_cycles(None, Cycles::new(100_000_000_000_000), None);
    let settings = env
        .canister_status(canister_id)
        .unwrap()
        .unwrap()
        .settings();
    assert_eq!(settings.minimum_msg_cycles_available(), 0_u128);

    // create_canister with the setting applied.
    let min_cycles: u128 = 1_000_000;
    let bytes = get_reply(
        env.create_canister_with_cycles_impl(
            None,
            Cycles::new(100_000_000_000_000),
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_minimum_msg_cycles_available(min_cycles)
                    .build(),
            ),
        ),
    );
    let created_canister_id = CanisterIdRecord::decode(&bytes).unwrap().get_canister_id();
    let settings = env
        .canister_status(created_canister_id)
        .unwrap()
        .unwrap()
        .settings();
    assert_eq!(settings.minimum_msg_cycles_available(), min_cycles);

    // update_settings changes the value.
    let new_min_cycles: u128 = 2_000_000;
    update_settings(
        &env,
        canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_minimum_msg_cycles_available(new_min_cycles)
            .build(),
    );
    let settings = env
        .canister_status(canister_id)
        .unwrap()
        .unwrap()
        .settings();
    assert_eq!(settings.minimum_msg_cycles_available(), new_min_cycles);
}

fn setup_two_canisters(min_cycles: u128) -> (StateMachine, CanisterId, CanisterId) {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    // Use no-heartbeat WASM for the callee so that heartbeat charges don't
    // interfere with cycle-balance assertions in tests.
    let callee_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            vec![],
            None,
            Cycles::new(100_000_000_000_000),
        )
        .unwrap();
    let caller_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            Cycles::new(100_000_000_000_000),
        )
        .unwrap();
    update_settings(
        &env,
        callee_id,
        CanisterSettingsArgsBuilder::new()
            .with_minimum_msg_cycles_available(min_cycles)
            .build(),
    );
    (env, callee_id, caller_id)
}

// Ingress messages must be accepted regardless of minimum_msg_cycles_available.
#[test]
fn minimum_msg_cycles_available_does_not_affect_ingress() {
    let (env, callee_id, _caller_id) = setup_two_canisters(1_000_000);

    let res = env
        .execute_ingress(callee_id, "update", wasm().reply_data(b"ok").build())
        .unwrap();
    assert_matches!(res, WasmResult::Reply(_));
}

// Inter-canister calls with at least minimum_msg_cycles_available cycles must succeed.
#[test]
fn inter_canister_call_accepted_when_cycles_sufficient() {
    let min_cycles: u128 = 1_000_000;
    let (env, callee_id, caller_id) = setup_two_canisters(min_cycles);

    let call_args = CallArgs::default()
        .other_side(wasm().reply_data(b"ok").build())
        .on_reply(wasm().reply_data(b"got reply").build())
        .on_reject(wasm().reject_message().reject().build());
    let res = env
        .execute_ingress(
            caller_id,
            "update",
            wasm()
                .call_with_cycles(callee_id, "update", call_args, min_cycles as u64)
                .build(),
        )
        .unwrap();
    assert_matches!(res, WasmResult::Reply(_));
}

// Verifies that attached cycles can be partially consumed before a downstream call
// and the rest consumed in the reply callback, even though the remaining amount is
// below minimum_msg_cycles_available (which only gates incoming call admission).
// DTS is triggered after each accept_cycles (via instruction_counter_is_at_least)
// to ensure that minimum_msg_cycles_available is not re-enforced at slice boundaries.
#[test]
fn attached_cycles_consumed_in_update_and_reply_below_minimum_msg_cycles_available() {
    const SLICE_INSTRUCTIONS: u64 = 1_000_000;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(SLICE_INSTRUCTIONS)
        .with_manual_execution()
        .build();

    let min_cycles: u128 = 1_000_000_000_000;
    let half_cycles: u128 = min_cycles / 2;

    let callee_id = test
        .universal_canister_with_cycles(Cycles::new(100_000_000_000_000_000))
        .unwrap();
    let caller_id = test
        .universal_canister_with_cycles(Cycles::new(100_000_000_000_000_000))
        .unwrap();
    test.update_settings(
        callee_id,
        CanisterSettingsArgsBuilder::new()
            .with_minimum_msg_cycles_available(min_cycles)
            .build(),
    )
    .unwrap();
    let initial_callee_balance = test.canister_state(callee_id).system_state.balance();

    // Callee accepts half_cycles in the update handler, then makes a downstream
    // call to caller_id. In the reply callback, the callee accepts the remaining
    // min_cycles - half_cycles, which is below minimum_msg_cycles_available —
    // reply callbacks are not subject to the minimum check.
    // instruction_counter_is_at_least after each accept_cycles forces a DTS slice
    // boundary to verify minimum_msg_cycles_available is not re-enforced on resume.
    let callee_args = wasm()
        .accept_cycles(half_cycles)
        .instruction_counter_is_at_least(SLICE_INSTRUCTIONS)
        .call_simple(
            caller_id,
            "update",
            CallArgs::default()
                .other_side(wasm().reply_data(b"ok").build())
                .on_reply(
                    wasm()
                        .accept_cycles(min_cycles - half_cycles)
                        .instruction_counter_is_at_least(SLICE_INSTRUCTIONS)
                        .reply_data(b"done")
                        .build(),
                )
                .on_reject(wasm().reject_message().reject().build()),
        )
        .build();
    let call_args = CallArgs::default()
        .other_side(callee_args)
        .on_reply(wasm().message_payload().append_and_reply().build())
        .on_reject(wasm().reject_message().reject().build());

    let (ingress_id, _) = test.ingress_raw(
        caller_id,
        "update",
        wasm()
            .call_with_cycles(callee_id, "update", call_args, min_cycles)
            .build(),
    );

    // Execute caller: sends call to callee with min_cycles attached.
    test.execute_message(caller_id);
    test.induct_messages();

    // Execute callee update slice 1: accepts half_cycles, then
    // instruction_counter_is_at_least exhausts the slice → DTS pause.
    test.execute_slice(callee_id);
    assert_eq!(
        test.canister_state(callee_id).next_execution(),
        NextExecution::ContinueLong,
    );

    // Execute callee update slice 2: loop exits, sends downstream call to caller.
    test.execute_slice(callee_id);
    test.induct_messages();

    // Execute caller: replies "ok" to callee.
    test.execute_message(caller_id);
    test.induct_messages();

    // Execute callee reply callback slice 1: accepts remaining half_cycles, then
    // instruction_counter_is_at_least exhausts the slice → DTS pause.
    test.execute_slice(callee_id);
    assert_eq!(
        test.canister_state(callee_id).next_execution(),
        NextExecution::ContinueLong,
    );

    // Execute callee reply callback slice 2: loop exits, replies "done".
    test.execute_slice(callee_id);
    test.induct_messages();

    // Execute caller: forwards "done" to the ingress.
    test.execute_message(caller_id);

    assert_eq!(
        get_reply(check_ingress_status(test.ingress_status(&ingress_id))),
        b"done"
    );
    // Fees (call/reply transmission) are small relative to min_cycles; assert
    // the callee gained at least 99% of the transferred cycles.
    let expected = (initial_callee_balance + Cycles::new(min_cycles)).get();
    let actual = test.canister_state(callee_id).system_state.balance().get();
    assert!(
        actual <= expected && expected.saturating_sub(actual) <= expected / 100,
        "cycle balance mismatch: got {actual}, expected ~{expected}"
    );
}

// Inter-canister calls with fewer than minimum_msg_cycles_available cycles must be
// rejected with CanisterError.
#[test]
fn inter_canister_call_rejected_when_cycles_insufficient() {
    let min_cycles: u128 = 1_000_000;
    let (env, callee_id, caller_id) = setup_two_canisters(min_cycles);

    let callee_balance_before = env.cycle_balance(callee_id);

    let call_args = CallArgs::default()
        .other_side(wasm().reply_data(b"ok").build())
        .on_reply(wasm().reply_data(b"got reply").build())
        .on_reject(wasm().reject_message().reject().build());
    let res = env
        .execute_ingress(
            caller_id,
            "update",
            wasm()
                .call_with_cycles(callee_id, "update", call_args, (min_cycles - 1) as u64)
                .build(),
        )
        .unwrap();
    let reject_msg = match res {
        WasmResult::Reject(msg) => msg,
        other => panic!("Expected reject, got {:?}", other),
    };
    assert!(
        reject_msg.contains("requires at least"),
        "Unexpected reject message: {reject_msg}"
    );
    assert_eq!(env.cycle_balance(callee_id), callee_balance_before);
}
