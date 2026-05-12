use assert_matches::assert_matches;
use candid::Nat;
use ic_error_types::ErrorCode;
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterSettingsArgs, CanisterSettingsArgsBuilder, CreateCanisterArgs,
    DefiniteCanisterSettingsArgs, IC_00, Method, Payload, UpdateSettingsArgs,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_test_utilities::universal_canister::{CallArgs, UNIVERSAL_CANISTER_WASM, wasm};
use ic_test_utilities_execution_environment::get_reply;
use ic_types::CanisterId;
use ic_types::NumBytes;
use ic_types::ingress::WasmResult;
use ic_types_cycles::Cycles;

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
