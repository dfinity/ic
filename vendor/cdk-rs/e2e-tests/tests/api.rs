use candid::Principal;
use ic_cdk::management_canister::{CanisterSettings, EnvironmentVariable, UpdateSettingsArgs};
use pocket_ic::ErrorCode;

mod test_utilities;
use test_utilities::{cargo_build_canister, pic_base, update};

#[test]
fn call_api() {
    let wasm = cargo_build_canister("api");
    // with_ii_subnet is required for testing the ic0.cost_sign_with_* API with pre-defined key name.
    let pic = pic_base().with_ii_subnet().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);
    let sender = Principal::anonymous();
    let res = pic
        .update_call(canister_id, sender, "call_msg_arg_data", vec![42])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_msg_caller", vec![])
        .unwrap();
    assert!(res.is_empty());
    // Unlike the other entry points, `call_msg_dealine_caller` was implemented with the `#[update]` macro.
    // So we use the update method which assumes candid
    let _: () = update(&pic, canister_id, "call_msg_deadline_caller", ()).unwrap();
    // `msg_reject_code` and `msg_reject_msg` can't be tested here.
    // They are invoked in the reply/reject callback of inter-canister calls.
    // So the `call.rs` test covers them.
    let res = pic
        .update_call(canister_id, sender, "call_msg_reply", vec![])
        .unwrap();
    assert_eq!(res, vec![42]);
    let res = pic
        .update_call(canister_id, sender, "call_msg_reject", vec![])
        .unwrap_err();
    assert_eq!(res.reject_message, "e2e test reject");
    let res = pic
        .update_call(canister_id, sender, "call_msg_cycles_available", vec![])
        .unwrap();
    assert!(res.is_empty());
    // `msg_cycles_refunded` can't be tested here.
    // It can only be called in the reply/reject callback of inter-canister calls.
    // TODO: Find a way to test it.
    let res = pic
        .update_call(canister_id, sender, "call_msg_cycles_accept", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_cycles_burn", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(
            canister_id,
            sender,
            "call_canister_self",
            canister_id.as_slice().to_vec(),
        )
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_canister_cycle_balance", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(
            canister_id,
            sender,
            "call_canister_liquid_cycle_balance",
            vec![],
        )
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_canister_status", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_canister_version", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_subnet_self", vec![])
        .unwrap();
    assert!(res.is_empty());
    // `msg_method_name` and `accept_message` are invoked in the inspect_message entry point.
    // Every calls above/below execute the inspect_message entry point.
    // So these two API bindings are tested implicitly.
    let res = pic
        .update_call(canister_id, sender, "call_stable", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_root_key", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_certified_data_set", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .query_call(canister_id, sender, "call_data_certificate", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_time", vec![])
        .unwrap();
    assert!(res.is_empty());
    // `global_timer_set` is tested in `timers.rs`.
    let res = pic
        .update_call(canister_id, sender, "call_performance_counter", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_is_controller", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_in_replicated_execution", vec![])
        .unwrap();
    assert_eq!(res, vec![1]);
    let res = pic
        .query_call(canister_id, sender, "call_in_replicated_execution", vec![])
        .unwrap();
    assert_eq!(res, vec![0]);
    let res = pic
        .update_call(canister_id, sender, "call_cost_call", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_cost_create_canister", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_cost_http_request", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_cost_sign_with_ecdsa", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_cost_sign_with_schnorr", vec![])
        .unwrap();
    assert!(res.is_empty());

    // env var
    let update_settings_arg = UpdateSettingsArgs {
        canister_id,
        settings: CanisterSettings {
            environment_variables: Some(vec![
                EnvironmentVariable {
                    name: "key1".to_string(),
                    value: "value1".to_string(),
                },
                EnvironmentVariable {
                    name: "key2".to_string(),
                    value: "value2".to_string(),
                },
            ]),
            ..Default::default()
        },
    };
    let _: () = update(
        &pic,
        Principal::management_canister(),
        "update_settings",
        (update_settings_arg,),
    )
    .unwrap();
    let res = pic
        .update_call(canister_id, sender, "call_env_var_count", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_env_var_name", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_env_var_name_exists", vec![])
        .unwrap();
    assert!(res.is_empty());
    let res = pic
        .update_call(canister_id, sender, "call_env_var_value", vec![])
        .unwrap();
    assert!(res.is_empty());

    let res = pic
        .update_call(canister_id, sender, "call_debug_print", vec![])
        .unwrap();
    assert!(res.is_empty());
    let rej = pic
        .update_call(canister_id, sender, "call_trap", vec![])
        .unwrap_err();
    assert_eq!(rej.error_code, ErrorCode::CanisterCalledTrap);
    assert!(rej.reject_message.contains("It's a trap!"));
}
