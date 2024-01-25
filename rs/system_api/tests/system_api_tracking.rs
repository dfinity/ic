use ic_interfaces::execution_environment::SystemApiCallCounters;
use ic_system_api::NonReplicatedQueryKind;
use ic_test_utilities::types::ids::subnet_test_id;
use ic_test_utilities::{types::ids::user_test_id, wasmtime_instance::WasmtimeInstanceBuilder};
use ic_test_utilities_time::mock_time;

fn call_counters_on_ok_call(wat: &str) -> SystemApiCallCounters {
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(wat)
        .with_api_type(ic_system_api::ApiType::non_replicated_query(
            mock_time(),
            user_test_id(0).get(),
            subnet_test_id(1),
            vec![0; 1024],
            None,
            NonReplicatedQueryKind::Stateful {
                call_context_id: 0.into(),
                outgoing_request: None,
            },
        ))
        .build();
    instance
        .run(ic_types::methods::FuncRef::Method(
            ic_types::methods::WasmMethod::CompositeQuery("call_system_api".into()),
        ))
        .unwrap();
    let system_api = &instance.store_data().system_api().unwrap();
    system_api.call_counters()
}

fn call_counters_on_err_call(wat: &str) -> SystemApiCallCounters {
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(wat)
        .with_api_type(ic_system_api::ApiType::start(mock_time()))
        .build();
    instance
        .run(ic_types::methods::FuncRef::Method(
            ic_types::methods::WasmMethod::CompositeQuery("call_system_api".into()),
        ))
        .unwrap_err();
    let system_api = &instance.store_data().system_api().unwrap();
    system_api.call_counters()
}

#[test]
fn track_call_perform() {
    let wat = r#"(module
            (import "ic0" "call_new"
                (func $ic0_call_new
                (param $callee_src i32)         (param $callee_size i32)
                (param $name_src i32)           (param $name_size i32)
                (param $reply_fun i32)          (param $reply_env i32)
                (param $reject_fun i32)         (param $reject_env i32)
            ))
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (memory 1)
            (func (export "canister_composite_query call_system_api")
                (call $ic0_call_new
                    (i32.const 0)   (i32.const 10)
                    (i32.const 100) (i32.const 18)
                    (i32.const 11)  (i32.const 0) ;; non-existent function
                    (i32.const 22)  (i32.const 0) ;; non-existent function
                )
                (drop (call $ic0_call_perform))
            )
        )"#;
    let call_counters = call_counters_on_ok_call(wat);
    assert_eq!(call_counters.call_perform, 1);
    let wat = r#"(module
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (memory 1)
            (func (export "canister_composite_query call_system_api")
                (drop (call $ic0_call_perform))
            )
        )"#;
    let call_counters = call_counters_on_err_call(wat);
    assert_eq!(call_counters.call_perform, 1);
}

#[test]
fn track_canister_cycle_balance() {
    let wat = r#"(module
            (import "ic0" "canister_cycle_balance"
                (func $ic0_canister_cycle_balance (result i64))
            )
            (memory 1)
            (func (export "canister_composite_query call_system_api")
                (drop (call $ic0_canister_cycle_balance))
            )
        )"#;
    let call_counters = call_counters_on_ok_call(wat);
    assert_eq!(call_counters.canister_cycle_balance, 1);
    let call_counters = call_counters_on_err_call(wat);
    assert_eq!(call_counters.canister_cycle_balance, 1);
}

#[test]
fn track_canister_cycle_balance128() {
    let wat = r#"(module
            (import "ic0" "canister_cycle_balance128"
                (func $ic0_canister_cycle_balance128 (param i32))
            )
            (memory 1)
            (func (export "canister_composite_query call_system_api")
                (call $ic0_canister_cycle_balance128 (i32.const 0))
            )
        )"#;
    let call_counters = call_counters_on_ok_call(wat);
    assert_eq!(call_counters.canister_cycle_balance128, 1);
    let call_counters = call_counters_on_err_call(wat);
    assert_eq!(call_counters.canister_cycle_balance128, 1);
}

#[test]
fn track_time() {
    let wat = r#"(module
                (import "ic0" "time" (func $ic0_time (result i64)))
                (memory 1)
                (func (export "canister_composite_query call_system_api")
                    (drop (call $ic0_time))
                )
            )"#;
    let call_counters = call_counters_on_ok_call(wat);
    assert_eq!(call_counters.time, 1);
    let call_counters = call_counters_on_err_call(wat);
    assert_eq!(call_counters.time, 1);
}

#[test]
fn track_other() {
    let wat = r#"(module
            (import "ic0" "msg_reply" (func $ic0_msg_reply))
            (memory 1)
            (func (export "canister_composite_query call_system_api")
                (call $ic0_msg_reply)
            )
        )"#;
    let call_counters = call_counters_on_ok_call(wat);
    assert_eq!(call_counters.call_perform, 0);
    assert_eq!(call_counters.canister_cycle_balance, 0);
    assert_eq!(call_counters.canister_cycle_balance128, 0);
    assert_eq!(call_counters.time, 0);
    let call_counters = call_counters_on_err_call(wat);
    assert_eq!(call_counters.call_perform, 0);
    assert_eq!(call_counters.canister_cycle_balance, 0);
    assert_eq!(call_counters.canister_cycle_balance128, 0);
    assert_eq!(call_counters.time, 0);
}
