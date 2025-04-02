use ic_interfaces::execution_environment::SystemApiCallCounters;
use ic_system_api::NonReplicatedQueryKind;
use ic_test_utilities_embedders::WasmtimeInstanceBuilder;
use ic_test_utilities_types::ids::{subnet_test_id, user_test_id};
use ic_types::time::UNIX_EPOCH;

fn call_counters_on_ok_call(wat: &str) -> SystemApiCallCounters {
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(wat)
        .with_api_type(ic_system_api::ApiType::non_replicated_query(
            UNIX_EPOCH,
            user_test_id(0).get(),
            subnet_test_id(1),
            vec![0; 1024],
            Some(vec![]),
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
        .with_api_type(ic_system_api::ApiType::start(UNIX_EPOCH))
        .build();
    instance
        .run(ic_types::methods::FuncRef::Method(
            ic_types::methods::WasmMethod::CompositeQuery("call_system_api".into()),
        ))
        .unwrap_err();
    let system_api = &instance.store_data().system_api().unwrap();
    system_api.call_counters()
}

// The test `track_data_certificate_copy` is covered by:
//
// * `query_cache_metrics_system_api_calls_work_on_composite_query`
// * `query_cache_metrics_system_api_calls_work_on_query_err`
//
// With the `WasmtimeInstanceBuilder`, the certificate is never present.
//
#[test]
fn track_data_certificate_copy() {
    let wat = r#"(module
            (import "ic0" "data_certificate_copy"
                (func $ic0_data_certificate_copy
                    (param $dst i32)
                    (param $offset i32)
                    (param $size i32)
                )
            )
            (memory 1)
            (func (export "canister_composite_query call_system_api")
                (call $ic0_data_certificate_copy (i32.const 0) (i32.const 0) (i32.const 0))
            )
        )"#;
    let call_counters = call_counters_on_ok_call(wat);
    assert_eq!(call_counters.data_certificate_copy, 1);
    let call_counters = call_counters_on_err_call(wat);
    assert_eq!(call_counters.data_certificate_copy, 1);
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
    assert_eq!(call_counters.canister_cycle_balance, 0);
    assert_eq!(call_counters.canister_cycle_balance128, 0);
    assert_eq!(call_counters.time, 0);
    let call_counters = call_counters_on_err_call(wat);
    assert_eq!(call_counters.canister_cycle_balance, 0);
    assert_eq!(call_counters.canister_cycle_balance128, 0);
    assert_eq!(call_counters.time, 0);
}
