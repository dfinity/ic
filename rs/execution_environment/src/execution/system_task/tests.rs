use crate::execution::system_task::CanisterSystemTaskError;
use crate::execution::test_utilities::{wat_compilation_cost, ExecutionTestBuilder};
use assert_matches::assert_matches;
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::execution_environment::{HypervisorError, TrapCode};
use ic_replicated_state::{page_map::PAGE_SIZE, CanisterStatus};
use ic_state_machine_tests::StateMachine;
use ic_state_machine_tests::WasmResult;
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::methods::SystemMethod;
use ic_types::NumBytes;
use ic_universal_canister::{wasm, UNIVERSAL_CANISTER_WASM};
use maplit::btreemap;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn heartbeat_is_executed() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_heartbeat") unreachable)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test
        .system_task(canister_id, SystemMethod::CanisterHeartbeat)
        .unwrap_err();
    assert_eq!(
        err,
        CanisterSystemTaskError::CanisterExecutionFailed(HypervisorError::Trapped(
            TrapCode::Unreachable
        ))
    );
}

#[test]
fn global_timer_is_executed() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_global_timer") unreachable)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test
        .system_task(canister_id, SystemMethod::CanisterGlobalTimer)
        .unwrap_err();
    assert_eq!(
        err,
        CanisterSystemTaskError::CanisterExecutionFailed(HypervisorError::Trapped(
            TrapCode::Unreachable
        ))
    );
}

#[test]
fn heartbeat_produces_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_heartbeat")
                (i32.store (i32.const 10) (i32.const 10))
            )
            (memory (export "memory") 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    test.system_task(canister_id, SystemMethod::CanisterHeartbeat)
        .unwrap();
    assert_eq!(
        NumBytes::from((PAGE_SIZE) as u64),
        test.state().metadata.heap_delta_estimate
    );
}

#[test]
fn global_timer_produces_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_global_timer")
                (i32.store (i32.const 10) (i32.const 10))
            )
            (memory (export "memory") 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    test.system_task(canister_id, SystemMethod::CanisterGlobalTimer)
        .unwrap();
    assert_eq!(
        NumBytes::from((PAGE_SIZE) as u64),
        test.state().metadata.heap_delta_estimate
    );
}

#[test]
fn heartbeat_fails_gracefully_if_not_exported() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = "(module)";
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.system_task(canister_id, SystemMethod::CanisterHeartbeat)
        .unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    assert_eq!(wat_compilation_cost(wat), test.executed_instructions());
}

#[test]
fn global_timer_fails_gracefully_if_not_exported() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = "(module)";
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.system_task(canister_id, SystemMethod::CanisterGlobalTimer)
        .unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    assert_eq!(wat_compilation_cost(wat), test.executed_instructions());
}

#[test]
fn heartbeat_doesnt_run_if_canister_is_stopped() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_heartbeat") unreachable)
            (memory (export "memory") 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.stop_canister(canister_id);
    test.process_stopping_canisters();
    assert_eq!(
        CanisterStatus::Stopped,
        test.canister_state(canister_id).system_state.status
    );
    let err = test
        .system_task(canister_id, SystemMethod::CanisterHeartbeat)
        .unwrap_err();
    assert_eq!(
        err,
        CanisterSystemTaskError::CanisterNotRunning {
            status: CanisterStatusType::Stopped,
        }
    );
}

#[test]
fn global_timer_doesnt_run_if_canister_is_stopped() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_global_timer") unreachable)
            (memory (export "memory") 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.stop_canister(canister_id);
    test.process_stopping_canisters();
    assert_eq!(
        CanisterStatus::Stopped,
        test.canister_state(canister_id).system_state.status
    );
    let err = test
        .system_task(canister_id, SystemMethod::CanisterGlobalTimer)
        .unwrap_err();
    assert_eq!(
        err,
        CanisterSystemTaskError::CanisterNotRunning {
            status: CanisterStatusType::Stopped,
        }
    );
}

#[test]
fn heartbeat_doesnt_run_if_canister_is_stopping() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_heartbeat") unreachable)
            (memory (export "memory") 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.stop_canister(canister_id);
    assert_matches!(
        test.canister_state(canister_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );
    let err = test
        .system_task(canister_id, SystemMethod::CanisterHeartbeat)
        .unwrap_err();
    assert_eq!(
        err,
        CanisterSystemTaskError::CanisterNotRunning {
            status: CanisterStatusType::Stopping,
        }
    );
}

#[test]
fn global_timer_doesnt_run_if_canister_is_stopping() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_global_timer") unreachable)
            (memory (export "memory") 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.stop_canister(canister_id);
    assert_matches!(
        test.canister_state(canister_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );
    let err = test
        .system_task(canister_id, SystemMethod::CanisterGlobalTimer)
        .unwrap_err();
    assert_eq!(
        err,
        CanisterSystemTaskError::CanisterNotRunning {
            status: CanisterStatusType::Stopping,
        }
    );
}

#[test]
fn global_timer_can_be_cancelled() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
        .unwrap();

    // Setup global timer to increase a global counter
    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let set_global_timer = wasm()
        .set_global_timer_method(wasm().inc_global_counter())
        .api_global_timer_set(now_nanos + 1)
        .get_global_counter()
        .reply_int64()
        .build();
    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));

    let get_global_counter = wasm().get_global_counter().reply_int64().build();

    // The counter is still zero as the timer has not yet reached the deadline
    let result = env
        .execute_ingress(canister_id, "update", get_global_counter.clone())
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));

    let cancel_global_counter = wasm().api_global_timer_set(0).reply_int64().build();

    // Cancel the timer
    let result = env
        .execute_ingress(canister_id, "update", cancel_global_counter)
        .unwrap();
    assert_eq!(
        result,
        WasmResult::Reply((now_nanos + 1).to_le_bytes().into())
    );

    // The timer should not be called
    env.advance_time(Duration::from_secs(1));
    let result = env
        .execute_ingress(canister_id, "update", get_global_counter)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));
}

#[test]
fn global_timer_can_be_immediately_cancelled() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
        .unwrap();

    // Setup global timer to increase a global counter
    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let set_global_timer = wasm()
        .set_global_timer_method(wasm().inc_global_counter())
        .api_global_timer_set(now_nanos + 1)
        .api_global_timer_set(0)
        .reply_int64()
        .build();
    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();
    assert_eq!(
        result,
        WasmResult::Reply((now_nanos + 1).to_le_bytes().into())
    );

    let get_global_counter = wasm().get_global_counter().reply_int64().build();

    // The counter must be zero as the timer should have been immediately cancelled
    let result = env
        .execute_ingress(canister_id, "update", get_global_counter)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));
}

#[test]
fn global_timer_is_one_off() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
        .unwrap();

    // Setup global timer to increase a global counter
    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let set_global_timer = wasm()
        .set_global_timer_method(wasm().inc_global_counter())
        .api_global_timer_set(now_nanos + 1)
        .get_global_counter()
        .reply_int64()
        .build();
    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));

    let get_global_counter = wasm().get_global_counter().reply_int64().build();

    // The counter is still zero as the timer has not yet reached the deadline
    let result = env
        .execute_ingress(canister_id, "update", get_global_counter.clone())
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));

    // The timer should reach the deadline now
    env.advance_time(Duration::from_secs(1));
    let result = env
        .execute_ingress(canister_id, "update", get_global_counter.clone())
        .unwrap();
    assert_eq!(result, WasmResult::Reply(1u64.to_le_bytes().into()));

    // The timer should be called just once
    env.advance_time(Duration::from_secs(1));
    let result = env
        .execute_ingress(canister_id, "update", get_global_counter)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(1u64.to_le_bytes().into()));
}

#[test]
fn global_timer_can_be_reactivated() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
        .unwrap();

    // Setup global timer to increase a global counter
    let set_global_timer = wasm()
        .set_global_timer_method(wasm().inc_global_counter())
        .api_global_timer_set(1)
        .get_global_counter()
        .reply_int64()
        .build();
    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));

    let get_global_counter = wasm().get_global_counter().reply_int64().build();

    // The timer should immediately reach the deadline
    let result = env
        .execute_ingress(canister_id, "update", get_global_counter.clone())
        .unwrap();
    assert_eq!(result, WasmResult::Reply(1u64.to_le_bytes().into()));

    // The timer should be called just once
    env.advance_time(Duration::from_secs(1));
    let result = env
        .execute_ingress(canister_id, "update", get_global_counter.clone())
        .unwrap();
    assert_eq!(result, WasmResult::Reply(1u64.to_le_bytes().into()));

    let set_global_timer = wasm()
        .api_global_timer_set(1)
        .get_global_counter()
        .reply_int64()
        .build();

    // Reactivate the timer
    env.advance_time(Duration::from_secs(1));
    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(1u64.to_le_bytes().into()));

    // The timer should be called again
    env.advance_time(Duration::from_secs(1));
    let result = env
        .execute_ingress(canister_id, "update", get_global_counter)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(2u64.to_le_bytes().into()));
}

#[test]
fn global_timer_can_be_reactivated_in_canister_global_timer_method() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
        .unwrap();

    // Setup global timer to increase a global counter
    let set_global_timer = wasm()
        .set_global_timer_method(wasm().inc_global_counter().api_global_timer_set(1))
        .api_global_timer_set(1)
        .get_global_counter()
        .reply_int64()
        .build();
    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));

    let get_global_counter = wasm().get_global_counter().reply_int64().build();

    for i in 1..5u64 {
        // Each execution should trigger the timer, increase the counter
        // and reactivate the timer again.
        let result = env
            .execute_ingress(canister_id, "update", get_global_counter.clone())
            .unwrap();
        assert_eq!(WasmResult::Reply(i.to_le_bytes().into()), result);
    }
}

#[test]
fn system_task_metrics_are_observable() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
        .unwrap();

    let set_global_timer = wasm()
        .set_global_timer_method(wasm().api_global_timer_set(1))
        .api_global_timer_set(1)
        .reply_int64()
        .build();
    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));

    // The timer should be triggered and reactivated each round.
    for _ in 0..5 {
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }
    let executed_messages =
        fetch_int_counter_vec(env.metrics_registry(), "hypervisor_executed_messages_total");

    let heartbeat_no_response = btreemap! {
        "api_type".into() => "heartbeat".into(),
        "status".into() => "NoResponse".into(),
    };
    // Includes install code, update and 5 ticks
    assert_eq!(7, executed_messages[&heartbeat_no_response]);

    let global_timer_no_response = btreemap! {
        "api_type".into() => "global timer".into(),
        "status".into() => "NoResponse".into(),
    };
    // Includes just 5 ticks, as the timer is activated after the update
    assert_eq!(5, executed_messages[&global_timer_no_response]);
}

#[test]
fn global_timer_is_not_set_if_execution_traps() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
        .unwrap();

    let set_global_timer = wasm()
        .set_global_timer_method(wasm().api_global_timer_set(1).trap())
        .api_global_timer_set(1)
        .reply_int64()
        .build();
    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));

    // The timer should trap and never reactivated again.
    for _ in 0..5 {
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }
    let executed_messages =
        fetch_int_counter_vec(env.metrics_registry(), "hypervisor_executed_messages_total");

    let global_timer_called_trap = btreemap! {
        "api_type".into() => "global timer".into(),
        "status".into() => "CalledTrap".into(),
    };
    assert_eq!(1, executed_messages[&global_timer_called_trap]);

    let heartbeat_no_response = btreemap! {
        "api_type".into() => "heartbeat".into(),
        "status".into() => "NoResponse".into(),
    };
    // Includes install code, update and 5 ticks
    assert_eq!(7, executed_messages[&heartbeat_no_response]);
}
