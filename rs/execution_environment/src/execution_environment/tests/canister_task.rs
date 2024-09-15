use assert_matches::assert_matches;
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_error_types::RejectCode;
use ic_management_canister_types::{CanisterSettingsArgsBuilder, CanisterStatusType};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::page_map::PAGE_SIZE;
use ic_replicated_state::NumWasmPages;
use ic_state_machine_tests::{Cycles, StateMachine};
use ic_state_machine_tests::{StateMachineBuilder, StateMachineConfig, WasmResult};
use ic_test_utilities_execution_environment::{wat_compilation_cost, ExecutionTestBuilder};
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::messages::CanisterTask;
use ic_types::{CanisterId, NumBytes};
use ic_universal_canister::{wasm, UNIVERSAL_CANISTER_WASM};
use maplit::btreemap;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn heartbeat_is_executed() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"(module
            (func (export "canister_heartbeat")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.canister_task(canister_id, CanisterTask::Heartbeat);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(11)
    );
}

#[test]
fn global_timer_is_executed() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"(module
            (func (export "canister_global_timer")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.canister_task(canister_id, CanisterTask::GlobalTimer);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(11)
    );
}

#[test]
fn ic0_global_timer_set_is_supported_in_pre_upgrade() {
    let env = StateMachine::new();
    let wat = r#"
        (module
            (import "ic0" "global_timer_set"
                (func $global_timer_set (param i64) (result i64))
            )
            (func (export "canister_pre_upgrade")
                (drop (call $global_timer_set (i64.const 1)))
            )
        )"#;
    let canister_id = env.install_canister_wat(wat, vec![], None);

    let empty_binary = wat::parse_str("(module)").unwrap();
    let result = env.upgrade_canister(canister_id, empty_binary, vec![]);
    assert_eq!(result, Ok(()));
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
    test.canister_task(canister_id, CanisterTask::Heartbeat);
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
    test.canister_task(canister_id, CanisterTask::GlobalTimer);
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
    test.canister_task(canister_id, CanisterTask::Heartbeat);
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    assert_eq!(wat_compilation_cost(wat), test.executed_instructions());
}

#[test]
fn global_timer_fails_gracefully_if_not_exported() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = "(module)";
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.canister_task(canister_id, CanisterTask::GlobalTimer);
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    assert_eq!(wat_compilation_cost(wat), test.executed_instructions());
}

#[test]
fn heartbeat_doesnt_run_if_canister_is_stopped() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"(module
            (func (export "canister_heartbeat")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.stop_canister(canister_id);
    test.process_stopping_canisters();
    assert_eq!(
        CanisterStatusType::Stopped,
        test.canister_state(canister_id).system_state.status()
    );
    test.canister_task(canister_id, CanisterTask::Heartbeat);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );
}

#[test]
fn global_timer_doesnt_run_if_canister_is_stopped() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"(module
            (func (export "canister_global_timer")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.stop_canister(canister_id);
    test.process_stopping_canisters();
    assert_eq!(
        CanisterStatusType::Stopped,
        test.canister_state(canister_id).system_state.status()
    );
    test.canister_task(canister_id, CanisterTask::GlobalTimer);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );
}

#[test]
fn heartbeat_doesnt_run_if_canister_is_stopping() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"(module
            (func (export "canister_heartbeat")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.stop_canister(canister_id);
    assert_eq!(
        CanisterStatusType::Stopping,
        test.canister_state(canister_id).system_state.status()
    );
    test.canister_task(canister_id, CanisterTask::Heartbeat);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );
}

#[test]
fn global_timer_doesnt_run_if_canister_is_stopping() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"(module
            (func (export "canister_global_timer")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.stop_canister(canister_id);
    assert_eq!(
        CanisterStatusType::Stopping,
        test.canister_state(canister_id).system_state.status()
    );
    test.canister_task(canister_id, CanisterTask::GlobalTimer);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );
}

#[test]
fn global_timer_can_be_cancelled() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
        .unwrap();

    // Setup global timer to increase a global counter
    let now_nanos = env
        .time_of_next_round()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let set_global_timer = wasm()
        .set_global_timer_method(wasm().inc_global_counter())
        .api_global_timer_set(now_nanos + 3) // set the deadline in three rounds from now
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

    let cancel_global_timer = wasm().api_global_timer_set(0).reply_int64().build();

    // Cancel the timer
    let result = env
        .execute_ingress(canister_id, "update", cancel_global_timer)
        .unwrap();
    assert_eq!(
        result,
        WasmResult::Reply((now_nanos + 3).to_le_bytes().into())
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
    let now_nanos = env
        .time_of_next_round()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let set_global_timer = wasm()
        .set_global_timer_method(wasm().inc_global_counter())
        .api_global_timer_set(now_nanos + 2) // set the deadline in two rounds from now
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
    env.tick();
    let result = env
        .execute_ingress(canister_id, "update", get_global_counter.clone())
        .unwrap();
    assert_eq!(result, WasmResult::Reply(1u64.to_le_bytes().into()));

    // The timer should be called just once
    env.advance_time(Duration::from_secs(1));
    env.tick();
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

    for i in 1..20u64 {
        // In every third execution, NextScheduledMethod is Message, hence in such
        // executions only the message will be executed.
        // While in the other executions, NextScheduledMethod is either GlobalTimer
        // or Heartbeat hence timer, heartbeat, and messages are all executed.
        let result = env
            .execute_ingress(canister_id, "update", get_global_counter.clone())
            .unwrap();
        let expected_global_counter = i - i / 3;
        assert_eq!(
            WasmResult::Reply(expected_global_counter.to_le_bytes().into()),
            result
        );
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

    // Execute heartbeat.
    env.tick();

    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));

    // The timer should be triggered and reactivated each round.
    for _ in 0..5 {
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }
    let executed_messages = fetch_int_counter_vec(
        env.metrics_registry(),
        "sandboxed_execution_executed_message_slices_total",
    );

    let heartbeat_no_response = btreemap! {
        "api_type".into() => "heartbeat".into(),
        "status".into() => "NoResponse".into(),
    };
    // Includes install code, tick prior the update and 5 ticks
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

    env.tick();

    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));

    // The timer should trap and never reactivated again.
    for _ in 0..5 {
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }
    let executed_messages = fetch_int_counter_vec(
        env.metrics_registry(),
        "sandboxed_execution_executed_message_slices_total",
    );

    let global_timer_called_trap = btreemap! {
        "api_type".into() => "global timer".into(),
        "status".into() => "CalledTrap".into(),
    };
    assert_eq!(1, executed_messages[&global_timer_called_trap]);

    let heartbeat_no_response = btreemap! {
        "api_type".into() => "heartbeat".into(),
        "status".into() => "NoResponse".into(),
    };
    // Includes install code, tick prior the update and 5 ticks
    assert_eq!(7, executed_messages[&heartbeat_no_response]);
}

#[test]
fn global_timer_refunds_cycles_for_request_in_prep() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let binary = wat::parse_str(
        r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                (param $callee_src i32)         (param $callee_size i32)
                (param $name_src i32)           (param $name_size i32)
                (param $reply_fun i32)          (param $reply_env i32)
                (param $reject_fun i32)         (param $reject_env i32)
            ))
            (import "ic0" "call_cycles_add"
                (func $ic0_call_cycles_add (param $amount i64))
            )
            (import "ic0" "global_timer_set"
                (func $global_timer_set (param i64) (result i64))
            )
            (import "ic0" "msg_reply" (func $ic0_msg_reply))
            (memory 1)

            (func (export "canister_global_timer")
                (drop (call $global_timer_set (i64.const 1)))
                (call $ic0_call_new
                    (i32.const 0)   (i32.const 10)
                    (i32.const 100) (i32.const 18)
                    (i32.const 11)  (i32.const 0) ;; non-existent function
                    (i32.const 22)  (i32.const 0) ;; non-existent function
                )
                ;; Add a lot of cycles...
                (call $ic0_call_cycles_add (i64.const 10000000000))
                ;; ...but never perform the call
            )
            (func (export "canister_update test")
                (drop (call $global_timer_set (i64.const 1)))
                (call $ic0_msg_reply)
            )
        )"#,
    )
    .unwrap();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, Cycles::new(100_000_000_000))
        .unwrap();

    let result = env.execute_ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
    env.tick();

    // There should be a consistent cycles difference across rounds.
    let initial_cycle_balance = env.cycle_balance(canister_id);
    env.tick();
    let mut cycle_balance = env.cycle_balance(canister_id);
    let cycle_balance_diff = initial_cycle_balance - cycle_balance;
    // The timer should run every tick(), so the instructions diff should be non-zero.
    assert_ne!(0, cycle_balance_diff);
    // As we don't perform the call, the cycles balance should decrease very slowly,
    // and we should be able to perform 100 rounds.
    for _ in 0..10 {
        let initial_cycle_balance = cycle_balance;
        env.tick();
        cycle_balance = env.cycle_balance(canister_id);
        assert_eq!(initial_cycle_balance - cycle_balance, cycle_balance_diff);
    }
}

#[test]
fn global_timer_set_returns_zero_in_canister_global_timer_method() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let binary = wat::parse_str(
        r#"
        (module
            (import "ic0" "global_timer_set"
                (func $ic0_global_timer_set (param i64) (result i64))
            )
            (import "ic0" "msg_reply" (func $ic0_msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $ic0_msg_reply_data_append (param i32 i32)))
            (memory 1)

            (func (export "canister_global_timer")
                ;; Overwrite the value in the timer handler
                (i64.store
                    (i32.const 0)
                    ;; The ic0_global_timer_set should return 0, not 1 here
                    (call $ic0_global_timer_set (i64.const 1))
                )
            )
            (func (export "canister_update global_timer_set")
                ;; Store some value at memory offset 0
                (i64.store (i32.const 0) (i64.const 0xDEADBEAFDEADBEAF))
                (drop (call $ic0_global_timer_set (i64.const 1)))
                (call $ic0_msg_reply)
            )
            (func (export "canister_query read_value")
                ;; Read 8-byte value at offset 0
                (call $ic0_msg_reply_data_append (i32.const 0) (i32.const 8))
                (call $ic0_msg_reply)
            )
        )"#,
    )
    .unwrap();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, Cycles::new(100_000_000_000))
        .unwrap();

    let result = env
        .execute_ingress(canister_id, "global_timer_set", vec![])
        .unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));

    // At the beginning there should be a 0xDEADBEAF
    let result = env.query(canister_id, "read_value", vec![]).unwrap();
    assert_eq!(
        result,
        WasmResult::Reply(0xDEADBEAFDEADBEAF_u64.to_le_bytes().into())
    );

    // The timer should be triggered.
    env.advance_time(Duration::from_secs(1));
    env.tick();

    // Now there should be zero, as the timer value is reset before executing the timer handler
    let result = env.query(canister_id, "read_value", vec![]).unwrap();
    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().into()));
}

#[test]
fn global_timer_runs_if_set_in_stopped_canister_post_upgrade() {
    let env = StateMachine::new();
    let canister_id = env.install_canister_wat("(module)", vec![], None);

    // Stop the canister.
    let result = env.stop_canister(canister_id);
    assert_matches!(result, Ok(_));

    // Upgrade the canister.
    let set_global_timer_in_post_upgrade = wasm()
        .set_global_timer_method(wasm().inc_global_counter().api_global_timer_set(1))
        .api_global_timer_set(1)
        .build();
    let result = env.upgrade_canister(
        canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        set_global_timer_in_post_upgrade,
    );
    assert_eq!(result, Ok(()));

    // The timer should not be triggered as the canister is stopped.
    env.advance_time(Duration::from_secs(1));
    env.tick();

    // Any update calls should fail as the canister is stopped.
    let result = env.execute_ingress(canister_id, "update", vec![]);
    assert_matches!(result, Err(_));

    // Start the canister.
    let result = env.start_canister(canister_id);
    assert_matches!(result, Ok(_));

    // The timer should be triggered and reactivated each round.
    for _ in 1..5 {
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }

    // Assert the global timer is running.
    let get_global_counter = wasm().get_global_counter().reply_int64().build();
    let result = env.query(canister_id, "query", get_global_counter).unwrap();
    assert_eq!(result, WasmResult::Reply(5_u64.to_le_bytes().into()));
}

fn global_timer_resumes<F, G>(stop: F, start: G)
where
    F: FnOnce(&StateMachine, CanisterId),
    G: FnOnce(&StateMachine, CanisterId),
{
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config.clone(),
        HypervisorConfig::default(),
    ));

    // Install a canister with a periodic timer.
    let set_global_timer_in_canister_init = wasm()
        .set_global_timer_method(wasm().inc_global_counter().api_global_timer_set(1))
        .api_global_timer_set(1)
        .build();
    let canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            set_global_timer_in_canister_init,
            None,
            Cycles::new(1_000_000_000_000),
        )
        .unwrap();

    // The timer should be triggered and reactivated each round.
    for _ in 1..5 {
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }

    let get_global_counter = wasm().get_global_counter().reply_int64().build();
    // Assert the global timer is running.
    let result = env
        .query(canister_id, "query", get_global_counter.clone())
        .unwrap();
    assert_eq!(result, WasmResult::Reply(5_u64.to_le_bytes().into()));

    // Stop the canister.
    stop(&env, canister_id);

    // The timer should not be triggered as the canister is stopped.
    for _ in 0..20 {
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }

    // Start the canister.
    start(&env, canister_id);

    // Assert the global timer was not running.
    let result = env
        .query(canister_id, "query", get_global_counter.clone())
        .unwrap();
    // Note, there is one timer execution that comes from the `env.start_canister()`
    assert_eq!(result, WasmResult::Reply(6_u64.to_le_bytes().into()));

    // The timer should be triggered and reactivated each round.
    for _ in 6..10 {
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }

    // Assert the global timer is running.
    let result = env.query(canister_id, "query", get_global_counter).unwrap();
    assert_eq!(result, WasmResult::Reply(10_u64.to_le_bytes().into()));
}

#[test]
fn global_timer_resumes_after_canister_is_being_stopped_and_started_again() {
    let start = |env: &StateMachine, canister_id: CanisterId| {
        let result = env.stop_canister(canister_id);
        assert_matches!(result, Ok(_));
    };
    let stop = |env: &StateMachine, canister_id: CanisterId| {
        let result = env.start_canister(canister_id);
        assert_matches!(result, Ok(_));
    };
    global_timer_resumes(start, stop);
}

#[test]
fn global_timer_resumes_after_canister_is_being_frozen_and_unfrozen_again() {
    let freeze = |env: &StateMachine, canister_id: CanisterId| {
        let args = CanisterSettingsArgsBuilder::new()
            .with_freezing_threshold(1 << 62)
            .build();
        let result = env.update_settings(&canister_id, args);
        assert_matches!(result, Ok(_));
    };
    let unfreeze = |env: &StateMachine, canister_id: CanisterId| {
        let args = CanisterSettingsArgsBuilder::new()
            .with_freezing_threshold(0)
            .build();
        let result = env.update_settings(&canister_id, args);
        assert_matches!(result, Ok(_));
    };
    global_timer_resumes(freeze, unfreeze);
}

#[test]
fn global_timer_produces_transient_error_on_out_of_cycles() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    // The canister has no enough cycles for the install.
    let err = env
        .install_canister_with_cycles(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None, 0_u64.into())
        .unwrap_err();

    assert_eq!(RejectCode::SysTransient, err.code().into());
}
