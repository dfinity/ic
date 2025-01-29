use assert_matches::assert_matches;
use ic_base_types::NumSeconds;
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_error_types::RejectCode;
use ic_management_canister_types::{CanisterSettingsArgsBuilder, CanisterStatusType};
use ic_management_canister_types::{CanisterUpgradeOptions, WasmMemoryPersistence};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::OnLowWasmMemoryHookStatus;
use ic_replicated_state::canister_state::NextExecution;
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_replicated_state::page_map::PAGE_SIZE;
use ic_replicated_state::NumWasmPages;
use ic_state_machine_tests::StateMachine;
use ic_state_machine_tests::{StateMachineBuilder, StateMachineConfig, WasmResult};
use ic_test_utilities_execution_environment::{wat_compilation_cost, ExecutionTestBuilder};
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::messages::CanisterTask;
use ic_types::Cycles;
use ic_types::{CanisterId, NumBytes};
use ic_universal_canister::wasm;
use ic_universal_canister::UNIVERSAL_CANISTER_WASM;
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

    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    // Setup global timer to increase a global counter
    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
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

    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    // Setup global timer to increase a global counter
    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
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
        .install_canister_with_cycles(binary, vec![], None, Cycles::new(301_000_000_000))
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
        .install_canister_with_cycles(binary, vec![], None, Cycles::new(301_000_000_000))
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

fn get_wat_with_update_and_hook_mem_grow(
    update_grow_mem_size: i32,
    hook_grow_mem_size: i32,
    with_enchanced_ortogonal_persistence: bool,
) -> String {
    let mut wat = r#"
    (module
    (import "ic0" "msg_reply" (func $msg_reply))
    (func $grow_mem
        (drop (memory.grow (i32.const "#
        .to_owned();
    wat.push_str(update_grow_mem_size.to_string().as_str());
    wat.push_str(
        r#")))
        (call $msg_reply)
    )
    (export "canister_update grow_mem" (func $grow_mem))
    (func (export "canister_on_low_wasm_memory")
        (drop (memory.grow (i32.const "#,
    );
    wat.push_str(hook_grow_mem_size.to_string().as_str());
    wat.push_str(
        r#")))
    )
    (memory 1 20)"#,
    );
    if with_enchanced_ortogonal_persistence {
        wat.push_str(
            r#"
            (@custom "icp:private enhanced-orthogonal-persistence" "")
            "#,
        );
    }
    wat.push_str(
        r#"
    )"#,
    );
    wat
}

#[test]
fn on_low_wasm_memory_hook_is_run_after_freezing() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    let update_grow_mem_size = 7;
    let hook_grow_mem_size = 5;

    let wat =
        get_wat_with_update_and_hook_mem_grow(update_grow_mem_size, hook_grow_mem_size, false);

    let canister_id = test
        .canister_from_cycles_and_wat(Cycles::new(200_000_000_000_000), wat)
        .unwrap();

    test.canister_update_wasm_memory_limit_and_wasm_memory_threshold(
        canister_id,
        (20 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
        (15 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
    )
    .unwrap();

    // Here we have:
    // wasm_capacity = wasm_memory_limit = 20 Wasm Pages
    // wasm_memory_threshold = 15 Wasm Pages

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    // Two ingress messages are sent.
    test.ingress_raw(canister_id, "grow_mem", vec![]);
    test.ingress_raw(canister_id, "grow_mem", vec![]);

    // The first ingress message gets executed.
    // wasm_memory.size = 1 + 7 = 8
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    // wasm_capacity - used_wasm_memory < self.wasm_memory_threshold
    // The hook condition is triggered.
    // Hence hook should be executed next.
    assert_eq!(
        test.state()
            .canister_states
            .get(&canister_id)
            .unwrap()
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Ready
    );

    // We update `freezing_threshold` making canister frozen.
    test.update_freezing_threshold(canister_id, NumSeconds::new(100_000_000_000_000))
        .unwrap();

    // The execution of the hook is not finished due to freezing.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    // The hook status is still `Ready`.
    assert_eq!(
        test.state()
            .canister_states
            .get(&canister_id)
            .unwrap()
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Ready
    );

    // We update `freezing_threshold` unfreezing canister.
    test.update_freezing_threshold(canister_id, NumSeconds::new(100))
        .unwrap();

    // The hook is executed.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(13)
    );

    assert_eq!(
        test.state()
            .canister_states
            .get(&canister_id)
            .unwrap()
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Executed
    );

    // The second ingress message is executed.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(20)
    );
}

#[test]
fn on_low_wasm_memory_is_executed() {
    let mut test = ExecutionTestBuilder::new().build();

    let update_grow_mem_size = 7;
    let hook_grow_mem_size = 5;

    let wat =
        get_wat_with_update_and_hook_mem_grow(update_grow_mem_size, hook_grow_mem_size, false);

    let canister_id = test.canister_from_wat(wat.as_str()).unwrap();

    test.canister_update_wasm_memory_limit_and_wasm_memory_threshold(
        canister_id,
        (20 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
        (10 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
    )
    .unwrap();

    // Here we have:
    // wasm_capacity = wasm_memory_limit = 20 Wasm Pages
    // wasm_memory_threshold = 10 Wasm Pages

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    // wasm_memory.size = 1 + 7 = 8
    // wasm_capacity - used_wasm_memory > self.wasm_memory_threshold
    // hook is not executed.
    test.ingress(canister_id, "grow_mem", vec![]).unwrap();
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    // wasm_memory.size = 8 + 7 = 15
    // wasm_capacity - used_wasm_memory < self.wasm_memory_threshold
    // hence hook will be executed. After hook execution we have:
    // wasm_memory.size = 15 + 5 = 20.
    test.ingress(canister_id, "grow_mem", vec![]).unwrap();

    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(20)
    );
}

#[test]
fn on_low_wasm_memory_is_executed_before_message() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    let update_grow_mem_size = 7;
    let hook_grow_mem_size = 5;

    let wat =
        get_wat_with_update_and_hook_mem_grow(update_grow_mem_size, hook_grow_mem_size, false);

    let canister_id = test.canister_from_wat(wat.as_str()).unwrap();

    test.canister_update_wasm_memory_limit_and_wasm_memory_threshold(
        canister_id,
        (20 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
        (15 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
    )
    .unwrap();

    // Here we have:
    // wasm_capacity = wasm_memory_limit = 20 Wasm Pages
    // wasm_memory_threshold = 15 Wasm Pages

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    test.ingress_raw(canister_id, "grow_mem", vec![]);
    test.ingress_raw(canister_id, "grow_mem", vec![]);

    // First ingress messages gets executed.
    // wasm_memory.size = 1 + 7 = 8
    // wasm_capacity - used_wasm_memory < self.wasm_memory_threshold
    // Hook condition is triggered.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    // Though we have the second ingress message awaiting to be processed,
    // hook will be executed first.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(13)
    );

    // The second ingress message is executed after the hook.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(20)
    );
}

#[test]
fn on_low_wasm_memory_is_executed_after_upgrade_if_condition_holds() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    let update_grow_mem_size = 7;
    let hook_grow_mem_size = 5;

    let wat: String =
        get_wat_with_update_and_hook_mem_grow(update_grow_mem_size, hook_grow_mem_size, true);

    let canister_id = test.canister_from_wat(wat.as_str()).unwrap();

    test.canister_update_wasm_memory_limit_and_wasm_memory_threshold(
        canister_id,
        (20 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
        (15 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
    )
    .unwrap();

    // Here we have:
    // wasm_capacity = wasm_memory_limit = 20 Wasm Pages
    // wasm_memory_threshold = 15 Wasm Pages

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    test.ingress_raw(canister_id, "grow_mem", vec![]);
    test.ingress_raw(canister_id, "grow_mem", vec![]);

    // First ingress messages gets executed.
    // wasm_memory.size = 1 + 7 = 8
    // wasm_capacity - used_wasm_memory < self.wasm_memory_threshold
    // Hook condition is triggered.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    let result = test.upgrade_canister_v2(
        canister_id,
        wat::parse_str(wat).unwrap(),
        CanisterUpgradeOptions {
            skip_pre_upgrade: None,
            wasm_memory_persistence: Some(WasmMemoryPersistence::Keep),
        },
    );
    assert_eq!(result, Ok(()));

    // Upgrade is executed, and the wasm_memory size is unchanged.
    // Hook condition is triggered.
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    // Though we have the second ingress message awaiting to be processed,
    // hook will be executed first.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(13)
    );

    // The second ingress message is executed after the hook.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(20)
    );
}

#[test]
fn on_low_wasm_memory_is_not_executed_after_upgrade_if_condition_becomes_unsatisfied() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    let update_grow_mem_size = 3;
    let hook_grow_mem_size = 5;

    let wat: String =
        get_wat_with_update_and_hook_mem_grow(update_grow_mem_size, hook_grow_mem_size, false);

    let canister_id = test.canister_from_wat(wat.as_str()).unwrap();

    test.canister_update_wasm_memory_limit_and_wasm_memory_threshold(
        canister_id,
        (20 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
        (15 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
    )
    .unwrap();

    // Here we have:
    // wasm_capacity = wasm_memory_limit = 20 Wasm Pages
    // wasm_memory_threshold = 15 Wasm Pages

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    test.ingress_raw(canister_id, "grow_mem", vec![]);
    test.ingress_raw(canister_id, "grow_mem", vec![]);
    test.ingress_raw(canister_id, "grow_mem", vec![]);

    // First ingress messages gets executed.
    // wasm_memory.size = 1 + 3 = 4
    // wasm_capacity - used_wasm_memory > self.wasm_memory_threshold
    // Hook condition is not triggered.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(4)
    );

    // Second ingress messages gets executed.
    // wasm_memory.size = 4 + 3 = 7
    // wasm_capacity - used_wasm_memory < self.wasm_memory_threshold
    // Hook condition is triggered.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(7)
    );
    println!("canister upgrade");

    let result = test.upgrade_canister_v2(
        canister_id,
        wat::parse_str(wat).unwrap(),
        CanisterUpgradeOptions {
            skip_pre_upgrade: None,
            wasm_memory_persistence: None,
        },
    );
    assert_eq!(result, Ok(()));
    println!("canister upgrade");

    // Upgrade is executed, and the wasm_memory size reset to 1.
    // Hook condition is not triggered.
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    // Though the hook was initially scheduled, it is now removed
    // from queue, and the third ingress message will be executed.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(4)
    );

    // There are no messages left to be executed.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(4)
    );
}

#[test]
fn on_low_wasm_memory_is_executed_once() {
    let mut test = ExecutionTestBuilder::new().build();

    let update_grow_mem_size = 7;
    let hook_grow_mem_size = 2;

    let wat =
        get_wat_with_update_and_hook_mem_grow(update_grow_mem_size, hook_grow_mem_size, false);

    let canister_id = test.canister_from_wat(wat.as_str()).unwrap();

    test.canister_update_wasm_memory_limit_and_wasm_memory_threshold(
        canister_id,
        (20 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
        (15 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
    )
    .unwrap();

    // Here we have:
    // wasm_capacity = wasm_memory_limit = 20 Wasm Pages
    // wasm_memory_threshold = 15 Wasm Pages

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    // wasm_memory.size = 1 + 7 = 8
    // wasm_capacity - used_wasm_memory < self.wasm_memory_threshold
    // hence hook will be executed. After hook execution we have:
    // wasm_memory.size = 8 + 2 = 10.
    test.ingress(canister_id, "grow_mem", vec![]).unwrap();
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(10)
    );

    // wasm_memory.size = 10 + 7 = 17
    // wasm_capacity - used_wasm_memory < self.wasm_memory_threshold
    // but because the hook is already executed it will not be executed again.
    test.ingress(canister_id, "grow_mem", vec![]).unwrap();

    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(17)
    );
}

#[test]
fn on_low_wasm_memory_runs_after_dts_execution() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(1_000_000)
        .with_slice_instruction_limit(1_000)
        .with_manual_execution()
        .build();

    let wat = r#"(module
        (import "ic0" "msg_reply" (func $msg_reply))
        (func $grow_mem
            (drop (memory.grow (i32.const 7)))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (memory.fill (i32.const 0) (i32.const 34) (i32.const 1000))
            (call $msg_reply)
        )
        (export "canister_update grow_mem" (func $grow_mem))
        (func (export "canister_on_low_wasm_memory")
            (drop (memory.grow (i32.const 5)))
        )
        (memory 1 20)
    )"#;

    let canister_id = test.canister_from_wat(wat).unwrap();

    test.canister_update_wasm_memory_limit_and_wasm_memory_threshold(
        canister_id,
        (20 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
        (15 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
    )
    .unwrap();

    // Here we have:
    // wasm_capacity = wasm_memory_limit = 20 Wasm Pages
    // wasm_memory_threshold = 15 Wasm Pages

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    test.ingress_raw(canister_id, "grow_mem", vec![]);
    test.execute_slice(canister_id);

    // Ensure that we have ongoing dts execution.
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong
    );

    // Finish dts execution.
    while test.canister_state(canister_id).next_execution() == NextExecution::ContinueLong {
        test.execute_slice(canister_id);
    }

    // After dts execution we should have the following:
    // wasm_memory.size = 1 + 7 = 8
    // wasm_capacity - used_wasm_memory < self.wasm_memory_threshold
    // hence hook will be executed.
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    // Execute hook.
    test.execute_slice(canister_id);

    // After hook execution we have:
    // wasm_memory.size = 8 + 5 = 13.
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(13)
    );
}

#[test]
fn on_low_wasm_memory_is_executed_after_growing_stable_memory() {
    let mut test = ExecutionTestBuilder::new().build();

    let wat = r#"(module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "stable_grow"
                    (func $ic0_stable_grow (param $pages i32) (result i32)))
            (func $stable_grow
                (drop (call $ic0_stable_grow (i32.const 7)))
                (call $msg_reply)
            )
            (export "canister_update stable_grow" (func $stable_grow))
            (func (export "canister_on_low_wasm_memory")
                (drop (memory.grow (i32.const 5)))
            )
            (memory 1 20)
        )"#;

    let canister_id = test.canister_from_wat(wat).unwrap();

    test.canister_update_memory_allocation_and_wasm_memory_threshold(
        canister_id,
        (30 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
        (20 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
    )
    .unwrap();

    // Here we have:
    // wasm_capacity = memory_allocation - used_stable_memory = 30 Wasm Pages - used_stable_memory
    // wasm_memory_threshold = 20 Wasm Pages

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );
    assert_eq!(
        test.execution_state(canister_id).stable_memory.size,
        NumWasmPages::new(0)
    );

    // stable_memory.size = 7
    // wasm_capacity - used_wasm_memory > self.wasm_memory_threshold
    // memory_allocation - used_stable_memory - used_wasm_memory > self.wasm_memory_threshold
    // hence hook will not be executed.
    test.ingress(canister_id, "stable_grow", vec![]).unwrap();
    assert_eq!(
        test.execution_state(canister_id).stable_memory.size,
        NumWasmPages::new(7)
    );
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    // stable_memory.size = 7 + 7 = 14
    // wasm_capacity - used_wasm_memory < self.wasm_memory_threshold
    // memory_allocation - used_stable_memory - used_wasm_memory < self.wasm_memory_threshold
    // hence hook will be executed. After hook execution we have:
    // wasm_memory.size = 1 + 5 = 6.
    test.ingress(canister_id, "stable_grow", vec![]).unwrap();
    assert_eq!(
        test.execution_state(canister_id).stable_memory.size,
        NumWasmPages::new(14)
    );
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(6)
    );
}
