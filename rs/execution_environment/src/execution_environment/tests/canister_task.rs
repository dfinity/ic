use assert_matches::assert_matches;
use ic_base_types::{NumSeconds, PrincipalId};
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_error_types::RejectCode;
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterSettingsArgsBuilder, CanisterStatusType, CanisterUpgradeOptions,
    IC_00, OnLowWasmMemoryHookStatus, Payload, WasmMemoryPersistence,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::NumWasmPages;
use ic_replicated_state::canister_state::NextExecution;
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_replicated_state::canister_state::execution_state::NextScheduledMethod;
use ic_replicated_state::page_map::PAGE_SIZE;
use ic_state_machine_tests::StateMachine;
use ic_state_machine_tests::{StateMachineBuilder, StateMachineConfig, WasmResult};
use ic_test_utilities_execution_environment::{ExecutionTestBuilder, wat_compilation_cost};
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::Cycles;
use ic_types::messages::CanisterTask;
use ic_types::{CanisterId, NumBytes};
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};
use maplit::btreemap;
use std::time::{Duration, UNIX_EPOCH};
use strum::IntoEnumIterator;

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
    let deadline = now_nanos + 1_000; // set the deadline in 1_000 rounds from now, i.e., far in the future so that the timer does not trigger before getting cancelled
    let set_global_timer = wasm()
        .set_global_timer_method(wasm().inc_global_counter())
        .api_global_timer_set(deadline)
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
    assert_eq!(result, WasmResult::Reply(deadline.to_le_bytes().into()));

    // The timer should not be called even after bumping time by 1s = 1_000_000_000ns
    // to exceed the deadline.
    env.advance_time(Duration::from_secs(1));
    // We execute rounds to exercise all possible next scheduled method types (to ensure a canister task would run if scheduled).
    for _ in NextScheduledMethod::iter() {
        let result = env
            .execute_ingress(canister_id, "update", get_global_counter.clone())
            .unwrap();
        assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));
    }
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
    // We execute rounds to exercise all possible next scheduled method types (to ensure a canister task would run if scheduled).
    for _ in NextScheduledMethod::iter() {
        let result = env
            .execute_ingress(canister_id, "update", get_global_counter.clone())
            .unwrap();
        assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));
    }
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
    // We execute rounds to exercise all possible next scheduled method types (to ensure a canister task would run if scheduled).
    for _ in NextScheduledMethod::iter() {
        env.advance_time(Duration::from_secs(1));
        env.tick();
        let result = env
            .execute_ingress(canister_id, "update", get_global_counter.clone())
            .unwrap();
        assert_eq!(result, WasmResult::Reply(1u64.to_le_bytes().into()));
    }
}

#[test]
fn global_timer_in_far_future_does_not_run() {
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
        .api_global_timer_set(now_nanos + 1_000_000) // set the deadline in many rounds from now
        .get_global_counter()
        .reply_int64()
        .build();
    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();
    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));

    let get_global_counter = wasm().get_global_counter().reply_int64().build();

    // We execute rounds to exercise all possible next scheduled method types (to ensure a canister task would run if scheduled).
    for _ in NextScheduledMethod::iter() {
        env.tick();
        let result = env
            .execute_ingress(canister_id, "update", get_global_counter.clone())
            .unwrap();
        assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().into()));
    }
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
    // We execute rounds to exercise all possible next scheduled method types (to ensure a canister task would run if scheduled).
    for _ in NextScheduledMethod::iter() {
        let result = env
            .execute_ingress(canister_id, "update", get_global_counter.clone())
            .unwrap();
        assert_eq!(result, WasmResult::Reply(1u64.to_le_bytes().into()));
    }

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
fn wasm64_task_metrics_are_observable() {
    let env = StateMachine::new();
    let wasm64_wat = r#"
        (module
            (import "ic0" "msg_reply" (func $ic0_msg_reply))
            (func $test (export "canister_update test")
                (call $ic0_msg_reply)
            )
            (memory i64 1)
        )"#;

    let canister_id = env.install_canister_wat(wasm64_wat, vec![], None);
    let result = env.execute_ingress(canister_id, "test", vec![]).unwrap();

    assert_eq!(result, WasmResult::Reply(vec![]));

    // Check if the metric reports a Wasm64 update.
    let executed_messages = fetch_int_counter_vec(
        env.metrics_registry(),
        "sandboxed_execution_executed_message_slices_total",
    );
    let update_msg = btreemap! {
        "api_type".into() => "update".into(),
        "status".into() => "Success".into(),
        "wasm_execution_mode".into() => "wasm64".into(),
    };
    assert_eq!(1, executed_messages[&update_msg]);
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
        "wasm_execution_mode".into() => "wasm32".into(),
    };
    // Includes install code, tick prior the update and 5 ticks
    assert_eq!(7, executed_messages[&heartbeat_no_response]);

    let global_timer_no_response = btreemap! {
        "api_type".into() => "global timer".into(),
        "status".into() => "NoResponse".into(),
        "wasm_execution_mode".into() => "wasm32".into(),
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
        "wasm_execution_mode".into() => "wasm32".into(),
    };
    assert_eq!(1, executed_messages[&global_timer_called_trap]);

    let heartbeat_no_response = btreemap! {
        "api_type".into() => "heartbeat".into(),
        "status".into() => "NoResponse".into(),
        "wasm_execution_mode".into() => "wasm32".into(),
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
fn global_timer_in_pre_and_post_upgrade() {
    let env = StateMachine::new();

    // Pre-upgrade pushes the timer it sees into stable memory and sets the timer into the past.
    let canister_id = env
        .install_canister(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            wasm()
                .set_pre_upgrade(
                    wasm()
                        .stable_grow(1)
                        .push_int(0)
                        .api_global_timer_set(1)
                        .int64_to_blob()
                        .stable_write_offset_blob()
                        .build(),
                )
                .build(),
            None,
        )
        .unwrap();

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let far_future_time = now_nanos + 1_000_000;
    let other_far_future_time = now_nanos + 2_000_000;

    // We set the timer (to confirm that pre-upgrade sees the timer) into far future (so that it does not actually run).
    env.execute_ingress(
        canister_id,
        "update",
        wasm().api_global_timer_set(far_future_time).reply().build(),
    )
    .unwrap();

    // Upgrade the canister to trigger pre-upgrade and post-upgrade.
    // Post-upgrade pushes the timer it sees into stable memory and sets the timer (to confirm that post-upgrade set the timer) into far future (so that it does not actually run).
    let set_global_timer_in_post_upgrade = wasm()
        .push_int(8)
        .api_global_timer_set(other_far_future_time)
        .int64_to_blob()
        .stable_write_offset_blob()
        .build();
    let result = env.upgrade_canister(
        canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        set_global_timer_in_post_upgrade,
    );
    assert_eq!(result, Ok(()));

    // We fetch the two timers from stable memory:
    // - the first timer is the custom timer seen in pre-upgrade;
    // - the second timer is the cleared timer seen in post-uprade.
    let result = env
        .execute_ingress(
            canister_id,
            "update",
            wasm().stable_read(0, 16).append_and_reply().build(),
        )
        .unwrap();
    match result {
        WasmResult::Reply(data) => {
            assert_eq!(
                data,
                [far_future_time.to_le_bytes(), 0_u64.to_le_bytes()].concat()
            );
        }
        WasmResult::Reject(msg) => panic!("Unexpected reject: {msg}"),
    };

    // We confirm that post-upgrade set the timer by resetting the timer and checking its previous value.
    let result = env
        .execute_ingress(
            canister_id,
            "update",
            wasm()
                .api_global_timer_set(far_future_time)
                .reply_int64()
                .build(),
        )
        .unwrap();
    match result {
        WasmResult::Reply(data) => {
            assert_eq!(data, other_far_future_time.to_le_bytes());
        }
        WasmResult::Reject(msg) => panic!("Unexpected reject: {msg}"),
    };
}

#[test]
fn global_timer_in_init() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), wasm().build(), None)
        .unwrap();

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let far_future_time = now_nanos + 1_000_000;
    let other_far_future_time = now_nanos + 2_000_000;

    // We set the timer (to confirm that init sees the cleared timer) into far future (so that it does not actually run).
    env.execute_ingress(
        canister_id,
        "update",
        wasm().api_global_timer_set(far_future_time).reply().build(),
    )
    .unwrap();

    // Reinstall the canister to trigger init.
    // Init pushes the timer it sees into stable memory and sets the timer (to confirm that init set the timer) into far future (so that it does not actually run).
    let set_global_timer_in_init = wasm()
        .stable_grow(1)
        .push_int(0)
        .api_global_timer_set(other_far_future_time)
        .int64_to_blob()
        .stable_write_offset_blob()
        .build();
    let result = env.reinstall_canister(
        canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        set_global_timer_in_init,
    );
    assert_eq!(result, Ok(()));

    // We fetch the cleared timer seen in init from stable memory.
    let result = env
        .execute_ingress(
            canister_id,
            "update",
            wasm().stable_read(0, 8).append_and_reply().build(),
        )
        .unwrap();
    match result {
        WasmResult::Reply(data) => {
            assert_eq!(data, 0_u64.to_le_bytes(),);
        }
        WasmResult::Reject(msg) => panic!("Unexpected reject: {msg}"),
    };

    // We confirm that init set the timer by resetting the timer and checking its previous value.
    let result = env
        .execute_ingress(
            canister_id,
            "update",
            wasm()
                .api_global_timer_set(far_future_time)
                .reply_int64()
                .build(),
        )
        .unwrap();
    match result {
        WasmResult::Reply(data) => {
            assert_eq!(data, other_far_future_time.to_le_bytes());
        }
        WasmResult::Reject(msg) => panic!("Unexpected reject: {msg}"),
    };
}

#[test]
fn global_timer_runs_if_set_in_stopping_canister_post_upgrade() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), wasm().build(), None)
        .unwrap();

    // Make the canister control itself so that it can try to stop itself.
    let settings = CanisterSettingsArgsBuilder::new()
        .with_controllers(vec![PrincipalId::new_anonymous(), canister_id.get()])
        .build();
    env.update_settings(&canister_id, settings).unwrap();

    // Make the canister stopping (not stopped) by trying to stop itself.
    let stop_arg: CanisterIdRecord = canister_id.into();
    let result = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .call_simple(
                IC_00,
                "stop_canister",
                call_args().other_side(stop_arg.encode()),
            )
            .reply()
            .build(),
    );
    assert_matches!(result, Ok(_));

    // Make sure the canister is indeed stopping.
    let status = env.canister_status(canister_id).unwrap().unwrap();
    assert_eq!(status.status(), CanisterStatusType::Stopping);

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

    // The timer should not be triggered as the canister is stopping.
    // We execute rounds to exercise all possible next scheduled method types (to ensure a canister task would run if scheduled).
    for _ in NextScheduledMethod::iter() {
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }

    // Any update calls should fail as the canister is stopping.
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
    // We execute rounds to exercise all possible next scheduled method types (to ensure a canister task would run if scheduled).
    for _ in NextScheduledMethod::iter() {
        env.advance_time(Duration::from_secs(1));
        env.tick();
    }

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
    // wasm_memory_limit = 20 Wasm Pages
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

    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
    // Hook condition is satisfied.
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
    // wasm_memory_limit = 20 Wasm Pages
    // wasm_memory_threshold = 10 Wasm Pages

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    // wasm_memory.size = 1 + 7 = 8
    // wasm_memory_limit - used_wasm_memory >= self.wasm_memory_threshold
    // hook is not executed.
    test.ingress(canister_id, "grow_mem", vec![]).unwrap();
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    // wasm_memory.size = 8 + 7 = 15
    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
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
    // wasm_memory_limit = 20 Wasm Pages
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
    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
    // Hook condition is satisfied.
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
    // wasm_memory_limit = 20 Wasm Pages
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
    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
    // Hook condition is satisfied.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Ready
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
    // Hook condition is satisfied.
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    // Status of the hook is still Ready.
    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Ready
    );

    // Though we have the second ingress message awaiting to be processed,
    // hook will be executed first.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(13)
    );

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Executed
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
    // wasm_memory_limit = 20 Wasm Pages
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
    // wasm_memory_limit - used_wasm_memory >= self.wasm_memory_threshold
    // Hook condition is not satisfied.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(4)
    );

    // Second ingress messages gets executed.
    // wasm_memory.size = 4 + 3 = 7
    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
    // Hook condition is satisfied.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(7)
    );

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Ready
    );

    let result = test.upgrade_canister_v2(
        canister_id,
        wat::parse_str(wat).unwrap(),
        CanisterUpgradeOptions {
            skip_pre_upgrade: None,
            wasm_memory_persistence: None,
        },
    );
    assert_eq!(result, Ok(()));

    // Upgrade is executed, and the wasm_memory size reset to 1.
    // Hook condition is not satisfied.
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied
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
fn upgrade_changes_hook_status_to_not_satisfied() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    let update_grow_mem_size = 7;
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
    // wasm_memory_limit = 20 Wasm Pages
    // wasm_memory_threshold = 15 Wasm Pages

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    test.ingress_raw(canister_id, "grow_mem", vec![]);

    // Ingress messages gets executed.
    // wasm_memory.size = 1 + 7 = 8
    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
    // Hook condition is satisfied.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Ready
    );

    // Hook is executed
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(13)
    );

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Executed
    );

    // Canister upgrade.
    assert!(
        test.upgrade_canister_v2(
            canister_id,
            wat::parse_str(wat).unwrap(),
            CanisterUpgradeOptions {
                skip_pre_upgrade: None,
                wasm_memory_persistence: None,
            },
        )
        .is_ok()
    );

    // Upgrade is executed, and the wasm_memory size reset to 1.
    // wasm_memory_limit - used_wasm_memory >= self.wasm_memory_threshold
    // Hook condition is not satisfied.
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    // Hook status is changed after upgrade.
    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied
    );
}

#[test]
fn hook_status_remains_executed_if_condition_holds_after_upgrade() {
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
    // wasm_memory_limit = 20 Wasm Pages
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
    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
    // Hook condition is satisfied.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(8)
    );

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Ready
    );

    // Hook is executed.
    test.execute_slice(canister_id);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(13)
    );
    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Executed
    );

    // Upgrade canister.
    let result = test.upgrade_canister_v2(
        canister_id,
        wat::parse_str(wat).unwrap(),
        CanisterUpgradeOptions {
            skip_pre_upgrade: None,
            wasm_memory_persistence: Some(WasmMemoryPersistence::Keep),
        },
    );
    assert_eq!(result, Ok(()));

    // Hook condition is still satisfied.
    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(13)
    );

    // Hence hook status should remain executed.
    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Executed
    );
}

#[test]
fn upgrade_changes_hook_status_to_ready() {
    let wat = r#"(module
            (memory 1 20)
        )"#;
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    let canister_id = test.canister_from_wat(wat).unwrap();

    test.canister_update_wasm_memory_limit_and_wasm_memory_threshold(
        canister_id,
        (10 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
        (9 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
    )
    .unwrap();

    // Here we have:
    // wasm_memory_limit = 10 Wasm Pages
    // wasm_memory_threshold = 9 Wasm Pages

    // Initially wasm_memory.size = 1
    // wasm_memory_limit - used_wasm_memory = wasm_memory_threshold
    // Hook condition is not satisfied.
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied
    );

    let wat2 = r#"(module
        (memory 2 2)
    )"#;

    // Canister upgrade.
    assert!(
        test.upgrade_canister_v2(
            canister_id,
            wat::parse_str(wat2).unwrap(),
            CanisterUpgradeOptions {
                skip_pre_upgrade: None,
                wasm_memory_persistence: None,
            },
        )
        .is_ok()
    );

    // Upgrade is executed, and the used_wasm_memory size is 2.
    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
    // Hook condition is satisfied.
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(2)
    );

    // Hook status is changed after upgrade.
    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Ready
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
    // wasm_memory_limit = 20 Wasm Pages
    // wasm_memory_threshold = 15 Wasm Pages

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    // wasm_memory.size = 1 + 7 = 8
    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
    // hence hook will be executed. After hook execution we have:
    // wasm_memory.size = 8 + 2 = 10.
    test.ingress(canister_id, "grow_mem", vec![]).unwrap();
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(10)
    );

    // wasm_memory.size = 10 + 7 = 17
    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
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
    // wasm_memory_limit = 20 Wasm Pages
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
    // wasm_memory_limit - used_wasm_memory < self.wasm_memory_threshold
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
fn low_wasm_memory_hook_is_run_when_memory_limit_is_exceeded() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();

    let update_grow_mem_size = 10;
    let hook_grow_mem_size = 5;

    let wat: String =
        get_wat_with_update_and_hook_mem_grow(update_grow_mem_size, hook_grow_mem_size, true);

    let canister_id = test.canister_from_wat(wat.as_str()).unwrap();

    // Initially wasm_memory.size = 1
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(1)
    );

    test.ingress_raw(canister_id, "grow_mem", vec![]);

    // First ingress messages gets executed.
    // wasm_memory.size = 1 + 10 = 11
    test.execute_slice(canister_id);

    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(11)
    );

    // We update `wasm_memory_limit` to be smaller than `used_wasm_memory`.
    test.canister_update_wasm_memory_limit_and_wasm_memory_threshold(
        canister_id,
        (10 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
        (5 * WASM_PAGE_SIZE_IN_BYTES as u64).into(),
    )
    .unwrap();

    // The update will also satisfy condition for `low_wasm_memory` hook.
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

    // Low wasm memory hook is executed.
    test.execute_slice(canister_id);

    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(16)
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
}
