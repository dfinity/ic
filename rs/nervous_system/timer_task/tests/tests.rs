use candid::{Decode, Encode};
use canister_test::Project;
use ic_config::subnet_config::SubnetConfig;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types::{ingress::WasmResult, CanisterId};

fn state_machine_for_test() -> StateMachine {
    // Setting up the state machine with a lower instruction limit to make the tests run faster.
    let mut hypervisor_config = ic_config::execution_environment::Config::default();
    let mut subnet_config = SubnetConfig::new(SubnetType::System);
    let instruction_divisor = 10;
    subnet_config.scheduler_config.max_instructions_per_round /= instruction_divisor;
    subnet_config.scheduler_config.max_instructions_per_message /= instruction_divisor;
    subnet_config
        .scheduler_config
        .max_instructions_per_message_without_dts /= instruction_divisor;
    hypervisor_config.max_query_call_graph_instructions /= instruction_divisor;

    StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            subnet_config,
            hypervisor_config,
        )))
        .build()
}

fn get_counter(state_machine: &StateMachine, canister_id: CanisterId, name: &str) -> u64 {
    let result = state_machine
        .query(
            canister_id,
            "get_counter",
            Encode!(&name.to_string()).unwrap(),
        )
        .unwrap();
    let WasmResult::Reply(reply) = result else {
        panic!("Query failed: {:?}", result);
    };
    Decode!(&reply, u64).unwrap()
}

fn set_up_canister_with_tasks(state_machine: &StateMachine, task_names: Vec<String>) -> CanisterId {
    let timer_task_canister_wasm = Project::cargo_bin_maybe_from_env("timer-task-canister", &[]);
    state_machine
        .install_canister(
            timer_task_canister_wasm.bytes(),
            Encode!(&task_names).unwrap(),
            None,
        )
        .unwrap()
}

#[test]
fn test_incremental_delay() {
    let state_machine = state_machine_for_test();
    let canister_id = set_up_canister_with_tasks(
        &state_machine,
        vec!["IncrementalDelayRecurringSyncTask".to_string()],
    );

    for _ in 0..10 {
        state_machine.advance_time(std::time::Duration::from_secs(1));
        state_machine.tick();
    }

    let counter = get_counter(
        &state_machine,
        canister_id,
        "IncrementalDelayRecurringSyncTask",
    );
    assert_eq!(counter, 5);
}

#[test]
fn test_out_of_instruction_tasks() {
    let state_machine = state_machine_for_test();
    let canister_id = set_up_canister_with_tasks(
        &state_machine,
        vec![
            "SuccessRecurringSyncTask".to_string(),
            "OutOfInstructionsRecurringSyncTask".to_string(),
            "OutOfInstructionsBeforeCallRecurringAsyncTask".to_string(),
            "OutOfInstructionsAfterCallRecurringAsyncTask".to_string(),
        ],
    );

    for _ in 0..100 {
        state_machine.advance_time(std::time::Duration::from_secs(1));
        state_machine.tick();
    }

    let successful_counter = get_counter(&state_machine, canister_id, "SuccessRecurringSyncTask");
    assert!(
        successful_counter > 20,
        "successful_counter {}",
        successful_counter
    );

    let out_of_instructions_sync_counter = get_counter(
        &state_machine,
        canister_id,
        "OutOfInstructionsRecurringSyncTask",
    );
    assert_eq!(out_of_instructions_sync_counter, 0);

    let out_of_instructions_after_call_async_counter = get_counter(
        &state_machine,
        canister_id,
        "OutOfInstructionsAfterCallRecurringAsyncTask",
    );
    assert_eq!(out_of_instructions_after_call_async_counter, 1);
}

#[test]
fn test_panic_recurring_sync_task() {
    let state_machine = state_machine_for_test();
    let canister_id =
        set_up_canister_with_tasks(&state_machine, vec!["PanicRecurringSyncTask".to_string()]);

    for _ in 0..100 {
        state_machine.advance_time(std::time::Duration::from_secs(1));
        state_machine.tick();
    }

    let counter = get_counter(&state_machine, canister_id, "PanicRecurringSyncTask");
    assert_eq!(counter, 0);
}

#[test]
fn test_panic_recurring_async_task() {
    let state_machine = state_machine_for_test();
    let canister_id =
        set_up_canister_with_tasks(&state_machine, vec!["PanicRecurringAsyncTask".to_string()]);

    for _ in 0..100 {
        state_machine.advance_time(std::time::Duration::from_secs(1));
        state_machine.tick();
    }

    let counter = get_counter(&state_machine, canister_id, "PanicRecurringAsyncTask");
    assert_eq!(counter, 1);
}

#[test]
fn test_success_tasks() {
    let state_machine = state_machine_for_test();
    let task_names = vec![
        "SuccessRecurringSyncTask".to_string(),
        "SuccessRecurringAsyncTask".to_string(),
        "SuccessPeriodicSyncTask".to_string(),
        "SuccessPeriodicAsyncTask".to_string(),
    ];
    let canister_id = set_up_canister_with_tasks(&state_machine, task_names.clone());

    for _ in 0..100 {
        state_machine.advance_time(std::time::Duration::from_secs(1));
        state_machine.tick();
    }

    for name in task_names {
        let counter = get_counter(&state_machine, canister_id, &name);
        assert!(counter >= 100, "{} counter {}", name, counter);
    }
}

#[test]
fn test_panic_periodic_async_task() {
    let state_machine = state_machine_for_test();
    let canister_id =
        set_up_canister_with_tasks(&state_machine, vec!["PanicPeriodicAsyncTask".to_string()]);

    for _ in 0..100 {
        state_machine.advance_time(std::time::Duration::from_secs(1));
        state_machine.tick();
    }

    let counter = get_counter(&state_machine, canister_id, "PanicPeriodicAsyncTask");
    assert!(counter >= 100, "counter {}", counter);
}
