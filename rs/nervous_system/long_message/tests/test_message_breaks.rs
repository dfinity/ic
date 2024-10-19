use canister_test::Project;
use ic_config::subnet_config::SubnetConfig;
use ic_nns_test_utils::state_test_helpers::{create_canister, update_with_sender};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types::{NumInstructions, PrincipalId};
use std::time::Duration;

#[derive(candid::CandidType, serde::Deserialize)]
struct TestParameters {
    pub use_break: bool,
    pub message_threshold: u64,
    pub upper_bound: Option<u64>,
}

fn state_machine_for_test(instructions_limit: u64) -> StateMachine {
    let mut hypervisor_config = ic_config::execution_environment::Config::default();
    let mut subnet_config = SubnetConfig::new(SubnetType::System);

    let instruction_limit = NumInstructions::new(instructions_limit);
    if instruction_limit > subnet_config.scheduler_config.max_instructions_per_round {
        subnet_config.scheduler_config.max_instructions_per_round = instruction_limit;
    }
    subnet_config.scheduler_config.max_instructions_per_message = instruction_limit;
    subnet_config
        .scheduler_config
        .max_instructions_per_message_without_dts = instruction_limit;
    hypervisor_config.max_query_call_graph_instructions = instruction_limit;

    StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            subnet_config,
            hypervisor_config,
        )))
        .build()
}

#[test]
fn test_next_message_if_over_instructions() {
    let instructions_limit = 500_000;
    let state_machine = state_machine_for_test(instructions_limit);

    let canister_playground_wasm = Project::cargo_bin_maybe_from_env("long-message-canister", &[]);

    let playground_id =
        create_canister(&state_machine, canister_playground_wasm, Some(vec![]), None);

    let err: String = update_with_sender::<TestParameters, ()>(
        &state_machine,
        playground_id,
        "test_next_message_if_over_instructions",
        TestParameters {
            use_break: false,
            message_threshold: instructions_limit * 4 / 5,
            upper_bound: None,
        },
        PrincipalId::new_anonymous(),
    )
    .unwrap_err();
    assert!(err.contains(
        format!(
            "Canister exceeded the limit of {} instructions",
            instructions_limit
        )
        .as_str()
    ));

    update_with_sender::<TestParameters, ()>(
        &state_machine,
        playground_id,
        "test_next_message_if_over_instructions",
        TestParameters {
            use_break: true,
            message_threshold: instructions_limit * 4 / 5,
            upper_bound: None,
        },
        PrincipalId::new_anonymous(),
    )
    .unwrap();
}

#[test]
fn test_upper_bound() {
    let instructions_limit = 500_000;
    let state_machine = state_machine_for_test(instructions_limit);

    let canister_playground_wasm = Project::cargo_bin_maybe_from_env("long-message-canister", &[]);

    let playground_id =
        create_canister(&state_machine, canister_playground_wasm, Some(vec![]), None);

    let err: String = update_with_sender::<TestParameters, ()>(
        &state_machine,
        playground_id,
        "test_next_message_if_over_instructions",
        TestParameters {
            use_break: false,
            message_threshold: instructions_limit * 4 / 5,
            upper_bound: Some(instructions_limit * 6 / 5),
        },
        PrincipalId::new_anonymous(),
    )
    .unwrap_err();
    assert!(err.contains(
        format!(
            "Canister call exceeded the limit of {} instructions in the call context.",
            instructions_limit * 6 / 5
        )
        .as_str()
    ));

    update_with_sender::<TestParameters, ()>(
        &state_machine,
        playground_id,
        "test_next_message_if_over_instructions",
        TestParameters {
            use_break: true,
            message_threshold: instructions_limit * 4 / 5,
            upper_bound: None,
        },
        PrincipalId::new_anonymous(),
    )
    .unwrap();
}
