use candid::Encode;
use ic_base_types::CanisterId;
use ic_nervous_system_clients::canister_status::CanisterStatusType;
use ic_nervous_system_root::change_canister::{
    CanisterAction as RootCanisterAction, StopOrStartCanisterRequest,
};
use ic_nns_constants::{REGISTRY_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::pb::v1::{
    manage_neuron_response::Command, proposal::Action, stop_or_start_canister::CanisterAction,
    ExecuteNnsFunction, NnsFunction, Proposal, StopOrStartCanister,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::get_neuron_1,
    state_test_helpers::{
        get_canister_status, nns_governance_make_proposal, nns_wait_for_proposal_execution,
        setup_nns_canisters, state_machine_builder_for_nns_tests,
    },
};

fn test_stop_and_start_registry_canister(use_proposal_action: bool) {
    // Step 1: Set up the NNS canisters and get the neuron.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    let canister_status_type = || -> CanisterStatusType {
        let canister_status = get_canister_status(
            &state_machine,
            ROOT_CANISTER_ID.get(),
            REGISTRY_CANISTER_ID,
            CanisterId::ic_00(),
        );
        canister_status.unwrap().status
    };
    let n1 = get_neuron_1();

    // Step 2: Make sure the canister is running.
    assert_eq!(canister_status_type(), CanisterStatusType::Running);

    // Step 3: Make a proposal to stop the canister and wait for it to be executed.
    let action = if use_proposal_action {
        Action::StopOrStartCanister(StopOrStartCanister {
            canister_id: Some(REGISTRY_CANISTER_ID.get()),
            action: Some(CanisterAction::Stop as i32),
        })
    } else {
        let stop_or_start_request = StopOrStartCanisterRequest {
            canister_id: REGISTRY_CANISTER_ID,
            action: RootCanisterAction::Stop,
        };
        Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::StopOrStartNnsCanister as i32,
            payload: Encode!(&stop_or_start_request).unwrap(),
        })
    };
    let propose_response = nns_governance_make_proposal(
        &state_machine,
        n1.principal_id,
        n1.neuron_id,
        &Proposal {
            title: Some("Stop registry canister".to_string()),
            action: Some(action),
            ..Default::default()
        },
    );
    let proposal_id = match propose_response.command.unwrap() {
        Command::MakeProposal(response) => response.proposal_id.unwrap(),
        _ => panic!("Propose didn't return MakeProposal"),
    };
    nns_wait_for_proposal_execution(&state_machine, proposal_id.id);

    // Step 4: Make sure the canister is stopped.
    assert_eq!(canister_status_type(), CanisterStatusType::Stopped);

    // Step 5: Make a proposal to start the canister and wait for it to be executed.
    let action = if use_proposal_action {
        Action::StopOrStartCanister(StopOrStartCanister {
            canister_id: Some(REGISTRY_CANISTER_ID.get()),
            action: Some(CanisterAction::Start as i32),
        })
    } else {
        let stop_or_start_request = StopOrStartCanisterRequest {
            canister_id: REGISTRY_CANISTER_ID,
            action: RootCanisterAction::Start,
        };
        Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::StopOrStartNnsCanister as i32,
            payload: Encode!(&stop_or_start_request).unwrap(),
        })
    };
    let propose_response = nns_governance_make_proposal(
        &state_machine,
        n1.principal_id,
        n1.neuron_id,
        &Proposal {
            title: Some("Start registry canister".to_string()),
            action: Some(action),
            ..Default::default()
        },
    );
    let proposal_id = match propose_response.command.unwrap() {
        Command::MakeProposal(response) => response.proposal_id.unwrap(),
        _ => panic!("Propose didn't return MakeProposal"),
    };
    nns_wait_for_proposal_execution(&state_machine, proposal_id.id);

    // Step 6: Make sure the canister is running.
    assert_eq!(canister_status_type(), CanisterStatusType::Running);
}

#[test]
fn stop_and_start_registry_by_action() {
    test_stop_and_start_registry_canister(true);
}

#[test]
fn stop_and_start_registry_by_nns_function() {
    test_stop_and_start_registry_canister(false);
}
