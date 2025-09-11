use candid::Encode;
use ic_base_types::CanisterId;
use ic_nervous_system_clients::canister_id_record::CanisterIdRecord;
use ic_nns_constants::LIFELINE_CANISTER_INDEX_IN_NNS_SUBNET;
use ic_nns_governance_api::{
    ExecuteNnsFunction, MakeProposalRequest, NnsFunction, ProposalActionRequest,
    manage_neuron_response::{Command, MakeProposalResponse},
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::get_neuron_1,
    state_test_helpers::{
        get_canister_status_from_root, nns_governance_make_proposal, setup_nns_canisters,
        state_machine_builder_for_nns_tests,
    },
};
use ic_state_machine_tests::StateMachine;

/*
Title:: Uninstall a canister from a subnet via proposal

Goal:: Ensure that canisters can be uninstalled via proposals submitted to the Governance Canister.

Runbook::
. Setup: StateMachine of the replica with installed NNS canisters.
. Assert that `update` call executes successfully on a test canister (lifeline_canister).
. Submit a proposal to the Governance Canister to uninstall the test canister code.
. Assert that `update` call fails on the test canister.

Success::
. Update call executes successfully on the test canister after its installation.
. Update call fails on the test canister after the proposal to uninstall code of this canister is executed.
*/

fn setup_state_machine_with_nns_canisters() -> StateMachine {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    state_machine
}

#[test]
fn uninstall_canister_by_proposal() {
    let state_machine = setup_state_machine_with_nns_canisters();
    // Pick some installed nns canister for testing
    let canister_id = CanisterId::from_u64(LIFELINE_CANISTER_INDEX_IN_NNS_SUBNET);
    // Confirm that canister exists and has some code installed (module_hash is Some)
    assert!(state_machine.canister_exists(canister_id));
    let status = get_canister_status_from_root(&state_machine, canister_id);
    assert!(status.module_hash.is_some());
    // Prepare a proposal to uninstall canister code
    let proposal = MakeProposalRequest {
        title: Some("<proposal to uninstall an NNS canister>".to_string()),
        summary: "".to_string(),
        url: "".to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: NnsFunction::UninstallCode as i32,
                payload: Encode!(&CanisterIdRecord { canister_id })
                    .expect("Error encoding proposal payload"),
            },
        )),
    };
    // To make a proposal we need a neuron
    let n1 = get_neuron_1();
    // Execute a proposal
    let response =
        nns_governance_make_proposal(&state_machine, n1.principal_id, n1.neuron_id, &proposal)
            .command
            .expect("Making NNS proposal failed");
    let _proposal_id = match response {
        Command::MakeProposal(MakeProposalResponse {
            proposal_id: Some(ic_nns_common::pb::v1::ProposalId { id }),
            ..
        }) => id,
        _ => panic!("Response did not contain a proposal_id: {response:#?}"),
    };
    // Verify that the canister no longer has code install (module_hash is None)
    let status = get_canister_status_from_root(&state_machine, canister_id);
    assert_eq!(status.module_hash, None);
    // Canister itself should still exist though
    assert!(state_machine.canister_exists(canister_id));
}
