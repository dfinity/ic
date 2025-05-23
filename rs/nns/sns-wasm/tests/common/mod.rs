use candid::Encode;
use canister_test::Project;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_nervous_system_common::ONE_TRILLION;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_test_utils::{
    common::{NnsInitPayloads, NnsInitPayloadsBuilder},
    state_test_helpers::{create_canister, setup_nns_canisters, update_with_sender},
};
use ic_sns_wasm::pb::v1::{
    get_deployed_sns_by_proposal_id_response::GetDeployedSnsByProposalIdResult, DeployedSns,
    GetDeployedSnsByProposalIdRequest, GetDeployedSnsByProposalIdResponse,
};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_test_utilities_execution_environment::get_routing_table_with_specified_ids_allocation_range;
use std::str::FromStr;

pub const EXPECTED_SNS_CREATION_FEE: u128 = 180 * ONE_TRILLION as u128;

/// Create a `StateMachine` with NNS installed
pub fn set_up_state_machine_with_nns() -> StateMachine {
    let subnet_id: SubnetId =
        PrincipalId::from_str("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .unwrap()
            .into();
    let routing_table = get_routing_table_with_specified_ids_allocation_range(subnet_id).unwrap();
    let machine = StateMachineBuilder::new()
        .with_current_time()
        .with_routing_table(routing_table)
        .with_subnet_id(subnet_id)
        .build();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .with_sns_wasm_access_controls(true)
        .build();

    setup_nns_canisters(&machine, nns_init_payload);
    machine
}

pub fn install_sns_wasm(machine: &StateMachine, nns_init_payload: &NnsInitPayloads) -> CanisterId {
    let sns_wasm_bin = Project::cargo_bin_maybe_from_env("sns-wasm-canister", &[]);

    create_canister(
        machine,
        sns_wasm_bin,
        Some(Encode!(&nns_init_payload.sns_wasms.clone()).unwrap()),
        None,
    )
}

pub fn get_deployed_sns_by_proposal_id(
    machine: &StateMachine,
    proposal_id: u64,
) -> GetDeployedSnsByProposalIdResponse {
    update_with_sender(
        machine,
        SNS_WASM_CANISTER_ID,
        "get_deployed_sns_by_proposal_id",
        GetDeployedSnsByProposalIdRequest { proposal_id },
        PrincipalId::new_anonymous(),
    )
    .unwrap()
}

pub fn get_deployed_sns_by_proposal_id_unchecked(
    machine: &StateMachine,
    proposal_id: u64,
) -> DeployedSns {
    // Make sure the recorded DeployedSns matches the ProposalId in the SnsInitPayload
    let response: GetDeployedSnsByProposalIdResponse =
        get_deployed_sns_by_proposal_id(machine, proposal_id);

    match response.get_deployed_sns_by_proposal_id_result.unwrap() {
        GetDeployedSnsByProposalIdResult::DeployedSns(deployed_sns) => deployed_sns,
        GetDeployedSnsByProposalIdResult::Error(message) => panic!(
            "Expected Ok response from get_deployed_sns_by_proposal_id. Instead, got {:?}",
            message
        ),
    }
}
