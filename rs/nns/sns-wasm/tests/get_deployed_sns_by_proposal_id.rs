use crate::common::{get_deployed_sns_by_proposal_id, get_deployed_sns_by_proposal_id_unchecked};
use common::set_up_state_machine_with_nns;
use ic_nervous_system_common::ONE_TRILLION;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, NODE_REWARDS_CANISTER_INDEX_IN_NNS_SUBNET, SNS_WASM_CANISTER_ID,
};
use ic_nns_test_utils::sns_wasm;
use ic_sns_init::pb::v1::{DappCanisters, SnsInitPayload};
use ic_sns_wasm::pb::v1::{
    DappCanistersTransferResult, DeployNewSnsResponse, GetDeployedSnsByProposalIdResponse,
    SnsCanisterIds, get_deployed_sns_by_proposal_id_response::GetDeployedSnsByProposalIdResult,
};
use ic_test_utilities_types::ids::canister_test_id;

pub mod common;

#[test]
fn test_get_deployed_sns_by_proposal_id() {
    // Setup the state machine
    let machine = set_up_state_machine_with_nns();

    // Add cycles to the SNS-W canister to deploy the SNS
    machine.add_cycles(SNS_WASM_CANISTER_ID, 200 * ONE_TRILLION as u128);

    // Add the Wasms of the SNS canisters to SNS-W
    sns_wasm::add_real_wasms_to_sns_wasms(&machine);

    // Add the dapp to the SnsInitPayload
    let sns_init_payload = SnsInitPayload {
        dapp_canisters: Some(DappCanisters { canisters: vec![] }),
        ..SnsInitPayload::with_valid_values_for_testing_post_execution()
    };
    let proposal_id = *sns_init_payload.nns_proposal_id.as_ref().unwrap();

    // Call the code under test
    let response = sns_wasm::deploy_new_sns(
        &machine,
        GOVERNANCE_CANISTER_ID,
        SNS_WASM_CANISTER_ID,
        sns_init_payload,
    );

    let highest_nns_created_canister_index = NODE_REWARDS_CANISTER_INDEX_IN_NNS_SUBNET;

    let root_canister_id = canister_test_id(highest_nns_created_canister_index + 1);
    let governance_canister_id = canister_test_id(highest_nns_created_canister_index + 2);
    let ledger_canister_id = canister_test_id(highest_nns_created_canister_index + 3);
    let swap_canister_id = canister_test_id(highest_nns_created_canister_index + 4);
    let index_canister_id = canister_test_id(highest_nns_created_canister_index + 5);

    assert_eq!(
        response,
        DeployNewSnsResponse {
            subnet_id: Some(machine.get_subnet_id().get()),
            canisters: Some(SnsCanisterIds {
                governance: Some(governance_canister_id.get()),
                root: Some(root_canister_id.get()),
                ledger: Some(ledger_canister_id.get()),
                swap: Some(swap_canister_id.get()),
                index: Some(index_canister_id.get()),
            }),
            error: None,
            dapp_canisters_transfer_result: Some(DappCanistersTransferResult {
                restored_dapp_canisters: vec![],
                nns_controlled_dapp_canisters: vec![],
                sns_controlled_dapp_canisters: vec![],
            }),
        }
    );

    // Make sure the recorded DeployedSns matches the ProposalId in the SnsInitPayload
    let deployed_sns = get_deployed_sns_by_proposal_id_unchecked(&machine, proposal_id);

    assert_eq!(
        deployed_sns.governance_canister_id,
        Some(governance_canister_id.get())
    );
    assert_eq!(deployed_sns.root_canister_id, Some(root_canister_id.get()));
    assert_eq!(deployed_sns.swap_canister_id, Some(swap_canister_id.get()));
    assert_eq!(
        deployed_sns.ledger_canister_id,
        Some(ledger_canister_id.get())
    );
    assert_eq!(
        deployed_sns.index_canister_id,
        Some(index_canister_id.get())
    );

    // Assert an Error is returned if given a bogus proposal id
    let response: GetDeployedSnsByProposalIdResponse =
        get_deployed_sns_by_proposal_id(&machine, 42);
    assert!(matches!(
        response.get_deployed_sns_by_proposal_id_result.unwrap(),
        GetDeployedSnsByProposalIdResult::Error(_)
    ))
}
