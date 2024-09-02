use candid::{Decode, Encode, Principal};
use ic_sns_swap::pb::v1::{
    GetStateRequest, GetStateResponse, Init, NeuronBasketConstructionParameters,
};
use ic_sns_test_utils::state_test_helpers::state_machine_builder_for_sns_tests;
use pretty_assertions::assert_eq;

#[test]
fn test_upgrade() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    // install the swap canister
    let wasm = ic_test_utilities_load_wasm::load_wasm("../swap", "sns-swap-canister", &[]);
    let args = Encode!(&Init {
        nns_governance_canister_id: Principal::anonymous().to_string(),
        sns_governance_canister_id: Principal::anonymous().to_string(),
        sns_ledger_canister_id: Principal::anonymous().to_string(),
        icp_ledger_canister_id: Principal::anonymous().to_string(),
        sns_root_canister_id: Principal::anonymous().to_string(),
        fallback_controller_principal_ids: vec![Principal::anonymous().to_string()],
        transaction_fee_e8s: Some(10_000),
        neuron_minimum_stake_e8s: Some(1_000_000),
        confirmation_text: None,
        restricted_countries: None,
        min_participants: Some(5),
        min_icp_e8s: None,
        max_icp_e8s: None,
        min_direct_participation_icp_e8s: Some(12_300_000_000),
        max_direct_participation_icp_e8s: Some(65_000_000_000),
        min_participant_icp_e8s: Some(6_500_000_000),
        max_participant_icp_e8s: Some(65_000_000_000),
        swap_start_timestamp_seconds: Some(0),
        swap_due_timestamp_seconds: Some(u64::MAX),
        sns_token_e8s: Some(10_000_000),
        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 5,
            dissolve_delay_interval_seconds: 10_001,
        }),
        nns_proposal_id: Some(10),
        should_auto_finalize: Some(true),
        neurons_fund_participation_constraints: None,
        neurons_fund_participation: Some(false),
    })
    .unwrap();
    let canister_id = state_machine
        .install_canister(wasm.clone(), args, None)
        .unwrap();

    // get the state before upgrading
    let args = Encode!(&GetStateRequest {}).unwrap();
    let state_before_upgrade = state_machine
        .execute_ingress(canister_id, "get_state", args)
        .expect("Unable to call get_state on the Swap canister");
    let state_before_upgrade = Decode!(&state_before_upgrade.bytes(), GetStateResponse).unwrap();

    // upgrade the canister
    state_machine
        .upgrade_canister(canister_id, wasm, Encode!(&()).unwrap())
        .expect("Swap pre_upgrade or post_upgrade failed");

    // get the state after upgrading and verify it
    let args = Encode!(&GetStateRequest {}).unwrap();
    let state_after_upgrade = state_machine
        .execute_ingress(canister_id, "get_state", args)
        .expect("Unable to call get_state on the Swap canister");
    let state_after_upgrade = Decode!(&state_after_upgrade.bytes(), GetStateResponse).unwrap();
    assert_eq!(state_before_upgrade, state_after_upgrade);
}
