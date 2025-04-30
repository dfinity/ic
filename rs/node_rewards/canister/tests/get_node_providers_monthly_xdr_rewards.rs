use ic_nns_constants::NODE_REWARDS_CANISTER_ID;
use ic_nns_test_utils::state_test_helpers::{
    setup_nns_node_rewards_with_correct_canister_id, state_machine_builder_for_nns_tests,
    update_with_sender,
};
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
};
use ic_types::PrincipalId;

#[test]
fn get_node_providers_monthly_xdr_rewards_is_only_callable_by_governance() {
    let state_machine = state_machine_builder_for_nns_tests().build();
    setup_nns_node_rewards_with_correct_canister_id(&state_machine);

    let request = GetNodeProvidersMonthlyXdrRewardsRequest {
        registry_version: None,
    };

    let attempt_with_bad_caller: Result<GetNodeProvidersMonthlyXdrRewardsResponse, String> =
        update_with_sender(
            &state_machine,
            NODE_REWARDS_CANISTER_ID,
            "get_node_providers_monthly_xdr_rewards",
            request.clone(),
            PrincipalId::new_user_test_id(1),
        );
    let actual_error = attempt_with_bad_caller.unwrap_err();

    assert!(
        actual_error.contains("Only the governance canister can call this method"),
        "Expected error message not found, was {}",
        actual_error
    );

    let attempt_with_governance: Result<GetNodeProvidersMonthlyXdrRewardsResponse, String> =
        update_with_sender(
            &state_machine,
            NODE_REWARDS_CANISTER_ID,
            "get_node_providers_monthly_xdr_rewards",
            request,
            ic_nns_constants::GOVERNANCE_CANISTER_ID.get(),
        );

    let error = attempt_with_governance.unwrap().error.unwrap();

    // Registry canister isn't installed, so this is the expected error when you use the right caller.
    assert!(
        error.contains("Could not sync registry store to latest version, please try again later"),
        "Expected error response not found, was {}",
        error
    );
}
