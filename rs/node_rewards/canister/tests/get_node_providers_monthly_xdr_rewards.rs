use futures_util::FutureExt;
use ic_nervous_system_agent::nns::node_rewards::get_node_providers_monthly_xdr_rewards;
use ic_nervous_system_agent::state_machine_impl::StateMachineAgent;
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

    let bad_agent = StateMachineAgent::new(&state_machine, PrincipalId::new_anonymous());

    let attempt_with_bad_caller =
        get_node_providers_monthly_xdr_rewards(&bad_agent, request.clone())
            .now_or_never()
            .unwrap();
    let error = attempt_with_bad_caller.unwrap_err();

    assert!(
        error.contains("Only the governance canister can call this method"),
        "Expected error message not found, was {}",
        error
    );
    let governance_agent = StateMachineAgent::new(
        &state_machine,
        ic_nns_constants::GOVERNANCE_CANISTER_ID.get(),
    );

    let attempt_with_governance =
        get_node_providers_monthly_xdr_rewards(&governance_agent, request)
            .now_or_never()
            .unwrap();
    let error = attempt_with_governance.unwrap().error.unwrap();

    // Registry canister isn't installed, so this is the expected error when you use the right caller.
    assert!(
        error.contains("Could not sync registry store to latest version, please try again later"),
        "Expected error response not found, was {}",
        error
    );
}
