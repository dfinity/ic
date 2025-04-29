use futures_util::FutureExt;
use ic_nervous_system_agent::nns::node_rewards::get_node_providers_monthly_xdr_rewards;
use ic_nervous_system_agent::state_machine_impl::StateMachineAgent;
use ic_nervous_system_agent::AgentFor;
use ic_nervous_system_integration_tests::pocket_ic_helpers::NnsInstaller;
use ic_nns_constants::NODE_REWARDS_CANISTER_ID;
use ic_nns_test_utils::state_test_helpers::{
    setup_nns_node_rewards_with_correct_canister_id, state_machine_builder_for_nns_tests,
    update_with_sender,
};
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
};
use ic_types::PrincipalId;
use pocket_ic::PocketIcBuilder;

#[tokio::test]
async fn get_node_providers_monthly_xdr_rewards_is_only_callable_by_governance() {
    let pocket_ic = PocketIcBuilder::new()
        .with_sns_subnet()
        .with_nns_subnet()
        .build_async()
        .await;
    let mut nns_installer = NnsInstaller::default();
    nns_installer.with_current_nns_canister_versions();
    nns_installer.with_node_rewards_canister();
    nns_installer.install(&pocket_ic).await;

    let request = GetNodeProvidersMonthlyXdrRewardsRequest {
        registry_version: None,
    };

    let attempt_with_anonymous_caller =
        get_node_providers_monthly_xdr_rewards(&pocket_ic, request.clone()).await;
    let error = attempt_with_anonymous_caller.unwrap_err();

    assert!(
        error.contains("Only the governance canister can call this method"),
        "Expected error message not found, was {}",
        error
    );
    let governance_agent = pocket_ic.agent_for(ic_nns_constants::GOVERNANCE_CANISTER_ID.get());

    let attempt_with_governance =
        get_node_providers_monthly_xdr_rewards(&governance_agent, request).await;
    let error = attempt_with_governance.unwrap().error.unwrap();

    // Registry canister isn't installed, so this is the expected error when you use the right caller.
    assert!(
        error.contains("Could not sync registry store to latest version, please try again later"),
        "Expected error response not found, was {}",
        error
    );
}
