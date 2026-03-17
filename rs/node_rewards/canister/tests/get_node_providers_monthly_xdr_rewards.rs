use candid::Encode;
use ic_nervous_system_agent::AgentFor;
use ic_nervous_system_agent::nns::node_rewards::get_node_providers_monthly_xdr_rewards;
use ic_nns_constants::NODE_REWARDS_CANISTER_ID;
use ic_nns_test_utils::common::build_node_rewards_wasm;
use ic_node_rewards_canister_api::DateUtc;
use ic_node_rewards_canister_api::monthly_rewards::GetNodeProvidersMonthlyXdrRewardsRequest;
use ic_node_rewards_canister_api::provider_rewards_calculation::{
    GetNodeProvidersRewardsCalculationRequest, GetNodeProvidersRewardsCalculationResponse,
};
use ic_types::PrincipalId;
use pocket_ic::PocketIcBuilder;
use pocket_ic::common::rest::{IcpFeatures, IcpFeaturesConfig};
use pocket_ic::nonblocking::{PocketIc, query_candid, update_candid};
use std::time::Duration;

async fn setup_env() -> PocketIc {
    let icp_features = IcpFeatures {
        registry: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pocket_ic = PocketIcBuilder::new()
        .with_icp_features(icp_features)
        .with_sns_subnet()
        .with_nns_subnet()
        .build_async()
        .await;

    pocket_ic
        .create_canister_with_id(None, None, NODE_REWARDS_CANISTER_ID.get().0)
        .await
        .expect("Failed to create node rewards canister");

    pocket_ic
        .install_canister(
            NODE_REWARDS_CANISTER_ID.get().0,
            build_node_rewards_wasm().bytes(),
            Encode!().unwrap(),
            None,
        )
        .await;

    pocket_ic
}

#[tokio::test]
async fn get_node_providers_monthly_xdr_rewards_is_only_callable_by_governance() {
    let pocket_ic = setup_env().await;

    let request = GetNodeProvidersMonthlyXdrRewardsRequest {
        registry_version: None,
    };

    let anon_agent = pocket_ic.agent_for(PrincipalId::new_anonymous());
    let attempt_with_anonymous_caller =
        get_node_providers_monthly_xdr_rewards(&anon_agent, request.clone()).await;
    let error = attempt_with_anonymous_caller.unwrap_err();

    assert!(
        error.contains("Only the governance canister can call this method"),
        "Expected error message not found, was {error}"
    );

    let governance_agent = pocket_ic.agent_for(ic_nns_constants::GOVERNANCE_CANISTER_ID.get());
    let attempt_with_governance =
        get_node_providers_monthly_xdr_rewards(&governance_agent, request).await;
    assert!(attempt_with_governance.unwrap().error.is_none());
}

#[tokio::test]
async fn get_node_providers_rewards_calculation_is_only_callable_in_nonreplicated_mode() {
    let pocket_ic = setup_env().await;
    let node_rewards_id = NODE_REWARDS_CANISTER_ID.get().0;

    let past_time_nanos = pocket_ic.get_time().await.as_nanos_since_unix_epoch();
    pocket_ic.advance_time(Duration::from_secs(86_400)).await;
    pocket_ic.tick().await;
    let day = DateUtc::from_unix_timestamp_nanoseconds(past_time_nanos);

    let request = GetNodeProvidersRewardsCalculationRequest {
        day,
        algorithm_version: None,
    };

    // Non-replicated query call is allowed.
    let err = query_candid::<_, (GetNodeProvidersRewardsCalculationResponse,)>(
        &pocket_ic,
        node_rewards_id,
        "get_node_providers_rewards_calculation",
        (request.clone(),),
    )
    .await
    .unwrap()
    .0
    .unwrap_err();
    assert_eq!(err, "Metrics and registry are not synced up");

    // Replicated update call is not allowed.
    let err = update_candid::<_, (GetNodeProvidersRewardsCalculationResponse,)>(
        &pocket_ic,
        node_rewards_id,
        "get_node_providers_rewards_calculation",
        (request,),
    )
    .await
    .unwrap()
    .0
    .unwrap_err();
    assert_eq!(
        err,
        "Replicated execution of this method is not allowed. Use a non-replicated query call."
    );
}
