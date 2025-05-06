use crate::CallCanisters;
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
};

pub mod requests;

pub async fn get_node_providers_monthly_xdr_rewards<C: CallCanisters>(
    agent: &C,
    request: GetNodeProvidersMonthlyXdrRewardsRequest,
) -> Result<GetNodeProvidersMonthlyXdrRewardsResponse, String> {
    agent
        .call(ic_nns_constants::NODE_REWARDS_CANISTER_ID, request)
        .await
        .map_err(|e| format!("{e}"))
}
