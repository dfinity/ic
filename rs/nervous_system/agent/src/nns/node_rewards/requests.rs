use crate::Request;
use candid::Error;
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
};

impl Request for GetNodeProvidersMonthlyXdrRewardsRequest {
    fn method(&self) -> &'static str {
        "get_node_providers_monthly_xdr_rewards"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, Error> {
        candid::encode_one(self)
    }

    type Response = GetNodeProvidersMonthlyXdrRewardsResponse;
}
