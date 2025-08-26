use crate::DayUtc;
use candid::{CandidType, Deserialize, Principal};
use ic_node_rewards_canister_protobuf::pb::rewards_calculator::v1::NodeProviderRewards;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProviderRewardsCalculationRequest {
    pub from: DayUtc,
    pub to: DayUtc,
    pub provider_id: Principal,
}

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct GetNodeProviderRewardsCalculationResponse {
    pub rewards: Option<NodeProviderRewards>,
    pub error: Option<String>,
}
