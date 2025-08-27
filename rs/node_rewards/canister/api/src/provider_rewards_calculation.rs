use candid::{CandidType, Deserialize, Principal};
use ic_node_rewards_canister_protobuf::pb::rewards_calculator::v1::NodeProviderRewards;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProviderRewardsCalculationRequest {
    pub from_nanos: u64,
    pub to_nanos: u64,
    pub provider_id: Principal,
}

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub enum GetNodeProviderRewardsCalculationResponse {
    Ok(NodeProviderRewards),
    Err(String),
}
