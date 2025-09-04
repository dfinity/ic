use candid::{CandidType, Deserialize, Principal};
use ic_node_rewards_canister_protobuf::pb::rewards_calculator::v1::NodeProviderRewards;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProviderRewardsCalculationRequest {
    pub day_timestamp_nanos: u64,
    pub provider_id: Principal,
}

pub type GetNodeProviderRewardsCalculationResponse = Result<NodeProviderRewards, String>;
