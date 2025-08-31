use candid::{CandidType, Deserialize, Principal};
use ic_node_rewards_canister_protobuf::pb::rewards_calculator::v1::NodeProviderRewards;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProviderRewardsCalculationRequest {
    pub from_nanos: u64,
    pub to_nanos: u64,
    pub provider_id: Principal,
    pub historical: bool,
}

pub type GetNodeProviderRewardsCalculationResponse = Result<NodeProviderRewards, String>;

#[derive(CandidType, Clone, Deserialize, Debug, PartialEq, Eq)]
pub struct HistoricalRewardPeriod {
    pub from_nanos: u64,
    pub to_nanos: u64,
    pub providers_rewarded: Vec<Principal>,
}
pub type GetHistoricalRewardPeriods = Vec<HistoricalRewardPeriod>;
