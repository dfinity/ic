use crate::DateUtc;
use candid::{CandidType, Deserialize, Principal};
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetRewardableNodesRequest {
    pub day: DateUtc,
}

pub type GetRewardableNodesResponse = Result<RewardableNodesResult, String>;

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq)]
pub struct RewardableNodeApi {
    pub node_id: Option<Principal>,
    pub region: Option<String>,
    pub node_reward_type: Option<i32>,
    pub dc_id: Option<String>,
}

#[derive(CandidType, Deserialize, Debug, Clone, PartialEq)]
pub struct RewardableNodesResult {
    pub rewardable_nodes: BTreeMap<Principal, Vec<RewardableNodeApi>>,
}
