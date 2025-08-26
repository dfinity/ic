use crate::DayUtc;
use candid::{CandidType, Deserialize, Principal};
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProvidersRewardsRequest {
    pub from: DayUtc,
    pub to: DayUtc,
}

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct GetNodeProvidersRewardsResponse {
    pub rewards: Option<NodeProvidersRewards>,
    pub error: Option<String>,
}

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct NodeProvidersRewards {
    pub rewards_xdr_permyriad: BTreeMap<Principal, u64>,
}
