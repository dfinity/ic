use candid::{CandidType, Deserialize, Principal};
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProvidersRewardsRequest {
    pub from: u64,
    pub to: u64,
}

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProvidersRewardsResponse {
    pub rewards: BTreeMap<Principal, u64>,
}
