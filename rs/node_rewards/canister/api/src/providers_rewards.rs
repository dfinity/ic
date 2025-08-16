use candid::{CandidType, Deserialize, Principal};
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProvidersRewardsRequest {
    /// These timestamps cover the entire correspondent UTC day and are inclusive.
    pub from_timestamp_nanoseconds: u64,
    pub to_timestamp_nanoseconds: u64,
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
