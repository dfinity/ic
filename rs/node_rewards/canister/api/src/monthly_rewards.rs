use candid::{CandidType, Deserialize, Principal};
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProvidersMonthlyXdrRewardsRequest {
    pub registry_version: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct GetNodeProvidersMonthlyXdrRewardsResponse {
    pub rewards: Option<NodeProvidersMonthlyXdrRewards>,
    pub error: Option<String>,
}

// This is a duplicate of the Registry's NodeProvidersMonthlyXdrRewards struct
// We redefine it so that it can change independently of the Registry's definition, and we can
// remove the Registry's definition eventually.  But it must be compatible until Node Rewards Canister
// is calculating rewards
#[derive(candid::CandidType, candid::Deserialize, Debug, PartialEq)]
pub struct NodeProvidersMonthlyXdrRewards {
    pub rewards: BTreeMap<Principal, u64>,
    /// Registry version at which rewards were calculated
    pub registry_version: ::core::option::Option<u64>,
}
