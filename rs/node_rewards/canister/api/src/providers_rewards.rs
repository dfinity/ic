use candid::{CandidType, Deserialize, Principal};
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProvidersRewardsRequest {
    /// Start of the reward distribution period, as a Unix timestamp in nanoseconds.
    /// This timestamp is covers the entire correspondent UTC day and is inclusive.
    pub from_timestamp_nanoseconds: u64,
    /// End of the reward distribution period, as a Unix timestamp in nanoseconds.
    /// This timestamp is covers the entire correspondent UTC day and is inclusive.
    pub to: u64,
}

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProvidersRewardsResponse {
    pub rewards: BTreeMap<Principal, u64>,
}
