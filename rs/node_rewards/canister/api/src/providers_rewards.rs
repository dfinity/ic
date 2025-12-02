use crate::{DateUtc, RewardsCalculationAlgorithmVersion};
use candid::{CandidType, Deserialize, Principal};
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProvidersRewardsRequest {
    pub from_day: DateUtc,
    pub to_day: DateUtc,
    pub algorithm_version: Option<RewardsCalculationAlgorithmVersion>,
}
pub type GetNodeProvidersRewardsResponse = Result<NodeProvidersRewards, String>;

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct NodeProvidersRewards {
    pub rewards_xdr_permyriad: BTreeMap<Principal, u64>,
    pub algorithm_version: RewardsCalculationAlgorithmVersion,
}
