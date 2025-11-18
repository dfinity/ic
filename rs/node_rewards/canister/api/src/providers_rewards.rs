use crate::{DateUtc, RewardsCalculationVersion};
use candid::{CandidType, Deserialize, Principal};
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProvidersRewardsRequest {
    pub from_day: DateUtc,
    pub to_day: DateUtc,
    pub rewards_calculation_version: Option<RewardsCalculationVersion>,
}
pub type GetNodeProvidersRewardsResponse = Result<NodeProvidersRewards, String>;

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct NodeProvidersRewards {
    pub rewards_xdr_permyriad: BTreeMap<Principal, u64>,
    pub rewards_calculation_version: RewardsCalculationVersion,
}
