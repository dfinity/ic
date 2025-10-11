pub use crate::DateUtc;
use candid::{CandidType, Deserialize};
use ic_base_types::{PrincipalId, SubnetId};
use ic_nervous_system_proto::pb::v1::Decimal;
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProviderRewardsCalculationRequest {
    pub day: DateUtc,
}

pub type GetNodeProviderRewardsCalculationResponse = Result<DailyResults, String>;

// These are API-facing types with all fields wrapped in `Option`
// to ensure forward compatibility. This way, new fields can be added
// in the future without breaking clients that consume the API.
//
// Check rewards_calculation/performance_based_algorithm/results.rs for the explanations of the fields.
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct NodeMetricsDaily {
    pub subnet_assigned: Option<PrincipalId>,
    pub subnet_assigned_fr_percent: Option<Decimal>,
    pub num_blocks_proposed: Option<u64>,
    pub num_blocks_failed: Option<u64>,
    pub original_fr_percent: Option<Decimal>,
    pub relative_fr_percent: Option<Decimal>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub enum NodeStatus {
    Assigned {
        node_metrics: Option<NodeMetricsDaily>,
    },
    Unassigned {
        extrapolated_fr_percent: Option<Decimal>,
    },
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct DailyNodeRewards {
    pub node_id: Option<PrincipalId>,
    pub node_reward_type: Option<String>,
    pub region: Option<String>,
    pub dc_id: Option<String>,
    pub node_status: Option<NodeStatus>,
    pub performance_multiplier_percent: Option<Decimal>,
    pub rewards_reduction_percent: Option<Decimal>,
    pub base_rewards_xdr_permyriad: Option<Decimal>,
    pub adjusted_rewards_xdr_permyriad: Option<Decimal>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct BaseRewards {
    pub monthly_xdr_permyriad: Option<Decimal>,
    pub daily_xdr_permyriad: Option<Decimal>,
    pub node_reward_type: Option<String>,
    pub region: Option<String>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct Type3BaseRewards {
    pub region: Option<String>,
    pub nodes_count: Option<u64>,
    pub avg_rewards_xdr_permyriad: Option<Decimal>,
    pub avg_coefficient_percent: Option<Decimal>,
    pub value_xdr_permyriad: Option<Decimal>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct DailyNodeProviderRewards {
    pub rewards_total_xdr_permyriad: Option<Decimal>,
    pub base_rewards: Vec<BaseRewards>,
    pub base_rewards_type3: Vec<Type3BaseRewards>,
    pub nodes_results: Vec<DailyNodeRewards>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct DailyResults {
    pub subnets_fr: BTreeMap<SubnetId, Decimal>,
    pub provider_results: BTreeMap<PrincipalId, DailyNodeProviderRewards>,
}
