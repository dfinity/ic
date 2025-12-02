pub use crate::DateUtc;
use crate::RewardsCalculationAlgorithmVersion;
use candid::{CandidType, Deserialize};
use ic_base_types::{PrincipalId, SubnetId};
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProvidersRewardsCalculationRequest {
    pub day: DateUtc,
    pub algorithm_version: Option<RewardsCalculationAlgorithmVersion>,
}

// TODO: Remove useless level of indirection: https://github.com/dfinity/ic/pull/7071/files#r2406450031
pub type GetNodeProvidersRewardsCalculationResponse = Result<DailyResults, String>;

// These are API-facing types with all fields wrapped in `Option`
// to ensure forward compatibility. This way, new fields can be added
// in the future without breaking clients that consume the API.
//
// Check rewards_calculation/performance_based_algorithm/results.rs for the explanations of the fields.
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct NodeMetricsDaily {
    pub subnet_assigned: Option<PrincipalId>,
    pub subnet_assigned_failure_rate: Option<f64>,
    pub num_blocks_proposed: Option<u64>,
    pub num_blocks_failed: Option<u64>,
    pub original_failure_rate: Option<f64>,
    pub relative_failure_rate: Option<f64>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub enum DailyNodeFailureRate {
    SubnetMember {
        node_metrics: Option<NodeMetricsDaily>,
    },
    NonSubnetMember {
        extrapolated_failure_rate: Option<f64>,
    },
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct DailyNodeRewards {
    pub node_id: Option<PrincipalId>,
    pub node_reward_type: Option<String>,
    pub region: Option<String>,
    pub dc_id: Option<String>,
    pub daily_node_failure_rate: Option<DailyNodeFailureRate>,
    pub performance_multiplier: Option<f64>,
    pub rewards_reduction: Option<f64>,
    pub base_rewards_xdr_permyriad: Option<f64>,
    pub adjusted_rewards_xdr_permyriad: Option<f64>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct NodeTypeRegionBaseRewards {
    pub monthly_xdr_permyriad: Option<f64>,
    pub daily_xdr_permyriad: Option<f64>,
    pub node_reward_type: Option<String>,
    pub region: Option<String>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct Type3RegionBaseRewards {
    pub region: Option<String>,
    pub nodes_count: Option<u64>,
    pub avg_rewards_xdr_permyriad: Option<f64>,
    pub avg_coefficient: Option<f64>,
    pub daily_xdr_permyriad: Option<f64>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct DailyNodeProviderRewards {
    pub total_base_rewards_xdr_permyriad: Option<u64>,
    pub total_adjusted_rewards_xdr_permyriad: Option<u64>,
    pub base_rewards: Vec<NodeTypeRegionBaseRewards>,
    pub base_rewards_type3: Vec<Type3RegionBaseRewards>,
    pub daily_nodes_rewards: Vec<DailyNodeRewards>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct DailyResults {
    pub subnets_failure_rate: BTreeMap<SubnetId, f64>,
    pub provider_results: BTreeMap<PrincipalId, DailyNodeProviderRewards>,
}
