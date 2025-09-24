pub use crate::DayUtc;
use candid::{CandidType, Deserialize, Principal};
use ic_base_types::PrincipalId;
use ic_nervous_system_proto::pb::v1::Decimal;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProviderRewardsCalculationRequest {
    pub from_day: DayUtc,
    pub to_day: DayUtc,
    pub provider_id: Principal,
}

pub type GetNodeProviderRewardsCalculationResponse = Result<Vec<NodeProviderRewardsDaily>, String>;

// These are API-facing types with all fields wrapped in `Option`
// to ensure forward compatibility. This way, new fields can be added
// in the future without breaking clients that consume the API.
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
pub struct NodeResults {
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
pub struct BaseRewardsType3 {
    pub region: Option<String>,
    pub nodes_count: Option<u64>,
    pub avg_rewards_xdr_permyriad: Option<Decimal>,
    pub avg_coefficient_percent: Option<Decimal>,
    pub value_xdr_permyriad: Option<Decimal>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct NodeProviderRewards {
    pub rewards_total_xdr_permyriad: Option<Decimal>,
    pub base_rewards: Vec<BaseRewards>,
    pub base_rewards_type3: Vec<BaseRewardsType3>,
    pub nodes_results: Vec<NodeResults>,
}

#[derive(CandidType, candid::Deserialize, Clone, Debug)]
pub struct NodeProviderRewardsDaily {
    pub day_utc: Option<DayUtc>,
    pub node_provider_rewards: Option<NodeProviderRewards>,
}
