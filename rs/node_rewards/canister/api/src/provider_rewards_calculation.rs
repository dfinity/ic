use candid::{CandidType, Deserialize, Principal};
#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProviderRewardsCalculationRequest {
    pub from_nanos: u64,
    pub to_nanos: u64,
    pub provider_id: Principal,
}

pub type GetNodeProviderRewardsCalculationResponse = Result<NodeProviderRewards, String>;

#[derive(
    PartialOrd, Ord, Eq, candid::CandidType, candid::Deserialize, Clone, Copy, PartialEq, Debug,
)]
pub struct DayUtc {
    pub value: Option<u64>,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct NodeMetricsDaily {
    pub subnet_assigned: Option<::ic_base_types::PrincipalId>,
    pub subnet_assigned_fr_percent: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    pub num_blocks_proposed: Option<u64>,
    pub num_blocks_failed: Option<u64>,
    pub original_fr_percent: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    pub relative_fr_percent: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct Assigned {
    pub node_metrics: Option<NodeMetricsDaily>,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct Unassigned {
    pub extrapolated_fr_percent: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct NodeStatus {
    pub status: Option<node_status::Status>,
}

/// Nested message and enum types in `NodeStatus`.
pub mod node_status {
    #[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
    pub enum Status {
        Assigned(super::Assigned),
        Unassigned(super::Unassigned),
    }
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct DailyResults {
    pub day: Option<DayUtc>,
    pub node_status: Option<NodeStatus>,
    pub performance_multiplier_percent: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    pub rewards_reduction_percent: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    pub base_rewards_xdr_permyriad: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    pub adjusted_rewards_xdr_permyriad: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct NodeResults {
    pub node_id: Option<::ic_base_types::PrincipalId>,
    pub node_reward_type: Option<String>,
    pub region: Option<String>,
    pub dc_id: Option<String>,
    pub daily_results: Vec<DailyResults>,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct BaseRewards {
    pub monthly_xdr_permyriad: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    pub daily_xdr_permyriad: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    pub node_reward_type: Option<String>,
    pub region: Option<String>,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct DailyBaseRewardsType3 {
    pub day: Option<DayUtc>,
    pub region: Option<String>,
    pub nodes_count: Option<u64>,
    pub avg_rewards_xdr_permyriad: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    pub avg_coefficient_percent: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    pub value_xdr_permyriad: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct NodeProviderRewards {
    pub rewards_total_xdr_permyriad: Option<u64>,
    pub base_rewards: Vec<BaseRewards>,
    pub base_rewards_type3: Vec<DailyBaseRewardsType3>,
    pub nodes_results: Vec<NodeResults>,
}
