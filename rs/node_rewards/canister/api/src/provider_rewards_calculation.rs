use candid::{CandidType, Deserialize, Principal};
use ic_base_types::PrincipalId;
use ic_nervous_system_proto::pb::v1::Decimal;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProviderRewardsCalculationRequest {
    pub from_day_timestamp_nanos: u64,
    pub to_day_timestamp_nanos: u64,
    pub provider_id: Principal,
}

pub type GetNodeProviderRewardsCalculationResponse = Result<Vec<NodeProviderRewardsDaily>, String>;

#[derive(CandidType, candid::Deserialize, Clone, Debug)]
pub struct NodeProviderRewardsDaily {
    pub node_provider_rewards: NodeProviderRewards,
    pub day_utc: DayUtc,
}

#[derive(
    PartialOrd, Ord, Eq, candid::CandidType, candid::Deserialize, Clone, Copy, PartialEq, Debug,
)]
pub struct DayUtc {
    pub value: Option<u64>,
}

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
    pub rewards_total_xdr_permyriad: Option<u64>,
    pub base_rewards: Vec<BaseRewards>,
    pub base_rewards_type3: Vec<BaseRewardsType3>,
    pub nodes_results: Vec<NodeResults>,
}

impl From<rewards_calculation::rewards_calculator_results::BaseRewards> for BaseRewards {
    fn from(value: rewards_calculation::rewards_calculator_results::BaseRewards) -> Self {
        Self {
            monthly_xdr_permyriad: Some(value.monthly.into()),
            daily_xdr_permyriad: Some(value.daily.into()),
            node_reward_type: Some(value.node_reward_type.to_string()),
            region: Some(value.region.to_string()),
        }
    }
}

impl From<rewards_calculation::rewards_calculator_results::BaseRewardsType3> for BaseRewardsType3 {
    fn from(value: rewards_calculation::rewards_calculator_results::BaseRewardsType3) -> Self {
        Self {
            region: Some(value.region),
            nodes_count: Some(value.nodes_count as u64),
            avg_coefficient_percent: Some(value.avg_coefficient.into()),
            avg_rewards_xdr_permyriad: Some(value.avg_rewards.into()),
            value_xdr_permyriad: Some(value.value.into()),
        }
    }
}

impl From<rewards_calculation::rewards_calculator_results::NodeStatus> for NodeStatus {
    fn from(value: rewards_calculation::rewards_calculator_results::NodeStatus) -> Self {
        match value {
            rewards_calculation::rewards_calculator_results::NodeStatus::Assigned {
                node_metrics,
            } => Self::Assigned {
                node_metrics: Some(node_metrics.into()),
            },
            rewards_calculation::rewards_calculator_results::NodeStatus::Unassigned {
                extrapolated_fr,
            } => Self::Unassigned {
                extrapolated_fr_percent: Some(extrapolated_fr.into()),
            },
        }
    }
}

impl From<rewards_calculation::rewards_calculator_results::NodeMetricsDaily> for NodeMetricsDaily {
    fn from(value: rewards_calculation::rewards_calculator_results::NodeMetricsDaily) -> Self {
        Self {
            subnet_assigned: Some(value.subnet_assigned.get()),
            subnet_assigned_fr_percent: Some(value.subnet_assigned_fr.into()),
            num_blocks_proposed: Some(value.num_blocks_proposed),
            num_blocks_failed: Some(value.num_blocks_failed),
            original_fr_percent: Some(value.original_fr.into()),
            relative_fr_percent: Some(value.relative_fr.into()),
        }
    }
}

impl From<rewards_calculation::rewards_calculator_results::NodeProviderRewards>
    for NodeProviderRewards
{
    fn from(rewards: rewards_calculation::rewards_calculator_results::NodeProviderRewards) -> Self {
        Self {
            rewards_total_xdr_permyriad: Some(rewards.rewards_total_xdr_permyriad),
            base_rewards: rewards.base_rewards.into_iter().map(Into::into).collect(),
            base_rewards_type3: rewards
                .base_rewards_type3
                .into_iter()
                .map(Into::into)
                .collect(),
            nodes_results: rewards.nodes_results.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<rewards_calculation::rewards_calculator_results::NodeResults> for NodeResults {
    fn from(value: rewards_calculation::rewards_calculator_results::NodeResults) -> Self {
        Self {
            node_id: Some(value.node_id.get()),
            node_reward_type: Some(value.node_reward_type.to_string()),
            region: Some(value.region),
            dc_id: Some(value.dc_id),
            node_status: Some(value.node_status.into()),
            performance_multiplier_percent: Some(value.performance_multiplier.into()),
            rewards_reduction_percent: Some(value.rewards_reduction.into()),
            base_rewards_xdr_permyriad: Some(value.base_rewards.into()),
            adjusted_rewards_xdr_permyriad: Some(value.adjusted_rewards.into()),
        }
    }
}

impl From<rewards_calculation::types::DayUtc> for DayUtc {
    fn from(value: rewards_calculation::types::DayUtc) -> Self {
        Self {
            value: Some(value.get()),
        }
    }
}
