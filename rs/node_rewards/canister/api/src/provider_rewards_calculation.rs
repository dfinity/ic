use candid::{CandidType, Deserialize};
use ic_base_types::{PrincipalId, SubnetId};
use ic_nervous_system_proto::pb::v1::Decimal;
use ic_protobuf::registry::node::v1::NodeRewardType;
use rewards_calculation::performance_based_algorithm::results;
use rewards_calculation::types;
use rust_decimal::Decimal as RustDecimal;
use std::collections::BTreeMap;
use std::str::FromStr;

#[derive(CandidType, Clone, Deserialize)]
pub struct GetNodeProviderRewardsCalculationRequest {
    pub day_timestamp_nanos: u64,
}

pub type GetNodeProviderRewardsCalculationResponse = Result<DailyResults, String>;

#[derive(
    PartialOrd, Ord, Eq, candid::CandidType, candid::Deserialize, Clone, Copy, PartialEq, Debug,
)]
pub struct DayUtc {
    pub value: Option<u64>,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug, Default)]
pub struct NodeMetricsDaily {
    pub subnet_assigned: Option<PrincipalId>,
    pub subnet_assigned_fr: Option<Decimal>,
    pub num_blocks_proposed: Option<u64>,
    pub num_blocks_failed: Option<u64>,
    pub original_fr: Option<Decimal>,
    pub relative_fr: Option<Decimal>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub enum NodeStatus {
    Assigned {
        node_metrics: Option<NodeMetricsDaily>,
    },
    Unassigned {
        extrapolated_fr: Option<Decimal>,
    },
}

impl Default for NodeStatus {
    fn default() -> Self {
        Self::Assigned { node_metrics: None }
    }
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct NodeResults {
    pub node_id: Option<PrincipalId>,
    pub node_reward_type: Option<String>,
    pub region: Option<String>,
    pub dc_id: Option<String>,
    pub node_status: Option<NodeStatus>,
    pub performance_multiplier: Option<Decimal>,
    pub rewards_reduction: Option<Decimal>,
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
    pub avg_coefficient: Option<Decimal>,
    pub value_xdr_permyriad: Option<Decimal>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct NodeProviderRewards {
    pub rewards_total_xdr_permyriad: Option<Decimal>,
    pub base_rewards: Vec<BaseRewards>,
    pub base_rewards_type3: Vec<BaseRewardsType3>,
    pub nodes_results: Vec<NodeResults>,
}
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, Debug)]
pub struct DailyResults {
    pub subnets_fr: BTreeMap<SubnetId, Decimal>,
    pub provider_results: BTreeMap<PrincipalId, NodeProviderRewards>,
}

// ================================================================================================
// Conversion implementations for API types <-> Internal types
// ================================================================================================

// Helper function to convert between Decimal types
fn convert_decimal(api_decimal: &Decimal) -> RustDecimal {
    // Convert from ic_nervous_system_proto::pb::v1::Decimal to rust_decimal::Decimal
    // The nervous system Decimal has a human_readable string field
    let empty_string = String::new();
    let human_readable = api_decimal.human_readable.as_ref().unwrap_or(&empty_string);
    RustDecimal::from_str(human_readable).unwrap_or_default()
}

// Helper function to parse NodeRewardType from string
fn parse_node_reward_type(s: &str) -> NodeRewardType {
    match s {
        "Type1" => NodeRewardType::Type1,
        "Type2" => NodeRewardType::Type2,
        "Type3" => NodeRewardType::Type3,
        "Type3dot1" => NodeRewardType::Type3dot1,
        _ => NodeRewardType::Type1, // Default fallback
    }
}

// DayUtc conversions
impl From<types::DayUtc> for DayUtc {
    fn from(day_utc: types::DayUtc) -> Self {
        Self {
            value: Some(day_utc.get()),
        }
    }
}

impl From<DayUtc> for types::DayUtc {
    fn from(day_utc: DayUtc) -> Self {
        types::DayUtc::from(day_utc.value.unwrap_or(0))
    }
}

// NodeMetricsDaily conversions
impl From<results::NodeMetricsDaily> for NodeMetricsDaily {
    fn from(metrics: results::NodeMetricsDaily) -> Self {
        Self {
            subnet_assigned: Some(metrics.subnet_assigned.get()),
            subnet_assigned_fr: Some(metrics.subnet_assigned_fr.into()),
            num_blocks_proposed: Some(metrics.num_blocks_proposed),
            num_blocks_failed: Some(metrics.num_blocks_failed),
            original_fr: Some(metrics.original_fr.into()),
            relative_fr: Some(metrics.relative_fr.into()),
        }
    }
}

impl From<NodeMetricsDaily> for results::NodeMetricsDaily {
    fn from(metrics: NodeMetricsDaily) -> Self {
        Self {
            subnet_assigned: metrics.subnet_assigned.unwrap_or_default().into(),
            subnet_assigned_fr: convert_decimal(&metrics.subnet_assigned_fr.unwrap_or_default()),
            num_blocks_proposed: metrics.num_blocks_proposed.unwrap_or(0),
            num_blocks_failed: metrics.num_blocks_failed.unwrap_or(0),
            original_fr: convert_decimal(&metrics.original_fr.unwrap_or_default()),
            relative_fr: convert_decimal(&metrics.relative_fr.unwrap_or_default()),
        }
    }
}

// NodeStatus conversions
impl From<results::NodeStatus> for NodeStatus {
    fn from(status: results::NodeStatus) -> Self {
        match status {
            results::NodeStatus::Assigned { node_metrics } => Self::Assigned {
                node_metrics: Some(node_metrics.into()),
            },
            results::NodeStatus::Unassigned { extrapolated_fr } => Self::Unassigned {
                extrapolated_fr: Some(extrapolated_fr.into()),
            },
        }
    }
}

impl From<NodeStatus> for results::NodeStatus {
    fn from(status: NodeStatus) -> Self {
        match status {
            NodeStatus::Assigned { node_metrics } => Self::Assigned {
                node_metrics: node_metrics.unwrap_or_default().into(),
            },
            NodeStatus::Unassigned { extrapolated_fr } => Self::Unassigned {
                extrapolated_fr: convert_decimal(&extrapolated_fr.unwrap_or_default()),
            },
        }
    }
}

// NodeResults conversions
impl From<results::NodeResults> for NodeResults {
    fn from(results: results::NodeResults) -> Self {
        Self {
            node_id: Some(results.node_id.get()),
            node_reward_type: Some(results.node_reward_type.to_string()),
            region: Some(results.region),
            dc_id: Some(results.dc_id),
            node_status: Some(results.node_status.into()),
            performance_multiplier: Some(results.performance_multiplier.into()),
            rewards_reduction: Some(results.rewards_reduction.into()),
            base_rewards_xdr_permyriad: Some(results.base_rewards.into()),
            adjusted_rewards_xdr_permyriad: Some(results.adjusted_rewards.into()),
        }
    }
}

impl From<NodeResults> for results::NodeResults {
    fn from(results: NodeResults) -> Self {
        Self {
            node_id: results.node_id.unwrap_or_default().into(),
            node_reward_type: parse_node_reward_type(&results.node_reward_type.unwrap_or_default()),
            region: results.region.unwrap_or_default(),
            dc_id: results.dc_id.unwrap_or_default(),
            node_status: results.node_status.unwrap_or_default().into(),
            performance_multiplier: convert_decimal(
                &results.performance_multiplier.unwrap_or_default(),
            ),
            rewards_reduction: convert_decimal(&results.rewards_reduction.unwrap_or_default()),
            base_rewards: convert_decimal(&results.base_rewards_xdr_permyriad.unwrap_or_default()),
            adjusted_rewards: convert_decimal(
                &results.adjusted_rewards_xdr_permyriad.unwrap_or_default(),
            ),
        }
    }
}

// BaseRewards conversions
impl From<results::BaseRewards> for BaseRewards {
    fn from(rewards: results::BaseRewards) -> Self {
        Self {
            monthly_xdr_permyriad: Some(rewards.monthly.into()),
            daily_xdr_permyriad: Some(rewards.daily.into()),
            node_reward_type: Some(rewards.node_reward_type.to_string()),
            region: Some(rewards.region),
        }
    }
}

impl From<BaseRewards> for results::BaseRewards {
    fn from(rewards: BaseRewards) -> Self {
        Self {
            node_reward_type: parse_node_reward_type(&rewards.node_reward_type.unwrap_or_default()),
            region: rewards.region.unwrap_or_default(),
            monthly: convert_decimal(&rewards.monthly_xdr_permyriad.unwrap_or_default()),
            daily: convert_decimal(&rewards.daily_xdr_permyriad.unwrap_or_default()),
        }
    }
}

// BaseRewardsType3 conversions
impl From<results::BaseRewardsType3> for BaseRewardsType3 {
    fn from(rewards: results::BaseRewardsType3) -> Self {
        Self {
            region: Some(rewards.region),
            nodes_count: Some(rewards.nodes_count as u64),
            avg_rewards_xdr_permyriad: Some(rewards.avg_rewards.into()),
            avg_coefficient: Some(rewards.avg_coefficient.into()),
            value_xdr_permyriad: Some(rewards.value.into()),
        }
    }
}

impl From<BaseRewardsType3> for results::BaseRewardsType3 {
    fn from(rewards: BaseRewardsType3) -> Self {
        Self {
            region: rewards.region.unwrap_or_default(),
            nodes_count: rewards.nodes_count.unwrap_or(0) as usize,
            avg_rewards: convert_decimal(&rewards.avg_rewards_xdr_permyriad.unwrap_or_default()),
            avg_coefficient: convert_decimal(&rewards.avg_coefficient.unwrap_or_default()),
            value: convert_decimal(&rewards.value_xdr_permyriad.unwrap_or_default()),
        }
    }
}

// NodeProviderRewards conversions
impl From<results::NodeProviderRewards> for NodeProviderRewards {
    fn from(rewards: results::NodeProviderRewards) -> Self {
        Self {
            rewards_total_xdr_permyriad: Some(rewards.rewards_total.into()),
            base_rewards: rewards.base_rewards.into_iter().map(|r| r.into()).collect(),
            base_rewards_type3: rewards
                .base_rewards_type3
                .into_iter()
                .map(|r| r.into())
                .collect(),
            nodes_results: rewards
                .nodes_results
                .into_iter()
                .map(|r| r.into())
                .collect(),
        }
    }
}

impl From<NodeProviderRewards> for results::NodeProviderRewards {
    fn from(rewards: NodeProviderRewards) -> Self {
        Self {
            rewards_total: convert_decimal(
                &rewards.rewards_total_xdr_permyriad.unwrap_or_default(),
            ),
            base_rewards: rewards.base_rewards.into_iter().map(|r| r.into()).collect(),
            base_rewards_type3: rewards
                .base_rewards_type3
                .into_iter()
                .map(|r| r.into())
                .collect(),
            nodes_results: rewards
                .nodes_results
                .into_iter()
                .map(|r| r.into())
                .collect(),
        }
    }
}

// DailyResults conversions
impl From<results::DailyResults> for DailyResults {
    fn from(results: results::DailyResults) -> Self {
        Self {
            subnets_fr: results
                .subnets_fr
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            provider_results: results
                .provider_results
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl From<DailyResults> for results::DailyResults {
    fn from(results: DailyResults) -> Self {
        Self {
            subnets_fr: results
                .subnets_fr
                .into_iter()
                .map(|(k, v)| (k, convert_decimal(&v)))
                .collect(),
            provider_results: results
                .provider_results
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}
