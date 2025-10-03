use crate::provider_rewards_calculation::{
    BaseRewards, BaseRewardsType3, DailyResults, NodeMetricsDaily, NodeProviderRewards,
    NodeResults, NodeStatus,
};
use ic_base_types::{NodeId, SubnetId};
use ic_nervous_system_proto::pb::v1::Decimal as DecimalProto;
use ic_protobuf::registry::node::v1::NodeRewardType;
use rewards_calculation::performance_based_algorithm::results as native_types;
use rust_decimal::Decimal;

// ================================================================================================
// Conversion implementations for API types <-> Internal types
// ================================================================================================

// NodeMetricsDaily conversions
impl From<native_types::NodeMetricsDaily> for NodeMetricsDaily {
    fn from(metrics: native_types::NodeMetricsDaily) -> Self {
        Self {
            subnet_assigned: Some(metrics.subnet_assigned.get()),
            subnet_assigned_fr_percent: Some(DecimalProto::from(metrics.subnet_assigned_fr)),
            num_blocks_proposed: Some(metrics.num_blocks_proposed),
            num_blocks_failed: Some(metrics.num_blocks_failed),
            original_fr_percent: Some(DecimalProto::from(metrics.original_fr)),
            relative_fr_percent: Some(DecimalProto::from(metrics.relative_fr)),
        }
    }
}

impl TryFrom<NodeMetricsDaily> for native_types::NodeMetricsDaily {
    type Error = String;

    fn try_from(value: NodeMetricsDaily) -> Result<Self, Self::Error> {
        Ok(Self {
            subnet_assigned: SubnetId::from(value.subnet_assigned.unwrap()),
            subnet_assigned_fr: Decimal::try_from(value.subnet_assigned_fr_percent.unwrap())?,
            num_blocks_proposed: value.num_blocks_proposed.unwrap(),
            num_blocks_failed: value.num_blocks_failed.unwrap(),
            original_fr: Decimal::try_from(value.original_fr_percent.unwrap())?,
            relative_fr: Decimal::try_from(value.relative_fr_percent.unwrap())?,
        })
    }
}

// NodeStatus conversions
impl From<native_types::NodeStatus> for NodeStatus {
    fn from(status: native_types::NodeStatus) -> Self {
        match status {
            native_types::NodeStatus::Assigned { node_metrics } => Self::Assigned {
                node_metrics: Some(NodeMetricsDaily::from(node_metrics)),
            },
            native_types::NodeStatus::Unassigned { extrapolated_fr } => Self::Unassigned {
                extrapolated_fr_percent: Some(DecimalProto::from(extrapolated_fr)),
            },
        }
    }
}

impl TryFrom<NodeStatus> for native_types::NodeStatus {
    type Error = String;

    fn try_from(value: NodeStatus) -> Result<Self, Self::Error> {
        match value {
            NodeStatus::Assigned { node_metrics } => Ok(Self::Assigned {
                node_metrics: native_types::NodeMetricsDaily::try_from(node_metrics.unwrap())?,
            }),
            NodeStatus::Unassigned {
                extrapolated_fr_percent,
            } => Ok(Self::Unassigned {
                extrapolated_fr: Decimal::try_from(extrapolated_fr_percent.unwrap())?,
            }),
        }
    }
}

// NodeResults conversions
impl From<native_types::NodeResults> for NodeResults {
    fn from(results: native_types::NodeResults) -> Self {
        Self {
            node_id: Some(results.node_id.get()),
            node_reward_type: Some(results.node_reward_type.to_string()),
            region: Some(results.region),
            dc_id: Some(results.dc_id),
            node_status: Some(NodeStatus::from(results.node_status)),
            performance_multiplier_percent: Some(DecimalProto::from(
                results.performance_multiplier,
            )),
            rewards_reduction_percent: Some(DecimalProto::from(results.rewards_reduction)),
            base_rewards_xdr_permyriad: Some(DecimalProto::from(results.base_rewards)),
            adjusted_rewards_xdr_permyriad: Some(DecimalProto::from(results.adjusted_rewards)),
        }
    }
}

impl TryFrom<NodeResults> for native_types::NodeResults {
    type Error = String;
    fn try_from(value: NodeResults) -> Result<Self, Self::Error> {
        Ok(Self {
            node_id: NodeId::from(value.node_id.unwrap()),
            node_reward_type: NodeRewardType::from(value.node_reward_type.unwrap()),
            region: value.region.unwrap(),
            dc_id: value.dc_id.unwrap(),
            node_status: native_types::NodeStatus::try_from(value.node_status.unwrap())?,
            performance_multiplier: Decimal::try_from(
                value.performance_multiplier_percent.unwrap(),
            )?,
            rewards_reduction: Decimal::try_from(value.rewards_reduction_percent.unwrap())?,
            base_rewards: Decimal::try_from(value.base_rewards_xdr_permyriad.unwrap())?,
            adjusted_rewards: Decimal::try_from(value.adjusted_rewards_xdr_permyriad.unwrap())?,
        })
    }
}

// BaseRewards conversions
impl From<native_types::BaseRewards> for BaseRewards {
    fn from(rewards: native_types::BaseRewards) -> Self {
        Self {
            monthly_xdr_permyriad: Some(DecimalProto::from(rewards.monthly)),
            daily_xdr_permyriad: Some(DecimalProto::from(rewards.daily)),
            node_reward_type: Some(rewards.node_reward_type.to_string()),
            region: Some(rewards.region),
        }
    }
}

impl TryFrom<BaseRewards> for native_types::BaseRewards {
    type Error = String;

    fn try_from(value: BaseRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            node_reward_type: NodeRewardType::from(value.node_reward_type.unwrap()),
            region: value.region.unwrap(),
            monthly: Decimal::try_from(value.monthly_xdr_permyriad.unwrap())?,
            daily: Decimal::try_from(value.daily_xdr_permyriad.unwrap())?,
        })
    }
}

// BaseRewardsType3 conversions
impl From<native_types::BaseRewardsType3> for BaseRewardsType3 {
    fn from(rewards: native_types::BaseRewardsType3) -> Self {
        Self {
            region: Some(rewards.region),
            nodes_count: Some(rewards.nodes_count as u64),
            avg_rewards_xdr_permyriad: Some(DecimalProto::from(rewards.avg_rewards)),
            avg_coefficient_percent: Some(DecimalProto::from(rewards.avg_coefficient)),
            value_xdr_permyriad: Some(DecimalProto::from(rewards.value)),
        }
    }
}

impl TryFrom<BaseRewardsType3> for native_types::BaseRewardsType3 {
    type Error = String;

    fn try_from(value: BaseRewardsType3) -> Result<Self, Self::Error> {
        Ok(Self {
            region: value.region.unwrap(),
            nodes_count: value.nodes_count.unwrap() as usize,
            avg_rewards: Decimal::try_from(value.avg_rewards_xdr_permyriad.unwrap())?,
            avg_coefficient: Decimal::try_from(value.avg_coefficient_percent.unwrap())?,
            value: Decimal::try_from(value.value_xdr_permyriad.unwrap())?,
        })
    }
}

// NodeProviderRewards conversions
impl From<native_types::NodeProviderRewards> for NodeProviderRewards {
    fn from(rewards: native_types::NodeProviderRewards) -> Self {
        Self {
            rewards_total_xdr_permyriad: Some(DecimalProto::from(rewards.rewards_total)),
            base_rewards: rewards
                .base_rewards
                .into_iter()
                .map(BaseRewards::from)
                .collect(),
            base_rewards_type3: rewards
                .base_rewards_type3
                .into_iter()
                .map(BaseRewardsType3::from)
                .collect(),
            nodes_results: rewards
                .nodes_results
                .into_iter()
                .map(NodeResults::from)
                .collect(),
        }
    }
}

impl TryFrom<NodeProviderRewards> for native_types::NodeProviderRewards {
    type Error = String;

    fn try_from(value: NodeProviderRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            rewards_total: Decimal::try_from(value.rewards_total_xdr_permyriad.unwrap())?,
            base_rewards: value
                .base_rewards
                .into_iter()
                .map(native_types::BaseRewards::try_from)
                .collect::<Result<_, _>>()?,
            base_rewards_type3: value
                .base_rewards_type3
                .into_iter()
                .map(native_types::BaseRewardsType3::try_from)
                .collect::<Result<_, _>>()?,
            nodes_results: value
                .nodes_results
                .into_iter()
                .map(native_types::NodeResults::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

// DailyResults conversions
impl From<native_types::DailyResults> for DailyResults {
    fn from(value: native_types::DailyResults) -> Self {
        Self {
            subnets_fr: value
                .subnets_fr
                .into_iter()
                .map(|(k, v)| (k, DecimalProto::from(v)))
                .collect(),
            provider_results: value
                .provider_results
                .into_iter()
                .map(|(k, v)| (k, NodeProviderRewards::from(v)))
                .collect(),
        }
    }
}

impl TryFrom<DailyResults> for native_types::DailyResults {
    type Error = String;

    fn try_from(value: DailyResults) -> Result<Self, Self::Error> {
        Ok(Self {
            subnets_fr: value
                .subnets_fr
                .into_iter()
                .map(|(k, v)| Decimal::try_from(v).map(|dec| (k, dec)))
                .collect::<Result<_, _>>()?,
            provider_results: value
                .provider_results
                .into_iter()
                .map(|(k, v)| native_types::NodeProviderRewards::try_from(v).map(|v| (k, v)))
                .collect::<Result<_, _>>()?,
        })
    }
}
