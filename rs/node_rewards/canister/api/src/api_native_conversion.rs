use crate::provider_rewards_calculation::{
    BaseRewards, DailyNodeProviderRewards, DailyNodeRewards, DailyResults, NodeMetricsDaily,
    NodeStatus, Type3BaseRewards,
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
    fn from(src: native_types::NodeMetricsDaily) -> Self {
        Self {
            subnet_assigned: Some(src.subnet_assigned.get()),
            subnet_assigned_fr_percent: Some(DecimalProto::from(src.subnet_assigned_fr)),
            num_blocks_proposed: Some(src.num_blocks_proposed),
            num_blocks_failed: Some(src.num_blocks_failed),
            original_fr_percent: Some(DecimalProto::from(src.original_fr)),
            relative_fr_percent: Some(DecimalProto::from(src.relative_fr)),
        }
    }
}

impl TryFrom<NodeMetricsDaily> for native_types::NodeMetricsDaily {
    type Error = String;

    fn try_from(src: NodeMetricsDaily) -> Result<Self, Self::Error> {
        Ok(Self {
            subnet_assigned: SubnetId::from(
                src.subnet_assigned
                    .ok_or("subnet_assigned is missing (from NodeMetricsDaily).")?,
            ),
            subnet_assigned_fr: Decimal::try_from(
                src.subnet_assigned_fr_percent
                    .ok_or("subnet_assigned_fr_percent is missing (from NodeMetricsDaily).")?,
            )?,
            num_blocks_proposed: src
                .num_blocks_proposed
                .ok_or("num_blocks_proposed is missing (from NodeMetricsDaily).")?,
            num_blocks_failed: src
                .num_blocks_failed
                .ok_or("num_blocks_failed is missing (from NodeMetricsDaily).")?,
            original_fr: Decimal::try_from(
                src.original_fr_percent
                    .ok_or("original_fr_percent is missing (from NodeMetricsDaily).")?,
            )?,
            relative_fr: Decimal::try_from(
                src.relative_fr_percent
                    .ok_or("relative_fr_percent is missing (from NodeMetricsDaily).")?,
            )?,
        })
    }
}

// NodeStatus conversions
impl From<native_types::NodeStatus> for NodeStatus {
    fn from(src: native_types::NodeStatus) -> Self {
        match src {
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

    fn try_from(src: NodeStatus) -> Result<Self, Self::Error> {
        match src {
            NodeStatus::Assigned { node_metrics } => Ok(Self::Assigned {
                node_metrics: native_types::NodeMetricsDaily::try_from(
                    node_metrics.ok_or("node_metrics is missing (from NodeStatus).")?,
                )?,
            }),
            NodeStatus::Unassigned {
                extrapolated_fr_percent,
            } => Ok(Self::Unassigned {
                extrapolated_fr: Decimal::try_from(
                    extrapolated_fr_percent
                        .ok_or("extrapolated_fr_percent is missing (from NodeStatus).")?,
                )?,
            }),
        }
    }
}

// DailyNodeRewards conversions
impl From<native_types::DailyNodeRewards> for DailyNodeRewards {
    fn from(src: native_types::DailyNodeRewards) -> Self {
        Self {
            node_id: Some(src.node_id.get()),
            node_reward_type: Some(src.node_reward_type.to_string()),
            region: Some(src.region),
            dc_id: Some(src.dc_id),
            node_status: Some(NodeStatus::from(src.node_status)),
            performance_multiplier_percent: Some(DecimalProto::from(src.performance_multiplier)),
            rewards_reduction_percent: Some(DecimalProto::from(src.rewards_reduction)),
            base_rewards_xdr_permyriad: Some(DecimalProto::from(src.base_rewards)),
            adjusted_rewards_xdr_permyriad: Some(DecimalProto::from(src.adjusted_rewards)),
        }
    }
}

impl TryFrom<DailyNodeRewards> for native_types::DailyNodeRewards {
    type Error = String;
    fn try_from(src: DailyNodeRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            node_id: NodeId::from(
                src.node_id
                    .ok_or("node_id is missing (from DailyNodeRewards).")?,
            ),
            node_reward_type: NodeRewardType::from(
                src.node_reward_type
                    .ok_or("node_reward_type is missing (from DailyNodeRewards).")?,
            ),
            region: src
                .region
                .ok_or("region is missing (from DailyNodeRewards).")?,
            dc_id: src
                .dc_id
                .ok_or("dc_id is missing (from DailyNodeRewards).")?,
            node_status: native_types::NodeStatus::try_from(
                src.node_status
                    .ok_or("node_status is missing (from DailyNodeRewards).")?,
            )?,
            performance_multiplier: Decimal::try_from(
                src.performance_multiplier_percent
                    .ok_or("performance_multiplier_percent is missing (from DailyNodeRewards).")?,
            )?,
            rewards_reduction: Decimal::try_from(
                src.rewards_reduction_percent
                    .ok_or("rewards_reduction_percent is missing (from DailyNodeRewards).")?,
            )?,
            base_rewards: Decimal::try_from(
                src.base_rewards_xdr_permyriad
                    .ok_or("base_rewards_xdr_permyriad is missing (from DailyNodeRewards).")?,
            )?,
            adjusted_rewards: Decimal::try_from(
                src.adjusted_rewards_xdr_permyriad
                    .ok_or("adjusted_rewards_xdr_permyriad is missing (from DailyNodeRewards).")?,
            )?,
        })
    }
}

// BaseRewards conversions
impl From<native_types::BaseRewards> for BaseRewards {
    fn from(src: native_types::BaseRewards) -> Self {
        Self {
            monthly_xdr_permyriad: Some(DecimalProto::from(src.monthly)),
            daily_xdr_permyriad: Some(DecimalProto::from(src.daily)),
            node_reward_type: Some(src.node_reward_type.to_string()),
            region: Some(src.region),
        }
    }
}

impl TryFrom<BaseRewards> for native_types::BaseRewards {
    type Error = String;

    fn try_from(src: BaseRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            node_reward_type: NodeRewardType::from(
                src.node_reward_type
                    .ok_or("node_reward_type is missing (from BaseRewards).")?,
            ),
            region: src.region.ok_or("region is missing (from BaseRewards).")?,
            monthly: Decimal::try_from(
                src.monthly_xdr_permyriad
                    .ok_or("monthly_xdr_permyriad is missing (from BaseRewards).")?,
            )?,
            daily: Decimal::try_from(
                src.daily_xdr_permyriad
                    .ok_or("daily_xdr_permyriad is missing (from BaseRewards).")?,
            )?,
        })
    }
}

// Type3BaseRewards conversions
impl From<native_types::Type3BaseRewards> for Type3BaseRewards {
    fn from(src: native_types::Type3BaseRewards) -> Self {
        Self {
            region: Some(src.region),
            nodes_count: Some(src.nodes_count as u64),
            avg_rewards_xdr_permyriad: Some(DecimalProto::from(src.avg_rewards)),
            avg_coefficient_percent: Some(DecimalProto::from(src.avg_coefficient)),
            value_xdr_permyriad: Some(DecimalProto::from(src.value)),
        }
    }
}

impl TryFrom<Type3BaseRewards> for native_types::Type3BaseRewards {
    type Error = String;

    fn try_from(value: Type3BaseRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            region: value
                .region
                .ok_or("region is missing (from Type3BaseRewards).")?,
            nodes_count: value
                .nodes_count
                .ok_or("nodes_count is missing (from Type3BaseRewards).")?
                as usize,
            avg_rewards: Decimal::try_from(
                value
                    .avg_rewards_xdr_permyriad
                    .ok_or("avg_rewards_xdr_permyriad is missing (from Type3BaseRewards).")?,
            )?,
            avg_coefficient: Decimal::try_from(
                value
                    .avg_coefficient_percent
                    .ok_or("avg_coefficient_percent is missing (from Type3BaseRewards).")?,
            )?,
            value: Decimal::try_from(
                value
                    .value_xdr_permyriad
                    .ok_or("value_xdr_permyriad is missing (from Type3BaseRewards).")?,
            )?,
        })
    }
}

// DailyNodeProviderRewards conversions
impl From<native_types::DailyNodeProviderRewards> for DailyNodeProviderRewards {
    fn from(src: native_types::DailyNodeProviderRewards) -> Self {
        Self {
            rewards_total_xdr_permyriad: Some(DecimalProto::from(src.rewards_total)),
            base_rewards: src
                .base_rewards
                .into_iter()
                .map(BaseRewards::from)
                .collect(),
            base_rewards_type3: src
                .type3_base_rewards
                .into_iter()
                .map(Type3BaseRewards::from)
                .collect(),
            daily_nodes_rewards: src
                .daily_nodes_rewards
                .into_iter()
                .map(DailyNodeRewards::from)
                .collect(),
        }
    }
}

impl TryFrom<DailyNodeProviderRewards> for native_types::DailyNodeProviderRewards {
    type Error = String;

    fn try_from(src: DailyNodeProviderRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            rewards_total: Decimal::try_from(src.rewards_total_xdr_permyriad.ok_or(
                "rewards_total_xdr_permyriad is missing (from DailyNodeProviderRewards).",
            )?)?,
            base_rewards: src
                .base_rewards
                .into_iter()
                .map(native_types::BaseRewards::try_from)
                .collect::<Result<_, _>>()?,
            type3_base_rewards: src
                .base_rewards_type3
                .into_iter()
                .map(native_types::Type3BaseRewards::try_from)
                .collect::<Result<_, _>>()?,
            daily_nodes_rewards: src
                .daily_nodes_rewards
                .into_iter()
                .map(native_types::DailyNodeRewards::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

// DailyResults conversions
impl From<native_types::DailyResults> for DailyResults {
    fn from(src: native_types::DailyResults) -> Self {
        Self {
            subnets_fr: src
                .subnets_fr
                .into_iter()
                .map(|(k, v)| (k, DecimalProto::from(v)))
                .collect(),
            provider_results: src
                .provider_results
                .into_iter()
                .map(|(k, v)| (k, DailyNodeProviderRewards::from(v)))
                .collect(),
        }
    }
}

impl TryFrom<DailyResults> for native_types::DailyResults {
    type Error = String;

    fn try_from(src: DailyResults) -> Result<Self, Self::Error> {
        Ok(Self {
            subnets_fr: src
                .subnets_fr
                .into_iter()
                .map(|(k, v)| Decimal::try_from(v).map(|dec| (k, dec)))
                .collect::<Result<_, _>>()?,
            provider_results: src
                .provider_results
                .into_iter()
                .map(|(k, v)| native_types::DailyNodeProviderRewards::try_from(v).map(|v| (k, v)))
                .collect::<Result<_, _>>()?,
        })
    }
}
