use crate::provider_rewards_calculation::{
    DailyNodeFailureRate, DailyNodeProviderRewards, DailyNodeRewards, DailyResults,
    NodeMetricsDaily, NodeTypeRegionBaseRewards, Type3RegionBaseRewards,
};
use ic_base_types::{NodeId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use rewards_calculation::performance_based_algorithm::results as native_types;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use std::convert::TryFrom;

// ================================================================================================
// Conversion implementations for API types <-> Internal types (Decimal → f64 for API)
// ================================================================================================

// NodeMetricsDaily conversions
impl TryFrom<native_types::NodeMetricsDaily> for NodeMetricsDaily {
    type Error = String;

    fn try_from(src: native_types::NodeMetricsDaily) -> Result<Self, Self::Error> {
        Ok(Self {
            subnet_assigned: Some(src.subnet_assigned.get()),
            subnet_assigned_fr_percent: Some(
                src.subnet_assigned_fr_percent
                    .to_f64()
                    .ok_or("Conversion to f64 failed (subnet_assigned_fr_percent)")?,
            ),
            num_blocks_proposed: Some(src.num_blocks_proposed),
            num_blocks_failed: Some(src.num_blocks_failed),
            original_fr_percent: Some(
                src.original_fr_percent
                    .to_f64()
                    .ok_or("Conversion to f64 failed (original_fr_percent)")?,
            ),
            relative_fr_percent: Some(
                src.relative_fr_percent
                    .to_f64()
                    .ok_or("Conversion to f64 failed (relative_fr_percent)")?,
            ),
        })
    }
}

impl TryFrom<NodeMetricsDaily> for native_types::NodeMetricsDaily {
    type Error = String;

    fn try_from(src: NodeMetricsDaily) -> Result<Self, Self::Error> {
        Ok(Self {
            subnet_assigned: SubnetId::from(
                src.subnet_assigned
                    .ok_or("subnet_assigned is missing (NodeMetricsDaily)")?,
            ),
            subnet_assigned_fr_percent: Decimal::from(
                src.subnet_assigned_fr_percent
                    .ok_or("subnet_assigned_fr_percent is missing (NodeMetricsDaily)")?,
            ),
            num_blocks_proposed: src
                .num_blocks_proposed
                .ok_or("num_blocks_proposed is missing (NodeMetricsDaily)")?,
            num_blocks_failed: src
                .num_blocks_failed
                .ok_or("num_blocks_failed is missing (NodeMetricsDaily)")?,
            original_fr_percent: Decimal::from(
                src.original_fr_percent
                    .ok_or("original_fr_percent is missing (NodeMetricsDaily)")?,
            ),
            relative_fr_percent: Decimal::from(
                src.relative_fr_percent
                    .ok_or("relative_fr_percent is missing (NodeMetricsDaily)")?,
            ),
        })
    }
}

// DailyNodeFailureRate conversions
impl TryFrom<native_types::DailyNodeFailureRate> for DailyNodeFailureRate {
    type Error = String;

    fn try_from(src: native_types::DailyNodeFailureRate) -> Result<Self, Self::Error> {
        match src {
            native_types::DailyNodeFailureRate::SubnetMember { node_metrics } => {
                Ok(DailyNodeFailureRate::SubnetMember {
                    node_metrics: Some(NodeMetricsDaily::try_from(node_metrics)?),
                })
            }
            native_types::DailyNodeFailureRate::NonSubnetMember { extrapolated_fr } => {
                Ok(DailyNodeFailureRate::NonSubnetMember {
                    extrapolated_fr_percent: Some(
                        extrapolated_fr
                            .to_f64()
                            .ok_or("Conversion to f64 failed (extrapolated_fr)")?,
                    ),
                })
            }
        }
    }
}

impl TryFrom<DailyNodeFailureRate> for native_types::DailyNodeFailureRate {
    type Error = String;

    fn try_from(src: DailyNodeFailureRate) -> Result<Self, Self::Error> {
        match src {
            DailyNodeFailureRate::SubnetMember { node_metrics } => {
                Ok(native_types::DailyNodeFailureRate::SubnetMember {
                    node_metrics: native_types::NodeMetricsDaily::try_from(
                        node_metrics.ok_or("node_metrics is missing (DailyNodeFailureRate)")?,
                    )?,
                })
            }
            DailyNodeFailureRate::NonSubnetMember {
                extrapolated_fr_percent,
            } => Ok(native_types::DailyNodeFailureRate::NonSubnetMember {
                extrapolated_fr: Decimal::from(
                    extrapolated_fr_percent
                        .ok_or("extrapolated_fr_percent is missing (DailyNodeFailureRate)")?,
                ),
            }),
        }
    }
}

// DailyNodeRewards conversions
impl TryFrom<native_types::DailyNodeRewards> for DailyNodeRewards {
    type Error = String;

    fn try_from(src: native_types::DailyNodeRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            node_id: Some(src.node_id.get()),
            node_reward_type: Some(src.node_reward_type.to_string()),
            region: Some(src.region),
            dc_id: Some(src.dc_id),
            daily_node_fr: Some(DailyNodeFailureRate::try_from(src.daily_node_fr)?),
            performance_multiplier_percent: Some(
                src.performance_multiplier_percent
                    .to_f64()
                    .ok_or("Conversion to f64 failed (performance_multiplier_percent)")?,
            ),
            rewards_reduction_percent: Some(
                src.rewards_reduction_percent
                    .to_f64()
                    .ok_or("Conversion to f64 failed (rewards_reduction_percent)")?,
            ),
            base_rewards_xdr_permyriad: Some(
                src.base_rewards_xdr_permyriad
                    .to_u64()
                    .ok_or("Conversion to u64 failed (base_rewards_xdr_permyriad)")?,
            ),
            adjusted_rewards_xdr_permyriad: Some(
                src.adjusted_rewards_xdr_permyriad
                    .to_u64()
                    .ok_or("Conversion to u64 failed (adjusted_rewards_xdr_permyriad)")?,
            ),
        })
    }
}

impl TryFrom<DailyNodeRewards> for native_types::DailyNodeRewards {
    type Error = String;

    fn try_from(src: DailyNodeRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            node_id: NodeId::from(src.node_id.ok_or("node_id is missing (DailyNodeRewards)")?),
            node_reward_type: NodeRewardType::from(
                src.node_reward_type
                    .ok_or("node_reward_type is missing (DailyNodeRewards)")?,
            ),
            region: src.region.ok_or("region is missing (DailyNodeRewards)")?,
            dc_id: src.dc_id.ok_or("dc_id is missing (DailyNodeRewards)")?,
            daily_node_fr: native_types::DailyNodeFailureRate::try_from(
                src.daily_node_fr
                    .ok_or("daily_node_fr is missing (DailyNodeRewards)")?,
            )?,
            performance_multiplier_percent: Decimal::from(
                src.performance_multiplier_percent
                    .ok_or("performance_multiplier_percent is missing (DailyNodeRewards)")?,
            ),
            rewards_reduction_percent: Decimal::from(
                src.rewards_reduction_percent
                    .ok_or("rewards_reduction_percent is missing (DailyNodeRewards)")?,
            ),
            base_rewards_xdr_permyriad: Decimal::from(
                src.base_rewards_xdr_permyriad
                    .ok_or("base_rewards_xdr_permyriad is missing (DailyNodeRewards)")?,
            ),
            adjusted_rewards_xdr_permyriad: Decimal::from(
                src.adjusted_rewards_xdr_permyriad
                    .ok_or("adjusted_rewards_xdr_permyriad is missing (DailyNodeRewards)")?,
            ),
        })
    }
}

// NodeTypeRegionBaseRewards conversions
impl TryFrom<native_types::NodeTypeRegionBaseRewards> for NodeTypeRegionBaseRewards {
    type Error = String;

    fn try_from(src: native_types::NodeTypeRegionBaseRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            monthly_xdr_permyriad: Some(
                src.monthly_xdr_permyriad
                    .to_u64()
                    .ok_or("Conversion to f64 failed (monthly_xdr_permyriad)")?,
            ),
            daily_xdr_permyriad: Some(
                src.daily_xdr_permyriad
                    .to_u64()
                    .ok_or("Conversion to f64 failed (daily_xdr_permyriad)")?,
            ),
            node_reward_type: Some(src.node_reward_type.to_string()),
            region: Some(src.region),
        })
    }
}

impl TryFrom<NodeTypeRegionBaseRewards> for native_types::NodeTypeRegionBaseRewards {
    type Error = String;

    fn try_from(src: NodeTypeRegionBaseRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            node_reward_type: NodeRewardType::from(
                src.node_reward_type
                    .ok_or("node_reward_type is missing (NodeTypeRegionBaseRewards)")?,
            ),
            region: src
                .region
                .ok_or("region is missing (NodeTypeRegionBaseRewards)")?,
            monthly_xdr_permyriad: Decimal::from(
                src.monthly_xdr_permyriad
                    .ok_or("monthly_xdr_permyriad is missing (NodeTypeRegionBaseRewards)")?,
            ),
            daily_xdr_permyriad: Decimal::from(
                src.daily_xdr_permyriad
                    .ok_or("daily_xdr_permyriad is missing (NodeTypeRegionBaseRewards)")?,
            ),
        })
    }
}

// Type3RegionBaseRewards conversions
impl TryFrom<native_types::Type3RegionBaseRewards> for Type3RegionBaseRewards {
    type Error = String;

    fn try_from(src: native_types::Type3RegionBaseRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            region: Some(src.region),
            nodes_count: Some(src.nodes_count as u64),
            avg_rewards_xdr_permyriad: Some(
                src.avg_rewards_xdr_permyriad
                    .to_u64()
                    .ok_or("Conversion to u64 failed (avg_rewards_xdr_permyriad)")?,
            ),
            avg_coefficient_percent: Some(
                src.avg_coefficient_percent
                    .to_f64()
                    .ok_or("Conversion to f64 failed (avg_coefficient_percent)")?,
            ),
            daily_xdr_permyriad: Some(
                src.daily_xdr_permyriad
                    .to_u64()
                    .ok_or("Conversion to u64 failed (daily_xdr_permyriad)")?,
            ),
        })
    }
}

impl TryFrom<Type3RegionBaseRewards> for native_types::Type3RegionBaseRewards {
    type Error = String;

    fn try_from(src: Type3RegionBaseRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            region: src
                .region
                .ok_or("region is missing (Type3RegionBaseRewards)")?,
            nodes_count: src
                .nodes_count
                .ok_or("nodes_count is missing (Type3RegionBaseRewards)")?
                as usize,
            avg_rewards_xdr_permyriad: Decimal::from(
                src.avg_rewards_xdr_permyriad
                    .ok_or("avg_rewards_xdr_permyriad is missing (Type3RegionBaseRewards)")?,
            ),
            avg_coefficient_percent: Decimal::from(
                src.avg_coefficient_percent
                    .ok_or("avg_coefficient_percent is missing (Type3RegionBaseRewards)")?,
            ),
            daily_xdr_permyriad: Decimal::from(
                src.daily_xdr_permyriad
                    .ok_or("daily_xdr_permyriad is missing (Type3RegionBaseRewards)")?,
            ),
        })
    }
}

// DailyNodeProviderRewards conversions
impl TryFrom<native_types::DailyNodeProviderRewards> for DailyNodeProviderRewards {
    type Error = String;

    fn try_from(src: native_types::DailyNodeProviderRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            rewards_total_xdr_permyriad: Some(
                src.rewards_total_xdr_permyriad
                    .to_u64()
                    .ok_or("Conversion to u64 failed (rewards_total_xdr_permyriad)")?,
            ),
            base_rewards: src
                .base_rewards
                .into_iter()
                .map(NodeTypeRegionBaseRewards::try_from)
                .collect::<Result<_, _>>()?,
            base_rewards_type3: src
                .type3_base_rewards
                .into_iter()
                .map(Type3RegionBaseRewards::try_from)
                .collect::<Result<_, _>>()?,
            daily_nodes_rewards: src
                .daily_nodes_rewards
                .into_iter()
                .map(DailyNodeRewards::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<DailyNodeProviderRewards> for native_types::DailyNodeProviderRewards {
    type Error = String;

    fn try_from(src: DailyNodeProviderRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            rewards_total_xdr_permyriad: Decimal::from(
                src.rewards_total_xdr_permyriad
                    .ok_or("rewards_total_xdr_permyriad is missing (DailyNodeProviderRewards)")?,
            ),
            base_rewards: src
                .base_rewards
                .into_iter()
                .map(native_types::NodeTypeRegionBaseRewards::try_from)
                .collect::<Result<_, _>>()?,
            type3_base_rewards: src
                .base_rewards_type3
                .into_iter()
                .map(native_types::Type3RegionBaseRewards::try_from)
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
impl TryFrom<native_types::DailyResults> for DailyResults {
    type Error = String;

    fn try_from(src: native_types::DailyResults) -> Result<Self, Self::Error> {
        Ok(Self {
            subnets_fr: src
                .subnets_fr_percent
                .into_iter()
                .map(|(k, v)| {
                    v.to_f64()
                        .map(|v| (k, v))
                        .ok_or("Conversion to f64 failed (subnets_fr_percent)")
                })
                .collect::<Result<_, _>>()?,
            provider_results: src
                .provider_results
                .into_iter()
                .map(|(k, v)| Ok((k, DailyNodeProviderRewards::try_from(v)?)))
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<DailyResults> for native_types::DailyResults {
    type Error = String;

    fn try_from(src: DailyResults) -> Result<Self, Self::Error> {
        Ok(Self {
            subnets_fr_percent: src
                .subnets_fr
                .into_iter()
                .map(|(k, v)| Ok((k, Decimal::try_from(v)?)))
                .collect::<Result<_, _>>()?,
            provider_results: src
                .provider_results
                .into_iter()
                .map(|(k, v)| Ok((k, native_types::DailyNodeProviderRewards::try_from(v)?)))
                .collect::<Result<_, _>>()?,
        })
    }
}
