use crate::provider_rewards_calculation::{
    DailyNodeFailureRate, DailyNodeProviderRewards, DailyNodeRewards, DailyResults,
    NodeMetricsDaily, NodeTypeRegionBaseRewards, Type3RegionBaseRewards,
};
use rewards_calculation::performance_based_algorithm::results as native_types;
use rust_decimal::prelude::ToPrimitive;
use std::convert::TryFrom;

// ================================================================================================
// Conversion implementations for API types <-> Internal types
// ================================================================================================

// NodeMetricsDaily conversions
impl TryFrom<native_types::NodeMetricsDaily> for NodeMetricsDaily {
    type Error = String;

    fn try_from(src: native_types::NodeMetricsDaily) -> Result<Self, Self::Error> {
        Ok(Self {
            subnet_assigned: Some(src.subnet_assigned.get()),
            subnet_assigned_failure_rate: Some(
                src.subnet_assigned_failure_rate
                    .to_f64()
                    .ok_or("Conversion to f64 failed (subnet_assigned_fr_percent)")?,
            ),
            num_blocks_proposed: Some(src.num_blocks_proposed),
            num_blocks_failed: Some(src.num_blocks_failed),
            original_failure_rate: Some(
                src.original_failure_rate
                    .to_f64()
                    .ok_or("Conversion to f64 failed (original_fr_percent)")?,
            ),
            relative_failure_rate: Some(
                src.relative_failure_rate
                    .to_f64()
                    .ok_or("Conversion to f64 failed (relative_fr_percent)")?,
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
            native_types::DailyNodeFailureRate::NonSubnetMember {
                extrapolated_failure_rate,
            } => Ok(DailyNodeFailureRate::NonSubnetMember {
                extrapolated_failure_rate: Some(
                    extrapolated_failure_rate
                        .to_f64()
                        .ok_or("Conversion to f64 failed (extrapolated_fr)")?,
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
            daily_node_failure_rate: Some(DailyNodeFailureRate::try_from(
                src.daily_node_failure_rate,
            )?),
            performance_multiplier: Some(
                src.performance_multiplier
                    .to_f64()
                    .ok_or("Conversion to f64 failed (performance_multiplier_percent)")?,
            ),
            rewards_reduction: Some(
                src.rewards_reduction
                    .to_f64()
                    .ok_or("Conversion to f64 failed (rewards_reduction_percent)")?,
            ),
            base_rewards_xdr_permyriad: Some(
                src.base_rewards_xdr_permyriad
                    .to_f64()
                    .ok_or("Conversion to f64 failed (base_rewards_xdr_permyriad)")?,
            ),
            adjusted_rewards_xdr_permyriad: Some(
                src.adjusted_rewards_xdr_permyriad
                    .to_f64()
                    .ok_or("Conversion to f64 failed (adjusted_rewards_xdr_permyriad)")?,
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
                    .to_f64()
                    .ok_or("Conversion to f64 failed (monthly_xdr_permyriad)")?,
            ),
            daily_xdr_permyriad: Some(
                src.daily_xdr_permyriad
                    .to_f64()
                    .ok_or("Conversion to f64 failed (daily_xdr_permyriad)")?,
            ),
            node_reward_type: Some(src.node_reward_type.to_string()),
            region: Some(src.region),
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
                    .to_f64()
                    .ok_or("Conversion to f64 failed (avg_rewards_xdr_permyriad)")?,
            ),
            avg_coefficient: Some(
                src.avg_coefficient
                    .to_f64()
                    .ok_or("Conversion to f64 failed (avg_coefficient_percent)")?,
            ),
            daily_xdr_permyriad: Some(
                src.daily_xdr_permyriad
                    .to_f64()
                    .ok_or("Conversion to f64 failed (daily_xdr_permyriad)")?,
            ),
        })
    }
}

// DailyNodeProviderRewards conversions
impl TryFrom<native_types::DailyNodeProviderRewards> for DailyNodeProviderRewards {
    type Error = String;

    fn try_from(src: native_types::DailyNodeProviderRewards) -> Result<Self, Self::Error> {
        Ok(Self {
            total_base_rewards_xdr_permyriad: Some(src.total_base_rewards_xdr_permyriad),
            total_adjusted_rewards_xdr_permyriad: Some(src.total_adjusted_rewards_xdr_permyriad),
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

// DailyResults conversions
impl TryFrom<native_types::DailyResults> for DailyResults {
    type Error = String;

    fn try_from(src: native_types::DailyResults) -> Result<Self, Self::Error> {
        Ok(Self {
            subnets_failure_rate: src
                .subnets_failure_rate
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
                .map(|(k, v)| DailyNodeProviderRewards::try_from(v).map(|v| (k, v)))
                .collect::<Result<_, _>>()?,
        })
    }
}
