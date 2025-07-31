use crate::pb::ic_node_rewards::v1::{SubnetIdKey, SubnetMetricsKey};
use crate::pb::rewards_calculator::v1::{node_status, Assigned, Unassigned};
use ic_base_types::SubnetId;
use ic_management_canister_types::NodeMetrics;
use rewards_calculation::rewards_calculator_results::{
    DailyResults, DayUtc, NodeMetricsDaily, NodeProviderRewards, NodeResults, NodeStatus,
};
use rewards_calculation::types::SubnetMetricsDailyKey;

impl From<SubnetId> for SubnetIdKey {
    fn from(subnet_id: SubnetId) -> Self {
        Self {
            subnet_id: Some(subnet_id.get()),
        }
    }
}

impl From<SubnetIdKey> for SubnetId {
    fn from(subnet_id: SubnetIdKey) -> Self {
        subnet_id.subnet_id.unwrap().into()
    }
}

impl From<SubnetMetricsKey> for SubnetMetricsDailyKey {
    fn from(key: SubnetMetricsKey) -> Self {
        Self {
            day: key.timestamp_nanos.into(),
            subnet_id: SubnetId::from(key.subnet_id.unwrap()),
        }
    }
}

impl From<NodeMetrics> for crate::pb::ic_node_rewards::v1::NodeMetrics {
    fn from(metrics: NodeMetrics) -> Self {
        crate::pb::ic_node_rewards::v1::NodeMetrics {
            node_id: Some(metrics.node_id.into()),
            num_blocks_proposed_total: metrics.num_blocks_proposed_total,
            num_blocks_failed_total: metrics.num_block_failures_total,
        }
    }
}

impl From<NodeProviderRewards> for crate::pb::rewards_calculator::v1::NodeProviderRewards {
    fn from(
        NodeProviderRewards {
            rewards_total_xdr_permyriad,
            computation_log,
            nodes_results,
        }: NodeProviderRewards,
    ) -> Self {
        Self {
            rewards_total_xdr_permyriad: rewards_total_xdr_permyriad.into(),
            computation_log: Some(computation_log),
            nodes_results: nodes_results.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<NodeResults> for crate::pb::rewards_calculator::v1::NodeResults {
    fn from(
        NodeResults {
            node_id,
            node_reward_type,
            region,
            dc_id,
            daily_results,
        }: NodeResults,
    ) -> Self {
        Self {
            node_id: Some(node_id.get().into()),
            node_reward_type: Some(node_reward_type),
            region: Some(region),
            dc_id: Some(dc_id),
            daily_results: daily_results.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<DailyResults> for crate::pb::rewards_calculator::v1::DailyResults {
    fn from(
        DailyResults {
            day,
            node_status,
            performance_multiplier_percent,
            rewards_reduction_percent,
            base_rewards_xdr_permyriad,
            adjusted_rewards_xdr_permyriad,
        }: DailyResults,
    ) -> Self {
        Self {
            day: Some(day.into()),
            node_status: Some(node_status.into()),
            performance_multiplier_percent: Some(performance_multiplier_percent.into()),
            rewards_reduction_percent: Some(rewards_reduction_percent.into()),
            base_rewards_xdr_permyriad: Some(base_rewards_xdr_permyriad.into()),
            adjusted_rewards_xdr_permyriad: Some(adjusted_rewards_xdr_permyriad.into()),
        }
    }
}

impl From<NodeStatus> for crate::pb::rewards_calculator::v1::NodeStatus {
    fn from(value: NodeStatus) -> Self {
        match value {
            NodeStatus::Assigned { node_metrics } => Self {
                status: Some(node_status::Status::Assigned(Assigned {
                    node_metrics: Some(node_metrics.into()),
                })),
            },
            NodeStatus::Unassigned {
                extrapolated_fr_percent,
            } => Self {
                status: Some(node_status::Status::Unassigned(Unassigned {
                    extrapolated_fr_percent: Some(extrapolated_fr_percent.into()),
                })),
            },
        }
    }
}

impl From<DayUtc> for crate::pb::rewards_calculator::v1::DayUtc {
    fn from(day: DayUtc) -> Self {
        Self {
            value: Some(day.unix_ts_at_day_end()),
        }
    }
}

impl From<NodeMetricsDaily> for crate::pb::rewards_calculator::v1::NodeMetricsDaily {
    fn from(
        NodeMetricsDaily {
            subnet_assigned,
            subnet_assigned_fr_percent,
            num_blocks_proposed,
            num_blocks_failed,
            original_fr_percent,
            relative_fr_percent,
        }: NodeMetricsDaily,
    ) -> Self {
        Self {
            subnet_assigned: Some(subnet_assigned.get()),
            subnet_assigned_fr_percent: Some(subnet_assigned_fr_percent.into()),
            num_blocks_proposed: Some(num_blocks_proposed),
            num_blocks_failed: Some(num_blocks_failed),
            original_fr_percent: Some(original_fr_percent.into()),
            relative_fr_percent: Some(relative_fr_percent.into()),
        }
    }
}
