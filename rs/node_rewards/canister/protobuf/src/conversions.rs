use crate::pb;
use ic_base_types::SubnetId;
use ic_management_canister_types::NodeMetrics;
use rewards_calculation::rewards_calculator_results::{
    BaseRewards, DailyBaseRewardsType3, DailyResults, NodeMetricsDaily, NodeProviderRewards,
    NodeResults, NodeStatus,
};
use rewards_calculation::types::{DayUtc, SubnetMetricsDailyKey};

impl From<SubnetId> for pb::ic_node_rewards::v1::SubnetIdKey {
    fn from(subnet_id: SubnetId) -> Self {
        Self {
            subnet_id: Some(subnet_id.get()),
        }
    }
}

impl From<pb::ic_node_rewards::v1::SubnetIdKey> for SubnetId {
    fn from(subnet_id: pb::ic_node_rewards::v1::SubnetIdKey) -> Self {
        subnet_id.subnet_id.unwrap().into()
    }
}

impl From<pb::ic_node_rewards::v1::SubnetMetricsKey> for SubnetMetricsDailyKey {
    fn from(key: pb::ic_node_rewards::v1::SubnetMetricsKey) -> Self {
        Self {
            day: key.timestamp_nanos.into(),
            subnet_id: SubnetId::from(key.subnet_id.unwrap()),
        }
    }
}

impl From<NodeMetrics> for pb::ic_node_rewards::v1::NodeMetrics {
    fn from(metrics: NodeMetrics) -> Self {
        pb::ic_node_rewards::v1::NodeMetrics {
            node_id: Some(metrics.node_id.into()),
            num_blocks_proposed_total: metrics.num_blocks_proposed_total,
            num_blocks_failed_total: metrics.num_block_failures_total,
        }
    }
}

impl From<NodeProviderRewards> for pb::rewards_calculator::v1::NodeProviderRewards {
    fn from(
        NodeProviderRewards {
            rewards_total_xdr_permyriad,
            base_rewards,
            base_rewards_type3,
            nodes_results,
        }: NodeProviderRewards,
    ) -> Self {
        Self {
            rewards_total_xdr_permyriad: rewards_total_xdr_permyriad.into(),
            base_rewards: base_rewards.into_iter().map(Into::into).collect(),
            base_rewards_type3: base_rewards_type3.into_iter().map(Into::into).collect(),
            nodes_results: nodes_results.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<NodeResults> for pb::rewards_calculator::v1::NodeResults {
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
            node_id: Some(node_id.get()),
            node_reward_type: Some(node_reward_type.to_string()),
            region: Some(region),
            dc_id: Some(dc_id),
            daily_results: daily_results.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<DailyResults> for pb::rewards_calculator::v1::DailyResults {
    fn from(
        DailyResults {
            day,
            node_status,
            performance_multiplier,
            rewards_reduction,
            base_rewards,
            adjusted_rewards,
        }: DailyResults,
    ) -> Self {
        Self {
            day: Some(day.into()),
            node_status: Some(node_status.into()),
            performance_multiplier_percent: Some(performance_multiplier.into()),
            rewards_reduction_percent: Some(rewards_reduction.into()),
            base_rewards_xdr_permyriad: Some(base_rewards.into()),
            adjusted_rewards_xdr_permyriad: Some(adjusted_rewards.into()),
        }
    }
}

impl From<BaseRewards> for pb::rewards_calculator::v1::BaseRewards {
    fn from(
        BaseRewards {
            node_reward_type,
            region,
            monthly,
            daily,
        }: BaseRewards,
    ) -> Self {
        Self {
            node_reward_type: Some(node_reward_type.as_str_name().to_string()),
            region: Some(region),
            monthly_xdr_permyriad: Some(monthly.into()),
            daily_xdr_permyriad: Some(daily.into()),
        }
    }
}

impl From<DailyBaseRewardsType3> for pb::rewards_calculator::v1::DailyBaseRewardsType3 {
    fn from(
        DailyBaseRewardsType3 {
            day,
            region,
            nodes_count,
            avg_rewards,
            avg_coefficient,
            value,
        }: DailyBaseRewardsType3,
    ) -> Self {
        Self {
            day: Some(day.into()),
            region: Some(region),
            nodes_count: Some(nodes_count as u64),
            avg_rewards_xdr_permyriad: Some(avg_rewards.into()),
            avg_coefficient_percent: Some(avg_coefficient.into()),
            value_xdr_permyriad: Some(value.into()),
        }
    }
}

impl From<NodeStatus> for pb::rewards_calculator::v1::NodeStatus {
    fn from(value: NodeStatus) -> Self {
        match value {
            NodeStatus::Assigned { node_metrics } => Self {
                status: Some(pb::rewards_calculator::v1::node_status::Status::Assigned(
                    pb::rewards_calculator::v1::Assigned {
                        node_metrics: Some(node_metrics.into()),
                    },
                )),
            },
            NodeStatus::Unassigned { extrapolated_fr } => Self {
                status: Some(pb::rewards_calculator::v1::node_status::Status::Unassigned(
                    pb::rewards_calculator::v1::Unassigned {
                        extrapolated_fr_percent: Some(extrapolated_fr.into()),
                    },
                )),
            },
        }
    }
}

impl From<DayUtc> for pb::rewards_calculator::v1::DayUtc {
    fn from(day: DayUtc) -> Self {
        Self {
            value: Some(day.unix_ts_at_day_end()),
        }
    }
}

impl From<NodeMetricsDaily> for pb::rewards_calculator::v1::NodeMetricsDaily {
    fn from(
        NodeMetricsDaily {
            subnet_assigned,
            subnet_assigned_fr,
            num_blocks_proposed,
            num_blocks_failed,
            original_fr,
            relative_fr,
        }: NodeMetricsDaily,
    ) -> Self {
        Self {
            subnet_assigned: Some(subnet_assigned.get()),
            subnet_assigned_fr_percent: Some(subnet_assigned_fr.into()),
            num_blocks_proposed: Some(num_blocks_proposed),
            num_blocks_failed: Some(num_blocks_failed),
            original_fr_percent: Some(original_fr.into()),
            relative_fr_percent: Some(relative_fr.into()),
        }
    }
}
