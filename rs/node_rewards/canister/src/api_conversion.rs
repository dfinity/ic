use ic_node_rewards_canister_api::provider_rewards_calculation::{
    Assigned as AssignedCandid, BaseRewards as BaseRewardsCandid,
    DailyBaseRewardsType3 as DailyBaseRewardsType3Candid, DailyResults as DailyResultsCandid,
    DayUtc as DayUtcCandid, NodeMetricsDaily as NodeMetricsDailyCandid,
    NodeProviderRewards as NodeProviderRewardsCandid, NodeResults as NodeResultsCandid,
    NodeStatus as NodeStatusCandid, Unassigned as UnassignedCandid,
    node_status::Status as StatusCandid,
};
use rewards_calculation::rewards_calculator_results::{NodeProviderRewards, NodeStatus};

pub fn to_candid_type(rewards: NodeProviderRewards) -> NodeProviderRewardsCandid {
    NodeProviderRewardsCandid {
        rewards_total_xdr_permyriad: Some(rewards.rewards_total_xdr_permyriad),
        base_rewards: rewards
            .base_rewards
            .into_iter()
            .map(|br| BaseRewardsCandid {
                node_reward_type: Some(br.node_reward_type.to_string()),
                region: Some(br.region),
                monthly_xdr_permyriad: Some(br.monthly.into()),
                daily_xdr_permyriad: Some(br.daily.into()),
            })
            .collect(),
        base_rewards_type3: rewards
            .base_rewards_type3
            .into_iter()
            .map(|br3| DailyBaseRewardsType3Candid {
                day: Some(DayUtcCandid {
                    value: Some(br3.day.unix_ts_at_day_end()),
                }),
                region: Some(br3.region),
                nodes_count: Some(br3.nodes_count as u64),
                avg_rewards_xdr_permyriad: Some(br3.avg_rewards.into()),
                avg_coefficient_percent: Some(br3.avg_coefficient.into()),
                value_xdr_permyriad: Some(br3.value.into()),
            })
            .collect(),
        nodes_results: rewards
            .nodes_results
            .into_iter()
            .map(|nr| NodeResultsCandid {
                node_id: Some(nr.node_id.get()),
                node_reward_type: Some(nr.node_reward_type.to_string()),
                region: Some(nr.region),
                dc_id: Some(nr.dc_id),
                daily_results: nr
                    .daily_results
                    .into_iter()
                    .map(|dr| DailyResultsCandid {
                        day: Some(DayUtcCandid {
                            value: Some(dr.day.unix_ts_at_day_end()),
                        }),
                        node_status: match dr.node_status {
                            NodeStatus::Assigned { node_metrics } => Some(NodeStatusCandid {
                                status: Some(StatusCandid::Assigned(AssignedCandid {
                                    node_metrics: Some(NodeMetricsDailyCandid {
                                        subnet_assigned: Some(node_metrics.subnet_assigned.get()),
                                        subnet_assigned_fr_percent: Some(
                                            node_metrics.subnet_assigned_fr.into(),
                                        ),
                                        num_blocks_proposed: Some(node_metrics.num_blocks_proposed),
                                        num_blocks_failed: Some(node_metrics.num_blocks_failed),
                                        original_fr_percent: Some(node_metrics.original_fr.into()),
                                        relative_fr_percent: Some(node_metrics.relative_fr.into()),
                                    }),
                                })),
                            }),
                            NodeStatus::Unassigned { extrapolated_fr } => Some(NodeStatusCandid {
                                status: Some(StatusCandid::Unassigned(UnassignedCandid {
                                    extrapolated_fr_percent: Some(extrapolated_fr.into()),
                                })),
                            }),
                        },
                        performance_multiplier_percent: Some(dr.performance_multiplier.into()),
                        rewards_reduction_percent: Some(dr.rewards_reduction.into()),
                        base_rewards_xdr_permyriad: Some(dr.base_rewards.into()),
                        adjusted_rewards_xdr_permyriad: Some(dr.adjusted_rewards.into()),
                    })
                    .collect(),
            })
            .collect(),
    }
}
