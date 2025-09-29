use ic_base_types::PrincipalId;
use ic_node_rewards_canister_api::provider_rewards_calculation::{
    BaseRewards as BaseRewardsCandid, BaseRewardsType3 as BaseRewardsType3Candid,
    GetNodeProviderRewardsCalculationResponse, NodeMetricsDaily as NodeMetricsDailyCandid,
    NodeProviderRewards as NodeProviderRewardsCandid, NodeProviderRewardsDaily,
    NodeResults as NodeResultsCandid, NodeStatus as NodeStatusCandid,
};
use rewards_calculation::performance_based_algorithm::results::{
    NodeStatus, RewardsCalculatorResults,
};

pub fn into_rewards_calculation_results(
    results: RewardsCalculatorResults,
    provider_id: PrincipalId,
) -> GetNodeProviderRewardsCalculationResponse {
    let mut daily_rewards: Vec<NodeProviderRewardsDaily> = Vec::new();

    for (day, mut daily_results) in results.daily_results {
        let daily_provider_results = daily_results
            .provider_results
            .remove(&provider_id)
            .ok_or(format!("No results found for provider_id: {}", provider_id))?;

        let nodes_results = daily_provider_results
            .nodes_results
            .iter()
            .map(|nr| NodeResultsCandid {
                node_id: Some(nr.node_id.get()),
                node_reward_type: Some(nr.node_reward_type.to_string()),
                region: Some(nr.region.clone()),
                dc_id: Some(nr.dc_id.clone()),
                node_status: match &nr.node_status {
                    NodeStatus::Assigned { node_metrics } => Some(NodeStatusCandid::Assigned {
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
                    }),
                    NodeStatus::Unassigned { extrapolated_fr } => {
                        Some(NodeStatusCandid::Unassigned {
                            extrapolated_fr_percent: Some((*extrapolated_fr).into()),
                        })
                    }
                },
                performance_multiplier_percent: Some(nr.performance_multiplier.into()),
                rewards_reduction_percent: Some(nr.rewards_reduction.into()),
                base_rewards_xdr_permyriad: Some(nr.base_rewards.into()),
                adjusted_rewards_xdr_permyriad: Some(nr.adjusted_rewards.into()),
            })
            .collect();

        // Map BaseRewards
        let base_rewards = daily_provider_results
            .base_rewards
            .iter()
            .map(|br| BaseRewardsCandid {
                monthly_xdr_permyriad: Some(br.monthly.into()),
                daily_xdr_permyriad: Some(br.daily.into()),
                node_reward_type: Some(br.node_reward_type.to_string()),
                region: Some(br.region.clone()),
            })
            .collect();

        // Map BaseRewardsType3
        let base_rewards_type3 = daily_provider_results
            .base_rewards_type3
            .iter()
            .map(|br3| BaseRewardsType3Candid {
                region: Some(br3.region.clone()),
                nodes_count: Some(br3.nodes_count as u64),
                avg_rewards_xdr_permyriad: Some(br3.avg_rewards.into()),
                avg_coefficient_percent: Some(br3.avg_coefficient.into()),
                value_xdr_permyriad: Some(br3.value.into()),
            })
            .collect();

        let node_provider_rewards = NodeProviderRewardsCandid {
            rewards_total_xdr_permyriad: Some(daily_provider_results.rewards_total.into()),
            base_rewards,
            base_rewards_type3,
            nodes_results,
        };

        daily_rewards.push(NodeProviderRewardsDaily {
            day_utc: Some(day.into()),
            node_provider_rewards: Some(node_provider_rewards),
        });
    }
    Ok(daily_rewards)
}
