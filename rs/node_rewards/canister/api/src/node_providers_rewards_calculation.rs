use crate::common::{DayUTC, Percent, RewardPeriodArgs, XDRPermyriad};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use rewards_calculation::rewards_calculator_results;
use std::collections::BTreeMap;

#[derive(candid::CandidType, candid::Deserialize)]
pub struct NodeProviderRewardsCalculationArgs {
    pub provider_id: PrincipalId,
    pub reward_period: RewardPeriodArgs,
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct NodeMetricsDaily {
    pub day: Option<DayUTC>,
    pub subnet_assigned: Option<SubnetId>,

    /// Subnet Assigned Failure Rate.
    ///
    /// The failure rate of the entire subnet.
    /// Calculated as 75th percentile of the failure rate of all nodes in the subnet.
    pub subnet_assigned_fr: Option<Percent>,

    /// The number of proposed blocks for this node on this day
    pub num_blocks_proposed: Option<u64>,

    /// The number of failed blocks for this node on this day
    pub num_blocks_failed: Option<u64>,

    /// Original Failure Rate.
    ///
    /// The failure rate before subnet failure rate reduction.
    /// Calculated as `blocks_failed` / (`blocks_proposed` + `blocks_failed`)
    pub original_fr: Option<Percent>,

    /// Relative Failure Rate (`RFR`).
    ///
    /// The failure rate reduced by the subnet assigned failure rate.
    /// Calculated as Max(0, `original_fr` - `subnet_assigned_fr`)
    pub relative_fr: Option<Percent>,
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct NodeResults {
    pub node_type: Option<String>,
    pub region: Option<String>,
    pub dc_id: Option<String>,

    /// The UTC day on which a node becomes rewardable (i.e., is present in the registry) within the given reward period.
    /// If the node was already in the registry before the reward period's start_ts, this day aligns with the UTC day of the start_ts.
    pub rewardable_from: Option<DayUTC>,

    /// The UTC day on which a node ceases to be rewardable (i.e., is last present in the registry) within the given reward period.
    /// If the node remains in the registry after the reward period's end_ts, this day aligns with the UTC day of the end_ts.
    pub rewardable_to: Option<DayUTC>,

    /// Number of UTC days in which the node is rewardable (i.e., is present in the registry)
    pub rewardable_days: Option<u64>,

    /// The node metrics for all the days the node was rewardable and assigned
    pub daily_metrics: Option<Vec<NodeMetricsDaily>>,

    /// Average Relative Failure Rate (`ARFR`).
    ///
    /// Average of `RFR` for the entire reward period.
    /// None if the node is unassigned in the entire reward period
    pub avg_relative_fr: Option<Option<Percent>>,

    /// Average Extrapolated Failure Rate (`AEFR`).
    ///
    /// Failure rate average for the entire reward period
    /// - On days when the node is unassigned `EFR` is used
    /// - On days when the node is assigned `RFR` is used
    pub avg_extrapolated_fr: Option<Percent>,

    /// Rewards reduction (`RR`).
    ///
    /// - For nodes with `AEFR` < 0.1, the rewards reduction is 0
    /// - For nodes with `AEFR` > 0.6, the rewards reduction is 0.8
    /// - For nodes with 0.1 <= `AEFR` <= 0.6, the rewards reduction is linearly interpolated between 0 and 0.8
    pub rewards_reduction: Option<Percent>,

    /// Performance multiplier (`PM`).
    ///
    /// Calculated as 1 - 'RR'
    pub performance_multiplier: Option<Percent>,
    pub base_rewards_per_month: Option<XDRPermyriad>,

    /// Base Rewards for the rewards period.
    ///
    /// Currently, 1/12 of a year: 365.25 / 12 = 30.4375
    /// 365.25: This represents the average length of a year in days, accounting for leap years
    /// Calculated as `base_rewards_per_month` / 30.4375 * `rewardable_days`
    pub base_rewards: Option<XDRPermyriad>,

    /// Adjusted rewards (`AR`).
    ///
    /// Calculated as base_rewards * `PM`
    pub adjusted_rewards: Option<XDRPermyriad>,
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct RewardsCalculatorResults {
    pub results_by_node: Option<BTreeMap<NodeId, NodeResults>>,

    /// Extrapolated Failure Rate (`EFR`).
    ///
    /// Extrapolated failure rate used as replacement for days when the node is unassigned
    pub extrapolated_fr: Option<Percent>,

    /// Rewards Total
    ///
    /// The total rewards for the entire reward period computed as sum of the `AR`
    pub rewards_total: Option<XDRPermyriad>,
}

impl TryFrom<rewards_calculator_results::RewardsCalculatorResults> for RewardsCalculatorResults {
    type Error = String;

    fn try_from(
        value: rewards_calculator_results::RewardsCalculatorResults,
    ) -> Result<Self, Self::Error> {
        let results_by_node = value
            .results_by_node
            .into_iter()
            .map(|(node_id, node_results)| {
                let region = Some(node_results.region.0);
                let node_type = Some(node_results.node_type.0);
                let dc_id = Some(node_results.dc_id.to_string());
                let avg_relative_fr = Some(
                    node_results
                        .avg_relative_fr
                        .map(|fr| fr.try_into())
                        .transpose()?,
                );

                let daily_node_results: Vec<_> = node_results
                    .daily_metrics
                    .into_iter()
                    .map(|daily_metrics| {
                        Ok(NodeMetricsDaily {
                            day: Some(daily_metrics.day.into()),
                            subnet_assigned: Some(daily_metrics.subnet_assigned),
                            subnet_assigned_fr: Some(daily_metrics.subnet_assigned_fr.try_into()?),
                            num_blocks_proposed: Some(daily_metrics.num_blocks_proposed),
                            num_blocks_failed: Some(daily_metrics.num_blocks_failed),
                            original_fr: Some(daily_metrics.original_fr.try_into()?),
                            relative_fr: Some(daily_metrics.relative_fr.try_into()?),
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;

                Ok((
                    node_id,
                    NodeResults {
                        node_type,
                        region,
                        dc_id,
                        daily_metrics: Some(daily_node_results),
                        avg_relative_fr,
                        rewardable_from: Some(node_results.rewardable_from.into()),
                        rewardable_to: Some(node_results.rewardable_to.into()),
                        rewardable_days: Some(node_results.rewardable_days as u64),
                        avg_extrapolated_fr: Some(node_results.avg_extrapolated_fr.try_into()?),
                        rewards_reduction: Some(node_results.rewards_reduction.try_into()?),
                        performance_multiplier: Some(
                            node_results.performance_multiplier.try_into()?,
                        ),
                        base_rewards_per_month: Some(
                            node_results.base_rewards_per_month.try_into()?,
                        ),
                        base_rewards: Some(node_results.base_rewards.try_into()?),
                        adjusted_rewards: Some(node_results.adjusted_rewards.try_into()?),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;

        Ok(Self {
            results_by_node: Some(results_by_node),
            extrapolated_fr: Some(value.extrapolated_fr.try_into()?),
            rewards_total: Some(value.rewards_total.try_into()?),
        })
    }
}
