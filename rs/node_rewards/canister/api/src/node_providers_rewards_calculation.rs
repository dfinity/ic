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
/// see [`rewards_calculator_results::NodeMetricsDaily`]
pub struct NodeMetricsDaily {
    pub day: DayUTC,
    pub subnet_assigned: SubnetId,

    /// Subnet Assigned Failure Rate.
    ///
    /// The failure rate of the entire subnet.
    /// Calculated as 75th percentile of the failure rate of all nodes in the subnet.
    pub subnet_assigned_fr: Percent,

    /// The number of proposed blocks for this node on this day
    pub num_blocks_proposed: u64,

    /// The number of failed blocks for this node on this day
    pub num_blocks_failed: u64,

    /// Original Failure Rate.
    ///
    /// The failure rate before subnet failure rate reduction.
    /// Calculated as `blocks_failed` / (`blocks_proposed` + `blocks_failed`)
    pub original_fr: Percent,

    /// Relative Failure Rate (`RFR`).
    ///
    /// The failure rate reduced by the subnet assigned failure rate.
    /// Calculated as Max(0, `original_fr` - `subnet_assigned_fr`)
    pub relative_fr: Percent,
}

#[derive(candid::CandidType, candid::Deserialize)]
/// see [`rewards_calculator_results::NodeResults`]
pub struct NodeResults {
    pub node_type: String,
    pub region: String,
    pub dc_id: String,

    /// The UTC day on which a node becomes rewardable (i.e., is present in the registry) within the given reward period.
    /// If the node was already in the registry before the reward period's start_ts, this day aligns with the UTC day of the start_ts.
    pub rewardable_from: DayUTC,

    /// The UTC day on which a node ceases to be rewardable (i.e., is last present in the registry) within the given reward period.
    /// If the node remains in the registry after the reward period's end_ts, this day aligns with the UTC day of the end_ts.
    pub rewardable_to: DayUTC,
    pub rewardable_days: u64,
    pub daily_metrics: Vec<NodeMetricsDaily>,
    pub avg_relative_fr: Option<Percent>,
    pub avg_extrapolated_fr: Percent,
    pub rewards_reduction: Percent,
    pub performance_multiplier: Percent,
    pub base_rewards_per_month: XDRPermyriad,
    pub base_rewards: XDRPermyriad,
    pub adjusted_rewards: XDRPermyriad,
}

#[derive(candid::CandidType, candid::Deserialize)]
/// see [`rewards_calculator_results::RewardsCalculatorResults`]
pub struct RewardsCalculatorResults {
    pub results_by_node: BTreeMap<NodeId, NodeResults>,
    pub extrapolated_fr: Percent,
    pub rewards_total: XDRPermyriad,
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
                let region = node_results.region.0;
                let node_type = node_results.node_type.0;
                let dc_id = node_results.dc_id.to_string();
                let avg_relative_fr = node_results
                    .avg_relative_fr
                    .map(|fr| fr.try_into())
                    .transpose()?;

                let daily_node_results: Vec<_> = node_results
                    .daily_metrics
                    .into_iter()
                    .map(|daily_metrics| {
                        Ok(NodeMetricsDaily {
                            day: daily_metrics.day.into(),
                            subnet_assigned: daily_metrics.subnet_assigned,
                            subnet_assigned_fr: daily_metrics.subnet_assigned_fr.try_into()?,
                            num_blocks_proposed: daily_metrics.num_blocks_proposed,
                            num_blocks_failed: daily_metrics.num_blocks_failed,
                            original_fr: daily_metrics.original_fr.try_into()?,
                            relative_fr: daily_metrics.relative_fr.try_into()?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;

                Ok((
                    node_id,
                    NodeResults {
                        node_type,
                        region,
                        dc_id,
                        daily_metrics: daily_node_results,
                        avg_relative_fr,
                        rewardable_from: node_results.rewardable_from.into(),
                        rewardable_to: node_results.rewardable_to.into(),
                        rewardable_days: node_results.rewardable_days as u64,
                        avg_extrapolated_fr: node_results.avg_extrapolated_fr.try_into()?,
                        rewards_reduction: node_results.rewards_reduction.try_into()?,
                        performance_multiplier: node_results.performance_multiplier.try_into()?,
                        base_rewards_per_month: node_results.base_rewards_per_month.try_into()?,
                        base_rewards: node_results.base_rewards.try_into()?,
                        adjusted_rewards: node_results.adjusted_rewards.try_into()?,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;

        Ok(Self {
            results_by_node,
            extrapolated_fr: value.extrapolated_fr.try_into()?,
            rewards_total: value.rewards_total.try_into()?,
        })
    }
}
