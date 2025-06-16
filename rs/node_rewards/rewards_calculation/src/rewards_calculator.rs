use crate::rewards_calculator_results::{
    days_between, NodeMetricsDaily, RewardCalculatorError, RewardsCalculatorResults,
};
use crate::types::{
    NodeMetricsDailyRaw, NodeType, ProviderRewardableNodes, Region, RewardPeriod,
    SubnetMetricsDailyKey,
};
use ic_base_types::{NodeId, PrincipalId};
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use itertools::Itertools;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::cmp::max;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::marker::PhantomData;
pub mod builder;

/// RewardsCalculator is responsible for calculating the rewards for nodes based on their performance metrics.
pub struct RewardsCalculator {
    /// The period for which the rewards will be calculated.
    reward_period: RewardPeriod,
    /// The table containing the rewards for each (region, node_type).
    rewards_table: NodeRewardsTable,
    /// The metrics for each node assigned to a subnet in the reward_period.
    metrics_by_node: HashMap<NodeId, Vec<NodeMetricsDaily>>,
    /// Rewardable Nodes per node provider
    rewardable_nodes_per_provider: BTreeMap<PrincipalId, ProviderRewardableNodes>,
}

impl RewardsCalculator {
    fn calculate_rewards(
        &self,
        provider_rewardable_nodes: &ProviderRewardableNodes,
    ) -> RewardsCalculatorResults {
        let ctx: RewardsCalculatorPipeline<Initialized> = RewardsCalculatorPipeline {
            reward_period: &self.reward_period,
            rewards_table: &self.rewards_table,
            metrics_by_node: &self.metrics_by_node,
            provider_rewardable_nodes,
            calculator_results: RewardsCalculatorResults::default(),

            _marker: PhantomData,
        };
        let computed: RewardsCalculatorPipeline<RewardsTotalComputed> =
            ctx.next().next().next().next().next().next().next().next();
        computed.get_results()
    }

    pub fn calculate_rewards_single_provider(
        &self,
        provider_id: PrincipalId,
    ) -> Result<RewardsCalculatorResults, RewardCalculatorError> {
        let rewardable_nodes = self
            .rewardable_nodes_per_provider
            .get(&provider_id)
            .ok_or(RewardCalculatorError::ProviderNotFound(provider_id))?;

        let rewards_result = self.calculate_rewards(rewardable_nodes);
        Ok(rewards_result)
    }

    pub fn calculate_rewards_per_provider(
        &self,
    ) -> BTreeMap<PrincipalId, RewardsCalculatorResults> {
        let mut res = BTreeMap::new();
        for (provider_id, rewardables) in self.rewardable_nodes_per_provider.iter() {
            let rewards_result = self.calculate_rewards(rewardables);
            res.insert(*provider_id, rewards_result);
        }
        res
    }
}

/// The minimum and maximum failure rates for a node.
/// Nodes with a failure rate below `MIN_FAILURE_RATE` will not be penalized.
/// Nodes with a failure rate above `MAX_FAILURE_RATE` will be penalized with `MAX_REWARDS_REDUCTION`.
const MIN_FAILURE_RATE: Decimal = dec!(0.1);
const MAX_FAILURE_RATE: Decimal = dec!(0.6);

/// The minimum and maximum rewards reduction for a node.
const MIN_REWARDS_REDUCTION: Decimal = dec!(0);
const MAX_REWARDS_REDUCTION: Decimal = dec!(0.8);

const FULL_REWARDS_MACHINES_LIMIT: u32 = 4;

/// From constant [NODE_PROVIDER_REWARD_PERIOD_SECONDS]
/// const NODE_PROVIDER_REWARD_PERIOD_SECONDS: u64 = 2629800;
/// 30.4375 = 2629800 / 86400
const REWARDS_TABLE_DAYS: Decimal = dec!(30.4375);

fn avg(values: &[Decimal]) -> Decimal {
    values.iter().sum::<Decimal>() / Decimal::from(values.len().max(1))
}

struct RewardsCalculatorPipeline<'a, T: ExecutionState> {
    reward_period: &'a RewardPeriod,
    rewards_table: &'a NodeRewardsTable,
    metrics_by_node: &'a HashMap<NodeId, Vec<NodeMetricsDaily>>,
    provider_rewardable_nodes: &'a ProviderRewardableNodes,

    calculator_results: RewardsCalculatorResults,
    _marker: PhantomData<T>,
}

impl<'a, T: ExecutionState> RewardsCalculatorPipeline<'a, T> {
    fn transition<S: ExecutionState>(self) -> RewardsCalculatorPipeline<'a, S> {
        RewardsCalculatorPipeline {
            provider_rewardable_nodes: self.provider_rewardable_nodes,
            metrics_by_node: self.metrics_by_node,
            calculator_results: self.calculator_results,
            reward_period: self.reward_period,
            rewards_table: self.rewards_table,
            _marker: PhantomData,
        }
    }
}

impl<'a> RewardsCalculatorPipeline<'a, Initialized> {
    pub(crate) fn next(self) -> RewardsCalculatorPipeline<'a, ComputeRewardableNodesMetrics> {
        RewardsCalculatorPipeline::transition(self)
    }
}

/// Extracts the rewardable nodes metrics from all the `metrics_by_node`.
impl<'a> RewardsCalculatorPipeline<'a, ComputeRewardableNodesMetrics> {
    pub(crate) fn next(mut self) -> RewardsCalculatorPipeline<'a, ComputeExtrapolatedFR> {
        for node in self.provider_rewardable_nodes.rewardable_nodes.iter() {
            let node_results = self
                .calculator_results
                .results_by_node
                .entry(node.node_id)
                .or_default();
            node_results.region = node.region.clone();
            node_results.node_type = node.node_type.clone();
            node_results.dc_id = node.dc_id.clone();
            node_results.rewardable_from = node.rewardable_from;
            node_results.rewardable_to = node.rewardable_to;
            node_results.rewardable_days = days_between(node.rewardable_from, node.rewardable_to);

            if let Some(rewardable_node_metrics) = self.metrics_by_node.get(&node.node_id) {
                rewardable_node_metrics
                    .iter()
                    .into_group_map_by(|daily_metrics| daily_metrics.day)
                    .into_values()
                    .for_each(|single_day_metrics| {
                        // Node can be assigned to different subnets on the same day.
                        // The algorithm considers for this case the subnet where the node has proposed and failed more blocks.
                        let selected = single_day_metrics
                            .into_iter()
                            .max_by_key(|m| m.num_blocks_proposed + m.num_blocks_failed)
                            .expect("Exists")
                            .clone();

                        node_results.daily_metrics.push(selected);
                    })
            }
            node_results
                .daily_metrics
                .sort_by_key(|daily_metrics| daily_metrics.day);
        }
        RewardsCalculatorPipeline::transition(self)
    }
}

/// Calculates the extrapolated failure rate used as replacement for days in which the node is not assigned
/// to a subnet.
///
/// For each node is computed the average of the relative failure rates `avg_relative_fr` recorded in the reward period.
/// The extrapolated failure rate is the average of these averages `extrapolated_fr`.
/// This is done to put higher weight on nodes with less recorded failure rates (assigned for fewer days).
impl<'a> RewardsCalculatorPipeline<'a, ComputeExtrapolatedFR> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<'a, ComputeAverageExtrapolatedFR> {
        let mut nodes_avg_rel_fr = Vec::new();
        for node_results in self.calculator_results.results_by_node.values_mut() {
            let rel_fr: Vec<Decimal> = node_results
                .daily_metrics
                .iter()
                .map(|daily_metrics| daily_metrics.relative_fr.get())
                .collect();

            // Do not consider nodes completely unassigned
            if !rel_fr.is_empty() {
                let avg_rel_fr = avg(&rel_fr);
                node_results.avg_relative_fr = Some(avg_rel_fr.into());
                nodes_avg_rel_fr.push(avg_rel_fr);
            }
        }
        self.calculator_results.extrapolated_fr = avg(&nodes_avg_rel_fr).into();
        RewardsCalculatorPipeline::transition(self)
    }
}

/// Calculates the average of the failure rates for each node in the reward period.
///
/// The average failure rate is used then to calculate the performance multiplier for each node.
/// The average failure rate is calculated as the average of:
///    - the `relative_fr` for each day in which the node is assigned to a subnet.
///    - the `extrapolated_fr` for each day in which the node is not assigned to a subnet.
impl<'a> RewardsCalculatorPipeline<'a, ComputeAverageExtrapolatedFR> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<'a, ComputePerformanceMultipliers> {
        for (_, node_results) in self.calculator_results.results_by_node.iter_mut() {
            let mut rel_fr: Vec<Decimal> = node_results
                .daily_metrics
                .iter()
                .map(|daily_metrics| daily_metrics.relative_fr.get())
                .collect();

            // Use the extrapolated failure rate on days in which the node is not assigned.
            // This covers also the case of nodes completely unassigned in the reward period
            rel_fr.resize(
                node_results.rewardable_days,
                self.calculator_results.extrapolated_fr.get(),
            );

            node_results.avg_extrapolated_fr = avg(&rel_fr).into();
        }

        RewardsCalculatorPipeline::transition(self)
    }
}

/// Calculates the performance multiplier for a node based on its average failure rate.
impl<'a> RewardsCalculatorPipeline<'a, ComputePerformanceMultipliers> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<'a, ComputeBaseRewardsByCategory> {
        for (_, node_results) in self.calculator_results.results_by_node.iter_mut() {
            let rewards_reduction;
            let avg_rel_ext_fr = node_results.avg_extrapolated_fr.get();

            if avg_rel_ext_fr < MIN_FAILURE_RATE {
                rewards_reduction = MIN_REWARDS_REDUCTION;
            } else if avg_rel_ext_fr > MAX_FAILURE_RATE {
                rewards_reduction = MAX_REWARDS_REDUCTION;
            } else {
                // Linear interpolation between MIN_REWARDS_REDUCTION and MAX_REWARDS_REDUCTION
                rewards_reduction = ((avg_rel_ext_fr - MIN_FAILURE_RATE)
                    / (MAX_FAILURE_RATE - MIN_FAILURE_RATE))
                    * MAX_REWARDS_REDUCTION;
            };

            node_results.rewards_reduction = rewards_reduction.into();
            node_results.performance_multiplier = (dec!(1) - rewards_reduction).into();
        }

        RewardsCalculatorPipeline::transition(self)
    }
}

struct Type3Rewards {
    coefficients: Vec<Decimal>,
    base_rewards_per_month: Vec<Decimal>,
    region_nodetype_cat: Vec<(Region, NodeType)>,
}

fn is_type3(node_type: &str) -> bool {
    node_type.starts_with("type3")
}

/// Calculate the base rewards for all the [NodeCategory].
///
/// The base rewards are calculated based on the rewards table entries for the specific region and node type.
/// For type3* nodes the base rewards are computed as the average of base rewards on DC Country level.
impl<'a> RewardsCalculatorPipeline<'a, ComputeBaseRewardsByCategory> {
    fn fill_nodes_base_rewards(
        &mut self,
        rewards_by_category: HashMap<(Region, NodeType), Decimal>,
    ) {
        for node_results in self.calculator_results.results_by_node.values_mut() {
            let node_category = (node_results.region.clone(), node_results.node_type.clone());
            let base_rewards_per_month = *rewards_by_category
                .get(&node_category)
                .expect("Each node category should have a base reward");

            node_results.base_rewards_per_month = base_rewards_per_month.into();
        }
    }

    pub fn next(mut self) -> RewardsCalculatorPipeline<'a, AdjustNodesRewards> {
        let mut rewards_by_category: HashMap<(Region, NodeType), Decimal> = HashMap::default();
        let mut type3_category_rewards: HashMap<String, Type3Rewards> = HashMap::default();

        for ((region, node_type), nodes_count) in
            self.provider_rewardable_nodes.rewardable_nodes_count.iter()
        {
            let (base_rewards_per_month, coefficient) = self
                .rewards_table
                .get_rate(&region.0, &node_type.0)
                .map(|rate| {
                    let base_rewards_per_month =
                        Decimal::from(rate.xdr_permyriad_per_node_per_month);
                    // Default reward_coefficient_percent is set to 80%, which is used as a fallback only in the
                    // unlikely case that the type3 entry in the reward table:
                    // a) has xdr_permyriad_per_node_per_month entry set for this region, but
                    // b) does NOT have the reward_coefficient_percent value set
                    let reward_coefficient_percent =
                        Decimal::from(rate.reward_coefficient_percent.unwrap_or(80)) / dec!(100);

                    (base_rewards_per_month, reward_coefficient_percent)
                })
                .unwrap_or((dec!(1), dec!(100)));

            // For nodes which are type3* the base rewards for the single node is computed as the average of base rewards
            // on DC Country level. Moreover, to de-stimulate the same NP having too many nodes in the same country,
            // the node rewards is reduced for each node the NP has in the given country. The reduction coefficient is
            // computed as the average of reduction coefficients on DC Country level.
            if is_type3(&node_type.0) && *nodes_count > 0 {
                let coefficients = vec![coefficient; *nodes_count as usize];
                let base_rewards_per_month = vec![base_rewards_per_month; *nodes_count as usize];

                // The rewards table contains entries of this form DC Continent + DC Country + DC State/City.
                // The grouping for type3* nodes will be on DC Continent + DC Country level. This group is used for computing
                // the reduction coefficient and base reward for the group.
                let region_key = region
                    .0
                    .splitn(3, ',')
                    .take(2)
                    .collect::<Vec<&str>>()
                    .join(":");

                type3_category_rewards
                    .entry(region_key)
                    .and_modify(|type3_rewards| {
                        type3_rewards.coefficients.extend(&coefficients);
                        type3_rewards
                            .base_rewards_per_month
                            .extend(&base_rewards_per_month);
                        type3_rewards
                            .region_nodetype_cat
                            .push((region.clone(), node_type.clone()));
                    })
                    .or_insert(Type3Rewards {
                        coefficients,
                        base_rewards_per_month,
                        region_nodetype_cat: vec![(region.clone(), node_type.clone())],
                    });
            } else {
                // For `rewardable_nodes` which are not type3* the base rewards for the sigle node is the entry
                // in the rewards table for the specific region (DC Continent + DC Country + DC State/City) and node type.
                rewards_by_category
                    .insert((region.clone(), node_type.clone()), base_rewards_per_month);
            }
        }

        // Computes node rewards for type3* nodes in all regions and add it to region_nodetype_rewards
        for (_, type3_rewards) in type3_category_rewards {
            let rewards_len = type3_rewards.base_rewards_per_month.len();

            let coefficients_avg = avg(&type3_rewards.coefficients);
            let rewards_avg = avg(&type3_rewards.base_rewards_per_month);

            let mut running_coefficient = dec!(1);
            let mut region_rewards = Vec::new();
            for _ in 0..rewards_len {
                region_rewards.push(rewards_avg * running_coefficient);
                running_coefficient *= coefficients_avg;
            }
            let region_rewards_avg = avg(&region_rewards);

            for node_category in type3_rewards.region_nodetype_cat {
                rewards_by_category.insert(node_category, region_rewards_avg);
            }
        }

        self.fill_nodes_base_rewards(rewards_by_category);
        RewardsCalculatorPipeline::transition(self)
    }
}

/// Calculate the adjusted rewards for all the nodes based on their performance.
impl<'a> RewardsCalculatorPipeline<'a, AdjustNodesRewards> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<'a, ComputeRewardsTotal> {
        let nodes_count = self.calculator_results.results_by_node.len() as u32;

        for node_results in self.calculator_results.results_by_node.values_mut() {
            let base_node_rewards: Decimal = node_results.base_rewards_per_month.clone().get()
                / REWARDS_TABLE_DAYS
                * Decimal::from(node_results.rewardable_days);
            node_results.base_rewards = base_node_rewards.into();

            if nodes_count <= FULL_REWARDS_MACHINES_LIMIT {
                // Node Providers with less than FULL_REWARDS_MACHINES_LIMIT machines are rewarded fully, independently of their performance

                node_results.adjusted_rewards = base_node_rewards.into();
            } else {
                node_results.adjusted_rewards =
                    (base_node_rewards * node_results.performance_multiplier.get()).into();
            }
        }

        RewardsCalculatorPipeline::transition(self)
    }
}

/// Calculate the adjusted rewards for all the nodes based on their performance.
impl<'a> RewardsCalculatorPipeline<'a, ComputeRewardsTotal> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<'a, RewardsTotalComputed> {
        let rewards_total = self
            .calculator_results
            .results_by_node
            .values()
            .map(|node_results| node_results.adjusted_rewards.get())
            .sum::<Decimal>();

        self.calculator_results.rewards_total = rewards_total.into();
        RewardsCalculatorPipeline::transition(self)
    }
}

impl RewardsCalculatorPipeline<'_, RewardsTotalComputed> {
    pub fn get_results(self) -> RewardsCalculatorResults {
        self.calculator_results
    }
}

pub trait ExecutionState {}

pub(crate) struct Initialized;
impl ExecutionState for Initialized {}

pub(crate) struct ComputeRewardableNodesMetrics;
impl ExecutionState for ComputeRewardableNodesMetrics {}
pub(crate) struct ComputeExtrapolatedFR;
impl ExecutionState for ComputeExtrapolatedFR {}
pub(crate) struct ComputeAverageExtrapolatedFR;
impl ExecutionState for ComputeAverageExtrapolatedFR {}
pub(crate) struct ComputePerformanceMultipliers;
impl ExecutionState for ComputePerformanceMultipliers {}
pub(crate) struct ComputeBaseRewardsByCategory;
impl ExecutionState for ComputeBaseRewardsByCategory {}
pub(crate) struct AdjustNodesRewards;
impl ExecutionState for AdjustNodesRewards {}
pub(crate) struct ComputeRewardsTotal;
impl ExecutionState for ComputeRewardsTotal {}
pub(crate) struct RewardsTotalComputed;
impl ExecutionState for RewardsTotalComputed {}

#[cfg(test)]
mod tests;
