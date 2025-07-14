use crate::rewards_calculator_results::{
    DailyResults, DayUTC, NodeMetricsDaily, NodeProviderResults, NodeResults, NodeStatus, Percent,
    RewardCalculatorError, RewardsCalculatorResults, XDRPermyriad,
};
use crate::types::{
    NodeMetricsDailyRaw, ProviderRewardableNodes, Region, RewardPeriod, SubnetMetricsDailyKey,
};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use itertools::Itertools;
use rust_decimal::prelude::Zero;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::cmp::max;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::marker::PhantomData;

pub struct RewardsCalculatorInput {
    pub reward_period: RewardPeriod,
    pub rewards_table: NodeRewardsTable,
    pub daily_metrics_by_subnet: HashMap<SubnetMetricsDailyKey, Vec<NodeMetricsDailyRaw>>,
    pub rewardable_nodes: Vec<ProviderRewardableNodes>,
}

fn validate_input(input: &RewardsCalculatorInput) -> Result<(), RewardCalculatorError> {
    for (key, daily_metrics) in input.daily_metrics_by_subnet.iter() {
        // Check if all metrics are within the reward period
        if !input.reward_period.contains(key.day) {
            return Err(RewardCalculatorError::SubnetMetricsOutOfRange {
                subnet_id: key.subnet_id,
                day: key.day,
                reward_period: input.reward_period.clone(),
            });
        }

        // Metrics are unique if there are no duplicate entries for the same day and subnet.
        // Metrics with the same timestamp and different subnet are allowed.
        let unique_node = daily_metrics
            .iter()
            .map(|entry| entry.node_id)
            .collect::<HashSet<_>>();
        if unique_node.len() != daily_metrics.len() {
            return Err(RewardCalculatorError::DuplicateMetrics(
                key.subnet_id,
                key.day,
            ));
        }
    }

    Ok(())
}

pub fn calculate_rewards(
    input: RewardsCalculatorInput,
) -> Result<RewardsCalculatorResults, RewardCalculatorError> {
    validate_input(&input)?;

    let ctx: RewardsCalculatorPipeline<Initialized> = RewardsCalculatorPipeline {
        input,
        intermediate_results: IntermediateResults::default(),
        _marker: PhantomData,
    };
    let computed: RewardsCalculatorPipeline<RewardsTotalComputed> = ctx
        .next()
        .next()
        .next()
        .next()
        .next()
        .next()
        .next()
        .next()
        .next();
    let result = computed.construct_results();

    Ok(result)
}

/// The percentile used to calculate the failure rate for a subnet.
const SUBNET_FAILURE_RATE_PERCENTILE: f64 = 0.75;

/// The minimum and maximum failure rates for a node.
/// Nodes with a failure rate below `MIN_FAILURE_RATE` will not be penalized.
/// Nodes with a failure rate above `MAX_FAILURE_RATE` will be penalized with `MAX_REWARDS_REDUCTION`.
const MIN_FAILURE_RATE: Decimal = dec!(0.1);
const MAX_FAILURE_RATE: Decimal = dec!(0.6);

/// The minimum and maximum rewards reduction for a node.
const MIN_REWARDS_REDUCTION: Decimal = dec!(0);
const MAX_REWARDS_REDUCTION: Decimal = dec!(0.8);

const FULL_REWARDS_MACHINES_LIMIT: usize = 4;

/// From constant [NODE_PROVIDER_REWARD_PERIOD_SECONDS]
/// const NODE_PROVIDER_REWARD_PERIOD_SECONDS: u64 = 2629800;
/// 30.4375 = 2629800 / 86400
const REWARDS_TABLE_DAYS: Decimal = dec!(30.4375);

fn avg(values: &[Decimal]) -> Decimal {
    values.iter().sum::<Decimal>() / Decimal::from(values.len().max(1))
}

type RewardsCoefficientPercent = Decimal;
type RegionKey = String;

#[derive(Default, Clone)]
struct IntermediateResults {
    original_nodes_fr: BTreeMap<(DayUTC, NodeId), Percent>,
    subnets_fr: BTreeMap<(DayUTC, SubnetId), Percent>,
    relative_nodes_fr: BTreeMap<(DayUTC, NodeId), Percent>,
    extrapolated_fr: BTreeMap<(PrincipalId, DayUTC), Percent>,
    reward_reduction: BTreeMap<(DayUTC, NodeId), Percent>,
    performance_multiplier: BTreeMap<(DayUTC, NodeId), Percent>,
    base_rewards_type_region: BTreeMap<(NodeRewardType, Region), XDRPermyriad>,
    type3_base_rewards_type_region: BTreeMap<(PrincipalId, DayUTC, RegionKey), XDRPermyriad>,
    base_rewards: BTreeMap<(DayUTC, NodeId), XDRPermyriad>,
    nodes_count: BTreeMap<(PrincipalId, DayUTC), usize>,
    adjusted_rewards: BTreeMap<(DayUTC, NodeId), XDRPermyriad>,
    rewards_total: BTreeMap<PrincipalId, XDRPermyriad>,
}

struct RewardsCalculatorPipeline<T: ExecutionState> {
    input: RewardsCalculatorInput,
    intermediate_results: IntermediateResults,
    _marker: PhantomData<T>,
}

impl<T: ExecutionState> RewardsCalculatorPipeline<T> {
    fn transition<S: ExecutionState>(self) -> RewardsCalculatorPipeline<S> {
        RewardsCalculatorPipeline {
            input: self.input,
            intermediate_results: self.intermediate_results,
            _marker: PhantomData,
        }
    }
}
impl RewardsCalculatorPipeline<Initialized> {
    pub(crate) fn next(self) -> RewardsCalculatorPipeline<ComputeSubnetsNodesFR> {
        RewardsCalculatorPipeline::transition(self)
    }
}

/// Calculates the daily failure rate for each node in each subnet and for the subnet itself.
/// - The failure rate for a node is calculated as the ratio of blocks failed to total blocks.
/// - The failure rate for a subnet is calculated as the 'SUBNET_FAILURE_RATE_PERCENTILE' of the failure rates of its nodes.
impl RewardsCalculatorPipeline<ComputeSubnetsNodesFR> {
    pub(crate) fn next(mut self) -> RewardsCalculatorPipeline<ComputeProvidersExtrapolatedFR> {
        fn calculate_daily_node_fr(num_blocks_proposed: u64, num_blocks_failed: u64) -> Decimal {
            let total_blocks = Decimal::from(num_blocks_proposed + num_blocks_failed);
            if total_blocks == Decimal::ZERO {
                Decimal::ZERO
            } else {
                let num_blocks_failed = Decimal::from(num_blocks_failed);
                num_blocks_failed / total_blocks
            }
        }

        fn calculate_daily_subnet_fr(nodes_fr: &[Decimal]) -> Decimal {
            let failure_rates = nodes_fr.iter().sorted().collect::<Vec<_>>();
            let index =
                ((nodes_fr.len() as f64) * SUBNET_FAILURE_RATE_PERCENTILE).ceil() as usize - 1;
            *failure_rates[index]
        }

        for (SubnetMetricsDailyKey { subnet_id, day }, subnet_nodes_metrics) in
            &self.input.daily_metrics_by_subnet
        {
            let original_nodes_fr = subnet_nodes_metrics
                .iter()
                .map(|metrics| {
                    let original_fr = calculate_daily_node_fr(
                        metrics.num_blocks_proposed,
                        metrics.num_blocks_failed,
                    );
                    ((day.clone(), metrics.node_id), original_fr)
                })
                .collect::<BTreeMap<_, _>>();

            let subnet_fr = calculate_daily_subnet_fr(
                original_nodes_fr.values().cloned().collect_vec().as_slice(),
            );

            let relative_nodes_fr = original_nodes_fr
                .iter()
                .map(|(key, original_fr)| {
                    let relative_fr = max(Decimal::ZERO, *original_fr - subnet_fr);
                    (key.clone(), relative_fr)
                })
                .collect::<BTreeMap<_, _>>();

            self.intermediate_results
                .original_nodes_fr
                .extend(original_nodes_fr);
            self.intermediate_results
                .subnets_fr
                .insert((day.clone(), subnet_id.clone()), subnet_fr);
            self.intermediate_results
                .relative_nodes_fr
                .extend(relative_nodes_fr);
        }

        RewardsCalculatorPipeline::transition(self)
    }
}

/// Calculates the daily extrapolated failure rate for each node provider.
///
/// For each day in the reward period the extrapolated failure rate is the average of the relative failure rates
/// for that day of the nodes of the node provider.
impl RewardsCalculatorPipeline<ComputeProvidersExtrapolatedFR> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<ComputeNodesPerformanceMultiplier> {
        for ProviderRewardableNodes {
            provider_id,
            rewardable_nodes,
        } in &self.input.rewardable_nodes
        {
            let provider_nodes = rewardable_nodes
                .iter()
                .map(|node| node.node_id)
                .collect::<HashSet<_>>();

            let provider_extrapolated_fr = self
                .intermediate_results
                .relative_nodes_fr
                .iter()
                .filter(|((_, node_id), _)| !provider_nodes.contains(node_id))
                .map(|((day, _), relative_node_fr)| (day.clone(), *relative_node_fr))
                .into_group_map()
                .into_iter()
                .map(|(day, relative_nodes_fr)| {
                    (
                        (provider_id.clone(), day),
                        avg(relative_nodes_fr.as_slice()),
                    )
                })
                .collect::<BTreeMap<(PrincipalId, DayUTC), Decimal>>();

            self.intermediate_results
                .extrapolated_fr
                .extend(provider_extrapolated_fr);
        }

        RewardsCalculatorPipeline::transition(self)
    }
}

/// Calculates the daily performance multiplier for a node based on its daily failure rate.
impl RewardsCalculatorPipeline<ComputeNodesPerformanceMultiplier> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<ComputeBaseRewardsTypeRegion> {
        fn calculate_rewards_reduction(fr: Decimal) -> Decimal {
            if fr < MIN_FAILURE_RATE {
                MIN_REWARDS_REDUCTION
            } else if fr > MAX_FAILURE_RATE {
                MAX_REWARDS_REDUCTION
            } else {
                // Linear interpolation between MIN_REWARDS_REDUCTION and MAX_REWARDS_REDUCTION
                (fr - MIN_FAILURE_RATE) / (MAX_FAILURE_RATE - MIN_FAILURE_RATE)
                    * MAX_REWARDS_REDUCTION
            }
        }

        for ProviderRewardableNodes {
            provider_id,
            rewardable_nodes,
        } in &self.input.rewardable_nodes
        {
            for node in rewardable_nodes {
                for day in &node.rewardable_days {
                    let daily_fr_used;

                    if let Some(relative_fr) = self
                        .intermediate_results
                        .relative_nodes_fr
                        .get(&(*day, node.node_id))
                    {
                        // If the node is assigned on this day, use the relative failure rate for that day.
                        daily_fr_used = *relative_fr;
                    } else if let Some(extrapolated_fr) = self
                        .intermediate_results
                        .extrapolated_fr
                        .get(&(provider_id.clone(), *day))
                    {
                        // If the node is not assigned on this day, use the extrapolated failure rate for that day.
                        daily_fr_used = *extrapolated_fr;
                    } else {
                        // If there is no extrapolated failure rate for this day, will be rewarded fully.
                        daily_fr_used = Decimal::zero();
                    }
                    let rewards_reduction = calculate_rewards_reduction(daily_fr_used);
                    let performance_multiplier = dec!(1) - rewards_reduction;

                    self.intermediate_results
                        .reward_reduction
                        .insert((*day, node.node_id), rewards_reduction);
                    self.intermediate_results
                        .performance_multiplier
                        .insert((*day, node.node_id), performance_multiplier);
                }
            }
        }

        RewardsCalculatorPipeline::transition(self)
    }
}

fn get_daily_rate(
    rewards_table: &NodeRewardsTable,
    region: &Region,
    node_reward_type: &NodeRewardType,
) -> (XDRPermyriad, RewardsCoefficientPercent) {
    rewards_table
        .get_rate(region, &node_reward_type.to_string())
        .map(|rate| {
            let base_rewards_daily =
                Decimal::from(rate.xdr_permyriad_per_node_per_month) / REWARDS_TABLE_DAYS;
            // Default reward_coefficient_percent is set to 80%, which is used as a fallback only in the
            // unlikely case that the type3 entry in the reward table:
            // a) has xdr_permyriad_per_node_per_month entry set for this region, but
            // b) does NOT have the reward_coefficient_percent value set
            let reward_coefficient_percent =
                Decimal::from(rate.reward_coefficient_percent.unwrap_or(80)) / dec!(100);

            (base_rewards_daily.into(), reward_coefficient_percent)
        })
        .unwrap_or((dec!(1).into(), dec!(100)))
}

fn is_type3(node_type: &NodeRewardType) -> bool {
    node_type == &NodeRewardType::Type3 || node_type == &NodeRewardType::Type3dot1
}

fn type3_region_key(region: &Region) -> String {
    region
        .splitn(3, ',')
        .take(2)
        .collect::<Vec<&str>>()
        .join(":")
}

/// Compute base rewards from the rewards table entries for specific region and node type.
/// For type3* nodes the base rewards are computed as the average of base rewards on DC Country level.
impl RewardsCalculatorPipeline<ComputeBaseRewardsTypeRegion> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<ComputeBaseRewards> {
        let mut type3_base_rewards = BTreeMap::new();

        for ProviderRewardableNodes {
            provider_id,
            rewardable_nodes,
        } in &self.input.rewardable_nodes
        {
            for node in rewardable_nodes {
                let (base_rewards_daily, coefficient) = get_daily_rate(
                    &self.input.rewards_table,
                    &node.region,
                    &node.node_reward_type,
                );

                self.intermediate_results.base_rewards_type_region.insert(
                    (node.node_reward_type.clone(), node.region.clone()),
                    base_rewards_daily,
                );

                // For nodes which are type3* the base rewards for the single node is computed as the average of base rewards
                // on DC Country level. Moreover, to de-stimulate the same NP having too many nodes in the same country,
                // the node rewards is reduced for each node the NP has in the given country. The reduction coefficient is
                // computed as the average of reduction coefficients on DC Country level.
                if is_type3(&node.node_reward_type) {
                    // The rewards table contains entries of this form DC Continent + DC Country + DC State/City.
                    // The grouping for type3* nodes will be on DC Continent + DC Country level. This group is used for computing
                    // the reduction coefficient and base reward for the group.
                    let region_key = type3_region_key(&node.region);

                    for day in &node.rewardable_days {
                        let key = (provider_id.clone(), day.clone(), region_key.clone());

                        type3_base_rewards
                            .entry(key)
                            .and_modify(
                                |(rates, coeffs): &mut (
                                    Vec<XDRPermyriad>,
                                    Vec<RewardsCoefficientPercent>,
                                )| {
                                    rates.push(base_rewards_daily.clone());
                                    coeffs.push(coefficient);
                                },
                            )
                            .or_insert((vec![base_rewards_daily], vec![coefficient]));
                    }
                }
            }
        }

        let type3_base_rewards = type3_base_rewards
            .into_iter()
            .map(|(key, (rates, coeff))| {
                let rates_len = rates.len();
                let avg_rate = avg(rates.as_slice());
                let avg_coeff = avg(coeff.as_slice());

                let mut running_coefficient = dec!(1);
                let mut region_rewards = Vec::new();
                for _ in 0..rates_len {
                    region_rewards.push(avg_rate * running_coefficient);
                    running_coefficient *= avg_coeff;
                }
                let region_rewards_avg = avg(&region_rewards);

                (key, region_rewards_avg)
            })
            .collect::<BTreeMap<_, _>>();

        self.intermediate_results.type3_base_rewards_type_region = type3_base_rewards;
        RewardsCalculatorPipeline::transition(self)
    }
}

/// Calculates the base rewards for each node based on its region and node type.
impl RewardsCalculatorPipeline<ComputeBaseRewards> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<ComputeNodesCount> {
        let mut base_rewards = BTreeMap::new();
        for ProviderRewardableNodes {
            provider_id,
            rewardable_nodes,
        } in &self.input.rewardable_nodes
        {
            for node in rewardable_nodes {
                for day in &node.rewardable_days {
                    let base_rewards_for_day;

                    if is_type3(&node.node_reward_type) {
                        let region_key = type3_region_key(&node.region);

                        base_rewards_for_day = self
                            .intermediate_results
                            .type3_base_rewards_type_region
                            .get(&(provider_id.clone(), day.clone(), region_key))
                            .expect("Type3 base rewards expected for provider")
                    } else {
                        base_rewards_for_day = self
                            .intermediate_results
                            .base_rewards_type_region
                            .get(&(node.node_reward_type.clone(), node.region.clone()))
                            .expect("base rewards expected for each node")
                    }

                    base_rewards.insert((day.clone(), node.node_id), *base_rewards_for_day);
                }
            }
        }

        self.intermediate_results.base_rewards = base_rewards;

        RewardsCalculatorPipeline::transition(self)
    }
}

/// Compute the nodes count for each provider on each day.
impl RewardsCalculatorPipeline<ComputeNodesCount> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<AdjustNodesRewards> {
        let mut nodes_count = BTreeMap::new();

        for ProviderRewardableNodes {
            provider_id,
            rewardable_nodes,
        } in &self.input.rewardable_nodes
        {
            for node in rewardable_nodes {
                for day in &node.rewardable_days {
                    nodes_count
                        .entry((provider_id.clone(), day.clone()))
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }
            }
        }
        self.intermediate_results.nodes_count = nodes_count;

        RewardsCalculatorPipeline::transition(self)
    }
}

/// Calculate the adjusted rewards for all the nodes based on their performance.
impl RewardsCalculatorPipeline<AdjustNodesRewards> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<ComputeRewardsTotal> {
        let mut adjusted_rewards = BTreeMap::new();
        for ProviderRewardableNodes {
            provider_id,
            rewardable_nodes,
        } in &self.input.rewardable_nodes
        {
            for node in rewardable_nodes {
                for day in &node.rewardable_days {
                    let provider_nodes_count = self
                        .intermediate_results
                        .nodes_count
                        .get(&(provider_id.clone(), day.clone()))
                        .expect("Daily nodes count expected for provider");

                    let base_rewards_for_day = *self
                        .intermediate_results
                        .base_rewards
                        .get(&(day.clone(), node.node_id))
                        .expect("Base rewards expected for each node");

                    if provider_nodes_count <= &FULL_REWARDS_MACHINES_LIMIT {
                        // Node Providers with less than FULL_REWARDS_MACHINES_LIMIT machines are rewarded fully,
                        // independently of their performance.
                        adjusted_rewards
                            .insert((day.clone(), node.node_id), base_rewards_for_day.clone());
                    } else {
                        let performance_multiplier = self
                            .intermediate_results
                            .performance_multiplier
                            .get(&(day.clone(), node.node_id))
                            .expect("Performance multiplier expected for every node");

                        let adjusted_rewards_for_day =
                            base_rewards_for_day * performance_multiplier;
                        adjusted_rewards
                            .insert((day.clone(), node.node_id), adjusted_rewards_for_day);
                    }
                }
            }
        }

        self.intermediate_results.adjusted_rewards = adjusted_rewards;

        RewardsCalculatorPipeline::transition(self)
    }
}

/// Calculate the rewards total for each provider.
///
/// The rewards total is the sum of the adjusted rewards for all nodes of the provider
impl RewardsCalculatorPipeline<ComputeRewardsTotal> {
    pub fn next(mut self) -> RewardsCalculatorPipeline<RewardsTotalComputed> {
        let mut rewards_total = BTreeMap::new();

        for ProviderRewardableNodes {
            provider_id,
            rewardable_nodes,
        } in &self.input.rewardable_nodes
        {
            for node in rewardable_nodes {
                for day in &node.rewardable_days {
                    let node_rewards = *self
                        .intermediate_results
                        .adjusted_rewards
                        .get(&(day.clone(), node.node_id))
                        .expect("Adjusted rewards expected for each node");

                    rewards_total
                        .entry(provider_id.clone())
                        .and_modify(|rewards_total| *rewards_total += node_rewards)
                        .or_insert(node_rewards);
                }
            }
        }

        self.intermediate_results.rewards_total = rewards_total;
        RewardsCalculatorPipeline::transition(self)
    }
}

impl RewardsCalculatorPipeline<RewardsTotalComputed> {
    pub fn construct_results(mut self) -> RewardsCalculatorResults {
        let mut assigned_nodes = BTreeMap::new();
        let mut provider_results = BTreeMap::new();
        let subnets_fr = self
            .intermediate_results
            .subnets_fr
            .into_iter()
            .map(|(key, val)| (key, val.into()))
            .collect();

        for (SubnetMetricsDailyKey { subnet_id, day }, subnet_nodes_metrics) in
            self.input.daily_metrics_by_subnet
        {
            for metrics in subnet_nodes_metrics {
                let node_id = metrics.node_id;
                let original_fr = self
                    .intermediate_results
                    .original_nodes_fr
                    .remove(&(day, node_id))
                    .expect("Original failure rate should be present in rewards");

                let relative_fr = self
                    .intermediate_results
                    .relative_nodes_fr
                    .remove(&(day, node_id))
                    .expect("Relative failure rate should be present in rewards");

                let node_status = NodeStatus::Assigned {
                    node_metrics: NodeMetricsDaily {
                        original_fr: original_fr.into(),
                        relative_fr: relative_fr.into(),
                        subnet_assigned: subnet_id.clone(),
                        num_blocks_proposed: metrics.num_blocks_proposed,
                        num_blocks_failed: metrics.num_blocks_failed,
                    },
                };

                assigned_nodes.insert((day, node_id), node_status);
            }
        }

        for ProviderRewardableNodes {
            provider_id,
            rewardable_nodes,
        } in self.input.rewardable_nodes
        {
            let mut node_results = BTreeMap::new();

            for node in rewardable_nodes {
                let node_reward_type = node.node_reward_type;
                let region = node.region;
                let dc_id = node.dc_id;
                let mut daily_results = BTreeMap::new();

                for day in node.rewardable_days {
                    let node_status =
                        if let Some(node_status) = assigned_nodes.remove(&(day, node.node_id)) {
                            node_status
                        } else {
                            let extrapolated_fr = self
                                .intermediate_results
                                .extrapolated_fr
                                .remove(&(provider_id.clone(), day))
                                .expect("Extrapolated fr should be present");

                            NodeStatus::Unassigned {
                                extrapolated_fr: extrapolated_fr.into(),
                            }
                        };

                    let rewards_reduction = self
                        .intermediate_results
                        .reward_reduction
                        .remove(&(day, node.node_id))
                        .expect("Rewards reduction should be present in rewards")
                        .into();

                    let performance_multiplier = self
                        .intermediate_results
                        .performance_multiplier
                        .remove(&(day, node.node_id))
                        .expect("Performance multiplier should be present in rewards")
                        .into();

                    let adjusted_rewards = self
                        .intermediate_results
                        .adjusted_rewards
                        .remove(&(day, node.node_id))
                        .expect("Adjusted rewards should be present in rewards")
                        .into();

                    let base_rewards = self
                        .intermediate_results
                        .base_rewards
                        .remove(&(day, node.node_id))
                        .expect("Base rewards should be present in rewards")
                        .into();

                    daily_results.insert(
                        day,
                        DailyResults {
                            node_status,
                            performance_multiplier,
                            rewards_reduction,
                            base_rewards,
                            adjusted_rewards,
                        },
                    );
                }

                node_results.insert(
                    node.node_id,
                    NodeResults {
                        node_reward_type: node_reward_type.to_string(),
                        region,
                        dc_id,
                        daily_results,
                    },
                );
            }

            let rewards_total = self
                .intermediate_results
                .rewards_total
                .remove(&provider_id)
                .expect("Rewards total should be present in rewards")
                .into();

            provider_results.insert(
                provider_id,
                NodeProviderResults {
                    rewards_total,
                    node_results,
                },
            );
        }

        RewardsCalculatorResults {
            subnets_fr,
            provider_results,
        }
    }
}

pub trait ExecutionState {}

pub(crate) struct Initialized;
impl ExecutionState for Initialized {}
pub(crate) struct ComputeSubnetsNodesFR;
impl ExecutionState for ComputeSubnetsNodesFR {}
pub(crate) struct ComputeProvidersExtrapolatedFR;
impl ExecutionState for ComputeProvidersExtrapolatedFR {}
pub(crate) struct ComputeNodesPerformanceMultiplier;
impl ExecutionState for ComputeNodesPerformanceMultiplier {}
pub(crate) struct ComputeBaseRewardsTypeRegion;
impl ExecutionState for ComputeBaseRewardsTypeRegion {}
pub(crate) struct ComputeBaseRewards;
impl ExecutionState for ComputeBaseRewards {}
pub(crate) struct ComputeNodesCount;
impl ExecutionState for ComputeNodesCount {}
pub(crate) struct AdjustNodesRewards;
impl ExecutionState for AdjustNodesRewards {}
pub(crate) struct ComputeRewardsTotal;
impl ExecutionState for ComputeRewardsTotal {}
pub(crate) struct RewardsTotalComputed;
impl ExecutionState for RewardsTotalComputed {}

#[cfg(test)]
mod tests;
