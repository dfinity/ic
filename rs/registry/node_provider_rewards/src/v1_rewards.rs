use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardsTable};
use itertools::Itertools;
use num_traits::ToPrimitive;

use crate::v1_logs::LogLevel;
use crate::v1_reward_period::RewardPeriod;
use crate::v1_types::TimestampNanos;
use crate::{
    v1_logs::{LogEntry, Operation, RewardsLog},
    v1_types::{
        DailyNodeMetrics, RegionNodeTypeCategory, RewardableNode, Rewards, RewardsPerNodeProvider,
    },
};
use ic_management_canister_types::{NodeMetrics, NodeMetricsHistoryResponse};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum RewardCalculationError {
    SubnetMetricsOutOfRange {
        subnet_id: SubnetId,
        timestamp: TimestampNanos,
        reward_period: RewardPeriod,
    },
    EmptyRewardables,
    NodeNotInRewardables(NodeId),
}

impl fmt::Display for RewardCalculationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RewardCalculationError::SubnetMetricsOutOfRange {
                subnet_id,
                timestamp,
                reward_period,
            } => {
                write!(
                    f,
                    "Subnet {} has metrics outside the reward period: timestamp: {} not in {}",
                    subnet_id, timestamp, reward_period
                )
            }
            RewardCalculationError::EmptyRewardables => {
                write!(f, "No rewardable nodes were provided")
            }
            RewardCalculationError::NodeNotInRewardables(node_id) => {
                write!(f, "Node {} has metrics in rewarding period but it is not part of rewardable_nodes", node_id)
            }
        }
    }
}

pub fn validate_input(
    reward_period: &RewardPeriod,
    subnet_metrics: &HashMap<SubnetId, Vec<NodeMetricsHistoryResponse>>,
    rewardable_nodes: &[RewardableNode],
) -> Result<(), RewardCalculationError> {
    if rewardable_nodes.is_empty() {
        return Err(RewardCalculationError::EmptyRewardables);
    }

    for (subnet_id, metrics) in subnet_metrics {
        for metric in metrics {
            if !reward_period.contains(metric.timestamp_nanos) {
                return Err(RewardCalculationError::SubnetMetricsOutOfRange {
                    subnet_id: *subnet_id,
                    timestamp: metric.timestamp_nanos,
                    reward_period: reward_period.clone(),
                });
            }
        }
    }

    for metrics in subnet_metrics.values().flatten() {
        for node_metrics in &metrics.node_metrics {
            let node_id: NodeId = node_metrics.node_id.into();

            if !rewardable_nodes.iter().any(|node| node.node_id == node_id) {
                return Err(RewardCalculationError::NodeNotInRewardables(node_id));
            }
        }
    }

    Ok(())
}

const FULL_REWARDS_MACHINES_LIMIT: u32 = 3;
const MIN_FAILURE_RATE: Decimal = dec!(0.1);
const MAX_FAILURE_RATE: Decimal = dec!(0.6);
const MAX_REWARDS_REDUCTION: Decimal = dec!(0.8);
const RF: &str = "Linear Reduction factor";

pub fn calculate_rewards(
    reward_period: RewardPeriod,
    rewards_table: &NodeRewardsTable,
    subnet_metrics: HashMap<SubnetId, Vec<NodeMetricsHistoryResponse>>,
    rewardable_nodes: &[RewardableNode],
) -> Result<RewardsPerNodeProvider, RewardCalculationError> {
    validate_input(&reward_period, &subnet_metrics, rewardable_nodes)?;

    let mut rewards_per_node_provider = HashMap::default();
    let mut rewards_log_per_node_provider = HashMap::default();

    let mut metrics_in_rewarding_period = metrics_in_rewarding_period(subnet_metrics);
    let subnets_systematic_fr = systematic_fr_per_subnet(&metrics_in_rewarding_period);
    let node_provider_rewardables = rewardable_nodes_by_node_provider(rewardable_nodes);

    for (node_provider_id, nodes) in node_provider_rewardables {
        let mut logger = RewardsLog::default();
        logger.add_entry(
            LogLevel::High,
            LogEntry::CalculateRewardsForNodeProvider(node_provider_id),
        );

        let daily_metrics_by_node: HashMap<NodeId, Vec<DailyNodeMetrics>> = nodes
            .iter()
            .filter_map(|node| {
                metrics_in_rewarding_period
                    .remove(&node.node_id)
                    .map(|daily_metrics| (node.node_id, daily_metrics))
            })
            .collect();
        let node_daily_fr = compute_relative_node_failure_rate(
            &mut logger,
            &daily_metrics_by_node,
            &subnets_systematic_fr,
        );

        let rewards = node_provider_rewards(
            &mut logger,
            &nodes,
            node_daily_fr,
            reward_period.days_between(),
            rewards_table,
        );

        rewards_log_per_node_provider.insert(node_provider_id, logger);
        rewards_per_node_provider.insert(node_provider_id, rewards);
    }

    Ok(RewardsPerNodeProvider {
        rewards_per_node_provider,
        rewards_log_per_node_provider,
    })
}

/// Computes the relative node failure rates discounting the subnet systematic failure rate.
fn compute_relative_node_failure_rate(
    logger: &mut RewardsLog,
    assigned_metrics: &HashMap<NodeId, Vec<DailyNodeMetrics>>,
    subnets_systematic_fr: &HashMap<(SubnetId, TimestampNanos), Decimal>,
) -> HashMap<NodeId, Vec<Decimal>> {
    let mut nodes_idiosyncratic_fr: HashMap<NodeId, Vec<Decimal>> = HashMap::new();

    for (node_id, daily_metrics) in assigned_metrics {
        let failure_rates = nodes_idiosyncratic_fr.entry(*node_id).or_default();

        for metrics in daily_metrics {
            let systematic_fr = subnets_systematic_fr
                .get(&(metrics.subnet_assigned, metrics.ts))
                .expect("Systematic failure rate not found");
            let fr = if metrics.failure_rate < *systematic_fr {
                Decimal::ZERO
            } else {
                metrics.failure_rate - *systematic_fr
            };
            failure_rates.push(fr);
        }
        logger.add_entry(
            LogLevel::High,
            LogEntry::ActiveIdiosyncraticFailureRates {
                node_id: *node_id,
                failure_rates: failure_rates.clone(),
            },
        );
    }

    nodes_idiosyncratic_fr
}

fn node_provider_rewards(
    logger: &mut RewardsLog,
    rewardables: &[RewardableNode],
    nodes_idiosyncratic_fr: HashMap<NodeId, Vec<Decimal>>,
    days_in_period: u64,
    rewards_table: &NodeRewardsTable,
) -> Rewards {
    let mut rewards_xdr_total = Vec::new();
    let mut rewards_xdr_no_penalty_total = Vec::new();

    let mut nodes_active_fr: Vec<Decimal> = Vec::new();
    let mut region_node_type_rewardables = HashMap::new();

    let rewardable_nodes_count = rewardables.len() as u32;
    let mut nodes_idiosyncratic_fr = nodes_idiosyncratic_fr;

    // 0. Compute base rewards for each region and node type
    logger.add_entry(
        LogLevel::High,
        LogEntry::ComputeBaseRewardsForRegionNodeType,
    );
    for node in rewardables {
        let nodes_count = region_node_type_rewardables
            .entry((node.region.clone(), node.node_type.clone()))
            .or_default();
        *nodes_count += 1;
    }
    let region_nodetype_rewards: HashMap<RegionNodeTypeCategory, Decimal> =
        base_rewards_region_nodetype(logger, &region_node_type_rewardables, rewards_table);

    // 1. Extrapolate the unassigned daily failure rate from the active nodes
    logger.add_entry(LogLevel::High, LogEntry::ComputeUnassignedFailureRate);
    for node in rewardables {
        if let Some(fr) = nodes_idiosyncratic_fr.get(&node.node_id) {
            let avg_fr = logger.execute(
                &format!("Avg. failure rate for node: {}", node.node_id),
                Operation::Avg(fr.clone()),
            );
            nodes_active_fr.push(avg_fr);
        }
    }
    let unassigned_fr: Decimal = if !nodes_active_fr.is_empty() {
        logger.execute(
            "Unassigned days failure rate:",
            Operation::Avg(nodes_active_fr),
        )
    } else {
        dec!(1)
    };

    // 2. Compute rewards multiplier for fully unassigned nodes
    let rewards_reduction_unassigned = rewards_reduction_percent(logger, &unassigned_fr);
    let multiplier_unassigned = logger.execute(
        "Reward multiplier fully unassigned nodes:",
        Operation::Subtract(dec!(1), rewards_reduction_unassigned),
    );

    // 3. reward the nodes of node provider
    let mut sorted_rewardables = rewardables.to_vec();
    sorted_rewardables.sort_by(|a, b| a.region.cmp(&b.region).then(a.node_type.cmp(&b.node_type)));
    for node in sorted_rewardables {
        logger.add_entry(
            LogLevel::High,
            LogEntry::ComputeRewardsForNode {
                node_id: node.node_id,
                node_type: node.node_type.clone(),
                region: node.region.clone(),
            },
        );

        let node_type = node.node_type.clone();
        let region = node.region.clone();

        let rewards_xdr_no_penalty = if node_type.starts_with("type3") {
            let region_key = region_type3_key(region.clone());
            region_nodetype_rewards
                .get(&region_key)
                .expect("Type3 rewards already filled")
        } else {
            region_nodetype_rewards
                .get(&(node.region.clone(), node.node_type.clone()))
                .expect("Rewards already filled")
        };

        logger.add_entry(
            LogLevel::Mid,
            LogEntry::BaseRewards(*rewards_xdr_no_penalty),
        );

        rewards_xdr_no_penalty_total.push(*rewards_xdr_no_penalty);

        // Node Providers with less than 4 machines are rewarded fully, independently of their performance
        if rewardable_nodes_count <= FULL_REWARDS_MACHINES_LIMIT {
            rewards_xdr_total.push(*rewards_xdr_no_penalty);
            continue;
        }

        let reward_multiplier = if let Some(mut daily_idiosyncratic_fr) =
            nodes_idiosyncratic_fr.remove(&node.node_id)
        {
            logger.add_entry(LogLevel::Mid, LogEntry::NodeStatusAssigned);
            daily_idiosyncratic_fr.resize(days_in_period as usize, unassigned_fr);

            logger.add_entry(
                LogLevel::Mid,
                LogEntry::IdiosyncraticFailureRates(daily_idiosyncratic_fr.clone()),
            );

            assigned_multiplier(logger, daily_idiosyncratic_fr)
        } else {
            logger.add_entry(LogLevel::Mid, LogEntry::NodeStatusUnassigned);

            multiplier_unassigned
        };

        let rewards_xdr = logger.execute(
            "Rewards XDR for the node",
            Operation::Multiply(*rewards_xdr_no_penalty, reward_multiplier),
        );
        rewards_xdr_total.push(rewards_xdr);
    }

    let rewards_xdr_total = logger.execute(
        "Compute total permyriad XDR",
        Operation::Sum(rewards_xdr_total),
    );
    let rewards_xdr_no_reduction_total = logger.execute(
        "Compute total permyriad XDR no performance penalty",
        Operation::Sum(rewards_xdr_no_penalty_total),
    );
    logger.add_entry(
        LogLevel::High,
        LogEntry::RewardsXDRTotal(rewards_xdr_total, rewards_xdr_no_reduction_total),
    );

    Rewards {
        xdr_permyriad: rewards_xdr_total.to_u64().unwrap(),
        xdr_permyriad_no_reduction: rewards_xdr_no_reduction_total.to_u64().unwrap(),
    }
}

fn assigned_multiplier(logger: &mut RewardsLog, daily_failure_rate: Vec<Decimal>) -> Decimal {
    let average_fr = logger.execute("Failure rate average", Operation::Avg(daily_failure_rate));
    let rewards_reduction = rewards_reduction_percent(logger, &average_fr);

    logger.execute(
        "Reward Multiplier",
        Operation::Subtract(dec!(1), rewards_reduction),
    )
}

/// Computes the systematic failure rate for each subnet per day.
///
/// This function calculates the 75th percentile of failure rates for each subnet on a daily basis.
/// This represents the systematic failure rate for all the nodes in the subnet for that day.
fn systematic_fr_per_subnet(
    daily_node_metrics: &HashMap<NodeId, Vec<DailyNodeMetrics>>,
) -> HashMap<(SubnetId, TimestampNanos), Decimal> {
    fn percentile_75(mut values: Vec<Decimal>) -> Decimal {
        values.sort();
        let len = values.len();
        if len == 0 {
            return Decimal::ZERO;
        }
        let idx = ((len as f64) * 0.75).ceil() as usize - 1;
        values[idx]
    }

    let mut subnet_daily_failure_rates: HashMap<(SubnetId, u64), Vec<Decimal>> = HashMap::new();

    for metrics in daily_node_metrics.values() {
        for metric in metrics {
            subnet_daily_failure_rates
                .entry((metric.subnet_assigned, metric.ts))
                .or_default()
                .push(metric.failure_rate);
        }
    }

    subnet_daily_failure_rates
        .into_iter()
        .map(|((subnet, ts), failure_rates)| ((subnet, ts), percentile_75(failure_rates)))
        .collect()
}

fn metrics_in_rewarding_period(
    subnets_metrics: HashMap<SubnetId, Vec<NodeMetricsHistoryResponse>>,
) -> HashMap<NodeId, Vec<DailyNodeMetrics>> {
    let mut subnets_metrics = subnets_metrics
        .into_iter()
        .flat_map(|(subnet_id, metrics)| {
            metrics.into_iter().map(move |metrics| (subnet_id, metrics))
        })
        .collect_vec();
    subnets_metrics.sort_by_key(|(_, metrics)| metrics.timestamp_nanos);

    let mut metrics_in_rewarding_period: HashMap<NodeId, Vec<(SubnetId, u64, NodeMetrics)>> =
        HashMap::default();

    for (subnet_id, metrics) in subnets_metrics {
        for node_metrics in metrics.node_metrics {
            metrics_in_rewarding_period
                .entry(node_metrics.node_id.into())
                .or_default()
                .push((subnet_id, metrics.timestamp_nanos, node_metrics));
        }
    }

    metrics_in_rewarding_period
        .into_iter()
        .map(|(node_id, metrics)| {
            let mut daily_metrics = Vec::new();
            let mut previous_proposed_total = 0;
            let mut previous_failed_total = 0;

            for (subnet_id, ts, node_metrics) in metrics {
                let current_proposed_total = node_metrics.num_blocks_proposed_total;
                let current_failed_total = node_metrics.num_block_failures_total;

                let (num_blocks_proposed, num_blocks_failed) = if previous_failed_total
                    > current_failed_total
                    || previous_proposed_total > current_proposed_total
                {
                    // This is the case when node is deployed again
                    (current_proposed_total, current_failed_total)
                } else {
                    (
                        current_proposed_total - previous_proposed_total,
                        current_failed_total - previous_failed_total,
                    )
                };

                daily_metrics.push(DailyNodeMetrics::new(
                    ts,
                    subnet_id,
                    num_blocks_proposed,
                    num_blocks_failed,
                ));

                previous_proposed_total = current_proposed_total;
                previous_failed_total = current_failed_total;
            }
            (node_id, daily_metrics)
        })
        .collect()
}

/// Calculates the rewards reduction based on the failure rate.
///
/// if `failure_rate` is:
/// - Below the `MIN_FAILURE_RATE`, no reduction in rewards applied.
/// - Above the `MAX_FAILURE_RATE`, maximum reduction in rewards applied.
/// - Within the defined range (`MIN_FAILURE_RATE` to `MAX_FAILURE_RATE`),
///   the function calculates the reduction from the linear reduction function.
fn rewards_reduction_percent(logger: &mut RewardsLog, failure_rate: &Decimal) -> Decimal {
    if failure_rate < &MIN_FAILURE_RATE {
        logger.execute(
            &format!(
                "No Reduction applied because {} is less than {} failure rate.\n{}",
                failure_rate.round_dp(4),
                MIN_FAILURE_RATE,
                RF
            ),
            Operation::Set(dec!(0)),
        )
    } else if failure_rate > &MAX_FAILURE_RATE {
        logger.execute(
            &format!(
                "Max reduction applied because {} is over {} failure rate.\n{}",
                failure_rate.round_dp(4),
                MAX_FAILURE_RATE,
                RF
            ),
            Operation::Set(dec!(0.8)),
        )
    } else {
        let rewards_reduction = (*failure_rate - MIN_FAILURE_RATE)
            / (MAX_FAILURE_RATE - MIN_FAILURE_RATE)
            * MAX_REWARDS_REDUCTION;
        logger.add_entry(
            LogLevel::Mid,
            LogEntry::RewardsReductionPercent {
                failure_rate: *failure_rate,
                min_fr: MIN_FAILURE_RATE,
                max_fr: MAX_FAILURE_RATE,
                max_rr: MAX_REWARDS_REDUCTION,
                rewards_reduction,
            },
        );

        rewards_reduction
    }
}

fn region_type3_key(region: String) -> RegionNodeTypeCategory {
    // The rewards table contains entries of this form DC Continent + DC Country + DC State/City.
    // The grouping for type3* nodes will be on DC Continent + DC Country level. This group is used for computing
    // the reduction coefficient and base reward for the group.

    let region_key = region
        .splitn(3, ',')
        .take(2)
        .collect::<Vec<&str>>()
        .join(":");
    (region_key, "type3*".to_string())
}

fn base_rewards_region_nodetype(
    logger: &mut RewardsLog,
    rewardable_nodes: &HashMap<RegionNodeTypeCategory, u32>,
    rewards_table: &NodeRewardsTable,
) -> HashMap<RegionNodeTypeCategory, Decimal> {
    let mut type3_coefficients_rewards: HashMap<
        RegionNodeTypeCategory,
        (Vec<Decimal>, Vec<Decimal>),
    > = HashMap::default();
    let mut region_nodetype_rewards: HashMap<RegionNodeTypeCategory, Decimal> = HashMap::default();

    for ((region, node_type), node_count) in rewardable_nodes {
        let rate = match rewards_table.get_rate(region, node_type) {
            Some(rate) => rate,
            None => {
                logger.add_entry(
                    LogLevel::High,
                    LogEntry::RateNotFoundInRewardTable {
                        node_type: node_type.to_string(),
                        region: region.to_string(),
                    },
                );

                NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 1,
                    reward_coefficient_percent: Some(100),
                }
            }
        };
        let base_rewards = Decimal::from(rate.xdr_permyriad_per_node_per_month);
        let mut coeff = dec!(1);

        if node_type.starts_with("type3") && *node_count > 0 {
            // For nodes which are type3* the base rewards for the single node is computed as the average of base rewards
            // on DC Country level. Moreover, to de-stimulate the same NP having too many nodes in the same country,
            // the node rewards is reduced for each node the NP has in the given country. The reduction coefficient is
            // computed as the average of reduction coefficients on DC Country level.

            coeff = Decimal::from(rate.reward_coefficient_percent.unwrap_or(80)) / dec!(100);
            let coefficients = vec![coeff; *node_count as usize];
            let base_rewards = vec![base_rewards; *node_count as usize];
            let region_key = region_type3_key(region.to_string());

            type3_coefficients_rewards
                .entry(region_key)
                .and_modify(|(entry_coefficients, entry_rewards)| {
                    entry_coefficients.extend(&coefficients);
                    entry_rewards.extend(&base_rewards);
                })
                .or_insert((coefficients, base_rewards));
        } else {
            // For `rewardable_nodes` which are not type3* the base rewards for the sigle node is the entry
            // in the rewards table for the specific region (DC Continent + DC Country + DC State/City) and node type.

            region_nodetype_rewards.insert((region.clone(), node_type.clone()), base_rewards);
        }

        logger.add_entry(
            LogLevel::Mid,
            LogEntry::RewardTableEntry {
                node_type: node_type.to_string(),
                region: region.to_string(),
                coeff,
                base_rewards,
                node_count: *node_count,
            },
        );
    }

    // Computes node rewards for type3* nodes in all regions and add it to region_nodetype_rewards
    for (key, (coefficients, rewards)) in type3_coefficients_rewards {
        let rewards_len = rewards.len();
        let mut running_coefficient = dec!(1);
        let mut region_rewards = Vec::new();

        let coefficients_avg = logger.execute("Coefficients avg.", Operation::Avg(coefficients));
        let rewards_avg = logger.execute("Rewards avg.", Operation::Avg(rewards));
        for _ in 0..rewards_len {
            region_rewards.push(Operation::Multiply(rewards_avg, running_coefficient));
            running_coefficient *= coefficients_avg;
        }
        let region_rewards = logger.execute(
            "Total rewards after coefficient reduction",
            Operation::SumOps(region_rewards),
        );
        let region_rewards_avg = logger.execute(
            "Rewards average after coefficient reduction",
            Operation::Divide(region_rewards, Decimal::from(rewards_len)),
        );

        region_nodetype_rewards.insert(key, region_rewards_avg);
    }

    region_nodetype_rewards
}

fn rewardable_nodes_by_node_provider(
    nodes: &[RewardableNode],
) -> HashMap<PrincipalId, Vec<RewardableNode>> {
    let mut node_provider_rewardables: HashMap<PrincipalId, Vec<RewardableNode>> =
        HashMap::default();

    nodes.iter().for_each(|node| {
        let rewardable_nodes = node_provider_rewardables
            .entry(node.node_provider_id)
            .or_default();
        rewardable_nodes.push(node.clone());
    });

    node_provider_rewardables
}

#[cfg(test)]
mod tests;
