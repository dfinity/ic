use ic_base_types::PrincipalId;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardsTable};
use itertools::Itertools;
use num_traits::ToPrimitive;

use crate::v1_logs::LogLevel;
use crate::v1_types::{NodeProviderComputationData, TimestampNanos};
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

const FULL_REWARDS_MACHINES_LIMIT: u32 = 3;
const MIN_FAILURE_RATE: Decimal = dec!(0.1);
const MAX_FAILURE_RATE: Decimal = dec!(0.6);
const MAX_REWARDS_REDUCTION: Decimal = dec!(0.8);
const RF: &str = "Linear Reduction factor";

pub fn calculate_rewards(
    days_in_period: u64,
    rewards_table: &NodeRewardsTable,
    subnet_metrics: HashMap<PrincipalId, Vec<NodeMetricsHistoryResponse>>,
    rewardable_nodes: &[RewardableNode],
) -> RewardsPerNodeProvider {
    let mut rewards_per_node_provider = HashMap::default();
    let mut rewards_log_per_node_provider = HashMap::default();
    let mut rewards_data_per_node_provider = HashMap::default();

    let mut all_assigned_metrics = daily_node_metrics(subnet_metrics);
    let systematic_failure_rates = systematic_fr_per_subnet(&all_assigned_metrics);
    let node_provider_rewardables = rewardables_by_node_provider(rewardable_nodes);

    for (node_provider_id, node_provider_rewardables) in node_provider_rewardables {
        let mut logger = RewardsLog::default();
        let mut computation_data = NodeProviderComputationData::default();
        computation_data.node_provider_rewardables = node_provider_rewardables.clone();

        logger.add_entry(
            LogLevel::High,
            LogEntry::CalculateRewardsForNodeProvider(node_provider_id),
        );

        let assigned_metrics: HashMap<PrincipalId, Vec<DailyNodeMetrics>> =
            node_provider_rewardables
                .iter()
                .filter_map(|node| {
                    all_assigned_metrics
                        .remove(&node.node_id)
                        .map(|daily_metrics| (node.node_id, daily_metrics))
                })
                .collect::<HashMap<PrincipalId, Vec<DailyNodeMetrics>>>();
        computation_data.assigned_metrics = assigned_metrics.clone();
        let node_daily_fr =
            nodes_idiosyncratic_fr(&mut logger, &assigned_metrics, &systematic_failure_rates);
        computation_data.node_daily_fr = node_daily_fr.clone();

        let rewards = node_provider_rewards(
            &mut logger,
            &mut computation_data,
            &node_provider_rewardables,
            node_daily_fr,
            days_in_period,
            rewards_table,
        );

        rewards_log_per_node_provider.insert(node_provider_id, logger);
        rewards_per_node_provider.insert(node_provider_id, rewards);
        rewards_data_per_node_provider.insert(node_provider_id, computation_data);
    }

    let systematic_failure_rates: HashMap<PrincipalId, Vec<(TimestampNanos, Decimal)>> =
        systematic_failure_rates
            .into_iter()
            .map(|((subnet, ts), fr)| (subnet, (ts, fr)))
            .into_group_map();

    RewardsPerNodeProvider {
        rewards_per_node_provider,
        rewards_log_per_node_provider,
        rewards_data_per_node_provider,
        systematic_failure_rates,
    }
}

/// Computes the idiosyncratic daily failure rates for each node.
///
/// This function calculates the idiosyncratic failure rates by subtracting the systematic
/// failure rate of the subnet from the node's failure rate for each day.
/// If the node's failure rate is less than the systematic failure rate, the idiosyncratic
/// failure rate is set to zero.
pub fn nodes_idiosyncratic_fr(
    logger: &mut RewardsLog,
    assigned_metrics: &HashMap<PrincipalId, Vec<DailyNodeMetrics>>,
    subnets_systematic_fr: &HashMap<(PrincipalId, TimestampNanos), Decimal>,
) -> HashMap<PrincipalId, Vec<Decimal>> {
    let mut nodes_idiosyncratic_fr: HashMap<PrincipalId, Vec<Decimal>> = HashMap::new();

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

pub fn node_provider_rewards(
    logger: &mut RewardsLog,
    computation_data: &mut NodeProviderComputationData,
    rewardables: &[RewardableNode],
    nodes_idiosyncratic_fr: HashMap<PrincipalId, Vec<Decimal>>,
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
    computation_data.region_nodetype_rewards = region_nodetype_rewards.clone();

    // 1. Extrapolate the unassigned daily failure rate from the active nodes
    logger.add_entry(LogLevel::High, LogEntry::ComputeUnassignedFailureRate);
    for node in rewardables {
        if let Some(fr) = nodes_idiosyncratic_fr.get(&node.node_id) {
            let avg_fr = logger.execute(
                &format!("Avg. failure rate for node: {}", node.node_id),
                Operation::Avg(fr.clone()),
            );
            computation_data
                .avg_assigned_failure_rate
                .insert(node.node_id, avg_fr);
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
    computation_data.unassigned_fr = unassigned_fr;

    // 2. Compute rewards multiplier for fully unassigned nodes
    let rewards_reduction_unassigned = rewards_reduction_percent(logger, &unassigned_fr);
    let multiplier_unassigned = logger.execute(
        "Reward multiplier fully unassigned nodes:",
        Operation::Subtract(dec!(1), rewards_reduction_unassigned),
    );

    computation_data.multiplier_unassigned = multiplier_unassigned;

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
        computation_data
            .rewards_xdr_no_penalty_total
            .insert(node.node_id, *rewards_xdr_no_penalty);

        // Node Providers with less than 4 machines are rewarded fully, independently of their performance
        if rewardable_nodes_count <= FULL_REWARDS_MACHINES_LIMIT {
            computation_data
                .rewards_xdr
                .insert(node.node_id, *rewards_xdr_no_penalty);
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

            let failure_rate_rewarding_period = logger.execute(
                "Failure rate rewarding period",
                Operation::Avg(daily_idiosyncratic_fr.clone()),
            );
            computation_data
                .failure_rate_rewarding_period
                .insert(node.node_id, failure_rate_rewarding_period);

            assigned_multiplier(logger, daily_idiosyncratic_fr)
        } else {
            logger.add_entry(LogLevel::Mid, LogEntry::NodeStatusUnassigned);

            multiplier_unassigned
        };

        computation_data
            .rewards_multiplier
            .insert(node.node_id, reward_multiplier);

        let rewards_xdr = logger.execute(
            "Rewards XDR for the node",
            Operation::Multiply(*rewards_xdr_no_penalty, reward_multiplier),
        );
        computation_data
            .rewards_xdr
            .insert(node.node_id, rewards_xdr);
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

pub fn assigned_multiplier(logger: &mut RewardsLog, daily_failure_rate: Vec<Decimal>) -> Decimal {
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
pub fn systematic_fr_per_subnet(
    daily_node_metrics: &HashMap<PrincipalId, Vec<DailyNodeMetrics>>,
) -> HashMap<(PrincipalId, TimestampNanos), Decimal> {
    fn percentile_75(mut values: Vec<Decimal>) -> Decimal {
        values.sort();
        let len = values.len();
        if len == 0 {
            return Decimal::ZERO;
        }
        let idx = ((len as f64) * 0.75).ceil() as usize - 1;
        values[idx]
    }

    let mut subnet_daily_failure_rates: HashMap<(PrincipalId, u64), Vec<Decimal>> = HashMap::new();

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

pub fn daily_node_metrics(
    subnets_metrics: HashMap<PrincipalId, Vec<NodeMetricsHistoryResponse>>,
) -> HashMap<PrincipalId, Vec<DailyNodeMetrics>> {
    let mut subnets_metrics = subnets_metrics
        .into_iter()
        .flat_map(|(subnet_id, metrics)| {
            metrics.into_iter().map(move |metrics| (subnet_id, metrics))
        })
        .collect_vec();
    subnets_metrics.sort_by_key(|(_, metrics)| metrics.timestamp_nanos);

    let mut daily_node_metrics: HashMap<PrincipalId, Vec<(PrincipalId, u64, NodeMetrics)>> =
        HashMap::default();

    for (subnet_id, metrics) in subnets_metrics {
        for node_metrics in metrics.node_metrics {
            daily_node_metrics
                .entry(node_metrics.node_id)
                .or_default()
                .push((subnet_id, metrics.timestamp_nanos, node_metrics));
        }
    }

    daily_node_metrics
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
pub fn rewards_reduction_percent(logger: &mut RewardsLog, failure_rate: &Decimal) -> Decimal {
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

pub fn base_rewards_region_nodetype(
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

pub fn rewardables_by_node_provider(
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
