use candid::Principal;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::pb::v1::MonthlyNodeProviderRewards;
use ic_protobuf::registry::node_rewards::{v2::NodeRewardRate, v2::NodeRewardsTable};
use ic_registry_keys::NODE_REWARDS_TABLE_KEY;
use itertools::Itertools;
use num_traits::{ToPrimitive, Zero};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::{self, BTreeMap, HashMap, HashSet};
use trustworthy_node_metrics_types::types::{
    DailyNodeMetrics, NodeProviderRewards, NodeProviderRewardsAvg, NodeProviderRewardsComputation, NodeRewardsMultiplier, RewardsMultiplierStats
};

use crate::{
    chrono_utils::DateTimeRange,
    computation_logger::{ComputationLogger, Operation, OperationExecutor},
    stable_memory::{self, RegionNodeTypeCategory},
};

const MIN_FAILURE_RATE: Decimal = dec!(0.1);
const MAX_FAILURE_RATE: Decimal = dec!(0.6);

/// Calculates the rewards reduction based on the failure rate.
///
/// # Arguments
///
/// * `failure_rate` - A reference to a `Decimal` value representing the failure rate.
///
/// # Returns
///
/// * A `Decimal` value representing the rewards reduction, where:
///   - `0` indicates no reduction (failure rate below the minimum threshold),
///   - `1` indicates maximum reduction (failure rate above the maximum threshold),
///   - A value between `0` and `1` represents a proportional reduction based on the failure rate.
///
/// # Explanation
///
/// 1. The function checks if the provided `failure_rate` is below the `MIN_FAILURE_RATE` -> no reduction in rewards.
///
/// 2. It then checks if the `failure_rate` is above the `MAX_FAILURE_RATE` -> maximum reduction in rewards.
///
/// 3. If the `failure_rate` is within the defined range (`MIN_FAILURE_RATE` to `MAX_FAILURE_RATE`),
///    the function calculates the reduction proportionally.
fn rewards_reduction_percent(failure_rate: &Decimal) -> (Vec<OperationExecutor>, Decimal) {
    const RF: &str = "Linear Reduction factor";

    if failure_rate < &MIN_FAILURE_RATE {
        let (operation, result) = OperationExecutor::execute(
            &format!(
                "No Reduction applied because {} is less than {} failure rate.\n{}",
                failure_rate.round_dp(4),
                MIN_FAILURE_RATE,
                RF
            ),
            Operation::Set(dec!(0)),
        );
        (vec![operation], result)
    } else if failure_rate > &MAX_FAILURE_RATE {
        let (operation, result) = OperationExecutor::execute(
            &format!(
                "Max reduction applied because {} is over {} failure rate.\n{}",
                failure_rate.round_dp(4),
                MAX_FAILURE_RATE,
                RF
            ),
            Operation::Set(dec!(0.8)),
        );

        (vec![operation], result)
    } else {
        let (y_change_operation, y_change) =
            OperationExecutor::execute("Linear Reduction Y change", Operation::Subtract(*failure_rate, MIN_FAILURE_RATE));
        let (x_change_operation, x_change) =
            OperationExecutor::execute("Linear Reduction X change", Operation::Subtract(MAX_FAILURE_RATE, MIN_FAILURE_RATE));

        let (m_operation, m) = OperationExecutor::execute("Compute m", Operation::Divide(y_change, x_change));
        let (operation, result) = OperationExecutor::execute(RF, Operation::Multiply(m, dec!(0.8)));
        (vec![y_change_operation, x_change_operation, m_operation, operation], result)
    }
}

/// Compute rewards percent
///
/// Computes the rewards percentage based on the overall failure rate in the period.
///
/// # Arguments
///
/// * `daily_metrics` - A slice of `DailyNodeMetrics` structs, where each struct represents the metrics for a single day.
///
/// # Returns
///
/// * A `RewardsComputationResult`.
///
/// # Explanation
///
/// 1. The function iterates through each day's metrics, summing up the `daily_failed` and `daily_total` blocks across all days.
/// 2. The `overall_failure_rate` is calculated by dividing the `overall_failed` blocks by the `overall_total` blocks.
/// 3. The `rewards_reduction` function is applied to `overall_failure_rate`.
/// 3. Finally, the rewards percentage to be distrubuted to the node is computed.
fn compute_rewards_multiplier(daily_metrics: &[DailyNodeMetrics], total_days: u64) -> (Decimal, RewardsMultiplierStats) {
    let mut computation_logger = ComputationLogger::new();

    let total_days = computation_logger.execute("Days In Period", Operation::Set(Decimal::from(total_days)));
    let days_assigned = computation_logger.execute("Assigned Days In Period", Operation::Set(Decimal::from(daily_metrics.len())));
    let days_unassigned = computation_logger.execute("Unassigned Days In Period", Operation::Subtract(total_days, days_assigned));

    let daily_failed = daily_metrics.iter().map(|metrics| metrics.num_blocks_failed.into()).collect_vec();
    let daily_proposed = daily_metrics.iter().map(|metrics| metrics.num_blocks_proposed.into()).collect_vec();

    let overall_failed = computation_logger.execute("Computing Total Failed Blocks", Operation::Sum(daily_failed));
    let overall_proposed = computation_logger.execute("Computing Total Proposed Blocks", Operation::Sum(daily_proposed));
    let overall_total = computation_logger.execute("Computing Total Blocks", Operation::Sum(vec![overall_failed, overall_proposed]));
    let overall_failure_rate = computation_logger.execute(
        "Computing Total Failure Rate",
        if overall_total > dec!(0) {
            Operation::Divide(overall_failed, overall_total)
        } else {
            Operation::Set(dec!(0))
        },
    );

    let (operations, rewards_reduction) = rewards_reduction_percent(&overall_failure_rate);
    computation_logger.add_executed(operations);
    let rewards_multiplier_unassigned = computation_logger.execute("Reward Multiplier Unassigned Days", Operation::Set(dec!(1)));
    let rewards_multiplier_assigned = computation_logger.execute("Reward Multiplier Assigned Days", Operation::Subtract(dec!(1), rewards_reduction));
    let assigned_days_factor = computation_logger.execute("Assigned Days Factor", Operation::Multiply(days_assigned, rewards_multiplier_assigned));
    let unassigned_days_factor = computation_logger.execute(
        "Unassigned Days Factor",
        Operation::Multiply(days_unassigned, rewards_multiplier_unassigned),
    );
    let rewards_multiplier = computation_logger.execute(
        "Average reward multiplier",
        Operation::Divide(assigned_days_factor + unassigned_days_factor, total_days),
    );

    let rewards_multiplier_stats = RewardsMultiplierStats {
        days_assigned: days_assigned.to_u64().unwrap(),
        days_unassigned: days_unassigned.to_u64().unwrap(),
        rewards_reduction: rewards_reduction.to_f64().unwrap(),
        blocks_failed: overall_failed.to_u64().unwrap(),
        blocks_proposed: overall_proposed.to_u64().unwrap(),
        blocks_total: overall_total.to_u64().unwrap(),
        failure_rate: overall_failure_rate.to_f64().unwrap(),
        computation_log: computation_logger.get_log(),
    };

    (rewards_multiplier, rewards_multiplier_stats)
}

fn compute_node_provider_rewards(
    assigned_multipliers: &collections::BTreeMap<RegionNodeTypeCategory, Vec<Decimal>>,
    rewardable_nodes: &collections::BTreeMap<RegionNodeTypeCategory, u32>,
    rewards_table: &NodeRewardsTable,
) -> (ComputationLogger, NodeProviderRewardsComputation) {
    let mut rewards_xdr_total = dec!(0);
    let mut rewards_xdr_no_reduction_total = dec!(0);
    let mut computation_logger = ComputationLogger::new();

    // 1.1 - Extract coefficients and rewards for type3* nodes in all regions

    let mut type3_coefficients_rewards: HashMap<String, (Vec<Decimal>, Vec<Decimal>)> = HashMap::new();
    let mut other_rewards: HashMap<RegionNodeTypeCategory, Decimal> = HashMap::new();

    for ((region, node_type), node_count) in rewardable_nodes {
        let rate = match rewards_table.get_rate(region, node_type) {
            Some(rate) => rate,
            None => {
                println!(
                    "The Node Rewards Table does not have an entry for \
                         node type '{}' within region '{}' or parent region, defaulting to 1 xdr per month per node",
                    node_type, region
                );
                NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 1,
                    reward_coefficient_percent: Some(100),
                }
            }
        };
        let base_rewards = Decimal::from(rate.xdr_permyriad_per_node_per_month);

        if node_type.starts_with("type3") && *node_count > 0 {
            let coeff = Decimal::from(rate.reward_coefficient_percent.unwrap_or(80)) / dec!(100);
            let coefficients = vec![coeff; *node_count as usize];
            let rewards = vec![base_rewards; *node_count as usize];
            let region_key = region.splitn(3, ',').take(2).collect::<Vec<&str>>().join(":");

            computation_logger.execute(
                &format!(
                    "Setting count of nodes in region {} with type {}, with coefficient {}, with rewards {} XDR * 10'000\n",
                    region, node_type, coeff, base_rewards
                ),
                Operation::Set(Decimal::from(*node_count)),
            );

            type3_coefficients_rewards
                .entry(region_key)
                .and_modify(|(entry_coefficients, entry_rewards)| {
                    entry_coefficients.extend(&coefficients);
                    entry_rewards.extend(&rewards);
                })
                .or_insert((coefficients, rewards));
        } else {
            other_rewards.insert((region.clone(), node_type.clone()), base_rewards);
        }
    }

    // 1.2 - Compute node rewards for type3* nodes in all regions

    let type3_rewards: HashMap<String, Decimal> = type3_coefficients_rewards
        .clone()
        .into_iter()
        .map(|(region, (coefficients, rewards))| {
            let mut running_coefficient = dec!(1);
            let mut region_rewards = dec!(0);
            let coefficients_avg = computation_logger.execute(
                &format!("Coefficient average in region {} for type3* nodes\n", region),
                Operation::Set(coefficients.iter().fold(Decimal::zero(), |acc, val| acc + val) / Decimal::from(coefficients.len())),
            );
            let rewards_avg = computation_logger.execute(
                &format!("Rewards average in region {} for type3* nodes\n", region),
                Operation::Set(rewards.iter().fold(Decimal::zero(), |acc, val| acc + val) / Decimal::from(rewards.len())),
            );

            for _ in 0..rewards.len() {
                region_rewards += rewards_avg * running_coefficient;
                running_coefficient *= coefficients_avg;
            }
            let region_rewards_avg = computation_logger.execute(
                &format!(
                    "Computing rewards average after coefficient reduction in region {} for type3* nodes\n",
                    region
                ),
                Operation::Divide(region_rewards, Decimal::from(rewards.len())),
            );

            (region, region_rewards_avg)
        })
        .collect();

    // 3 - Now compute total rewards with reductions

    for ((region, node_type), node_count) in rewardable_nodes {
        let mut rewards_xdr = dec!(0);
        let mut rewards_multipliers = assigned_multipliers.get(&(region.clone(), node_type.clone())).unwrap_or(&vec![]).clone();
        rewards_multipliers.resize(*node_count as usize, dec!(1));

        computation_logger.execute(
            &format!(
                "Rewards multipliers len for nodes in region {} with type {}: {:?}\n",
                &region, &node_type, rewards_multipliers
            ),
            Operation::Set(Decimal::from(rewards_multipliers.len())),
        );

        for multiplier in rewards_multipliers {
            if node_type.starts_with("type3") {
                let region_key = region.as_str().splitn(3, ',').take(2).collect::<Vec<&str>>().join(":");
                let xdr_permyriad_avg_based = type3_rewards.get(&region_key).expect("Type3 rewards should have been filled already");

                rewards_xdr_no_reduction_total += *xdr_permyriad_avg_based;
                rewards_xdr += *xdr_permyriad_avg_based * multiplier;
            } else {
                let xdr_permyriad = other_rewards.get(&(region.clone(), node_type.clone())).expect("Rewards already filled");
                rewards_xdr_no_reduction_total += xdr_permyriad;
                rewards_xdr += xdr_permyriad * multiplier;
            }
        }

        computation_logger.execute(
            &format!(
                "Rewards contribution XDR * 10'000 for nodes in region {} with type: {}\n",
                region, node_type
            ),
            Operation::Set(rewards_xdr),
        );

        rewards_xdr_total += rewards_xdr;
    }

    computation_logger.execute("Total rewards XDR * 10'000\n", Operation::Set(rewards_xdr_total));

    let results = NodeProviderRewardsComputation {
        rewards_xdr_permyriad: rewards_xdr_total.to_u64().unwrap(),
        rewards_xdr_permyriad_no_reduction: rewards_xdr_no_reduction_total.to_u64().unwrap(),
    };

    (computation_logger, results)
}

fn get_daily_metrics(node_ids: Vec<Principal>, rewarding_period: DateTimeRange) -> collections::BTreeMap<Principal, Vec<DailyNodeMetrics>> {
    let mut daily_metrics: collections::BTreeMap<Principal, Vec<DailyNodeMetrics>> = collections::BTreeMap::new();
    let nodes_metrics = stable_memory::get_metrics_range(
        rewarding_period.start_timestamp_nanos(),
        Some(rewarding_period.end_timestamp_nanos()),
        Some(&node_ids),
    );

    for node_id in node_ids {
        daily_metrics.entry(node_id).or_default();
    }

    for ((ts, node_id), node_metrics_value) in nodes_metrics {
        let daily_node_metrics = DailyNodeMetrics::new(
            ts,
            node_metrics_value.subnet_assigned,
            node_metrics_value.num_blocks_proposed,
            node_metrics_value.num_blocks_failed,
        );

        daily_metrics.entry(node_id).or_default().push(daily_node_metrics);
    }
    daily_metrics
}

pub fn node_rewards_multiplier(node_ids: Vec<Principal>, rewarding_period: DateTimeRange) -> Vec<NodeRewardsMultiplier> {
    let total_days = rewarding_period.days_between();
    let daily_metrics = get_daily_metrics(node_ids, rewarding_period);

    daily_metrics
        .into_iter()
        .map(|(node_id, daily_node_metrics)| {
            let (rewards_multiplier, rewards_multiplier_stats) = compute_rewards_multiplier(&daily_node_metrics, total_days);
            let node_metadata = stable_memory::get_node_metadata(&node_id).expect("Node should have one node provider");
            let rewards_table = stable_memory::get_node_rewards_table();
            let node_rate = match rewards_table.get_rate(&node_metadata.region, &node_metadata.node_type) {
                Some(rate) => rate,
                None => {
                    println!(
                        "The Node Rewards Table does not have an entry for \
                             node type '{}' within region '{}' or parent region, defaulting to 1 xdr per month per node",
                        node_metadata.region, node_metadata.node_type
                    );
                    NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 1,
                        reward_coefficient_percent: Some(100),
                    }
                }
            };

            NodeRewardsMultiplier {
                node_id,
                daily_node_metrics,
                node_rate,
                rewards_multiplier: rewards_multiplier.to_f64().unwrap(),
                rewards_multiplier_stats,
            }
        })
        .collect_vec()
}

pub fn node_provider_rewards(node_provider_id: Principal, rewarding_period: DateTimeRange) -> NodeProviderRewards {
    let total_days = rewarding_period.days_between();
    let rewardable_nodes: collections::BTreeMap<RegionNodeTypeCategory, u32> = stable_memory::get_rewardable_nodes(&node_provider_id);
    let rewards_table = stable_memory::get_node_rewards_table();
    let mut logger = ComputationLogger::new();
    let latest_np_rewards = stable_memory::get_latest_node_providers_rewards();
    let node_ids = stable_memory::get_node_principals(&node_provider_id);
    let mut assigned_multipliers: BTreeMap<RegionNodeTypeCategory, Vec<Decimal>> = BTreeMap::new();
    let mut rewards_multipliers_stats = Vec::new();

    let daily_metrics = get_daily_metrics(node_ids, rewarding_period);

    for (node_id, daily_node_metrics) in daily_metrics {
        let (multiplier, multiplier_stats) = compute_rewards_multiplier(&daily_node_metrics, total_days);
        let node_metadata = stable_memory::get_node_metadata(&node_id).expect("Node should have one node provider");

        logger.execute(
            &format!(
                "Set rewards multiplier for Node {}, in region {} with type {}\n",
                node_id, node_metadata.region, node_metadata.node_type
            ),
            Operation::Set(multiplier),
        );
        assigned_multipliers
            .entry((node_metadata.region, node_metadata.node_type))
            .or_default()
            .push(multiplier);

        rewards_multipliers_stats.push(multiplier_stats);
    }

    let (np_rewards_log, rewards_computation) = compute_node_provider_rewards(&assigned_multipliers, &rewardable_nodes, &rewards_table);

    let rewards_xdr_old = latest_np_rewards
        .rewards
        .into_iter()
        .filter_map(|np_rewards| {
            if let Some(node_provider) = np_rewards.node_provider {
                if let Some(id) = node_provider.id {
                    if id.0 == node_provider_id {
                        return Some(np_rewards.amount_e8s);
                    }
                }
            }
            None
        })
        .next();

    logger.operations_executed.extend(np_rewards_log.operations_executed);
    NodeProviderRewards {
        node_provider_id,
        rewards_xdr_permyriad: rewards_computation.rewards_xdr_permyriad,
        rewards_xdr_permyriad_no_reduction: rewards_computation.rewards_xdr_permyriad_no_reduction,
        computation_log: logger.get_log(),
        rewards_xdr_old,
        ts_distribution: latest_np_rewards.timestamp,
        xdr_conversion_rate: latest_np_rewards.xdr_conversion_rate.and_then(|rate| rate.xdr_permyriad_per_icp),
        rewards_multipliers_stats,
    }
}

/// Update node rewards table
pub async fn update_node_rewards_table() -> anyhow::Result<()> {
    let (rewards_table, _): (NodeRewardsTable, _) = ic_nns_common::registry::get_value(NODE_REWARDS_TABLE_KEY.as_bytes(), None).await?;
    for (region, rewards_rates) in rewards_table.table {
        stable_memory::insert_rewards_rates(region, rewards_rates)
    }

    Ok(())
}

/// Update recent node providers rewards
pub async fn update_recent_provider_rewards() -> anyhow::Result<()> {
    let (maybe_monthly_rewards,): (Option<MonthlyNodeProviderRewards>,) = ic_cdk::api::call::call(
        Principal::from(GOVERNANCE_CANISTER_ID),
        "get_most_recent_monthly_node_provider_rewards",
        (),
    )
    .await
    .map_err(|(code, msg)| {
        anyhow::anyhow!(
            "Error when calling get_most_recent_monthly_node_provider_rewards:\n Code:{:?}\nMsg:{}",
            code,
            msg
        )
    })?;

    if let Some(monthly_rewards) = maybe_monthly_rewards {
        let latest_np_rewards = stable_memory::get_latest_node_providers_rewards();

        if latest_np_rewards.timestamp < monthly_rewards.timestamp {
            stable_memory::insert_node_provider_rewards(monthly_rewards.timestamp, monthly_rewards)
        }
    }

    Ok(())
}


pub(crate) fn node_provider_rewards_avg(from: u32, to: u32, rewarding_period: DateTimeRange) -> Vec<NodeProviderRewardsAvg> {
    let metadata: HashSet<Principal> = stable_memory::nodes_metadata().into_iter().map(|meta| meta.node_metadata_stored.node_provider_id).collect();
    let metadata = metadata.into_iter().sorted().collect_vec();
    let rewardable = stable_memory::get_rewardables();


    ic_cdk::println!("count {}",  metadata.len());

    metadata.into_iter() 
    .skip(from as usize)
    .take(to as usize).map(|np| {
        let rewards = node_provider_rewards(np, rewarding_period.clone());
        let nodes_num: u32 = rewardable
        .iter()
        .filter_map(|(key, value)| {
            if key.node_provider_id == np {
                Some(value)
            } else {
                None
            }
        })
        .sum();

        NodeProviderRewardsAvg {
            node_provider_id: np,
            rewards_xdr_permyriad_avg: rewards.rewards_xdr_permyriad_no_reduction / nodes_num as u64
        }
    }).collect_vec()
}


#[cfg(test)]
mod tests {
    use candid::Principal;
    use ic_protobuf::registry::node_rewards::v2::NodeRewardRates;
    use itertools::Itertools;

    use super::*;

    #[derive(Clone)]
    struct MockedMetrics {
        days: u64,
        proposed_blocks: u64,
        failed_blocks: u64,
    }

    impl MockedMetrics {
        fn new(days: u64, proposed_blocks: u64, failed_blocks: u64) -> Self {
            MockedMetrics {
                days,
                proposed_blocks,
                failed_blocks,
            }
        }
    }

    fn daily_mocked_metrics(metrics: Vec<MockedMetrics>) -> Vec<DailyNodeMetrics> {
        let subnet = Principal::anonymous();
        let mut i = 0;

        metrics
            .into_iter()
            .flat_map(|mocked_metrics: MockedMetrics| {
                (0..mocked_metrics.days).map(move |_| {
                    i += 1;
                    DailyNodeMetrics::new(i, subnet, mocked_metrics.proposed_blocks, mocked_metrics.failed_blocks)
                })
            })
            .collect_vec()
    }

    fn mocked_rewards_table() -> NodeRewardsTable {
        let mut rates_outer: BTreeMap<String, NodeRewardRate> = BTreeMap::new();
        let mut rates_inner: BTreeMap<String, NodeRewardRate> = BTreeMap::new();
        let mut table: BTreeMap<String, NodeRewardRates> = BTreeMap::new();

        let rate_outer = NodeRewardRate {
            xdr_permyriad_per_node_per_month: 1000,
            reward_coefficient_percent: Some(97),
        };

        let rate_inner = NodeRewardRate {
            xdr_permyriad_per_node_per_month: 1500,
            reward_coefficient_percent: Some(95),
        };

        rates_outer.insert("type0".to_string(), rate_outer.clone());
        rates_outer.insert("type1".to_string(), rate_outer.clone());
        rates_outer.insert("type3".to_string(), rate_outer);

        rates_inner.insert("type3.1".to_string(), rate_inner);

        table.insert("A,B,C".to_string(), NodeRewardRates { rates: rates_inner });
        table.insert("A,B".to_string(), NodeRewardRates { rates: rates_outer });

        NodeRewardsTable { table }
    }

    #[test]
    fn test_rewards_percent() {
        // Overall failed = 130 Overall total = 500 Failure rate = 0.26
        let daily_metrics: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![MockedMetrics::new(20, 6, 4), MockedMetrics::new(25, 10, 2)]);
        let (result, _) = compute_rewards_multiplier(&daily_metrics, daily_metrics.len() as u64);
        assert_eq!(result, dec!(0.744));

        // Overall failed = 45 Overall total = 450 Failure rate = 0.1
        // rewards_reduction = 0.0
        let daily_metrics: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            MockedMetrics::new(1, 400, 20),
            MockedMetrics::new(1, 5, 25), // no penalty
        ]);
        let (result, _) = compute_rewards_multiplier(&daily_metrics, daily_metrics.len() as u64);
        assert_eq!(result, dec!(1.0));

        // Overall failed = 5 Overall total = 10 Failure rate = 0.5
        let daily_metrics: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            MockedMetrics::new(1, 5, 5), // no penalty
        ]);
        let (result, _) = compute_rewards_multiplier(&daily_metrics, daily_metrics.len() as u64);
        assert_eq!(result, dec!(0.36));
    }

    #[test]
    fn test_rewards_percent_max_reduction() {
        let daily_metrics: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            MockedMetrics::new(10, 5, 95), // max failure rate
        ]);
        let (result, _) = compute_rewards_multiplier(&daily_metrics, daily_metrics.len() as u64);
        assert_eq!(result, dec!(0.2));
    }

    #[test]
    fn test_rewards_percent_min_reduction() {
        let daily_metrics: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            MockedMetrics::new(10, 9, 1), // min failure rate
        ]);
        let (result, _) = compute_rewards_multiplier(&daily_metrics, daily_metrics.len() as u64);
        assert_eq!(result, dec!(1.0));
    }

    #[test]
    fn test_same_rewards_percent_if_gaps_no_penalty() {
        let gap = MockedMetrics::new(1, 10, 0);

        let daily_metrics_mid_gap: Vec<DailyNodeMetrics> =
            daily_mocked_metrics(vec![MockedMetrics::new(1, 6, 4), gap.clone(), MockedMetrics::new(1, 7, 3)]);

        let daily_metrics_left_gap: Vec<DailyNodeMetrics> =
            daily_mocked_metrics(vec![gap.clone(), MockedMetrics::new(1, 6, 4), MockedMetrics::new(1, 7, 3)]);

        let daily_metrics_right_gap: Vec<DailyNodeMetrics> =
            daily_mocked_metrics(vec![gap.clone(), MockedMetrics::new(1, 6, 4), MockedMetrics::new(1, 7, 3)]);

        assert_eq!(
            compute_rewards_multiplier(&daily_metrics_mid_gap, daily_metrics_mid_gap.len() as u64).0,
            dec!(0.7866666666666666666666666667)
        );

        assert_eq!(
            compute_rewards_multiplier(&daily_metrics_mid_gap, daily_metrics_mid_gap.len() as u64).0,
            compute_rewards_multiplier(&daily_metrics_left_gap, daily_metrics_left_gap.len() as u64).0
        );
        assert_eq!(
            compute_rewards_multiplier(&daily_metrics_right_gap, daily_metrics_right_gap.len() as u64).0,
            compute_rewards_multiplier(&daily_metrics_left_gap, daily_metrics_left_gap.len() as u64).0
        );
    }

    #[test]
    fn test_same_rewards_if_reversed() {
        let daily_metrics: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            MockedMetrics::new(1, 5, 5),
            MockedMetrics::new(5, 6, 4),
            MockedMetrics::new(25, 10, 0),
        ]);

        let mut daily_metrics = daily_metrics.clone();
        let result = compute_rewards_multiplier(&daily_metrics, daily_metrics.len() as u64);
        daily_metrics.reverse();
        let result_rev = compute_rewards_multiplier(&daily_metrics, daily_metrics.len() as u64);

        assert_eq!(result.0, dec!(1.0));
        assert_eq!(result_rev.0, result.0);
    }

    #[test]
    fn test_np_rewards_other_type() {
        let mut assigned_multipliers: collections::BTreeMap<RegionNodeTypeCategory, Vec<Decimal>> = BTreeMap::new();
        let mut rewardable_nodes: collections::BTreeMap<RegionNodeTypeCategory, u32> = BTreeMap::new();

        assigned_multipliers.insert(("A,B,C".to_string(), "type0".to_string()), vec![dec!(0.5), dec!(0.5)]);
        rewardable_nodes.insert(("A,B,C".to_string(), "type0".to_string()), 4);
        let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
        let (_, rewards) = compute_node_provider_rewards(&assigned_multipliers, &rewardable_nodes, &node_rewards_table);

        // 4 nodes type0 1000 * 4 = 4000
        assert_eq!(rewards.rewards_xdr_permyriad_no_reduction, 4000);
        // 4 nodes type0 1000 * 1 + 1000 * 1 + 1000 * 0.5 + 1000 * 0.5 * 4 = 3000
        assert_eq!(rewards.rewards_xdr_permyriad, 3000);
    }

    #[test]
    fn test_np_rewards_type3_coeff() {
        let mut assigned_multipliers: collections::BTreeMap<RegionNodeTypeCategory, Vec<Decimal>> = BTreeMap::new();
        let mut rewardable_nodes: collections::BTreeMap<RegionNodeTypeCategory, u32> = BTreeMap::new();

        assigned_multipliers.insert(("A,B,C".to_string(), "type3.1".to_string()), vec![dec!(0.5)]);
        rewardable_nodes.insert(("A,B,C".to_string(), "type3.1".to_string()), 4);
        let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
        let (_, rewards) = compute_node_provider_rewards(&assigned_multipliers, &rewardable_nodes, &node_rewards_table);

        // 4 nodes type3.1 avg rewards 1500 avg coefficient 0.95
        // 1500 * 1 + 1500 * 0.95 + 1500 * 0.95 * 0.95 + 1500 * 0.95 * 0.95 * 0.95
        assert_eq!(rewards.rewards_xdr_permyriad_no_reduction, 5564);

        // rewards coeff avg 5564/4=1391
        // 1391 * 0.5 + 1391 * 3 = 4868
        assert_eq!(rewards.rewards_xdr_permyriad, 4869);
    }

    #[test]
    fn test_np_rewards_type3_mix() {
        let mut assigned_multipliers: collections::BTreeMap<RegionNodeTypeCategory, Vec<Decimal>> = BTreeMap::new();
        let mut rewardable_nodes: collections::BTreeMap<RegionNodeTypeCategory, u32> = BTreeMap::new();

        assigned_multipliers.insert(("A,B,D".to_string(), "type3".to_string()), vec![dec!(0.5)]);

        // This will take rates from outer
        rewardable_nodes.insert(("A,B,D".to_string(), "type3".to_string()), 2);

        // This will take rates from inner
        rewardable_nodes.insert(("A,B,C".to_string(), "type3.1".to_string()), 2);

        let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
        let (_, rewards) = compute_node_provider_rewards(&assigned_multipliers, &rewardable_nodes, &node_rewards_table);

        // 4 nodes type3* avg rewards 1250 avg coefficient 0.96
        // 1250 * 1 + 1250 * 0.96 + 1250 * 0.96^2 + 1250 * 0.96^3
        assert_eq!(rewards.rewards_xdr_permyriad_no_reduction, 4707);

        // rewards coeff avg 4707/4 = 1176.75
        // 1176.75 * 0.5 + 1176.75 * 3
        assert_eq!(rewards.rewards_xdr_permyriad, 4119);
    }
}
