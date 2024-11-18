use ic_base_types::PrincipalId;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardsTable};
use itertools::Itertools;
use lazy_static::lazy_static;
use num_traits::ToPrimitive;

use crate::{
    v1_logs::{LogEntry, Operation, RewardsLog},
    v1_types::{
        AHashMap, DailyNodeMetrics, MultiplierStats, NodeMultiplierStats, RegionNodeTypeCategory,
        RewardableNode, RewardablesWithNodesMetrics, Rewards, RewardsPerNodeProvider,
    },
};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::{
    mem,
    sync::{Arc, RwLock},
};

const FULL_REWARDS_MACHINES_LIMIT: u32 = 4;
const MIN_FAILURE_RATE: Decimal = dec!(0.1);
const MAX_FAILURE_RATE: Decimal = dec!(0.6);

const RF: &str = "Linear Reduction factor";

lazy_static! {
    static ref LOGGER: Arc<RwLock<RewardsLog>> = Arc::new(RwLock::new(RewardsLog::default()));
}

fn logger() -> std::sync::RwLockWriteGuard<'static, RewardsLog> {
    LOGGER.write().unwrap()
}

/// Calculates the rewards reduction based on the failure rate.
///
/// if `failure_rate` is:
/// - Below the `MIN_FAILURE_RATE`, no reduction in rewards applied.
/// - Above the `MAX_FAILURE_RATE`, maximum reduction in rewards applied.
/// - Within the defined range (`MIN_FAILURE_RATE` to `MAX_FAILURE_RATE`),
///   the function calculates the reduction from the linear reduction function.
fn rewards_reduction_percent(failure_rate: &Decimal) -> Decimal {
    if failure_rate < &MIN_FAILURE_RATE {
        logger().execute(
            &format!(
                "No Reduction applied because {} is less than {} failure rate.\n{}",
                failure_rate.round_dp(4),
                MIN_FAILURE_RATE,
                RF
            ),
            Operation::Set(dec!(0)),
        )
    } else if failure_rate > &MAX_FAILURE_RATE {
        logger().execute(
            &format!(
                "Max reduction applied because {} is over {} failure rate.\n{}",
                failure_rate.round_dp(4),
                MAX_FAILURE_RATE,
                RF
            ),
            Operation::Set(dec!(0.8)),
        )
    } else {
        let y_change = logger().execute(
            "Linear Reduction Y change",
            Operation::Subtract(*failure_rate, MIN_FAILURE_RATE),
        );
        let x_change = logger().execute(
            "Linear Reduction X change",
            Operation::Subtract(MAX_FAILURE_RATE, MIN_FAILURE_RATE),
        );

        let m = logger().execute("Compute m", Operation::Divide(y_change, x_change));

        logger().execute(RF, Operation::Multiply(m, dec!(0.8)))
    }
}

/// Assigned nodes multiplier
///
/// Computes the rewards multiplier for a single assigned node based on the overall failure rate in the period.
///
/// 1. The function iterates through each day's metrics, summing up the `daily_failed` and `daily_total` blocks across all days.
/// 2. The `overall_failure_rate` for the period is calculated by dividing the `overall_failed` blocks by the `overall_total` blocks.
/// 3. The `rewards_reduction` function is applied to `overall_failure_rate`.
/// 3. Finally, the rewards multiplier to be distributed to the node is computed.
pub fn assigned_nodes_multiplier(
    daily_metrics: &[DailyNodeMetrics],
    total_days: u64,
) -> (Decimal, MultiplierStats) {
    let total_days = Decimal::from(total_days);

    let days_assigned = logger().execute(
        "Assigned Days In Period",
        Operation::Set(Decimal::from(daily_metrics.len())),
    );
    let days_unassigned = logger().execute(
        "Unassigned Days In Period",
        Operation::Subtract(total_days, days_assigned),
    );

    let daily_failed = daily_metrics
        .iter()
        .map(|metrics| metrics.num_blocks_failed.into())
        .collect_vec();
    let daily_proposed = daily_metrics
        .iter()
        .map(|metrics| metrics.num_blocks_proposed.into())
        .collect_vec();

    let overall_failed = logger().execute(
        "Computing Total Failed Blocks",
        Operation::Sum(daily_failed),
    );
    let overall_proposed = logger().execute(
        "Computing Total Proposed Blocks",
        Operation::Sum(daily_proposed),
    );
    let overall_total = logger().execute(
        "Computing Total Blocks",
        Operation::Sum(vec![overall_failed, overall_proposed]),
    );
    let overall_failure_rate = logger().execute(
        "Computing Total Failure Rate",
        if overall_total > dec!(0) {
            Operation::Divide(overall_failed, overall_total)
        } else {
            Operation::Set(dec!(0))
        },
    );

    let rewards_reduction = rewards_reduction_percent(&overall_failure_rate);
    let rewards_multiplier_assigned = logger().execute(
        "Reward Multiplier Assigned Days",
        Operation::Subtract(dec!(1), rewards_reduction),
    );

    // On days when the node is not assigned to a subnet, it will receive the same `Reward Multiplier` as computed for the days it was assigned.
    let rewards_multiplier_unassigned = logger().execute(
        "Reward Multiplier Unassigned Days",
        Operation::Set(rewards_multiplier_assigned),
    );
    let assigned_days_factor = logger().execute(
        "Assigned Days Factor",
        Operation::Multiply(days_assigned, rewards_multiplier_assigned),
    );
    let unassigned_days_factor = logger().execute(
        "Unassigned Days Factor (currently equal to Assigned Days Factor)",
        Operation::Multiply(days_unassigned, rewards_multiplier_unassigned),
    );
    let rewards_multiplier = logger().execute(
        "Average reward multiplier",
        Operation::Divide(assigned_days_factor + unassigned_days_factor, total_days),
    );

    let rewards_multiplier_stats = MultiplierStats {
        days_assigned: days_assigned.to_u64().unwrap(),
        days_unassigned: days_unassigned.to_u64().unwrap(),
        rewards_reduction: rewards_reduction.to_f64().unwrap(),
        blocks_failed: overall_failed.to_u64().unwrap(),
        blocks_proposed: overall_proposed.to_u64().unwrap(),
        blocks_total: overall_total.to_u64().unwrap(),
        failure_rate: overall_failure_rate.to_f64().unwrap(),
    };

    (rewards_multiplier, rewards_multiplier_stats)
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
    rewardable_nodes: &AHashMap<RegionNodeTypeCategory, u32>,
    rewards_table: &NodeRewardsTable,
) -> AHashMap<RegionNodeTypeCategory, Decimal> {
    let mut type3_coefficients_rewards: AHashMap<
        RegionNodeTypeCategory,
        (Vec<Decimal>, Vec<Decimal>),
    > = AHashMap::default();
    let mut region_nodetype_rewards: AHashMap<RegionNodeTypeCategory, Decimal> =
        AHashMap::default();

    for ((region, node_type), node_count) in rewardable_nodes {
        let rate = match rewards_table.get_rate(region, node_type) {
            Some(rate) => rate,
            None => {
                logger().add_entry(LogEntry::RateNotFoundInRewardTable {
                    node_type: node_type.clone(),
                    region: region.clone(),
                });

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
            let region_key = region_type3_key(region.clone());

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

        logger().add_entry(LogEntry::RewardTableEntry {
            node_type: node_type.clone(),
            region: region.clone(),
            coeff,
            base_rewards,
        });
    }

    // Computes node rewards for type3* nodes in all regions and add it to region_nodetype_rewards
    for (key, (coefficients, rewards)) in type3_coefficients_rewards {
        let rewards_len = rewards.len();
        let mut running_coefficient = dec!(1);
        let mut region_rewards = Vec::new();

        let coefficients_avg = logger().execute("Coefficients avg.", Operation::Avg(coefficients));
        let rewards_avg = logger().execute("Rewards avg.", Operation::Avg(rewards));
        for _ in 0..rewards_len {
            region_rewards.push(Operation::Multiply(rewards_avg, running_coefficient));
            running_coefficient *= coefficients_avg;
        }
        let region_rewards = logger().execute(
            "Total rewards after coefficient reduction",
            Operation::SumOps(region_rewards),
        );
        let region_rewards_avg = logger().execute(
            "Rewards average after coefficient reduction",
            Operation::Divide(region_rewards, Decimal::from(rewards_len)),
        );

        logger().add_entry(LogEntry::AvgType3Rewards {
            region: key.0.clone(),
            rewards_avg,
            coefficients_avg,
            region_rewards_avg,
        });

        region_nodetype_rewards.insert(key, region_rewards_avg);
    }

    region_nodetype_rewards
}

fn node_provider_rewards(
    assigned_multipliers: &AHashMap<RegionNodeTypeCategory, Vec<Decimal>>,
    rewardable_nodes: &AHashMap<RegionNodeTypeCategory, u32>,
    rewards_table: &NodeRewardsTable,
) -> Rewards {
    let mut rewards_xdr_total = Vec::new();
    let mut rewards_xdr_no_penalty_total = Vec::new();
    let rewardable_nodes_count: u32 = rewardable_nodes.values().sum();

    let region_nodetype_rewards: AHashMap<RegionNodeTypeCategory, Decimal> =
        base_rewards_region_nodetype(rewardable_nodes, rewards_table);

    // Computes the rewards multiplier for unassigned nodes as the average of the multipliers of the assigned nodes.
    let assigned_multipliers_v = assigned_multipliers
        .values()
        .flatten()
        .cloned()
        .collect_vec();
    let unassigned_multiplier = logger().execute(
        "Unassigned Nodes Multiplier",
        Operation::Avg(assigned_multipliers_v),
    );
    logger().add_entry(LogEntry::UnassignedMultiplier(unassigned_multiplier));

    for ((region, node_type), node_count) in rewardable_nodes {
        let xdr_permyriad = if node_type.starts_with("type3") {
            let region_key = region_type3_key(region.clone());
            region_nodetype_rewards
                .get(&region_key)
                .expect("Type3 rewards already filled")
        } else {
            region_nodetype_rewards
                .get(&(region.clone(), node_type.clone()))
                .expect("Rewards already filled")
        };
        let rewards_xdr_no_penalty =
            Operation::Multiply(*xdr_permyriad, Decimal::from(*node_count));
        rewards_xdr_no_penalty_total.push(rewards_xdr_no_penalty.clone());

        // Node Providers with less than 4 machines are rewarded fully, independently of their performance
        if rewardable_nodes_count < FULL_REWARDS_MACHINES_LIMIT {
            logger().add_entry(LogEntry::NodeCountRewardables {
                node_type: node_type.clone(),
                region: region.clone(),
                count: *node_count as usize,
            });

            rewards_xdr_total.push(rewards_xdr_no_penalty);
        } else {
            let mut rewards_multipliers = assigned_multipliers
                .get(&(region.clone(), node_type.clone()))
                .cloned()
                .unwrap_or_default();
            let assigned_len = rewards_multipliers.len();

            rewards_multipliers.resize(*node_count as usize, unassigned_multiplier);

            logger().add_entry(LogEntry::PerformanceBasedRewardables {
                node_type: node_type.clone(),
                region: region.clone(),
                count: *node_count as usize,
                assigned_multipliers: rewards_multipliers[..assigned_len].to_vec(),
                unassigned_multipliers: rewards_multipliers[assigned_len..].to_vec(),
            });

            for multiplier in rewards_multipliers {
                rewards_xdr_total.push(Operation::Multiply(*xdr_permyriad, multiplier));
            }
        }
    }

    let rewards_xdr_total = logger().execute(
        "Compute total permyriad XDR",
        Operation::SumOps(rewards_xdr_total),
    );
    let rewards_xdr_no_reduction_total = logger().execute(
        "Compute total permyriad XDR no performance penalty",
        Operation::SumOps(rewards_xdr_no_penalty_total),
    );
    logger().add_entry(LogEntry::RewardsXDRTotal(rewards_xdr_total));

    Rewards {
        xdr_permyriad: rewards_xdr_total.to_u64().unwrap(),
        xdr_permyriad_no_reduction: rewards_xdr_no_reduction_total.to_u64().unwrap(),
    }
}

fn node_providers_rewardables(
    nodes: &[RewardableNode],
) -> AHashMap<PrincipalId, RewardablesWithNodesMetrics> {
    let mut node_provider_rewardables: AHashMap<PrincipalId, RewardablesWithNodesMetrics> =
        AHashMap::default();

    nodes.iter().for_each(|node| {
        let (rewardable_nodes, assigned_metrics) = node_provider_rewardables
            .entry(node.node_provider_id)
            .or_default();

        let nodes_count = rewardable_nodes
            .entry((node.region.clone(), node.node_type.clone()))
            .or_default();
        *nodes_count += 1;

        if let Some(daily_metrics) = &node.node_metrics {
            assigned_metrics.insert(node.clone(), daily_metrics.clone());
        }
    });

    node_provider_rewardables
}

pub fn calculate_rewards_v1(
    days_in_period: u64,
    rewards_table: &NodeRewardsTable,
    nodes_in_period: &[RewardableNode],
) -> RewardsPerNodeProvider {
    let mut rewards_per_node_provider = AHashMap::default();
    let mut rewards_log_per_node_provider = AHashMap::default();
    let node_provider_rewardables = node_providers_rewardables(nodes_in_period);

    for (node_provider_id, (rewardable_nodes, assigned_nodes_metrics)) in node_provider_rewardables
    {
        let mut assigned_multipliers: AHashMap<RegionNodeTypeCategory, Vec<Decimal>> =
            AHashMap::default();
        let mut nodes_multiplier_stats: Vec<NodeMultiplierStats> = Vec::new();
        let total_rewardable_nodes: u32 = rewardable_nodes.values().sum();

        logger().add_entry(LogEntry::RewardsForNodeProvider(
            node_provider_id,
            total_rewardable_nodes,
        ));

        for (node, daily_metrics) in assigned_nodes_metrics {
            let (multiplier, multiplier_stats) =
                assigned_nodes_multiplier(&daily_metrics, days_in_period);
            logger().add_entry(LogEntry::RewardMultiplierForNode(node.node_id, multiplier));
            nodes_multiplier_stats.push((node.node_id, multiplier_stats));
            assigned_multipliers
                .entry((node.region.clone(), node.node_type.clone()))
                .or_default()
                .push(multiplier);
        }

        let rewards =
            node_provider_rewards(&assigned_multipliers, &rewardable_nodes, rewards_table);
        let node_provider_log = mem::take(&mut *logger());

        rewards_log_per_node_provider.insert(node_provider_id, node_provider_log);
        rewards_per_node_provider.insert(node_provider_id, (rewards, nodes_multiplier_stats));
    }

    RewardsPerNodeProvider {
        rewards_per_node_provider,
        rewards_log_per_node_provider,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

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
        metrics
            .into_iter()
            .flat_map(|mocked_metrics: MockedMetrics| {
                (0..mocked_metrics.days).map(move |_| DailyNodeMetrics {
                    num_blocks_proposed: mocked_metrics.proposed_blocks,
                    num_blocks_failed: mocked_metrics.failed_blocks,
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

        rates_outer.insert("type0".to_string(), rate_outer);
        rates_outer.insert("type1".to_string(), rate_outer);
        rates_outer.insert("type3".to_string(), rate_outer);

        rates_inner.insert("type3.1".to_string(), rate_inner);

        table.insert("A,B,C".to_string(), NodeRewardRates { rates: rates_inner });
        table.insert("A,B".to_string(), NodeRewardRates { rates: rates_outer });

        NodeRewardsTable { table }
    }

    #[test]
    fn test_rewards_percent() {
        // Overall failed = 130 Overall total = 500 Failure rate = 0.26
        let daily_metrics: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            MockedMetrics::new(20, 6, 4),
            MockedMetrics::new(25, 10, 2),
        ]);
        let (result, _) = assigned_nodes_multiplier(&daily_metrics, daily_metrics.len() as u64);
        assert_eq!(result, dec!(0.744));

        // Overall failed = 45 Overall total = 450 Failure rate = 0.1
        // rewards_reduction = 0.0
        let daily_metrics: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            MockedMetrics::new(1, 400, 20),
            MockedMetrics::new(1, 5, 25), // no penalty
        ]);
        let (result, _) = assigned_nodes_multiplier(&daily_metrics, daily_metrics.len() as u64);
        assert_eq!(result, dec!(1.0));

        // Overall failed = 5 Overall total = 10 Failure rate = 0.5
        let daily_metrics: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            MockedMetrics::new(1, 5, 5), // no penalty
        ]);
        let (result, _) = assigned_nodes_multiplier(&daily_metrics, daily_metrics.len() as u64);
        assert_eq!(result, dec!(0.36));
    }

    #[test]
    fn test_rewards_percent_max_reduction() {
        let daily_metrics: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            MockedMetrics::new(10, 5, 95), // max failure rate
        ]);
        let (result, _) = assigned_nodes_multiplier(&daily_metrics, daily_metrics.len() as u64);
        assert_eq!(result, dec!(0.2));
    }

    #[test]
    fn test_rewards_percent_min_reduction() {
        let daily_metrics: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            MockedMetrics::new(10, 9, 1), // min failure rate
        ]);
        let (result, _) = assigned_nodes_multiplier(&daily_metrics, daily_metrics.len() as u64);
        assert_eq!(result, dec!(1.0));
    }

    #[test]
    fn test_same_rewards_percent_if_gaps_no_penalty() {
        let gap = MockedMetrics::new(1, 10, 0);
        let daily_metrics_mid_gap: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            MockedMetrics::new(1, 6, 4),
            gap.clone(),
            MockedMetrics::new(1, 7, 3),
        ]);
        let daily_metrics_left_gap: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            gap.clone(),
            MockedMetrics::new(1, 6, 4),
            MockedMetrics::new(1, 7, 3),
        ]);
        let daily_metrics_right_gap: Vec<DailyNodeMetrics> = daily_mocked_metrics(vec![
            gap.clone(),
            MockedMetrics::new(1, 6, 4),
            MockedMetrics::new(1, 7, 3),
        ]);

        assert_eq!(
            assigned_nodes_multiplier(&daily_metrics_mid_gap, daily_metrics_mid_gap.len() as u64).0,
            dec!(0.7866666666666666666666666667)
        );

        assert_eq!(
            assigned_nodes_multiplier(&daily_metrics_mid_gap, daily_metrics_mid_gap.len() as u64).0,
            assigned_nodes_multiplier(&daily_metrics_left_gap, daily_metrics_left_gap.len() as u64)
                .0
        );
        assert_eq!(
            assigned_nodes_multiplier(
                &daily_metrics_right_gap,
                daily_metrics_right_gap.len() as u64
            )
            .0,
            assigned_nodes_multiplier(&daily_metrics_left_gap, daily_metrics_left_gap.len() as u64)
                .0
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
        let result = assigned_nodes_multiplier(&daily_metrics, daily_metrics.len() as u64);
        daily_metrics.reverse();
        let result_rev = assigned_nodes_multiplier(&daily_metrics, daily_metrics.len() as u64);

        assert_eq!(result.0, dec!(1.0));
        assert_eq!(result_rev.0, result.0);
    }

    #[test]
    fn test_np_rewards_other_type() {
        let mut assigned_multipliers: AHashMap<RegionNodeTypeCategory, Vec<Decimal>> =
            AHashMap::default();
        let mut rewardable_nodes: AHashMap<RegionNodeTypeCategory, u32> = AHashMap::default();

        let region_node_type = ("A,B,C".to_string(), "type0".to_string());

        // 4 nodes in period: 2 assigned, 2 unassigned
        rewardable_nodes.insert(region_node_type.clone(), 4);
        assigned_multipliers.insert(region_node_type.clone(), vec![dec!(0.5), dec!(0.5)]);

        let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
        let rewards = node_provider_rewards(
            &assigned_multipliers,
            &rewardable_nodes,
            &node_rewards_table,
        );

        // Total XDR no penalties, operation=sum(1000,1000,1000,1000), result=4000
        assert_eq!(rewards.xdr_permyriad_no_reduction, 4000);

        // Total XDR, operation=sum(1000 * 0.5,1000 * 0.5,1000 * 0.5,1000 * 0.5), result=2000
        assert_eq!(rewards.xdr_permyriad, 2000);
    }

    #[test]
    fn test_np_rewards_type3_coeff() {
        let mut assigned_multipliers: AHashMap<RegionNodeTypeCategory, Vec<Decimal>> =
            AHashMap::default();
        let mut rewardable_nodes: AHashMap<RegionNodeTypeCategory, u32> = AHashMap::default();
        let region_node_type = ("A,B,C".to_string(), "type3.1".to_string());

        // 4 nodes in period: 1 assigned, 3 unassigned
        rewardable_nodes.insert(region_node_type.clone(), 4);
        assigned_multipliers.insert(region_node_type, vec![dec!(0.5)]);
        let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
        let rewards = node_provider_rewards(
            &assigned_multipliers,
            &rewardable_nodes,
            &node_rewards_table,
        );

        // Coefficients avg., operation=avg(0.95,0.95,0.95,0.95), result=0.95
        // Rewards avg., operation=avg(1500,1500,1500,1500), result=1500
        // Total rewards after coefficient reduction, operation=sum(1500 * 1,1500 * 0.95,1500 * 0.9025,1500 * 0.8574), result=5564

        // Rewards average after coefficient reduction, operation=5564 / 4, result=1391
        // Total XDR no penalties, operation=sum(1391,1391,1391,1391), result=5564
        assert_eq!(rewards.xdr_permyriad_no_reduction, 5564);

        // Total XDR, operation=sum(1391 * 0.5,1391 * 0.5,1391 * 0.5,1391 * 0.5), result=2782
        assert_eq!(rewards.xdr_permyriad, 2782);
    }

    #[test]
    fn test_np_rewards_type3_mix() {
        let mut assigned_multipliers: AHashMap<RegionNodeTypeCategory, Vec<Decimal>> =
            AHashMap::default();
        let mut rewardable_nodes: AHashMap<RegionNodeTypeCategory, u32> = AHashMap::default();

        // 5 nodes in period: 2 assigned, 3 unassigned
        assigned_multipliers.insert(
            ("A,B,D".to_string(), "type3".to_string()),
            vec![dec!(0.5), dec!(0.4)],
        );

        // This will take rates from outer
        rewardable_nodes.insert(("A,B,D".to_string(), "type3".to_string()), 3);

        // This will take rates from inner
        rewardable_nodes.insert(("A,B,C".to_string(), "type3.1".to_string()), 2);

        let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
        let rewards = node_provider_rewards(
            &assigned_multipliers,
            &rewardable_nodes,
            &node_rewards_table,
        );

        // Coefficients avg(0.95,0.95,0.97,0.97,0.97) = 0.9620
        // Rewards avg., operation=avg(1500,1500,1000,1000,1000), result=1200
        // Rewards average sum(1200 * 1,1200 * 0.9620,1200 * 0.9254,1200 * 0.8903,1200 * 0.8564) / 5, result=1112
        // Unassigned Nodes Multiplier, operation=avg(0.5,0.4), result=0.450

        // Total XDR, operation=sum(1112 * 0.450,1112 * 0.450,1112 * 0.5,1112 * 0.4,1112 * 0.450), result=2502
        assert_eq!(rewards.xdr_permyriad, 2502);
        // Total XDR no penalties, operation=1112 * 5, result=5561
        assert_eq!(rewards.xdr_permyriad_no_reduction, 5561);
    }
}
