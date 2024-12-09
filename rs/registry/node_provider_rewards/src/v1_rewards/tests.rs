use ic_protobuf::registry::node_rewards::v2::NodeRewardRates;
use num_traits::FromPrimitive;
use std::collections::BTreeMap;

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

impl DailyNodeMetrics {
    fn from_fr_dummy(ts: u64, subnet_assigned: PrincipalId, failure_rate: Decimal) -> Self {
        let num_blocks_proposed = 10;
        let num_blocks_failed = if failure_rate.is_zero() {
            0
        } else {
            let total_blocks =
                (failure_rate / (Decimal::ONE - failure_rate)) * Decimal::from(num_blocks_proposed);
            total_blocks.floor().to_u64().unwrap_or(0)
        };
        DailyNodeMetrics {
            ts,
            subnet_assigned,
            num_blocks_proposed,
            num_blocks_failed,
            failure_rate,
        }
    }
}

fn daily_mocked_failure_rates(metrics: Vec<MockedMetrics>) -> Vec<Decimal> {
    metrics
        .into_iter()
        .flat_map(|mocked_metrics: MockedMetrics| {
            (0..mocked_metrics.days).map(move |i| {
                DailyNodeMetrics::new(
                    i,
                    PrincipalId::new_anonymous(),
                    mocked_metrics.proposed_blocks,
                    mocked_metrics.failed_blocks,
                )
                .failure_rate
            })
        })
        .collect()
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
fn test_daily_node_metrics() {
    let subnet1 = PrincipalId::new_user_test_id(1);
    let subnet2 = PrincipalId::new_user_test_id(2);

    let node1 = PrincipalId::new_user_test_id(101);
    let node2 = PrincipalId::new_user_test_id(102);

    let sub1_day1 = NodeMetricsHistoryResponse {
        timestamp_nanos: 1,
        node_metrics: vec![
            NodeMetrics {
                node_id: node1,
                num_blocks_proposed_total: 10,
                num_block_failures_total: 2,
            },
            NodeMetrics {
                node_id: node2,
                num_blocks_proposed_total: 20,
                num_block_failures_total: 5,
            },
        ],
    };

    let sub1_day2 = NodeMetricsHistoryResponse {
        timestamp_nanos: 2,
        node_metrics: vec![
            NodeMetrics {
                node_id: node1,
                num_blocks_proposed_total: 20,
                num_block_failures_total: 12,
            },
            NodeMetrics {
                node_id: node2,
                num_blocks_proposed_total: 25,
                num_block_failures_total: 8,
            },
        ],
    };

    // This happens when the node gets redeployed
    let sub1_day3 = NodeMetricsHistoryResponse {
        timestamp_nanos: 3,
        node_metrics: vec![NodeMetrics {
            node_id: node1,
            num_blocks_proposed_total: 15,
            num_block_failures_total: 3,
        }],
    };

    // Simulating subnet change
    let sub2_day3 = NodeMetricsHistoryResponse {
        timestamp_nanos: 3,
        node_metrics: vec![NodeMetrics {
            node_id: node2,
            num_blocks_proposed_total: 35,
            num_block_failures_total: 10,
        }],
    };

    let input_metrics = HashMap::from([
        (subnet1, vec![sub1_day1, sub1_day2, sub1_day3]),
        (subnet2, vec![sub2_day3]),
    ]);

    let result = daily_node_metrics(input_metrics);

    let metrics_node1 = result.get(&node1).expect("Node1 metrics not found");
    assert_eq!(metrics_node1[0].subnet_assigned, subnet1);
    assert_eq!(metrics_node1[0].num_blocks_proposed, 10);
    assert_eq!(metrics_node1[0].num_blocks_failed, 2);

    assert_eq!(metrics_node1[1].subnet_assigned, subnet1);
    assert_eq!(metrics_node1[1].num_blocks_proposed, 10);
    assert_eq!(metrics_node1[1].num_blocks_failed, 10);

    assert_eq!(metrics_node1[2].subnet_assigned, subnet1);
    assert_eq!(metrics_node1[2].num_blocks_proposed, 15);
    assert_eq!(metrics_node1[2].num_blocks_failed, 3);

    let metrics_node2 = result.get(&node2).expect("Node2 metrics not found");
    assert_eq!(metrics_node2[0].subnet_assigned, subnet1);
    assert_eq!(metrics_node2[0].num_blocks_proposed, 20);
    assert_eq!(metrics_node2[0].num_blocks_failed, 5);

    assert_eq!(metrics_node2[1].subnet_assigned, subnet1);
    assert_eq!(metrics_node2[1].num_blocks_proposed, 5);
    assert_eq!(metrics_node2[1].num_blocks_failed, 3);

    assert_eq!(metrics_node2[2].subnet_assigned, subnet2);
    assert_eq!(metrics_node2[2].num_blocks_proposed, 10);
    assert_eq!(metrics_node2[2].num_blocks_failed, 2);
}
#[test]
fn test_rewards_percent() {
    let mut logger = RewardsLog::default();
    let daily_fr: Vec<Decimal> = daily_mocked_failure_rates(vec![
        // Avg. failure rate = 0.4
        MockedMetrics::new(20, 6, 4),
        // Avg. failure rate = 0.2
        MockedMetrics::new(20, 8, 2),
    ]);

    let result = assigned_multiplier(&mut logger, daily_fr);
    // Avg. failure rate = 0.3 -> 1 - (0.3-0.1) / (0.6-0.1) * 0.8 = 0.68
    assert_eq!(result, dec!(0.68));

    let daily_fr: Vec<Decimal> = daily_mocked_failure_rates(vec![
        // Avg. failure rate = 0.5
        MockedMetrics::new(1, 5, 5),
    ]);
    let result = assigned_multiplier(&mut logger, daily_fr);
    // Avg. failure rate = 0.5 -> 1 - (0.5-0.1) / (0.6-0.1) * 0.8 = 0.36
    assert_eq!(result, dec!(0.36));

    let daily_fr: Vec<Decimal> = daily_mocked_failure_rates(vec![
        // Avg. failure rate = 0.6666666667
        MockedMetrics::new(1, 200, 400),
        // Avg. failure rate = 0.8333333333
        MockedMetrics::new(1, 5, 25), // no penalty
    ]);
    let result = assigned_multiplier(&mut logger, daily_fr);
    // Avg. failure rate = (0.6666666667 + 0.8333333333) / 2 = 0.75
    // 1 - (0.75-0.1) / (0.6-0.1) * 0.8 = 0.2
    assert_eq!(result, dec!(0.2));
}

#[test]
fn test_rewards_percent_max_reduction() {
    let mut logger = RewardsLog::default();

    let daily_fr: Vec<Decimal> = daily_mocked_failure_rates(vec![
        // Avg. failure rate = 0.95
        MockedMetrics::new(10, 5, 95),
    ]);
    let result = assigned_multiplier(&mut logger, daily_fr);
    assert_eq!(result, dec!(0.2));
}

#[test]
fn test_rewards_percent_min_reduction() {
    let mut logger = RewardsLog::default();

    let daily_fr: Vec<Decimal> = daily_mocked_failure_rates(vec![
        // Avg. failure rate = 0.1
        MockedMetrics::new(10, 9, 1),
    ]);
    let result = assigned_multiplier(&mut logger, daily_fr);
    assert_eq!(result, dec!(1));
}

#[test]
fn test_same_rewards_percent_if_gaps_no_penalty() {
    let mut logger = RewardsLog::default();
    let gap = MockedMetrics::new(1, 10, 0);
    let daily_fr_mid_gap: Vec<Decimal> = daily_mocked_failure_rates(vec![
        MockedMetrics::new(1, 6, 4),
        gap.clone(),
        MockedMetrics::new(1, 7, 3),
    ]);
    let daily_fr_left_gap: Vec<Decimal> = daily_mocked_failure_rates(vec![
        gap.clone(),
        MockedMetrics::new(1, 6, 4),
        MockedMetrics::new(1, 7, 3),
    ]);
    let daily_fr_right_gap: Vec<Decimal> = daily_mocked_failure_rates(vec![
        gap.clone(),
        MockedMetrics::new(1, 6, 4),
        MockedMetrics::new(1, 7, 3),
    ]);

    assert_eq!(
        assigned_multiplier(&mut logger, daily_fr_mid_gap.clone()),
        dec!(0.7866666666666666666666666667)
    );

    assert_eq!(
        assigned_multiplier(&mut logger, daily_fr_mid_gap.clone()),
        assigned_multiplier(&mut logger, daily_fr_left_gap.clone())
    );
    assert_eq!(
        assigned_multiplier(&mut logger, daily_fr_right_gap.clone()),
        assigned_multiplier(&mut logger, daily_fr_left_gap)
    );
}

fn from_subnet_daily_metrics(
    subnet_id: PrincipalId,
    daily_subnet_fr: Vec<(TimestampNanos, Vec<f64>)>,
) -> HashMap<PrincipalId, Vec<DailyNodeMetrics>> {
    let mut daily_node_metrics = HashMap::new();
    for (day, fr) in daily_subnet_fr {
        fr.into_iter().enumerate().for_each(|(i, fr)| {
            let node_metrics: &mut Vec<DailyNodeMetrics> = daily_node_metrics
                .entry(PrincipalId::new_user_test_id(i as u64))
                .or_default();

            node_metrics.push(DailyNodeMetrics {
                ts: day,
                subnet_assigned: subnet_id,
                failure_rate: Decimal::from_f64(fr).unwrap(),
                ..DailyNodeMetrics::default()
            });
        });
    }
    daily_node_metrics
}
#[test]
fn test_systematic_fr_calculation() {
    let subnet1 = PrincipalId::new_user_test_id(10);

    let assigned_metrics = from_subnet_daily_metrics(
        subnet1,
        vec![
            (1, vec![0.2, 0.21, 0.1, 0.9, 0.3]), // Ordered: [0.1, 0.2, 0.21, * 0.3, 0.9]
            (2, vec![0.8, 0.9, 0.5, 0.6, 0.7]),  // Ordered: [0.5, 0.6, 0.7, * 0.8, 0.9]
            (3, vec![0.5, 0.6, 0.64, 0.8]),      // Ordered: [0.5, 0.6, * 0.64, 0.8]
            (4, vec![0.5, 0.6]),                 // Ordered: [0.5, * 0.6]
            (5, vec![0.2, 0.21, 0.1, 0.9, 0.3, 0.23]), // Ordered: [0.1, 0.2, 0.21, 0.23, * 0.3, 0.9]
        ],
    );

    let result = systematic_fr_per_subnet(&assigned_metrics);

    let expected: HashMap<(PrincipalId, TimestampNanos), Decimal> = HashMap::from([
        ((subnet1, 1), dec!(0.3)),
        ((subnet1, 2), dec!(0.8)),
        ((subnet1, 3), dec!(0.64)),
        ((subnet1, 4), dec!(0.6)),
        ((subnet1, 5), dec!(0.3)),
    ]);

    assert_eq!(result, expected);
}

#[test]
fn test_idiosyncratic_daily_fr_correct_values() {
    let node1 = PrincipalId::new_user_test_id(1);
    let node2 = PrincipalId::new_user_test_id(2);
    let subnet1 = PrincipalId::new_user_test_id(10);

    let assigned_metrics = HashMap::from([
        (
            node1,
            vec![
                DailyNodeMetrics::from_fr_dummy(1, subnet1, dec!(0.2)),
                DailyNodeMetrics::from_fr_dummy(2, subnet1, dec!(0.5)),
                DailyNodeMetrics::from_fr_dummy(3, subnet1, dec!(0.849)),
            ],
        ),
        (
            node2,
            vec![DailyNodeMetrics::from_fr_dummy(1, subnet1, dec!(0.5))],
        ),
    ]);

    let subnets_systematic_fr = HashMap::from([
        ((subnet1, 1), dec!(0.1)),
        ((subnet1, 2), dec!(0.2)),
        ((subnet1, 3), dec!(0.1)),
    ]);

    let result = idiosyncratic_daily_fr(&assigned_metrics, &subnets_systematic_fr);

    let expected = HashMap::from([
        (node1, vec![dec!(0.1), dec!(0.3), dec!(0.749)]), // (0.2 - 0.1), (0.5 - 0.2), (0.849 - 0.1)
        (node2, vec![dec!(0.4)]),                         // (0.5 - 0.1)
    ]);

    assert_eq!(result, expected);
}

#[test]
#[should_panic(expected = "Systematic failure rate not found")]
fn test_idiosyncratic_daily_fr_missing_systematic_fr() {
    let node1 = PrincipalId::new_user_test_id(1);
    let subnet1 = PrincipalId::new_user_test_id(10);

    let assigned_metrics = HashMap::from([(
        node1,
        vec![DailyNodeMetrics::from_fr_dummy(1, subnet1, dec!(0.2))],
    )]);

    let subnets_systematic_fr = HashMap::from([((subnet1, 2), dec!(0.1))]);

    idiosyncratic_daily_fr(&assigned_metrics, &subnets_systematic_fr);
}

#[test]
fn test_idiosyncratic_daily_fr_negative_failure_rate() {
    let node1 = PrincipalId::new_user_test_id(1);
    let subnet1 = PrincipalId::new_user_test_id(10);

    let assigned_metrics = HashMap::from([(
        node1,
        vec![DailyNodeMetrics::from_fr_dummy(1, subnet1, dec!(0.05))],
    )]);

    let subnets_systematic_fr = HashMap::from([((subnet1, 1), dec!(0.1))]);

    let result = idiosyncratic_daily_fr(&assigned_metrics, &subnets_systematic_fr);

    // Expecting zero due to saturation
    let expected = HashMap::from([(node1, vec![Decimal::ZERO])]);

    assert_eq!(result, expected);
}

#[test]
fn test_node_provider_rewards_no_nodes() {
    let mut logger = RewardsLog::default();
    let rewardables = vec![];
    let nodes_idiosyncratic_fr = HashMap::new();
    let days_in_period = 30;
    let rewards_table = NodeRewardsTable::default();

    let rewards = node_provider_rewards(
        &mut logger,
        &rewardables,
        nodes_idiosyncratic_fr,
        days_in_period,
        &rewards_table,
    );

    assert_eq!(rewards.xdr_permyriad, 0);
    assert_eq!(rewards.xdr_permyriad_no_reduction, 0);
}

#[test]
fn test_node_provider_below_min_limit() {
    let mut logger = RewardsLog::default();
    let node_provider_id = PrincipalId::new_anonymous();
    let rewardables = vec![
        RewardableNode {
            node_id: PrincipalId::new_user_test_id(1),
            node_provider_id,
            region: "region1".to_string(),
            node_type: "type1".to_string(),
        },
        RewardableNode {
            node_id: PrincipalId::new_user_test_id(2),
            node_provider_id,
            region: "region1".to_string(),
            node_type: "type3.1".to_string(),
        },
    ];
    let nodes_idiosyncratic_fr = HashMap::new();
    let days_in_period = 30;
    let rewards_table = NodeRewardsTable::default();

    let rewards = node_provider_rewards(
        &mut logger,
        &rewardables,
        nodes_idiosyncratic_fr,
        days_in_period,
        &rewards_table,
    );

    assert_eq!(rewards.xdr_permyriad, 2);
    assert_eq!(rewards.xdr_permyriad_no_reduction, 2);
}

fn helper_dummy_rewardables(node_id: PrincipalId, node_provider_id: PrincipalId) -> RewardableNode {
    RewardableNode {
        node_id,
        node_provider_id,
        region: "A,B".to_string(),
        node_type: "type1".to_string(),
    }
}

#[test]
fn test_node_provider_rewards_one_assigned() {
    let mut logger = RewardsLog::default();
    let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
    let days_in_period = 30;

    let rewardables = (1..=5)
        .map(|i| {
            helper_dummy_rewardables(
                PrincipalId::new_user_test_id(i),
                PrincipalId::new_anonymous(),
            )
        })
        .collect_vec();

    let mut nodes_idiosyncratic_fr = HashMap::new();
    nodes_idiosyncratic_fr.insert(
        PrincipalId::new_user_test_id(1),
        vec![dec!(0.4), dec!(0.2), dec!(0.3), dec!(0.4)], // Avg. 0.325
    );

    let rewards = node_provider_rewards(
        &mut logger,
        &rewardables,
        nodes_idiosyncratic_fr,
        days_in_period,
        &node_rewards_table,
    );

    // Unassigned failure rate: 0.325
    // Unassigned multiplier: 1 - (0.325-0.1) / (0.6-0.1) * 0.8 = 0.64 Rewards: 1000 * 0.64 = 640 XDRs
    // Total rewards: 640 * 5 = 3200 XDRs
    assert_eq!(rewards.xdr_permyriad, 3200);
    assert_eq!(rewards.xdr_permyriad_no_reduction, 5000);
}

#[test]
fn test_node_provider_rewards_two_assigned() {
    let mut logger = RewardsLog::default();
    let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
    let days_in_period = 30;

    let rewardables = (1..=5)
        .map(|i| {
            helper_dummy_rewardables(
                PrincipalId::new_user_test_id(i),
                PrincipalId::new_anonymous(),
            )
        })
        .collect_vec();

    let mut nodes_idiosyncratic_fr = HashMap::new();
    nodes_idiosyncratic_fr.insert(
        PrincipalId::new_user_test_id(1),
        vec![dec!(0.4), dec!(0.2), dec!(0.3), dec!(0.4)], // Avg. 0.325
    );
    nodes_idiosyncratic_fr.insert(
        PrincipalId::new_user_test_id(2),
        vec![dec!(0.9), dec!(0.6), dec!(0.304), dec!(0.102)], // Avg. 0.4765
    );

    let rewards = node_provider_rewards(
        &mut logger,
        &rewardables,
        nodes_idiosyncratic_fr,
        days_in_period,
        &node_rewards_table,
    );

    // Avg. assigned failure rate: (0.325 + 0.4765) / 2 = 0.40075
    // 3 nodes are unassigned in the period:
    // Unassigned failure rate: 0.40075
    // Unassigned multiplier: 1 - (0.40075-0.1) / (0.6-0.1) * 0.8 = 0.51880
    // Rewards: 1000 * 0.51880 = 518.80 XDRs
    // 2 nodes are assigned in the period:
    // node1:
    //  failure rate = (0.325 * 4 + 0.40075 * 26) / 30 = 0.390
    //  multiplier = 1 - (0.390-0.1) / (0.6-0.1) * 0.8 = 0.53496
    //  Rewards: 1000 * 0.53496 = 534.96 XDRs
    // node2:
    //  failure rate = (0.4765 * 4 + 0.40075 * 26) / 30 = 0.41
    //  multiplier = 1 - (0.41-0.1) / (0.6-0.1) * 0.8 = 0.50264
    //  Rewards: 1000 * 0.50264 = 502.64 XDRs
    // Total rewards: 518.80 * 3 + 534.96 + 502.64 = 2594 XDRs
    assert_eq!(rewards.xdr_permyriad, 2594);
    assert_eq!(rewards.xdr_permyriad_no_reduction, 5000);
}

// #[test]
// fn test_np_rewards_type3_coeff() {
//     let mut logger = RewardsLog::default();
//     let mut assigned_multipliers: HashMap<RegionNodeTypeCategory, Vec<Decimal>> =
//         HashMap::default();
//     let mut rewardable_nodes: HashMap<RegionNodeTypeCategory, u32> = HashMap::default();
//     let region_node_type = ("A,B,C".to_string(), "type3.1".to_string());
//
//     // 4 nodes in period: 1 assigned, 3 unassigned
//     rewardable_nodes.insert(region_node_type.clone(), 4);
//     assigned_multipliers.insert(region_node_type, vec![dec!(0.5)]);
//     let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
//     let rewards = node_provider_rewards(
//         &mut logger,
//         &assigned_multipliers,
//         &rewardable_nodes,
//         &node_rewards_table,
//     );
//
//     let rewardables = vec![RewardableNode {
//         node_id: PrincipalId::new_user_test_id(1),
//         node_provider_id: PrincipalId::new_user_test_id(2),
//         region: "A,B,C".to_string(),
//         node_type: "type3.1".to_string(),
//     }];
//     let mut assigned_metrics = HashMap::new();
//     assigned_metrics.insert(
//         PrincipalId::new_user_test_id(1),
//         vec![DailyNodeMetrics::new(
//             0,
//             PrincipalId::new_user_test_id(1),
//             10,
//             1,
//         )],
//     );
//     let subnets_systematic_fr = HashMap::new();
//     let days_in_period = 30;
//     let rewards_table = NodeRewardsTable::default();
//
//     let rewards = node_provider_rewards(
//         &mut logger,
//         &rewardables,
//         &assigned_metrics,
//         &subnets_systematic_fr,
//         days_in_period,
//         &rewards_table,
//     );
//
//     // Coefficients avg., operation=avg(0.95,0.95,0.95,0.95), result=0.95
//     // Rewards avg., operation=avg(1500,1500,1500,1500), result=1500
//     // Total rewards after coefficient reduction, operation=sum(1500 * 1,1500 * 0.95,1500 * 0.9025,1500 * 0.8574), result=5564
//
//     // Rewards average after coefficient reduction, operation=5564 / 4, result=1391
//     // Total XDR no penalties, operation=sum(1391,1391,1391,1391), result=5564
//     assert_eq!(rewards.xdr_permyriad_no_reduction, 5564);
//
//     // Total XDR, operation=sum(1391 * 0.5,1391 * 0.5,1391 * 0.5,1391 * 0.5), result=2782
//     assert_eq!(rewards.xdr_permyriad, 2782);
// }

// #[test]
// fn test_np_rewards_type3_coeff() {
//     let mut logger = RewardsLog::default();
//     let mut assigned_multipliers: HashMap<RegionNodeTypeCategory, Vec<Decimal>> =
//         HashMap::default();
//     let mut rewardable_nodes: HashMap<RegionNodeTypeCategory, u32> = HashMap::default();
//     let region_node_type = ("A,B,C".to_string(), "type3.1".to_string());
//
//     // 4 nodes in period: 1 assigned, 3 unassigned
//     rewardable_nodes.insert(region_node_type.clone(), 4);
//     assigned_multipliers.insert(region_node_type, vec![dec!(0.5)]);
//     let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
//     let rewards = node_provider_rewards(
//         &mut logger,
//         &assigned_multipliers,
//         &rewardable_nodes,
//         &node_rewards_table,
//     );
//
//     // Coefficients avg., operation=avg(0.95,0.95,0.95,0.95), result=0.95
//     // Rewards avg., operation=avg(1500,1500,1500,1500), result=1500
//     // Total rewards after coefficient reduction, operation=sum(1500 * 1,1500 * 0.95,1500 * 0.9025,1500 * 0.8574), result=5564
//
//     // Rewards average after coefficient reduction, operation=5564 / 4, result=1391
//     // Total XDR no penalties, operation=sum(1391,1391,1391,1391), result=5564
//     assert_eq!(rewards.xdr_permyriad_no_reduction, 5564);
//
//     // Total XDR, operation=sum(1391 * 0.5,1391 * 0.5,1391 * 0.5,1391 * 0.5), result=2782
//     assert_eq!(rewards.xdr_permyriad, 2782);
// }

// #[test]
// fn test_np_rewards_type3_mix() {
//     let mut logger = RewardsLog::default();
//     let mut assigned_multipliers: HashMap<RegionNodeTypeCategory, Vec<Decimal>> =
//         HashMap::default();
//     let mut rewardable_nodes: HashMap<RegionNodeTypeCategory, u32> = HashMap::default();
//
//     // 5 nodes in period: 2 assigned, 3 unassigned
//     assigned_multipliers.insert(
//         ("A,B,D".to_string(), "type3".to_string()),
//         vec![dec!(0.5), dec!(0.4)],
//     );
//
//     // This will take rates from outer
//     rewardable_nodes.insert(("A,B,D".to_string(), "type3".to_string()), 3);
//
//     // This will take rates from inner
//     rewardable_nodes.insert(("A,B,C".to_string(), "type3.1".to_string()), 2);
//
//     let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
//     let rewards = node_provider_rewards(
//         &mut logger,
//         &assigned_multipliers,
//         &rewardable_nodes,
//         &node_rewards_table,
//     );
//
//     // Coefficients avg(0.95,0.95,0.97,0.97,0.97) = 0.9620
//     // Rewards avg., operation=avg(1500,1500,1000,1000,1000), result=1200
//     // Rewards average sum(1200 * 1,1200 * 0.9620,1200 * 0.9254,1200 * 0.8903,1200 * 0.8564) / 5, result=1112
//     // Unassigned Nodes Multiplier, operation=avg(0.5,0.4), result=0.450
//
//     // Total XDR, operation=sum(1112 * 0.450,1112 * 0.450,1112 * 0.5,1112 * 0.4,1112 * 0.450), result=2502
//     assert_eq!(rewards.xdr_permyriad, 2502);
//     // Total XDR no penalties, operation=1112 * 5, result=5561
//     assert_eq!(rewards.xdr_permyriad_no_reduction, 5561);
// }
