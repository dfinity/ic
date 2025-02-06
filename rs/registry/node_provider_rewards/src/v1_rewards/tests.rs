use super::*;
use ic_protobuf::registry::node_rewards::v2::NodeRewardRates;
use num_traits::FromPrimitive;
use std::collections::BTreeMap;

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
    fn from_fr_dummy(ts: u64, subnet_assigned: SubnetId, failure_rate: Decimal) -> Self {
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
                    PrincipalId::new_anonymous().into(),
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
fn test_invalid_subnet_metric_error() {
    let from_ts: u64 = 1_000;
    let to_ts: u64 = 2_000;

    let rewarding_period = RewardingPeriod::new(from_ts, to_ts).unwrap();
    let subnet_id: SubnetId = PrincipalId::new_user_test_id(1).into();

    let invalid_metric = NodeMetricsHistoryResponse {
        timestamp_nanos: 500,
        node_metrics: vec![NodeMetrics::default()],
    };

    let mut subnet_metrics = HashMap::new();
    subnet_metrics.insert(subnet_id, vec![invalid_metric]);

    let rewards_table = NodeRewardsTable::default();
    let rewardable_nodes: Vec<RewardableNode> = vec![];

    let result = calculate_rewards(
        rewarding_period,
        &rewards_table,
        subnet_metrics,
        &rewardable_nodes,
    );
    assert_eq!(
        result,
        Err(RewardCalculationError::InvalidSubnetMetric {
            subnet_id,
            timestamp: 500,
            from_ts,
            to_ts
        })
    );
}
#[test]
fn test_daily_node_metrics() {
    let subnet1: SubnetId = PrincipalId::new_user_test_id(1).into();
    let subnet2: SubnetId = PrincipalId::new_user_test_id(2).into();

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

    let result = metrics_in_rewarding_period(input_metrics);

    let metrics_node1 = result.get(&node1.into()).expect("Node1 metrics not found");
    assert_eq!(metrics_node1[0].subnet_assigned, subnet1);
    assert_eq!(metrics_node1[0].num_blocks_proposed, 10);
    assert_eq!(metrics_node1[0].num_blocks_failed, 2);

    assert_eq!(metrics_node1[1].subnet_assigned, subnet1);
    assert_eq!(metrics_node1[1].num_blocks_proposed, 10);
    assert_eq!(metrics_node1[1].num_blocks_failed, 10);

    assert_eq!(metrics_node1[2].subnet_assigned, subnet1);
    assert_eq!(metrics_node1[2].num_blocks_proposed, 15);
    assert_eq!(metrics_node1[2].num_blocks_failed, 3);

    let metrics_node2 = result.get(&node2.into()).expect("Node2 metrics not found");
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
    subnet_id: SubnetId,
    daily_subnet_fr: Vec<(TimestampNanos, Vec<f64>)>,
) -> HashMap<NodeId, Vec<DailyNodeMetrics>> {
    let mut daily_node_metrics = HashMap::new();
    for (day, fr) in daily_subnet_fr {
        fr.into_iter().enumerate().for_each(|(i, fr)| {
            let node_metrics: &mut Vec<DailyNodeMetrics> = daily_node_metrics
                .entry(NodeId::from(PrincipalId::new_user_test_id(i as u64)))
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
    let subnet1 = SubnetId::new(PrincipalId::new_user_test_id(1));

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

    let expected: HashMap<(SubnetId, TimestampNanos), Decimal> = HashMap::from([
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
    let mut logger = RewardsLog::default();
    let node1 = NodeId::from(PrincipalId::new_user_test_id(1));
    let node2 = NodeId::from(PrincipalId::new_user_test_id(2));
    let subnet1 = SubnetId::from(PrincipalId::new_user_test_id(10));

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

    let result =
        compute_relative_node_failure_rate(&mut logger, &assigned_metrics, &subnets_systematic_fr);

    let expected = HashMap::from([
        (node1, vec![dec!(0.1), dec!(0.3), dec!(0.749)]), // (0.2 - 0.1), (0.5 - 0.2), (0.849 - 0.1)
        (node2, vec![dec!(0.4)]),                         // (0.5 - 0.1)
    ]);

    assert_eq!(result, expected);
}

#[test]
#[should_panic(expected = "Systematic failure rate not found")]
fn test_idiosyncratic_daily_fr_missing_systematic_fr() {
    let mut logger = RewardsLog::default();
    let node1: NodeId = PrincipalId::new_user_test_id(1).into();
    let subnet1: SubnetId = PrincipalId::new_user_test_id(10).into();

    let assigned_metrics = HashMap::from([(
        node1,
        vec![DailyNodeMetrics::from_fr_dummy(1, subnet1, dec!(0.2))],
    )]);

    let subnets_systematic_fr = HashMap::from([((subnet1, 2), dec!(0.1))]);

    compute_relative_node_failure_rate(&mut logger, &assigned_metrics, &subnets_systematic_fr);
}

#[test]
fn test_idiosyncratic_daily_fr_negative_failure_rate() {
    let mut logger = RewardsLog::default();
    let node1: NodeId = PrincipalId::new_user_test_id(1).into();
    let subnet1: SubnetId = PrincipalId::new_user_test_id(10).into();

    let assigned_metrics = HashMap::from([(
        node1,
        vec![DailyNodeMetrics::from_fr_dummy(1, subnet1, dec!(0.05))],
    )]);

    let subnets_systematic_fr = HashMap::from([((subnet1, 1), dec!(0.1))]);

    let result =
        compute_relative_node_failure_rate(&mut logger, &assigned_metrics, &subnets_systematic_fr);

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
            node_id: PrincipalId::new_user_test_id(1).into(),
            node_provider_id,
            region: "region1".to_string(),
            node_type: "type1".to_string(),
        },
        RewardableNode {
            node_id: PrincipalId::new_user_test_id(2).into(),
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

#[test]
fn test_node_provider_rewards_one_assigned() {
    let mut logger = RewardsLog::default();
    let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
    let days_in_period = 30;

    let rewardables = (1..=5)
        .map(|i| RewardableNode {
            node_id: PrincipalId::new_user_test_id(i).into(),
            node_provider_id: PrincipalId::new_anonymous(),
            region: "A,B".to_string(),
            node_type: "type1".to_string(),
        })
        .collect_vec();

    let mut nodes_idiosyncratic_fr: HashMap<NodeId, Vec<Decimal>> = HashMap::new();
    nodes_idiosyncratic_fr.insert(
        PrincipalId::new_user_test_id(1).into(),
        vec![dec!(0.4), dec!(0.2), dec!(0.3), dec!(0.4)], // Avg. 0.325
    );

    let rewards = node_provider_rewards(
        &mut logger,
        &rewardables,
        nodes_idiosyncratic_fr,
        days_in_period,
        &node_rewards_table,
    );

    // Compute Base Rewards For RegionNodeType
    //     - node_type: type1, region: A,B, coeff: 1, base_rewards: 1000, node_count: 5
    // Compute Unassigned Days Failure Rate
    //     - Avg. failure rate for node: 6fyp7-3ibaa-aaaaa-aaaap-4ai: avg(0.4,0.2,0.3,0.4) = 0.325
    //     - Unassigned days failure rate:: avg(0.325) = 0.325
    //     - Rewards reduction percent: (0.325 - 0.1) / (0.6 - 0.1) * 0.8 = 0.360
    //     - Reward multiplier fully unassigned nodes:: 1 - 0.360 = 0.640
    // Compute Rewards For Node | node_id=6fyp7-3ibaa-aaaaa-aaaap-4ai, node_type=type1, region=A,B
    //     - Base rewards XDRs: 1000
    //     - Node status: Assigned
    //     - Idiosyncratic daily failure rates : 0.4,0.2,0.3,0.4,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325
    //     - Failure rate average: avg(0.4,0.2,0.3,0.4,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325) = 0.325
    //     - Rewards reduction percent: (0.325 - 0.1) / (0.6 - 0.1) * 0.8 = 0.360
    //     - Reward Multiplier: 1 - 0.360 = 0.640
    //     - Rewards XDR for the node: 1000 * 0.640 = 640.000
    // Compute Rewards For Node | node_id=djduj-3qcaa-aaaaa-aaaap-4ai, node_type=type1, region=A,B
    //     - Base rewards XDRs: 1000
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1000 * 0.640 = 640.000
    // Compute Rewards For Node | node_id=6wcs7-uadaa-aaaaa-aaaap-4ai, node_type=type1, region=A,B
    //     - Base rewards XDRs: 1000
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1000 * 0.640 = 640.000
    // Compute Rewards For Node | node_id=c5mtj-kieaa-aaaaa-aaaap-4ai, node_type=type1, region=A,B
    //     - Base rewards XDRs: 1000
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1000 * 0.640 = 640.000
    // Compute Rewards For Node | node_id=7cnv7-fyfaa-aaaaa-aaaap-4ai, node_type=type1, region=A,B
    //     - Base rewards XDRs: 1000
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1000 * 0.640 = 640.000
    //     - Compute total permyriad XDR: sum(640.000,640.000,640.000,640.000,640.000) = 3200.000
    //     - Compute total permyriad XDR no performance penalty: sum(1000,1000,1000,1000,1000) = 5000
    // Total rewards XDR permyriad: 3200.000
    // Total rewards XDR permyriad not adjusted: 5000
    assert_eq!(rewards.xdr_permyriad, 3200);
    assert_eq!(rewards.xdr_permyriad_no_reduction, 5000);
}

#[test]
fn test_node_provider_rewards_two_assigned() {
    let mut logger = RewardsLog::default();
    let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
    let days_in_period = 30;

    let rewardables = (1..=5)
        .map(|i| RewardableNode {
            node_id: PrincipalId::new_user_test_id(i).into(),
            node_provider_id: PrincipalId::new_anonymous(),
            region: "A,B".to_string(),
            node_type: "type1".to_string(),
        })
        .collect_vec();

    let mut nodes_idiosyncratic_fr: HashMap<NodeId, Vec<Decimal>> = HashMap::new();
    nodes_idiosyncratic_fr.insert(
        PrincipalId::new_user_test_id(1).into(),
        vec![dec!(0.4), dec!(0.2), dec!(0.3), dec!(0.4)], // Avg. 0.325
    );
    nodes_idiosyncratic_fr.insert(
        PrincipalId::new_user_test_id(2).into(),
        vec![dec!(0.9), dec!(0.6), dec!(0.304), dec!(0.102)], // Avg. 0.4765
    );

    let rewards = node_provider_rewards(
        &mut logger,
        &rewardables,
        nodes_idiosyncratic_fr,
        days_in_period,
        &node_rewards_table,
    );

    // Compute Base Rewards For RegionNodeType
    //     - node_type: type1, region: A,B, coeff: 1, base_rewards: 1000, node_count: 5
    // Compute Unassigned Days Failure Rate
    //     - Avg. failure rate for node: 6fyp7-3ibaa-aaaaa-aaaap-4ai: avg(0.4,0.2,0.3,0.4) = 0.325
    //     - Avg. failure rate for node: djduj-3qcaa-aaaaa-aaaap-4ai: avg(0.9,0.6,0.304,0.102) = 0.4765
    //     - Unassigned days failure rate:: avg(0.325,0.4765) = 0.4008
    //     - Rewards reduction percent: (0.4008 - 0.1) / (0.6 - 0.1) * 0.8 = 0.4812
    //     - Reward multiplier fully unassigned nodes:: 1 - 0.4812 = 0.5188
    // Compute Rewards For Node | node_id=6fyp7-3ibaa-aaaaa-aaaap-4ai, node_type=type1, region=A,B
    //     - Base rewards XDRs: 1000
    //     - Node status: Assigned
    //     - Idiosyncratic daily failure rates : 0.4,0.2,0.3,0.4,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075
    //     - Failure rate average: avg(0.4,0.2,0.3,0.4,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008) = 0.3906
    //     - Rewards reduction percent: (0.3906 - 0.1) / (0.6 - 0.1) * 0.8 = 0.4650
    //     - Reward Multiplier: 1 - 0.4650 = 0.5350
    //     - Rewards XDR for the node: 1000 * 0.5350 = 534.9600
    // Compute Rewards For Node | node_id=djduj-3qcaa-aaaaa-aaaap-4ai, node_type=type1, region=A,B
    //     - Base rewards XDRs: 1000
    //     - Node status: Assigned
    //     - Idiosyncratic daily failure rates : 0.9,0.6,0.304,0.102,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075,0.40075
    //     - Failure rate average: avg(0.9,0.6,0.304,0.102,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008,0.4008) = 0.4108
    //     - Rewards reduction percent: (0.4108 - 0.1) / (0.6 - 0.1) * 0.8 = 0.4974
    //     - Reward Multiplier: 1 - 0.4974 = 0.5026
    //     - Rewards XDR for the node: 1000 * 0.5026 = 502.6400
    // Compute Rewards For Node | node_id=6wcs7-uadaa-aaaaa-aaaap-4ai, node_type=type1, region=A,B
    //     - Base rewards XDRs: 1000
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1000 * 0.5188 = 518.8000
    // Compute Rewards For Node | node_id=c5mtj-kieaa-aaaaa-aaaap-4ai, node_type=type1, region=A,B
    //     - Base rewards XDRs: 1000
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1000 * 0.5188 = 518.8000
    // Compute Rewards For Node | node_id=7cnv7-fyfaa-aaaaa-aaaap-4ai, node_type=type1, region=A,B
    //     - Base rewards XDRs: 1000
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1000 * 0.5188 = 518.8000
    //     - Compute total permyriad XDR: sum(534.9600,502.6400,518.8000,518.8000,518.8000) = 2594.0000
    //     - Compute total permyriad XDR no performance penalty: sum(1000,1000,1000,1000,1000) = 5000
    // Total rewards XDR permyriad: 2594.0000
    // Total rewards XDR permyriad not adjusted: 5000

    assert_eq!(rewards.xdr_permyriad, 2594);
    assert_eq!(rewards.xdr_permyriad_no_reduction, 5000);
}

#[test]
fn test_np_rewards_type3_coeff() {
    let mut logger = RewardsLog::default();
    let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
    let days_in_period = 30;

    // 4 nodes in period: 1 assigned, 3 unassigned
    let rewardables = (1..=4)
        .map(|i| RewardableNode {
            node_id: PrincipalId::new_user_test_id(i).into(),
            node_provider_id: PrincipalId::new_anonymous(),
            region: "A,B,C".to_string(),
            node_type: "type3.1".to_string(),
        })
        .collect_vec();
    let mut nodes_idiosyncratic_fr: HashMap<NodeId, Vec<Decimal>> = HashMap::new();
    nodes_idiosyncratic_fr.insert(
        PrincipalId::new_user_test_id(1).into(),
        vec![dec!(0.4), dec!(0.2), dec!(0.3), dec!(0.4)], // Avg. 0.325
    );

    let rewards = node_provider_rewards(
        &mut logger,
        &rewardables,
        nodes_idiosyncratic_fr,
        days_in_period,
        &node_rewards_table,
    );

    // Compute Base Rewards For RegionNodeType
    //     - node_type: type3.1, region: A,B,C, coeff: 0.95, base_rewards: 1500, node_count: 4
    //     - Coefficients avg.: avg(0.95,0.95,0.95,0.95) = 0.95
    //     - Rewards avg.: avg(1500,1500,1500,1500) = 1500
    //     - Total rewards after coefficient reduction: sum(1500 * 1,1500 * 0.95,1500 * 0.9025,1500 * 0.8574) = 5564.8125
    //     - Rewards average after coefficient reduction: 5564.8125 / 4 = 1391.2031
    // Compute Unassigned Days Failure Rate
    //     - Avg. failure rate for node: 6fyp7-3ibaa-aaaaa-aaaap-4ai: avg(0.4,0.2,0.3,0.4) = 0.325
    //     - Unassigned days failure rate:: avg(0.325) = 0.325
    //     - Rewards reduction percent: (0.325 - 0.1) / (0.6 - 0.1) * 0.8 = 0.360
    //     - Reward multiplier fully unassigned nodes:: 1 - 0.360 = 0.640
    // Compute Rewards For Node | node_id=6fyp7-3ibaa-aaaaa-aaaap-4ai, node_type=type3.1, region=A,B,C
    //     - Base rewards XDRs: 1391.2031
    //     - Node status: Assigned
    //     - Idiosyncratic daily failure rates : 0.4,0.2,0.3,0.4,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325
    //     - Failure rate average: avg(0.4,0.2,0.3,0.4,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325,0.325) = 0.325
    //     - Rewards reduction percent: (0.325 - 0.1) / (0.6 - 0.1) * 0.8 = 0.360
    //     - Reward Multiplier: 1 - 0.360 = 0.640
    //     - Rewards XDR for the node: 1391.2031 * 0.640 = 890.3700
    // Compute Rewards For Node | node_id=djduj-3qcaa-aaaaa-aaaap-4ai, node_type=type3.1, region=A,B,C
    //     - Base rewards XDRs: 1391.2031
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1391.2031 * 0.640 = 890.3700
    // Compute Rewards For Node | node_id=6wcs7-uadaa-aaaaa-aaaap-4ai, node_type=type3.1, region=A,B,C
    //     - Base rewards XDRs: 1391.2031
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1391.2031 * 0.640 = 890.3700
    // Compute Rewards For Node | node_id=c5mtj-kieaa-aaaaa-aaaap-4ai, node_type=type3.1, region=A,B,C
    //     - Base rewards XDRs: 1391.2031
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1391.2031 * 0.640 = 890.3700
    //     - Compute total permyriad XDR: sum(890.3700,890.3700,890.3700,890.3700) = 3561.4800
    //     - Compute total permyriad XDR no performance penalty: sum(1391.2031,1391.2031,1391.2031,1391.2031) = 5564.8125
    // Total rewards XDR permyriad: 3561.4800
    // Total rewards XDR permyriad not adjusted: 5564.8125

    assert_eq!(rewards.xdr_permyriad, 3561);
    assert_eq!(rewards.xdr_permyriad_no_reduction, 5564);
}

#[test]
fn test_np_rewards_type3_mix() {
    let mut logger = RewardsLog::default();
    let node_rewards_table: NodeRewardsTable = mocked_rewards_table();
    let days_in_period = 30;

    // 4 nodes in period: 1 assigned, 3 unassigned
    let mut rewardables = (1..=3)
        .map(|i| RewardableNode {
            node_id: PrincipalId::new_user_test_id(i).into(),
            node_provider_id: PrincipalId::new_anonymous(),
            region: "A,B,C".to_string(),
            node_type: "type3.1".to_string(),
        })
        .collect_vec();

    rewardables.push(RewardableNode {
        node_id: PrincipalId::new_user_test_id(4).into(),
        node_provider_id: PrincipalId::new_anonymous(),
        region: "A,B,D".to_string(),
        node_type: "type3".to_string(),
    });

    let mut nodes_idiosyncratic_fr: HashMap<NodeId, Vec<Decimal>> = HashMap::new();
    nodes_idiosyncratic_fr.insert(
        PrincipalId::new_user_test_id(3).into(),
        vec![dec!(0.1), dec!(0.12), dec!(0.23), dec!(0.12)],
    );
    nodes_idiosyncratic_fr.insert(
        PrincipalId::new_user_test_id(4).into(),
        vec![dec!(0.2), dec!(0.32), dec!(0.123), dec!(0.432)],
    );

    let rewards = node_provider_rewards(
        &mut logger,
        &rewardables,
        nodes_idiosyncratic_fr,
        days_in_period,
        &node_rewards_table,
    );

    // Compute Base Rewards For RegionNodeType
    //     - node_type: type3, region: A,B,D, coeff: 0.97, base_rewards: 1000, node_count: 1
    //     - node_type: type3.1, region: A,B,C, coeff: 0.95, base_rewards: 1500, node_count: 3
    //     - Coefficients avg.: avg(0.97,0.95,0.95,0.95) = 0.9550
    //     - Rewards avg.: avg(1000,1500,1500,1500) = 1375
    //     - Total rewards after coefficient reduction: sum(1375 * 1,1375 * 0.9550,1375 * 0.9120,1375 * 0.8710) = 5139.7622
    //     - Rewards average after coefficient reduction: 5139.7622 / 4 = 1284.9406
    // Compute Unassigned Days Failure Rate
    //     - Avg. failure rate for node: 6wcs7-uadaa-aaaaa-aaaap-4ai: avg(0.1,0.12,0.23,0.12) = 0.1425
    //     - Avg. failure rate for node: c5mtj-kieaa-aaaaa-aaaap-4ai: avg(0.2,0.32,0.123,0.432) = 0.2688
    //     - Unassigned days failure rate:: avg(0.1425,0.2688) = 0.2056
    //     - Rewards reduction percent: (0.2056 - 0.1) / (0.6 - 0.1) * 0.8 = 0.1690
    //     - Reward multiplier fully unassigned nodes:: 1 - 0.1690 = 0.8310
    // Compute Rewards For Node | node_id=6fyp7-3ibaa-aaaaa-aaaap-4ai, node_type=type3.1, region=A,B,C
    //     - Base rewards XDRs: 1284.9406
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1284.9406 * 0.8310 = 1067.7856
    // Compute Rewards For Node | node_id=djduj-3qcaa-aaaaa-aaaap-4ai, node_type=type3.1, region=A,B,C
    //     - Base rewards XDRs: 1284.9406
    //     - Node status: Unassigned
    //     - Rewards XDR for the node: 1284.9406 * 0.8310 = 1067.7856
    // Compute Rewards For Node | node_id=6wcs7-uadaa-aaaaa-aaaap-4ai, node_type=type3.1, region=A,B,C
    //     - Base rewards XDRs: 1284.9406
    //     - Node status: Assigned
    //     - Idiosyncratic daily failure rates : 0.1,0.12,0.23,0.12,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250
    //     - Failure rate average: avg(0.1,0.12,0.23,0.12,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056) = 0.1972
    //     - Rewards reduction percent: (0.1972 - 0.1) / (0.6 - 0.1) * 0.8 = 0.1555
    //     - Reward Multiplier: 1 - 0.1555 = 0.8445
    //     - Rewards XDR for the node: 1284.9406 * 0.8445 = 1085.0895
    // Compute Rewards For Node | node_id=c5mtj-kieaa-aaaaa-aaaap-4ai, node_type=type3, region=A,B,D
    //     - Base rewards XDRs: 1284.9406
    //     - Node status: Assigned
    //     - Idiosyncratic daily failure rates : 0.2,0.32,0.123,0.432,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250,0.2056250
    //     - Failure rate average: avg(0.2,0.32,0.123,0.432,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056,0.2056) = 0.2140
    //     - Rewards reduction percent: (0.2140 - 0.1) / (0.6 - 0.1) * 0.8 = 0.1825
    //     - Reward Multiplier: 1 - 0.1825 = 0.8175
    //     - Rewards XDR for the node: 1284.9406 * 0.8175 = 1050.4817
    //     - Compute total permyriad XDR: sum(1067.7856,1067.7856,1085.0895,1050.4817) = 4271.1424
    //     - Compute total permyriad XDR no performance penalty: sum(1284.9406,1284.9406,1284.9406,1284.9406) = 5139.7622
    // Total rewards XDR permyriad: 4271.1424
    // Total rewards XDR permyriad not adjusted: 5139.7622

    assert_eq!(rewards.xdr_permyriad, 4271);
    assert_eq!(rewards.xdr_permyriad_no_reduction, 5139);
}
