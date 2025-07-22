use super::*;
use crate::types::RewardableNode;
use chrono::{DateTime, NaiveDateTime, Utc};
use ic_base_types::PrincipalId;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates};
use maplit::btreemap;

// --- Test Helpers ---
fn test_node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

fn test_provider_id(id: u64) -> PrincipalId {
    PrincipalId::new_user_test_id(id)
}

fn test_subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}

impl From<&str> for DayUTC {
    fn from(dmy: &str) -> Self {
        let dt = format!("{} 00:00:00", dmy);
        let naive =
            NaiveDateTime::parse_from_str(&dt, "%Y-%m-%d %H:%M:%S").expect("Invalid date format");
        let datetime: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);
        let ts = datetime.timestamp_nanos_opt().unwrap() as u64;

        DayUTC::from(ts)
    }
}

impl Default for RewardableNode {
    fn default() -> Self {
        RewardableNode {
            node_id: NodeId::from(PrincipalId::new_node_test_id(0)),
            rewardable_days: vec![],
            region: Region::default(),
            node_reward_type: NodeRewardType::default(),
            dc_id: "default_dc".into(),
        }
    }
}

fn default_test_input() -> RewardsCalculatorInput {
    RewardsCalculatorInput {
        reward_period: RewardPeriod {
            from: "2024-01-01".into(),
            to: "2024-01-02".into(),
        },
        rewards_table: NodeRewardsTable {
            table: BTreeMap::new(),
        },
        daily_metrics_by_subnet: HashMap::new(),
        provider_rewardable_nodes: btreemap![],
    }
}

fn build_daily_metrics(
    subnet_id: SubnetId,
    day: DayUTC,
    nodes_data: &[(NodeId, u64, u64)],
) -> (SubnetMetricsDailyKey, Vec<NodeMetricsDailyRaw>) {
    let key = SubnetMetricsDailyKey { subnet_id, day };
    let metrics = nodes_data
        .iter()
        .map(|(node_id, proposed, failed)| NodeMetricsDailyRaw {
            node_id: *node_id,
            num_blocks_proposed: *proposed,
            num_blocks_failed: *failed,
        })
        .collect();
    (key, metrics)
}

fn generate_rewardable_nodes(
    nodes_with_rewardable_days: Vec<(NodeId, Vec<DayUTC>)>,
) -> Vec<RewardableNode> {
    nodes_with_rewardable_days
        .into_iter()
        .map(|(node_id, rewardable_days)| RewardableNode {
            node_id,
            rewardable_days,
            ..Default::default()
        })
        .collect()
}

#[test]
fn test_compute_subnets_nodes_fr() {
    let mut input = default_test_input();
    let day1 = "2024-01-01".into();
    let day2 = "2024-01-02".into();
    let subnet1 = test_subnet_id(1);
    let subnet2 = test_subnet_id(2);

    // Nodes for Subnet 1
    let s1_node1 = test_node_id(11);
    let s1_node2 = test_node_id(12);
    let s1_node3 = test_node_id(13);
    let s1_node4 = test_node_id(14);

    // Nodes for Subnet 2
    let s2_node1 = test_node_id(21);
    let s2_node2 = test_node_id(22);

    let p1 = test_provider_id(1);
    let p2 = test_provider_id(2);

    input.provider_rewardable_nodes = btreemap! {
        p1 => generate_rewardable_nodes( vec![
            (s1_node1, vec![day1, day2]),
            (s1_node2, vec![day1]),
            (s1_node3, vec![day1]),
            (s2_node2, vec![day1]),
        ]),
        p2 => generate_rewardable_nodes( vec![
            (s1_node4, vec![day1, day2]),
            (s2_node1, vec![day1]),
        ]),
    };

    // --- Data Setup ---
    input.daily_metrics_by_subnet.extend(vec![
        // Day 1, Subnet 1
        build_daily_metrics(
            subnet1,
            day1,
            &[
                (s1_node1, 75, 25), // FR = 0.25
                (s1_node2, 90, 10), // FR = 0.10
                (s1_node3, 95, 5),  // FR = 0.05
                (s1_node4, 50, 50), // FR = 0.50
            ],
        ),
        // Day 1, Subnet 2
        build_daily_metrics(
            subnet2,
            day1,
            &[
                (s2_node1, 80, 20), // FR = 0.20
                (s2_node2, 60, 40), // FR = 0.40
            ],
        ),
        // Day 2, Subnet 1
        build_daily_metrics(
            subnet1,
            day2,
            &[
                (s1_node1, 99, 1),  // FR = 0.01
                (s1_node2, 90, 10), // FR = 0.10
            ],
        ),
    ]);

    // --- Execution ---
    let pipeline = RewardsCalculatorPipeline::<Initialized> {
        input,
        intermediate_results: IntermediateResults::default(),
        _marker: PhantomData,
    }
    .next();
    let result = pipeline.next();
    let subnets_fr = result.intermediate_results.subnets_fr;
    let original_nodes_fr = result.intermediate_results.original_nodes_fr;
    let relative_nodes_fr = result.intermediate_results.relative_nodes_fr;

    // --- Assertions for Day 1, Subnet 1 ---
    // Sorted FRs: 0.05, 0.10, 0.25, 0.50
    // 75th percentile index = ceil(4 * 0.75) - 1 = 2. Value is 0.25
    let expected_subnet1_day1_fr = dec!(0.25);
    assert_eq!(
        subnets_fr.get(&(day1, subnet1)),
        Some(&expected_subnet1_day1_fr)
    );
    assert_eq!(original_nodes_fr.get(&(day1, s1_node1)), Some(&dec!(0.25)));
    // Relative FR = max(0, original - subnet_fr)
    assert_eq!(relative_nodes_fr.get(&(day1, s1_node1)), Some(&dec!(0.0))); // 0.25 - 0.25 = 0
    assert_eq!(relative_nodes_fr.get(&(day1, s1_node2)), Some(&dec!(0.0))); // 0.10 - 0.25 < 0
    assert_eq!(relative_nodes_fr.get(&(day1, s1_node4)), Some(&dec!(0.25))); // 0.50 - 0.25 = 0.25

    // --- Assertions for Day 1, Subnet 2 ---
    // Sorted FRs: 0.20, 0.40
    // 75th percentile index = ceil(2 * 0.75) - 1 = 1. Value is 0.40
    let expected_subnet2_day1_fr = dec!(0.40);
    assert_eq!(
        subnets_fr.get(&(day1, subnet2)),
        Some(&expected_subnet2_day1_fr)
    );
    assert_eq!(original_nodes_fr.get(&(day1, s2_node1)), Some(&dec!(0.20)));
    assert_eq!(relative_nodes_fr.get(&(day1, s2_node1)), Some(&dec!(0.0))); // 0.20 - 0.40 < 0
    assert_eq!(relative_nodes_fr.get(&(day1, s2_node2)), Some(&dec!(0.0))); // 0.40 - 0.40 = 0

    // --- Assertions for Day 2, Subnet 1 ---
    // Sorted FRs: 0.01, 0.10
    // 75th percentile index = ceil(2 * 0.75) - 1 = 1. Value is 0.10
    let expected_subnet1_day2_fr = dec!(0.10);
    assert_eq!(
        subnets_fr.get(&(day2, subnet1)),
        Some(&expected_subnet1_day2_fr)
    );
    assert_eq!(original_nodes_fr.get(&(day2, s1_node1)), Some(&dec!(0.01)));
    assert_eq!(relative_nodes_fr.get(&(day2, s1_node1)), Some(&dec!(0.0))); // 0.01 - 0.10 < 0
    assert_eq!(relative_nodes_fr.get(&(day2, s1_node2)), Some(&dec!(0.0))); // 0.10 - 0.10 = 0
}

#[test]
fn test_compute_providers_extrapolated_fr() {
    let mut intermediate_results = IntermediateResults::default();
    let day = "2024-01-01".into();
    let p1 = test_provider_id(1);
    let p2 = test_provider_id(2);
    let p1_node1 = test_node_id(1);
    let p2_node1 = test_node_id(2); // Belongs to other provider
    let p2_node2 = test_node_id(3); // Belongs to other provider

    intermediate_results
        .relative_nodes_fr
        .insert((day, p2_node1), dec!(0.2));
    intermediate_results
        .relative_nodes_fr
        .insert((day, p2_node2), dec!(0.4));

    let provider_rewardable_nodes = btreemap! {
        p1 => generate_rewardable_nodes(vec![(p1_node1, vec![day])]),
        p2 => generate_rewardable_nodes(vec![
            (p2_node1, vec![day]),
            (p2_node2, vec![day]),
        ]),
    };
    let input = RewardsCalculatorInput {
        provider_rewardable_nodes,
        ..default_test_input()
    };

    let pipeline = RewardsCalculatorPipeline::<ComputeProvidersExtrapolatedFR> {
        input,
        intermediate_results,
        _marker: PhantomData,
    };

    let result = pipeline.next();
    let intermediate = result.intermediate_results;

    // Extrapolated FR for P2 should be the average of other nodes' relative FR
    let expected_fr = (dec!(0.2) + dec!(0.4)) / dec!(2); // 0.3
    assert_eq!(
        intermediate.extrapolated_fr.get(&(p2, day)),
        Some(&expected_fr)
    );

    // Extrapolated FR for P1 should be 0 since no nodes are assigned
    assert_eq!(
        intermediate.extrapolated_fr.get(&(p1, day)),
        Some(&Decimal::zero())
    );
}

#[test]
fn test_compute_nodes_performance_multiplier() {
    let mut intermediate_results = IntermediateResults::default();
    let day = "2024-01-01".into();
    let p1 = test_provider_id(1);
    let node_good = test_node_id(1); // FR below threshold
    let node_mid = test_node_id(2); // FR in penalty zone
    let node_bad = test_node_id(3); // FR above threshold
    let node_unassigned = test_node_id(4); // Uses extrapolated FR

    // Assigned nodes
    intermediate_results
        .relative_nodes_fr
        .insert((day, node_good), dec!(0.05)); // < 0.1
    intermediate_results
        .relative_nodes_fr
        .insert((day, node_mid), dec!(0.35)); // (0.35-0.1)/(0.6-0.1)*0.8 = 0.4
    intermediate_results
        .relative_nodes_fr
        .insert((day, node_bad), dec!(0.7)); // > 0.6
                                             // Unassigned node
    intermediate_results
        .extrapolated_fr
        .insert((p1, day), dec!(0.35));

    let provider_rewardable_nodes = btreemap! {
        p1 => generate_rewardable_nodes(vec![
                (node_good, vec![day]),
                (node_mid, vec![day]),
                (node_bad, vec![day]),
                (node_unassigned, vec![day]),
            ])
    };
    let input = RewardsCalculatorInput {
        provider_rewardable_nodes,
        ..default_test_input()
    };

    let pipeline = RewardsCalculatorPipeline::<ComputeNodesPerformanceMultiplier> {
        input,
        intermediate_results,
        _marker: PhantomData,
    };
    let result = pipeline.next();
    let reward_reduction = result.intermediate_results.reward_reduction;
    let performance_multiplier = result.intermediate_results.performance_multiplier;

    // Good node: reduction = 0, multiplier = 1
    assert_eq!(
        reward_reduction.get(&(day, node_good)),
        Some(&MIN_REWARDS_REDUCTION)
    );
    assert_eq!(
        performance_multiplier.get(&(day, node_good)),
        Some(&dec!(1.0))
    );

    // Mid node: reduction = 0.4, multiplier = 0.6
    assert_eq!(reward_reduction.get(&(day, node_mid)), Some(&dec!(0.4)));
    assert_eq!(
        performance_multiplier.get(&(day, node_mid)),
        Some(&dec!(0.6))
    );

    // Bad node: reduction = 0.8, multiplier = 0.2
    assert_eq!(
        reward_reduction.get(&(day, node_bad)),
        Some(&MAX_REWARDS_REDUCTION)
    );
    assert_eq!(
        performance_multiplier.get(&(day, node_bad)),
        Some(&dec!(0.2))
    );

    // Unassigned node (uses extrapolated FR, same as mid)
    assert_eq!(
        performance_multiplier.get(&(day, node_unassigned)),
        Some(&dec!(0.6))
    );
}

fn create_rewards_table_for_region_test() -> NodeRewardsTable {
    let mut table = BTreeMap::new();

    // Switzerland
    let mut ch_rates = BTreeMap::new();
    ch_rates.insert(
        NodeRewardType::Type1.to_string(),
        NodeRewardRate {
            xdr_permyriad_per_node_per_month: 304375, // -> 10000 / day
            reward_coefficient_percent: None,
        },
    );
    table.insert(
        "Europe,Switzerland".to_string(),
        NodeRewardRates { rates: ch_rates },
    );

    // USA, CA
    let mut usa_ca_rates = BTreeMap::new();
    usa_ca_rates.insert(
        NodeRewardType::Type3.to_string(),
        NodeRewardRate {
            xdr_permyriad_per_node_per_month: 913125, // -> 30000 / day
            reward_coefficient_percent: Some(90),
        },
    );
    table.insert(
        "North America,USA,California".to_string(),
        NodeRewardRates {
            rates: usa_ca_rates,
        },
    );

    // USA, NV
    let mut usa_nv_rates = BTreeMap::new();
    usa_nv_rates.insert(
        NodeRewardType::Type3dot1.to_string(),
        NodeRewardRate {
            xdr_permyriad_per_node_per_month: 1217500, // -> 40000 / day
            reward_coefficient_percent: Some(70),
        },
    );
    table.insert(
        "North America,USA,Nevada".to_string(),
        NodeRewardRates {
            rates: usa_nv_rates,
        },
    );

    NodeRewardsTable { table }
}

#[test]
fn test_compute_base_rewards() {
    let day = "2024-01-01".into();
    let p1 = test_provider_id(1);
    let type1_node = test_node_id(1);
    let type3_node_ca = test_node_id(2); // California
    let type3_node_nv = test_node_id(3); // Nevada

    let input = RewardsCalculatorInput {
        rewards_table: create_rewards_table_for_region_test(),
        provider_rewardable_nodes: btreemap![
            p1 => vec![
                RewardableNode {
                    node_id: type1_node,
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    rewardable_days: vec![day],
                    dc_id: "dc1".into(),
                },
                RewardableNode {
                    node_id: type3_node_ca,
                    node_reward_type: NodeRewardType::Type3,
                    region: "North America,USA,California".into(),
                    rewardable_days: vec![day],
                    dc_id: "dc2".into(),
                },
                RewardableNode {
                    node_id: type3_node_nv,
                    node_reward_type: NodeRewardType::Type3dot1,
                    region: "North America,USA,Nevada".into(),
                    rewardable_days: vec![day],
                    dc_id: "dc3".into(),
                },
            ],
        ],
        ..default_test_input()
    };

    let pipeline = RewardsCalculatorPipeline::<ComputeBaseRewardsTypeRegion> {
        input,
        intermediate_results: IntermediateResults::default(),
        _marker: PhantomData,
    };
    let base_rewards_computed = pipeline.next().next();
    let results = base_rewards_computed.intermediate_results.clone();

    // --- Assert non-Type3 base rewards ---
    let expected_type1_reward = dec!(304375) / REWARDS_TABLE_DAYS;
    assert_eq!(
        results
            .base_rewards_type_region
            .get(&(NodeRewardType::Type1, "Europe,Switzerland".into())),
        Some(&expected_type1_reward)
    );

    // --- Type3 grouped calculation ---
    // Two type3 nodes are in "North America,USA" group for p1
    // Daily rates: 30_000 and 40_000. Avg rate = 35_000
    // Coefficients: 0.9 and 0.7. Avg coeff = 0.8
    // Rewards for the two nodes in the region:
    // 1st node reward: 35_000 * 1 = 35_000
    // 2nd node reward: 35_000 * 0.8 = 28_000
    // Average reward for the region group: (35_000 + 28_000) / 2 = 31_500
    let expected_type3_avg_reward = dec!(31500);
    let region_key = "North America:USA".to_string();

    assert_eq!(
        results
            .type3_base_rewards_type_region
            .get(&(p1, day, region_key)),
        Some(&expected_type3_avg_reward)
    );

    assert_eq!(
        Some(&expected_type1_reward),
        results.base_rewards.get(&(day, type1_node))
    );
    assert_eq!(
        Some(&expected_type3_avg_reward),
        results.base_rewards.get(&(day, type3_node_ca))
    );
    assert_eq!(
        Some(&expected_type3_avg_reward),
        results.base_rewards.get(&(day, type3_node_nv))
    );
}

#[test]
fn test_compute_nodes_count() {
    let day1 = "2024-01-01".into();
    let day2 = "2024-01-02".into();
    let p1 = test_provider_id(1);
    let node1 = test_node_id(1);
    let node2 = test_node_id(2);

    let provider_rewardable_nodes = btreemap! {
        p1 => generate_rewardable_nodes(vec![(node1, vec![day1, day2]), (node2, vec![day1])])
    };
    let input = RewardsCalculatorInput {
        provider_rewardable_nodes,
        ..default_test_input()
    };

    let pipeline = RewardsCalculatorPipeline::<ComputeNodesCount> {
        input,
        intermediate_results: IntermediateResults::default(),
        _marker: PhantomData,
    };
    let result = pipeline.next();
    let intermediate = result.intermediate_results;

    assert_eq!(intermediate.nodes_count.get(&(p1, day1)), Some(&2));
    assert_eq!(intermediate.nodes_count.get(&(p1, day2)), Some(&1));
}

// #[test]
// fn test_adjust_nodes_rewards() {
//     let mut intermediate_results = IntermediateResults::default();
//     let day = "2024-01-01".into();
//     let p1 = test_provider_id(1);
//     let node1 = test_node_id(1);
//     let node2 = test_node_id(2);
//     let region_ch = "CH".into();
//     let reward_type = NodeRewardType::Type1;
//
//     // Case 1: More than 4 nodes, performance matters
//     intermediate_results.nodes_count.insert((p1, day), 5);
//     intermediate_results
//         .performance_multiplier
//         .insert((day, node1), dec!(0.5));
//     intermediate_results
//         .base_rewards_type_region
//         .insert((reward_type.clone(), region_ch.clone()), dec!(1000));
//
//     // Case 2: 4 or fewer nodes, full rewards
//     // This test will use the same provider and day, but we'll check node2
//     // which will fall under a different condition in the code.
//     intermediate_results
//         .performance_multiplier
//         .insert((day, node2), dec!(0.5)); // Should be ignored
//
//     let mut node1_metrics: crate::types::NodeInfo = node1.into();
//     node1_metrics.rewardable_days = vec![day];
//     node1_metrics.node_reward_type = reward_type.clone();
//     node1_metrics.region = region_ch.clone();
//
//     let mut node2_metrics: crate::types::NodeInfo = node2.into();
//     node2_metrics.rewardable_days = vec![day];
//     node2_metrics.node_reward_type = reward_type;
//     node2_metrics.region = region_ch;
//
//     let input = RewardsCalculatorInput {
//         rewardable_nodes: vec![ProviderRewardableNodes {
//             provider_id: p1,
//             rewardable_nodes: vec![node1_metrics.clone(), node2_metrics.clone()],
//         }],
//         ..default_test_input()
//     };
//
//     // --- Test for node1 (penalty applied) ---
//     let mut pipeline1 = RewardsCalculatorPipeline::<AdjustNodesRewards> {
//         input: input.clone(),
//         intermediate_results: intermediate_results.clone(),
//         _marker: PhantomData,
//     };
//     // Manually set node count for this specific test case
//     pipeline1
//         .intermediate_results
//         .nodes_count
//         .insert((p1, day), 5);
//     let result1 = pipeline1.next();
//     assert_eq!(
//         result1
//             .intermediate_results
//             .adjusted_rewards
//             .get(&(day, node1)),
//         Some(&dec!(500))
//     ); // 1000 * 0.5
//
//     // --- Test for node2 (no penalty) ---
//     let mut pipeline2 = RewardsCalculatorPipeline::<AdjustNodesRewards> {
//         input,
//         intermediate_results,
//         _marker: PhantomData,
//     };
//     // Manually set node count for this specific test case
//     pipeline2
//         .intermediate_results
//         .nodes_count
//         .insert((p1, day), 4);
//     let result2 = pipeline2.next();
//     assert_eq!(
//         result2
//             .intermediate_results
//             .adjusted_rewards
//             .get(&(day, node2)),
//         Some(&dec!(1000))
//     );
// }

#[test]
fn test_compute_rewards_total() {
    let mut intermediate_results = IntermediateResults::default();
    let day1 = "2024-01-01".into();
    let day2 = "2024-01-02".into();
    let p1 = test_provider_id(1);
    let node1 = test_node_id(1);
    let node2 = test_node_id(2);

    intermediate_results
        .adjusted_rewards
        .insert((day1, node1), dec!(100));
    intermediate_results
        .adjusted_rewards
        .insert((day2, node1), dec!(100));
    intermediate_results
        .adjusted_rewards
        .insert((day1, node2), dec!(50));

    let provider_rewardable_nodes = btreemap! {
        p1 => generate_rewardable_nodes(vec![(node1, vec![day1, day2]), (node2, vec![day1])])
    };
    let input = RewardsCalculatorInput {
        provider_rewardable_nodes,
        ..default_test_input()
    };

    let pipeline = RewardsCalculatorPipeline::<ComputeRewardsTotal> {
        input,
        intermediate_results,
        _marker: PhantomData,
    };
    let result = pipeline.next();
    let intermediate = result.intermediate_results;

    // Total for p1 = 100 + 100 + 50 = 250
    assert_eq!(intermediate.rewards_total.get(&p1), Some(&dec!(250)));
}
