use super::*;
use crate::rewards_calculator::test_utils::{
    build_daily_metrics, create_rewards_table_for_region_test, generate_rewardable_nodes,
    test_node_id, test_provider_id, test_subnet_id,
};
use crate::types::RewardableNode;
use ic_base_types::PrincipalId;
use maplit::{btreemap, hashmap};
use tabled::builder::Builder;
use tabled::settings::object::Rows;
use tabled::settings::style::LineText;
use tabled::Table;

// ------------------------------------------------------------------------------------------------
// Step 0: Pre-compute subnets and nodes failure rates
// ------------------------------------------------------------------------------------------------
#[test]
fn test_compute_subnets_nodes_fr() {
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

    // --- Data Setup ---
    let daily_metrics_by_subnet = BTreeMap::from_iter(vec![
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
                (s1_node1, 99, 1), // FR = 0.01
                (s1_node2, 0, 0),  // FR = 0.0, but not in rewardable_nodes for day2 so ignored
            ],
        ),
    ]);

    // --- Execution ---
    let result = step_0_subnets_nodes_fr(daily_metrics_by_subnet);
    let subnets_fr = result.subnets_fr;
    let original_nodes_fr: BTreeMap<_, _> = result
        .nodes_metrics_daily
        .iter()
        .map(|(k, v)| (*k, v.original_fr_percent))
        .collect();
    let relative_nodes_fr: BTreeMap<_, _> = result
        .nodes_metrics_daily
        .iter()
        .map(|(k, v)| (*k, v.relative_fr_percent))
        .collect();

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
    // Sorted FRs: 0.0, 0.01
    // 75th percentile index = ceil(2 * 0.75) - 1 = 1. Value is 0.01
    let expected_subnet1_day2_fr = dec!(0.01);
    assert_eq!(
        subnets_fr.get(&(day2, subnet1)),
        Some(&expected_subnet1_day2_fr)
    );
    assert_eq!(original_nodes_fr.get(&(day2, s1_node1)), Some(&dec!(0.01)));
    assert_eq!(relative_nodes_fr.get(&(day2, s1_node1)), Some(&dec!(0.0))); // 0.01 - 0.01 = 0
}

// ------------------------------------------------------------------------------------------------
// Step 2: Extrapolated failure rate for each provider
// ------------------------------------------------------------------------------------------------

impl Default for NodeMetricsDaily {
    fn default() -> Self {
        Self {
            subnet_assigned: test_subnet_id(0),
            subnet_assigned_fr_percent: dec!(0.0),
            num_blocks_proposed: 0,
            num_blocks_failed: 0,
            original_fr_percent: dec!(0.0),
            relative_fr_percent: dec!(0.0),
        }
    }
}

#[test]
fn test_compute_providers_extrapolated_fr() {
    let day = "2024-01-01".into();
    let p1_node1 = test_node_id(1);
    let p2_node1 = test_node_id(2);
    let p2_node2 = test_node_id(3);

    // --- P1 Data: No nodes with metrics ---
    let p1_nodes = generate_rewardable_nodes(vec![(p1_node1, vec![day])]);
    let p1_metrics = BTreeMap::new(); // No metrics available
    let result_p1 = step_2_extrapolated_fr(&p1_nodes, &p1_metrics);
    // Extrapolated FR for P1 should be 0 since no nodes are assigned
    assert_eq!(result_p1.extrapolated_fr.get(&day), Some(&Decimal::ZERO));

    // --- P2 Data: Two nodes with metrics ---
    let p2_nodes = generate_rewardable_nodes(vec![(p2_node1, vec![day]), (p2_node2, vec![day])]);
    let p2_metrics = btreemap! {
        (day, p2_node1) => NodeMetricsDaily { relative_fr_percent: dec!(0.2), ..Default::default() },
        (day, p2_node2) => NodeMetricsDaily { relative_fr_percent: dec!(0.4), ..Default::default() },
    };
    let result_p2 = step_2_extrapolated_fr(&p2_nodes, &p2_metrics);
    // Extrapolated FR for P2 should be the average of its nodes' relative FR
    let expected_fr_p2 = (dec!(0.2) + dec!(0.4)) / dec!(2); // 0.3
    assert_eq!(result_p2.extrapolated_fr.get(&day), Some(&expected_fr_p2));
}

// ------------------------------------------------------------------------------------------------
// Step 3: Compute performance multiplier for each node for each provider
// ------------------------------------------------------------------------------------------------
#[test]
fn test_compute_nodes_performance_multiplier() {
    let day = "2024-01-01".into();
    let node_good = test_node_id(1); // FR below threshold
    let node_mid = test_node_id(2); // FR in penalty zone
    let node_bad = test_node_id(3); // FR above threshold
    let node_unassigned = test_node_id(4); // Uses extrapolated FR

    // --- Data Setup ---
    let rewardable_nodes = generate_rewardable_nodes(vec![
        (node_good, vec![day]),
        (node_mid, vec![day]),
        (node_bad, vec![day]),
        (node_unassigned, vec![day]),
    ]);

    // Assigned nodes' relative FR
    let relative_nodes_fr = btreemap! {
        (day, node_good) => dec!(0.05), // < 0.1
        (day, node_mid) => dec!(0.35), // (0.35-0.1)/(0.6-0.1)*0.8 = 0.4
        (day, node_bad) => dec!(0.7),  // > 0.6
    };
    // Unassigned nodes use extrapolated FR
    let extrapolated_fr = hashmap! {
        day => dec!(0.35)
    };

    // --- Execution ---
    let result =
        step_3_performance_multiplier(&rewardable_nodes, &relative_nodes_fr, &extrapolated_fr);
    let reward_reduction = result.reward_reduction;
    let performance_multiplier = result.performance_multiplier;

    // --- Assertions ---
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

// ------------------------------------------------------------------------------------------------
// Step 4: Compute base rewards for each node based on its region and node type
// ------------------------------------------------------------------------------------------------

#[test]
fn test_compute_base_rewards() {
    let day = "2024-01-01".into();
    let type1_node = test_node_id(1);
    let type3_node_ca = test_node_id(2);
    let type3_node_nv = test_node_id(3);

    let rewardable_nodes = vec![
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
    ];
    let rewards_table = create_rewards_table_for_region_test();

    // --- Execution ---
    let Step4Results {
        base_rewards,
        base_rewards_log,
    } = step_4_compute_base_rewards_type_region(&rewards_table, &rewardable_nodes);

    let expected_log = r#"Base Rewards Log:
Region: Europe,Switzerland, Type: type1, Base Rewards Daily: 10000, Coefficient: 0.80
Region: North America,USA,California, Type: type3, Base Rewards Daily: 30000, Coefficient: 0.90
Region: North America,USA,Nevada, Type: type3.1, Base Rewards Daily: 40000, Coefficient: 0.70
Type3* - Day: 01-01-2024 Region: North America:USA, Nodes Count: 2, Base Rewards Daily Avg: 35000, Coefficient Avg: 0.80, Base Rewards Daily: 31500.00"#;
    assert_eq!(base_rewards_log, expected_log);

    // --- Assertions ---
    assert_eq!(base_rewards.get(&(day, type1_node)), Some(&dec!(10000)));
    assert_eq!(base_rewards.get(&(day, type3_node_ca)), Some(&dec!(31500)));
    assert_eq!(base_rewards.get(&(day, type3_node_nv)), Some(&dec!(31500)));
}

// ------------------------------------------------------------------------------------------------
// Step 5: Adjust nodes rewards based on performance and number of nodes
// ------------------------------------------------------------------------------------------------
#[test]
fn test_adjust_nodes_rewards() {
    let day1 = "2024-01-01".into();
    let day2 = "2024-01-02".into();
    let node1 = test_node_id(1);
    let node2 = test_node_id(2);
    let node3 = test_node_id(3);
    let node4 = test_node_id(4);
    let node5 = test_node_id(5);

    // Day 1 has 5 nodes, Day 2 has 4 nodes.
    let rewardable_nodes = generate_rewardable_nodes(vec![
        (node1, vec![day1, day2]),
        (node2, vec![day1, day2]),
        (node3, vec![day1, day2]),
        (node4, vec![day1, day2]),
        (node5, vec![day1]),
    ]);

    let mut base_rewards = BTreeMap::new();
    let mut performance_multiplier = HashMap::new();
    for node in &rewardable_nodes {
        for day in &node.rewardable_days {
            base_rewards.insert((*day, node.node_id), dec!(1000));
            performance_multiplier.insert((*day, node.node_id), dec!(0.5));
        }
    }

    // --- Execution ---
    let Step5Results { adjusted_rewards } =
        step_5_adjust_node_rewards(&rewardable_nodes, &base_rewards, &performance_multiplier);

    // --- Assertions ---
    // Case 1: More than 4 nodes (5 on day1), penalty applies
    assert_eq!(
        adjusted_rewards.get(&(day1, node1)),
        Some(&(dec!(1000) * dec!(0.5)))
    );
    // Case 2: 4 or fewer nodes (4 on day2), full rewards
    assert_eq!(adjusted_rewards.get(&(day2, node1)), Some(&(dec!(1000))));
}

// ------------------------------------------------------------------------------------------------
// End-to-end test for the rewards calculation process
// ------------------------------------------------------------------------------------------------

#[test]
fn test_calculate_rewards_end_to_end() {
    let day1 = "2024-01-01".into();
    let day2 = "2024-01-02".into();
    let subnet1 = test_subnet_id(1);
    let subnet2 = test_subnet_id(2);
    let p1 = test_provider_id(1);
    let p2 = test_provider_id(2);

    // Provider 1 nodes
    let p1_node1_t1 = test_node_id(11); // Type1, CH, in Subnet1 on D1, D2
    let p1_node2_t3 = test_node_id(12); // Type3, CA, in Subnet1 on D1, unassigned D2
    let p1_node3_t31 = test_node_id(13); // Type3.1, NV, in Subnet1 on D1 only
    let p1_node4_unassigned = test_node_id(14); // Always unassigned
    let p1_node5_perf = test_node_id(15); // In Subnet1 on D1, bad performance

    // Provider 2 nodes
    let p2_node1 = test_node_id(21); // In Subnet2 on D1

    // --- Input Setup ---
    let daily_metrics_by_subnet = BTreeMap::from_iter(vec![
        // Day 1, Subnet 1
        build_daily_metrics(
            subnet1,
            day1,
            &[
                (p1_node1_t1, 95, 5),    // FR = 0.05
                (p1_node2_t3, 90, 10),   // FR = 0.10
                (p1_node3_t31, 75, 25),  // FR = 0.25
                (p1_node5_perf, 30, 70), // FR = 0.70
            ],
        ),
        // Day 1, Subnet 2
        build_daily_metrics(subnet2, day1, &[(p2_node1, 80, 20)]), // FR = 0.20
        // Day 2, Subnet 1
        build_daily_metrics(subnet1, day2, &[(p1_node1_t1, 98, 2)]), // FR = 0.02
    ]);

    let provider_rewardable_nodes = btreemap! {
        p1 => vec![
            RewardableNode {
                node_id: p1_node1_t1,
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                rewardable_days: vec![day1, day2],
                dc_id: "dc1".into(),
            },
            RewardableNode {
                node_id: p1_node2_t3,
                node_reward_type: NodeRewardType::Type3,
                region: "North America,USA,California".into(),
                rewardable_days: vec![day1, day2],
                dc_id: "dc2".into(),
            },
            RewardableNode {
                node_id: p1_node3_t31,
                node_reward_type: NodeRewardType::Type3dot1,
                region: "North America,USA,Nevada".into(),
                rewardable_days: vec![day1],
                dc_id: "dc3".into(),
            },
            RewardableNode {
                node_id: p1_node4_unassigned,
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                rewardable_days: vec![day1, day2],
                dc_id: "dc1".into(),
            },
            RewardableNode {
                node_id: p1_node5_perf,
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                rewardable_days: vec![day1],
                dc_id: "dc1".into(),
            },
        ],
        p2 => vec![
            RewardableNode {
                node_id: p2_node1,
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                rewardable_days: vec![day1],
                dc_id: "dc1".into(),
            },
        ],
    };

    let input = RewardsCalculatorInput {
        reward_period: RewardPeriod {
            from: day1,
            to: day2,
        },
        rewards_table: create_rewards_table_for_region_test(),
        daily_metrics_by_subnet,
        provider_rewardable_nodes,
    };

    let results = calculate_rewards(input).unwrap();
    let total_p1_rewards = results
        .provider_results
        .get(&p1)
        .unwrap()
        .rewards_total_xdr_permyriad;
    let expected_total_p1_rewards = 87200 + 50000;
    assert_eq!(total_p1_rewards, expected_total_p1_rewards);

    let total_p2_rewards = results
        .provider_results
        .get(&p2)
        .unwrap()
        .rewards_total_xdr_permyriad;
    let expected_total_p2_rewards = 10000;
    assert_eq!(total_p2_rewards, expected_total_p2_rewards);
}
