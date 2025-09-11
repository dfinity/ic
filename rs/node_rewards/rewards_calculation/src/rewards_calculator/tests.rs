use super::*;
use crate::rewards_calculator::test_utils::{
    build_daily_metrics, create_rewards_table_for_region_test, generate_rewardable_nodes,
    test_node_id, test_subnet_id,
};
use crate::types::RewardableNode;
use maplit::btreemap;

// ------------------------------------------------------------------------------------------------
// Step 0: Pre-compute subnets and nodes failure rates
// ------------------------------------------------------------------------------------------------
#[test]
fn test_compute_subnets_nodes_fr() {
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
        build_daily_metrics(
            subnet1,
            &[
                (s1_node1, 75, 25), // FR = 0.25
                (s1_node2, 90, 10), // FR = 0.10
                (s1_node3, 95, 5),  // FR = 0.05
                (s1_node4, 50, 50), // FR = 0.50
            ],
        ),
        build_daily_metrics(
            subnet2,
            &[
                (s2_node1, 80, 20), // FR = 0.20
                (s2_node2, 60, 40), // FR = 0.40
            ],
        ),
    ]);

    // --- Execution ---
    let result = step_0_subnets_nodes_fr(daily_metrics_by_subnet);
    let subnets_fr = result.subnets_fr;
    let original_nodes_fr: BTreeMap<_, _> = result
        .nodes_metrics_daily
        .iter()
        .map(|(k, v)| (*k, v.original_fr))
        .collect();
    let relative_nodes_fr: BTreeMap<_, _> = result
        .nodes_metrics_daily
        .iter()
        .map(|(k, v)| (*k, v.relative_fr))
        .collect();

    // --- Assertions for Day 1, Subnet 1 ---
    // Sorted FRs: 0.05, 0.10, 0.25, 0.50
    // 75th percentile index = ceil(4 * 0.75) - 1 = 2. Value is 0.25
    let expected_subnet1_day1_fr = dec!(0.25);
    assert_eq!(subnets_fr.get(&subnet1), Some(&expected_subnet1_day1_fr));
    assert_eq!(original_nodes_fr.get(&s1_node1), Some(&dec!(0.25)));
    // Relative FR = max(0, original - subnet_fr)
    assert_eq!(relative_nodes_fr.get(&s1_node1), Some(&dec!(0.0))); // 0.25 - 0.25 = 0
    assert_eq!(relative_nodes_fr.get(&s1_node2), Some(&dec!(0.0))); // 0.10 - 0.25 < 0
    assert_eq!(relative_nodes_fr.get(&s1_node4), Some(&dec!(0.25))); // 0.50 - 0.25 = 0.25

    // --- Assertions for Day 1, Subnet 2 ---
    // Sorted FRs: 0.20, 0.40
    // 75th percentile index = ceil(2 * 0.75) - 1 = 1. Value is 0.40
    let expected_subnet2_day1_fr = dec!(0.40);
    assert_eq!(subnets_fr.get(&subnet2), Some(&expected_subnet2_day1_fr));
    assert_eq!(original_nodes_fr.get(&s2_node1), Some(&dec!(0.20)));
    assert_eq!(relative_nodes_fr.get(&s2_node1), Some(&dec!(0.0))); // 0.20 - 0.40 < 0
    assert_eq!(relative_nodes_fr.get(&s2_node1), Some(&dec!(0.0))); // 0.40 - 0.40 = 0

    // --- Data Setup ---
    let daily_metrics_by_subnet = BTreeMap::from_iter(vec![build_daily_metrics(
        subnet1,
        &[
            (s1_node1, 99, 1), // FR = 0.01
            (s1_node2, 0, 0),  // FR = 0.0, but not in rewardable_nodes for day2 so ignored
        ],
    )]);
    let result = step_0_subnets_nodes_fr(daily_metrics_by_subnet);
    let subnets_fr = result.subnets_fr;
    let original_nodes_fr: BTreeMap<_, _> = result
        .nodes_metrics_daily
        .iter()
        .map(|(k, v)| (*k, v.original_fr))
        .collect();
    let relative_nodes_fr: BTreeMap<_, _> = result
        .nodes_metrics_daily
        .iter()
        .map(|(k, v)| (*k, v.relative_fr))
        .collect();

    // --- Assertions for Day 2, Subnet 1 ---
    // Sorted FRs: 0.0, 0.01
    // 75th percentile index = ceil(2 * 0.75) - 1 = 1. Value is 0.01
    let expected_subnet1_day2_fr = dec!(0.01);

    assert_eq!(subnets_fr.get(&subnet1), Some(&expected_subnet1_day2_fr));
    assert_eq!(original_nodes_fr.get(&s1_node1), Some(&dec!(0.01)));
    assert_eq!(relative_nodes_fr.get(&s1_node1), Some(&dec!(0.0))); // 0.01 - 0.01 = 0
}

// ------------------------------------------------------------------------------------------------
// Step 3: Compute performance multiplier for each node for each provider
// ------------------------------------------------------------------------------------------------
#[test]
fn test_compute_nodes_performance_multiplier() {
    let node_good = test_node_id(1); // FR below threshold
    let node_mid = test_node_id(2); // FR in penalty zone
    let node_bad = test_node_id(3); // FR above threshold
    let node_unassigned = test_node_id(4); // Uses extrapolated FR

    // --- Data Setup ---
    let rewardable_nodes =
        generate_rewardable_nodes(vec![node_good, node_mid, node_bad, node_unassigned]);

    // Assigned nodes' relative FR
    let relative_nodes_fr = btreemap! {
        node_good => dec!(0.05), // < 0.1
        node_mid => dec!(0.35), // (0.35-0.1)/(0.6-0.1)*0.8 = 0.4
        node_bad => dec!(0.7),  // > 0.6
    };
    // Unassigned nodes use extrapolated FR
    let extrapolated_fr = dec!(0.35);

    // --- Execution ---
    let result =
        step_3_performance_multiplier(&rewardable_nodes, &relative_nodes_fr, &extrapolated_fr);
    let reward_reduction = result.reward_reduction;
    let performance_multiplier = result.performance_multiplier;

    // --- Assertions ---
    // Good node: reduction = 0, multiplier = 1
    assert_eq!(
        reward_reduction.get(&node_good),
        Some(&MIN_REWARDS_REDUCTION)
    );
    assert_eq!(performance_multiplier.get(&node_good), Some(&dec!(1.0)));

    // Mid node: reduction = 0.4, multiplier = 0.6
    assert_eq!(reward_reduction.get(&node_mid), Some(&dec!(0.4)));
    assert_eq!(performance_multiplier.get(&node_mid), Some(&dec!(0.6)));

    // Bad node: reduction = 0.8, multiplier = 0.2
    assert_eq!(
        reward_reduction.get(&node_bad),
        Some(&MAX_REWARDS_REDUCTION)
    );
    assert_eq!(performance_multiplier.get(&node_bad), Some(&dec!(0.2)));

    // Unassigned node (uses extrapolated FR, same as mid)
    assert_eq!(
        performance_multiplier.get(&node_unassigned),
        Some(&dec!(0.6))
    );
}

// ------------------------------------------------------------------------------------------------
// Step 4: Compute base rewards for each node based on its region and node type
// ------------------------------------------------------------------------------------------------

#[test]
fn test_compute_base_rewards() {
    let type1_node = test_node_id(1);
    let type3_node_ca = test_node_id(2);
    let type3_node_nv = test_node_id(3);

    let rewardable_nodes = vec![
        RewardableNode {
            node_id: type1_node,
            node_reward_type: NodeRewardType::Type1,
            region: "Europe,Switzerland".into(),
            dc_id: "dc1".into(),
        },
        RewardableNode {
            node_id: type3_node_ca,
            node_reward_type: NodeRewardType::Type3,
            region: "North America,USA,California".into(),
            dc_id: "dc2".into(),
        },
        RewardableNode {
            node_id: type3_node_nv,
            node_reward_type: NodeRewardType::Type3dot1,
            region: "North America,USA,Nevada".into(),
            dc_id: "dc3".into(),
        },
    ];
    let rewards_table = create_rewards_table_for_region_test();

    // --- Execution ---
    let Step4Results {
        base_rewards_per_node,
        ..
    } = step_4_compute_base_rewards_type_region(&rewards_table, &rewardable_nodes);

    // --- Assertions ---
    assert_eq!(base_rewards_per_node.get(&type1_node), Some(&dec!(10000)));
    assert_eq!(
        base_rewards_per_node.get(&type3_node_ca),
        Some(&dec!(31500))
    );
    assert_eq!(
        base_rewards_per_node.get(&type3_node_nv),
        Some(&dec!(31500))
    );
}

// ------------------------------------------------------------------------------------------------
// Step 5: Adjust nodes rewards based on performance and number of nodes
// ------------------------------------------------------------------------------------------------
#[test]
fn test_adjust_nodes_rewards() {
    let node1 = test_node_id(1);
    let node2 = test_node_id(2);
    let node3 = test_node_id(3);
    let node4 = test_node_id(4);
    let node5 = test_node_id(5);

    // Day 1 has 5 nodes, Day 2 and Day 3 has 3 nodes.
    let rewardable_nodes = generate_rewardable_nodes(vec![node1, node2, node3, node4, node5]);

    let mut base_rewards = BTreeMap::new();
    let mut performance_multiplier = HashMap::new();
    for node in &rewardable_nodes {
        base_rewards.insert(node.node_id, dec!(1000));
        // Assigned nodes
        performance_multiplier.insert(node.node_id, dec!(0.5));
    }

    // --- Execution ---
    let Step5Results { adjusted_rewards } =
        step_5_adjust_node_rewards(&rewardable_nodes, &base_rewards, &performance_multiplier);

    // --- Assertions ---
    let expected = dec!(1000) * dec!(0.5);

    for node in &[node1, node2, node3, node4, node5] {
        assert_eq!(
            adjusted_rewards.get(node),
            Some(&expected),
            "Unexpected reward for node {:?}",
            node
        );
    }
}
