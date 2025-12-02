use crate::AlgorithmVersion;
use crate::performance_based_algorithm::results::RewardsCalculatorResults;
use crate::performance_based_algorithm::{
    PerformanceBasedAlgorithm, PerformanceBasedAlgorithmInputProvider,
};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
// ================================================================================================
// VERSIONING SAFETY WARNING
// ================================================================================================
//
// CRITICAL: This RewardsCalculationV1 implementation must maintain historical reproducibility.
//
// Any changes to the calculation logic, constants, or data structures in this version MUST NOT
// affect the results of previously calculated rewards. This is essential for:
//
// 1. **Audit Trail Integrity**: Historical reward calculations must remain verifiable
// 3. **Financial Accuracy**: Incorrect historical calculations could have legal implications
// 4. **System Reliability**: Users depend on consistent reward calculations over time
//
// If you need to change the calculation logic, create a new version (V2, V3, etc.) instead
// of modifying this V1 implementation. This ensures backward compatibility and historical
// reproducibility while allowing for future algorithm improvements.
//
// ================================================================================================

pub struct RewardsCalculationV1;

impl PerformanceBasedAlgorithm for RewardsCalculationV1 {
    const SUBNET_FAILURE_RATE_PERCENTILE: f64 = 0.75;
    const MIN_FAILURE_RATE: Decimal = dec!(0.1);
    const MAX_FAILURE_RATE: Decimal = dec!(0.6);
    const MIN_REWARDS_REDUCTION: Decimal = dec!(0);
    const MAX_REWARDS_REDUCTION: Decimal = dec!(0.8);
}

impl AlgorithmVersion for RewardsCalculationV1 {
    const VERSION: u32 = 1;
}

impl RewardsCalculationV1 {
    pub fn calculate_rewards(
        from_date: NaiveDate,
        to_date: NaiveDate,
        input_provider: impl PerformanceBasedAlgorithmInputProvider,
    ) -> Result<RewardsCalculatorResults, String> {
        <RewardsCalculationV1 as PerformanceBasedAlgorithm>::calculate_rewards(
            from_date,
            to_date,
            input_provider,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::performance_based_algorithm::test_utils::{
        build_daily_metrics, create_rewards_table_for_region_test, generate_rewardable_nodes,
        test_node_id, test_subnet_id,
    };
    use crate::performance_based_algorithm::v1::RewardsCalculationV1;
    use crate::performance_based_algorithm::{
        AdjustedRewardsResults, BaseRewardsResults, PerformanceBasedAlgorithm,
    };
    use crate::types::RewardableNode;
    use ic_protobuf::registry::node::v1::NodeRewardType;
    use maplit::btreemap;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

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
        let result = RewardsCalculationV1::calculate_failure_rates(daily_metrics_by_subnet);
        let subnets_fr = result.subnets_failure_rate;
        let original_nodes_fr: BTreeMap<_, _> = result
            .nodes_metrics_daily
            .iter()
            .map(|(k, v)| (*k, v.original_failure_rate))
            .collect();
        let relative_nodes_fr: BTreeMap<_, _> = result
            .nodes_metrics_daily
            .iter()
            .map(|(k, v)| (*k, v.relative_failure_rate))
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
        let result = RewardsCalculationV1::calculate_failure_rates(daily_metrics_by_subnet);
        let subnets_fr = result.subnets_failure_rate;
        let original_nodes_fr: BTreeMap<_, _> = result
            .nodes_metrics_daily
            .iter()
            .map(|(k, v)| (*k, v.original_failure_rate))
            .collect();
        let relative_nodes_fr: BTreeMap<_, _> = result
            .nodes_metrics_daily
            .iter()
            .map(|(k, v)| (*k, v.relative_failure_rate))
            .collect();

        // --- Assertions for Day 2, Subnet 1 ---
        // Sorted FRs: 0.0, 0.01
        // 75th percentile index = ceil(2 * 0.75) - 1 = 1. Value is 0.01
        let expected_subnet1_day2_fr = dec!(0.01);

        assert_eq!(subnets_fr.get(&subnet1), Some(&expected_subnet1_day2_fr));
        assert_eq!(original_nodes_fr.get(&s1_node1), Some(&dec!(0.01)));
        assert_eq!(relative_nodes_fr.get(&s1_node1), Some(&dec!(0.0))); // 0.01 - 0.01 = 0
    }

    #[test]
    fn test_node_assigned_to_multiple_subnets_same_day_should_retain_only_the_one_with_more_total_blocks()
     {
        let subnet1 = test_subnet_id(1);
        let subnet2 = test_subnet_id(2);

        // Nodes for Subnet 1
        let s1_node1 = test_node_id(11);

        // --- Data Setup ---
        let daily_metrics_by_subnet = BTreeMap::from_iter(vec![
            build_daily_metrics(
                subnet1,
                &[
                    (s1_node1, 75, 25), // FR = 0.25
                ],
            ),
            build_daily_metrics(
                subnet2,
                &[
                    // Node is assigned to both subnets, but only the one with more blocks should be used.
                    (s1_node1, 800, 200), // FR = 0.20
                ],
            ),
        ]);

        // --- Execution ---
        let result = RewardsCalculationV1::calculate_failure_rates(daily_metrics_by_subnet);

        assert!(!result.subnets_failure_rate.contains_key(&subnet1));
        assert_eq!(result.subnets_failure_rate.get(&subnet2), Some(&dec!(0.20)));

        let node_fr = result.nodes_metrics_daily.get(&s1_node1).unwrap();
        assert_eq!(node_fr.original_failure_rate, dec!(0.2));
        assert_eq!(node_fr.relative_failure_rate, dec!(0.0));
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
        let result = RewardsCalculationV1::calculate_performance_multipliers(
            &rewardable_nodes,
            &relative_nodes_fr,
            &extrapolated_fr,
        );
        let reward_reduction = result.reward_reduction;
        let performance_multiplier = result.performance_multiplier;

        // --- Assertions ---
        // Good node: reduction = 0, multiplier = 1
        assert_eq!(
            reward_reduction.get(&node_good),
            Some(&RewardsCalculationV1::MIN_REWARDS_REDUCTION)
        );
        assert_eq!(performance_multiplier.get(&node_good), Some(&dec!(1.0)));

        // Mid node: reduction = 0.4, multiplier = 0.6
        assert_eq!(reward_reduction.get(&node_mid), Some(&dec!(0.4)));
        assert_eq!(performance_multiplier.get(&node_mid), Some(&dec!(0.6)));

        // Bad node: reduction = 0.8, multiplier = 0.2
        assert_eq!(
            reward_reduction.get(&node_bad),
            Some(&RewardsCalculationV1::MAX_REWARDS_REDUCTION)
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
        let BaseRewardsResults {
            base_rewards_per_node,
            ..
        } = RewardsCalculationV1::calculate_base_rewards_by_region_and_type(
            &rewards_table,
            &rewardable_nodes,
        );

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
        let mut performance_multiplier = BTreeMap::new();
        for node in &rewardable_nodes {
            base_rewards.insert(node.node_id, dec!(1000));
            // Assigned nodes
            performance_multiplier.insert(node.node_id, dec!(0.5));
        }

        // --- Execution ---
        let AdjustedRewardsResults { adjusted_rewards } =
            RewardsCalculationV1::apply_performance_adjustments(
                &rewardable_nodes,
                &base_rewards,
                &performance_multiplier,
            );

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
}

#[cfg(test)]
mod e2e_tests;
