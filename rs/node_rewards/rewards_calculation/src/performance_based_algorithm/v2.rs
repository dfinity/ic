use crate::AlgorithmVersion;
use crate::performance_based_algorithm::results::RewardsCalculatorResults;
use crate::performance_based_algorithm::{
    PerformanceBasedAlgorithm, PerformanceBasedAlgorithmInputProvider,
};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

pub struct RewardsCalculationV2;

impl PerformanceBasedAlgorithm for RewardsCalculationV2 {
    const SUBNET_FAILURE_RATE_PERCENTILE: f64 = 0.75;
    const MIN_FAILURE_RATE: Decimal = dec!(0.1);
    const MAX_FAILURE_RATE: Decimal = dec!(0.6);
    const MIN_REWARDS_REDUCTION: Decimal = dec!(0);
    const MAX_REWARDS_REDUCTION: Decimal = dec!(0.8);
}

impl AlgorithmVersion for RewardsCalculationV2 {
    const VERSION: u32 = 2;
}

impl RewardsCalculationV2 {
    pub fn calculate_rewards(
        from_date: NaiveDate,
        to_date: NaiveDate,
        input_provider: impl PerformanceBasedAlgorithmInputProvider,
    ) -> Result<RewardsCalculatorResults, String> {
        <RewardsCalculationV2 as PerformanceBasedAlgorithm>::calculate_rewards(
            from_date,
            to_date,
            input_provider,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::performance_based_algorithm::test_utils::{
        create_rewards_table_for_region_test, test_node_id,
    };
    use crate::performance_based_algorithm::v2::RewardsCalculationV2;
    use crate::performance_based_algorithm::{BaseRewardsResults, PerformanceBasedAlgorithm};
    use crate::types::RewardableNode;
    use ic_protobuf::registry::node::v1::NodeRewardType;
    use ic_protobuf::registry::node_rewards::v2::{
        NodeRewardRate, NodeRewardRates, NodeRewardsTable,
    };
    use maplit::btreemap;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    /// Test the V2 algorithm with Type3 and Type3.1 nodes in the same country.
    ///
    /// V2 Algorithm:
    /// - Groups all Type3/Type3.1 nodes by (continent, country)
    /// - Sorts entries by base_reward (desc) then coefficient (desc)
    /// - Applies sequential coefficient reduction
    /// - ALL nodes in the group get the SAME average reward
    ///
    /// DATA: type3 base_rewards: 10000/day, coeff: 0.95, N: 2
    ///       type3.1 base_rewards: 10000/day, coeff: 0.80, N: 2
    ///
    /// After sorting by (rate desc, coeff desc):
    /// - (10000, 0.95), (10000, 0.95), (10000, 0.80), (10000, 0.80)
    ///
    /// Calculation:
    /// 1. 10000 * 1.0 = 10000, running_coeff = 0.95
    /// 2. 10000 * 0.95 = 9500, running_coeff = 0.9025
    /// 3. 10000 * 0.9025 = 9025, running_coeff = 0.722
    /// 4. 10000 * 0.722 = 7220, running_coeff = 0.5776
    ///
    /// Total = 35745, Avg = 35745 / 4 = 8936.25
    #[test]
    fn test_v2_type3_type3dot1_grouped_calculation() {
        let mut table = BTreeMap::new();
        table.insert(
            "North America,USA,California".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type3.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 304375, // -> 10000 / day
                        reward_coefficient_percent: Some(95),
                    },
                },
            },
        );
        table.insert(
            "North America,USA,Nevada".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type3dot1.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 304375, // -> 10000 / day
                        reward_coefficient_percent: Some(80),
                    },
                },
            },
        );
        let rewards_table = NodeRewardsTable { table };

        let rewardable_nodes = vec![
            // 2 Type3.1 nodes in Nevada (same country as California)
            RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type3dot1,
                region: "North America,USA,Nevada".into(),
                dc_id: "dc3".into(),
            },
            RewardableNode {
                node_id: test_node_id(2),
                node_reward_type: NodeRewardType::Type3dot1,
                region: "North America,USA,Nevada".into(),
                dc_id: "dc4".into(),
            },
            // 2 Type3 nodes in California
            RewardableNode {
                node_id: test_node_id(3),
                node_reward_type: NodeRewardType::Type3,
                region: "North America,USA,California".into(),
                dc_id: "dc1".into(),
            },
            RewardableNode {
                node_id: test_node_id(4),
                node_reward_type: NodeRewardType::Type3,
                region: "North America,USA,California".into(),
                dc_id: "dc2".into(),
            },
        ];

        let BaseRewardsResults {
            base_rewards_per_node,
            base_rewards_type3,
            ..
        } = RewardsCalculationV2::calculate_base_rewards_by_region_and_type(
            &rewards_table,
            &rewardable_nodes,
        );

        // V2: All nodes in the same country get the same average reward
        // Calculation: (10000 + 9500 + 9025 + 7220) / 4 = 8936.25
        let expected_avg = dec!(8936.25);

        // All four nodes should get the same reward
        for i in 1..=4 {
            let reward = base_rewards_per_node.get(&test_node_id(i)).unwrap();
            assert_eq!(*reward, expected_avg, "Node {} has unexpected reward", i);
        }

        // Verify the Type3RegionBaseRewards entry (single entry for the country)
        assert_eq!(base_rewards_type3.len(), 1);

        let region = &base_rewards_type3[0];
        assert_eq!(region.region, "North America:USA");
        assert_eq!(region.nodes_count, 4);
        assert_eq!(region.daily_xdr_permyriad, expected_avg);
        // Average coefficient: (0.95 + 0.95 + 0.80 + 0.80) / 4 = 0.875
        assert_eq!(region.avg_coefficient, dec!(0.875));
        // Average base rewards: 10000
        assert_eq!(region.avg_rewards_xdr_permyriad, dec!(10000));
    }

    /// Test V2 with only Type3 nodes (no Type3.1)
    #[test]
    fn test_v2_type3_only() {
        let mut table = BTreeMap::new();
        table.insert(
            "North America,USA,California".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type3.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 304375, // -> 10000 / day
                        reward_coefficient_percent: Some(90),
                    },
                },
            },
        );
        let rewards_table = NodeRewardsTable { table };

        let rewardable_nodes = vec![
            RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type3,
                region: "North America,USA,California".into(),
                dc_id: "dc1".into(),
            },
            RewardableNode {
                node_id: test_node_id(2),
                node_reward_type: NodeRewardType::Type3,
                region: "North America,USA,California".into(),
                dc_id: "dc2".into(),
            },
            RewardableNode {
                node_id: test_node_id(3),
                node_reward_type: NodeRewardType::Type3,
                region: "North America,USA,California".into(),
                dc_id: "dc3".into(),
            },
        ];

        let BaseRewardsResults {
            base_rewards_per_node,
            ..
        } = RewardsCalculationV2::calculate_base_rewards_by_region_and_type(
            &rewards_table,
            &rewardable_nodes,
        );

        // V2 with same coefficients: (10000 * 1 + 10000 * 0.9 + 10000 * 0.81) / 3
        // = (10000 + 9000 + 8100) / 3 = 27100 / 3 = 9033.333...
        let expected = dec!(27100) / dec!(3);

        for i in 1..=3 {
            let reward = base_rewards_per_node.get(&test_node_id(i)).unwrap();
            assert_eq!(*reward, expected);
        }
    }

    /// Test V2 with only Type3.1 nodes (no Type3)
    #[test]
    fn test_v2_type3dot1_only() {
        let mut table = BTreeMap::new();
        table.insert(
            "North America,USA,Nevada".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type3dot1.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 304375, // -> 10000 / day
                        reward_coefficient_percent: Some(80),
                    },
                },
            },
        );
        let rewards_table = NodeRewardsTable { table };

        let rewardable_nodes = vec![
            RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type3dot1,
                region: "North America,USA,Nevada".into(),
                dc_id: "dc1".into(),
            },
            RewardableNode {
                node_id: test_node_id(2),
                node_reward_type: NodeRewardType::Type3dot1,
                region: "North America,USA,Nevada".into(),
                dc_id: "dc2".into(),
            },
        ];

        let BaseRewardsResults {
            base_rewards_per_node,
            ..
        } = RewardsCalculationV2::calculate_base_rewards_by_region_and_type(
            &rewards_table,
            &rewardable_nodes,
        );

        // V2: (10000 * 1 + 10000 * 0.8) / 2 = (10000 + 8000) / 2 = 9000
        let expected = dec!(9000);

        for i in 1..=2 {
            let reward = base_rewards_per_node.get(&test_node_id(i)).unwrap();
            assert_eq!(*reward, expected);
        }
    }

    /// Test V2 with non-Type3 nodes (should work the same as V1)
    #[test]
    fn test_v2_non_type3_nodes() {
        let rewards_table = create_rewards_table_for_region_test();

        let rewardable_nodes = vec![RewardableNode {
            node_id: test_node_id(1),
            node_reward_type: NodeRewardType::Type1,
            region: "Europe,Switzerland".into(),
            dc_id: "dc1".into(),
        }];

        let BaseRewardsResults {
            base_rewards_per_node,
            ..
        } = RewardsCalculationV2::calculate_base_rewards_by_region_and_type(
            &rewards_table,
            &rewardable_nodes,
        );

        // Type1 should get standard daily rate (10000)
        let reward = base_rewards_per_node.get(&test_node_id(1)).unwrap();
        assert_eq!(*reward, dec!(10000));
    }

    /// Test V2 sorting behavior: higher base_reward nodes are processed first,
    /// then higher coefficient nodes
    #[test]
    fn test_v2_sorting_by_rate_then_coefficient() {
        let mut table = BTreeMap::new();
        // High rate, high coeff
        table.insert(
            "North America,USA,California".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type3.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 608750, // -> 20000 / day
                        reward_coefficient_percent: Some(80),
                    },
                },
            },
        );
        // Low rate, low coeff
        table.insert(
            "North America,USA,Nevada".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type3dot1.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 304375, // -> 10000 / day
                        reward_coefficient_percent: Some(90),
                    },
                },
            },
        );
        let rewards_table = NodeRewardsTable { table };

        let rewardable_nodes = vec![
            // Lower rate Type3.1 node
            RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type3dot1,
                region: "North America,USA,Nevada".into(),
                dc_id: "dc2".into(),
            },
            // Higher rate Type3 node
            RewardableNode {
                node_id: test_node_id(2),
                node_reward_type: NodeRewardType::Type3,
                region: "North America,USA,California".into(),
                dc_id: "dc1".into(),
            },
        ];

        let BaseRewardsResults {
            base_rewards_per_node,
            base_rewards_type3,
            ..
        } = RewardsCalculationV2::calculate_base_rewards_by_region_and_type(
            &rewards_table,
            &rewardable_nodes,
        );

        // V2 sorts by rate desc, then coeff desc:
        // Entry 1: (20000, 0.80) - processed first
        // Entry 2: (10000, 0.90) - processed second
        //
        // Calculation:
        // 1. 20000 * 1.0 = 20000, running_coeff = 0.80
        // 2. 10000 * 0.80 = 8000, running_coeff = 0.72
        //
        // Total = 28000, Avg = 14000
        let expected_avg = dec!(14000);

        for i in 1..=2 {
            let reward = base_rewards_per_node.get(&test_node_id(i)).unwrap();
            assert_eq!(*reward, expected_avg, "Node {} has unexpected reward", i);
        }

        // Verify region data
        assert_eq!(base_rewards_type3.len(), 1);
        let region = &base_rewards_type3[0];
        assert_eq!(region.nodes_count, 2);
        // Avg rate: (20000 + 10000) / 2 = 15000
        assert_eq!(region.avg_rewards_xdr_permyriad, dec!(15000));
        // Avg coeff: (0.90 + 0.80) / 2 = 0.85
        assert_eq!(region.avg_coefficient, dec!(0.85));
    }
}

#[cfg(test)]
mod e2e_tests;
