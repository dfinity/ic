use crate::performance_based_algorithm::PerformanceBasedAlgorithmInputProvider;
use crate::performance_based_algorithm::test_utils::{
    test_node_id, test_provider_id, test_subnet_id,
};
use crate::performance_based_algorithm::v2::RewardsCalculationV2;
use crate::types::{NodeMetricsDailyRaw, RewardableNode};
use chrono::NaiveDate;
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use maplit::btreemap;
use rust_decimal_macros::dec;
use std::collections::{BTreeMap, HashMap};

#[derive(Default, Clone)]
pub struct FakeInputProvider {
    rewards_tables: BTreeMap<NaiveDate, NodeRewardsTable>,
    daily_metrics: BTreeMap<NaiveDate, BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>>>,
    rewardable_nodes: BTreeMap<NaiveDate, BTreeMap<PrincipalId, Vec<RewardableNode>>>,
}

impl FakeInputProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rewards_table(mut self, day: NaiveDate, table: NodeRewardsTable) -> Self {
        self.rewards_tables.insert(day, table);
        self
    }

    pub fn add_daily_metrics(
        mut self,
        day: NaiveDate,
        subnet_id: SubnetId,
        metrics: Vec<NodeMetricsDailyRaw>,
    ) -> Self {
        self.daily_metrics
            .entry(day)
            .or_default()
            .insert(subnet_id, metrics);
        self
    }

    pub fn add_rewardable_nodes(
        mut self,
        day: NaiveDate,
        provider_id: PrincipalId,
        nodes: Vec<RewardableNode>,
    ) -> Self {
        self.rewardable_nodes
            .entry(day)
            .or_default()
            .insert(provider_id, nodes);
        self
    }

    pub fn create_rewards_table_v2_test() -> NodeRewardsTable {
        let mut table = BTreeMap::new();

        // Type1 nodes - Europe
        table.insert(
            "Europe,Switzerland".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type1.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 304375, // 10000/day
                        reward_coefficient_percent: None,
                    },
                },
            },
        );

        // Type3 nodes - North America (coefficient 95%)
        table.insert(
            "North America,USA,California".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type3.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 304375, // 10000/day
                        reward_coefficient_percent: Some(95),
                    },
                },
            },
        );

        // Type3.1 nodes - North America (coefficient 80%)
        table.insert(
            "North America,USA,Nevada".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type3dot1.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 304375, // 10000/day
                        reward_coefficient_percent: Some(80),
                    },
                },
            },
        );

        NodeRewardsTable { table }
    }
}

impl PerformanceBasedAlgorithmInputProvider for FakeInputProvider {
    fn get_rewards_table(&self, day: &NaiveDate) -> Result<NodeRewardsTable, String> {
        self.rewards_tables
            .get(day)
            .cloned()
            .ok_or_else(|| format!("No rewards table found for day {day}"))
    }

    fn get_daily_metrics_by_subnet(
        &self,
        day: &NaiveDate,
    ) -> Result<BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>>, String> {
        self.daily_metrics
            .get(day)
            .cloned()
            .ok_or_else(|| format!("No metrics found for day {day}"))
    }

    fn get_rewardable_nodes(
        &self,
        day: &NaiveDate,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, String> {
        self.rewardable_nodes
            .get(day)
            .cloned()
            .ok_or_else(|| format!("No rewardable nodes found for day {day}"))
    }
}

/// **Scenario**: V2 algorithm with Type3 and Type3.1 nodes in same country
/// **Expected**: All Type3/Type3.1 nodes in the same country get the same average reward
/// **Key Test**: V2 groups all Type3* nodes by country and sorts by (rate desc, coeff desc)
///
/// DATA: type3 base_rewards: 10000, coeff: 0.95, N: 2
///       type3.1 base_rewards: 10000, coeff: 0.8, N: 2
///       1 type3 node has performance penalty
///
/// V2 Algorithm:
/// - All 4 nodes grouped under "North America:USA"
/// - Sorted by (rate desc, coeff desc): (10000, 0.95), (10000, 0.95), (10000, 0.80), (10000, 0.80)
/// - Calculation:
///   1. 10000 * 1.0 = 10000, running_coeff = 0.95
///   2. 10000 * 0.95 = 9500, running_coeff = 0.9025
///   3. 10000 * 0.9025 = 9025, running_coeff = 0.722
///   4. 10000 * 0.722 = 7220, running_coeff = 0.5776
/// - Total = 35745, Avg = 8936.25
/// - All 4 nodes get base_rewards = 8936.25
#[test]
fn test_v2_type3_type3dot1_grouped_with_performance_penalty() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Node 1 (Type3) will have high failure rate (penalty applied)
    // Nodes 2, 3, 4 will have good performance (no penalty)
    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, FakeInputProvider::create_rewards_table_v2_test())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                // Type3 node 1: 90% failure rate (will get max penalty)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 10,
                    num_blocks_failed: 90, // 90% failure rate
                },
                // Type3 node 2: 0% failure rate (good performance)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                },
                // Type3.1 node 3: 0% failure rate (good performance)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(3),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                },
                // Type3.1 node 4: 0% failure rate (good performance)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(4),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![
                // 2 Type3 nodes in California
                RewardableNode {
                    node_id: test_node_id(1),
                    node_reward_type: NodeRewardType::Type3,
                    region: "North America,USA,California".into(),
                    dc_id: "dc_ca_1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(2),
                    node_reward_type: NodeRewardType::Type3,
                    region: "North America,USA,California".into(),
                    dc_id: "dc_ca_2".into(),
                },
                // 2 Type3.1 nodes in Nevada (same country as California)
                RewardableNode {
                    node_id: test_node_id(3),
                    node_reward_type: NodeRewardType::Type3dot1,
                    region: "North America,USA,Nevada".into(),
                    dc_id: "dc_nv_1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(4),
                    node_reward_type: NodeRewardType::Type3dot1,
                    region: "North America,USA,Nevada".into(),
                    dc_id: "dc_nv_2".into(),
                },
            ],
        );

    let result = RewardsCalculationV2::calculate_rewards(day, day, fake_input_provider)
        .expect("Calculation should succeed");

    assert_eq!(result.algorithm_version, 2);

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // V2: All Type3/Type3.1 nodes in the same country are grouped together
    assert_eq!(provider_result.type3_base_rewards.len(), 1);

    let region = &provider_result.type3_base_rewards[0];
    assert_eq!(region.region, "North America:USA");
    assert_eq!(region.nodes_count, 4);
    // Average coefficient: (0.95 + 0.95 + 0.80 + 0.80) / 4 = 0.875
    assert_eq!(region.avg_coefficient, dec!(0.875));
    assert_eq!(region.avg_rewards_xdr_permyriad, dec!(10000));
    // (10000 + 9500 + 9025 + 7220) / 4 = 8936.25
    assert_eq!(region.daily_xdr_permyriad, dec!(8936.25));

    // Convert node_results into a HashMap for direct access by node_id
    let node_results_map: HashMap<_, _> = provider_result
        .daily_nodes_rewards
        .iter()
        .map(|n| (n.node_id, n))
        .collect();

    // All nodes get the same base rewards (8936.25)
    let expected_base_rewards = dec!(8936.25);

    for i in 1..=4 {
        let node = node_results_map.get(&test_node_id(i)).unwrap();
        assert_eq!(
            node.base_rewards_xdr_permyriad, expected_base_rewards,
            "Node {} has unexpected base rewards",
            i
        );
    }

    // Verify node 1 has performance penalty (90% failure rate > 60% max threshold)
    let node1 = node_results_map.get(&test_node_id(1)).unwrap();
    assert_eq!(node1.rewards_reduction, dec!(0.8)); // Max penalty
    assert_eq!(node1.performance_multiplier, dec!(0.2)); // 1 - 0.8

    // Verify other nodes have no penalty
    for i in 2..=4 {
        let node = node_results_map.get(&test_node_id(i)).unwrap();
        assert_eq!(
            node.performance_multiplier,
            dec!(1.0),
            "Node {} should have no penalty",
            i
        );
    }
}

/// Test that V2 produces different results than V1 for Type3/Type3.1 nodes
/// due to the different sorting/calculation order
#[test]
fn test_v2_differs_from_v1() {
    use crate::performance_based_algorithm::v1::RewardsCalculationV1;

    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, FakeInputProvider::create_rewards_table_v2_test())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(3),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(4),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![
                // 2 Type3 nodes in California
                RewardableNode {
                    node_id: test_node_id(1),
                    node_reward_type: NodeRewardType::Type3,
                    region: "North America,USA,California".into(),
                    dc_id: "dc_ca_1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(2),
                    node_reward_type: NodeRewardType::Type3,
                    region: "North America,USA,California".into(),
                    dc_id: "dc_ca_2".into(),
                },
                // 2 Type3.1 nodes in Nevada (same country)
                RewardableNode {
                    node_id: test_node_id(3),
                    node_reward_type: NodeRewardType::Type3dot1,
                    region: "North America,USA,Nevada".into(),
                    dc_id: "dc_nv_1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(4),
                    node_reward_type: NodeRewardType::Type3dot1,
                    region: "North America,USA,Nevada".into(),
                    dc_id: "dc_nv_2".into(),
                },
            ],
        );

    let v1_result = RewardsCalculationV1::calculate_rewards(day, day, fake_input_provider.clone())
        .expect("V1 calculation should succeed");
    let v2_result = RewardsCalculationV2::calculate_rewards(day, day, fake_input_provider)
        .expect("V2 calculation should succeed");

    assert_eq!(v1_result.algorithm_version, 1);
    assert_eq!(v2_result.algorithm_version, 2);

    let v1_provider = &v1_result.daily_results[&day].provider_results[&provider_id];
    let v2_provider = &v2_result.daily_results[&day].provider_results[&provider_id];

    // Both V1 and V2 group all Type3/Type3.1 nodes in the same country together
    assert_eq!(v1_provider.type3_base_rewards.len(), 1);
    assert_eq!(v2_provider.type3_base_rewards.len(), 1);

    // V1 averages rates and coefficients first, then applies reduction
    // V2 sorts by (rate desc, coeff desc) and applies reduction sequentially
    //
    // V1 calculation:
    // - avg_rate = 10000, avg_coeff = 0.875
    // - rewards: 10000 * 0.875^0 + 10000 * 0.875^1 + 10000 * 0.875^2 + 10000 * 0.875^3
    // - = 10000 + 8750 + 7656.25 + 6699.21875 = 33105.46875
    // - avg = 8276.3671875
    //
    // V2 calculation:
    // - sorted: (10000, 0.95), (10000, 0.95), (10000, 0.80), (10000, 0.80)
    // - rewards: 10000*1 + 10000*0.95 + 10000*0.9025 + 10000*0.722 = 35745
    // - avg = 8936.25

    let v1_region = &v1_provider.type3_base_rewards[0];
    let v2_region = &v2_provider.type3_base_rewards[0];

    // The daily rewards should differ due to different calculation methods
    assert_ne!(
        v1_region.daily_xdr_permyriad, v2_region.daily_xdr_permyriad,
        "V1 and V2 should produce different daily rewards"
    );

    // Verify expected V1 result
    assert_eq!(v1_region.daily_xdr_permyriad, dec!(8276.3671875));

    // Verify expected V2 result
    assert_eq!(v2_region.daily_xdr_permyriad, dec!(8936.25));

    // Total adjusted rewards should also differ
    assert_ne!(
        v1_provider.total_adjusted_rewards_xdr_permyriad,
        v2_provider.total_adjusted_rewards_xdr_permyriad
    );
}

// ------------------------------------------------------------------------------------------------
// Type4 Reward Calculation Tests
// ------------------------------------------------------------------------------------------------

/// **Scenario**: Type4 node in a region NOT present in the rewards table
/// **Expected**: Falls back to default rewards (1 permyriad, coefficient 1.0)
/// **Key Test**: Verifies that missing type4 entries in rewards table result in minimal rewards
#[test]
fn test_type4_not_in_rewards_table() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Use standard rewards table which does NOT have type4 entries
    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, FakeInputProvider::create_rewards_table_v2_test())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(1),
                num_blocks_proposed: 100,
                num_blocks_failed: 5, // 4.76% failure rate
            }],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type4,
                region: "Europe,Germany,Berlin".into(), // Region with no type4 entry
                dc_id: "dc1".into(),
            }],
        );

    let result = RewardsCalculationV2::calculate_rewards(day, day, fake_input_provider)
        .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Type4 should NOT use type3 logic (no grouping by country)
    assert!(provider_result.type3_base_rewards.is_empty());

    // Verify base rewards entry exists for type4
    let type4_base_rewards = provider_result
        .base_rewards
        .iter()
        .find(|r| r.node_reward_type == NodeRewardType::Type4)
        .expect("Should have base rewards for type4");

    // When type is not in rewards table, it defaults to 1 permyriad monthly
    // Daily = 1 / 30.4375 (REWARDS_TABLE_DAYS) ≈ 0.0328...
    assert_eq!(type4_base_rewards.monthly_xdr_permyriad, dec!(1));

    // Verify node rewards
    let node_rewards = &provider_result.daily_nodes_rewards[0];
    assert_eq!(node_rewards.node_id, test_node_id(1));
    assert_eq!(node_rewards.node_reward_type, NodeRewardType::Type4);

    // Base rewards should be 1 / 30.4375 ≈ 0.0328...
    assert_eq!(
        node_rewards.base_rewards_xdr_permyriad,
        dec!(0.0328542094455852156057494867)
    );

    // With good performance (relative FR = 0), performance_multiplier should be 1.0
    assert_eq!(node_rewards.performance_multiplier, dec!(1.0));
    assert_eq!(node_rewards.rewards_reduction, dec!(0.0));

    // Adjusted rewards = base * performance_multiplier ≈ 0.0328...
    assert_eq!(
        node_rewards.adjusted_rewards_xdr_permyriad,
        dec!(0.0328542094455852156057494867)
    );

    // Total rewards should be essentially zero (truncated to 0)
    assert_eq!(provider_result.total_adjusted_rewards_xdr_permyriad, 0);
}

/// **Scenario**: Type4 node in a region where type4 is explicitly set to 0 XDR
/// **Expected**: Node receives exactly 0 rewards
/// **Key Test**: Verifies that explicit 0 rate results in 0 rewards (different from fallback behavior)
#[test]
fn test_type4_explicit_zero_rate() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Create a rewards table with type4 explicitly set to 0
    let mut rewards_table = FakeInputProvider::create_rewards_table_v2_test();
    rewards_table.table.insert(
        "North America,Canada,BC".to_string(),
        NodeRewardRates {
            rates: btreemap! {
                NodeRewardType::Type4.to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 0, // Explicitly 0
                    reward_coefficient_percent: None,
                },
            },
        },
    );

    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, rewards_table)
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0, // Perfect performance
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0, // Perfect performance
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![
                RewardableNode {
                    node_id: test_node_id(1),
                    node_reward_type: NodeRewardType::Type4,
                    region: "North America,Canada,BC".into(),
                    dc_id: "dc1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(2),
                    node_reward_type: NodeRewardType::Type4,
                    region: "North America,Canada,BC".into(),
                    dc_id: "dc2".into(),
                },
            ],
        );

    let result = RewardsCalculationV2::calculate_rewards(day, day, fake_input_provider)
        .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Type4 should NOT use type3 logic
    assert!(provider_result.type3_base_rewards.is_empty());

    // Verify base rewards entry exists for type4 with 0 rate
    let type4_base_rewards = provider_result
        .base_rewards
        .iter()
        .find(|r| r.node_reward_type == NodeRewardType::Type4)
        .expect("Should have base rewards for type4");

    assert_eq!(type4_base_rewards.monthly_xdr_permyriad, dec!(0));
    assert_eq!(type4_base_rewards.daily_xdr_permyriad, dec!(0));

    // Verify both nodes have 0 base rewards
    let node_results: HashMap<_, _> = provider_result
        .daily_nodes_rewards
        .iter()
        .map(|n| (n.node_id, n))
        .collect();

    let node1 = node_results.get(&test_node_id(1)).unwrap();
    let node2 = node_results.get(&test_node_id(2)).unwrap();

    // Both nodes should have exactly 0 rewards
    assert_eq!(node1.base_rewards_xdr_permyriad, dec!(0));
    assert_eq!(node2.base_rewards_xdr_permyriad, dec!(0));
    assert_eq!(node1.adjusted_rewards_xdr_permyriad, dec!(0));
    assert_eq!(node2.adjusted_rewards_xdr_permyriad, dec!(0));

    // Total rewards should be exactly 0
    assert_eq!(provider_result.total_adjusted_rewards_xdr_permyriad, 0);
    assert_eq!(provider_result.total_base_rewards_xdr_permyriad, 0);
}

/// **Scenario**: Type4 node in a region that IS present in the rewards table
/// **Expected**: Uses the configured rate from rewards table, no reduction coefficient logic
/// **Key Test**: Verifies type4 uses flat per-node rewards (not type3 grouped logic)
#[test]
fn test_type4_in_rewards_table() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Create a rewards table with type4 entry
    let mut rewards_table = FakeInputProvider::create_rewards_table_v2_test();
    rewards_table.table.insert(
        "Europe,Germany,Berlin".to_string(),
        NodeRewardRates {
            rates: btreemap! {
                NodeRewardType::Type4.to_string() => NodeRewardRate {
                    xdr_permyriad_per_node_per_month: 608750, // 20000/day
                    reward_coefficient_percent: Some(85), // Should be ignored for type4
                },
            },
        },
    );

    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, rewards_table)
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5, // 4.76% failure rate
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 10, // 9.09% failure rate
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![
                RewardableNode {
                    node_id: test_node_id(1),
                    node_reward_type: NodeRewardType::Type4,
                    region: "Europe,Germany,Berlin".into(),
                    dc_id: "dc1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(2),
                    node_reward_type: NodeRewardType::Type4,
                    region: "Europe,Germany,Berlin".into(),
                    dc_id: "dc2".into(),
                },
            ],
        );

    let result = RewardsCalculationV2::calculate_rewards(day, day, fake_input_provider)
        .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Type4 should NOT use type3 logic - no country-level grouping
    assert!(
        provider_result.type3_base_rewards.is_empty(),
        "Type4 should not have type3 base rewards grouping"
    );

    // Verify base rewards entry exists for type4
    let type4_base_rewards = provider_result
        .base_rewards
        .iter()
        .find(|r| r.node_reward_type == NodeRewardType::Type4)
        .expect("Should have base rewards for type4");

    assert_eq!(type4_base_rewards.monthly_xdr_permyriad, dec!(608750));
    assert_eq!(type4_base_rewards.daily_xdr_permyriad, dec!(20000)); // 608750 / 30.4375

    // Verify both nodes have the same base rewards (no reduction coefficient applied)
    let node_results: HashMap<_, _> = provider_result
        .daily_nodes_rewards
        .iter()
        .map(|n| (n.node_id, n))
        .collect();

    let node1 = node_results.get(&test_node_id(1)).unwrap();
    let node2 = node_results.get(&test_node_id(2)).unwrap();

    // Both nodes should have the same base rewards (no grouping/reduction like type3)
    assert_eq!(node1.base_rewards_xdr_permyriad, dec!(20000));
    assert_eq!(node2.base_rewards_xdr_permyriad, dec!(20000));

    // Verify subnet failure rate (75th percentile of 4.76% and 9.09% = 9.09%)
    let subnet_fr = daily_result.subnets_failure_rate[&subnet_id];
    assert_eq!(subnet_fr, dec!(0.0909090909090909090909090909));

    // Node 1 (4.76% failure rate) - below subnet FR, no penalty
    assert_eq!(node1.performance_multiplier, dec!(1.0));
    assert_eq!(node1.rewards_reduction, dec!(0.0));
    assert_eq!(node1.adjusted_rewards_xdr_permyriad, dec!(20000));

    // Node 2 (9.09% failure rate = subnet FR) - relative FR = 0, no penalty
    assert_eq!(node2.performance_multiplier, dec!(1.0));
    assert_eq!(node2.rewards_reduction, dec!(0.0));
    assert_eq!(node2.adjusted_rewards_xdr_permyriad, dec!(20000));

    // Total rewards = 20000 + 20000 = 40000
    assert_eq!(provider_result.total_adjusted_rewards_xdr_permyriad, 40000);
    assert_eq!(provider_result.total_base_rewards_xdr_permyriad, 40000);
}
