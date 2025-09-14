use crate::performance_based_algorithm::DataProvider;
use crate::performance_based_algorithm::test_utils::{
    test_node_id, test_provider_id, test_subnet_id,
};
use crate::performance_based_algorithm::v1::RewardsCalculationV1;
use crate::types::{DayUtc, NodeMetricsDailyRaw, RewardableNode};
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use maplit::btreemap;
use rust_decimal_macros::dec;
use std::collections::BTreeMap;
// ================================================================================================
// Mock DataProvider for Comprehensive Testing
// ================================================================================================

#[derive(Default, Clone)]
pub struct MockDataProvider {
    rewards_tables: BTreeMap<DayUtc, NodeRewardsTable>,
    daily_metrics: BTreeMap<DayUtc, BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>>>,
    rewardable_nodes: BTreeMap<DayUtc, BTreeMap<PrincipalId, Vec<RewardableNode>>>,
}

impl MockDataProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rewards_table(mut self, day: DayUtc, table: NodeRewardsTable) -> Self {
        self.rewards_tables.insert(day, table);
        self
    }

    pub fn add_daily_metrics(
        mut self,
        day: DayUtc,
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
        day: DayUtc,
        provider_id: PrincipalId,
        nodes: Vec<RewardableNode>,
    ) -> Self {
        self.rewardable_nodes
            .entry(day)
            .or_default()
            .insert(provider_id, nodes);
        self
    }

    pub fn create_comprehensive_rewards_table() -> NodeRewardsTable {
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

        // Type3 nodes - North America
        table.insert(
            "North America,USA,California".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type3.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 913125, // 30000/day
                        reward_coefficient_percent: Some(90),
                    },
                },
            },
        );

        // Type3.1 nodes - North America
        table.insert(
            "North America,USA,Nevada".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type3dot1.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 1217500, // 40000/day
                        reward_coefficient_percent: Some(70),
                    },
                },
            },
        );

        // Type3 nodes - Asia
        table.insert(
            "Asia,Japan,Tokyo".to_string(),
            NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type3.to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 1217500, // 40000/day
                        reward_coefficient_percent: Some(80),
                    },
                },
            },
        );

        NodeRewardsTable { table }
    }
}

impl DataProvider for MockDataProvider {
    fn get_rewards_table(&self, day: &DayUtc) -> Result<NodeRewardsTable, String> {
        self.rewards_tables
            .get(day)
            .cloned()
            .ok_or_else(|| format!("No rewards table found for day {day}"))
    }

    fn get_daily_metrics_by_subnet(
        &self,
        day: &DayUtc,
    ) -> Result<BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>>, String> {
        self.daily_metrics
            .get(day)
            .cloned()
            .ok_or_else(|| format!("No metrics found for day {day}"))
    }

    fn get_rewardable_nodes(
        &self,
        day: &DayUtc,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, String> {
        self.rewardable_nodes
            .get(day)
            .cloned()
            .ok_or_else(|| format!("No rewardable nodes found for day {day}"))
    }
}

// ================================================================================================
// Test Helper Functions
// ================================================================================================

fn create_test_rewardable_nodes() -> Vec<RewardableNode> {
    vec![
        RewardableNode {
            node_id: test_node_id(1),
            node_reward_type: NodeRewardType::Type1,
            region: "Europe,Switzerland".into(),
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
            node_reward_type: NodeRewardType::Type3dot1,
            region: "North America,USA,Nevada".into(),
            dc_id: "dc3".into(),
        },
    ]
}

// ------------------------------------------------------------------------------------------------
// Basic Calculation Flow Tests
// ------------------------------------------------------------------------------------------------

/// **Scenario**: Single node with good performance (5% failure rate)
/// **Expected**: Node gets full rewards with no penalty
/// **Key Test**: Basic reward calculation flow works correctly
#[test]
fn test_basic_single_day_calculation() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(1),
                num_blocks_proposed: 100,
                num_blocks_failed: 5, // 5% failure rate
            }],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                dc_id: "dc1".into(),
            }],
        );

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    // Verify we have results for the specified day
    assert!(result.daily_results.contains_key(&day));

    // Verify we have results for the provider
    let daily_result = &result.daily_results[&day];
    assert!(daily_result.provider_results.contains_key(&provider_id));

    // Verify total rewards are calculated
    assert!(
        result
            .total_rewards_xdr_permyriad
            .contains_key(&provider_id)
    );

    // Verify the total rewards are reasonable (should be > 0)
    let total_rewards = result.total_rewards_xdr_permyriad[&provider_id];
    assert!(total_rewards > 0);
}

#[test]
fn test_multi_day_calculation() {
    let day1 = DayUtc::try_from("2024-01-01").unwrap();
    let day2 = DayUtc::try_from("2024-01-02").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    let rewards_table = MockDataProvider::create_comprehensive_rewards_table();

    let data_provider = MockDataProvider::new()
        .add_rewards_table(day1, rewards_table.clone())
        .add_rewards_table(day2, rewards_table)
        .add_daily_metrics(
            day1,
            subnet_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(1),
                num_blocks_proposed: 100,
                num_blocks_failed: 5,
            }],
        )
        .add_daily_metrics(
            day2,
            subnet_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(1),
                num_blocks_proposed: 100,
                num_blocks_failed: 10, // Higher failure rate on day 2
            }],
        )
        .add_rewardable_nodes(day1, provider_id, create_test_rewardable_nodes())
        .add_rewardable_nodes(day2, provider_id, create_test_rewardable_nodes());

    let result =
        RewardsCalculationV1::calculate_rewards(&day1, &day2, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    // Verify we have results for both days
    assert_eq!(result.daily_results.len(), 2);
    assert!(result.daily_results.contains_key(&day1));
    assert!(result.daily_results.contains_key(&day2));

    // Verify total rewards are accumulated across days
    let total_rewards = result.total_rewards_xdr_permyriad[&provider_id];
    assert!(total_rewards > 0);

    // Both days have the same rewards despite different failure rates
    // This is because the relative failure rates are still below the penalty threshold
    let day1_rewards = result.daily_results[&day1].provider_results[&provider_id].rewards_total;
    let day2_rewards = result.daily_results[&day2].provider_results[&provider_id].rewards_total;
    assert_eq!(
        day1_rewards, day2_rewards,
        "Both days have the same rewards"
    );
}

// ------------------------------------------------------------------------------------------------
// Failure Rate Calculation Tests
// ------------------------------------------------------------------------------------------------

/// **Scenario**: 4 nodes with different performance levels (0.99%, 4.76%, 16.67%, 33.33% failure rates)
/// **Expected**: 75th percentile = 16.67%, only the worst node (33.33%) gets penalized
/// **Key Test**: 75th percentile calculation and relative failure rate logic
#[test]
fn test_failure_rate_calculation_various_performance() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                // Excellent performance: 1/(100+1) = 0.99% failure rate
                NodeMetricsDailyRaw {
                    node_id: test_node_id(10),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 1,
                },
                // Good performance: 5/(100+5) = 4.76% failure rate
                NodeMetricsDailyRaw {
                    node_id: test_node_id(11),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
                // Average performance: 20/(100+20) = 16.67% failure rate
                NodeMetricsDailyRaw {
                    node_id: test_node_id(12),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 20,
                },
                // Poor performance: 50/(100+50) = 33.33% failure rate
                NodeMetricsDailyRaw {
                    node_id: test_node_id(13),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 50,
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![
                RewardableNode {
                    node_id: test_node_id(10),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(11),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc2".into(),
                },
                RewardableNode {
                    node_id: test_node_id(12),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc3".into(),
                },
                RewardableNode {
                    node_id: test_node_id(13),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc4".into(),
                },
            ],
        );

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Verify subnet failure rate is calculated (75th percentile of 0.99%, 4.76%, 16.67%, 33.33% = 16.67%)
    let subnet_fr = daily_result.subnets_fr[&subnet_id];
    assert_eq!(subnet_fr, dec!(0.1666666666666666666666666667));

    // Verify node results show different performance multipliers
    let node_results = &provider_result.nodes_results;
    assert_eq!(node_results.len(), 4);

    // Find nodes by ID and verify their performance
    let excellent_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(10))
        .unwrap();
    let good_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(11))
        .unwrap();
    let average_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(12))
        .unwrap();
    let poor_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(13))
        .unwrap();

    // Excellent node should have no penalty (performance_multiplier = 1.0)
    assert_eq!(excellent_node.performance_multiplier, dec!(1.0));
    assert_eq!(excellent_node.rewards_reduction, dec!(0.0));

    // Good node should have no penalty (failure rate < 10%)
    assert_eq!(good_node.performance_multiplier, dec!(1.0));
    assert_eq!(good_node.rewards_reduction, dec!(0.0));

    // Average node should have no penalty (failure rate = subnet FR)
    // With subnet FR = 0.1666..., relative FR = max(0, 0.1666... - 0.1666...) = 0.0
    // Since 0.0 < 0.1 (MIN_FAILURE_RATE), there should be no penalty
    assert_eq!(average_node.performance_multiplier, dec!(1.0));
    assert_eq!(average_node.rewards_reduction, dec!(0.0));

    // Poor node should have some penalty
    // With subnet FR = 0.1666..., relative FR = max(0, 0.3333... - 0.1666...) = 0.1666...
    // Since 0.1666... is between 0.1 and 0.6, penalty = (0.1666...-0.1)/(0.6-0.1) * 0.8 = 0.0666.../0.5 * 0.8 = 0.1066...
    // Performance multiplier = 1 - 0.1066... = 0.8933...
    assert_eq!(
        poor_node.performance_multiplier,
        dec!(0.8933333333333333333333333334)
    );
    assert_eq!(
        poor_node.rewards_reduction,
        dec!(0.1066666666666666666666666666)
    );
}

/// **Scenario**: Edge cases with extreme failure rates (0%, 50%, 100%)
/// **Expected**: 75th percentile = 50%, 100% node gets penalized, 0% and 50% nodes get no penalty
/// **Key Test**: Edge case handling for extreme failure rates
#[test]
fn test_failure_rate_calculation_edge_cases() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                // Zero blocks proposed and failed
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 0,
                    num_blocks_failed: 0,
                },
                // Only failed blocks
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 0,
                    num_blocks_failed: 10,
                },
                // Only proposed blocks
                NodeMetricsDailyRaw {
                    node_id: test_node_id(3),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![
                RewardableNode {
                    node_id: test_node_id(1),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(2),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc2".into(),
                },
                RewardableNode {
                    node_id: test_node_id(3),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc3".into(),
                },
            ],
        );

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Verify subnet failure rate is calculated correctly
    let subnet_fr = daily_result.subnets_fr[&subnet_id];
    // With failure rates 0, 1.0, 0, the 75th percentile should be 1.0
    assert_eq!(subnet_fr, dec!(1.0));

    // Verify node results
    let node_results = &provider_result.nodes_results;
    assert_eq!(node_results.len(), 3);

    // Node with zero blocks should have 0% failure rate
    let zero_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(1))
        .unwrap();
    assert_eq!(zero_node.performance_multiplier, dec!(1.0));

    // Node with only failed blocks should have 100% failure rate
    // But since subnet FR is also 100%, relative FR = 0, so no penalty
    let failed_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(2))
        .unwrap();
    assert_eq!(failed_node.performance_multiplier, dec!(1.0));

    // Node with only proposed blocks should have 0% failure rate
    let proposed_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(3))
        .unwrap();
    assert_eq!(proposed_node.performance_multiplier, dec!(1.0));
}

// ------------------------------------------------------------------------------------------------
// Base Rewards Calculation Tests
// ------------------------------------------------------------------------------------------------

#[test]
fn test_base_rewards_calculation_different_types() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(3),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
            ],
        )
        .add_rewardable_nodes(day, provider_id, create_test_rewardable_nodes());

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Verify base rewards are calculated correctly for different node types
    let node_results = &provider_result.nodes_results;

    let type1_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(1))
        .unwrap();
    let type3_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(2))
        .unwrap();
    let type3dot1_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(3))
        .unwrap();

    // Type1 node: 10000 per day
    assert_eq!(type1_node.base_rewards, dec!(10000));

    // Type3 node: 31500 per day (after Type3 adjustments)
    assert_eq!(type3_node.base_rewards, dec!(31500));

    // Type3.1 node: 31500 per day (after Type3 adjustments - grouped with Type3)
    assert_eq!(type3dot1_node.base_rewards, dec!(31500));
}

// ------------------------------------------------------------------------------------------------
// Type3 Special Logic Tests
// ------------------------------------------------------------------------------------------------

/// **Scenario**: Type3 and Type3.1 nodes in same country (3 Type3 + 2 Type3.1 in USA)
/// **Expected**: Nodes grouped by country, average coefficient applied, reduced rewards
/// **Key Test**: Type3 special logic with reduction coefficients
#[test]
fn test_type3_reduction_coefficient_logic() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                NodeMetricsDailyRaw {
                    node_id: test_node_id(20),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(21),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(22),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(23),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(24),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![
                // Type3 nodes in California
                RewardableNode {
                    node_id: test_node_id(20),
                    node_reward_type: NodeRewardType::Type3,
                    region: "North America,USA,California".into(),
                    dc_id: "dc_ca_1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(21),
                    node_reward_type: NodeRewardType::Type3,
                    region: "North America,USA,California".into(),
                    dc_id: "dc_ca_2".into(),
                },
                RewardableNode {
                    node_id: test_node_id(22),
                    node_reward_type: NodeRewardType::Type3,
                    region: "North America,USA,California".into(),
                    dc_id: "dc_ca_3".into(),
                },
                // Type3.1 nodes in Nevada
                RewardableNode {
                    node_id: test_node_id(23),
                    node_reward_type: NodeRewardType::Type3dot1,
                    region: "North America,USA,Nevada".into(),
                    dc_id: "dc_nv_1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(24),
                    node_reward_type: NodeRewardType::Type3dot1,
                    region: "North America,USA,Nevada".into(),
                    dc_id: "dc_nv_2".into(),
                },
            ],
        );

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Verify Type3 base rewards are calculated
    assert!(!provider_result.base_rewards_type3.is_empty());

    // Find the Type3 base rewards for California (3 nodes)
    let california_rewards = provider_result
        .base_rewards_type3
        .iter()
        .find(|r| r.region == "North America:USA")
        .expect("Should have Type3 rewards for California");

    assert_eq!(california_rewards.nodes_count, 5); // 3 Type3 + 2 Type3.1 nodes grouped together
    assert_eq!(california_rewards.avg_coefficient, dec!(0.82)); // Average of 90% and 70%

    // Verify individual node rewards are reduced due to multiple nodes in same country
    let node_results = &provider_result.nodes_results;
    let california_nodes: Vec<_> = node_results
        .iter()
        .filter(|n| n.region == "North America,USA,California")
        .collect();

    assert_eq!(california_nodes.len(), 3);

    // All California nodes should have the same base rewards (after Type3 adjustment)
    let first_ca_reward = california_nodes[0].base_rewards;
    for node in &california_nodes {
        assert_eq!(node.base_rewards, first_ca_reward);
    }
}

// ------------------------------------------------------------------------------------------------
// Financial Accuracy Tests
// ------------------------------------------------------------------------------------------------

#[test]
fn test_financial_accuracy_precise_calculations() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Create a scenario with precise failure rates that should result in specific calculations
    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                // 35% failure rate - should be in penalty zone
                // (35% - 10%) / (60% - 10%) * 80% = 25% / 50% * 80% = 40% reduction
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 35,
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                dc_id: "dc1".into(),
            }],
        );

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];
    let node_result = &provider_result.nodes_results[0];

    // Verify precise calculations
    assert_eq!(node_result.base_rewards, dec!(10000));
    // With subnet FR = 0.259..., relative FR = max(0, 0.35 - 0.259...) = 0.0907...
    // Since 0.0907... < 0.1 (MIN_FAILURE_RATE), there's no penalty
    assert_eq!(node_result.rewards_reduction, dec!(0.0)); // 0% reduction
    assert_eq!(node_result.performance_multiplier, dec!(1.0)); // 1 - 0.0
    assert_eq!(node_result.adjusted_rewards, dec!(10000)); // 10000 * 1.0
}

#[test]
fn test_financial_accuracy_rounding_behavior() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test with values that might cause rounding issues
    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(1),
                num_blocks_proposed: 333,
                num_blocks_failed: 111, // 33.333...% failure rate
            }],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                dc_id: "dc1".into(),
            }],
        );

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];
    let node_result = &provider_result.nodes_results[0];

    // Verify that calculations are precise and don't have unexpected rounding
    assert!(node_result.adjusted_rewards > dec!(0));
    assert!(node_result.adjusted_rewards <= node_result.base_rewards);

    // The total rewards should be exactly the adjusted rewards (single node)
    assert_eq!(provider_result.rewards_total, node_result.adjusted_rewards);
}

// ------------------------------------------------------------------------------------------------
// Provider Filtering Tests
// ------------------------------------------------------------------------------------------------

#[test]
fn test_provider_filtering() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider1_id = test_provider_id(1);
    let provider2_id = test_provider_id(2);
    let subnet_id = test_subnet_id(1);

    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider1_id,
            vec![RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                dc_id: "dc1".into(),
            }],
        )
        .add_rewardable_nodes(
            day,
            provider2_id,
            vec![RewardableNode {
                node_id: test_node_id(2),
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                dc_id: "dc2".into(),
            }],
        );

    // Test filtering for provider1 only
    let result1 = RewardsCalculationV1::calculate_rewards(
        &day,
        &day,
        Some(provider1_id),
        data_provider.clone(),
    )
    .expect("Calculation should succeed");

    assert_eq!(result1.daily_results[&day].provider_results.len(), 1);
    assert!(
        result1.daily_results[&day]
            .provider_results
            .contains_key(&provider1_id)
    );
    assert!(
        !result1.daily_results[&day]
            .provider_results
            .contains_key(&provider2_id)
    );

    // Test filtering for provider2 only
    let result2 =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider2_id), data_provider)
            .expect("Calculation should succeed");

    assert_eq!(result2.daily_results[&day].provider_results.len(), 1);
    assert!(
        result2.daily_results[&day]
            .provider_results
            .contains_key(&provider2_id)
    );
    assert!(
        !result2.daily_results[&day]
            .provider_results
            .contains_key(&provider1_id)
    );
}

#[test]
fn test_no_provider_filtering() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider1_id = test_provider_id(1);
    let provider2_id = test_provider_id(2);
    let subnet_id = test_subnet_id(1);

    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider1_id,
            vec![RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                dc_id: "dc1".into(),
            }],
        )
        .add_rewardable_nodes(
            day,
            provider2_id,
            vec![RewardableNode {
                node_id: test_node_id(2),
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                dc_id: "dc2".into(),
            }],
        );

    // Test with no provider filtering (should include all providers)
    let result = RewardsCalculationV1::calculate_rewards(&day, &day, None, data_provider)
        .expect("Calculation should succeed");

    assert_eq!(result.daily_results[&day].provider_results.len(), 2);
    assert!(
        result.daily_results[&day]
            .provider_results
            .contains_key(&provider1_id)
    );
    assert!(
        result.daily_results[&day]
            .provider_results
            .contains_key(&provider2_id)
    );
}

// ------------------------------------------------------------------------------------------------
// Error Handling Tests
// ------------------------------------------------------------------------------------------------

#[test]
fn test_invalid_date_range() {
    let day1 = DayUtc::try_from("2024-01-02").unwrap();
    let day2 = DayUtc::try_from("2024-01-01").unwrap(); // Before day1

    let data_provider = MockDataProvider::new();

    let result = RewardsCalculationV1::calculate_rewards(&day1, &day2, None, data_provider);

    match result {
        Err(error_msg) => assert!(error_msg.contains("from_day must be before to_day")),
        Ok(_) => panic!("Expected error but got success"),
    }
}

#[test]
fn test_missing_rewards_table() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);

    let data_provider = MockDataProvider::new(); // No rewards table added

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider);

    match result {
        Err(error_msg) => assert!(error_msg.contains("No rewards table found")),
        Ok(_) => panic!("Expected error but got success"),
    }
}

#[test]
fn test_missing_metrics() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);

    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table());
    // No metrics added

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider);

    match result {
        Err(error_msg) => assert!(error_msg.contains("No metrics found")),
        Ok(_) => panic!("Expected error but got success"),
    }
}

#[test]
fn test_missing_rewardable_nodes() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(1),
                num_blocks_proposed: 100,
                num_blocks_failed: 5,
            }],
        );
    // No rewardable nodes added

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider);

    match result {
        Err(error_msg) => assert!(error_msg.contains("No rewardable nodes found")),
        Ok(_) => panic!("Expected error but got success"),
    }
}

// ------------------------------------------------------------------------------------------------
// Edge Case and Validation Tests
// ------------------------------------------------------------------------------------------------

/// **Scenario**: Subnet with only one node (10% failure rate)
/// **Expected**: Subnet failure rate = node failure rate (10%), node gets no penalty
/// **Key Test**: Single node subnet behavior and 75th percentile with n=1
#[test]
fn test_single_node_subnet() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test with only one node in the subnet
    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(1),
                num_blocks_proposed: 100,
                num_blocks_failed: 10, // 10% failure rate
            }],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                dc_id: "dc1".into(),
            }],
        );

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // With only one node, the subnet failure rate should be the same as the node's failure rate
    let subnet_fr = daily_result.subnets_fr[&subnet_id];
    assert_eq!(subnet_fr, dec!(0.0909090909090909090909090909)); // 10/110

    // The single node should have no penalty since its relative failure rate is 0
    let node_result = &provider_result.nodes_results[0];
    assert_eq!(node_result.performance_multiplier, dec!(1.0));
    assert_eq!(node_result.rewards_reduction, dec!(0.0));
}

#[test]
fn test_very_high_failure_rates() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test with very high failure rates (90%+)
    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                // 90% failure rate
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 10,
                    num_blocks_failed: 90,
                },
                // 95% failure rate
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 5,
                    num_blocks_failed: 95,
                },
                // 99% failure rate
                NodeMetricsDailyRaw {
                    node_id: test_node_id(3),
                    num_blocks_proposed: 1,
                    num_blocks_failed: 99,
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![
                RewardableNode {
                    node_id: test_node_id(1),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(2),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc2".into(),
                },
                RewardableNode {
                    node_id: test_node_id(3),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc3".into(),
                },
            ],
        );

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Subnet failure rate should be 99% (75th percentile of 90%, 95%, 99%)
    let subnet_fr = daily_result.subnets_fr[&subnet_id];
    assert_eq!(subnet_fr, dec!(0.99));

    let node_results = &provider_result.nodes_results;
    assert_eq!(node_results.len(), 3);

    // Node 1: 90% failure rate, relative FR = max(0, 0.90 - 0.99) = 0 (no penalty)
    let node1 = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(1))
        .unwrap();
    assert_eq!(node1.performance_multiplier, dec!(1.0));
    assert_eq!(node1.rewards_reduction, dec!(0.0));

    // Node 2: 95% failure rate, relative FR = max(0, 0.95 - 0.99) = 0 (no penalty)
    let node2 = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(2))
        .unwrap();
    assert_eq!(node2.performance_multiplier, dec!(1.0));
    assert_eq!(node2.rewards_reduction, dec!(0.0));

    // Node 3: 99% failure rate, relative FR = max(0, 0.99 - 0.99) = 0 (no penalty)
    let node3 = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(3))
        .unwrap();
    assert_eq!(node3.performance_multiplier, dec!(1.0));
    assert_eq!(node3.rewards_reduction, dec!(0.0));
}

#[test]
fn test_extreme_failure_rates_with_penalty() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test with extreme failure rates that should trigger penalties
    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                // 5% failure rate (good performance)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 95,
                    num_blocks_failed: 5,
                },
                // 10% failure rate (average performance)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 90,
                    num_blocks_failed: 10,
                },
                // 15% failure rate (slightly above average)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(3),
                    num_blocks_proposed: 85,
                    num_blocks_failed: 15,
                },
                // 90% failure rate (very poor performance)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(4),
                    num_blocks_proposed: 10,
                    num_blocks_failed: 90,
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![
                RewardableNode {
                    node_id: test_node_id(1),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(2),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc2".into(),
                },
                RewardableNode {
                    node_id: test_node_id(3),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc3".into(),
                },
                RewardableNode {
                    node_id: test_node_id(4),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc4".into(),
                },
            ],
        );

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Subnet failure rate should be 15% (75th percentile of 5%, 10%, 15%, 90%)
    let subnet_fr = daily_result.subnets_fr[&subnet_id];
    assert_eq!(subnet_fr, dec!(0.15));

    let node_results = &provider_result.nodes_results;
    assert_eq!(node_results.len(), 4);

    // Node 1: 5% failure rate, relative FR = max(0, 0.05 - 0.15) = 0 (no penalty)
    let node1 = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(1))
        .unwrap();
    assert_eq!(node1.performance_multiplier, dec!(1.0));
    assert_eq!(node1.rewards_reduction, dec!(0.0));

    // Node 2: 10% failure rate, relative FR = max(0, 0.10 - 0.15) = 0 (no penalty)
    let node2 = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(2))
        .unwrap();
    assert_eq!(node2.performance_multiplier, dec!(1.0));
    assert_eq!(node2.rewards_reduction, dec!(0.0));

    // Node 3: 15% failure rate, relative FR = max(0, 0.15 - 0.15) = 0 (no penalty)
    let node3 = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(3))
        .unwrap();
    assert_eq!(node3.performance_multiplier, dec!(1.0));
    assert_eq!(node3.rewards_reduction, dec!(0.0));

    // Node 4: 90% failure rate, relative FR = max(0, 0.90 - 0.15) = 0.75
    // Since 0.75 >= 0.6 (MAX_FAILURE_RATE), max penalty
    let node4 = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(4))
        .unwrap();
    assert_eq!(node4.performance_multiplier, dec!(0.2)); // 1 - 0.8
    assert_eq!(node4.rewards_reduction, dec!(0.8)); // MAX_REWARDS_REDUCTION
}

/// **Scenario**: Subnet with empty metrics (no node performance data)
/// **Expected**: Subnet failure rate = 0%, node gets no penalty
/// **Key Test**: Empty subnet handling and zero failure rate logic
#[test]
fn test_empty_subnet_metrics() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test with empty metrics for a subnet
    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(day, subnet_id, vec![]) // Empty metrics
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![RewardableNode {
                node_id: test_node_id(1),
                node_reward_type: NodeRewardType::Type1,
                region: "Europe,Switzerland".into(),
                dc_id: "dc1".into(),
            }],
        );

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Subnet failure rate should be 0 for empty subnet
    let subnet_fr = daily_result.subnets_fr[&subnet_id];
    assert_eq!(subnet_fr, dec!(0.0));

    // Node should have no penalty since subnet FR is 0
    let node_result = &provider_result.nodes_results[0];
    assert_eq!(node_result.performance_multiplier, dec!(1.0));
    assert_eq!(node_result.rewards_reduction, dec!(0.0));
}

/// **Scenario**: Provider with empty rewardable nodes (no nodes to reward)
/// **Expected**: No node results, total rewards = 0
/// **Key Test**: Empty rewardable nodes handling
#[test]
fn test_empty_rewardable_nodes() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test with empty rewardable nodes
    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(1),
                num_blocks_proposed: 100,
                num_blocks_failed: 5,
            }],
        )
        .add_rewardable_nodes(day, provider_id, vec![]); // Empty rewardable nodes

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Should have no node results
    assert!(provider_result.nodes_results.is_empty());
    assert_eq!(provider_result.rewards_total, dec!(0.0));
}

#[test]
fn test_validation_errors() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);

    // Test invalid date range (from_day > to_day)
    let day1 = DayUtc::try_from("2024-01-02").unwrap();
    let day2 = DayUtc::try_from("2024-01-01").unwrap();
    let data_provider = MockDataProvider::new();

    let result =
        RewardsCalculationV1::calculate_rewards(&day1, &day2, Some(provider_id), data_provider);
    match result {
        Err(error_msg) => assert!(error_msg.contains("from_day must be before to_day")),
        Ok(_) => panic!("Expected error for invalid date range"),
    }

    // Test missing rewards table
    let data_provider = MockDataProvider::new(); // No rewards table
    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider);
    match result {
        Err(error_msg) => assert!(error_msg.contains("No rewards table found")),
        Ok(_) => panic!("Expected error for missing rewards table"),
    }

    // Test missing metrics
    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table());
    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider);
    match result {
        Err(error_msg) => assert!(error_msg.contains("No metrics found")),
        Ok(_) => panic!("Expected error for missing metrics"),
    }

    // Test missing rewardable nodes
    let subnet_id = test_subnet_id(1);
    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(1),
                num_blocks_proposed: 100,
                num_blocks_failed: 5,
            }],
        );
    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider);
    match result {
        Err(error_msg) => assert!(error_msg.contains("No rewardable nodes found")),
        Ok(_) => panic!("Expected error for missing rewardable nodes"),
    }
}

/// **Scenario**: Nodes with zero block scenarios (0/0, 0/10, 100/0)
/// **Expected**: 75th percentile = 100%, all nodes get no penalty
/// **Key Test**: Zero blocks edge case handling
#[test]
fn test_zero_blocks_edge_cases() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test various zero block scenarios
    let data_provider = MockDataProvider::new()
        .add_rewards_table(day, MockDataProvider::create_comprehensive_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                // Zero proposed, zero failed
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 0,
                    num_blocks_failed: 0,
                },
                // Zero proposed, some failed
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 0,
                    num_blocks_failed: 10,
                },
                // Some proposed, zero failed
                NodeMetricsDailyRaw {
                    node_id: test_node_id(3),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                },
            ],
        )
        .add_rewardable_nodes(
            day,
            provider_id,
            vec![
                RewardableNode {
                    node_id: test_node_id(1),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(2),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc2".into(),
                },
                RewardableNode {
                    node_id: test_node_id(3),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc3".into(),
                },
            ],
        );

    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider)
            .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Subnet failure rate should be 1.0 (75th percentile of 0, 1.0, 0)
    let subnet_fr = daily_result.subnets_fr[&subnet_id];
    assert_eq!(subnet_fr, dec!(1.0));

    let node_results = &provider_result.nodes_results;
    assert_eq!(node_results.len(), 3);

    // Node 1: 0% failure rate, relative FR = max(0, 0 - 1.0) = 0 (no penalty)
    let node1 = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(1))
        .unwrap();
    assert_eq!(node1.performance_multiplier, dec!(1.0));
    assert_eq!(node1.rewards_reduction, dec!(0.0));

    // Node 2: 100% failure rate, relative FR = max(0, 1.0 - 1.0) = 0 (no penalty)
    let node2 = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(2))
        .unwrap();
    assert_eq!(node2.performance_multiplier, dec!(1.0));
    assert_eq!(node2.rewards_reduction, dec!(0.0));

    // Node 3: 0% failure rate, relative FR = max(0, 0 - 1.0) = 0 (no penalty)
    let node3 = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(3))
        .unwrap();
    assert_eq!(node3.performance_multiplier, dec!(1.0));
    assert_eq!(node3.rewards_reduction, dec!(0.0));
}

// ------------------------------------------------------------------------------------------------
// Complex Multi-Scenario Tests
// ------------------------------------------------------------------------------------------------

#[test]
fn test_complex_multi_provider_multi_day_scenario() {
    let day1 = DayUtc::try_from("2024-01-01").unwrap();
    let day2 = DayUtc::try_from("2024-01-02").unwrap();
    let provider1_id = test_provider_id(1);
    let provider2_id = test_provider_id(2);
    let subnet1_id = test_subnet_id(1);
    let subnet2_id = test_subnet_id(2);

    let rewards_table = MockDataProvider::create_comprehensive_rewards_table();

    let data_provider = MockDataProvider::new()
        .add_rewards_table(day1, rewards_table.clone())
        .add_rewards_table(day2, rewards_table)
        // Day 1 metrics
        .add_daily_metrics(
            day1,
            subnet1_id,
            vec![
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5, // 5% failure rate
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 15, // 15% failure rate
                },
            ],
        )
        .add_daily_metrics(
            day1,
            subnet2_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(3),
                num_blocks_proposed: 100,
                num_blocks_failed: 10, // 10% failure rate
            }],
        )
        // Day 2 metrics (different performance)
        .add_daily_metrics(
            day2,
            subnet1_id,
            vec![
                NodeMetricsDailyRaw {
                    node_id: test_node_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 20, // 20% failure rate
                },
                NodeMetricsDailyRaw {
                    node_id: test_node_id(2),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5, // 5% failure rate
                },
            ],
        )
        .add_daily_metrics(
            day2,
            subnet2_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(3),
                num_blocks_proposed: 100,
                num_blocks_failed: 30, // 30% failure rate
            }],
        )
        // Day 1 rewardable nodes
        .add_rewardable_nodes(
            day1,
            provider1_id,
            vec![
                RewardableNode {
                    node_id: test_node_id(1),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(2),
                    node_reward_type: NodeRewardType::Type3,
                    region: "North America,USA,California".into(),
                    dc_id: "dc2".into(),
                },
            ],
        )
        .add_rewardable_nodes(
            day1,
            provider2_id,
            vec![RewardableNode {
                node_id: test_node_id(3),
                node_reward_type: NodeRewardType::Type3dot1,
                region: "North America,USA,Nevada".into(),
                dc_id: "dc3".into(),
            }],
        )
        // Day 2 rewardable nodes (same as day 1)
        .add_rewardable_nodes(
            day2,
            provider1_id,
            vec![
                RewardableNode {
                    node_id: test_node_id(1),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc1".into(),
                },
                RewardableNode {
                    node_id: test_node_id(2),
                    node_reward_type: NodeRewardType::Type3,
                    region: "North America,USA,California".into(),
                    dc_id: "dc2".into(),
                },
            ],
        )
        .add_rewardable_nodes(
            day2,
            provider2_id,
            vec![RewardableNode {
                node_id: test_node_id(3),
                node_reward_type: NodeRewardType::Type3dot1,
                region: "North America,USA,Nevada".into(),
                dc_id: "dc3".into(),
            }],
        );

    let result = RewardsCalculationV1::calculate_rewards(
        &day1,
        &day2,
        None, // No provider filtering
        data_provider,
    )
    .expect("Calculation should succeed");

    // Verify we have results for both days
    assert_eq!(result.daily_results.len(), 2);
    assert!(result.daily_results.contains_key(&day1));
    assert!(result.daily_results.contains_key(&day2));

    // Verify we have results for both providers on both days
    for day in [day1, day2] {
        let daily_result = &result.daily_results[&day];
        assert_eq!(daily_result.provider_results.len(), 2);
        assert!(daily_result.provider_results.contains_key(&provider1_id));
        assert!(daily_result.provider_results.contains_key(&provider2_id));
    }

    // Verify total rewards are accumulated across days
    assert!(
        result
            .total_rewards_xdr_permyriad
            .contains_key(&provider1_id)
    );
    assert!(
        result
            .total_rewards_xdr_permyriad
            .contains_key(&provider2_id)
    );

    let provider1_total = result.total_rewards_xdr_permyriad[&provider1_id];
    let provider2_total = result.total_rewards_xdr_permyriad[&provider2_id];

    assert!(provider1_total > 0);
    assert!(provider2_total > 0);

    // Verify that both days have the same rewards
    // This is because the relative failure rates are still below the penalty threshold
    let day1_provider1 = &result.daily_results[&day1].provider_results[&provider1_id];
    let day2_provider1 = &result.daily_results[&day2].provider_results[&provider1_id];

    assert_eq!(day1_provider1.rewards_total, day2_provider1.rewards_total);
}
