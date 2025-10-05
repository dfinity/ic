use crate::performance_based_algorithm::DataProvider;
use crate::performance_based_algorithm::test_utils::{
    test_node_id, test_provider_id, test_subnet_id,
};
use crate::performance_based_algorithm::v1::RewardsCalculationV1;
use crate::types::{DayUtc, NodeMetricsDailyRaw, RewardableNode};
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use lazy_static::lazy_static;
use maplit::btreemap;
use rust_decimal_macros::dec;
use std::collections::BTreeMap;

lazy_static! {
  static ref NODE_REWARDS_TABLE: NodeRewardsTable = {
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
  };
}

// ================================================================================================
// Mock DataProvider
// ================================================================================================

#[derive(Default, Clone)]
pub struct FakeDataProvider {
    rewards_tables: BTreeMap<DayUtc, NodeRewardsTable>,
    daily_metrics: BTreeMap<DayUtc, BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>>>,
    rewardable_nodes: BTreeMap<DayUtc, BTreeMap<PrincipalId, Vec<RewardableNode>>>,
}

impl FakeDataProvider {
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

    pub fn create_rewards_table() -> NodeRewardsTable {
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

impl DataProvider for FakeDataProvider {
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

    let data_provider = FakeDataProvider::new()
        .add_rewards_table(day, FakeDataProvider::create_rewards_table())
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

    let data_provider = FakeDataProvider::new()
        .add_rewards_table(day, FakeDataProvider::create_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                // Type3 node with 5% failure rate (good performance)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(20),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
                // Type3 node with 15% failure rate (moderate performance - should get penalty)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(21),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 15,
                },
                // Type3 node with 25% failure rate (poor performance - should get penalty)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(22),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 25,
                },
                // Type3.1 node with 35% failure rate (poor performance - should get penalty)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(23),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 35,
                },
                // Type3.1 node with 45% failure rate (very poor performance - should get penalty)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(24),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 45,
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

    // Find the Type3 base rewards for USA (3 nodes)
    let usa_rewards = provider_result
        .base_rewards_type3
        .iter()
        .find(|r| r.region == "North America:USA")
        .unwrap();

    assert_eq!(usa_rewards.nodes_count, 5); // 3 Type3 + 2 Type3.1 nodes grouped together
    assert_eq!(usa_rewards.avg_coefficient, dec!(0.82)); // Average of 90% and 70% coefficients -> (3 * 90 + 2 * 70)/5

    // Calculate expected subnet failure rate (75th percentile of 4.76%, 13.04%, 20%, 25.93%, 31.03% = 25.93%)
    let subnet_fr = daily_result.subnets_fr[&subnet_id];
    assert_eq!(subnet_fr, dec!(0.2592592592592592592592592593)); // 25.93% failure rate

    // Verify individual node rewards with performance penalties
    let node_results = &provider_result.nodes_results;

    // Find nodes by ID and verify their performance
    let good_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(20))
        .unwrap();
    let extremely_poor_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(24))
        .unwrap();

    // Node 20 (Type3, 4.76% failure rate): relative FR = max(0, 0.0476 - 0.2593) = 0 (no penalty)
    // Base rewards = 30000 * actual_coefficient = 23772.05036800
    assert_eq!(good_node.base_rewards, dec!(23772.05036800)); // Type3 base reward with coefficient applied
    assert_eq!(good_node.performance_multiplier, dec!(1.0)); // No penalty
    assert_eq!(good_node.rewards_reduction, dec!(0.0)); // No reduction
    // Adjusted rewards = 23772.05036800 * 1.0 = 23772.05036800
    assert_eq!(good_node.adjusted_rewards, dec!(23772.05036800));

    // Node 24 (Type3.1, 31.03% failure rate): relative FR = max(0, 0.3103 - 0.2593) = 0.051
    // Since 0.051 < 0.10 (MIN_FAILURE_RATE), no penalty
    // Base rewards = same as Type3 nodes due to country grouping = 23772.05036800
    assert_eq!(extremely_poor_node.base_rewards, dec!(23772.05036800)); // Type3.1 base reward with coefficient applied
    assert_eq!(extremely_poor_node.performance_multiplier, dec!(1.0)); // No penalty (below threshold)
    assert_eq!(extremely_poor_node.rewards_reduction, dec!(0.0)); // No reduction
    // Adjusted rewards = 23772.05036800 * 1.0 = 23772.05036800
    assert_eq!(extremely_poor_node.adjusted_rewards, dec!(23772.05036800));
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

    let data_provider = FakeDataProvider::new()
        .add_rewards_table(day, FakeDataProvider::create_rewards_table())
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

    let data_provider = FakeDataProvider::new()
        .add_rewards_table(day, FakeDataProvider::create_rewards_table())
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

    let data_provider = FakeDataProvider::new();

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

    let data_provider = FakeDataProvider::new(); // No rewards table added

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

    let data_provider =
        FakeDataProvider::new().add_rewards_table(day, FakeDataProvider::create_rewards_table());
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

    let data_provider = FakeDataProvider::new()
        .add_rewards_table(day, FakeDataProvider::create_rewards_table())
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
    let data_provider = FakeDataProvider::new()
        .add_rewards_table(day, FakeDataProvider::create_rewards_table())
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
fn test_empty_subnet_metrics() {
    let day = DayUtc::try_from("2024-01-01").unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test with empty metrics for a subnet
    let data_provider = FakeDataProvider::new()
        .add_rewards_table(day, FakeDataProvider::create_rewards_table())
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
    let data_provider = FakeDataProvider::new()
        .add_rewards_table(day, FakeDataProvider::create_rewards_table())
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
    let data_provider = FakeDataProvider::new();

    let result =
        RewardsCalculationV1::calculate_rewards(&day1, &day2, Some(provider_id), data_provider);
    match result {
        Err(error_msg) => assert!(error_msg.contains("from_day must be before to_day")),
        Ok(_) => panic!("Expected error for invalid date range"),
    }

    // Test missing rewards table
    let data_provider = FakeDataProvider::new(); // No rewards table
    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider);
    match result {
        Err(error_msg) => assert!(error_msg.contains("No rewards table found")),
        Ok(_) => panic!("Expected error for missing rewards table"),
    }

    // Test missing metrics
    let data_provider =
        FakeDataProvider::new().add_rewards_table(day, FakeDataProvider::create_rewards_table());
    let result =
        RewardsCalculationV1::calculate_rewards(&day, &day, Some(provider_id), data_provider);
    match result {
        Err(error_msg) => assert!(error_msg.contains("No metrics found")),
        Ok(_) => panic!("Expected error for missing metrics"),
    }

    // Test missing rewardable nodes
    let subnet_id = test_subnet_id(1);
    let data_provider = FakeDataProvider::new()
        .add_rewards_table(day, FakeDataProvider::create_rewards_table())
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
    let data_provider = FakeDataProvider::new()
        .add_rewards_table(day, FakeDataProvider::create_rewards_table())
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
