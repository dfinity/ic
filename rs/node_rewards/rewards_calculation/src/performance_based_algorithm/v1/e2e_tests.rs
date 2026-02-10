use crate::performance_based_algorithm::PerformanceBasedAlgorithmInputProvider;
use crate::performance_based_algorithm::results::{DailyNodeFailureRate, DailyNodeRewards};
use crate::performance_based_algorithm::test_utils::{
    test_node_id, test_provider_id, test_subnet_id,
};
use crate::performance_based_algorithm::v1::RewardsCalculationV1;
use crate::types::{NodeMetricsDailyRaw, RewardableNode};
use chrono::NaiveDate;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use lazy_static::lazy_static;
use maplit::btreemap;
use rust_decimal_macros::dec;
use std::collections::{BTreeMap, HashMap};

// Predefined rewards table used in tests
// Note: Values for 'xdr_permyriad_per_node_per_month' have been chosen to be give good daily
// rewards once divided by REWARDS_TABLE_DAYS.
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

// ------------------------------------------------------------------------------------------------
// Failure Rate Calculation Tests
// ------------------------------------------------------------------------------------------------

/// **Scenario**: 4 nodes with different performance levels (0.99%, 4.76%, 16.67%, 33.33% failure rates)
/// **Expected**: 75th percentile = 16.67%, only the worst node (33.33%) gets penalized
/// **Key Test**: 75th percentile calculation and relative failure rate logic
#[test]
fn test_failure_rate_calculation_various_performance() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, FakeInputProvider::create_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                // Excellent performance: 1/(100+1) = slightly less than 1% failure rate.
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

    let mut result = RewardsCalculationV1::calculate_rewards(day, day, fake_input_provider)
        .expect("Calculation should succeed");

    let mut daily_result = result.daily_results.remove(&day).unwrap();
    let provider_result = daily_result.provider_results.remove(&provider_id).unwrap();
    // Verify subnet failure rate is calculated (75th percentile of 0.99%, 4.76%, 16.67%, 33.33% = 16.67%)
    let subnet_fr = *daily_result.subnets_failure_rate.get(&subnet_id).unwrap();
    assert_eq!(subnet_fr, dec!(0.1666666666666666666666666667));

    // Verify node results show different performance multipliers
    let mut node_results: HashMap<NodeId, DailyNodeRewards> = provider_result
        .daily_nodes_rewards
        .into_iter()
        .map(|daily_rewards| (daily_rewards.node_id, daily_rewards))
        .collect();

    assert_eq!(node_results.len(), 4);

    // Find nodes by ID and verify their performance
    let excellent_node = node_results.remove(&test_node_id(10)).unwrap();
    let good_node = node_results.remove(&test_node_id(11)).unwrap();
    let average_node = node_results.remove(&test_node_id(12)).unwrap();
    let poor_node = node_results.remove(&test_node_id(13)).unwrap();

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
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, FakeInputProvider::create_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![
                // Type3 node with ~4.76% failure rate (5/105) (good performance)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(20),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 5,
                },
                // Type3 node with ~13.04% failure rate (15/115) (moderate performance - should get penalty)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(21),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 15,
                },
                // Type3 node with 20% failure rate (25/125) (poor performance - should get penalty)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(22),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 25,
                },
                // Type3.1 node with ~25.93% failure rate (35/135) (poor performance - should get penalty)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(23),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 35,
                },
                // Type3.1 node with ~41.1% failure rate (70/170) (very poor performance - should get penalty)
                NodeMetricsDailyRaw {
                    node_id: test_node_id(24),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 70,
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

    let result = RewardsCalculationV1::calculate_rewards(day, day, fake_input_provider)
        .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Both Type3 and Type3.1 nodes should be grouped under North America,USA
    assert_eq!(provider_result.type3_base_rewards.len(), 1);

    // Find the Type3 base rewards for USA (3 nodes)
    let usa_rewards = provider_result
        .type3_base_rewards
        .iter()
        .find(|r| r.region == "North America:USA")
        .unwrap();

    assert_eq!(usa_rewards.nodes_count, 5); // 3 Type3 + 2 Type3.1 nodes grouped together
    assert_eq!(usa_rewards.avg_coefficient, dec!(0.82)); // Average of 90% and 70% coefficients -> (3 * 90 + 2 * 70)/5
    assert_eq!(usa_rewards.avg_rewards_xdr_permyriad, dec!(34000)); // Average of daily rates -> (30000 * 3 + 40000 * 2) / 5
    // Average of daily rates discounted by coefficient percent
    // Computed as (34000 + 34000*0.82 + 34000*0.82^2 + 34000*0.82^3 + 34000*0.82^4) / 5
    assert_eq!(usa_rewards.daily_xdr_permyriad, dec!(23772.05036800));

    // Calculate expected subnet failure rate (75th percentile of 4.76%, 13.04%, 20%, 25.93%, 31.03% = 25.93%)
    let subnet_fr = daily_result.subnets_failure_rate[&subnet_id];
    assert_eq!(subnet_fr, dec!(0.2592592592592592592592592593)); // 25.93% failure rate

    // Verify individual node rewards with performance penalties
    let node_results = &provider_result.daily_nodes_rewards;

    // Node 20 (Type3, 4.76% failure rate)
    let good_node = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(20))
        .unwrap();
    assert_eq!(good_node.base_rewards_xdr_permyriad, dec!(23772.05036800)); // From previous assert case
    assert_eq!(good_node.performance_multiplier, dec!(1.0)); // No penalty
    assert_eq!(good_node.rewards_reduction, dec!(0.0)); // No reduction

    if let DailyNodeFailureRate::SubnetMember { node_metrics } = &good_node.daily_node_failure_rate
    {
        assert_eq!(
            node_metrics.original_failure_rate,
            dec!(0.0476190476190476190476190476)
        );
        // relative FR = max(0, 0.0476 - 0.2593) = 0 (no penalty)
        assert_eq!(node_metrics.relative_failure_rate, dec!(0));
    } else {
        panic!("Node is not a SubnetMember");
    }
    // Adjusted rewards = 23772.05036800 * 1.0 = 23772.05036800
    assert_eq!(
        good_node.adjusted_rewards_xdr_permyriad,
        dec!(23772.05036800)
    );

    // Node 24 (Type3.1, ~31.03% failure rate)
    let node_with_penalty = node_results
        .iter()
        .find(|n| n.node_id == test_node_id(24))
        .unwrap();

    println!("{:?}", node_with_penalty);
    assert_eq!(
        node_with_penalty.base_rewards_xdr_permyriad,
        dec!(23772.05036800)
    ); // From previous assert case

    if let DailyNodeFailureRate::SubnetMember { node_metrics } =
        &node_with_penalty.daily_node_failure_rate
    {
        assert_eq!(
            node_metrics.original_failure_rate,
            dec!(0.4117647058823529411764705882)
        );
        // relative FR = max(0, ~0.41 - 0.2593) ~= 0.1525
        assert_eq!(
            node_metrics.relative_failure_rate,
            dec!(0.1525054466230936819172113289)
        );
    } else {
        panic!("Node is not a SubnetMember");
    }

    assert_eq!(
        node_with_penalty.rewards_reduction,
        dec!(0.0840087145969498910675381262)
    ); // Linear interpolation
    assert_eq!(
        node_with_penalty.performance_multiplier,
        dec!(0.9159912854030501089324618738)
    );

    // Adjusted rewards = 23772.05036800 * 1.0 = 23772.05036800
    assert_eq!(
        good_node.adjusted_rewards_xdr_permyriad,
        dec!(23772.05036800)
    );
}

// ------------------------------------------------------------------------------------------------
// Error Handling Tests
// ------------------------------------------------------------------------------------------------

#[test]
fn test_invalid_date_range() {
    let day1 = NaiveDate::from_ymd_opt(2025, 1, 2).unwrap();
    let day2 = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(); // Before day1

    let fake_input_provider = FakeInputProvider::new();

    let result = RewardsCalculationV1::calculate_rewards(day1, day2, fake_input_provider);

    match result {
        Err(error_msg) => assert!(error_msg.contains("from_day must be before to_day")),
        Ok(_) => panic!("Expected error but got success"),
    }
}

#[test]
fn test_missing_rewards_table() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let fake_input_provider = FakeInputProvider::new(); // No rewards table added

    let result = RewardsCalculationV1::calculate_rewards(day, day, fake_input_provider);
    assert_eq!(
        result,
        Err("No rewards table found for day 2025-01-01".to_string())
    );
}

#[test]
fn test_missing_metrics() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let fake_input_provider =
        FakeInputProvider::new().add_rewards_table(day, FakeInputProvider::create_rewards_table());

    // No metrics added
    let result = RewardsCalculationV1::calculate_rewards(day, day, fake_input_provider);
    assert_eq!(
        result,
        Err("No metrics found for day 2025-01-01".to_string())
    );
}

#[test]
fn test_missing_rewardable_nodes() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let subnet_id = test_subnet_id(1);

    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, FakeInputProvider::create_rewards_table())
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
    let result = RewardsCalculationV1::calculate_rewards(day, day, fake_input_provider);
    assert_eq!(
        result,
        Err("No rewardable nodes found for day 2025-01-01".to_string())
    );
}

// ------------------------------------------------------------------------------------------------
// Edge Case and Validation Tests
// ------------------------------------------------------------------------------------------------

/// **Scenario**: Subnet with only one node (10% failure rate)
/// **Expected**: Subnet failure rate = node failure rate (10%), node gets no penalty
/// **Key Test**: Single node subnet behavior and 75th percentile with n=1
#[test]
fn test_single_node_subnet() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test with only one node in the subnet
    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, FakeInputProvider::create_rewards_table())
        .add_daily_metrics(
            day,
            subnet_id,
            vec![NodeMetricsDailyRaw {
                node_id: test_node_id(1),
                num_blocks_proposed: 90,
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

    let result = RewardsCalculationV1::calculate_rewards(day, day, fake_input_provider)
        .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // With only one node, the subnet failure rate should be the same as the node's failure rate
    let subnet_fr = daily_result.subnets_failure_rate[&subnet_id];
    assert_eq!(subnet_fr, dec!(0.1)); // 10/100

    // The single node should have no penalty since its relative failure rate is 0
    let node_1_rewards = &provider_result.daily_nodes_rewards[0];
    assert_eq!(node_1_rewards.performance_multiplier, dec!(1.0));
    assert_eq!(node_1_rewards.rewards_reduction, dec!(0.0));
}

#[test]
fn test_empty_subnet_metrics() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test with empty metrics for a subnet
    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, FakeInputProvider::create_rewards_table())
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

    let result = RewardsCalculationV1::calculate_rewards(day, day, fake_input_provider)
        .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    assert!(!daily_result.subnets_failure_rate.contains_key(&subnet_id));

    // Node should have no penalty since no nodes assigned to the subnet
    let daily_nodes_rewards = &provider_result.daily_nodes_rewards[0];
    assert_eq!(daily_nodes_rewards.performance_multiplier, dec!(1.0));
    assert_eq!(daily_nodes_rewards.rewards_reduction, dec!(0.0));
}

/// **Scenario**: Provider with empty rewardable nodes (no nodes to reward)
/// **Expected**: No node results, total rewards = 0
/// **Key Test**: Empty rewardable nodes handling
#[test]
fn test_empty_rewardable_nodes() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test with empty rewardable nodes
    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, FakeInputProvider::create_rewards_table())
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

    let result = RewardsCalculationV1::calculate_rewards(day, day, fake_input_provider)
        .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Should have no node results
    assert!(provider_result.daily_nodes_rewards.is_empty());
    assert_eq!(provider_result.total_adjusted_rewards_xdr_permyriad, 0);
}

/// **Scenario**: Nodes with zero block scenarios
/// **Expected**: 75th percentile = 100%, all nodes get no penalty
/// **Key Test**: Zero blocks edge case handling
#[test]
fn test_zero_blocks_edge_cases() {
    let day = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let provider_id = test_provider_id(1);
    let subnet_id = test_subnet_id(1);

    // Test various zero block scenarios
    let fake_input_provider = FakeInputProvider::new()
        .add_rewards_table(day, FakeInputProvider::create_rewards_table())
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
                // Some proposed, zero failed
                NodeMetricsDailyRaw {
                    node_id: test_node_id(4),
                    num_blocks_proposed: 10,
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
                    node_reward_type: NodeRewardType::Type3dot1,
                    region: "North America,USA,Nevada".into(),
                    dc_id: "dc2".into(),
                },
                RewardableNode {
                    node_id: test_node_id(3),
                    node_reward_type: NodeRewardType::Type1,
                    region: "North America,USA,California".into(),
                    dc_id: "dc3".into(),
                },
                RewardableNode {
                    node_id: test_node_id(4),
                    node_reward_type: NodeRewardType::Type1,
                    region: "Europe,Switzerland".into(),
                    dc_id: "dc3".into(),
                },
            ],
        );

    let result = RewardsCalculationV1::calculate_rewards(day, day, fake_input_provider)
        .expect("Calculation should succeed");

    let daily_result = &result.daily_results[&day];
    let provider_result = &daily_result.provider_results[&provider_id];

    // Subnet failure rate should be 1.0 (75th percentile of 0, 0, 0, 1.0)
    let subnet_fr = daily_result.subnets_failure_rate[&subnet_id];
    assert_eq!(subnet_fr, dec!(0));

    // Convert node_results into a HashMap for direct access by node_id
    let node_results_map: HashMap<_, _> = provider_result
        .daily_nodes_rewards
        .iter()
        .map(|n| (n.node_id, n))
        .collect();

    // Node 1
    let node1 = node_results_map.get(&test_node_id(1)).unwrap();
    let node_metrics = match &node1.daily_node_failure_rate {
        DailyNodeFailureRate::SubnetMember { node_metrics } => node_metrics,
        _ => panic!("Node 1 is not a SubnetMember"),
    };
    assert_eq!(node_metrics.original_failure_rate, dec!(0));
    assert_eq!(node_metrics.relative_failure_rate, dec!(0));
    assert_eq!(node1.adjusted_rewards_xdr_permyriad, dec!(10000)); // No penalty

    // Node 2
    let node2 = node_results_map.get(&test_node_id(2)).unwrap();
    let node_metrics = match &node2.daily_node_failure_rate {
        DailyNodeFailureRate::SubnetMember { node_metrics } => node_metrics,
        _ => panic!("Node 2 is not a SubnetMember"),
    };
    assert_eq!(node_metrics.original_failure_rate, dec!(1));
    assert_eq!(node_metrics.relative_failure_rate, dec!(1));
    assert_eq!(node2.performance_multiplier, dec!(0.2));
    assert_eq!(node2.adjusted_rewards_xdr_permyriad, dec!(8000)); // Max penalty 40000 * 0.2 = 8000
}
