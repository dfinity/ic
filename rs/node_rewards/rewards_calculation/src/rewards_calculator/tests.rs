// This module contains the end-to-end tests for the RewardsCalculator.
// It uses a builder pattern (`RewardCalculatorRunnerTest`) to set up test scenarios
// with a more descriptive and modular approach using `TestProvider`, `TestNode`, and `TestMetric` structs.

use super::*;
use crate::rewards_calculator::builder::RewardsCalculatorBuilder;
use crate::rewards_calculator_results::{NodeResults, Percent, RewardsCalculatorResults};
use crate::types::{
    NodeMetricsDailyRaw, RewardPeriod, RewardableNode, SubnetMetricsDailyKey, UnixTsNanos,
    NANOS_PER_DAY,
};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use itertools::Itertools;
use rust_decimal_macros::dec;
use std::collections::{BTreeMap, HashMap, HashSet};

// --- Test Helpers ---

/// Helper function to create a `NodeId` from a u64 for testing.
pub fn node_id(id: u64) -> NodeId {
    PrincipalId::new_node_test_id(id).into()
}

/// Helper function to create a `SubnetId` from a u64 for testing.
pub fn subnet_id(id: u64) -> SubnetId {
    PrincipalId::new_subnet_test_id(id).into()
}

// --- Descriptive Test Data Structs ---

/// Represents a node's metrics for a single day in a test.
pub struct TestMetric {
    pub day_index: u64,
    pub subnet_id: SubnetId,
    pub num_blocks_proposed: u64,
    pub num_blocks_failed: u64,
}

/// Represents a node in a test scenario, including its properties and performance metrics.
pub struct TestNode {
    pub id: NodeId,
    pub region: String,
    pub node_type: NodeRewardType,
    pub dc_id: String,
    pub metrics: Vec<TestMetric>,
}

impl TestNode {
    /// Creates a new `TestNode` with default values.
    pub fn new(id: NodeId, region: &str, node_type: NodeRewardType) -> Self {
        Self {
            id,
            region: region.to_string(),
            node_type,
            dc_id: "dc-0".to_string(),
            metrics: vec![],
        }
    }

    /// Adds performance metrics to the node.
    pub fn with_metrics(mut self, metrics: Vec<TestMetric>) -> Self {
        self.metrics = metrics;
        self
    }
}

/// Represents a Node Provider and their associated nodes in a test.
pub struct TestProvider {
    pub id: PrincipalId,
    pub nodes: Vec<TestNode>,
}

impl TestProvider {
    pub fn new(id: PrincipalId) -> Self {
        Self { id, nodes: vec![] }
    }

    pub fn with_nodes(mut self, nodes: Vec<TestNode>) -> Self {
        self.nodes = nodes;
        self
    }
}

// --- Test Runner Builder ---

/// `RewardCalculatorRunnerTest` is a test harness to build and run test scenarios.
/// It provides a fluent interface to configure every aspect of the rewards calculation input.
#[derive(Default)]
pub struct RewardCalculatorRunnerTest {
    reward_period: Option<RewardPeriod>,
    node_rewards_table: Option<NodeRewardsTable>,
    providers: Vec<TestProvider>,
}

impl RewardCalculatorRunnerTest {
    /// Sets the reward period for the test run.
    pub fn with_reward_period(mut self, start_day_index: u64, end_day_index: u64) -> Self {
        let start_ts = start_day_index * NANOS_PER_DAY;
        let end_ts = end_day_index * NANOS_PER_DAY;
        self.reward_period = Some(RewardPeriod::new(start_ts, end_ts).unwrap());
        self
    }

    /// Adds a Node Provider to the test scenario.
    pub fn with_provider(mut self, provider: TestProvider) -> Self {
        self.providers.push(provider);
        self
    }

    /// Configures the node reward rates for a specific region and node types.
    pub fn with_rewards_rates(
        mut self,
        region: &str,
        node_types: Vec<NodeRewardType>,
        rate: u64,
        coeff: u64,
    ) -> Self {
        let mut rates: BTreeMap<String, NodeRewardRate> = BTreeMap::new();
        for node_type in node_types {
            rates.insert(
                node_type.to_string(),
                NodeRewardRate {
                    xdr_permyriad_per_node_per_month: rate,
                    reward_coefficient_percent: Some(coeff as i32),
                },
            );
        }
        let mut node_rewards_table = self.node_rewards_table.take().unwrap_or_default();
        node_rewards_table
            .table
            .insert(region.to_string(), NodeRewardRates { rates });

        self.node_rewards_table = Some(node_rewards_table);
        self
    }

    /// Builds the `RewardsCalculator` with the configured data, runs the calculation,
    /// and returns the results for all configured providers.
    pub fn build_and_run(self) -> BTreeMap<PrincipalId, RewardsCalculatorResults> {
        let mut all_metrics_by_day = BTreeMap::<u64, ()>::new();
        for provider in &self.providers {
            for node in &provider.nodes {
                for metric in &node.metrics {
                    all_metrics_by_day.insert(metric.day_index, ());
                }
            }
        }

        let reward_period = self.reward_period.unwrap_or_else(|| {
            let start_day = all_metrics_by_day
                .first_key_value()
                .map(|(k, _)| *k)
                .unwrap_or(0);
            let end_day = all_metrics_by_day
                .last_key_value()
                .map(|(k, _)| *k)
                .unwrap_or(0);
            RewardPeriod::new(start_day * NANOS_PER_DAY, end_day * NANOS_PER_DAY).unwrap()
        });

        let mut rewardable_nodes_per_provider = BTreeMap::new();
        let mut daily_data: HashMap<UnixTsNanos, Vec<(SubnetId, NodeId, u64, u64)>> =
            HashMap::new();

        for provider in self.providers {
            let rewardable_nodes: Vec<_> = provider
                .nodes
                .iter()
                .map(|node| {
                    for metric in &node.metrics {
                        let day_ts = reward_period.from.get() + metric.day_index * NANOS_PER_DAY;
                        daily_data.entry(day_ts).or_default().push((
                            metric.subnet_id,
                            node.id,
                            metric.num_blocks_proposed,
                            metric.num_blocks_failed,
                        ));
                    }

                    RewardableNode {
                        node_id: node.id,
                        region: Region(node.region.clone()),
                        node_reward_type: node.node_type,
                        rewardable_days: reward_period.from.days_until(&reward_period.to).unwrap(),
                        dc_id: node.dc_id.clone(),
                    }
                })
                .collect();

            rewardable_nodes_per_provider.insert(
                provider.id,
                ProviderRewardableNodes {
                    provider_id: provider.id,
                    rewardable_nodes,
                },
            );
        }

        let subnets_metrics: HashMap<SubnetMetricsDailyKey, Vec<NodeMetricsDailyRaw>> = daily_data
            .into_iter()
            .flat_map(|(ts, metrics)| {
                metrics
                    .into_iter()
                    .map(move |(subnet_id, node_id, proposed, failed)| {
                        (
                            SubnetMetricsDailyKey {
                                subnet_id,
                                day: ts.into(),
                            },
                            NodeMetricsDailyRaw {
                                node_id,
                                num_blocks_proposed: proposed,
                                num_blocks_failed: failed,
                            },
                        )
                    })
            })
            .into_group_map();

        RewardsCalculatorBuilder {
            reward_period,
            rewardable_nodes_per_provider,
            daily_metrics_by_subnet: subnets_metrics.into_iter().collect(),
            rewards_table: self.node_rewards_table.unwrap_or_default(),
        }
        .build()
        .unwrap()
        .calculate_rewards_per_provider()
    }
}

// --- Test Cases ---

#[test]
fn test_calculates_node_failure_rates_correctly() {
    let provider = TestProvider::new(PrincipalId::new_anonymous()).with_nodes(vec![
        TestNode::new(node_id(0), "CH", NodeRewardType::Type1).with_metrics(vec![
            TestMetric {
                day_index: 0,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 90,
                num_blocks_failed: 10,
            },
            TestMetric {
                day_index: 0,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 1,
                num_blocks_failed: 0,
            },
        ]),
        TestNode::new(node_id(1), "CH", NodeRewardType::Type1).with_metrics(vec![TestMetric {
            day_index: 1,
            subnet_id: subnet_id(1),
            num_blocks_proposed: 60,
            num_blocks_failed: 40,
        }]),
    ]);

    let results = RewardCalculatorRunnerTest::default()
        .with_provider(provider)
        .build_and_run()
        .pop_first()
        .unwrap()
        .1;

    let node_0_metrics = results.results_by_node.get(&node_id(0)).unwrap();
    let node_0_day_0 = node_0_metrics.daily_metrics.get(&DayUTC::from(0)).unwrap();

    // Subnet 2 should be chosen due to higher block activity.
    assert_eq!(node_0_day_0.subnet_assigned, subnet_id(2));
    assert_eq!(node_0_day_0.original_fr.get(), dec!(0.1));
    assert_eq!(node_0_day_0.relative_fr.get(), dec!(0));

    let node_1_metrics = results.results_by_node.get(&node_id(1)).unwrap();
    let node_1_day_1 = node_1_metrics
        .daily_metrics
        .get(&DayUTC::from(NANOS_PER_DAY))
        .unwrap();

    assert_eq!(node_1_day_1.subnet_assigned, subnet_id(1));
    assert_eq!(node_1_day_1.original_fr.get(), dec!(0.4));
    assert_eq!(node_1_day_1.relative_fr.get(), dec!(0));
}

#[test]
fn test_scenario_1() {
    let provider = TestProvider::new(PrincipalId::new_anonymous()).with_nodes(vec![
        // Node data is now structured per-node, making it easier to follow.
        TestNode::new(node_id(1), "EU", NodeRewardType::Type1).with_metrics(vec![
            TestMetric {
                day_index: 0,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 70,
                num_blocks_failed: 30,
            },
            TestMetric {
                day_index: 1,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 80,
                num_blocks_failed: 20,
            },
            TestMetric {
                day_index: 2,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 90,
                num_blocks_failed: 10,
            },
        ]),
        TestNode::new(node_id(2), "EU", NodeRewardType::Type1).with_metrics(vec![
            TestMetric {
                day_index: 0,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 60,
                num_blocks_failed: 40,
            },
            TestMetric {
                day_index: 1,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 90,
                num_blocks_failed: 10,
            },
            TestMetric {
                day_index: 2,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 80,
                num_blocks_failed: 20,
            },
            TestMetric {
                day_index: 3,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 80,
                num_blocks_failed: 20,
            },
        ]),
        TestNode::new(node_id(3), "EU", NodeRewardType::Type1).with_metrics(vec![
            TestMetric {
                day_index: 0,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 50,
                num_blocks_failed: 50,
            },
            TestMetric {
                day_index: 1,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 100,
                num_blocks_failed: 0,
            },
            TestMetric {
                day_index: 2,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 70,
                num_blocks_failed: 30,
            },
            TestMetric {
                day_index: 3,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 70,
                num_blocks_failed: 30,
            },
        ]),
        TestNode::new(node_id(4), "NA", NodeRewardType::Type1).with_metrics(vec![
            TestMetric {
                day_index: 1,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 50,
                num_blocks_failed: 50,
            },
            TestMetric {
                day_index: 2,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 60,
                num_blocks_failed: 40,
            },
            TestMetric {
                day_index: 3,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 60,
                num_blocks_failed: 40,
            },
        ]),
        TestNode::new(node_id(5), "NA", NodeRewardType::Type1).with_metrics(vec![
            TestMetric {
                day_index: 0,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 66,
                num_blocks_failed: 34,
            },
            TestMetric {
                day_index: 1,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 0,
                num_blocks_failed: 100,
            },
            TestMetric {
                day_index: 2,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 0,
                num_blocks_failed: 100,
            },
        ]),
        TestNode::new(node_id(6), "AS", NodeRewardType::Type1).with_metrics(vec![
            TestMetric {
                day_index: 0,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 80,
                num_blocks_failed: 20,
            },
            TestMetric {
                day_index: 1,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 30,
                num_blocks_failed: 70,
            },
            TestMetric {
                day_index: 2,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 80,
                num_blocks_failed: 20,
            },
            TestMetric {
                day_index: 3,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 30,
                num_blocks_failed: 70,
            },
        ]),
        TestNode::new(node_id(7), "AS", NodeRewardType::Type1).with_metrics(vec![
            TestMetric {
                day_index: 0,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 80,
                num_blocks_failed: 20,
            },
            TestMetric {
                day_index: 1,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 30,
                num_blocks_failed: 70,
            },
            TestMetric {
                day_index: 2,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 90,
                num_blocks_failed: 10,
            },
            TestMetric {
                day_index: 3,
                subnet_id: subnet_id(2),
                num_blocks_proposed: 50,
                num_blocks_failed: 50,
            },
        ]),
    ]);

    let results = RewardCalculatorRunnerTest::default()
        .with_reward_period(0, 4)
        .with_provider(provider)
        .build_and_run()
        .pop_first()
        .unwrap()
        .1;

    // Assertions for Node 5
    let node_5_results = results.results_by_node.get(&node_id(5)).unwrap();
    let node_5_metrics = &node_5_results.daily_metrics;

    assert_eq!(node_5_metrics.len(), 3);

    let day_0_ts = 0;
    let day_1_ts = NANOS_PER_DAY;
    let day_2_ts = 2 * NANOS_PER_DAY;

    assert_eq!(
        node_5_metrics
            .get(&day_0_ts.into())
            .unwrap()
            .relative_fr
            .get(),
        dec!(0)
    );
    assert_eq!(
        node_5_metrics
            .get(&day_1_ts.into())
            .unwrap()
            .relative_fr
            .get(),
        dec!(0.3)
    );
    assert_eq!(
        node_5_metrics
            .get(&day_2_ts.into())
            .unwrap()
            .relative_fr
            .get(),
        dec!(0.6)
    );

    let expected_rewards_reduction: Vec<Percent> = vec![dec!(0), dec!(0.32), dec!(0.8), dec!(0)]
        .into_iter()
        .map(Percent::from)
        .collect_vec();

    assert_eq!(
        node_5_results
            .rewards_reduction
            .values()
            .cloned()
            .collect_vec(),
        expected_rewards_reduction
    );
}

#[test]
fn test_node_provider_rewards_one_assigned() {
    let provider_1 = TestProvider::new(PrincipalId::new_anonymous()).with_nodes(vec![
        TestNode::new(node_id(1), "A,B", NodeRewardType::Type1).with_metrics(vec![
            TestMetric {
                day_index: 0,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 60,
                num_blocks_failed: 40,
            },
            TestMetric {
                day_index: 1,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 80,
                num_blocks_failed: 20,
            },
            TestMetric {
                day_index: 2,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 70,
                num_blocks_failed: 30,
            },
            TestMetric {
                day_index: 3,
                subnet_id: subnet_id(1),
                num_blocks_proposed: 60,
                num_blocks_failed: 40,
            },
        ]),
        TestNode::new(node_id(2), "A,B", NodeRewardType::Type1),
        TestNode::new(node_id(3), "A,B", NodeRewardType::Type1),
        TestNode::new(node_id(4), "A,B", NodeRewardType::Type1),
        TestNode::new(node_id(5), "A,B", NodeRewardType::Type1),
    ]);

    // This provider's nodes have perfect performance to make the subnet failure rate 0.
    let provider_2 = TestProvider::new(PrincipalId::new_user_test_id(99)).with_nodes(vec![
        TestNode::new(node_id(6), "C,D", NodeRewardType::Type1).with_metrics(
            (0..4)
                .map(|i| TestMetric {
                    day_index: i,
                    subnet_id: subnet_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                })
                .collect(),
        ),
        TestNode::new(node_id(7), "C,D", NodeRewardType::Type1).with_metrics(
            (0..4)
                .map(|i| TestMetric {
                    day_index: i,
                    subnet_id: subnet_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                })
                .collect(),
        ),
        TestNode::new(node_id(8), "C,D", NodeRewardType::Type1).with_metrics(
            (0..4)
                .map(|i| TestMetric {
                    day_index: i,
                    subnet_id: subnet_id(1),
                    num_blocks_proposed: 100,
                    num_blocks_failed: 0,
                })
                .collect(),
        ),
    ]);

    let results = RewardCalculatorRunnerTest::default()
        .with_reward_period(0, 30)
        .with_rewards_rates(
            "A,B",
            vec![
                NodeRewardType::Type0,
                NodeRewardType::Type1,
                NodeRewardType::Type3,
            ],
            1000,
            97,
        )
        .with_provider(provider_1)
        .with_provider(provider_2)
        .build_and_run();

    let provider_1_results = results.get(&PrincipalId::new_anonymous()).unwrap();
    assert_eq!(provider_1_results.rewards_total.get().round(), dec!(421));
}
