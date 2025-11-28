use crate::AlgorithmVersion;
use crate::REWARDS_TABLE_DAYS;
use crate::performance_based_algorithm::results::{
    DailyNodeFailureRate, DailyNodeProviderRewards, DailyNodeRewards, DailyResults,
    NodeMetricsDaily, NodeTypeRegionBaseRewards, RewardsCalculatorResults, Type3RegionBaseRewards,
};
use crate::types::{NodeMetricsDailyRaw, Region, RewardableNode};
use chrono::NaiveDate;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use itertools::Itertools;
use rust_decimal::Decimal;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive, Zero};
use rust_decimal_macros::dec;
use std::cmp::max;
use std::collections::{BTreeMap, HashMap};

pub mod results;
pub mod test_utils;
pub mod v1;

// ================================================================================================
// VERSIONING SAFETY WARNING
// ================================================================================================
//
// This PerformanceBasedAlgorithm trait defines the core reward calculation interface.
//
// The trait methods in this module should NOT be modified directly as they serve as the
// stable API contract for all reward calculation versions. Instead, new algorithm versions
// should be created by implementing this trait with different behavior, as demonstrated
// by RewardsCalculationV1.
//
// This approach ensures:
//
// 1. **API Stability**: The trait interface remains consistent across versions
// 2. **Backward Compatibility**: Existing implementations continue to work
// 3. **Version Isolation**: Each version can have its own calculation logic
// 4. **Historical Reproducibility**: Past calculations remain verifiable
//
//
// To create a new algorithm version:
// 1. Create a new module (e.g., v2.rs)
// 2. Implement the PerformanceBasedAlgorithm trait
// 3. Override only the methods that need different behavior
// 4. Keep the same trait interface for compatibility
// ================================================================================================

#[derive(Default)]
struct FailureRateResults {
    subnets_failure_rate: BTreeMap<SubnetId, Decimal>,
    nodes_metrics_daily: BTreeMap<NodeId, NodeMetricsDaily>,
}

#[derive(Default)]
struct PerformanceMultiplierResults {
    reward_reduction: BTreeMap<NodeId, Decimal>,
    performance_multiplier: BTreeMap<NodeId, Decimal>,
}

#[derive(Default)]
struct BaseRewardsResults {
    base_rewards: Vec<NodeTypeRegionBaseRewards>,
    base_rewards_type3: Vec<Type3RegionBaseRewards>,
    base_rewards_per_node: BTreeMap<NodeId, Decimal>,
}

type RewardsCoefficientPercent = Decimal;

#[derive(Default)]
struct AdjustedRewardsResults {
    adjusted_rewards: BTreeMap<NodeId, Decimal>,
}

pub trait PerformanceBasedAlgorithmInputProvider {
    fn get_rewards_table(&self, date: &NaiveDate) -> Result<NodeRewardsTable, String>;

    fn get_daily_metrics_by_subnet(
        &self,
        date: &NaiveDate,
    ) -> Result<BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>>, String>;

    fn get_rewardable_nodes(
        &self,
        date: &NaiveDate,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, String>;
}

trait PerformanceBasedAlgorithm: AlgorithmVersion {
    /// The percentile used to calculate the failure rate for a subnet.
    const SUBNET_FAILURE_RATE_PERCENTILE: f64;

    /// The minimum and maximum failure rates for a node.
    /// Nodes with a failure rate below `MIN_FAILURE_RATE` will not be penalized.
    const MIN_FAILURE_RATE: Decimal;

    /// The maximum failure rate for a node.
    /// Nodes with a failure rate above `MAX_FAILURE_RATE` will be penalized with `MAX_REWARDS_REDUCTION`.
    const MAX_FAILURE_RATE: Decimal;

    /// The minimum rewards reduction for a node.
    const MIN_REWARDS_REDUCTION: Decimal;

    /// The maximum rewards reduction for a node.
    const MAX_REWARDS_REDUCTION: Decimal;

    fn calculate_rewards(
        from_date: NaiveDate,
        to_date: NaiveDate,
        input_provider: impl PerformanceBasedAlgorithmInputProvider,
    ) -> Result<RewardsCalculatorResults, String> {
        if from_date > to_date {
            return Err("from_day must be before to_day".to_string());
        }

        let reward_period = from_date.iter_days().take_while(|d| *d <= to_date);
        let mut total_rewards_xdr_permyriad = BTreeMap::new();
        let mut daily_results = BTreeMap::new();

        // Process each day in the reward period
        for day in reward_period {
            let result_for_day = Self::calculate_daily_rewards(&input_provider, &day)?;

            // Accumulate total rewards per provider across all days
            for (provider_id, provider_rewards) in &result_for_day.provider_results {
                total_rewards_xdr_permyriad
                    .entry(*provider_id)
                    .and_modify(|total| {
                        *total += provider_rewards.total_adjusted_rewards_xdr_permyriad
                    })
                    .or_insert(provider_rewards.total_adjusted_rewards_xdr_permyriad);
            }
            daily_results.insert(day, result_for_day);
        }

        Ok(RewardsCalculatorResults {
            algorithm_version: Self::VERSION,
            total_rewards_xdr_permyriad,
            daily_results,
        })
    }

    fn calculate_daily_rewards(
        data_provider: &impl PerformanceBasedAlgorithmInputProvider,
        date: &NaiveDate,
    ) -> Result<DailyResults, String> {
        let rewards_table = data_provider.get_rewards_table(date)?;
        let metrics_by_subnet = data_provider.get_daily_metrics_by_subnet(date)?;
        let providers_rewardable_nodes = data_provider.get_rewardable_nodes(date)?;
        let mut results_per_provider = BTreeMap::new();

        // Calculate failure rates for subnets and individual nodes
        let FailureRateResults {
            subnets_failure_rate,
            mut nodes_metrics_daily,
        } = Self::calculate_failure_rates(metrics_by_subnet);

        // Process each provider's nodes
        for (provider_id, rewardable_nodes) in providers_rewardable_nodes {
            let provider_results = Self::calculate_provider_rewards(
                &rewards_table,
                &mut nodes_metrics_daily,
                rewardable_nodes,
            );
            results_per_provider.insert(provider_id, provider_results);
        }

        Ok(DailyResults {
            subnets_failure_rate,
            provider_results: results_per_provider,
        })
    }

    fn calculate_provider_rewards(
        rewards_table: &NodeRewardsTable,
        nodes_metrics_daily: &mut BTreeMap<NodeId, NodeMetricsDaily>,
        rewardable_nodes: Vec<RewardableNode>,
    ) -> DailyNodeProviderRewards {
        let mut provider_nodes_metrics_daily = BTreeMap::new();
        for node in &rewardable_nodes {
            if let Some(metrics) = nodes_metrics_daily.remove(&node.node_id) {
                provider_nodes_metrics_daily.insert(node.node_id, metrics);
            }
        }

        let relative_nodes_failure_rate: BTreeMap<NodeId, Decimal> = provider_nodes_metrics_daily
            .iter()
            .map(|(node_id, metrics)| (*node_id, metrics.relative_failure_rate))
            .collect();

        // Calculate extrapolated failure rate for unassigned nodes
        // This is the average of relative failure rates for assigned nodes
        let extrapolated_failure_rate = if !relative_nodes_failure_rate.is_empty() {
            let values: Vec<Decimal> = relative_nodes_failure_rate.values().cloned().collect();
            avg(&values).unwrap_or_default()
        } else {
            Decimal::ZERO
        };

        // Calculate performance multipliers based on failure rates
        // Assigned nodes use actual failure rate, unassigned nodes use extrapolated rate
        let PerformanceMultiplierResults {
            reward_reduction,
            performance_multiplier,
        } = Self::calculate_performance_multipliers(
            &rewardable_nodes,
            &relative_nodes_failure_rate,
            &extrapolated_failure_rate,
        );

        // Calculate base rewards for each node based on region and node type
        // Handles special logic for Type3 nodes (grouped by country, with reduction coefficients)
        let BaseRewardsResults {
            base_rewards_per_node,
            base_rewards,
            base_rewards_type3,
        } = Self::calculate_base_rewards_by_region_and_type(rewards_table, &rewardable_nodes);

        // Apply performance multipliers to base rewards to get final daily rewards
        let AdjustedRewardsResults { adjusted_rewards } = Self::apply_performance_adjustments(
            &rewardable_nodes,
            &base_rewards_per_node,
            &performance_multiplier,
        );

        // Combine all calculated values into the final NodeProviderRewards structure
        Self::build_provider_rewards_summary(
            rewardable_nodes,
            provider_nodes_metrics_daily,
            extrapolated_failure_rate,
            reward_reduction,
            performance_multiplier,
            base_rewards_per_node,
            adjusted_rewards,
            base_rewards,
            base_rewards_type3,
        )
    }

    // ------------------------------------------------------------------------------------------------
    // Calculate failure rates for subnets and individual nodes
    // ------------------------------------------------------------------------------------------------
    fn calculate_failure_rates(
        daily_metrics_by_subnet: BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>>,
    ) -> FailureRateResults {
        fn calculate_daily_node_failure_rate(proposed: u64, failed: u64) -> Decimal {
            let total = Decimal::from(proposed + failed);
            if total.is_zero() {
                Decimal::ZERO
            } else {
                Decimal::from(failed) / total
            }
        }

        let mut result = FailureRateResults::default();

        // Find the maximum number of blocks proposed and failed for each node across all subnets.
        // This is used in case one node joins multiple subnets the same day. In this case, the algorithm
        // will assign the node to the subnet with the highest number of blocks proposed and failed.
        let mut max_blocks_by_node: HashMap<NodeId, (SubnetId, NodeMetricsDailyRaw)> =
            HashMap::new();

        for (subnet_id, metrics_list) in daily_metrics_by_subnet {
            for metric in metrics_list {
                let total_blocks = metric.num_blocks_proposed + metric.num_blocks_failed;
                max_blocks_by_node
                    .entry(metric.node_id)
                    .and_modify(|(s, existing)| {
                        let existing_total =
                            existing.num_blocks_proposed + existing.num_blocks_failed;
                        if total_blocks > existing_total {
                            *s = subnet_id;
                            *existing = metric.clone();
                        }
                    })
                    .or_insert((subnet_id, metric));
            }
        }

        // Group deduplicated metrics back by subnet.
        let deduped_by_subnet: BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>> = max_blocks_by_node
            .into_values()
            .fold(BTreeMap::new(), |mut acc, (subnet, metric)| {
                acc.entry(subnet).or_default().push(metric);
                acc
            });

        // Compute failure rates per subnet and per node.
        for (subnet_id, metrics_list) in deduped_by_subnet {
            // Precompute node failure rates for this subnet.
            let nodes_failure_rate: BTreeMap<_, _> = metrics_list
                .iter()
                .map(|m| {
                    let rate = calculate_daily_node_failure_rate(
                        m.num_blocks_proposed,
                        m.num_blocks_failed,
                    );
                    (m.node_id, rate)
                })
                .collect();

            // Sort to find the subnet percentile failure rate.
            let rates: Vec<_> = nodes_failure_rate
                .values()
                .cloned()
                .sorted()
                .collect::<Vec<_>>();

            let subnet_rate = if rates.is_empty() {
                Decimal::ZERO
            } else {
                // Nearest-rank percentile method.
                let idx = (((rates.len() as f64) * Self::SUBNET_FAILURE_RATE_PERCENTILE).ceil()
                    as isize
                    - 1)
                .max(0) as usize;
                rates[idx]
            };

            result.subnets_failure_rate.insert(subnet_id, subnet_rate);

            // Compute each node’s relative failure rate.
            for metric in metrics_list {
                let original = nodes_failure_rate[&metric.node_id];
                let relative = max(Decimal::ZERO, original - subnet_rate);

                result.nodes_metrics_daily.insert(
                    metric.node_id,
                    NodeMetricsDaily {
                        subnet_assigned: subnet_id,
                        subnet_assigned_failure_rate: subnet_rate,
                        num_blocks_proposed: metric.num_blocks_proposed,
                        num_blocks_failed: metric.num_blocks_failed,
                        original_failure_rate: original,
                        relative_failure_rate: relative,
                    },
                );
            }
        }

        result
    }

    fn calculate_performance_multipliers(
        rewardable_nodes: &[RewardableNode],
        relative_nodes_failure_rate: &BTreeMap<NodeId, Decimal>,
        extrapolated_failure_rate: &Decimal,
    ) -> PerformanceMultiplierResults {
        let mut reward_reduction = BTreeMap::new();
        let mut performance_multiplier = BTreeMap::new();

        let calculate_rewards_reduction = |fr: Decimal| -> Decimal {
            if fr < Self::MIN_FAILURE_RATE {
                Self::MIN_REWARDS_REDUCTION
            } else if fr > Self::MAX_FAILURE_RATE {
                Self::MAX_REWARDS_REDUCTION
            } else {
                // Linear interpolation between MIN_REWARDS_REDUCTION and MAX_REWARDS_REDUCTION
                (fr - Self::MIN_FAILURE_RATE) / (Self::MAX_FAILURE_RATE - Self::MIN_FAILURE_RATE)
                    * Self::MAX_REWARDS_REDUCTION
            }
        };

        for node in rewardable_nodes {
            let daily_failure_rate_used = relative_nodes_failure_rate
                .get(&node.node_id)
                .copied()
                .unwrap_or(*extrapolated_failure_rate);

            let rewards_reduction = calculate_rewards_reduction(daily_failure_rate_used);
            let performance_mult = dec!(1) - rewards_reduction;

            reward_reduction.insert(node.node_id, rewards_reduction);
            performance_multiplier.insert(node.node_id, performance_mult);
        }

        PerformanceMultiplierResults {
            reward_reduction,
            performance_multiplier,
        }
    }

    // ------------------------------------------------------------------------------------------------
    // Calculate base rewards for each node based on region and node type
    // ------------------------------------------------------------------------------------------------
    fn calculate_base_rewards_by_region_and_type(
        node_rewards_table: &NodeRewardsTable,
        rewardable_nodes: &[RewardableNode],
    ) -> BaseRewardsResults {
        fn get_monthly_rate(
            rewards_table: &NodeRewardsTable,
            region: &Region,
            node_reward_type: &NodeRewardType,
        ) -> (Decimal, RewardsCoefficientPercent) {
            rewards_table
                .get_rate(region, &node_reward_type.to_string())
                .map(|rate| {
                    let base_rewards_monthly = Decimal::from(rate.xdr_permyriad_per_node_per_month);
                    // Default reward_coefficient percent is set to 80%, which is used as a fallback only in the
                    // unlikely case that the type3 entry in the reward table:
                    // a) has xdr_permyriad_per_node_per_month entry set for this region, but
                    // b) does NOT have the reward_coefficient value set
                    let reward_coefficient =
                        Decimal::from(rate.reward_coefficient_percent.unwrap_or(80)) / dec!(100);

                    (base_rewards_monthly, reward_coefficient)
                })
                .unwrap_or((dec!(1), dec!(1)))
        }

        fn is_type3(node_type: &NodeRewardType) -> bool {
            node_type == &NodeRewardType::Type3 || node_type == &NodeRewardType::Type3dot1
        }

        fn type3_region_key(region: &Region) -> String {
            region
                .splitn(3, ',')
                .take(2)
                .collect::<Vec<&str>>()
                .join(":")
        }

        let mut base_rewards = BTreeMap::new();
        let mut base_rewards_type3 = BTreeMap::new();
        let mut base_rewards_per_node = BTreeMap::new();

        for node in rewardable_nodes {
            let (base_rewards_monthly, coefficient) =
                get_monthly_rate(node_rewards_table, &node.region, &node.node_reward_type);
            let base_rewards_daily =
                base_rewards_monthly / Decimal::from_f64(REWARDS_TABLE_DAYS).unwrap();

            base_rewards
                .entry((node.node_reward_type, node.region.clone()))
                .or_insert((base_rewards_daily, base_rewards_monthly));

            // For nodes which are type3* the base rewards for the single node is computed as the average of base rewards
            // on DC Country level. Moreover, to de-stimulate the same NP having too many nodes in the same country,
            // the node rewards is reduced for each node the NP has in the given country. The reduction coefficient is
            // computed as the average of reduction coefficients on DC Country level.
            if is_type3(&node.node_reward_type) {
                // The rewards table contains entries of this form DC Continent + DC Country + DC State/City.
                // The grouping for type3* nodes will be on DC Continent + DC Country level. This group is used for computing
                // the reduction coefficient and base reward for the group.
                let region_key = type3_region_key(&node.region);

                base_rewards_type3
                    .entry(region_key.clone())
                    .and_modify(
                        |(rates, coeffs): &mut (Vec<Decimal>, Vec<RewardsCoefficientPercent>)| {
                            rates.push(base_rewards_daily);
                            coeffs.push(coefficient);
                        },
                    )
                    .or_insert((vec![base_rewards_daily], vec![coefficient]));
            }
        }

        let base_rewards_type3 = base_rewards_type3
            .into_iter()
            .map(|(region, (rates, coeff))| {
                let nodes_count = rates.len();
                let avg_rate = avg(rates.as_slice()).unwrap_or_default();
                let avg_coeff = avg(coeff.as_slice()).unwrap_or_default();

                let mut running_coefficient = dec!(1);
                let mut region_rewards = Vec::new();
                for _ in 0..nodes_count {
                    region_rewards.push(avg_rate * running_coefficient);
                    running_coefficient *= avg_coeff;
                }
                let region_rewards_avg = avg(&region_rewards).unwrap_or_default();

                (
                    region,
                    (region_rewards_avg, nodes_count, avg_rate, avg_coeff),
                )
            })
            .collect::<BTreeMap<_, _>>();

        for node in rewardable_nodes {
            let base_rewards_for_day = if is_type3(&node.node_reward_type) {
                let region_key = type3_region_key(&node.region);

                let (base_rewards_daily, _, _, _) = base_rewards_type3
                    .get(&region_key)
                    .expect("Type3 base rewards expected for provider");
                base_rewards_daily
            } else {
                let (base_rewards_daily, _) = base_rewards
                    .get(&(node.node_reward_type, node.region.clone()))
                    .expect("base rewards expected for each node");
                base_rewards_daily
            };

            base_rewards_per_node.insert(node.node_id, *base_rewards_for_day);
        }

        let base_rewards_type3 = base_rewards_type3
            .into_iter()
            .map(
                |(region, (daily_rewards, nodes_count, avg_rewards, avg_coefficient))| {
                    Type3RegionBaseRewards {
                        region,
                        nodes_count,
                        avg_rewards_xdr_permyriad: avg_rewards,
                        avg_coefficient,
                        daily_xdr_permyriad: daily_rewards,
                    }
                },
            )
            .collect();

        let base_rewards = base_rewards
            .into_iter()
            .map(
                |((node_reward_type, region), (daily_rewards, monthly_rewards))| {
                    NodeTypeRegionBaseRewards {
                        node_reward_type,
                        region,
                        monthly_xdr_permyriad: monthly_rewards,
                        daily_xdr_permyriad: daily_rewards,
                    }
                },
            )
            .collect();

        BaseRewardsResults {
            base_rewards_per_node,
            base_rewards_type3,
            base_rewards,
        }
    }

    fn apply_performance_adjustments(
        rewardable_nodes: &[RewardableNode],
        base_rewards: &BTreeMap<NodeId, Decimal>,
        performance_multiplier: &BTreeMap<NodeId, Decimal>,
    ) -> AdjustedRewardsResults {
        let mut adjusted_rewards = BTreeMap::new();

        for node in rewardable_nodes {
            let base_rewards_for_day = base_rewards
                .get(&node.node_id)
                .expect("Base rewards expected for each node");

            let performance_mult = performance_multiplier
                .get(&node.node_id)
                .expect("Performance multiplier expected for every node");

            let adjusted_rewards_for_day = base_rewards_for_day * performance_mult;
            adjusted_rewards.insert(node.node_id, adjusted_rewards_for_day);
        }

        AdjustedRewardsResults { adjusted_rewards }
    }

    /// Build provider rewards summary using BTreeMap for consistency and better performance
    fn build_provider_rewards_summary(
        rewardable_nodes: Vec<RewardableNode>,
        mut provider_nodes_metrics_daily: BTreeMap<NodeId, NodeMetricsDaily>,
        extrapolated_failure_rate: Decimal,
        mut reward_reduction: BTreeMap<NodeId, Decimal>,
        mut performance_multiplier: BTreeMap<NodeId, Decimal>,
        mut base_rewards_per_node: BTreeMap<NodeId, Decimal>,
        mut adjusted_rewards: BTreeMap<NodeId, Decimal>,
        base_rewards: Vec<NodeTypeRegionBaseRewards>,
        base_rewards_type3: Vec<Type3RegionBaseRewards>,
    ) -> DailyNodeProviderRewards {
        let mut results_by_node = Vec::new();
        let mut total_adjusted_rewards_xdr_permyriad: Decimal = Decimal::zero();
        let mut total_base_rewards_xdr_permyriad: Decimal = Decimal::zero();

        for node in rewardable_nodes {
            let node_status =
                if let Some(node_metrics) = provider_nodes_metrics_daily.remove(&node.node_id) {
                    DailyNodeFailureRate::SubnetMember { node_metrics }
                } else {
                    DailyNodeFailureRate::NonSubnetMember {
                        extrapolated_failure_rate,
                    }
                };

            let node_rewards_reduction = reward_reduction
                .remove(&node.node_id)
                .expect("Rewards reduction should be present in rewards");

            let node_performance_multiplier = performance_multiplier
                .remove(&node.node_id)
                .expect("Performance multiplier should be present in rewards");

            let node_base_rewards_xdr_permyriad = base_rewards_per_node
                .remove(&node.node_id)
                .expect("Base rewards should be present in rewards");

            let node_adjusted_rewards_xdr_permyriad = adjusted_rewards
                .remove(&node.node_id)
                .expect("Adjusted rewards should be present in rewards");

            total_base_rewards_xdr_permyriad += node_base_rewards_xdr_permyriad;

            total_adjusted_rewards_xdr_permyriad += node_adjusted_rewards_xdr_permyriad;

            results_by_node.push(DailyNodeRewards {
                node_id: node.node_id,
                node_reward_type: node.node_reward_type,
                region: node.region,
                dc_id: node.dc_id,
                daily_node_failure_rate: node_status,
                performance_multiplier: node_performance_multiplier,
                rewards_reduction: node_rewards_reduction,
                base_rewards_xdr_permyriad: node_base_rewards_xdr_permyriad,
                adjusted_rewards_xdr_permyriad: node_adjusted_rewards_xdr_permyriad,
            });
        }

        let total_base_rewards_xdr_permyriad = total_base_rewards_xdr_permyriad
            .trunc()
            .to_u64()
            .expect("failed to truncate node_adjusted_rewards_xdr_permyriad");

        let total_adjusted_rewards_xdr_permyriad = total_adjusted_rewards_xdr_permyriad
            .trunc()
            .to_u64()
            .expect("failed to truncate node_adjusted_rewards_xdr_permyriad");

        DailyNodeProviderRewards {
            total_base_rewards_xdr_permyriad,
            total_adjusted_rewards_xdr_permyriad,
            base_rewards,
            type3_base_rewards: base_rewards_type3,
            daily_nodes_rewards: results_by_node,
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------------------------------------

fn avg(values: &[Decimal]) -> Option<Decimal> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<Decimal>() / Decimal::from(values.len()))
    }
}
