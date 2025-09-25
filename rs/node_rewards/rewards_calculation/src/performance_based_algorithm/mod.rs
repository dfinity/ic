use crate::performance_based_algorithm::results::{
    BaseRewards, BaseRewardsType3, DailyResults, NodeMetricsDaily, NodeProviderRewards,
    NodeResults, NodeStatus, Percent, RewardsCalculatorResults, XDRPermyriad,
};
use crate::types::{DayUtc, NodeMetricsDailyRaw, Region, RewardableNode};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use itertools::Itertools;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use rust_decimal_macros::dec;
use std::collections::BTreeMap;

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
    subnets_fr: BTreeMap<SubnetId, Percent>,
    nodes_metrics_daily: BTreeMap<NodeId, NodeMetricsDaily>,
}

#[derive(Default)]
struct PerformanceMultiplierResults {
    reward_reduction: BTreeMap<NodeId, Percent>,
    performance_multiplier: BTreeMap<NodeId, Percent>,
}

#[derive(Default)]
struct BaseRewardsResults {
    base_rewards: Vec<BaseRewards>,
    base_rewards_type3: Vec<BaseRewardsType3>,
    base_rewards_per_node: BTreeMap<NodeId, XDRPermyriad>,
}

type RewardsCoefficientPercent = Decimal;

#[derive(Default)]
struct AdjustedRewardsResults {
    adjusted_rewards: BTreeMap<NodeId, XDRPermyriad>,
}

pub trait DataProvider {
    fn get_rewards_table(&self, day: &DayUtc) -> Result<NodeRewardsTable, String>;

    fn get_daily_metrics_by_subnet(
        &self,
        day: &DayUtc,
    ) -> Result<BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>>, String>;

    fn get_rewardable_nodes(
        &self,
        day: &DayUtc,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, String>;
}

trait PerformanceBasedAlgorithm {
    /// The percentile used to calculate the failure rate for a subnet.
    const SUBNET_FAILURE_RATE_PERCENTILE: Decimal;

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

    /// From constant [NODE_PROVIDER_REWARD_PERIOD_SECONDS]
    /// const NODE_PROVIDER_REWARD_PERIOD_SECONDS: u64 = 2629800;
    /// const SECONDS_IN_DAY: u64 = 86400;
    /// 2629800 / 86400 = 30.4375 days of rewards
    const REWARDS_TABLE_DAYS: Decimal = dec!(30.4375);

    fn calculate_rewards(
        from_day: &DayUtc,
        to_day: &DayUtc,
        data_provider: impl DataProvider,
    ) -> Result<RewardsCalculatorResults, String> {
        if from_day > to_day {
            return Err("from_day must be before to_day".to_string());
        }

        let reward_period = from_day.days_until(to_day)?;
        let mut total_rewards_per_provider = BTreeMap::new();
        let mut daily_results = BTreeMap::new();

        // Process each day in the reward period
        for day in reward_period {
            let result_for_day = Self::calculate_daily_rewards(&data_provider, &day)?;

            // Accumulate total rewards per provider across all days
            for (provider_id, provider_rewards) in &result_for_day.provider_results {
                total_rewards_per_provider
                    .entry(*provider_id)
                    .and_modify(|total| *total = provider_rewards.rewards_total)
                    .or_insert(provider_rewards.rewards_total);
            }
            daily_results.insert(day, result_for_day);
        }

        let total_rewards_xdr_permyriad = total_rewards_per_provider
            .into_iter()
            .map(|(provider_id, total)| (provider_id, total.trunc().to_u64().unwrap()))
            .collect();

        Ok(RewardsCalculatorResults {
            total_rewards_xdr_permyriad,
            daily_results,
        })
    }

    fn calculate_daily_rewards(
        data_provider: &impl DataProvider,
        day: &DayUtc,
    ) -> Result<DailyResults, String> {
        let rewards_table = data_provider.get_rewards_table(day)?;
        let metrics_by_subnet = data_provider.get_daily_metrics_by_subnet(day)?;
        let providers_rewardable_nodes = data_provider.get_rewardable_nodes(day)?;
        let mut results_per_provider = BTreeMap::new();

        // Calculate failure rates for subnets and individual nodes
        let FailureRateResults {
            subnets_fr,
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
            subnets_fr,
            provider_results: results_per_provider,
        })
    }

    fn calculate_provider_rewards(
        rewards_table: &NodeRewardsTable,
        nodes_metrics_daily: &mut BTreeMap<NodeId, NodeMetricsDaily>,
        rewardable_nodes: Vec<RewardableNode>,
    ) -> NodeProviderRewards {
        let mut provider_nodes_metrics_daily = BTreeMap::new();
        for node in &rewardable_nodes {
            if let Some(metrics) = nodes_metrics_daily.remove(&node.node_id) {
                provider_nodes_metrics_daily.insert(node.node_id, metrics);
            }
        }

        let relative_nodes_fr: BTreeMap<NodeId, Decimal> = provider_nodes_metrics_daily
            .iter()
            .map(|(node_id, metrics)| (*node_id, metrics.relative_fr))
            .collect();

        // Calculate extrapolated failure rate for unassigned nodes
        // This is the average of relative failure rates for assigned nodes
        let extrapolated_fr = if !relative_nodes_fr.is_empty() {
            let values: Vec<Decimal> = relative_nodes_fr.values().cloned().collect();
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
            &relative_nodes_fr,
            &extrapolated_fr,
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
            extrapolated_fr,
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
        fn calculate_daily_node_fr(num_blocks_proposed: u64, num_blocks_failed: u64) -> Decimal {
            let total_blocks = Decimal::from(num_blocks_proposed + num_blocks_failed);
            if total_blocks == Decimal::ZERO {
                Decimal::ZERO
            } else {
                let num_blocks_failed = Decimal::from(num_blocks_failed);
                num_blocks_failed.checked_div(total_blocks).unwrap() // Safe because total_blocks != 0
            }
        }

        let mut result = FailureRateResults::default();

        for (subnet_id, subnet_nodes_metrics) in daily_metrics_by_subnet {
            let nodes_original_fr = subnet_nodes_metrics
                .iter()
                .map(|metrics| {
                    let original_fr = calculate_daily_node_fr(
                        metrics.num_blocks_proposed,
                        metrics.num_blocks_failed,
                    );
                    (metrics.node_id, original_fr)
                })
                .collect::<BTreeMap<_, _>>();
            let nodes_fr = nodes_original_fr.values().cloned().collect::<Vec<_>>();
            let subnet_fr = if nodes_fr.is_empty() {
                Decimal::ZERO
            } else {
                let failure_rates = nodes_fr.iter().sorted().collect::<Vec<_>>();
                let nodes_fr_count = Decimal::from(nodes_fr.len());
                let index = (nodes_fr_count.checked_mul(Self::SUBNET_FAILURE_RATE_PERCENTILE))
                    .unwrap() // Safe because nodes_fr_count > 0
                    .ceil()
                    .saturating_sub(dec!(1))
                    .to_usize()
                    .unwrap();
                *failure_rates[index]
            };
            result.subnets_fr.insert(subnet_id, subnet_fr);

            for NodeMetricsDailyRaw {
                node_id,
                num_blocks_proposed,
                num_blocks_failed,
            } in subnet_nodes_metrics
            {
                let original_fr = nodes_original_fr[&node_id];
                let relative_fr = original_fr.saturating_sub(subnet_fr);

                result.nodes_metrics_daily.insert(
                    node_id,
                    NodeMetricsDaily {
                        subnet_assigned: subnet_id,
                        subnet_assigned_fr: subnet_fr,
                        num_blocks_proposed,
                        num_blocks_failed,
                        original_fr,
                        relative_fr,
                    },
                );
            }
        }
        result
    }

    fn calculate_performance_multipliers(
        rewardable_nodes: &[RewardableNode],
        relative_nodes_fr: &BTreeMap<NodeId, Decimal>,
        extrapolated_fr: &Decimal,
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
            let daily_fr_used = relative_nodes_fr
                .get(&node.node_id)
                .copied()
                .unwrap_or(*extrapolated_fr);

            let rewards_reduction = calculate_rewards_reduction(daily_fr_used);
            let performance_mult = dec!(1).saturating_sub(rewards_reduction);

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
                    // Default reward_coefficient_percent is set to 80%, which is used as a fallback only in the
                    // unlikely case that the type3 entry in the reward table:
                    // a) has xdr_permyriad_per_node_per_month entry set for this region, but
                    // b) does NOT have the reward_coefficient_percent value set
                    let reward_coefficient_percent =
                        Decimal::from(rate.reward_coefficient_percent.unwrap_or(80))
                            .checked_div(dec!(100))
                            .unwrap();

                    (base_rewards_monthly, reward_coefficient_percent)
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
            let base_rewards_daily = base_rewards_monthly / Self::REWARDS_TABLE_DAYS;

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
                    BaseRewardsType3 {
                        region,
                        nodes_count,
                        avg_rewards,
                        avg_coefficient,
                        value: daily_rewards,
                    }
                },
            )
            .collect();

        let base_rewards = base_rewards
            .into_iter()
            .map(
                |((node_reward_type, region), (daily_rewards, monthly_rewards))| BaseRewards {
                    node_reward_type,
                    region,
                    monthly: monthly_rewards,
                    daily: daily_rewards,
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
        extrapolated_fr: Percent,
        mut reward_reduction: BTreeMap<NodeId, Percent>,
        mut performance_multiplier: BTreeMap<NodeId, Percent>,
        mut base_rewards_per_node: BTreeMap<NodeId, XDRPermyriad>,
        mut adjusted_rewards: BTreeMap<NodeId, XDRPermyriad>,
        base_rewards: Vec<BaseRewards>,
        base_rewards_type3: Vec<BaseRewardsType3>,
    ) -> NodeProviderRewards {
        let mut results_by_node = Vec::new();
        let mut rewards_total = Decimal::ZERO;

        for node in rewardable_nodes {
            let node_status =
                if let Some(node_metrics) = provider_nodes_metrics_daily.remove(&node.node_id) {
                    NodeStatus::Assigned { node_metrics }
                } else {
                    NodeStatus::Unassigned { extrapolated_fr }
                };

            let rewards_reduction_percent = reward_reduction
                .remove(&node.node_id)
                .expect("Rewards reduction should be present in rewards");

            let performance_multiplier_percent = performance_multiplier
                .remove(&node.node_id)
                .expect("Performance multiplier should be present in rewards");

            let base_rewards_xdr_permyriad = base_rewards_per_node
                .remove(&node.node_id)
                .expect("Base rewards should be present in rewards");

            let adjusted_rewards_xdr_permyriad = adjusted_rewards
                .remove(&node.node_id)
                .expect("Adjusted rewards should be present in rewards");

            rewards_total += adjusted_rewards_xdr_permyriad;

            results_by_node.push(NodeResults {
                node_id: node.node_id,
                node_reward_type: node.node_reward_type,
                region: node.region,
                dc_id: node.dc_id,
                node_status,
                performance_multiplier: performance_multiplier_percent,
                rewards_reduction: rewards_reduction_percent,
                base_rewards: base_rewards_xdr_permyriad,
                adjusted_rewards: adjusted_rewards_xdr_permyriad,
            });
        }

        NodeProviderRewards {
            rewards_total,
            base_rewards,
            base_rewards_type3,
            nodes_results: results_by_node,
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
        let values_count = Decimal::from(values.len());
        Some(
            values
                .iter()
                .sum::<Decimal>()
                .checked_div(values_count)
                .unwrap(),
        ) // Safe because values_count > 0
    }
}
