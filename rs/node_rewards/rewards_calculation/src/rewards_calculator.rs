use crate::rewards_calculator_results::{
    DailyResults, DayUtc, NodeMetricsDaily, NodeProviderRewards, NodeResults, NodeStatus, Percent,
    RewardCalculatorError, RewardsCalculatorResults, XDRPermyriad,
};
use crate::types::{
    NodeMetricsDailyRaw, Region, RewardPeriod, RewardableNode, SubnetMetricsDailyKey,
};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use itertools::Itertools;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::cmp::max;
use std::collections::{BTreeMap, HashMap, HashSet};

pub struct RewardsCalculatorInput {
    pub reward_period: RewardPeriod,
    pub rewards_table: NodeRewardsTable,
    pub daily_metrics_by_subnet: HashMap<SubnetMetricsDailyKey, Vec<NodeMetricsDailyRaw>>,
    pub provider_rewardable_nodes: BTreeMap<PrincipalId, Vec<RewardableNode>>,
}

fn validate_input(input: &RewardsCalculatorInput) -> Result<(), RewardCalculatorError> {
    for (key, daily_metrics) in input.daily_metrics_by_subnet.iter() {
        // Check if all metrics are within the reward period
        if !input.reward_period.contains(key.day) {
            return Err(RewardCalculatorError::SubnetMetricsOutOfRange {
                subnet_id: key.subnet_id,
                day: key.day,
                reward_period: input.reward_period.clone(),
            });
        }

        // Metrics are unique if there are no duplicate entries for the same day and subnet.
        // Metrics with the same timestamp and different subnet are allowed.
        let unique_node = daily_metrics
            .iter()
            .map(|entry| entry.node_id)
            .collect::<HashSet<_>>();
        if unique_node.len() != daily_metrics.len() {
            return Err(RewardCalculatorError::DuplicateMetrics(
                key.subnet_id,
                key.day,
            ));
        }
    }

    Ok(())
}

pub fn calculate_rewards(
    input: RewardsCalculatorInput,
) -> Result<RewardsCalculatorResults, RewardCalculatorError> {
    validate_input(&input)?;
    let mut results_per_provider = BTreeMap::new();

    // Step 0: Pre-compute subnets and nodes failure rates
    let Step0Results {
        subnets_fr,
        mut nodes_metrics_daily,
    } = step_0_subnets_nodes_fr(input.daily_metrics_by_subnet);

    for (provider_id, rewardable_nodes) in input.provider_rewardable_nodes {
        // Step 1: Extract Provider Nodes metrics daily
        let Step1Results {
            provider_nodes_metrics_daily,
        } = step_1_provider_nodes_metrics_daily(&rewardable_nodes, &mut nodes_metrics_daily);

        // Step 2: Extrapolated failure rate for each provider
        let Step2Results { extrapolated_fr } =
            step_2_extrapolated_fr(&rewardable_nodes, &provider_nodes_metrics_daily);

        // Step 3: Compute performance multiplier for each node for each provider
        let relative_nodes_fr = provider_nodes_metrics_daily
            .iter()
            .map(|((day, node_id), metrics)| ((*day, *node_id), metrics.relative_fr_percent))
            .collect::<BTreeMap<_, _>>();
        let Step3Results {
            reward_reduction,
            performance_multiplier,
        } = step_3_performance_multiplier(&rewardable_nodes, &relative_nodes_fr, &extrapolated_fr);

        // Step 4: Compute base rewards for each node based on its region and node type
        let Step4Results {
            base_rewards,
            base_rewards_log,
        } = step_4_compute_base_rewards_type_region(&input.rewards_table, &rewardable_nodes);

        // Step 5: Adjusted rewards for all the nodes based on their performance
        let Step5Results { adjusted_rewards } =
            step_5_adjust_node_rewards(&rewardable_nodes, &base_rewards, &performance_multiplier);

        // Step 6: Construct provider results
        let provider_results = step_6_construct_provider_results(
            rewardable_nodes,
            provider_nodes_metrics_daily,
            extrapolated_fr,
            reward_reduction,
            performance_multiplier,
            base_rewards,
            adjusted_rewards,
            base_rewards_log,
        );

        results_per_provider.insert(provider_id, provider_results);
    }

    Ok(RewardsCalculatorResults {
        subnets_fr_percent: subnets_fr,
        provider_results: results_per_provider,
    })
}

// ------------------------------------------------------------------------------------------------
// Step 0: Pre-compute subnets and nodes failure rates
// ------------------------------------------------------------------------------------------------

/// The percentile used to calculate the failure rate for a subnet.
const SUBNET_FAILURE_RATE_PERCENTILE: f64 = 0.75;

#[derive(Default)]
struct Step0Results {
    subnets_fr: BTreeMap<(DayUtc, SubnetId), Percent>,
    nodes_metrics_daily: BTreeMap<(DayUtc, NodeId), NodeMetricsDaily>,
}
fn step_0_subnets_nodes_fr(
    daily_metrics_by_subnet: HashMap<SubnetMetricsDailyKey, Vec<NodeMetricsDailyRaw>>,
) -> Step0Results {
    fn calculate_daily_node_fr(num_blocks_proposed: u64, num_blocks_failed: u64) -> Decimal {
        let total_blocks = Decimal::from(num_blocks_proposed + num_blocks_failed);
        if total_blocks == Decimal::ZERO {
            Decimal::ZERO
        } else {
            let num_blocks_failed = Decimal::from(num_blocks_failed);
            num_blocks_failed / total_blocks
        }
    }

    fn calculate_daily_subnet_fr(nodes_fr: &[Decimal]) -> Decimal {
        let failure_rates = nodes_fr.iter().sorted().collect::<Vec<_>>();
        let index = ((nodes_fr.len() as f64) * SUBNET_FAILURE_RATE_PERCENTILE).ceil() as usize - 1;
        *failure_rates[index]
    }

    let mut result = Step0Results::default();

    for (SubnetMetricsDailyKey { subnet_id, day }, subnet_nodes_metrics) in daily_metrics_by_subnet
    {
        let nodes_original_fr = subnet_nodes_metrics
            .iter()
            .map(|metrics| {
                let original_fr =
                    calculate_daily_node_fr(metrics.num_blocks_proposed, metrics.num_blocks_failed);
                (metrics.node_id, original_fr)
            })
            .collect::<BTreeMap<_, _>>();

        let subnet_fr =
            calculate_daily_subnet_fr(&nodes_original_fr.values().cloned().collect::<Vec<_>>());
        result.subnets_fr.insert((day, subnet_id), subnet_fr);

        for NodeMetricsDailyRaw {
            node_id,
            num_blocks_proposed,
            num_blocks_failed,
        } in subnet_nodes_metrics
        {
            let original_fr = nodes_original_fr[&node_id];
            let relative_fr = max(Decimal::ZERO, original_fr - subnet_fr);

            result.nodes_metrics_daily.insert(
                (day, node_id),
                NodeMetricsDaily {
                    subnet_assigned: subnet_id,
                    subnet_assigned_fr_percent: subnet_fr,
                    num_blocks_proposed,
                    num_blocks_failed,
                    original_fr_percent: original_fr,
                    relative_fr_percent: relative_fr,
                },
            );
        }
    }
    result
}

// ------------------------------------------------------------------------------------------------
// Step 1: Extract Provider Nodes metrics daily
// ------------------------------------------------------------------------------------------------
#[derive(Default)]
struct Step1Results {
    provider_nodes_metrics_daily: BTreeMap<(DayUtc, NodeId), NodeMetricsDaily>,
}

fn step_1_provider_nodes_metrics_daily(
    rewardable_nodes: &[RewardableNode],
    node_metrics_daily: &mut BTreeMap<(DayUtc, NodeId), NodeMetricsDaily>,
) -> Step1Results {
    let mut provider_nodes_metrics_daily = BTreeMap::new();

    for node in rewardable_nodes {
        for day in &node.rewardable_days {
            if let Some(metrics) = node_metrics_daily.remove(&(*day, node.node_id)) {
                provider_nodes_metrics_daily.insert((*day, node.node_id), metrics.clone());
            }
        }
    }

    Step1Results {
        provider_nodes_metrics_daily,
    }
}

// ------------------------------------------------------------------------------------------------
// Step 2: Extrapolated failure rate for each provider
// ------------------------------------------------------------------------------------------------
#[derive(Default)]
struct Step2Results {
    extrapolated_fr: HashMap<DayUtc, Percent>,
}
fn step_2_extrapolated_fr(
    rewardable_nodes: &[RewardableNode],
    nodes_metrics_daily: &BTreeMap<(DayUtc, NodeId), NodeMetricsDaily>,
) -> Step2Results {
    let mut result = Step2Results::default();
    // Collect all relative FRs for this provider's nodes grouped by day.
    let mut grouped_fr: BTreeMap<DayUtc, Vec<Decimal>> = BTreeMap::new();
    for ((day, _), metrics) in nodes_metrics_daily {
        grouped_fr
            .entry(*day)
            .or_default()
            .push(metrics.relative_fr_percent);
    }

    // Include all rewardable days even if there was no data
    let all_rewardable_days: HashSet<DayUtc> = rewardable_nodes
        .iter()
        .flat_map(|n| n.rewardable_days.clone())
        .collect();

    for day in all_rewardable_days {
        let frs = grouped_fr.remove(&day).unwrap_or_default();

        // If there are no relative FRs for this day, the extrapolated FR is set to 0.
        let avg_fr = avg(&frs).unwrap_or_default();

        result.extrapolated_fr.insert(day, avg_fr);
    }
    result
}

// ------------------------------------------------------------------------------------------------
// Step 3: Compute performance multiplier for each node for each provider
// ------------------------------------------------------------------------------------------------

/// The minimum and maximum failure rates for a node.
/// Nodes with a failure rate below `MIN_FAILURE_RATE` will not be penalized.
/// Nodes with a failure rate above `MAX_FAILURE_RATE` will be penalized with `MAX_REWARDS_REDUCTION`.
const MIN_FAILURE_RATE: Decimal = dec!(0.1);
const MAX_FAILURE_RATE: Decimal = dec!(0.6);

/// The minimum and maximum rewards reduction for a node.
const MIN_REWARDS_REDUCTION: Decimal = dec!(0);
const MAX_REWARDS_REDUCTION: Decimal = dec!(0.8);

#[derive(Default)]
struct Step3Results {
    reward_reduction: HashMap<(DayUtc, NodeId), Percent>,
    performance_multiplier: HashMap<(DayUtc, NodeId), Percent>,
}
fn step_3_performance_multiplier(
    rewardable_nodes: &[RewardableNode],
    relative_nodes_fr: &BTreeMap<(DayUtc, NodeId), Decimal>,
    extrapolated_fr: &HashMap<DayUtc, Decimal>,
) -> Step3Results {
    let mut results = Step3Results::default();
    fn calculate_rewards_reduction(fr: Decimal) -> Decimal {
        if fr < MIN_FAILURE_RATE {
            MIN_REWARDS_REDUCTION
        } else if fr > MAX_FAILURE_RATE {
            MAX_REWARDS_REDUCTION
        } else {
            // Linear interpolation between MIN_REWARDS_REDUCTION and MAX_REWARDS_REDUCTION
            (fr - MIN_FAILURE_RATE) / (MAX_FAILURE_RATE - MIN_FAILURE_RATE) * MAX_REWARDS_REDUCTION
        }
    }

    for node in rewardable_nodes {
        for day in &node.rewardable_days {
            let daily_fr_used;

            if let Some(relative_fr) = relative_nodes_fr.get(&(*day, node.node_id)) {
                // If the node is assigned on this day, use the relative failure rate for that day.
                daily_fr_used = *relative_fr;
            } else {
                // If the node is not assigned on this day, use the extrapolated failure rate for that day.
                daily_fr_used = *extrapolated_fr
                    .get(day)
                    .expect("Extrapolated FR expected for every provider");
            }
            let rewards_reduction = calculate_rewards_reduction(daily_fr_used);
            let performance_multiplier = dec!(1) - rewards_reduction;

            results
                .reward_reduction
                .insert((*day, node.node_id), rewards_reduction);
            results
                .performance_multiplier
                .insert((*day, node.node_id), performance_multiplier);
        }
    }
    results
}

// ------------------------------------------------------------------------------------------------
// Step 4: Compute base rewards for each node based on its region and node type
// ------------------------------------------------------------------------------------------------
type RewardsCoefficientPercent = Decimal;

/// From constant [NODE_PROVIDER_REWARD_PERIOD_SECONDS]
/// const NODE_PROVIDER_REWARD_PERIOD_SECONDS: u64 = 2629800;
/// 30.4375 = 2629800 / 86400
const REWARDS_TABLE_DAYS: Decimal = dec!(30.4375);

#[derive(Default)]
struct Step4Results {
    base_rewards: BTreeMap<(DayUtc, NodeId), XDRPermyriad>,
    base_rewards_log: String,
}
fn step_4_compute_base_rewards_type_region(
    node_rewards_table: &NodeRewardsTable,
    rewardable_nodes: &[RewardableNode],
) -> Step4Results {
    fn get_daily_rate(
        rewards_table: &NodeRewardsTable,
        region: &Region,
        node_reward_type: &NodeRewardType,
    ) -> (Decimal, RewardsCoefficientPercent) {
        rewards_table
            .get_rate(region, &node_reward_type.to_string())
            .map(|rate| {
                let base_rewards_daily =
                    Decimal::from(rate.xdr_permyriad_per_node_per_month) / REWARDS_TABLE_DAYS;
                // Default reward_coefficient_percent is set to 80%, which is used as a fallback only in the
                // unlikely case that the type3 entry in the reward table:
                // a) has xdr_permyriad_per_node_per_month entry set for this region, but
                // b) does NOT have the reward_coefficient_percent value set
                let reward_coefficient_percent =
                    Decimal::from(rate.reward_coefficient_percent.unwrap_or(80)) / dec!(100);

                (base_rewards_daily, reward_coefficient_percent)
            })
            .unwrap_or((dec!(1), dec!(100)))
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
    let mut base_rewards_log = vec!["Base Rewards Log:".to_string()];

    for node in rewardable_nodes {
        let (base_rewards_daily, coefficient) =
            get_daily_rate(node_rewards_table, &node.region, &node.node_reward_type);

        base_rewards
            .entry((node.node_reward_type, node.region.clone()))
            .or_insert_with(|| {
                base_rewards_log.push(format!(
                    "Region: {}, Type: {}, Base Rewards Daily: {}, Coefficient: {}",
                    node.region, node.node_reward_type, base_rewards_daily, coefficient
                ));
                base_rewards_daily
            });

        // For nodes which are type3* the base rewards for the single node is computed as the average of base rewards
        // on DC Country level. Moreover, to de-stimulate the same NP having too many nodes in the same country,
        // the node rewards is reduced for each node the NP has in the given country. The reduction coefficient is
        // computed as the average of reduction coefficients on DC Country level.
        if is_type3(&node.node_reward_type) {
            // The rewards table contains entries of this form DC Continent + DC Country + DC State/City.
            // The grouping for type3* nodes will be on DC Continent + DC Country level. This group is used for computing
            // the reduction coefficient and base reward for the group.
            let region_key = type3_region_key(&node.region);

            for day in &node.rewardable_days {
                let key = (day, region_key.clone());

                base_rewards_type3
                    .entry(key)
                    .and_modify(
                        |(rates, coeffs): &mut (Vec<Decimal>, Vec<RewardsCoefficientPercent>)| {
                            rates.push(base_rewards_daily);
                            coeffs.push(coefficient);
                        },
                    )
                    .or_insert((vec![base_rewards_daily], vec![coefficient]));
            }
        }
    }

    let base_rewards_type3 = base_rewards_type3
        .into_iter()
        .map(|((day, region), (rates, coeff))| {
            let rates_len = rates.len();
            let avg_rate = avg(rates.as_slice()).unwrap_or_default();
            let avg_coeff = avg(coeff.as_slice()).unwrap_or_default();

            let mut running_coefficient = dec!(1);
            let mut region_rewards = Vec::new();
            for _ in 0..rates_len {
                region_rewards.push(avg_rate * running_coefficient);
                running_coefficient *= avg_coeff;
            }
            let region_rewards_avg = avg(&region_rewards).unwrap_or_default();

            base_rewards_log.push(format!(
                "Type3* - Day: {} Region: {}, Nodes Count: {}, Base Rewards Daily Avg: {}, Coefficient Avg: {}, Base Rewards Daily: {}",
                day, region, rates_len, avg_rate, avg_coeff, region_rewards_avg
            ));

            ((day, region), region_rewards_avg)
        })
        .collect::<BTreeMap<_, _>>();

    for node in rewardable_nodes {
        for day in &node.rewardable_days {
            let base_rewards_for_day = if is_type3(&node.node_reward_type) {
                let region_key = type3_region_key(&node.region);

                base_rewards_type3
                    .get(&(day, region_key))
                    .expect("Type3 base rewards expected for provider")
            } else {
                base_rewards
                    .get(&(node.node_reward_type, node.region.clone()))
                    .expect("base rewards expected for each node")
            };

            base_rewards_per_node.insert((*day, node.node_id), *base_rewards_for_day);
        }
    }

    Step4Results {
        base_rewards: base_rewards_per_node,
        base_rewards_log: base_rewards_log.join("\n"),
    }
}

// ------------------------------------------------------------------------------------------------
// Step 5: Adjusted rewards for all the nodes based on their performance
// ------------------------------------------------------------------------------------------------

const FULL_REWARDS_MACHINES_LIMIT: usize = 4;

#[derive(Default)]
struct Step5Results {
    adjusted_rewards: BTreeMap<(DayUtc, NodeId), XDRPermyriad>,
}
fn step_5_adjust_node_rewards(
    rewardable_nodes: &[RewardableNode],
    base_rewards: &BTreeMap<(DayUtc, NodeId), Decimal>,
    performance_multiplier: &HashMap<(DayUtc, NodeId), Decimal>,
) -> Step5Results {
    let mut nodes_count = BTreeMap::new();
    let mut result = Step5Results::default();

    for node in rewardable_nodes {
        for day in &node.rewardable_days {
            nodes_count
                .entry(day)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }
    }

    for node in rewardable_nodes {
        for day in &node.rewardable_days {
            let provider_nodes_count = nodes_count.get(&day).expect("Daily nodes count expected");

            let base_rewards_for_day = base_rewards
                .get(&(*day, node.node_id))
                .expect("Base rewards expected for each node");

            if provider_nodes_count <= &FULL_REWARDS_MACHINES_LIMIT {
                // Node Providers with up to FULL_REWARDS_MACHINES_LIMIT nodes are rewarded fully,
                // independently of their performance.
                result
                    .adjusted_rewards
                    .insert((*day, node.node_id), *base_rewards_for_day);
            } else {
                let performance_multiplier = performance_multiplier
                    .get(&(*day, node.node_id))
                    .expect("Performance multiplier expected for every node");

                let adjusted_rewards_for_day = base_rewards_for_day * performance_multiplier;
                result
                    .adjusted_rewards
                    .insert((*day, node.node_id), adjusted_rewards_for_day);
            }
        }
    }

    result
}

// ------------------------------------------------------------------------------------------------
// Step 6: Construct provider results
// ------------------------------------------------------------------------------------------------
fn step_6_construct_provider_results(
    rewardable_nodes: Vec<RewardableNode>,
    mut provider_nodes_metrics_daily: BTreeMap<(DayUtc, NodeId), NodeMetricsDaily>,
    extrapolated_fr: HashMap<DayUtc, Percent>,
    mut reward_reduction: HashMap<(DayUtc, NodeId), Percent>,
    mut performance_multiplier: HashMap<(DayUtc, NodeId), Percent>,
    mut base_rewards: BTreeMap<(DayUtc, NodeId), XDRPermyriad>,
    mut adjusted_rewards: BTreeMap<(DayUtc, NodeId), XDRPermyriad>,
    computation_log: String,
) -> NodeProviderRewards {
    let mut results_by_node = Vec::new();
    let mut rewards_total_xdr_permyriad = Decimal::ZERO;

    for node in rewardable_nodes {
        let node_reward_type = node.node_reward_type;
        let region = node.region;
        let dc_id = node.dc_id;
        let mut daily_results = Vec::new();

        for day in node.rewardable_days {
            let node_status = if let Some(node_metrics) =
                provider_nodes_metrics_daily.remove(&(day, node.node_id))
            {
                NodeStatus::Assigned { node_metrics }
            } else {
                let extrapolated_fr = extrapolated_fr
                    .get(&day)
                    .expect("Extrapolated FR expected for every provider");

                NodeStatus::Unassigned {
                    extrapolated_fr_percent: *extrapolated_fr,
                }
            };

            let rewards_reduction_percent = reward_reduction
                .remove(&(day, node.node_id))
                .expect("Rewards reduction should be present in rewards");

            let performance_multiplier_percent = performance_multiplier
                .remove(&(day, node.node_id))
                .expect("Performance multiplier should be present in rewards");

            let base_rewards_xdr_permyriad = base_rewards
                .remove(&(day, node.node_id))
                .expect("Base rewards should be present in rewards");

            let adjusted_rewards_xdr_permyriad = adjusted_rewards
                .remove(&(day, node.node_id))
                .expect("Adjusted rewards should be present in rewards");

            rewards_total_xdr_permyriad += adjusted_rewards_xdr_permyriad;

            daily_results.push(DailyResults {
                day,
                node_status,
                performance_multiplier_percent,
                rewards_reduction_percent,
                base_rewards_xdr_permyriad,
                adjusted_rewards_xdr_permyriad,
            });
        }

        results_by_node.push(NodeResults {
            node_id: node.node_id,
            node_reward_type: node_reward_type.to_string(),
            region,
            dc_id,
            daily_results,
        });
    }

    NodeProviderRewards {
        rewards_total_xdr_permyriad,
        computation_log,
        nodes_results: results_by_node,
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

#[cfg(test)]
mod tests;
