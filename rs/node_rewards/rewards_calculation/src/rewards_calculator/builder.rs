use super::*;
use crate::types::ProviderRewardableNodes;

pub struct RewardsCalculatorBuilder {
    pub reward_period: RewardPeriod,
    pub rewards_table: NodeRewardsTable,
    pub daily_metrics_by_subnet: HashMap<SubnetMetricsDailyKey, Vec<NodeMetricsDailyRaw>>,
    pub rewardable_nodes_per_provider: BTreeMap<PrincipalId, ProviderRewardableNodes>,
}

/// The percentile used to calculate the failure rate for a subnet.
const SUBNET_FAILURE_RATE_PERCENTILE: f64 = 0.75;

impl RewardsCalculatorBuilder {
    fn validate_input(&self) -> Result<(), RewardCalculatorError> {
        for (key, daily_metrics) in self.daily_metrics_by_subnet.iter() {
            // Check if all metrics are within the reward period
            if !self.reward_period.contains(key.day) {
                return Err(RewardCalculatorError::SubnetMetricsOutOfRange {
                    subnet_id: key.subnet_id,
                    day: key.day,
                    reward_period: self.reward_period.clone(),
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

    fn calculate_daily_node_fr(num_blocks_proposed: u64, num_blocks_failed: u64) -> Decimal {
        let total_blocks = Decimal::from(num_blocks_proposed + num_blocks_failed);
        if total_blocks == Decimal::ZERO {
            Decimal::ZERO
        } else {
            let num_blocks_failed = Decimal::from(num_blocks_failed);
            num_blocks_failed / total_blocks
        }
    }

    fn calculate_daily_subnet_fr(daily_nodes_fr: &[Decimal]) -> Decimal {
        let failure_rates = daily_nodes_fr.iter().sorted().collect::<Vec<_>>();
        let index =
            ((daily_nodes_fr.len() as f64) * SUBNET_FAILURE_RATE_PERCENTILE).ceil() as usize - 1;
        *failure_rates[index]
    }

    pub fn build(self) -> Result<RewardsCalculator, RewardCalculatorError> {
        self.validate_input()?;

        let metrics_by_node = self
            .daily_metrics_by_subnet
            .into_iter()
            .flat_map(|(key, subnet_nodes_metrics)| {
                let nodes_fr = subnet_nodes_metrics
                    .iter()
                    .map(|metrics| {
                        Self::calculate_daily_node_fr(
                            metrics.num_blocks_proposed,
                            metrics.num_blocks_failed,
                        )
                    })
                    .collect::<Vec<_>>();
                let subnet_fr = Self::calculate_daily_subnet_fr(&nodes_fr);

                subnet_nodes_metrics.into_iter().map(move |metrics| {
                    let num_blocks_proposed = metrics.num_blocks_proposed;
                    let num_blocks_failed = metrics.num_blocks_failed;
                    let original_fr =
                        Self::calculate_daily_node_fr(num_blocks_proposed, num_blocks_failed);
                    let relative_fr = max(Decimal::ZERO, original_fr - subnet_fr);

                    (
                        metrics.node_id,
                        NodeMetricsDaily {
                            num_blocks_proposed,
                            num_blocks_failed,
                            subnet_assigned: key.subnet_id,
                            day: key.day,
                            subnet_assigned_fr: subnet_fr.into(),
                            original_fr: original_fr.into(),
                            relative_fr: relative_fr.into(),
                        },
                    )
                })
            })
            .into_group_map();

        Ok(RewardsCalculator {
            reward_period: self.reward_period,
            rewards_table: self.rewards_table,
            rewardable_nodes_per_provider: self.rewardable_nodes_per_provider,
            metrics_by_node,
        })
    }
}
