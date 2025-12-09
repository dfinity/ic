use ic_base_types::PrincipalId;
use ic_protobuf::registry::{
    dc::v1::DataCenterRecord,
    node_operator::v1::NodeOperatorRecord,
    node_rewards::v2::{NodeRewardRate, NodeRewardsTable},
};
use logs::{LogEntry, RewardsPerNodeProviderLog};
use std::collections::{BTreeMap, HashMap};
pub mod logs;

#[derive(Debug, PartialEq)]
pub struct RewardsPerNodeProvider {
    pub rewards_per_node_provider: BTreeMap<PrincipalId, u64>,
    pub computation_log: BTreeMap<PrincipalId, RewardsPerNodeProviderLog>,
}

pub fn calculate_rewards_v0(
    rewards_table: &NodeRewardsTable,
    node_operators: &[(String, NodeOperatorRecord)],
    data_centers: &BTreeMap<String, DataCenterRecord>,
) -> Result<RewardsPerNodeProvider, String> {
    // The reward coefficients for the NP, at the moment used only for type3 nodes, as a measure for stimulating decentralization.
    // It is kept outside of the reward calculation loop in order to reduce node rewards for NPs with multiple DCs.
    // We want to have as many independent NPs as possible for the given reward budget.
    let mut np_coefficients: HashMap<String, f64> = HashMap::new();

    let mut rewards = BTreeMap::new();
    let mut computation_log = BTreeMap::new();

    for (key_string, node_operator) in node_operators.iter() {
        let node_operator_id = PrincipalId::try_from(&node_operator.node_operator_principal_id)
            .map_err(|e| {
                format!(
                    "Node Operator key '{key_string:?}' cannot be parsed as a PrincipalId: '{e}'"
                )
            })?;

        let node_provider_id = PrincipalId::try_from(&node_operator.node_provider_principal_id)
            .map_err(|e| {
                format!(
                    "Node Operator with key '{node_operator_id}' has a node_provider_principal_id \
                                 that cannot be parsed as a PrincipalId: '{e}'"
                )
            })?;

        let dc = data_centers.get(&node_operator.dc_id).ok_or_else(|| {
            format!(
                "Node Operator with key '{}' has data center ID '{}' \
                            not found in the Registry",
                node_operator_id, node_operator.dc_id
            )
        })?;
        let region = &dc.region;

        let np_rewards = rewards.entry(node_provider_id).or_default();
        let np_log = computation_log
            .entry(node_provider_id)
            .or_insert(RewardsPerNodeProviderLog::new(node_provider_id));

        for (node_type, node_count) in node_operator.rewardable_nodes.iter() {
            let rate = match rewards_table.get_rate(region, node_type) {
                Some(rate) => rate,
                None => {
                    np_log.add_entry(LogEntry::RateNotFoundInRewardTable {
                        region: region.clone(),
                        node_type: node_type.clone(),
                        node_operator_id,
                    });

                    NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 1,
                        reward_coefficient_percent: Some(100),
                    }
                }
            };

            let dc_reward = match &node_type {
                t if t.starts_with("type3") => {
                    // For type3 nodes, the rewards are progressively reduced for each additional node owned by a NP.
                    // This helps to improve network decentralization. The first node gets the full reward.
                    // After the first node, the rewards are progressively reduced by multiplying them with reward_coefficient_percent.
                    // For the n-th node, the reward is:
                    // reward(n) = reward(n-1) * reward_coefficient_percent ^ (n-1)
                    //
                    // A note around the type3 rewards and iter() over self.store
                    //
                    // One known issue with this implementation is that in some edge cases it could lead to
                    // unexpected results. The outer loop iterates over the node operator records sorted
                    // lexicographically, instead of the order in which the records were added to the registry,
                    // or instead of the order in which NP/NO adds nodes to the network. This means that all
                    // reduction factors for the node operator A are applied prior to all reduction factors for
                    // the node operator B, independently from the order in which the node operator records,
                    // nodes, or the rewardable nodes were added to the registry.
                    // For instance, say a Node Provider adds a Node Operator B in region 1 with higher reward
                    // coefficient so higher average rewards, and then A in region 2 with lower reward
                    // coefficient so lower average rewards. When the rewards are calculated, the rewards for
                    // Node Operator A are calculated before the rewards for B (due to the lexicographical
                    // order), and the final rewards will be lower than they would be calculated first for B and
                    // then for A, as expected based on the insert order.

                    let reward_base = rate.xdr_permyriad_per_node_per_month as f64;

                    // To de-stimulate the same NP having too many nodes in the same country, the node rewards
                    // is reduced for each node the NP has in the given country.
                    // Join the NP PrincipalId + DC Continent + DC Country, and use that as the key for the
                    // reduction coefficients.
                    let np_coefficients_key = format!(
                        "{}:{}",
                        node_provider_id,
                        region
                            .splitn(3, ',')
                            .take(2)
                            .collect::<Vec<&str>>()
                            .join(":")
                    );

                    let mut np_coeff = *np_coefficients.get(&np_coefficients_key).unwrap_or(&1.0);

                    // Default reward_coefficient_percent is set to 80%, which is used as a fallback only in the
                    // unlikely case that the type3 entry in the reward table:
                    // a) has xdr_permyriad_per_node_per_month entry set for this region, but
                    // b) does NOT have the reward_coefficient_percent value set
                    let dc_reward_coefficient_percent =
                        rate.reward_coefficient_percent.unwrap_or(80) as f64 / 100.0;

                    let mut dc_reward = 0;
                    for i in 0..*node_count {
                        let node_reward = (reward_base * np_coeff) as u64;
                        np_log.add_entry(LogEntry::NodeRewards {
                            node_type: node_type.clone(),
                            node_idx: i,
                            dc_id: node_operator.dc_id.clone(),
                            rewardable_count: *node_count,
                            rewards_xdr_permyriad: node_reward,
                        });
                        dc_reward += node_reward;
                        np_coeff *= dc_reward_coefficient_percent;
                    }
                    np_coefficients.insert(np_coefficients_key, np_coeff);
                    dc_reward
                }
                _ => *node_count as u64 * rate.xdr_permyriad_per_node_per_month,
            };

            np_log.add_entry(LogEntry::DCRewards {
                dc_id: node_operator.dc_id.clone(),
                node_type: node_type.clone(),
                rewardable_count: *node_count,
                rewards_xdr_permyriad: dc_reward,
            });
            *np_rewards += dc_reward;
        }
    }

    Ok(RewardsPerNodeProvider {
        rewards_per_node_provider: rewards,
        computation_log,
    })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
