use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_canister_client::CanisterRegistryClient;
use ic_registry_keys::{
    make_subnet_list_record_key, DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX,
    NODE_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY,
};
use ic_types::registry::RegistryClientError;
use indexmap::IndexMap;
use rewards_calculation::rewards_calculator_results::DayUTC;
use rewards_calculation::types::{NodeType, ProviderRewardableNodes, Region, RewardableNode};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;

pub trait RegistryEntry: RegistryValue {
    const KEY_PREFIX: &'static str;
}

impl RegistryEntry for DataCenterRecord {
    const KEY_PREFIX: &'static str = DATA_CENTER_KEY_PREFIX;
}

impl RegistryEntry for NodeOperatorRecord {
    const KEY_PREFIX: &'static str = NODE_OPERATOR_RECORD_KEY_PREFIX;
}

impl RegistryEntry for NodeRecord {
    const KEY_PREFIX: &'static str = NODE_RECORD_KEY_PREFIX;
}

impl RegistryEntry for NodeRewardsTable {
    const KEY_PREFIX: &'static str = NODE_REWARDS_TABLE_KEY;
}

pub struct RegistryQuerier {
    registry_client: Arc<dyn CanisterRegistryClient>,
}

struct NodeOperatorData {
    node_provider_id: PrincipalId,
    dc_id: String,
    region: Region,
}

impl RegistryQuerier {
    pub fn new(registry_client: Arc<dyn CanisterRegistryClient>) -> Self {
        RegistryQuerier { registry_client }
    }

    ///  Returns a list of all subnets present in the registry at the specified version.
    pub fn subnets_list(&self, version: RegistryVersion) -> Vec<SubnetId> {
        let record = self
            .get_versioned_value::<SubnetListRecord>(
                make_subnet_list_record_key().as_str(),
                version,
            )
            .expect("Failed to get subnets list");

        record
            .subnets
            .into_iter()
            .map(|s| {
                SubnetId::from(PrincipalId::try_from(s.as_slice()).expect("Invalid subnet ID"))
            })
            .collect()
    }

    /// Returns the NodeRewardsTable at the specified version.
    pub fn get_rewards_table(&self, version: RegistryVersion) -> NodeRewardsTable {
        self.get_versioned_value::<NodeRewardsTable>(NODE_REWARDS_TABLE_KEY, version)
            .expect("Failed to get NodeRewardsTable")
    }

    /// Computes the set of rewardable nodes, grouped by node provider, for the given range of UTC days.
    ///
    /// A node is considered rewardable on a specific UTC day if it is present in the registry
    /// at the end of that day.
    /// Specifically:
    /// - A node becomes rewardable starting from the UTC day it is registered.
    /// - A node stops being rewardable on the UTC day it is removed from the registry.
    ///
    /// Nodes without a specified `node_reward_type` are excluded from the rewardable set.
    pub fn get_rewardable_nodes_per_provider(
        &self,
        from: DayUTC,
        to: DayUTC,
    ) -> Result<BTreeMap<PrincipalId, ProviderRewardableNodes>, RegistryClientError> {
        let mut rewardable_nodes_per_provider: BTreeMap<_, ProviderRewardableNodes> =
            BTreeMap::new();

        let nodes_in_range = self.nodes_in_registry(from, to)?;
        let node_operators_data = self.node_operators_data(to);

        for (node_id, (node_record, rewardable_days)) in nodes_in_range {
            let node_operator_id: PrincipalId = node_record.node_operator_id.try_into().unwrap();
            let Some(some_node_operator_data) = node_operators_data.get(&node_operator_id) else {
                // Reward only node operators that are registered in the registry at the end of the period
                continue;
            };
            let Some(some_reward_type) = node_record.node_reward_type else {
                // If the node does not have a node_reward_type, we skip it.
                continue;
            };

            let node_reward_type =
                NodeRewardType::try_from(some_reward_type).expect("Invalid node_reward_type value");
            let NodeOperatorData {
                node_provider_id,
                dc_id,
                region,
                ..
            } = some_node_operator_data;

            // TODO: Modify RewardableNode to use NodeRewardType instead of NodeType.
            let node_type = NodeType(node_reward_type.into());

            rewardable_nodes_per_provider
                .entry(*node_provider_id)
                .or_insert(ProviderRewardableNodes {
                    provider_id: *node_provider_id,
                    ..Default::default()
                })
                .rewardable_nodes
                .push(RewardableNode {
                    node_id,
                    rewardable_days,
                    node_type,
                    dc_id: dc_id.clone(),
                    region: region.clone(),
                });
        }
        Ok(rewardable_nodes_per_provider)
    }

    fn get_versioned_value<T: RegistryValue + Default>(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> Result<T, RegistryClientError> {
        let value = self
            .registry_client
            .get_versioned_value(key, version)?
            .map(|v| T::decode(v.as_slice()).unwrap())
            .value
            .unwrap_or_default();
        Ok(value)
    }

    fn get_family_entries_of_version<T: RegistryEntry + Default>(
        &self,
        version: RegistryVersion,
    ) -> IndexMap<String, T> {
        let prefix_length = T::KEY_PREFIX.len();

        self.registry_client
            .get_key_family(T::KEY_PREFIX, version)
            .expect("Failed to get key family")
            .iter()
            .filter_map(|key| {
                let r = self
                    .registry_client
                    .get_versioned_value(key, version)
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to get entry {} for type {}",
                            key,
                            std::any::type_name::<T>()
                        )
                    });

                r.as_ref().map(|v| {
                    (
                        key[prefix_length..].to_string(),
                        T::decode(v.as_slice()).expect("Invalid registry value"),
                    )
                })
            })
            .collect()
    }

    /// Returns a list of all nodes that were present in the registry during the given UTC day range,
    /// along with their decoded `NodeRecord` and the exact days they were registered.
    ///
    /// A node is considered "in the registry" for a given UTC day if it has not been removed before
    /// the start of that day. This function identifies those nodes by analyzing the registry history
    /// over a specified timestamp range (`from` to `to`).
    fn nodes_in_registry(
        &self,
        from: DayUTC,
        to: DayUTC,
    ) -> Result<BTreeMap<NodeId, (NodeRecord, Vec<DayUTC>)>, RegistryClientError> {
        let mut result: BTreeMap<NodeId, (NodeRecord, Vec<DayUTC>)> = BTreeMap::new();
        let days = from
            .days_until(&to)
            .expect("Failed to get days between from and to");

        for day in days {
            let end_of_day = day.unix_ts_at_day_end();
            let (_, last_version_for_day) = self
                .registry_client
                .latest_registry_version_before(end_of_day)?;

            let nodes_for_day =
                self.get_family_entries_of_version::<NodeRecord>(last_version_for_day);

            for (node_key, node_record) in nodes_for_day {
                let node_id = NodeId::from(
                    PrincipalId::from_str(&node_key).expect("Failed to parse node id"),
                );

                result
                    .entry(node_id)
                    .and_modify(|(record, days)| {
                        *record = node_record.clone();
                        days.push(day);
                    })
                    .or_insert((node_record, vec![day]));
            }
        }

        Ok(result)
    }

    fn node_operators_data(&self, day: DayUTC) -> HashMap<PrincipalId, NodeOperatorData> {
        let end_ts = day.unix_ts_at_day_end();
        let version_before_end_ts: RegistryVersion = *self
            .registry_client
            .timestamp_to_versions_map()
            .range(..=end_ts)
            .next_back()
            .map(|(_, versions)| versions.iter().max().expect("Failed to get max version"))
            .expect("Failed to find a version before end_ts");
        let node_operators = self
            .get_family_entries_of_version::<NodeOperatorRecord>(version_before_end_ts)
            .into_iter()
            .map(|(_, node_operator_record)| {
                (
                    PrincipalId::try_from(node_operator_record.node_operator_principal_id.clone())
                        .expect("Failed to parse PrincipalId"),
                    node_operator_record,
                )
            })
            .collect::<HashMap<_, _>>();
        let data_centers =
            self.get_family_entries_of_version::<DataCenterRecord>(version_before_end_ts);

        node_operators
            .into_iter()
            .map(|(node_operator_id, node_operator_record)| {
                let node_provider_id: PrincipalId = node_operator_record
                    .node_provider_principal_id
                    .try_into()
                    .expect("Failed to parse PrincipalId");
                let dc_id = node_operator_record.dc_id.clone();
                let data_center_record = data_centers.get(&dc_id).expect("Failed to find dc_id");
                let region = Region(data_center_record.region.clone());

                let node_operator_data = NodeOperatorData {
                    node_provider_id,
                    dc_id,
                    region,
                };
                (node_operator_id, node_operator_data)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
