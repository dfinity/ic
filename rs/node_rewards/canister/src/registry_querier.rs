use crate::chrono_utils::last_unix_timestamp_nanoseconds;
use chrono::NaiveDate;
use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_protobuf::registry::subnet::v1::{SubnetListRecord, SubnetRecord};
use ic_registry_canister_client::CanisterRegistryClient;
use ic_registry_keys::{
    DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_RECORD_KEY_PREFIX,
    NODE_REWARDS_TABLE_KEY, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_types::registry::RegistryClientError;
use rewards_calculation::types::{RewardableNode, UnixTsNanos};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;

pub struct RegistryQuerier {
    registry_client: Arc<dyn CanisterRegistryClient>,
}

impl RegistryQuerier {
    pub fn new(registry_client: Arc<dyn CanisterRegistryClient>) -> Self {
        RegistryQuerier { registry_client }
    }

    ///  Returns the latest registry version corresponding to the given timestamp.
    pub fn version_for_timestamp_nanoseconds(&self, ts: UnixTsNanos) -> Option<RegistryVersion> {
        self.registry_client
            .timestamp_to_versions_map()
            .range(..=ts)
            .next_back()
            .and_then(|(_, versions)| versions.iter().max())
            .cloned()
    }

    ///  Returns a list of all subnets present in the registry at the specified version.
    pub fn subnets_list(&self, version: RegistryVersion) -> Result<Vec<SubnetId>, String> {
        let key = make_subnet_list_record_key();
        let record_bytes = self
            .registry_client
            .get_value(key.as_str(), version)
            .map_err(|e| format!("Failed to get SubnetListRecord: {:?}", e))?;

        let record = if let Some(bytes) = record_bytes {
            SubnetListRecord::decode(bytes.as_slice())
                .map_err(|e| format!("Failed to decode SubnetListRecord: {:?}", e))?
        } else {
            SubnetListRecord::default()
        };

        record
            .subnets
            .into_iter()
            .map(|s| {
                let principal = PrincipalId::try_from(s.as_slice())
                    .map_err(|e| format!("Invalid subnet ID: {:?}", e))?;
                Ok(SubnetId::from(principal))
            })
            .collect()
    }

    /// Returns the [`SubnetRecord`] for the given subnet at the specified registry version,
    /// or `None` if the record does not exist.
    pub fn get_subnet_record(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> Result<Option<SubnetRecord>, String> {
        let key = make_subnet_record_key(subnet_id);
        let record_bytes = self
            .registry_client
            .get_value(key.as_str(), version)
            .map_err(|e| format!("Failed to get SubnetRecord for {subnet_id}: {e:?}"))?;

        match record_bytes {
            Some(bytes) => {
                let record = SubnetRecord::decode(bytes.as_slice())
                    .map_err(|e| format!("Failed to decode SubnetRecord for {subnet_id}: {e:?}"))?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Returns the NodeRewardsTable at the specified version.
    pub fn get_rewards_table(&self, version: RegistryVersion) -> NodeRewardsTable {
        self.registry_client
            .get_value(NODE_REWARDS_TABLE_KEY, version)
            .expect("Failed to get NodeRewardsTable")
            .map(|v| {
                NodeRewardsTable::decode(v.as_slice()).expect("Failed to decode SubnetListRecord")
            })
            .unwrap_or_default()
    }

    /// Returns all NodeOperatorRecords at the specified version, keyed by operator PrincipalId.
    ///
    /// This uses a single bulk prefix scan instead of individual lookups per operator,
    /// which is significantly cheaper in terms of instructions.
    fn all_node_operators(
        &self,
        version: RegistryVersion,
    ) -> Result<HashMap<PrincipalId, NodeOperatorRecord>, RegistryClientError> {
        let prefix_len = NODE_OPERATOR_RECORD_KEY_PREFIX.len();
        let records = self
            .registry_client
            .get_key_family_with_values(NODE_OPERATOR_RECORD_KEY_PREFIX, version)?;
        let mut result = HashMap::with_capacity(records.len());
        for (key, value) in records {
            let principal =
                PrincipalId::from_str(&key[prefix_len..]).expect("Invalid node operator key");
            let record = NodeOperatorRecord::decode(value.as_slice())
                .expect("Failed to decode NodeOperatorRecord");
            result.insert(principal, record);
        }
        Ok(result)
    }

    /// Returns all DataCenterRecords at the specified version, keyed by DC ID.
    ///
    /// This uses a single bulk prefix scan instead of individual lookups per data center,
    /// which is significantly cheaper in terms of instructions.
    fn all_data_centers(
        &self,
        version: RegistryVersion,
    ) -> Result<HashMap<String, DataCenterRecord>, RegistryClientError> {
        let prefix_len = DATA_CENTER_KEY_PREFIX.len();
        let records = self
            .registry_client
            .get_key_family_with_values(DATA_CENTER_KEY_PREFIX, version)?;
        let mut result = HashMap::with_capacity(records.len());
        for (key, value) in records {
            let dc_id = key[prefix_len..].to_string();
            let record = DataCenterRecord::decode(value.as_slice())
                .expect("Failed to decode DataCenterRecord");
            result.insert(dc_id, record);
        }
        Ok(result)
    }
}

// Exposed API Methods
impl RegistryQuerier {
    /// Computes the set of rewardable nodes, grouped by node provider, for the given UTC day.
    ///
    /// A node is considered rewardable on a specific UTC day if it exists in the last registry
    /// version of that day.
    ///
    /// Performance: This method bulk-fetches all NodeOperatorRecords and DataCenterRecords
    /// in two prefix scans rather than doing individual lookups per node
    pub fn get_rewardable_nodes_per_provider(
        &self,
        date: &NaiveDate,
        provider_filter: Option<&PrincipalId>,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, RegistryClientError> {
        let mut rewardable_nodes_per_provider: BTreeMap<_, Vec<RewardableNode>> = BTreeMap::new();
        let registry_version = self
            .version_for_timestamp_nanoseconds(last_unix_timestamp_nanoseconds(date))
            .unwrap();

        // Bulk-fetch all data upfront instead of per-node individual lookups.
        let nodes = self.nodes_in_version(registry_version)?;
        let all_operators = self.all_node_operators(registry_version)?;
        let all_data_centers = self.all_data_centers(registry_version)?;

        for (node_id, node_record) in nodes {
            let node_operator_id: PrincipalId = node_record
                .node_operator_id
                .try_into()
                .expect("Failed to parse PrincipalId from node operator ID");

            let Some(node_operator_record) = all_operators.get(&node_operator_id) else {
                ic_cdk::println!("Node {} has no NodeOperatorRecord: skipping", node_id);
                continue;
            };

            let Some(data_center_record) = all_data_centers.get(&node_operator_record.dc_id) else {
                ic_cdk::println!(
                    "Node {} has NodeOperator but no DataCenterRecord for dc_id {}: skipping",
                    node_id,
                    node_operator_record.dc_id
                );
                continue;
            };

            let node_provider_id: PrincipalId = node_operator_record
                .node_provider_principal_id
                .clone()
                .try_into()
                .expect("Failed to parse PrincipalId");

            if let Some(provider_filter) = provider_filter
                && &node_provider_id != provider_filter
            {
                continue;
            }
            let Some(some_reward_type) = node_record.node_reward_type else {
                // If the node does not have a node_reward_type, we skip it.
                continue;
            };

            let node_reward_type =
                NodeRewardType::try_from(some_reward_type).expect("Invalid node_reward_type value");

            rewardable_nodes_per_provider
                .entry(node_provider_id)
                .or_default()
                .push(RewardableNode {
                    node_id,
                    node_reward_type,
                    dc_id: node_operator_record.dc_id.clone(),
                    region: data_center_record.region.clone(),
                });
        }
        Ok(rewardable_nodes_per_provider)
    }

    /// Returns a map of all nodes that were present in the registry at the specified version.
    fn nodes_in_version(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<BTreeMap<NodeId, NodeRecord>, RegistryClientError> {
        let nodes_raw = self
            .registry_client
            .get_key_family_with_values(NODE_RECORD_KEY_PREFIX, registry_version)?;
        let prefix_length = NODE_RECORD_KEY_PREFIX.len();

        let nodes = nodes_raw
            .into_iter()
            .map(|(node_key, node_value)| {
                let principal =
                    PrincipalId::from_str(&node_key[prefix_length..]).expect("Invalid node key");
                let node_id = NodeId::from(principal);
                let node_record =
                    NodeRecord::decode(node_value.as_slice()).expect("Failed to decode NodeRecord");
                (node_id, node_record)
            })
            .collect();
        Ok(nodes)
    }
}

#[cfg(test)]
mod tests;
