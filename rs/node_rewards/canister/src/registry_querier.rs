use crate::chrono_utils::last_unix_timestamp_nanoseconds;
use chrono::NaiveDate;
use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_canister_client::{CanisterRegistryClient, get_decoded_value};
use ic_registry_keys::{
    NODE_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY, make_data_center_record_key,
    make_node_operator_record_key, make_subnet_list_record_key,
};
use ic_types::registry::RegistryClientError;
use rewards_calculation::types::{Region, RewardableNode, UnixTsNanos};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

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

    ///  Returns the latest registry version corresponding to the given timestamp.
    pub fn version_for_timestamp_nanoseconds(&self, ts: UnixTsNanos) -> Option<RegistryVersion> {
        ic_cdk::println!(
            "timestamp_to_versions_map: {:?}",
            self.registry_client.timestamp_to_versions_map()
        );
        ic_cdk::println!("ts: {:?}", ts);
        self.registry_client
            .timestamp_to_versions_map()
            .range(..=ts)
            .next_back()
            .and_then(|(_, versions)| versions.iter().max())
            .cloned()
    }

    ///  Returns a list of all subnets present in the registry at the specified version.
    pub fn subnets_list(&self, version: RegistryVersion) -> Vec<SubnetId> {
        let key = make_subnet_list_record_key();
        let record = self
            .registry_client
            .get_value(key.as_str(), version)
            .expect("Failed to get SubnetListRecord")
            .map(|v| {
                SubnetListRecord::decode(v.as_slice()).expect("Failed to decode SubnetListRecord")
            })
            .unwrap_or_default();

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
        self.registry_client
            .get_value(NODE_REWARDS_TABLE_KEY, version)
            .expect("Failed to get NodeRewardsTable")
            .map(|v| {
                NodeRewardsTable::decode(v.as_slice()).expect("Failed to decode SubnetListRecord")
            })
            .unwrap_or_default()
    }
}

// Exposed API Methods
impl RegistryQuerier {
    /// Computes the set of rewardable nodes, grouped by node provider, for the given UTC day.
    ///
    /// A node is considered rewardable on a specific UTC day if it exists in the last registry
    /// version of that day.
    pub fn get_rewardable_nodes_per_provider(
        &self,
        date: &NaiveDate,
        provider_filter: Option<&PrincipalId>,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, RegistryClientError> {
        ic_cdk::println!("get_rewardable_nodes_per_provider: {:?}", date);
        let mut rewardable_nodes_per_provider: BTreeMap<_, Vec<RewardableNode>> = BTreeMap::new();
        let registry_version = self
            .version_for_timestamp_nanoseconds(last_unix_timestamp_nanoseconds(date))
            .unwrap();
        let nodes = self.nodes_in_version(registry_version)?;

        for (node_id, node_record) in nodes {
            let node_operator_id: PrincipalId = node_record
                .node_operator_id
                .try_into()
                .expect("Failed to parse PrincipalId from node operator ID");

            let Some(NodeOperatorData {
                node_provider_id,
                dc_id,
                region,
                ..
            }) = self.node_operator_data(node_operator_id, registry_version)?
            else {
                ic_cdk::println!("Node {} has no NodeOperatorData: skipping", node_id);
                continue;
            };
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
                    dc_id: dc_id.clone(),
                    region: region.clone(),
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

    fn node_operator_data(
        &self,
        node_operator: PrincipalId,
        version: RegistryVersion,
    ) -> Result<Option<NodeOperatorData>, RegistryClientError> {
        let node_operator_record_key = make_node_operator_record_key(node_operator);
        let Some(node_operator_record) = get_decoded_value::<NodeOperatorRecord>(
            &*self.registry_client,
            node_operator_record_key.as_str(),
            version,
        )
        .map_err(|e| RegistryClientError::DecodeError {
            error: format!("Failed to decode NodeOperatorRecord: {}", e),
        })?
        else {
            return Ok(None);
        };

        let data_center_key = make_data_center_record_key(node_operator_record.dc_id.as_str());
        let Some(data_center_record) = get_decoded_value::<DataCenterRecord>(
            &*self.registry_client,
            data_center_key.as_str(),
            version,
        )
        .map_err(|e| RegistryClientError::DecodeError {
            error: format!("Failed to decode DataCenterRecord: {}", e),
        })?
        else {
            return Ok(None);
        };

        let node_provider_id: PrincipalId = node_operator_record
            .node_provider_principal_id
            .try_into()
            .expect("Failed to parse PrincipalId");

        Ok(Some(NodeOperatorData {
            node_provider_id,
            dc_id: node_operator_record.dc_id,
            region: data_center_record.region.clone(),
        }))
    }
}

#[cfg(test)]
mod tests;
