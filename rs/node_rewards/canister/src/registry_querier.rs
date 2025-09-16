use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_canister_client::{CanisterRegistryClient, get_decoded_value};
use ic_registry_keys::{
    NODE_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY, make_data_center_record_key,
    make_node_operator_record_key, make_subnet_list_record_key,
};
use ic_types::registry::RegistryClientError;
use rewards_calculation::types::{Region, UnixTsNanos};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

pub struct RegistryQuerier {
    registry_client: Arc<dyn CanisterRegistryClient>,
}

pub struct NodeOperatorData {
    pub node_provider_id: PrincipalId,
    pub dc_id: String,
    pub region: Region,
}

impl RegistryQuerier {
    pub fn new(registry_client: Arc<dyn CanisterRegistryClient>) -> Self {
        RegistryQuerier { registry_client }
    }

    ///  Returns the latest registry version corresponding to the given timestamp.
    pub fn version_for_timestamp(
        &self,
        ts: UnixTsNanos,
    ) -> Result<RegistryVersion, RegistryClientError> {
        self.registry_client
            .timestamp_to_versions_map()
            .range(..=ts)
            .next_back()
            .and_then(|(_, versions)| versions.iter().max())
            .cloned()
            .ok_or(RegistryClientError::NoVersionsBefore {
                timestamp_nanoseconds: ts,
            })
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
    pub fn get_rewards_table(
        &self,
        version: RegistryVersion,
    ) -> Result<NodeRewardsTable, RegistryClientError> {
        let v = self
            .registry_client
            .get_value(NODE_REWARDS_TABLE_KEY, version)?
            .ok_or(RegistryClientError::VersionNotAvailable { version })?;
        NodeRewardsTable::decode(v.as_slice()).map_err(|e| RegistryClientError::DecodeError {
            error: e.to_string(),
        })
    }

    /// Returns a map of all nodes that were present in the registry at the specified version.
    pub fn nodes_in_version(
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

    pub fn node_operator_data(
        &self,
        node_operator: PrincipalId,
        version: RegistryVersion,
    ) -> Result<Option<NodeOperatorData>, RegistryClientError> {
        let node_operator_record_key = make_node_operator_record_key(node_operator);
        let Some(node_operator_record) = get_decoded_value::<NodeOperatorRecord>(
            &*self.registry_client,
            node_operator_record_key.as_str(),
            version,
        )?
        else {
            return Ok(None);
        };

        let data_center_key = make_data_center_record_key(node_operator_record.dc_id.as_str());
        let Some(data_center_record) = get_decoded_value::<DataCenterRecord>(
            &*self.registry_client,
            data_center_key.as_str(),
            version,
        )?
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
