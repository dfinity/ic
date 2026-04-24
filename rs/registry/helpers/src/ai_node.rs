use crate::deserialize_registry_value;
use ic_base_types::{NodeId, RegistryVersion, SubnetId};
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::ai_node::v1::AiNodeRecord;
use ic_registry_keys::{
    AI_NODE_RECORD_KEY_PREFIX, get_ai_node_record_node_id, make_ai_node_record_key,
};
use ic_types::{PrincipalId, registry::RegistryClientError};

pub trait AiNodeRegistry {
    /// Returns all AI node ids registered at `version`.
    fn get_ai_node_ids(&self, version: RegistryVersion)
    -> Result<Vec<NodeId>, RegistryClientError>;

    /// Returns the `AiNodeRecord` for `node_id` at `version`, if any.
    fn get_ai_node_record(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<AiNodeRecord>;

    /// Returns all AI node ids associated with the given `subnet_id` at
    /// `version`.
    fn get_ai_nodes_for_subnet(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError>;
}

impl<T: RegistryClient + ?Sized> AiNodeRegistry for T {
    fn get_ai_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError> {
        let ai_node_record_keys = self.get_key_family(AI_NODE_RECORD_KEY_PREFIX, version)?;
        let res = ai_node_record_keys
            .iter()
            .filter_map(|s| get_ai_node_record_node_id(s))
            .map(NodeId::from)
            .collect();
        Ok(res)
    }

    fn get_ai_node_record(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<AiNodeRecord> {
        let bytes = self.get_value(&make_ai_node_record_key(node_id), version);
        deserialize_registry_value::<AiNodeRecord>(bytes)
    }

    fn get_ai_nodes_for_subnet(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError> {
        let target = subnet_id.get();
        let ids = self.get_ai_node_ids(version)?;
        let mut result = Vec::new();
        for id in ids {
            if let Some(record) = self.get_ai_node_record(id, version)?
                && let Some(raw) = record.subnet_id
                && let Ok(principal) = PrincipalId::try_from(raw.as_slice())
                && principal == target
            {
                result.push(id);
            }
        }
        Ok(result)
    }
}
