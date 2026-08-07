use crate::deserialize_registry_value;
use crate::subnet::{SubnetListRegistry, SubnetRegistry, get_node_ids_from_subnet_record};
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
pub use ic_protobuf::registry::node::v1::{ConnectionEndpoint, NodeRecord};
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_registry_keys::{NODE_RECORD_KEY_PREFIX, get_node_record_node_id, make_node_record_key};
use ic_types::registry::RegistryClientError;
pub use ic_types::{NodeId, RegistryVersion, SubnetId};

pub trait NodeRegistry {
    fn get_node_record(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<NodeRecord>;

    fn get_subnet_id_and_type_from_node_id(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<(SubnetId, SubnetType)>;

    fn get_subnet_id_from_node_id(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<SubnetId>;

    /// Returns a list of node ids that contains the id of each node that exists
    /// at version `version`.
    fn get_node_ids(&self, version: RegistryVersion) -> Result<Vec<NodeId>, RegistryClientError>;
}

impl<T: RegistryClient + ?Sized> NodeRegistry for T {
    fn get_node_record(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<NodeRecord> {
        let bytes = self.get_value(&make_node_record_key(node_id), version);
        deserialize_registry_value::<NodeRecord>(bytes)
    }

    fn get_subnet_id_and_type_from_node_id(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<(SubnetId, SubnetType)> {
        if let Some(subnet_ids) = self.get_subnet_ids(version)? {
            for subnet_id in subnet_ids {
                let Some(subnet_record) = self.get_subnet_record(subnet_id, version)? else {
                    continue;
                };
                let node_ids = get_node_ids_from_subnet_record(&subnet_record).map_err(|err| {
                    RegistryClientError::DecodeError {
                        error: format!("get_node_ids_from_subnet_record() failed with {err}"),
                    }
                })?;
                let subnet_type = subnet_record.subnet_type();
                if node_ids.contains(&node_id) {
                    return Ok(Some((subnet_id, subnet_type)));
                }
            }
        }

        Ok(None)
    }

    fn get_subnet_id_from_node_id(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<SubnetId> {
        Ok(self
            .get_subnet_id_and_type_from_node_id(node_id, version)?
            .map(|(subnet_id, _)| subnet_id))
    }

    fn get_node_ids(&self, version: RegistryVersion) -> Result<Vec<NodeId>, RegistryClientError> {
        let node_record_keys = self.get_key_family(NODE_RECORD_KEY_PREFIX, version)?;
        let res = node_record_keys
            .iter()
            .filter_map(|s| get_node_record_node_id(s.as_str()))
            .map(NodeId::from)
            .collect();
        Ok(res)
    }
}
