use crate::deserialize_registry_value;
use ic_base_types::{NodeId, RegistryVersion};
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
use ic_registry_keys::{
    API_BOUNDARY_NODE_RECORD_KEY_PREFIX, get_api_boundary_node_record_node_id,
    make_api_boundary_node_record_key,
};
use ic_types::registry::RegistryClientError;
use std::collections::HashSet;

pub trait ApiBoundaryNodeRegistry {
    fn get_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError>;

    fn get_api_boundary_node_record(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ApiBoundaryNodeRecord>;

    fn get_system_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError>;

    fn get_app_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError>;

    fn is_system_api_boundary_node(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> Result<bool, RegistryClientError>;
}

impl<T: RegistryClient + ?Sized> ApiBoundaryNodeRegistry for T {
    fn get_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError> {
        let api_boundary_node_record_keys =
            self.get_key_family(API_BOUNDARY_NODE_RECORD_KEY_PREFIX, version)?;
        let res = api_boundary_node_record_keys
            .iter()
            .filter_map(|s| get_api_boundary_node_record_node_id(s))
            .map(NodeId::from)
            .collect();
        Ok(res)
    }

    fn get_api_boundary_node_record(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ApiBoundaryNodeRecord> {
        let bytes = self.get_value(&make_api_boundary_node_record_key(node_id), version);
        deserialize_registry_value::<ApiBoundaryNodeRecord>(bytes)
    }

    fn get_system_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError> {
        let mut all_ids = self.get_api_boundary_node_ids(version)?;
        all_ids.sort();
        let n = all_ids.len();
        let split_point = n.div_ceil(2);
        all_ids.truncate(split_point);
        Ok(all_ids)
    }

    fn get_app_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError> {
        let all_ids = self.get_api_boundary_node_ids(version)?;
        let system_ids: HashSet<NodeId> =
            HashSet::from_iter(self.get_system_api_boundary_node_ids(version)?);

        let app_ids: Vec<NodeId> = all_ids
            .into_iter()
            .filter(|id| !system_ids.contains(id))
            .collect();

        Ok(app_ids)
    }

    fn is_system_api_boundary_node(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> Result<bool, RegistryClientError> {
        let system_api_bn_ids = self.get_system_api_boundary_node_ids(version)?;
        Ok(system_api_bn_ids.contains(&node_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_base_types::PrincipalId;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use std::sync::Arc;

    fn node_id(id: u64) -> NodeId {
        NodeId::from(PrincipalId::new_user_test_id(id))
    }

    fn setup_test_client(
        node_ids: Vec<NodeId>,
        version: RegistryVersion,
    ) -> Arc<dyn RegistryClient> {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        for node_id in node_ids {
            let record = ApiBoundaryNodeRecord::default();
            data_provider
                .add(
                    &make_api_boundary_node_record_key(node_id),
                    version,
                    Some(record),
                )
                .unwrap();
        }

        let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
        registry_client.update_to_latest_version();
        registry_client
    }

    #[test]
    fn test_split_even_nodes() {
        let version = RegistryVersion::from(1);
        let registry = setup_test_client(
            vec![node_id(1), node_id(2), node_id(3), node_id(4)],
            version,
        );

        let system_ids = registry.get_system_api_boundary_node_ids(version).unwrap();
        let mut app_ids = registry.get_app_api_boundary_node_ids(version).unwrap();
        app_ids.sort(); // Sort for deterministic comparison

        assert_eq!(system_ids, vec![node_id(1), node_id(2)]);
        assert_eq!(app_ids, vec![node_id(3), node_id(4)]);
    }

    #[test]
    fn test_split_odd_nodes() {
        let version = RegistryVersion::from(1);
        let registry = setup_test_client(
            vec![
                node_id(10),
                node_id(20),
                node_id(30),
                node_id(40),
                node_id(50),
            ],
            version,
        );

        let system_ids = registry.get_system_api_boundary_node_ids(version).unwrap();
        let mut app_ids = registry.get_app_api_boundary_node_ids(version).unwrap();
        app_ids.sort();

        assert_eq!(system_ids, vec![node_id(10), node_id(20), node_id(30)]);
        assert_eq!(app_ids, vec![node_id(40), node_id(50)]);
    }

    #[test]
    fn test_split_single_node() {
        let version = RegistryVersion::from(1);
        let registry = setup_test_client(vec![node_id(100)], version);

        let system_ids = registry.get_system_api_boundary_node_ids(version).unwrap();
        let app_ids = registry.get_app_api_boundary_node_ids(version).unwrap();

        assert_eq!(system_ids, vec![node_id(100)]);
        assert!(app_ids.is_empty());
    }

    #[test]
    fn test_is_system_api_boundary_node() {
        let version = RegistryVersion::from(1);
        let registry = setup_test_client(
            vec![node_id(1), node_id(2), node_id(3), node_id(4)],
            version,
        );

        assert!(
            registry
                .is_system_api_boundary_node(node_id(1), version)
                .unwrap()
        );
        assert!(
            registry
                .is_system_api_boundary_node(node_id(2), version)
                .unwrap()
        );
        assert!(
            !registry
                .is_system_api_boundary_node(node_id(3), version)
                .unwrap()
        );
        assert!(
            !registry
                .is_system_api_boundary_node(node_id(4), version)
                .unwrap()
        );
    }
}
