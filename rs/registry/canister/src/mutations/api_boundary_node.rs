use std::str::FromStr;

use crate::{
    common::LOG_PREFIX, mutations::node_management::common::get_key_family_iter, registry::Registry,
};

use ic_base_types::NodeId;
use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
use ic_registry_keys::{make_api_boundary_node_record_key, API_BOUNDARY_NODE_RECORD_KEY_PREFIX};
use ic_registry_transport::pb::v1::RegistryValue;
use ic_types::PrincipalId;
use prost::Message;

impl Registry {
    /// Get the ApiBoundaryNode record
    pub fn get_api_boundary_node_record(&self, node_id: NodeId) -> Option<ApiBoundaryNodeRecord> {
        let RegistryValue {
            value: api_boundary_node_record_vec,
            version: _,
            deletion_marker: _,
        } = self.get(
            &make_api_boundary_node_record_key(node_id).into_bytes(),
            self.latest_version(),
        )?;

        Some(ApiBoundaryNodeRecord::decode(api_boundary_node_record_vec.as_slice()).unwrap())
    }

    /// Get the ApiBoundaryNode record or panic on error with a message.
    pub fn get_api_boundary_node_or_panic(&self, node_id: NodeId) -> ApiBoundaryNodeRecord {
        self.get_api_boundary_node_record(node_id)
            .unwrap_or_else(|| {
                panic!(
                    "{}api_boundary_node record for {:} not found in the registry.",
                    LOG_PREFIX, node_id
                )
            })
    }

    /// Get all API boundary nodes IDs.
    pub fn get_api_boundary_node_ids(&self) -> Result<Vec<NodeId>, String> {
        let mut err_ids = Vec::new();

        let ids: Vec<NodeId> =
            get_key_family_iter::<ApiBoundaryNodeRecord>(self, API_BOUNDARY_NODE_RECORD_KEY_PREFIX)
                .filter_map(|(id_str, _)| match PrincipalId::from_str(&id_str) {
                    Ok(principal_id) => Some(NodeId::from(principal_id)),
                    Err(_) => {
                        err_ids.push(id_str);
                        None
                    }
                })
                .collect();

        if err_ids.is_empty() {
            Ok(ids)
        } else {
            let err_msg = format!(
                "The following API node IDs couldn't be parsed from registry: [{}]",
                err_ids.join(", ")
            );
            Err(err_msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use ic_registry_keys::{
        make_api_boundary_node_record_key, API_BOUNDARY_NODE_RECORD_KEY_PREFIX,
    };
    use ic_registry_transport::pb::v1::RegistryValue;
    use ic_types_test_utils::ids::node_test_id;

    use crate::registry::Registry;

    #[test]
    fn test_get_api_boundary_node_ids_success() {
        let mut registry = Registry::new();

        let key_1 = make_api_boundary_node_record_key(node_test_id(1)).into_bytes();
        let key_2 = make_api_boundary_node_record_key(node_test_id(2)).into_bytes();

        let mut value = VecDeque::new();
        value.push_back(RegistryValue {
            ..Default::default()
        });

        registry.store.insert(key_1, value.clone());
        registry.store.insert(key_2, value);
        // Act
        let mut api_bns = registry.get_api_boundary_node_ids().unwrap();

        // Assert
        api_bns.sort();
        assert_eq!(vec![node_test_id(1), node_test_id(2)], api_bns);
    }

    #[test]
    fn test_get_api_boundary_node_ids_failure() {
        let mut registry = Registry::new();

        let key_1_ok = make_api_boundary_node_record_key(node_test_id(1)).into_bytes();
        let key_2_err = format!(
            "{}{}",
            API_BOUNDARY_NODE_RECORD_KEY_PREFIX, "not_a_principal_1"
        )
        .into_bytes();
        let key_3_err = format!(
            "{}{}",
            API_BOUNDARY_NODE_RECORD_KEY_PREFIX, "not_a_principal_2"
        )
        .into_bytes();

        let mut value = VecDeque::new();
        value.push_back(RegistryValue {
            ..Default::default()
        });

        registry.store.insert(key_1_ok, value.clone());
        registry.store.insert(key_2_err, value.clone());
        registry.store.insert(key_3_err, value);
        // Act
        let err_msg = registry.get_api_boundary_node_ids().unwrap_err();

        assert_eq!(
            err_msg,
            "The following API node IDs couldn't be parsed from registry: [not_a_principal_1, not_a_principal_2]"
        )
    }
}
