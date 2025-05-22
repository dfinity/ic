use crate::{common::LOG_PREFIX, mutations::common::check_ipv6_format, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::PrincipalId;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};

use prost::Message;
use std::collections::BTreeMap;

impl Registry {
    /// Update an existing Node Operator's config
    pub fn do_update_node_operator_config(&mut self, payload: UpdateNodeOperatorConfigPayload) {
        println!(
            "{}do_update_node_operator_config: {:?}",
            LOG_PREFIX, payload
        );

        let node_operator_id = payload.node_operator_id.unwrap();
        let node_operator_record_key = make_node_operator_record_key(node_operator_id).into_bytes();
        let RegistryValue {
            value: node_operator_record_vec,
            version: _,
            deletion_marker: _,
        } = self
            .get(&node_operator_record_key, self.latest_version())
            .unwrap_or_else(|| {
                panic!(
                    "{}Node Operator record with ID {} not found in the registry.",
                    LOG_PREFIX, node_operator_id
                )
            });

        let mut node_operator_record =
            NodeOperatorRecord::decode(node_operator_record_vec.as_slice()).unwrap();

        if let Some(new_allowance) = payload.node_allowance {
            node_operator_record.node_allowance = new_allowance;
        };

        if let Some(new_dc_id) = payload.dc_id {
            node_operator_record.dc_id = new_dc_id;
        }

        if !payload.rewardable_nodes.is_empty() {
            node_operator_record.rewardable_nodes = payload.rewardable_nodes;
        }

        if let Some(node_provider_id) = payload.node_provider_id {
            assert_ne!(
                node_provider_id, node_operator_id,
                "The Node Operator ID cannot be the same as the Node Provider ID: {}",
                node_operator_id
            );
            node_operator_record.node_provider_principal_id = node_provider_id.to_vec();
        }

        if let Some(node_operator_ipv6) = payload.ipv6 {
            if !check_ipv6_format(&node_operator_ipv6) {
                panic!(
                    "{}New Ipv6 field {} does not conform to the required format",
                    LOG_PREFIX, node_operator_ipv6
                );
            }

            node_operator_record.ipv6 = Some(node_operator_ipv6);
        }

        if let Some(set_ipv6_none) = payload.set_ipv6_to_none {
            if set_ipv6_none {
                node_operator_record.ipv6 = None;
            }
        }

        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Update as i32,
            key: node_operator_record_key,
            value: node_operator_record.encode_to_vec(),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of a proposal to update an existing Node Operator
///
/// See /rs/protobuf/def/registry/node_operator/v1/node_operator.proto
#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct UpdateNodeOperatorConfigPayload {
    /// The principal id of the node operator. This principal is the entity that
    /// is able to add and remove nodes.
    #[prost(message, optional, tag = "1")]
    pub node_operator_id: Option<PrincipalId>,

    /// The remaining number of nodes that could be added by this Node Operator.
    #[prost(message, optional, tag = "2")]
    pub node_allowance: Option<u64>,

    /// The ID of the data center where this Node Operator hosts nodes.
    #[prost(message, optional, tag = "3")]
    pub dc_id: Option<String>,

    /// A map from node type to the number of nodes for which the associated
    /// Node Provider should be rewarded.
    #[prost(btree_map = "string, uint32", tag = "4")]
    pub rewardable_nodes: BTreeMap<String, u32>,

    /// The principal id of this node's provider.
    #[prost(message, optional, tag = "5")]
    pub node_provider_id: Option<PrincipalId>,

    /// The ipv6 address of this node's provider.
    #[prost(message, optional, tag = "6")]
    pub ipv6: Option<String>,

    /// Set the field ipv6 in the NodeOperatorRecord to None. If the field ipv6 in the
    /// UpdateNodeOperatorConfigPayload is set to None, the field ipv6 in the NodeOperatorRecord will
    /// not be updated. This field is for the case when we want to update the value to be None.
    #[prost(message, optional, tag = "7")]
    pub set_ipv6_to_none: Option<bool>,

    /// A map from node type to the maximum number of nodes for which the associated Node
    /// Operator should be rewarded.
    pub max_rewardable_nodes: BTreeMap<String, i32>,
}

#[cfg(test)]
mod tests {
    use crate::common::test_helpers::invariant_compliant_registry;
    use crate::mutations::common::test::TEST_NODE_ID;
    use crate::mutations::do_update_node_operator_config::UpdateNodeOperatorConfigPayload;
    use ic_base_types::PrincipalId;
    use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
    use ic_registry_keys::make_node_operator_record_key;
    use ic_registry_transport::insert;
    use maplit::btreemap;

    #[test]
    fn test_should_update_fields_if_included() {
        let mut registry = invariant_compliant_registry(0);

        // create a new NO record
        let node_operator_record = NodeOperatorRecord {
            node_operator_principal_id: PrincipalId::new_user_test_id(100).to_vec(),
            node_allowance: 1, // Should be > 0 to add a new node
            node_provider_principal_id: PrincipalId::new_user_test_id(1000).to_vec(),
            dc_id: "DC1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("foo".to_string()),
            max_rewardable_nodes: btreemap! { "type1.2".to_string() => 1 },
        };
        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);

        // Make a proposal to upgrade all unassigned nodes to a new version
        let payload = UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(PrincipalId::new_user_test_id(100)),
            node_allowance: Some(2),
            dc_id: Some("DC2".to_string()),
            rewardable_nodes: btreemap! { "type1.3".to_string() => 2 },
            node_provider_id: Some(PrincipalId::new_user_test_id(2000)),
            ipv6: Some("bar".to_string()),
            set_ipv6_to_none: None,
            max_rewardable_nodes: btreemap! { "type1.4".to_string() => 3 },
        };

        registry.do_update_node_operator_config(payload);
        let node_operator_record = get_node_operator_record(&registry, node_operator_id);
        assert_eq!(
            node_operator_record,
            NodeOperatorRecord {
                node_operator_principal_id: PrincipalId::new_user_test_id(100).to_vec(),
                node_allowance: 2,
                node_provider_principal_id: PrincipalId::new_user_test_id(2000).to_vec(),
                dc_id: "DC2".to_string(),
                rewardable_nodes: btreemap! { "type1.3".to_string() => 2 },
                ipv6: Some("bar".to_string()),
                max_rewardable_nodes: btreemap! { "type1.4".to_string() => 3 },
            }
        );
    }

    #[test]
    fn test_should_not_update_fields_if_omitted() {}
}
