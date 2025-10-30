use crate::{common::LOG_PREFIX, mutations::common::check_ipv6_format, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::PrincipalId;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::pb::v1::{RegistryMutation, RegistryValue, registry_mutation};

use prost::Message;
use std::collections::BTreeMap;

impl Registry {
    /// Update an existing Node Operator's config
    pub fn do_update_node_operator_config(&mut self, payload: UpdateNodeOperatorConfigPayload) {
        println!("{LOG_PREFIX}do_update_node_operator_config: {payload:?}");

        let node_operator_id = payload.node_operator_id.unwrap();
        let node_operator_record_key = make_node_operator_record_key(node_operator_id).into_bytes();
        let RegistryValue {
            value: node_operator_record_vec,
            version: _,
            deletion_marker: _,
            timestamp_nanoseconds: _,
        } = self
            .get(&node_operator_record_key, self.latest_version())
            .unwrap_or_else(|| {
                panic!(
                    "{LOG_PREFIX}Node Operator record with ID {node_operator_id} not found in the registry."
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
                "The Node Operator ID cannot be the same as the Node Provider ID: {node_operator_id}"
            );
            node_operator_record.node_provider_principal_id = node_provider_id.to_vec();
        }

        if let Some(node_operator_ipv6) = payload.ipv6 {
            if !check_ipv6_format(&node_operator_ipv6) {
                panic!(
                    "{LOG_PREFIX}New Ipv6 field {node_operator_ipv6} does not conform to the required format"
                );
            }

            node_operator_record.ipv6 = Some(node_operator_ipv6);
        }

        if let Some(set_ipv6_none) = payload.set_ipv6_to_none
            && set_ipv6_none
        {
            node_operator_record.ipv6 = None;
        }

        if let Some(max_rewardable_nodes) = payload.max_rewardable_nodes {
            // It might make sense to allow setting this to None, but for now we keep the same
            // behavior as the old field of only making changes if values are set.
            if !max_rewardable_nodes.is_empty() {
                node_operator_record.max_rewardable_nodes = max_rewardable_nodes;
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
#[derive(Clone, Debug, Default, Eq, PartialEq, CandidType, Deserialize, Serialize)]
pub struct UpdateNodeOperatorConfigPayload {
    /// The principal id of the node operator. This principal is the entity that
    /// is able to add and remove nodes.
    pub node_operator_id: Option<PrincipalId>,

    /// The remaining number of nodes that could be added by this Node Operator.
    pub node_allowance: Option<u64>,

    /// The ID of the data center where this Node Operator hosts nodes.
    pub dc_id: Option<String>,

    /// A map from node type to the number of nodes for which the associated
    /// Node Provider should be rewarded.
    pub rewardable_nodes: BTreeMap<String, u32>,

    /// The principal id of this node's provider.
    pub node_provider_id: Option<PrincipalId>,

    /// The ipv6 address of this node's provider.
    pub ipv6: Option<String>,

    /// Set the field ipv6 in the NodeOperatorRecord to None. If the field ipv6 in the
    /// UpdateNodeOperatorConfigPayload is set to None, the field ipv6 in the NodeOperatorRecord will
    /// not be updated. This field is for the case when we want to update the value to be None.
    pub set_ipv6_to_none: Option<bool>,

    /// A map from node type to the maximum number of nodes for which the associated Node
    /// Operator could be rewarded.  To set all values to 0, you need to send a map with at least
    /// one entry and a value of 0, like `Some(btreemap! { "type1.1".to_string() => 0 })`.  If an
    /// empty map is sent, the existing values will not be updated, to be consistent with the behavior
    /// of `rewardable_nodes`.  That behavior may change in the future, so prefer sending None
    /// instead of an empty BtreeMap.
    pub max_rewardable_nodes: Option<BTreeMap<String, u32>>,
}

#[cfg(test)]
mod tests {
    use crate::common::test_helpers::invariant_compliant_registry;
    use crate::mutations::common::test::TEST_NODE_ID;
    use crate::mutations::do_update_node_operator_config::UpdateNodeOperatorConfigPayload;
    use crate::mutations::node_management::common::get_node_operator_record;
    use ic_base_types::PrincipalId;
    use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
    use ic_registry_keys::make_node_operator_record_key;
    use ic_registry_transport::insert;
    use maplit::btreemap;
    use prost::Message;
    use std::str::FromStr;

    #[test]
    fn test_should_update_fields_if_included() {
        let mut registry = invariant_compliant_registry(0);

        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();

        // create a new NO record
        let node_operator_record = NodeOperatorRecord {
            node_operator_principal_id: node_operator_id.to_vec(),
            node_allowance: 1, // Should be > 0 to add a new node
            node_provider_principal_id: PrincipalId::new_user_test_id(1000).to_vec(),
            dc_id: "DC1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("foo".to_string()),
            max_rewardable_nodes: btreemap! { "type1.2".to_string() => 1 },
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);

        // Make a proposal to upgrade all unassigned nodes to a new version
        let payload = UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(node_operator_id),
            node_allowance: Some(2),
            dc_id: Some("DC2".to_string()),
            rewardable_nodes: btreemap! { "type1.3".to_string() => 2 },
            node_provider_id: Some(PrincipalId::new_user_test_id(2000)),
            ipv6: Some("2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string()),
            set_ipv6_to_none: None,
            max_rewardable_nodes: Some(btreemap! { "type1.4".to_string() => 3 }),
        };

        registry.do_update_node_operator_config(payload);
        let node_operator_record = get_node_operator_record(&registry, node_operator_id)
            .expect("Could not find NO Record");

        assert_eq!(
            node_operator_record,
            NodeOperatorRecord {
                node_operator_principal_id: node_operator_id.to_vec(),
                node_allowance: 2,
                node_provider_principal_id: PrincipalId::new_user_test_id(2000).to_vec(),
                dc_id: "DC2".to_string(),
                rewardable_nodes: btreemap! { "type1.3".to_string() => 2 },
                ipv6: Some("2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string()),
                max_rewardable_nodes: btreemap! { "type1.4".to_string() => 3 },
            }
        );
    }

    #[test]
    fn test_should_not_update_fields_if_omitted() {
        let mut registry = invariant_compliant_registry(0);

        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();

        // create a new NO record
        let node_operator_record = NodeOperatorRecord {
            node_operator_principal_id: node_operator_id.to_vec(),
            node_allowance: 1, // Should be > 0 to add a new node
            node_provider_principal_id: PrincipalId::new_user_test_id(1000).to_vec(),
            dc_id: "DC1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("foo".to_string()),
            max_rewardable_nodes: btreemap! { "type1.2".to_string() => 1 },
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);

        // Make a proposal to upgrade all unassigned nodes to a new version
        let payload = UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(node_operator_id),
            node_allowance: None,
            dc_id: None,
            rewardable_nodes: btreemap! {},
            node_provider_id: None,
            ipv6: None,
            set_ipv6_to_none: None,
            max_rewardable_nodes: None,
        };

        registry.do_update_node_operator_config(payload);
        let updated_node_operator_record = get_node_operator_record(&registry, node_operator_id)
            .expect("Could not find NO Record");
        assert_eq!(updated_node_operator_record, node_operator_record);
    }
}
