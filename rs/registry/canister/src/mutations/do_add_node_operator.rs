use crate::{common::LOG_PREFIX, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::PrincipalId;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::pb::v1::{RegistryMutation, registry_mutation};

use prost::Message;
use std::collections::BTreeMap;

impl Registry {
    /// Add a new Node Operator
    pub fn do_add_node_operator(&mut self, payload: AddNodeOperatorPayload) {
        println!("{LOG_PREFIX}do_add_node_operator: {payload:?}");

        let node_operator_record_key =
            make_node_operator_record_key(payload.node_operator_principal_id.unwrap()).into_bytes();
        let node_operator_record: NodeOperatorRecord = payload.into();

        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Insert as i32,
            key: node_operator_record_key,
            value: node_operator_record.encode_to_vec(),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of a proposal to add a new Node Operator
///
/// See /rs/protobuf/def/registry/node_operator/v1/node_operator.proto
#[derive(Clone, Debug, Default, Eq, PartialEq, CandidType, Deserialize, Serialize)]
pub struct AddNodeOperatorPayload {
    /// The principal id of the node operator. This principal is the entity that
    /// is able to add and remove nodes.
    ///
    /// This must be unique across NodeOperatorRecords.
    pub node_operator_principal_id: Option<PrincipalId>,

    pub node_provider_principal_id: Option<PrincipalId>,

    /// The remaining number of nodes that could be added by this Node Operator.
    pub node_allowance: u64,

    // The ID of the data center where this Node Operator hosts nodes.
    pub dc_id: String,

    // A map from node type to the number of nodes for which the associated Node
    // Provider should be rewarded.
    pub rewardable_nodes: BTreeMap<String, u32>,

    // The ipv6 address of the node's provider.
    pub ipv6: Option<String>,

    // The maximum number of rewardable nodes for this node operator.
    pub max_rewardable_nodes: Option<BTreeMap<String, u32>>,
}

impl From<AddNodeOperatorPayload> for NodeOperatorRecord {
    fn from(val: AddNodeOperatorPayload) -> Self {
        NodeOperatorRecord {
            node_operator_principal_id: val.node_operator_principal_id.unwrap().to_vec(),
            node_provider_principal_id: val.node_provider_principal_id.unwrap().to_vec(),
            node_allowance: val.node_allowance,
            dc_id: val.dc_id.to_lowercase(),
            rewardable_nodes: val.rewardable_nodes,
            ipv6: val.ipv6,
            max_rewardable_nodes: val.max_rewardable_nodes.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::test_helpers::invariant_compliant_registry;
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;
    use crate::mutations::node_management::common::get_node_operator_record;
    use ic_base_types::PrincipalId;
    use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
    use maplit::btreemap;

    #[test]
    fn test_should_add_new_node_operator() {
        let mut registry = invariant_compliant_registry(0);

        // create a new NO record
        let node_operator_id = PrincipalId::new_user_test_id(100);

        // Make a proposal to upgrade all unassigned nodes to a new version
        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(node_operator_id),
            node_provider_principal_id: Some(PrincipalId::new_user_test_id(1000)),
            node_allowance: 1,
            dc_id: "DC1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("bar".to_string()),
            max_rewardable_nodes: Some(btreemap! { "type1.2".to_string() => 1 }),
        };

        registry.do_add_node_operator(payload);
        let node_operator_record = get_node_operator_record(&registry, node_operator_id)
            .expect("Couldn't find NO record.");

        let expected = NodeOperatorRecord {
            node_operator_principal_id: PrincipalId::new_user_test_id(100).to_vec(),
            node_allowance: 1, // Should be > 0 to add a new node
            node_provider_principal_id: PrincipalId::new_user_test_id(1000).to_vec(),
            dc_id: "dc1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("bar".to_string()),
            max_rewardable_nodes: btreemap! { "type1.2".to_string() => 1 },
        };
        assert_eq!(node_operator_record, expected);
    }
}
