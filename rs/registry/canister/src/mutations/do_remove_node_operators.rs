use crate::{
    common::LOG_PREFIX, mutations::node_management::common::get_key_family_iter, registry::Registry,
};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use candid::CandidType;
use ic_base_types::PrincipalId;
use ic_registry_keys::{NODE_RECORD_KEY_PREFIX, make_node_operator_record_key};
use ic_registry_transport::pb::v1::{RegistryMutation, registry_mutation};
use serde::{Deserialize, Serialize};

use ic_protobuf::registry::node::v1::NodeRecord;

impl Registry {
    /// Remove node operators
    pub fn do_remove_node_operators(&mut self, payload: RemoveNodeOperatorsPayload) {
        println!("{LOG_PREFIX}do_remove_node_operators: {payload:?}");

        let mut mutations = vec![];

        // Filter Node Operator IDs that have a NodeOperatorRecord in the Registry
        let mut valid_node_operator_ids_to_remove: Vec<PrincipalId> = payload
            .principal_ids_to_remove()
            .into_iter()
            .filter(|node_operator_id| {
                let node_operator_record_key =
                    make_node_operator_record_key(*node_operator_id).into_bytes();
                self.get(&node_operator_record_key, self.latest_version())
                    .is_some()
            })
            .collect();

        self.filter_out_node_operators_that_have_nodes(&mut valid_node_operator_ids_to_remove);

        for node_operator_id in valid_node_operator_ids_to_remove {
            let node_operator_record_key =
                make_node_operator_record_key(node_operator_id).into_bytes();
            mutations.push(RegistryMutation {
                mutation_type: registry_mutation::Type::Delete as i32,
                key: node_operator_record_key,
                value: vec![],
            });
        }

        self.maybe_apply_mutation_internal(mutations);
    }

    /// Takes a set of node operators and removes the node operators for which
    /// there exist at least one node record that is managed by the node
    /// operator.
    ///
    /// In other words, this retains only "empty" node operators, i.e. those
    /// that have ZERO nodes.
    fn filter_out_node_operators_that_have_nodes(&self, node_operators: &mut Vec<PrincipalId>) {
        if node_operators.is_empty() {
            return;
        }

        // This implementation is inefficient, because it does a full scan of all nodes.
        for (_key, node_record) in get_key_family_iter::<NodeRecord>(self, NODE_RECORD_KEY_PREFIX) {
            // Throw out node operators that operate the node (that this this loop is currently considering).
            node_operators
                .retain(|node_operator| node_operator.to_vec() != node_record.node_operator_id);
        }
    }
}

/// The payload of a request to remove Node Operator records from the Registry
#[derive(Clone, Debug, Eq, PartialEq, CandidType, Deserialize, Serialize, Hash)]
pub struct RemoveNodeOperatorsPayload {
    // Old compatibility field, required for Candid, to be removed in the future
    pub node_operators_to_remove: Vec<Vec<u8>>,

    // New field, where the Node Operator IDs are passed as PrincipalIds instead of Vec<u8>
    pub node_operator_principals_to_remove: Option<NodeOperatorPrincipals>,
}

/// Wrapper message for the optional repeated field
#[derive(Clone, Debug, Eq, PartialEq, CandidType, Deserialize, Serialize, Hash)]
pub struct NodeOperatorPrincipals {
    pub principals: Vec<PrincipalId>,
}

impl RemoveNodeOperatorsPayload {
    pub fn new(node_operators_to_remove: Vec<PrincipalId>) -> Self {
        Self {
            node_operators_to_remove: vec![],
            node_operator_principals_to_remove: Some(NodeOperatorPrincipals {
                principals: node_operators_to_remove,
            }),
        }
    }

    pub fn principal_ids_to_remove(&self) -> Vec<PrincipalId> {
        // Ensure only one of the fields is set to avoid confusing semantics.
        // If the new field is present, panic if the old field is also set.
        // This approach encourages clients to use the new field and allows for
        // eventual deprecation of the old field.
        match &self.node_operator_principals_to_remove {
            Some(principals) if self.node_operators_to_remove.is_empty() => {
                principals.principals.clone()
            }
            Some(_) => {
                panic!(
                    "Cannot specify both node_operators_to_remove and node_operator_principals_to_remove"
                );
            }
            None => self
                .node_operators_to_remove
                .iter()
                .filter_map(|bytes| PrincipalId::try_from(bytes.clone()).ok())
                .collect(),
        }
    }
}
