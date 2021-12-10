use crate::{common::LOG_PREFIX, registry::Registry};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_base_types::PrincipalId;
use ic_protobuf::registry::node_operator::v1::RemoveNodeOperatorsPayload;
use ic_registry_keys::{make_node_operator_record_key, NODE_RECORD_KEY_PREFIX};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};

use std::convert::TryFrom;

use ic_protobuf::registry::node::v1::NodeRecord;
use prost::Message;

impl Registry {
    /// Remove node operators
    pub fn do_remove_node_operators(&mut self, payload: RemoveNodeOperatorsPayload) {
        println!("{}do_remove_node_operators: {:?}", LOG_PREFIX, payload);

        let mut mutations = vec![];

        // Node Operator IDs that are parsable as PrincipalIds and have an associated
        // NodeOperatorRecord in the Registry
        let mut valid_node_operator_ids = payload
            .node_operators_to_remove
            .into_iter()
            .filter_map(|bytes| {
                PrincipalId::try_from(bytes)
                    .ok()
                    .filter(|node_operator_id| {
                        let node_operator_record_key =
                            make_node_operator_record_key(*node_operator_id).into_bytes();
                        self.get(&node_operator_record_key, self.latest_version())
                            .is_some()
                    })
            })
            .collect();

        self.filter_node_operators_that_have_nodes(&mut valid_node_operator_ids);

        for node_operator_id in valid_node_operator_ids {
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
    /// operator
    fn filter_node_operators_that_have_nodes(&self, node_operators: &mut Vec<PrincipalId>) {
        if node_operators.is_empty() {
            return;
        }

        for (key, values) in self.store.iter() {
            if key.starts_with(NODE_RECORD_KEY_PREFIX.as_bytes()) {
                if let Some(value) = values.back().map(|v| v.value.clone()) {
                    if let Ok(node_record) = NodeRecord::decode(value.as_slice()) {
                        node_operators.retain(|node_operator| {
                            node_operator.to_vec() != node_record.node_operator_id
                        })
                    }
                }
            }
        }
    }
}
