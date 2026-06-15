use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::ai_node::v1::AiNodeRecord;
use ic_registry_keys::{make_ai_node_record_key, make_subnet_record_key};
use ic_registry_transport::insert;
use prost::Message;
use serde::Serialize;

use crate::{common::LOG_PREFIX, registry::Registry};

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct AddAiNodesPayload {
    pub node_ids: Vec<NodeId>,
    /// Optional subnet id to associate the AI nodes with. When `None`, the
    /// nodes are registered without being associated to any subnet.
    pub subnet_id: Option<SubnetId>,
}

impl Registry {
    /// Adds an AiNodeRecord to the registry for each of the given node ids.
    pub fn do_add_ai_nodes(&mut self, payload: AddAiNodesPayload) {
        println!("{LOG_PREFIX}do_add_ai_nodes: {payload:?}");

        // Ensure payload is valid
        self.validate_add_ai_nodes_payload(&payload);

        // Serialize the subnet_id (if any) to its principal-bytes form once.
        let subnet_id_bytes = payload.subnet_id.map(|s| s.get().to_vec());

        // Mutations to insert AiNodeRecord
        let mutations = payload.node_ids.into_iter().map(|node_id| {
            let key = make_ai_node_record_key(node_id);
            insert(
                key,
                AiNodeRecord {
                    subnet_id: subnet_id_bytes.clone(),
                }
                .encode_to_vec(),
            )
        });

        self.maybe_apply_mutation_internal(mutations.collect());
    }

    fn validate_add_ai_nodes_payload(&self, payload: &AddAiNodesPayload) {
        // Ensure there are no duplicates
        let unique_count = payload
            .node_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        if unique_count != payload.node_ids.len() {
            panic!("there are duplicate nodes")
        }

        // If a subnet_id is provided, it must exist in the registry.
        if let Some(subnet_id) = payload.subnet_id {
            let key = make_subnet_record_key(subnet_id);
            if self.get(key.as_bytes(), self.latest_version()).is_none() {
                panic!("subnet {subnet_id} does not exist");
            }
        }

        for node_id in payload.node_ids.iter() {
            // Ensure node exists
            self.get_node_or_panic(*node_id);

            // Ensure record does not exist (the node is not already an AI node)
            let key = make_ai_node_record_key(*node_id);

            let record = self.get(key.as_bytes(), self.latest_version());

            if record.is_some() {
                panic!("record exists: {node_id}");
            }

            // Ensure node is not assigned to a subnet
            self.get_subnet_list_record().subnets.iter().for_each(|id| {
                let id =
                    SubnetId::from(PrincipalId::try_from(id).expect("failed to parse subnet id"));

                self.get_subnet_or_panic(id)
                    .membership
                    .iter()
                    .for_each(|id| {
                        let id = NodeId::from(
                            PrincipalId::try_from(id).expect("failed to parse principal id"),
                        );

                        if *node_id == id {
                            panic!("node assigned to subnet: {node_id}");
                        }
                    })
            });
        }
    }
}
