use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::NodeId;
use ic_registry_keys::make_api_boundary_node_record_key;
use ic_registry_transport::delete;
use serde::Serialize;

use crate::{common::LOG_PREFIX, registry::Registry};

use super::common::check_api_boundary_nodes_exist;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct RemoveApiBoundaryNodesPayload {
    pub node_ids: Vec<NodeId>,
}

impl Registry {
    /// Remove a set of ApiBoundaryNodeRecords from the registry
    pub fn do_remove_api_boundary_nodes(&mut self, payload: RemoveApiBoundaryNodesPayload) {
        println!("{LOG_PREFIX}do_remove_api_boundary_nodes: {payload:?}");

        // Ensure payload is valid
        self.validate_remove_api_boundary_nodes_payload(&payload);

        // Mutations to remove ApiBoundaryNodeRecords
        let mutations = payload.node_ids.into_iter().map(|node_id| {
            let key = make_api_boundary_node_record_key(node_id);
            delete(key)
        });

        self.maybe_apply_mutation_internal(mutations.collect())
    }

    fn validate_remove_api_boundary_nodes_payload(&self, payload: &RemoveApiBoundaryNodesPayload) {
        check_api_boundary_nodes_exist(self, &payload.node_ids);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ic_base_types::{NodeId, PrincipalId};
    use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
    use ic_registry_keys::make_api_boundary_node_record_key;
    use ic_registry_transport::insert;
    use ic_types::ReplicaVersion;
    use prost::Message;

    use crate::{
        common::test_helpers::{invariant_compliant_registry, prepare_registry_with_nodes},
        mutations::common::test::TEST_NODE_ID,
    };

    use super::RemoveApiBoundaryNodesPayload;

    #[test]
    #[should_panic(expected = "record not found")]
    fn should_panic_if_record_not_found() {
        let mut registry = invariant_compliant_registry(0);

        // Validate proposal payload
        let node_id = NodeId::from(
            PrincipalId::from_str(TEST_NODE_ID).expect("failed to parse principal id"),
        );

        let payload = RemoveApiBoundaryNodesPayload {
            node_ids: vec![node_id],
        };

        registry.do_remove_api_boundary_nodes(payload);
    }

    #[test]
    fn should_succeed_if_proposal_is_valid() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        // Add boundary node to registry
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();

        registry.maybe_apply_mutation_internal(vec![
            // Mutation to insert ApiBoundaryNodeRecord
            insert(
                make_api_boundary_node_record_key(node_id), // key
                ApiBoundaryNodeRecord {
                    version: ReplicaVersion::default().to_string(),
                }
                .encode_to_vec(),
            ),
        ]);

        let payload = RemoveApiBoundaryNodesPayload {
            node_ids: vec![node_id],
        };

        registry.do_remove_api_boundary_nodes(payload);
    }
}
