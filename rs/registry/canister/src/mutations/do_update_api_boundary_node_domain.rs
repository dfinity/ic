use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::NodeId;
use ic_registry_keys::make_api_boundary_node_record_key;
use ic_registry_transport::update;
use serde::Serialize;

use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use super::common::{check_api_boundary_nodes_exist, is_valid_domain};

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateApiBoundaryNodeDomainPayload {
    pub node_id: NodeId,
    pub domain: String,
}

impl Registry {
    /// Updates the domain of an ApiBoundaryNodeRecord
    pub fn do_update_api_boundary_node_domain(
        &mut self,
        payload: UpdateApiBoundaryNodeDomainPayload,
    ) {
        println!(
            "{}do_update_api_boundary_node_domain: {:?}",
            LOG_PREFIX, payload
        );

        // Ensure payload is valid
        self.validate_update_api_boundary_node_domain_payload(&payload);

        // Mutations to update ApiBoundaryNodeRecords with domain
        let mutation = {
            let key = make_api_boundary_node_record_key(payload.node_id);

            let mut api_boundary_node = self.get_api_boundary_node_or_panic(payload.node_id);
            api_boundary_node.domain = payload.domain;

            update(key, encode_or_panic(&api_boundary_node))
        };

        self.maybe_apply_mutation_internal(vec![mutation]);
    }

    fn validate_update_api_boundary_node_domain_payload(
        &self,
        payload: &UpdateApiBoundaryNodeDomainPayload,
    ) {
        check_api_boundary_nodes_exist(self, &[payload.node_id]);

        // Ensure domain is valid
        if !is_valid_domain(&payload.domain) {
            panic!("invalid domain");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ic_base_types::{NodeId, PrincipalId};
    use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
    use ic_registry_keys::make_api_boundary_node_record_key;
    use ic_registry_transport::insert;

    use crate::{
        common::test_helpers::{invariant_compliant_registry, prepare_registry_with_nodes},
        mutations::common::{encode_or_panic, test::TEST_NODE_ID},
    };

    use super::UpdateApiBoundaryNodeDomainPayload;

    #[test]
    #[should_panic(expected = "record not found")]
    fn should_panic_if_record_not_found() {
        let mut registry = invariant_compliant_registry(0);

        // Validate proposal payload
        let node_id = NodeId::from(
            PrincipalId::from_str(TEST_NODE_ID).expect("failed to parse principal id"),
        );

        let payload = UpdateApiBoundaryNodeDomainPayload {
            node_id,
            domain: "example.com".into(),
        };

        registry.do_update_api_boundary_node_domain(payload);
    }

    #[test]
    fn should_succeed_if_proposal_is_valid() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        // Add boundary node to registry
        let node_id = node_ids.first().expect("no node ids found").to_owned();

        registry.maybe_apply_mutation_internal(vec![
            // Mutation to insert ApiBoundaryNodeRecord
            insert(
                make_api_boundary_node_record_key(node_id), // key
                encode_or_panic(&ApiBoundaryNodeRecord {
                    version: "version".into(),
                    domain: "example.com".into(),
                }),
            ),
        ]);

        // Validate proposal payload
        let payload = UpdateApiBoundaryNodeDomainPayload {
            node_id,
            domain: "example.com".into(),
        };

        registry.do_update_api_boundary_node_domain(payload);
    }
}
