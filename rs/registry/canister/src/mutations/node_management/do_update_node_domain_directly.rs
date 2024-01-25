use crate::mutations::common::is_valid_domain;
use crate::mutations::node_management::common::get_node_operator_id_for_node;
use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use candid::{CandidType, Deserialize};
use ic_registry_keys::make_node_record_key;
use ic_registry_transport::update;
use serde::Serialize;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_base_types::{NodeId, PrincipalId};

// Payload of the request to update the domain name of an existing node
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateNodeDomainDirectlyPayload {
    pub node_id: NodeId,
    pub domain: Option<String>,
}

impl Registry {
    /// Updates domain name of a node
    /// This method is called directly by the node operator
    pub fn do_update_node_domain_directly(&mut self, payload: UpdateNodeDomainDirectlyPayload) {
        let caller_id = dfn_core::api::caller();
        println!(
            "{}do_update_node_domain_directly started: {:?} caller: {:?}",
            LOG_PREFIX, payload, caller_id
        );
        self.do_update_node_domain(payload, caller_id);
    }

    fn do_update_node_domain(
        &mut self,
        payload: UpdateNodeDomainDirectlyPayload,
        caller_id: PrincipalId,
    ) {
        let UpdateNodeDomainDirectlyPayload { node_id, domain } = payload;

        // Get existing node record and apply the changes
        let mut node_record = self.get_node_or_panic(node_id);

        // Ensure caller is an actual node operator of the node
        let node_operator_id = get_node_operator_id_for_node(self, node_id)
            .map_err(|e| format!("Failed to obtain the node operator ID: {}", e))
            .unwrap();

        assert_eq!(
            node_operator_id, caller_id,
            "The caller does not match this node's node operator id."
        );

        // Ensure domain name is valid
        if let Some(ref domain) = domain {
            if !is_valid_domain(domain) {
                panic!("invalid domain");
            }
        }

        node_record.domain = domain;

        // Create the mutation
        let update_node_record = update(
            make_node_record_key(node_id).as_bytes(),
            encode_or_panic(&node_record),
        );
        let mutations = vec![update_node_record];

        // Check invariants before applying the mutation
        self.maybe_apply_mutation_internal(mutations);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::test_helpers::{invariant_compliant_registry, prepare_registry_with_nodes},
        mutations::common::test::TEST_NODE_ID,
    };
    use std::str::FromStr;

    #[test]
    #[should_panic(expected = "node record for 2vxsx-fae not found in the registry")]
    fn should_panic_if_record_not_found() {
        let mut registry = invariant_compliant_registry(0);
        let node_id = NodeId::from(
            PrincipalId::from_str(TEST_NODE_ID).expect("failed to parse principal id"),
        );
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id)
                .expect("failed to get the node operator id");
        let payload = UpdateNodeDomainDirectlyPayload {
            node_id,
            domain: None,
        };

        registry.do_update_node_domain(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "The caller does not match this node's node operator id.")]
    fn should_panic_if_caller_is_not_node_operator() {
        let mut registry = invariant_compliant_registry(0);
        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_operator_id = PrincipalId::new_user_test_id(101);
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();
        let payload = UpdateNodeDomainDirectlyPayload {
            node_id,
            domain: None,
        };

        registry.do_update_node_domain(payload, node_operator_id);
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
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id)
                .expect("failed to get the node operator id");

        // Assert setting domain name to Some() works
        let new_domain = Some("example.com".to_string());
        registry.do_update_node_domain(
            UpdateNodeDomainDirectlyPayload {
                node_id,
                domain: new_domain.clone(),
            },
            node_operator_id,
        );
        let node_record = registry.get_node_or_panic(node_id);
        assert_eq!(node_record.domain, new_domain);

        // Assert setting domain name to None also works
        registry.do_update_node_domain(
            UpdateNodeDomainDirectlyPayload {
                node_id,
                domain: None,
            },
            node_operator_id,
        );
        let node_record = registry.get_node_or_panic(node_id);
        assert_eq!(node_record.domain, None);
    }
}
