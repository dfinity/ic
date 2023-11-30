use crate::mutations::node_management::common::get_node_operator_id_for_node;
use crate::{
    common::LOG_PREFIX,
    mutations::common::{
        are_in_the_same_subnet, encode_or_panic, is_global_ipv4_address, is_valid_ipv4_address,
        is_valid_ipv4_prefix_length, node_exists_or_panic,
    },
    registry::Registry,
};

use candid::{CandidType, Deserialize};
use ic_protobuf::registry::node::v1::IPv4InterfaceConfig;
use ic_registry_keys::make_node_record_key;
use ic_registry_transport::update;
use serde::Serialize;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_base_types::{NodeId, PrincipalId};

impl Registry {
    /// Updates the IPv4 configuration of a node
    ///
    /// This method is called directly by the node operator
    pub fn do_update_node_ipv4_config_directly(
        &mut self,
        payload: UpdateNodeIPv4ConfigDirectlyPayload,
    ) {
        let caller_id = dfn_core::api::caller();
        println!(
            "{}do_update_ipv4_config_directly started: {:?} caller: {:?}",
            LOG_PREFIX, payload, caller_id
        );

        self.do_update_node_ipv4_config(payload, caller_id)
    }

    fn do_update_node_ipv4_config(
        &mut self,
        payload: UpdateNodeIPv4ConfigDirectlyPayload,
        caller_id: PrincipalId,
    ) {
        let node_id = payload.node_id;

        // Ensure caller is actual node operator of the node in question
        self.check_caller_is_node_operator(caller_id, node_id);

        // Ensure payload is valid
        self.validate_update_node_ipv4_config_directly(&payload);

        // Get existing node record and apply the changes
        let mut node_record = self.get_node_or_panic(node_id);

        let ipv4_interface_config = IPv4InterfaceConfig {
            ip_addr: payload.ip_addr,
            gateway_ip_addr: payload.gateway_ip_addrs,
            prefix_length: payload.prefix_length,
        };
        node_record.public_ipv4_config = Some(ipv4_interface_config);

        // Create the mutation
        let update_node_record = update(
            make_node_record_key(node_id).as_bytes(),
            encode_or_panic(&node_record),
        );
        let mutations = vec![update_node_record];

        // Check invariants before applying the mutation
        self.maybe_apply_mutation_internal(mutations);
    }

    fn validate_update_node_ipv4_config_directly(
        &self,
        payload: &UpdateNodeIPv4ConfigDirectlyPayload,
    ) {
        // Ensure the node exists
        node_exists_or_panic(self, payload.node_id);

        // Ensure all are valid IPv4 addresses
        if !is_valid_ipv4_address(&payload.ip_addr) {
            panic!("The specified IPv4 address is not valid");
        }

        for ip_addr in &payload.gateway_ip_addrs {
            if !is_valid_ipv4_address(ip_addr) {
                panic!("The specified IPv4 address of the gateway is not valid");
            }
        }

        // Ensure the prefix length is valid
        if !is_valid_ipv4_prefix_length(payload.prefix_length) {
            panic!("The prefix length is not valid");
        }

        // Ensure all IPv4 addresses are in the same subnet
        let mut ip_addresses = payload.gateway_ip_addrs.clone();
        ip_addresses.push(payload.ip_addr.clone());
        if !are_in_the_same_subnet(ip_addresses, payload.prefix_length) {
            panic!("The specified IPv4 addresses are not in the same subnet");
        }

        // Ensure the IPv4 address is a routable address
        if !is_global_ipv4_address(&payload.ip_addr) {
            panic!("The specified IPv4 address is not a global address");
        }
    }

    fn check_caller_is_node_operator(&self, caller_id: PrincipalId, node_id: NodeId) {
        // Find the node operator id for this node
        let node_operator_id = get_node_operator_id_for_node(self, node_id)
            .map_err(|e| format!("Failed to obtain the node operator ID: {}", e))
            .unwrap();

        assert_eq!(
            node_operator_id, caller_id,
            "The caller does not match this node's node operator id."
        );
    }
}

// The payload of a request to update the IPv4 configuration of an existing node
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateNodeIPv4ConfigDirectlyPayload {
    pub node_id: NodeId,
    pub ip_addr: String,
    pub gateway_ip_addrs: Vec<String>,
    pub prefix_length: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use crate::{
        common::test_helpers::{invariant_compliant_registry, prepare_registry_with_nodes},
        mutations::common::test::TEST_NODE_ID,
    };
    use ic_base_types::{NodeId, PrincipalId};

    #[test]
    #[should_panic(
        expected = "Failed to obtain the node operator ID: Node Id 2vxsx-fae not found in the registry"
    )]
    fn should_panic_if_record_not_found() {
        let mut registry = invariant_compliant_registry(0);

        let node_id = NodeId::from(
            PrincipalId::from_str(TEST_NODE_ID).expect("failed to parse principal id"),
        );

        let node_operator_id = PrincipalId::new_user_test_id(101);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ip_addr: "193.118.59.140".into(),
            gateway_ip_addrs: vec![
                "193.118.59.137".into(),
                "193.118.59.138".into(),
                "193.118.59.139".into(),
            ],
            prefix_length: 29,
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "The caller does not match this node's node operator id.")]
    fn should_panic_if_caller_is_not_node_operator() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_operator_id = PrincipalId::new_user_test_id(101);

        let node_id = node_ids.first().expect("no node ids found").to_owned();

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ip_addr: "193.118.59.140".into(),
            gateway_ip_addrs: vec!["193.118.59.137".into(), "193.118.59.139".into()],
            prefix_length: 29,
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "The specified IPv4 address is not valid")]
    fn should_panic_if_ip_address_is_invalid() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_id = node_ids.first().expect("no node ids found").to_owned();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id)
                .expect("failed to get the node operator id");

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ip_addr: "193.118.256.140".into(),
            gateway_ip_addrs: vec!["193.118.59.137".into(), "193.118.59.139".into()],
            prefix_length: 29,
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "The specified IPv4 address of the gateway is not valid")]
    fn should_panic_if_gateway_is_invalid() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_id = node_ids.first().expect("no node ids found").to_owned();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id)
                .expect("failed to get the node operator id");

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ip_addr: "193.118.59.140".into(),
            gateway_ip_addrs: vec!["193.118.999.137".into()],
            prefix_length: 29,
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "The specified IPv4 address is not a global address")]
    fn should_panic_if_address_is_private() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_id = node_ids.first().expect("no node ids found").to_owned();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id)
                .expect("failed to get the node operator id");

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ip_addr: "192.168.178.6".into(),
            gateway_ip_addrs: vec!["192.168.178.1".into(), "192.168.178.2".into()],
            prefix_length: 29,
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "The prefix length is not valid")]
    fn should_panic_if_prefix_length_is_invalid() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_id = node_ids.first().expect("no node ids found").to_owned();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id)
                .expect("failed to get the node operator id");

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ip_addr: "193.118.59.140".into(),
            gateway_ip_addrs: vec!["193.118.59.137".into()],
            prefix_length: 34,
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    fn should_succeed_if_payload_is_valid() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_id = node_ids.first().expect("no node ids found").to_owned();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id)
                .expect("failed to get the node operator id");

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ip_addr: "193.118.59.140".into(),
            gateway_ip_addrs: vec!["193.118.59.137".into(), "193.118.59.139".into()],
            prefix_length: 29,
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }
}
