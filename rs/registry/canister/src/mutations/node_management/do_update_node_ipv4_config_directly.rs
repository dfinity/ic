use crate::mutations::node_management::common::{
    get_node_operator_id_for_node, node_exists_with_ipv4,
};
use crate::{common::LOG_PREFIX, mutations::common::node_exists_or_panic, registry::Registry};

use ic_protobuf::registry::node::v1::IPv4InterfaceConfig;
use ic_registry_canister_api::UpdateNodeIPv4ConfigDirectlyPayload;
use ic_registry_keys::make_node_record_key;
use ic_registry_transport::update;
use prost::Message;

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
        self.validate_update_node_ipv4_config_directly_payload(&payload);

        // Get existing node record and apply the changes
        let mut node_record = self.get_node_or_panic(node_id);

        node_record.public_ipv4_config =
            payload.ipv4_config.map(|ipv4_config| IPv4InterfaceConfig {
                ip_addr: ipv4_config.ip_addr().to_string(),
                gateway_ip_addr: vec![ipv4_config.gateway_ip_addr().to_string()],
                prefix_length: ipv4_config.prefix_length(),
            });

        // Create the mutation
        let update_node_record = update(
            make_node_record_key(node_id).as_bytes(),
            node_record.encode_to_vec(),
        );
        let mutations = vec![update_node_record];

        // Check invariants before applying the mutation
        self.maybe_apply_mutation_internal(mutations);
    }

    fn validate_update_node_ipv4_config_directly_payload(
        &self,
        payload: &UpdateNodeIPv4ConfigDirectlyPayload,
    ) {
        // Ensure the node exists
        node_exists_or_panic(self, payload.node_id);

        // Ensure validity of IPv4 config (if it is present)
        if let Some(ipv4_config) = &payload.ipv4_config {
            ipv4_config.panic_on_invalid();
            // Ensure that the IPv4 address is not used by any other node
            if node_exists_with_ipv4(self, ipv4_config.ip_addr()) {
                panic!("There is already at least one other node with the same IPv4 address",);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use crate::{
        common::test_helpers::{invariant_compliant_registry, prepare_registry_with_nodes},
        mutations::common::test::TEST_NODE_ID,
    };
    use ic_base_types::{NodeId, PrincipalId};
    use ic_registry_canister_api::IPv4Config;

    fn init_ipv4_config() -> IPv4Config {
        IPv4Config::try_new("193.118.59.140".into(), "193.118.59.137".into(), 29).unwrap()
    }

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
            ipv4_config: Some(init_ipv4_config()),
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
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

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(init_ipv4_config()),
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "InvalidIPv4Address")]
    fn should_panic_if_ip_address_is_invalid() {
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

        // create IPv4 config with invalid IP address
        let ipv4_config =
            IPv4Config::maybe_invalid_new("193.118.256.140".into(), "193.118.59.137".into(), 29);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config),
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "InvalidGatewayAddress")]
    fn should_panic_if_gateway_is_invalid() {
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

        // create IPv4 config with invalid gateway IP
        let ipv4_config =
            IPv4Config::maybe_invalid_new("193.118.59.140".into(), "193.118.999.137".into(), 29);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config),
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "NotInSameSubnet")]
    fn should_panic_if_address_and_gateway_not_in_same_subnet() {
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

        // create IPv4 config with invalid gateway IP
        let ipv4_config =
            IPv4Config::maybe_invalid_new("193.118.59.140".into(), "193.105.231.137".into(), 29);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config),
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "NotGlobalIPv4Address")]
    fn should_panic_if_address_is_private() {
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

        // create IPv4 config with private IP addresses
        let ipv4_config =
            IPv4Config::maybe_invalid_new("192.168.178.6".into(), "192.168.178.1".into(), 29);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config),
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "InvalidPrefixLength")]
    fn should_panic_if_prefix_length_is_invalid() {
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

        // create IPv4 config with an invalid prefix length
        let ipv4_config =
            IPv4Config::maybe_invalid_new("193.118.59.140".into(), "193.118.59.137".into(), 34);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config),
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }

    #[test]
    fn should_succeed_if_payload_is_valid_and_some() {
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

        let ipv4_config = init_ipv4_config();
        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config.clone()),
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);

        let node_record = registry.get_node_or_panic(node_id);
        let expected_intf_config = Some(IPv4InterfaceConfig {
            ip_addr: ipv4_config.ip_addr().to_string(),
            gateway_ip_addr: vec![ipv4_config.gateway_ip_addr().to_string()],
            prefix_length: ipv4_config.prefix_length(),
        });
        assert_eq!(node_record.public_ipv4_config, expected_intf_config);
    }

    #[test]
    fn should_succeed_updating_ipv4_config_two_times() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, mut node_ids) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_id = node_ids
            .first_entry()
            .expect("no node ids found")
            .key()
            .to_owned();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id)
                .expect("failed to get the node operator id");

        let ipv4_config = init_ipv4_config();
        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config.clone()),
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);

        let node_record = registry.get_node_or_panic(node_id);
        let expected_intf_config = Some(IPv4InterfaceConfig {
            ip_addr: ipv4_config.ip_addr().to_string(),
            gateway_ip_addr: vec![ipv4_config.gateway_ip_addr().to_string()],
            prefix_length: ipv4_config.prefix_length(),
        });
        assert_eq!(node_record.public_ipv4_config, expected_intf_config);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: None,
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
        let node_record = registry.get_node_or_panic(node_id);
        assert_eq!(node_record.public_ipv4_config, None);
    }

    #[test]
    #[should_panic(
        expected = "There is already at least one other node with the same IPv4 address"
    )]
    fn should_panic_if_other_node_has_same_ipv4() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            2, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_id_1 = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();

        let node_id_2 = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();

        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id_1).node_operator_id)
                .expect("failed to get the node operator id");

        // create IPv4 config with an invalid prefix length
        let ipv4_config = init_ipv4_config();

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id: node_id_1,
            ipv4_config: Some(ipv4_config.clone()),
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id: node_id_2,
            ipv4_config: Some(ipv4_config),
        };

        registry.do_update_node_ipv4_config(payload, node_operator_id);
    }
}
