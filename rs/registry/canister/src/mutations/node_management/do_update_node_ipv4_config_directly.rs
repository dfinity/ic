use crate::mutations::node_management::common::{
    get_node_operator_id_for_node, node_exists_with_ipv4,
};
use crate::{common::LOG_PREFIX, mutations::common::node_exists_or_panic, registry::Registry};

use ic_protobuf::registry::node::v1::IPv4InterfaceConfig;
use ic_registry_canister_api::UpdateNodeIPv4ConfigDirectlyPayload;
use ic_registry_keys::make_node_record_key;
use ic_registry_transport::update;
use prost::Message;
use std::time::SystemTime;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_base_types::{NodeId, PrincipalId};
use ic_nervous_system_time_helpers::now_system_time;

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
            "{LOG_PREFIX}do_update_ipv4_config_directly started: {payload:?} caller: {caller_id:?}"
        );

        self.do_update_node_ipv4_config_directly_(payload, caller_id, now_system_time())
            .unwrap_or_else(|e| panic!("{e}"));
    }

    fn do_update_node_ipv4_config_directly_(
        &mut self,
        payload: UpdateNodeIPv4ConfigDirectlyPayload,
        caller_id: PrincipalId,
        now: SystemTime,
    ) -> Result<(), String> {
        let node_id = payload.node_id;

        // Ensure caller is actual node operator of the node in question
        self.check_caller_is_node_operator(caller_id, node_id);
        let node_operator_id = caller_id;

        let reservation =
            self.try_reserve_capacity_for_node_operator_operation(now, node_operator_id, 1)?;

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

        if let Err(e) = self.commit_used_capacity_for_node_operator_operation(now, reservation) {
            println!("{LOG_PREFIX}Error committing Rate Limit usage: {e}");
        }

        Ok(())
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
            .map_err(|e| format!("Failed to obtain the node operator ID: {e}"))
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
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;
    use crate::{
        common::test_helpers::{invariant_compliant_registry, prepare_registry_with_nodes},
        mutations::common::test::TEST_NODE_ID,
    };
    use ic_base_types::{NodeId, PrincipalId};
    use ic_registry_canister_api::IPv4Config;
    use maplit::btreemap;
    use std::str::FromStr;

    fn init_ipv4_config() -> IPv4Config {
        IPv4Config::try_new("193.118.59.140".into(), "193.118.59.137".into(), 29).unwrap()
    }

    /// Returns Registry, NodeId, node operator id, node principal id
    fn setup_registry_for_test() -> (Registry, Vec<NodeId>, PrincipalId, PrincipalId) {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            2, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_ids: Vec<NodeId> = node_ids_and_dkg_pks.keys().cloned().collect();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_ids[0]).node_operator_id)
                .expect("failed to get the node operator id");

        let node_provider_id = PrincipalId::new_user_test_id(20_002);

        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(node_operator_id),
            node_provider_principal_id: Some(node_provider_id),
            node_allowance: 1,
            dc_id: "DC1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("bar".to_string()),
            max_rewardable_nodes: Some(btreemap! { "type1.2".to_string() => 1 }),
        };

        registry.do_add_node_operator(payload);

        (registry, node_ids, node_operator_id, node_provider_id)
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

        let _ = registry.do_update_node_ipv4_config_directly_(
            payload,
            node_operator_id,
            now_system_time(),
        );
    }

    #[test]
    #[should_panic(expected = "The caller does not match this node's node operator id.")]
    fn should_panic_if_caller_is_not_node_operator() {
        let (mut registry, node_ids, _, _) = setup_registry_for_test();

        let node_id = node_ids[0];
        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(init_ipv4_config()),
        };

        let wrong_node_operator_id = PrincipalId::new_user_test_id(101);

        let _ = registry.do_update_node_ipv4_config_directly_(
            payload,
            wrong_node_operator_id,
            now_system_time(),
        );
    }

    #[test]
    #[should_panic(expected = "InvalidIPv4Address")]
    fn should_panic_if_ip_address_is_invalid() {
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();

        let node_id = node_ids[0];
        // create IPv4 config with invalid IP address
        let ipv4_config =
            IPv4Config::maybe_invalid_new("193.118.256.140".into(), "193.118.59.137".into(), 29);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config),
        };

        let _ = registry.do_update_node_ipv4_config_directly_(
            payload,
            node_operator_id,
            now_system_time(),
        );
    }

    #[test]
    #[should_panic(expected = "InvalidGatewayAddress")]
    fn should_panic_if_gateway_is_invalid() {
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();

        let node_id = node_ids[0];
        // create IPv4 config with invalid gateway IP
        let ipv4_config =
            IPv4Config::maybe_invalid_new("193.118.59.140".into(), "193.118.999.137".into(), 29);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config),
        };

        let _ = registry.do_update_node_ipv4_config_directly_(
            payload,
            node_operator_id,
            now_system_time(),
        );
    }

    #[test]
    #[should_panic(expected = "NotInSameSubnet")]
    fn should_panic_if_address_and_gateway_not_in_same_subnet() {
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();

        let node_id = node_ids[0];
        // create IPv4 config with invalid gateway IP
        let ipv4_config =
            IPv4Config::maybe_invalid_new("193.118.59.140".into(), "193.105.231.137".into(), 29);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config),
        };

        let _ = registry.do_update_node_ipv4_config_directly_(
            payload,
            node_operator_id,
            now_system_time(),
        );
    }

    #[test]
    #[should_panic(expected = "NotGlobalIPv4Address")]
    fn should_panic_if_address_is_private() {
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();

        let node_id = node_ids[0];
        // create IPv4 config with private IP addresses
        let ipv4_config =
            IPv4Config::maybe_invalid_new("192.168.178.6".into(), "192.168.178.1".into(), 29);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config),
        };

        let _ = registry.do_update_node_ipv4_config_directly_(
            payload,
            node_operator_id,
            now_system_time(),
        );
    }

    #[test]
    #[should_panic(expected = "InvalidPrefixLength")]
    fn should_panic_if_prefix_length_is_invalid() {
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();

        let node_id = node_ids[0];
        // create IPv4 config with an invalid prefix length
        let ipv4_config =
            IPv4Config::maybe_invalid_new("193.118.59.140".into(), "193.118.59.137".into(), 34);

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config),
        };

        let _ = registry.do_update_node_ipv4_config_directly_(
            payload,
            node_operator_id,
            now_system_time(),
        );
    }

    #[test]
    fn should_succeed_if_payload_is_valid_and_some() {
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();

        let node_id = node_ids[0];
        let ipv4_config = init_ipv4_config();
        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config.clone()),
        };

        let _ = registry.do_update_node_ipv4_config_directly_(
            payload,
            node_operator_id,
            now_system_time(),
        );

        let node_record = registry.get_node_or_panic(node_ids[0]);
        let expected_intf_config = Some(IPv4InterfaceConfig {
            ip_addr: ipv4_config.ip_addr().to_string(),
            gateway_ip_addr: vec![ipv4_config.gateway_ip_addr().to_string()],
            prefix_length: ipv4_config.prefix_length(),
        });
        assert_eq!(node_record.public_ipv4_config, expected_intf_config);
    }

    #[test]
    fn should_succeed_updating_ipv4_config_two_times() {
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();

        let node_id = node_ids[0];
        let ipv4_config = init_ipv4_config();
        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config.clone()),
        };

        let _ = registry.do_update_node_ipv4_config_directly_(
            payload,
            node_operator_id,
            now_system_time(),
        );

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

        let _ = registry.do_update_node_ipv4_config_directly_(
            payload,
            node_operator_id,
            now_system_time(),
        );
        let node_record = registry.get_node_or_panic(node_id);
        assert_eq!(node_record.public_ipv4_config, None);
    }

    #[test]
    #[should_panic(
        expected = "There is already at least one other node with the same IPv4 address"
    )]
    fn should_panic_if_other_node_has_same_ipv4() {
        let (mut registry, node_ids, _, _) = setup_registry_for_test();

        let node_id_1 = node_ids[0];
        let node_id_2 = node_ids[1];

        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id_1).node_operator_id)
                .expect("failed to get the node operator id");

        // create IPv4 config with an invalid prefix length
        let ipv4_config = init_ipv4_config();

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id: node_id_1,
            ipv4_config: Some(ipv4_config.clone()),
        };

        registry
            .do_update_node_ipv4_config_directly_(payload, node_operator_id, now_system_time())
            .expect("failed to do update node ipv4 config");

        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id: node_id_2,
            ipv4_config: Some(ipv4_config),
        };

        registry
            .do_update_node_ipv4_config_directly_(payload, node_operator_id, now_system_time())
            .expect("failed to do update node ipv4 config");
    }

    #[test]
    fn test_do_update_node_ipv4_config_directly_fails_when_rate_limits_exceeded() {
        let (mut registry, node_ids, node_operator_id, node_provider_id) =
            setup_registry_for_test();

        let node_id = node_ids[0];
        let ipv4_config = init_ipv4_config();
        let payload = UpdateNodeIPv4ConfigDirectlyPayload {
            node_id,
            ipv4_config: Some(ipv4_config),
        };

        let now = now_system_time();

        // Exhaust the rate limit capacity
        let available_operator =
            registry.get_available_node_operator_op_capacity(node_operator_id, now);
        let available_provider =
            registry.get_available_node_provider_op_capacity(node_provider_id, now);
        let available = available_operator.min(available_provider);
        let reservation = registry
            .try_reserve_capacity_for_node_operator_operation(now, node_operator_id, available)
            .unwrap();
        registry
            .commit_used_capacity_for_node_operator_operation(now, reservation)
            .unwrap();

        let error = registry
            .do_update_node_ipv4_config_directly_(payload, node_operator_id, now)
            .unwrap_err();
        assert_eq!(
            error,
            "Rate Limit Capacity exceeded. Please wait and try again later."
        );
    }
}
