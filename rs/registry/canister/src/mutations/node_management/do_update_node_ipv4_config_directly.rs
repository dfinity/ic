use crate::mutations::node_management::common::{
    get_node_operator_id_for_node, node_exists_with_ipv4,
};
use crate::{common::LOG_PREFIX, mutations::common::node_exists_or_panic, registry::Registry};

use ic_protobuf::registry::node::v1::IPv4InterfaceConfig;
use ic_registry_canister_types::UpdateNodeIPv4ConfigDirectlyPayload;
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
