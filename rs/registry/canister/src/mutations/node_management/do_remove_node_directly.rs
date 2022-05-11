use crate::mutations::node_management::common::{
    find_subnet_for_node, get_node_operator_id_for_node, get_node_operator_record,
    get_subnet_list_record, make_remove_node_registry_mutations,
    make_update_node_operator_mutation,
};
use crate::{common::LOG_PREFIX, registry::Registry};
use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::NodeId;
use ic_registry_keys::make_subnet_record_key;

impl Registry {
    /// Removes an existing node from the registry.
    ///
    /// This method is called directly by the node operator tied to the node.
    pub fn do_remove_node_directly(&mut self, payload: RemoveNodeDirectlyPayload) {
        println!(
            "{}do_remove_node_directly started: {:?}",
            LOG_PREFIX, payload
        );

        // 1. Find the node operator id for this record
        // and abort if the node record is not found
        let node_operator_id = get_node_operator_id_for_node(self, payload.node_id)
            .map_err(|e| {
                format!(
                    "{}do_remove_node_directly: Aborting node removal: {}",
                    LOG_PREFIX, e
                )
            })
            .unwrap();

        // 2. Get the caller ID and check that it matches the node's NO
        let caller = dfn_core::api::caller();
        assert_eq!(
            node_operator_id, caller,
            "The caller {}, does not match this Node's Operator id.",
            caller
        );

        // 3. Ensure node is not in a subnet
        let subnet_list_record = get_subnet_list_record(self);
        let is_node_in_subnet = find_subnet_for_node(self, payload.node_id, &subnet_list_record);
        if let Some(subnet_id) = is_node_in_subnet {
            panic!("{}do_remove_node_directly: Cannot remove a node that is a member of a subnet. This node is a member of Subnet: {}",
                LOG_PREFIX,
                make_subnet_record_key(subnet_id)
            );
        }

        // 4. Retrieve the NO record and increment its node allowance by 1
        let mut new_node_operator_record = get_node_operator_record(self, caller)
            .map_err(|err| {
                format!(
                    "{}do_remove_node_directly: Aborting node removal: {}",
                    LOG_PREFIX, err
                )
            })
            .unwrap();
        new_node_operator_record.node_allowance += 1;

        // 5. Finally, generate the following mutations:
        //   * Delete the node
        //   * Delete entries for node encryption keys
        //   * Increment NO's allowance by 1
        let mut mutations = make_remove_node_registry_mutations(self, payload.node_id);
        // mutation to update node operator value
        mutations.push(make_update_node_operator_mutation(
            node_operator_id,
            &new_node_operator_record,
        ));

        // 6. Apply mutations after checking invariants
        self.maybe_apply_mutation_internal(mutations);

        println!(
            "{}do_remove_node_directly finished: {:?}",
            LOG_PREFIX, payload
        );
    }
}

/// The payload of an update request to remove a node.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemoveNodeDirectlyPayload {
    pub node_id: NodeId,
}
