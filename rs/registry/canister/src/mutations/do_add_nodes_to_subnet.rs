use crate::{common::LOG_PREFIX, registry::Registry};

use std::convert::TryFrom;

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::{NodeId, PrincipalId, SubnetId};

impl Registry {
    /// Adds the nodes to an existing subnet record in the registry.
    ///
    /// This method is called by the governance canister, after a proposal
    /// for modifying a subnet by adding nodes has been accepted.
    pub fn do_add_nodes_to_subnet(&mut self, payload: AddNodesToSubnetPayload) {
        println!("{}do_add_nodes_to_subnet: {:?}", LOG_PREFIX, payload);

        let mut nodes_to_add = payload.node_ids.clone();
        let subnet_record = self.get_subnet_or_panic(SubnetId::from(payload.subnet_id));

        let mut existing_nodes: Vec<NodeId> = subnet_record
            .membership
            .iter()
            .map(|bytes| NodeId::from(PrincipalId::try_from(bytes).unwrap()))
            .collect();

        nodes_to_add.append(&mut existing_nodes);

        let mutations = vec![self.make_replace_subnet_membership_mutation(
            SubnetId::from(payload.subnet_id),
            nodes_to_add,
        )];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of a proposal to add nodes to an existing subnet.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AddNodesToSubnetPayload {
    /// The subnet ID to add the nodes to.
    pub subnet_id: PrincipalId,
    /// The list of node IDs that will be added to the existing subnet.
    pub node_ids: Vec<NodeId>,
}
