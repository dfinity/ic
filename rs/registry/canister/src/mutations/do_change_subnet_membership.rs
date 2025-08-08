use crate::{common::LOG_PREFIX, registry::Registry};

use std::convert::TryFrom;

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_registry_keys::make_subnet_record_key;
use ic_registry_transport::upsert;
use prost::Message;
use serde::Serialize;

impl Registry {
    /// Changes membership of nodes in a subnet record in the registry.
    ///
    /// This method is called by the governance canister, after a proposal
    /// for modifying a subnet by changing the membership (adding/removing) has been accepted.
    pub fn do_change_subnet_membership(&mut self, payload: ChangeSubnetMembershipPayload) {
        println!(
            "{}do_change_subnet_membership started: {:?}",
            LOG_PREFIX, payload
        );

        let nodes_to_add = payload.node_ids_add.clone();
        let subnet_id = SubnetId::from(payload.subnet_id);
        let mut subnet_record = self.get_subnet_or_panic(subnet_id);

        let current_subnet_nodes: Vec<NodeId> = subnet_record
            .membership
            .iter()
            .map(|bytes| NodeId::from(PrincipalId::try_from(bytes).unwrap()))
            .collect();

        // Verify that nodes requested to be removed belong to the subnet provided in the payload
        if !payload
            .node_ids_remove
            .iter()
            .all(|n| current_subnet_nodes.contains(n))
        {
            panic!("Nodes that should be removed do not belong to the provided subnet.")
        }

        // Calculate a complete list of nodes in this subnet after the change of subnet membership is executed
        let subnet_membership_after_change = nodes_to_add
            .iter()
            .cloned()
            .chain(current_subnet_nodes)
            .filter(|node_id_in_subnet| {
                payload
                    .node_ids_remove
                    .iter()
                    .all(|node_id_to_remove| node_id_in_subnet != node_id_to_remove)
            })
            .collect();

        self.replace_subnet_record_membership(
            subnet_id,
            &mut subnet_record,
            subnet_membership_after_change,
        );
        let mutations = vec![upsert(
            make_subnet_record_key(subnet_id),
            subnet_record.encode_to_vec(),
        )];

        // Check the invariants and apply the mutations if invariants are satisfied
        self.maybe_apply_mutation_internal(mutations);

        println!(
            "{}do_change_subnet_membership finished: {:?}",
            LOG_PREFIX, payload
        );
    }
}

/// The payload of a proposal to change the membership of nodes in an existing subnet.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct ChangeSubnetMembershipPayload {
    /// The subnet ID to mutate.
    pub subnet_id: PrincipalId,
    /// The list of node IDs that will be added to the subnet.
    pub node_ids_add: Vec<NodeId>,
    /// The list of node IDs that will be removed from the subnet.
    pub node_ids_remove: Vec<NodeId>,
}

#[cfg(tests)]
mod tests {
    use ic_protobuf::registry::node::v1::NodeRecord;
    use ic_registry_keys::{make_node_record_key, make_subnet_record_key};

    use ic_registry_transport::{pb::v1::RegistryMutation, upsert};

    use crate::common::test_helpers::get_invariant_compliant_subnet_record;

    // This test is a proof of concept for how it is currently possible
    // to put a node in two subnet at once. If a node is currently in a subnet
    // and we issue a ChangeSubnetMembership proposal with that node for a
    // different subnet, it will be added there.
    #[test]
    fn move_node() {
        let mut registry = invariant_compliant_registry(0);

        let node_id_1 = NodeId::new(PrincipalId::new_node_test_id(1));
        let node_record_1 = NodeRecord::default();
        let node_id_2 = NodeId::new(PrincipalId::new_node_test_id(2));
        let node_record_2 = NodeRecord::default();
        let mutations = vec![
            upsert(
                make_node_record_key(node_id_1).as_bytes(),
                node_record_1.encode_to_vec(),
            ),
            upsert(
                make_node_record_key(node_id_2).as_bytes(),
                node_record_2.encode_to_vec(),
            ),
        ];

        registry.apply_mutations_for_test(mutations);

        let subnet_1 = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let subnet_2 = SubnetId::new(PrincipalId::new_subnet_test_id(2));

        let subnet_1_record = get_invariant_compliant_subnet_record(vec![node_id_1]);
        let subnet_2_record = get_invariant_compliant_subnet_record(vec![node_id_2]);

        let mutations = vec![
            upsert(
                make_subnet_record_key(subnet_1).as_bytes(),
                subnet_1_record.encode_to_vec(),
            ),
            upsert(
                make_subnet_record_key(subnet_2).as_bytes(),
                subnet_2_record.encode_to_vec(),
            ),
        ];

        registry.apply_mutations_for_test(mutations);

        let change = ChangeSubnetMembershipPayload {
            subnet_id: subnet_2.get(),
            node_ids_add: vec![node_id_1.get()],
            node_ids_remove: vec![node_id_2.get()],
        };

        // Should panic but doesn't
        registry.do_change_subnet_membership(change);

        let subnet_1_record = registry.get_subnet_or_panic(subnet_1.clone());
        let subnet_2_record = registry.get_subnet_or_panic(subnet_2.clone());

        // It is present in both subnets
        assert!(subnet_1_record
            .membership
            .iter()
            .find(|p| NodeId::from(p).eq(&node_id_1))
            .is_some());
        assert!(subnet_2_record
            .membership
            .iter()
            .find(|p| NodeId::from(p).eq(&node_id_1))
            .is_some());
    }
}
