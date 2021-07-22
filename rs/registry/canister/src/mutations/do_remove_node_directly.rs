use crate::{common::LOG_PREFIX, mutations::common::decode_registry_value, registry::Registry};

use std::convert::TryFrom;

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_nns_common::registry::encode_or_panic;
use ic_protobuf::registry::{
    node::v1::NodeRecord,
    node_operator::v1::NodeOperatorRecord,
    subnet::v1::{SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_node_operator_record_key, make_node_record_key, make_subnet_list_record_key,
    make_subnet_record_key,
};
use ic_registry_transport::{delete, pb::v1::RegistryValue, update};

impl Registry {
    /// Removes an existing node from the registry.
    ///
    /// This method is called directly by the node operator tied to the node.
    pub fn do_remove_node_directly(&mut self, payload: RemoveNodeDirectlyPayload) {
        println!("{}do_remove_node: {:?}", LOG_PREFIX, payload);

        // 1. Check that the specified node record exists
        let node_key = make_node_record_key(payload.node_id);
        let RegistryValue {
            value: node_record,
            version: _,
            deletion_marker: _,
        } = self
            .get(node_key.as_bytes(), self.latest_version())
            .map_or(
                Err(format!(
                "{}do_remove_node: Node Id {:} not found in the registry, aborting node removal.",
                LOG_PREFIX, payload.node_id)),
                Ok,
            )
            .unwrap();

        // 2. Get the caller ID and check that it matches the node's NO
        let caller = dfn_core::api::caller();
        assert_eq!(
            PrincipalId::try_from(
                decode_registry_value::<NodeRecord>(node_record.to_vec()).node_operator_id
            )
            .unwrap(),
            caller,
            "The caller {}, does not match this Node's Operator id.",
            caller
        );

        // 3. Retrieve the Subnet List and ensure no subnets contain the node
        let RegistryValue {
            value: subnet_list_record_vec,
            version: _,
            deletion_marker: _,
        } = self
            .get(
                make_subnet_list_record_key().as_bytes(),
                self.latest_version(),
            )
            .map_or(
                Err(format!(
                "{}do_remove_node: Subnet List not found in the registry, aborting node removal.",
                LOG_PREFIX)),
                Ok,
            )
            .unwrap();

        let subnet_list_record =
            decode_registry_value::<SubnetListRecord>(subnet_list_record_vec.to_vec());
        let is_node_in_subnet = subnet_list_record
                .subnets
                .iter()
                .find(|subnet_id| -> bool {
                    let subnet_key = make_subnet_record_key(SubnetId::new(
                            PrincipalId::try_from(*subnet_id).unwrap(),
                        ));

                    let RegistryValue {
                        value: subnet_record_vec,
                        version: _,
                        deletion_marker: _,
                    } = self
                        .get(
                            subnet_key.as_bytes(),
                            self.latest_version(),
                        )
                        .map_or(
                            Err(format!(
                                "{}do_remove_node: Subnet not found in the registry, aborting node removal.",
                                LOG_PREFIX)),
                            Ok,
                        )
                        .unwrap();

                    let subnet_record =
                        decode_registry_value::<SubnetRecord>(subnet_record_vec.to_vec());

                    subnet_record.membership.contains(&payload.node_id.get().to_vec())
                });

        if let Some(subnet_id) = is_node_in_subnet {
            panic!("{}do_remove_node: Cannot remove a node that is a member of a subnet. This node is a member of Subnet: {}",
                LOG_PREFIX,
                make_subnet_record_key(SubnetId::new(PrincipalId::try_from(subnet_id).unwrap()))
            );
        }

        // 4. Retrieve the NO record and decrement its node allowance by 1
        let node_operator_key = make_node_operator_record_key(caller);
        let RegistryValue {
            value: node_operator_record,
            version: _,
            deletion_marker: _,
        } = self
            .get(node_operator_key.as_bytes(), self.latest_version())
            .map_or(Err(format!(
                "{}do_remove_node: Node Operator Id {:} not found in the registry, aborting node removal.",
                LOG_PREFIX, caller)), Ok).unwrap();

        let mut new_node_operator_record =
            decode_registry_value::<NodeOperatorRecord>(node_operator_record.to_vec());
        new_node_operator_record.node_allowance += 1;

        // Lastly, apply the following mutations:
        //   * Delete the node
        //   * Increment NO's allowance by 1
        let mutations = vec![
            delete(node_key),
            update(
                node_operator_key,
                encode_or_panic(&new_node_operator_record),
            ),
        ];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of an update request to add a new node.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemoveNodeDirectlyPayload {
    pub node_id: NodeId,
}
