use crate::{
    common::LOG_PREFIX,
    mutations::common::{decode_registry_value, encode_or_panic},
    registry::Registry,
};

use std::convert::TryFrom;

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::subnet::v1::{SubnetListRecord, SubnetRecord};
use ic_registry_keys::{make_subnet_record_key, SUBNET_LIST_KEY};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};

impl Registry {
    /// Remove nodes from their subnets
    pub fn do_remove_nodes_from_subnet(&mut self, payload: RemoveNodesFromSubnetPayload) {
        println!("{}do_remove_nodes_from_subnet: {:?}", LOG_PREFIX, payload);

        let subnet_list_key = SUBNET_LIST_KEY.as_bytes();
        let mutations = match self.get(subnet_list_key, self.latest_version()) {
            Some(RegistryValue {
                value: subnet_list_record_vec,
                version: _,
                deletion_marker: _,
            }) => {
                let subnet_list_record =
                    decode_registry_value::<SubnetListRecord>(subnet_list_record_vec.to_vec());
                let mut subnet_records = subnet_list_record
                    .subnets
                    .iter()
                    .map(|subnet_id| {
                        let subnet_record_key = make_subnet_record_key(SubnetId::new(
                            PrincipalId::try_from(subnet_id).unwrap(),
                        ));
                        match self.get(subnet_record_key.as_bytes(), self.latest_version()) {
                            Some(RegistryValue {
                                value: subnet_record_vec,
                                version: _,
                                deletion_marker: _,
                            }) => Some((
                                subnet_record_key,
                                decode_registry_value::<SubnetRecord>(subnet_record_vec.to_vec()),
                                false,
                            )),
                            None => None,
                        }
                        .expect("Error while fetching a Subnet record from the list")
                    })
                    .collect::<Vec<(String, SubnetRecord, bool)>>();

                payload.node_ids.into_iter().for_each(|node_to_remove| {
                    subnet_records
                        .iter_mut()
                        .for_each(|(_, subnet, has_changed)| {
                            if let Some(pos) = subnet
                                .membership
                                .iter()
                                .position(|node_id| node_id == &node_to_remove.get().to_vec())
                            {
                                subnet.membership.remove(pos);
                                *has_changed = true;
                            }
                        })
                });

                subnet_records
                    .into_iter()
                    .filter_map(|(key, subnet, has_changed)| {
                        if has_changed {
                            Some(RegistryMutation {
                                mutation_type: registry_mutation::Type::Update as i32,
                                key: key.as_bytes().to_vec(),
                                value: encode_or_panic(&subnet),
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<RegistryMutation>>()
            }
            None => panic!("Error while fetching current Subnet List record"),
        };

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(
            // Add the NodeOperatorRecord for the new Node Operator
            mutations,
        );
    }
}

/// The payload of a proposal to remove a Node from a Subnet
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemoveNodesFromSubnetPayload {
    /// The list of Node IDs that will be removed from their subnet
    pub node_ids: Vec<NodeId>,
}
