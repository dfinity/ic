use crate::{
    common::LOG_PREFIX,
    mutations::common::{decode_registry_value, encode_or_panic},
    registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::{
    replica_version::v1::BlessedReplicaVersions, subnet::v1::SubnetRecord,
};
use ic_registry_keys::{make_blessed_replica_version_key, make_subnet_record_key};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};

impl Registry {
    pub fn do_update_subnet_replica_version(&mut self, payload: UpdateSubnetReplicaVersionPayload) {
        println!(
            "{}do_update_subnet_replica_version: {:?}",
            LOG_PREFIX, payload
        );

        let blessed_replica_key = make_blessed_replica_version_key();
        // Get the current list of blessed replica versions
        if let Some(RegistryValue {
            value: blessed_list_vec,
            version,
            deletion_marker: _,
        }) = self.get(blessed_replica_key.as_bytes(), self.latest_version())
        {
            let blessed_list =
                decode_registry_value::<BlessedReplicaVersions>(blessed_list_vec.clone());
            // Verify that the new one is blessed
            assert!(
                blessed_list
                    .blessed_version_ids
                    .iter()
                    .any(|v| v == &payload.replica_version_id),
                "Attempt to change the replica version of subnet {} to '{}' is rejected, \
                because that version is NOT blessed. The list of blessed replica versions, at version {}, \
                is: {}.",
                payload.subnet_id,
                payload.replica_version_id,
                version,
                blessed_versions_to_string(&blessed_list)
            );
        } else {
            panic!(
                "Error while fetching the list of blessed replica versions record: {}",
                payload.replica_version_id
            )
        }

        // Get the subnet record
        let subnet_key = make_subnet_record_key(SubnetId::from(payload.subnet_id));
        let mutation = match self.get(subnet_key.as_bytes(), self.latest_version()) {
            Some(RegistryValue {
                value: subnet_record_vec,
                version: _,
                deletion_marker: _,
            }) => {
                let mut subnet_record =
                    decode_registry_value::<SubnetRecord>(subnet_record_vec.clone());
                subnet_record.replica_version_id = payload.replica_version_id;
                RegistryMutation {
                    mutation_type: registry_mutation::Type::Update as i32,
                    key: subnet_key.as_bytes().to_vec(),
                    value: encode_or_panic(&subnet_record),
                }
            }
            None => panic!("Error while fetching the subnet record"),
        };

        let mutations = vec![mutation];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations)
    }
}

/// The argument of a command to update the replica version of a single subnet
/// to a specific version.
///
/// The replica will be mutated only if the given version is, indeed, blessed.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateSubnetReplicaVersionPayload {
    /// The subnet to update.
    pub subnet_id: PrincipalId, // SubnetId See NNS-73
    /// The new Replica version to use.
    pub replica_version_id: String,
}

fn blessed_versions_to_string(blessed: &BlessedReplicaVersions) -> String {
    format!("[{}]", blessed.blessed_version_ids.join(", "))
}
