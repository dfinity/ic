use crate::{
    common::LOG_PREFIX,
    mutations::common::{check_replica_version_is_blessed, decode_registry_value, encode_or_panic},
    registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};

impl Registry {
    pub fn do_update_subnet_replica_version(&mut self, payload: UpdateSubnetReplicaVersionPayload) {
        println!(
            "{}do_update_subnet_replica_version: {:?}",
            LOG_PREFIX, payload
        );

        check_replica_version_is_blessed(self, &payload.replica_version_id);

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
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateSubnetReplicaVersionPayload {
    /// The subnet to update.
    pub subnet_id: PrincipalId, // SubnetId See NNS-73
    /// The new Replica version to use.
    pub replica_version_id: String,
}
