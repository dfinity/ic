use crate::{
    common::LOG_PREFIX, mutations::common::check_replica_version_is_blessed, registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};
use prost::Message;
use serde::Serialize;

impl Registry {
    pub fn do_deploy_guestos_to_all_subnet_nodes(
        &mut self,
        payload: DeployGuestosToAllSubnetNodesPayload,
    ) {
        println!(
            "{}do_deploy_guestos_to_all_subnet_nodes: {:?}",
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
                timestamp_nanoseconds: _,
            }) => {
                let mut subnet_record = SubnetRecord::decode(subnet_record_vec.as_slice()).unwrap();
                subnet_record.replica_version_id = payload.replica_version_id;
                RegistryMutation {
                    mutation_type: registry_mutation::Type::Update as i32,
                    key: subnet_key.as_bytes().to_vec(),
                    value: subnet_record.encode_to_vec(),
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
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct DeployGuestosToAllSubnetNodesPayload {
    /// The subnet to update.
    pub subnet_id: PrincipalId, // SubnetId See NNS-73
    /// The new Replica version to use.
    pub replica_version_id: String,
}
