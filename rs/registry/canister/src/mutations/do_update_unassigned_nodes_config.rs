use crate::{
    common::LOG_PREFIX,
    mutations::common::{check_replica_version_is_blessed, encode_or_panic},
    registry::Registry,
};

use candid::{CandidType, Deserialize};
use ic_nns_common::registry::decode_or_panic;
use ic_protobuf::registry::unassigned_nodes_config::v1::UnassignedNodesConfigRecord;
use ic_registry_keys::make_unassigned_nodes_config_record_key;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};
use serde::Serialize;

/// Updates the parameter that apply to all unassigned nodes in the Registry.
///
/// This method is called by the Governance canister, after a proposal for
/// updating the unassigned nodes config has been accepted.
impl Registry {
    pub fn do_update_unassigned_nodes_config(
        &mut self,
        payload: UpdateUnassignedNodesConfigPayload,
    ) {
        println!("{}do_update_unassigned_nodes: {:?}", LOG_PREFIX, payload);

        let unassigned_nodes_key = make_unassigned_nodes_config_record_key();
        let (current_ssh_readonly_access, current_replica_version) = match self
            .get(unassigned_nodes_key.as_bytes(), self.latest_version())
        {
            Some(encoded_config) => {
                let config =
                    decode_or_panic::<UnassignedNodesConfigRecord>(encoded_config.value.to_vec());
                (config.ssh_readonly_access, config.replica_version)
            }
            None => (vec![], "".to_string()),
        };

        let config = UnassignedNodesConfigRecord {
            ssh_readonly_access: match payload.ssh_readonly_access {
                Some(keys) => keys,
                None => current_ssh_readonly_access,
            },
            replica_version: match payload.replica_version {
                Some(keys) => keys,
                None => current_replica_version,
            },
        };

        check_replica_version_is_blessed(self, &config.replica_version);

        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Upsert as i32,
            key: unassigned_nodes_key.as_bytes().to_vec(),
            value: encode_or_panic(&config),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateUnassignedNodesConfigPayload {
    pub ssh_readonly_access: Option<Vec<String>>,
    pub replica_version: Option<String>,
}
