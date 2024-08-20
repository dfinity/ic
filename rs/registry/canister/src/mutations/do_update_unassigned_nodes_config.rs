use crate::{
    common::LOG_PREFIX, mutations::common::check_replica_version_is_blessed, registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_protobuf::registry::unassigned_nodes_config::v1::UnassignedNodesConfigRecord;
use ic_registry_keys::make_unassigned_nodes_config_record_key;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};
use prost::Message;
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
                    UnassignedNodesConfigRecord::decode(encoded_config.value.as_slice()).unwrap();
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
            value: config.encode_to_vec(),
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

#[cfg(test)]
mod tests {
    use ic_protobuf::registry::replica_version::v1::{
        BlessedReplicaVersions, ReplicaVersionRecord,
    };
    use ic_registry_keys::{make_blessed_replica_versions_key, make_replica_version_key};
    use ic_registry_transport::{insert, upsert};
    use prost::Message;

    use crate::{
        common::test_helpers::invariant_compliant_registry,
        mutations::common::get_unassigned_nodes_record,
    };

    use super::UpdateUnassignedNodesConfigPayload;

    #[test]
    #[should_panic(expected = "version is NOT blessed")]
    fn should_panic_if_version_not_blessed() {
        let mut registry = invariant_compliant_registry(0);

        // Make a proposal to upgrade all unassigned nodes to a new version
        let payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: None,
            replica_version: Some("version".into()),
        };

        registry.do_update_unassigned_nodes_config(payload);
    }

    #[test]
    fn should_succeed_if_payload_is_valid() {
        let mut registry = invariant_compliant_registry(0);

        // Create and bless version
        let blessed_versions = registry
            .get(
                make_blessed_replica_versions_key().as_bytes(), // key
                registry.latest_version(),                      // version
            )
            .map(|v| BlessedReplicaVersions::decode(v.value.as_slice()).unwrap())
            .expect("failed to decode blessed versions");
        let blessed_versions = blessed_versions.blessed_version_ids;

        registry.maybe_apply_mutation_internal(vec![
            // Mutation to insert new replica version
            insert(
                make_replica_version_key("version"), // key
                ReplicaVersionRecord {
                    release_package_sha256_hex: "".into(),
                    release_package_urls: vec![],
                    guest_launch_measurement_sha256_hex: None,
                }
                .encode_to_vec(),
            ),
            // Mutation to insert BlessedReplicaVersions
            upsert(
                make_blessed_replica_versions_key(), // key
                BlessedReplicaVersions {
                    blessed_version_ids: [blessed_versions, vec!["version".into()]].concat(),
                }
                .encode_to_vec(),
            ),
        ]);

        let public_keys = vec!["keyX".into(), "keyY".into()];

        // Make a proposal to upgrade all unassigned nodes to a new blessed version
        // and add readonly SSH keys
        let payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: Some(public_keys.clone()),
            replica_version: Some("version".into()),
        };

        registry.do_update_unassigned_nodes_config(payload);

        let unassigned_nodes_record = get_unassigned_nodes_record(&registry)
            .expect("failed to get unassigned nodes config record");
        assert_eq!(unassigned_nodes_record.replica_version, "version");
        assert_eq!(unassigned_nodes_record.ssh_readonly_access, public_keys);

        // Make a proposal to remove all SSH keys
        let payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: Some(Vec::<String>::new()),
            replica_version: None,
        };

        registry.do_update_unassigned_nodes_config(payload);

        let unassigned_nodes_record = get_unassigned_nodes_record(&registry)
            .expect("failed to get unassigned nodes config record");
        assert_eq!(unassigned_nodes_record.replica_version, "version");
        assert_eq!(
            unassigned_nodes_record.ssh_readonly_access,
            Vec::<String>::new()
        );
    }
}
