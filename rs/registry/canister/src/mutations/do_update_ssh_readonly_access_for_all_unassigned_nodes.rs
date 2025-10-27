use crate::{
    common::LOG_PREFIX,
    mutations::do_update_unassigned_nodes_config::UpdateUnassignedNodesConfigPayload,
    registry::Registry,
};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

/// Updates the parameter that apply to all unassigned nodes in the Registry.
///
/// This method is called by the Governance canister, after a proposal for
/// updating the unassigned nodes config has been accepted.
impl Registry {
    pub fn do_update_ssh_readonly_access_for_all_unassigned_nodes(
        &mut self,
        payload: UpdateSshReadOnlyAccessForAllUnassignedNodesPayload,
    ) {
        println!("{LOG_PREFIX}do_update_ssh_readonly_access_for_all_unassigned_nodes: {payload:?}");

        let update_unassigned_nodes_config_payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: Some(payload.ssh_readonly_keys),
            replica_version: None,
        };

        self.do_update_unassigned_nodes_config(update_unassigned_nodes_config_payload);
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateSshReadOnlyAccessForAllUnassignedNodesPayload {
    pub ssh_readonly_keys: Vec<String>,
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
        mutations::{
            common::{get_blessed_replica_versions, get_unassigned_nodes_record},
            do_deploy_guestos_to_all_unassigned_nodes::DeployGuestosToAllUnassignedNodesPayload,
        },
    };

    use super::UpdateSshReadOnlyAccessForAllUnassignedNodesPayload;

    #[test]
    #[should_panic(expected = "version is NOT blessed")]
    fn should_panic_if_version_not_blessed() {
        let mut registry = invariant_compliant_registry(0);

        // Make a proposal to upgrade all unassigned nodes to a new version
        let payload = DeployGuestosToAllUnassignedNodesPayload {
            elected_replica_version: "version".into(),
        };

        registry.do_deploy_guestos_to_all_unassigned_nodes(payload);
    }

    #[test]
    fn should_succeed_if_upgrade_proposal_is_valid() {
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
                    guest_launch_measurements: None,
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

        // Make a proposal to upgrade all unassigned nodes to a new blessed version
        let payload = DeployGuestosToAllUnassignedNodesPayload {
            elected_replica_version: "version".into(),
        };

        registry.do_deploy_guestos_to_all_unassigned_nodes(payload);

        let unassigned_nodes_record = get_unassigned_nodes_record(&registry)
            .expect("failed to get unassigned nodes config record");
        assert_eq!(unassigned_nodes_record.replica_version, "version");
    }

    #[test]
    fn should_succeed_adding_and_removing_readonly_ssh_keys() {
        let mut registry = invariant_compliant_registry(0);

        // first we need to make sure that the unassigned nodes record has blessed replica version
        let blessed_versions = get_blessed_replica_versions(&registry)
            .expect("failed to get the blessed replica versions");
        let payload = DeployGuestosToAllUnassignedNodesPayload {
            elected_replica_version: blessed_versions
                .blessed_version_ids
                .first()
                .expect("there is no blessed replica version")
                .to_string(),
        };
        registry.do_deploy_guestos_to_all_unassigned_nodes(payload);

        // Make a proposal to add two keys with read only access for the unassigned nodes
        let public_keys = vec!["keyX".into(), "keyY".into()];
        let payload = UpdateSshReadOnlyAccessForAllUnassignedNodesPayload {
            ssh_readonly_keys: public_keys.clone(),
        };

        registry.do_update_ssh_readonly_access_for_all_unassigned_nodes(payload);

        let unassigned_nodes_record = get_unassigned_nodes_record(&registry)
            .expect("failed to get unassigned nodes config record");
        assert_eq!(unassigned_nodes_record.ssh_readonly_access, public_keys);

        // Make a proposal to remove the keys
        let payload = UpdateSshReadOnlyAccessForAllUnassignedNodesPayload {
            ssh_readonly_keys: vec![],
        };

        registry.do_update_ssh_readonly_access_for_all_unassigned_nodes(payload);

        let unassigned_nodes_record = get_unassigned_nodes_record(&registry)
            .expect("failed to get unassigned nodes config record");
        assert_eq!(
            unassigned_nodes_record.ssh_readonly_access,
            Vec::<String>::new()
        );
    }
}
