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
    pub fn do_deploy_guestos_to_all_unassigned_nodes(
        &mut self,
        payload: DeployGuestosToAllUnassignedNodesPayload,
    ) {
        println!(
            "{}do_deploy_guestos_to_all_unassigned_nodes: {:?}",
            LOG_PREFIX, payload
        );

        let update_unassigned_nodes_config_payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: None,
            replica_version: Some(payload.elected_replica_version),
        };

        self.do_update_unassigned_nodes_config(update_unassigned_nodes_config_payload);
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeployGuestosToAllUnassignedNodesPayload {
    pub elected_replica_version: String,
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

    use super::DeployGuestosToAllUnassignedNodesPayload;

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
        let blessed_versions: BlessedReplicaVersions = registry
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

        // Make a proposal to upgrade all unassigned nodes to a new blessed version
        let payload = DeployGuestosToAllUnassignedNodesPayload {
            elected_replica_version: "version".into(),
        };

        registry.do_deploy_guestos_to_all_unassigned_nodes(payload);

        let unassigned_nodes_record = get_unassigned_nodes_record(&registry)
            .expect("failed to get unassigned nodes config record");
        assert_eq!(unassigned_nodes_record.replica_version, "version");
    }
}
