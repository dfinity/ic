use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::NodeId;
use ic_registry_keys::make_api_boundary_node_record_key;
use ic_registry_transport::update;
use serde::Serialize;

use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use super::common::{check_api_boundary_nodes_exist, check_replica_version_is_blessed};

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateApiBoundaryNodesVersionPayload {
    pub node_ids: Vec<NodeId>,
    pub version: String,
}

impl Registry {
    /// Updates the version for a set of ApiBoundaryNodeRecords
    pub fn do_update_api_boundary_nodes_version(
        &mut self,
        payload: UpdateApiBoundaryNodesVersionPayload,
    ) {
        println!(
            "{}do_update_api_boundary_nodes_version: {:?}",
            LOG_PREFIX, payload
        );

        // Ensure payload is valid
        self.validate_update_api_boundary_nodes_version_payload(&payload);

        // Mutations to update ApiBoundaryNodeRecords with version
        let mutations = payload.node_ids.into_iter().map(|node_id| {
            let key = make_api_boundary_node_record_key(node_id);
            let mut api_boundary_node = self.get_api_boundary_node_or_panic(node_id);
            api_boundary_node.version = payload.version.clone();

            update(key, encode_or_panic(&api_boundary_node))
        });

        self.maybe_apply_mutation_internal(mutations.collect())
    }

    fn validate_update_api_boundary_nodes_version_payload(
        &self,
        payload: &UpdateApiBoundaryNodesVersionPayload,
    ) {
        check_api_boundary_nodes_exist(self, &payload.node_ids);
        check_replica_version_is_blessed(self, &payload.version);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ic_base_types::{NodeId, PrincipalId};
    use ic_protobuf::registry::{
        api_boundary_node::v1::ApiBoundaryNodeRecord,
        replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    };
    use ic_registry_keys::{
        make_api_boundary_node_record_key, make_blessed_replica_versions_key,
        make_replica_version_key,
    };
    use ic_registry_transport::{insert, upsert};
    use ic_types::ReplicaVersion;

    use crate::{
        common::test_helpers::{invariant_compliant_registry, prepare_registry_with_nodes},
        mutations::common::{decode_registry_value, encode_or_panic, test::TEST_NODE_ID},
    };

    use super::UpdateApiBoundaryNodesVersionPayload;

    #[test]
    #[should_panic(expected = "record not found")]
    fn should_panic_if_record_not_found() {
        let mut registry = invariant_compliant_registry(0);

        // Validate proposal payload
        let node_id = NodeId::from(
            PrincipalId::from_str(TEST_NODE_ID).expect("failed to parse principal id"),
        );

        let payload = UpdateApiBoundaryNodesVersionPayload {
            node_ids: vec![node_id],
            version: "version".into(),
        };

        registry.do_update_api_boundary_nodes_version(payload);
    }

    #[test]
    #[should_panic(expected = "version is NOT blessed")]
    fn should_panic_if_version_not_blessed() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        // Add boundary node to registry
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();

        registry.maybe_apply_mutation_internal(vec![
            // Mutation to insert ApiBoundaryNodeRecord
            insert(
                make_api_boundary_node_record_key(node_id), // key
                encode_or_panic(&ApiBoundaryNodeRecord {
                    version: ReplicaVersion::default().to_string(),
                }),
            ),
        ]);

        // Validate proposal payload
        let payload = UpdateApiBoundaryNodesVersionPayload {
            node_ids: vec![node_id],
            version: "version".into(),
        };

        registry.do_update_api_boundary_nodes_version(payload);
    }

    #[test]
    fn should_succeed_if_proposal_is_valid() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        // Create and bless version
        let blessed_versions: BlessedReplicaVersions = registry
            .get(
                make_blessed_replica_versions_key().as_bytes(), // key
                registry.latest_version(),                      // version
            )
            .map(|v| decode_registry_value(v.value.clone()))
            .expect("failed to decode blessed versions");
        let blessed_versions = blessed_versions.blessed_version_ids;

        registry.maybe_apply_mutation_internal(vec![
            // Mutation to insert ApiBoundaryNodeRecord
            insert(
                make_replica_version_key("version"), // key
                encode_or_panic(&ReplicaVersionRecord {
                    release_package_sha256_hex: "".into(),
                    release_package_urls: vec![],
                    guest_launch_measurement_sha256_hex: None,
                }),
            ),
            // Mutation to insert BlessedReplicaVersions
            upsert(
                make_blessed_replica_versions_key(), // key
                encode_or_panic(&BlessedReplicaVersions {
                    blessed_version_ids: [blessed_versions, vec!["version".into()]].concat(),
                }),
            ),
        ]);

        // Add boundary node to registry
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();

        registry.maybe_apply_mutation_internal(vec![
            // Mutation to insert ApiBoundaryNodeRecord
            insert(
                make_api_boundary_node_record_key(node_id), // key
                encode_or_panic(&ApiBoundaryNodeRecord {
                    version: "version".into(),
                }),
            ),
        ]);

        // Validate proposal payload
        let payload = UpdateApiBoundaryNodesVersionPayload {
            node_ids: vec![node_id],
            version: "version".into(),
        };

        registry.do_update_api_boundary_nodes_version(payload);
    }
}
