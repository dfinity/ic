use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::NodeId;
use ic_registry_keys::make_api_boundary_node_record_key;
use ic_registry_transport::update;
use prost::Message;
use serde::Serialize;

use crate::{common::LOG_PREFIX, registry::Registry};

use super::common::{check_api_boundary_nodes_exist, check_replica_version_is_blessed};

/// Deprecated; please use `DeployGuestosToSomeApiBoundaryNodes` instead.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateApiBoundaryNodesVersionPayload {
    pub node_ids: Vec<NodeId>,
    pub version: String,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct DeployGuestosToSomeApiBoundaryNodes {
    pub node_ids: Vec<NodeId>,
    pub version: String,
}

impl From<UpdateApiBoundaryNodesVersionPayload> for DeployGuestosToSomeApiBoundaryNodes {
    fn from(src: UpdateApiBoundaryNodesVersionPayload) -> Self {
        let UpdateApiBoundaryNodesVersionPayload { node_ids, version } = src;

        Self { node_ids, version }
    }
}

impl Registry {
    /// Deprecated; please use `do_update_api_boundary_nodes_version`.
    pub fn do_update_api_boundary_nodes_version(
        &mut self,
        payload: UpdateApiBoundaryNodesVersionPayload,
    ) {
        let payload = DeployGuestosToSomeApiBoundaryNodes::from(payload);
        self.do_deploy_guestos_to_some_api_boundary_nodes(payload);
    }

    /// Updates the version for a set of ApiBoundaryNodeRecords
    pub fn do_deploy_guestos_to_some_api_boundary_nodes(
        &mut self,
        payload: DeployGuestosToSomeApiBoundaryNodes,
    ) {
        println!("{LOG_PREFIX}do_update_api_boundary_nodes_version: {payload:?}");

        // Ensure payload is valid
        self.validate_update_api_boundary_nodes_version_payload(&payload);

        // Mutations to update ApiBoundaryNodeRecords with version
        let mutations = payload.node_ids.into_iter().map(|node_id| {
            let key = make_api_boundary_node_record_key(node_id);
            let mut api_boundary_node = self.get_api_boundary_node_or_panic(node_id);
            api_boundary_node.version.clone_from(&payload.version);

            update(key, api_boundary_node.encode_to_vec())
        });

        self.maybe_apply_mutation_internal(mutations.collect())
    }

    fn validate_update_api_boundary_nodes_version_payload(
        &self,
        payload: &DeployGuestosToSomeApiBoundaryNodes,
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
    use prost::Message;

    use crate::{
        common::test_helpers::{invariant_compliant_registry, prepare_registry_with_nodes},
        mutations::common::test::TEST_NODE_ID,
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
                ApiBoundaryNodeRecord {
                    version: ReplicaVersion::default().to_string(),
                }
                .encode_to_vec(),
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
        let blessed_versions = registry
            .get(
                make_blessed_replica_versions_key().as_bytes(), // key
                registry.latest_version(),                      // version
            )
            .map(|v| BlessedReplicaVersions::decode(v.value.as_slice()).unwrap())
            .expect("failed to decode blessed versions");
        let blessed_versions = blessed_versions.blessed_version_ids;

        registry.maybe_apply_mutation_internal(vec![
            // Mutation to insert ApiBoundaryNodeRecord
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
                ApiBoundaryNodeRecord {
                    version: "version".into(),
                }
                .encode_to_vec(),
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
