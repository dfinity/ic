use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
use ic_registry_keys::make_api_boundary_node_record_key;
use ic_registry_transport::insert;
use prost::Message;
use serde::Serialize;

use crate::{common::LOG_PREFIX, registry::Registry};

use super::common::check_replica_version_is_blessed;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct AddApiBoundaryNodesPayload {
    pub node_ids: Vec<NodeId>,
    pub version: String,
}

impl Registry {
    /// Adds an ApiBoundaryNodeRecord to the registry
    pub fn do_add_api_boundary_nodes(&mut self, payload: AddApiBoundaryNodesPayload) {
        println!("{}do_add_api_boundary_nodes: {:?}", LOG_PREFIX, payload);

        // Ensure payload is valid
        self.validate_add_api_boundary_nodes_payload(&payload);

        // Mutations to insert ApiBoundaryNodeRecord
        let mutations = payload.node_ids.into_iter().map(|node_id| {
            let key = make_api_boundary_node_record_key(node_id);
            insert(
                key,
                ApiBoundaryNodeRecord {
                    version: payload.version.clone(),
                }
                .encode_to_vec(),
            )
        });

        self.maybe_apply_mutation_internal(mutations.collect());
    }

    fn validate_add_api_boundary_nodes_payload(&self, payload: &AddApiBoundaryNodesPayload) {
        // Ensure there are no duplicates
        let unique_count = payload
            .node_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        if unique_count != payload.node_ids.len() {
            panic!("there are duplicate nodes")
        }

        for node_id in payload.node_ids.iter() {
            // Ensure node exists
            let node_record = self.get_node_or_panic(*node_id);

            // Ensure node has a domain name
            if node_record.domain.is_none() {
                panic!("node is missing a domain name: {node_id}")
            }

            // Ensure record does not exist (the node is not already an API boundary node)
            let key = make_api_boundary_node_record_key(*node_id);

            let record = self.get(
                key.as_bytes(),        // key
                self.latest_version(), // version
            );

            if record.is_some() {
                panic!("record exists: {node_id}");
            }

            // Ensure node is not assigned to a subnet
            self.get_subnet_list_record().subnets.iter().for_each(|id| {
                let id =
                    SubnetId::from(PrincipalId::try_from(id).expect("failed to parse subnet id"));

                self.get_subnet_or_panic(id)
                    .membership
                    .iter()
                    .for_each(|id| {
                        let id = NodeId::from(
                            PrincipalId::try_from(id).expect("failed to parse principal id"),
                        );

                        if *node_id == id {
                            panic!("node assigned to subnet: {node_id}");
                        }
                    })
            });
        }

        // Ensure version exists and is blessed
        check_replica_version_is_blessed(self, &payload.version);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ic_base_types::{NodeId, PrincipalId, SubnetId};
    use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
    use ic_protobuf::registry::{
        api_boundary_node::v1::ApiBoundaryNodeRecord,
        replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    };
    use ic_registry_keys::{
        make_api_boundary_node_record_key, make_blessed_replica_versions_key, make_node_record_key,
        make_replica_version_key,
    };
    use ic_registry_transport::{insert, update, upsert};
    use ic_types::ReplicaVersion;
    use prost::Message;

    use crate::{
        common::test_helpers::{
            add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
            prepare_registry_with_nodes,
        },
        mutations::common::test::TEST_NODE_ID,
    };

    use super::AddApiBoundaryNodesPayload;

    #[test]
    #[should_panic(expected = "node record for 2vxsx-fae not found in the registry")]
    fn should_panic_if_node_not_found() {
        let mut registry = invariant_compliant_registry(0);

        let node_id = NodeId::from(
            PrincipalId::from_str(TEST_NODE_ID).expect("failed to parse principal id"),
        );

        let payload = AddApiBoundaryNodesPayload {
            node_ids: vec![node_id],
            version: "version".into(),
        };

        registry.do_add_api_boundary_nodes(payload);
    }

    #[test]
    #[should_panic(expected = "record exists")]
    fn should_panic_if_record_exists() {
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

        let payload = AddApiBoundaryNodesPayload {
            node_ids: vec![node_id],
            version: ReplicaVersion::default().to_string(),
        };

        registry.maybe_apply_mutation_internal(vec![insert(
            make_api_boundary_node_record_key(node_id), // key
            ApiBoundaryNodeRecord {
                version: payload.version.clone(),
            }
            .encode_to_vec(),
        )]);

        registry.do_add_api_boundary_nodes(payload);
    }

    #[test]
    #[should_panic(expected = "node assigned to subnet")]
    fn should_panic_if_node_is_assigned_to_subnet() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        // Add subnet to registry and assign the node to it
        let subnet_record =
            get_invariant_compliant_subnet_record(node_ids_and_dkg_pks.keys().copied().collect());

        registry.maybe_apply_mutation_internal(add_fake_subnet(
            SubnetId::from(*TEST_USER1_PRINCIPAL),  // signing_subnet
            &mut registry.get_subnet_list_record(), // subnet_list_record
            subnet_record,
            &node_ids_and_dkg_pks,
        ));

        // Create an invalid proposal payload by picking a node that is assigned to a subnet
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();

        let payload = AddApiBoundaryNodesPayload {
            node_ids: vec![node_id],
            version: "version".into(),
        };

        registry.do_add_api_boundary_nodes(payload);
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

        // Create an invalid proposal payload by specifying a version that is not blessed
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();

        let payload = AddApiBoundaryNodesPayload {
            node_ids: vec![node_id],
            version: "version".into(),
        };

        registry.do_add_api_boundary_nodes(payload);
    }

    #[test]
    #[should_panic(expected = "node is missing a domain name")]
    fn should_panic_if_node_has_no_domain() {
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
            insert(
                make_replica_version_key("version"), // key
                ReplicaVersionRecord {
                    release_package_sha256_hex: "".into(),
                    release_package_urls: vec![],
                    guest_launch_measurement_sha256_hex: None,
                }
                .encode_to_vec(),
            ),
            upsert(
                make_blessed_replica_versions_key(), // key
                BlessedReplicaVersions {
                    blessed_version_ids: [blessed_versions, vec!["version".into()]].concat(),
                }
                .encode_to_vec(),
            ),
        ]);

        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();

        // remove the default domain name from the node
        let mut node_record = registry.get_node_or_panic(node_id);
        node_record.domain = None;
        let update_node_record = update(
            make_node_record_key(node_id).as_bytes(),
            node_record.encode_to_vec(),
        );
        let mutations = vec![update_node_record];
        registry.maybe_apply_mutation_internal(mutations);

        // try to turn node without domain name into an API boundary node
        let payload = AddApiBoundaryNodesPayload {
            node_ids: vec![node_id],
            version: "version".into(),
        };

        registry.do_add_api_boundary_nodes(payload);
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
            insert(
                make_replica_version_key("version"), // key
                ReplicaVersionRecord {
                    release_package_sha256_hex: "".into(),
                    release_package_urls: vec![],
                    guest_launch_measurement_sha256_hex: None,
                }
                .encode_to_vec(),
            ),
            upsert(
                make_blessed_replica_versions_key(), // key
                BlessedReplicaVersions {
                    blessed_version_ids: [blessed_versions, vec!["version".into()]].concat(),
                }
                .encode_to_vec(),
            ),
        ]);

        // Create a valid proposal payload
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();

        let payload = AddApiBoundaryNodesPayload {
            node_ids: vec![node_id],
            version: "version".into(),
        };

        registry.do_add_api_boundary_nodes(payload);
    }

    #[test]
    #[should_panic(expected = "there are duplicate nodes")]
    fn should_fail_adding_duplicate_nodes() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            3, // node count
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
            insert(
                make_replica_version_key("version"), // key
                ReplicaVersionRecord {
                    release_package_sha256_hex: "".into(),
                    release_package_urls: vec![],
                    guest_launch_measurement_sha256_hex: None,
                }
                .encode_to_vec(),
            ),
            upsert(
                make_blessed_replica_versions_key(), // key
                BlessedReplicaVersions {
                    blessed_version_ids: [blessed_versions, vec!["version".into()]].concat(),
                }
                .encode_to_vec(),
            ),
        ]);

        // Create an invalid proposal payload by adding a node twice
        let mut node_ids: Vec<_> = node_ids_and_dkg_pks.keys().cloned().collect();
        node_ids.push(node_ids.first().cloned().expect("failed to get a node id"));

        let payload = AddApiBoundaryNodesPayload {
            node_ids,
            version: "version".into(),
        };

        registry.do_add_api_boundary_nodes(payload);
    }

    #[test]
    #[should_panic(expected = "node assigned to subnet")]
    fn should_fail_if_at_least_one_node_is_in_a_subnet() {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            3, // node count
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
            insert(
                make_replica_version_key("version"), // key
                ReplicaVersionRecord {
                    release_package_sha256_hex: "".into(),
                    release_package_urls: vec![],
                    guest_launch_measurement_sha256_hex: None,
                }
                .encode_to_vec(),
            ),
            upsert(
                make_blessed_replica_versions_key(), // key
                BlessedReplicaVersions {
                    blessed_version_ids: [blessed_versions, vec!["version".into()]].concat(),
                }
                .encode_to_vec(),
            ),
        ]);

        let node_ids: Vec<_> = node_ids_and_dkg_pks.keys().cloned().collect();

        // Add subnet to registry and assign the node to it
        let subnet_record = get_invariant_compliant_subnet_record(vec![node_ids
            .first()
            .cloned()
            .expect("failed to get a node id")]);

        registry.maybe_apply_mutation_internal(add_fake_subnet(
            SubnetId::from(*TEST_USER1_PRINCIPAL),  // signing_subnet
            &mut registry.get_subnet_list_record(), // subnet_list_record
            subnet_record,
            &node_ids_and_dkg_pks,
        ));

        let payload = AddApiBoundaryNodesPayload {
            node_ids,
            version: "version".into(),
        };

        registry.do_add_api_boundary_nodes(payload);
    }

    #[test]
    fn should_succeed_adding_multiple_nodes() {
        let mut registry: crate::registry::Registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            3, // node count
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
            insert(
                make_replica_version_key("version"), // key
                ReplicaVersionRecord {
                    release_package_sha256_hex: "".into(),
                    release_package_urls: vec![],
                    guest_launch_measurement_sha256_hex: None,
                }
                .encode_to_vec(),
            ),
            upsert(
                make_blessed_replica_versions_key(), // key
                BlessedReplicaVersions {
                    blessed_version_ids: [blessed_versions, vec!["version".into()]].concat(),
                }
                .encode_to_vec(),
            ),
        ]);

        // Create a valid proposal payload
        let mut node_ids: Vec<NodeId> = node_ids_and_dkg_pks.keys().cloned().collect();

        let payload = AddApiBoundaryNodesPayload {
            node_ids: node_ids.clone(),
            version: "version".into(),
        };

        registry.do_add_api_boundary_nodes(payload);

        let mut api_bns = registry
            .get_api_boundary_node_ids()
            .expect("couldn't get API nodes");
        api_bns.sort();
        node_ids.sort();

        assert_eq!(node_ids, api_bns);
    }
}
