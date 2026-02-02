use crate::mutations::node_management::common::get_node_operator_id_for_node;
use crate::{common::LOG_PREFIX, registry::Registry};
use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId};
use ic_nervous_system_time_helpers::now_system_time;
use ic_registry_keys::make_node_record_key;
use ic_registry_transport::update;
use idna::domain_to_ascii_strict;
use prost::Message;
use serde::Serialize;
use std::time::SystemTime;

// Payload of the request to update the domain name of an existing node
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateNodeDomainDirectlyPayload {
    pub node_id: NodeId,
    pub domain: Option<String>,
}

impl Registry {
    /// Updates domain name of a node
    /// This method is called directly by the node operator
    pub fn do_update_node_domain_directly(&mut self, payload: UpdateNodeDomainDirectlyPayload) {
        let caller_id = dfn_core::api::caller();
        println!(
            "{LOG_PREFIX}do_update_node_domain_directly started: {payload:?} caller: {caller_id:?}"
        );
        self.do_update_node_domain(payload, caller_id, now_system_time())
            .unwrap();
    }

    fn do_update_node_domain(
        &mut self,
        payload: UpdateNodeDomainDirectlyPayload,
        caller_id: PrincipalId,
        now: SystemTime,
    ) -> Result<(), String> {
        let UpdateNodeDomainDirectlyPayload { node_id, domain } = payload;

        // Get existing node record and apply the changes
        let mut node_record = self.get_node_or_panic(node_id);

        // Ensure caller is an actual node operator of the node
        let node_operator_id = get_node_operator_id_for_node(self, node_id)
            .map_err(|e| format!("Failed to obtain the node operator ID: {e}"))
            .unwrap();

        assert_eq!(
            node_operator_id, caller_id,
            "The caller does not match this node's node operator id."
        );

        let reservation =
            self.try_reserve_capacity_for_node_operator_operation(now, node_operator_id, 1)?;

        // Ensure domain name is valid
        if let Some(ref domain) = domain
            && !domain_to_ascii_strict(domain).is_ok_and(|s| s == *domain)
        {
            panic!("invalid domain");
        }
        node_record.domain = domain;

        // Create the mutation
        let update_node_record = update(
            make_node_record_key(node_id).as_bytes(),
            node_record.encode_to_vec(),
        );
        let mutations = vec![update_node_record];

        // Check invariants before applying the mutation
        self.maybe_apply_mutation_internal(mutations);

        if let Err(e) = self.commit_used_capacity_for_node_operator_operation(now, reservation) {
            println!("{LOG_PREFIX}Error committing Rate Limit usage: {e}");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::UpdateNodeDomainDirectlyPayload;
    use crate::common::test_helpers::prepare_registry_with_nodes_and_node_operator_id;
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;
    use crate::registry::Registry;
    use crate::{
        common::test_helpers::{invariant_compliant_registry, prepare_registry_with_nodes},
        mutations::{
            common::test::TEST_NODE_ID, do_add_api_boundary_nodes::AddApiBoundaryNodesPayload,
        },
    };
    use ic_base_types::{NodeId, PrincipalId};
    use ic_nervous_system_time_helpers::now_system_time;
    use ic_protobuf::registry::replica_version::v1::{
        BlessedReplicaVersions, ReplicaVersionRecord,
    };
    use ic_registry_keys::{make_blessed_replica_versions_key, make_replica_version_key};
    use ic_registry_transport::{insert, upsert};
    use maplit::btreemap;
    use prost::Message;
    use std::str::FromStr;

    // Get the test data needed for most tests.
    // Registry, node id that exists, and the node operator id
    fn setup_registry_for_test() -> (Registry, NodeId, PrincipalId, PrincipalId) {
        let node_operator_id = PrincipalId::new_user_test_id(10_001);
        let node_provider_id = PrincipalId::new_user_test_id(20_002);

        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, node_ids_and_dkg_pks) =
            prepare_registry_with_nodes_and_node_operator_id(1, 1, node_operator_id);

        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(node_operator_id),
            node_provider_principal_id: Some(node_provider_id),
            node_allowance: 1,
            dc_id: "DC1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("bar".to_string()),
            max_rewardable_nodes: Some(btreemap! { "type1.2".to_string() => 1 }),
        };

        registry.do_add_node_operator(payload);
        let (node_id, _dkg_pks) = node_ids_and_dkg_pks.into_iter().next().unwrap();

        (registry, node_id, node_operator_id, node_provider_id)
    }

    #[test]
    #[should_panic(expected = "node record for 2vxsx-fae not found in the registry")]
    fn should_panic_if_record_not_found() {
        let mut registry = invariant_compliant_registry(0);
        let node_id = NodeId::from(
            PrincipalId::from_str(TEST_NODE_ID).expect("failed to parse principal id"),
        );
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id)
                .expect("failed to get the node operator id");
        let payload = UpdateNodeDomainDirectlyPayload {
            node_id,
            domain: None,
        };

        let _ = registry.do_update_node_domain(payload, node_operator_id, now_system_time());
    }

    #[test]
    #[should_panic(expected = "The caller does not match this node's node operator id.")]
    fn should_panic_if_caller_is_not_node_operator() {
        let mut registry = invariant_compliant_registry(0);
        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            1, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_operator_id = PrincipalId::new_user_test_id(101);
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("no node ids found")
            .to_owned();
        let payload = UpdateNodeDomainDirectlyPayload {
            node_id,
            domain: None,
        };

        registry
            .do_update_node_domain(payload, node_operator_id, now_system_time())
            .expect("Unexpected Err");
    }

    #[test]
    #[should_panic(expected = "invalid domain")]
    fn should_panic_if_domain_is_invalid() {
        let (mut registry, node_id, node_operator_id, _) = setup_registry_for_test();

        // Assert setting domain name to Some() works
        let new_domain = Some("_invalid".to_string());
        registry
            .do_update_node_domain(
                UpdateNodeDomainDirectlyPayload {
                    node_id,
                    domain: new_domain.clone(),
                },
                node_operator_id,
                now_system_time(),
            )
            .expect("Unexpected Err");
    }

    #[test]
    fn should_succeed_if_proposal_is_valid() {
        let (mut registry, node_id, node_operator_id, _) = setup_registry_for_test();

        // Assert setting domain name to Some() works
        let new_domain = Some("example.com".to_string());
        let _ = registry.do_update_node_domain(
            UpdateNodeDomainDirectlyPayload {
                node_id,
                domain: new_domain.clone(),
            },
            node_operator_id,
            now_system_time(),
        );
        let node_record = registry.get_node_or_panic(node_id);
        assert_eq!(node_record.domain, new_domain);

        // Assert setting domain name to None also works
        registry
            .do_update_node_domain(
                UpdateNodeDomainDirectlyPayload {
                    node_id,
                    domain: None,
                },
                node_operator_id,
                now_system_time(),
            )
            .expect("Unexpected Err");
        let node_record = registry.get_node_or_panic(node_id);
        assert_eq!(node_record.domain, None);
    }

    #[test]
    fn should_succeed_if_node_is_api_boundary_node() {
        let (mut registry, node_id, node_operator_id, _) = setup_registry_for_test();

        let new_domain = Some("example.com".to_string());
        registry
            .do_update_node_domain(
                UpdateNodeDomainDirectlyPayload {
                    node_id,
                    domain: new_domain.clone(),
                },
                node_operator_id,
                now_system_time(),
            )
            .expect("Unexpected Err");

        // create and bless version for the API boundary node
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

        let payload = AddApiBoundaryNodesPayload {
            node_ids: vec![node_id],
            version: "version".into(),
        };
        registry.do_add_api_boundary_nodes(payload);

        // try to change the domain name of this node
        let new_domain = Some("sample.io".to_string());
        registry
            .do_update_node_domain(
                UpdateNodeDomainDirectlyPayload {
                    node_id,
                    domain: new_domain.clone(),
                },
                node_operator_id,
                now_system_time(),
            )
            .expect("Unexpected Err");
        let node_record = registry.get_node_or_panic(node_id);
        assert_eq!(node_record.domain, new_domain);
    }

    #[test]
    fn test_do_update_node_domain_directly_fails_when_rate_limits_exceeded() {
        let (mut registry, node_id, node_operator_id, node_provider_id) = setup_registry_for_test();

        let payload = UpdateNodeDomainDirectlyPayload {
            node_id,
            domain: Some("example.com".to_string()),
        };

        let now = now_system_time();

        // Exhaust the rate limit capacity
        let available_operator =
            registry.get_available_node_operator_op_capacity(node_operator_id, now);
        let available_provider =
            registry.get_available_node_provider_op_capacity(node_provider_id, now);
        let available = available_operator.min(available_provider);
        let reservation = registry
            .try_reserve_capacity_for_node_operator_operation(now, node_operator_id, available)
            .unwrap();
        registry
            .commit_used_capacity_for_node_operator_operation(now, reservation)
            .unwrap();

        let error = registry
            .do_update_node_domain(payload, node_operator_id, now)
            .unwrap_err();
        assert_eq!(
            error,
            "Rate Limit Capacity exceeded. Please wait and try again later."
        );
    }
}
