//! TODO(NNS1-1025): To be deleted after the next registry upgrade

use std::str::FromStr;

use ic_base_types::{NodeId, PrincipalId};
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::{
    itest_helpers::{
        local_test_on_nns_subnet, set_up_registry_canister, set_up_universal_canister,
    },
    registry::{get_value, invariant_compliant_mutation_as_atomic_req, TEST_ID},
};
use ic_protobuf::registry::node::v1::{
    connection_endpoint::Protocol, ConnectionEndpoint, NodeRecord,
};
use ic_registry_keys::make_node_record_key;
use ic_registry_transport::pb::v1::{
    registry_mutation, RegistryAtomicMutateRequest, RegistryMutation,
};
use ic_test_utilities::types::ids::user_test_id;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;

#[test]
fn test_short_lived_delete_record_on_upgrade() {
    local_test_on_nns_subnet(|runtime| async move {
        let node_record_key = make_node_record_key(NodeId::new(
            PrincipalId::from_str(
                "hwywo-g5rog-wwern-wtt6d-ds6fb-jvh6j-mwlha-pj2ul-2m4dj-6mdqq-gqe",
            )
            .unwrap(),
        ));

        let node_operator_pid = user_test_id(TEST_ID);

        let connection_endpoint = ConnectionEndpoint {
            ip_addr: "128.0.0.1".to_string(),
            port: 12345,
            protocol: Protocol::Http1 as i32,
        };
        let node_record = NodeRecord {
            node_operator_id: node_operator_pid.get().to_vec(),
            xnet: Some(connection_endpoint.clone()),
            http: Some(connection_endpoint),
            ..Default::default()
        };

        // First prepare the registry with a Node Operator record and make it callable
        // by anyone
        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![RegistryMutation {
                        mutation_type: registry_mutation::Type::Insert as i32,
                        key: node_record_key.as_bytes().to_vec(),
                        value: encode_or_panic(&node_record),
                    }],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // Install the universal canister in place of the proposals canister
        let mock_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the proposal canister, it can impersonate
        // it
        assert_eq!(
            mock_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let node_record = get_value::<NodeRecord>(&registry, node_record_key.as_bytes()).await;
        // Check if some fields are present
        assert!(node_record.http.is_some());

        // Go through an upgrade cycle
        registry.upgrade_to_self_binary(vec![]).await.unwrap();

        // Then, ensure there is no value for the node
        let node_record = get_value::<NodeRecord>(&registry, node_record_key.as_bytes()).await;
        assert_eq!(node_record, NodeRecord::default());
        assert!(node_record.http.is_none());

        // Go through another upgrade cycle to ensure no panics occur after record is deleted
        registry.upgrade_to_self_binary(vec![]).await.unwrap();

        Ok(())
    })
}
