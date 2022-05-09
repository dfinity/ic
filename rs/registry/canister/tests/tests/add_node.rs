use std::collections::BTreeMap;

use dfn_candid::candid;
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_USER1_KEYPAIR,
};
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::registry::{
    get_committee_signing_key, get_dkg_dealing_key, get_node_operator_record, get_node_record,
    get_node_signing_key, get_transport_tls_certificate,
};
use ic_nns_test_utils::{
    itest_helpers::{local_test_on_nns_subnet, set_up_registry_canister},
    registry::{invariant_compliant_mutation_as_atomic_req, prepare_add_node_payload},
};
use ic_protobuf::registry::{node::v1::NodeRecord, node_operator::v1::NodeOperatorRecord};
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::pb::v1::{
    registry_mutation, RegistryAtomicMutateRequest, RegistryMutation,
};
use ic_types::NodeId;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;

#[test]
fn node_is_created_on_receiving_the_request() {
    local_test_on_nns_subnet(|runtime| async move {
        // First prepare the registry with a Node Operator record and make it callable
        // by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(init_mutation_with_node_allowance(100))
                .build(),
        )
        .await;

        let (payload, node_pks, node_id) = prepare_add_node_payload();

        // Then, ensure there is no value for the node
        let node_record = get_node_record(&registry, node_id).await;
        assert_eq!(node_record, NodeRecord::default());

        let response: Result<NodeId, String> = registry
            .update_from_sender(
                "add_node",
                candid,
                (payload,),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_ok());

        // Now let's check directly in the registry that the mutation actually happened
        let node_record = get_node_record(&registry, node_id).await;
        // Check if some fields are present
        assert!(node_record.http.is_some());
        assert_eq!(node_record.p2p_flow_endpoints.len(), 1);

        // Check that other fields are present
        let node_signing_pubkey_record = get_node_signing_key(&registry, node_id).await;
        assert_eq!(
            node_signing_pubkey_record,
            node_pks.node_signing_pk.unwrap()
        );

        let committee_signing_pubkey_record = get_committee_signing_key(&registry, node_id).await;
        assert_eq!(
            committee_signing_pubkey_record,
            node_pks.committee_signing_pk.unwrap()
        );

        let ni_dkg_dealing_encryption_pubkey_record = get_dkg_dealing_key(&registry, node_id).await;
        assert_eq!(
            ni_dkg_dealing_encryption_pubkey_record,
            node_pks.dkg_dealing_encryption_pk.unwrap()
        );

        let transport_tls_certificate_record =
            get_transport_tls_certificate(&registry, node_id).await;
        assert_eq!(
            transport_tls_certificate_record,
            node_pks.tls_certificate.unwrap()
        );

        // Check that node allowance has decreased
        let node_operator_record =
            get_node_operator_record(&registry, *TEST_NEURON_1_OWNER_PRINCIPAL).await;
        assert_eq!(node_operator_record.node_allowance, 99);

        Ok(())
    });
}

#[test]
fn node_is_not_created_on_wrong_principal() {
    local_test_on_nns_subnet(|runtime| async move {
        // First prepare the registry with a Node Operator record and make it callable
        // by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(init_mutation_with_node_allowance(100))
                .build(),
        )
        .await;

        let (payload, _node_pks, node_id) = prepare_add_node_payload();

        // Then, ensure there is no value for the node
        let node_record = get_node_record(&registry, node_id).await;
        assert_eq!(node_record, NodeRecord::default());

        // Issue a request with an unauthorized sender, which should fail.
        let response: Result<NodeId, String> = registry
            .update_from_sender(
                "add_node",
                candid,
                (payload,),
                &Sender::from_keypair(&TEST_USER1_KEYPAIR),
            )
            .await;
        assert!(response.is_err());

        // The record should still not be there
        let node_record = get_node_record(&registry, node_id).await;
        assert_eq!(node_record, NodeRecord::default());

        Ok(())
    });
}

#[test]
fn node_is_not_created_when_above_capacity() {
    local_test_on_nns_subnet(|runtime| async move {
        // First prepare the registry with a DC record and make it callable by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(init_mutation_with_node_allowance(1))
                .build(),
        )
        .await;

        let (payload, _node_pks, node_id) = prepare_add_node_payload();

        // Then, ensure there is no value for the node
        let node_record = get_node_record(&registry, node_id).await;
        assert_eq!(node_record, NodeRecord::default());

        // This should succeed
        let response: Result<NodeId, String> = registry
            .update_from_sender(
                "add_node",
                candid,
                (payload,),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_ok());

        // Try to add another node
        let (payload, _node_pks, node_id) = prepare_add_node_payload();

        // Ensure there is no value for this new node
        let node_record = get_node_record(&registry, node_id).await;
        assert_eq!(node_record, NodeRecord::default());

        // This should now be rejected
        let response: Result<NodeId, String> = registry
            .update_from_sender(
                "add_node",
                candid,
                (payload,),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_err());

        // The record should not be there
        let node_record = get_node_record(&registry, node_id).await;
        assert_eq!(node_record, NodeRecord::default());

        Ok(())
    });
}

fn init_mutation_with_node_allowance(node_allowance: u64) -> RegistryAtomicMutateRequest {
    let node_operator_record = NodeOperatorRecord {
        node_operator_principal_id: TEST_NEURON_1_OWNER_PRINCIPAL.to_vec(),
        node_allowance,
        // This doesn't go through Governance validation
        node_provider_principal_id: vec![],
        dc_id: "".into(),
        rewardable_nodes: BTreeMap::new(),
        ipv6: None,
    };
    RegistryAtomicMutateRequest {
        mutations: vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Insert as i32,
            key: make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL)
                .as_bytes()
                .to_vec(),
            value: encode_or_panic(&node_operator_record),
        }],
        preconditions: vec![],
    }
}
