use dfn_candid::candid;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_USER1_KEYPAIR,
};
use ic_nns_test_utils::{
    itest_helpers::{local_test_on_nns_subnet, set_up_registry_canister},
    registry::{
        get_committee_signing_key, get_dkg_dealing_key, get_node_operator_record, get_node_record,
        get_node_signing_key, get_transport_tls_certificate,
        invariant_compliant_mutation_as_atomic_req, prepare_add_node_payload,
    },
};
use ic_protobuf::registry::{node::v1::NodeRewardType, node_operator::v1::NodeOperatorRecord};
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::pb::v1::{
    RegistryAtomicMutateRequest, RegistryMutation, registry_mutation,
};
use ic_types::NodeId;
use maplit::btreemap;
use prost::Message;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use std::collections::BTreeMap;

#[test]
fn node_is_created_on_receiving_the_request() {
    local_test_on_nns_subnet(|runtime| async move {
        // First prepare the registry with a Node Operator record and make it callable
        // by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(init_mutation_with_max_rewardable_nodes(
                    btreemap! { "type3".to_string() => 100 },
                ))
                .build(),
        )
        .await;

        let (payload, node_pks) = prepare_add_node_payload(1, NodeRewardType::Type3);
        let node_id = node_pks.node_id();

        // Then, ensure there is no value for the node
        let node_record = get_node_record(&registry, node_id).await;
        assert!(node_record.is_none());

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
        assert!(node_record.is_some());
        let node_record = node_record.unwrap();
        assert_eq!(
            node_record.node_reward_type,
            Some(NodeRewardType::Type3 as i32)
        );

        // Check that other fields are present
        let node_signing_pubkey_record = get_node_signing_key(&registry, node_id).await.unwrap();
        assert_eq!(&node_signing_pubkey_record, node_pks.node_signing_key());

        let committee_signing_pubkey_record =
            get_committee_signing_key(&registry, node_id).await.unwrap();
        assert_eq!(
            &committee_signing_pubkey_record,
            node_pks.committee_signing_key()
        );

        let ni_dkg_dealing_encryption_pubkey_record =
            get_dkg_dealing_key(&registry, node_id).await.unwrap();
        assert_eq!(
            &ni_dkg_dealing_encryption_pubkey_record,
            node_pks.dkg_dealing_encryption_key()
        );

        let transport_tls_certificate_record = get_transport_tls_certificate(&registry, node_id)
            .await
            .unwrap();
        assert_eq!(
            &transport_tls_certificate_record,
            node_pks.tls_certificate()
        );

        // Check that node allowance has decreased
        let node_operator_record =
            get_node_operator_record(&registry, *TEST_NEURON_1_OWNER_PRINCIPAL)
                .await
                .unwrap();
        assert_eq!(
            node_operator_record.max_rewardable_nodes,
            btreemap! { "type3".to_string() => 100 }
        );

        Ok(())
    });
}

#[test]
fn node_is_not_created_with_invalid_type() {
    local_test_on_nns_subnet(|runtime| async move {
        // First prepare the registry with a Node Operator record and make it callable
        // by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(init_mutation_with_max_rewardable_nodes(
                    btreemap! { "type1".to_string() => 100 },
                ))
                .build(),
        )
        .await;

        let (mut payload, node_pks) = prepare_add_node_payload(1, NodeRewardType::Type1);
        payload.node_reward_type = Some("type0.11".to_string());
        let node_id = node_pks.node_id();

        // Then, ensure there is no value for the node
        let node_record = get_node_record(&registry, node_id).await;
        assert!(node_record.is_none());

        let response: Result<NodeId, String> = registry
            .update_from_sender(
                "add_node",
                candid,
                (payload,),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_err());
        assert!(
            response
                .unwrap_err()
                .to_string()
                .contains("Invalid node type")
        );

        // The record should still not be there
        let node_record = get_node_record(&registry, node_id).await;
        assert!(node_record.is_none());

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
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(init_mutation_with_max_rewardable_nodes(
                    btreemap! { "type1".to_string() => 100 },
                ))
                .build(),
        )
        .await;

        let (payload, node_pks) = prepare_add_node_payload(1, NodeRewardType::Type1);
        let node_id = node_pks.node_id();

        // Then, ensure there is no value for the node
        let node_record = get_node_record(&registry, node_id).await;
        assert!(node_record.is_none());

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
        assert!(node_record.is_none());

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
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(init_mutation_with_max_rewardable_nodes(
                    btreemap! { "type1".to_string() => 1 },
                ))
                .build(),
        )
        .await;

        let (payload, node_pks) = prepare_add_node_payload(1, NodeRewardType::Type1);
        let node_id = node_pks.node_id();

        // Then, ensure there is no value for the node
        let node_record = get_node_record(&registry, node_id).await;
        assert!(node_record.is_none());

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
        let (payload, node_pks) = prepare_add_node_payload(2, NodeRewardType::Type1);
        let node_id = node_pks.node_id();

        // Ensure there is no value for this new node
        let node_record = get_node_record(&registry, node_id).await;
        assert!(node_record.is_none());

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
        assert!(node_record.is_none());

        Ok(())
    });
}

#[test]
fn duplicated_nodes_are_removed_on_join() {
    local_test_on_nns_subnet(|runtime| async move {
        // First prepare the registry with a DC record.
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(init_mutation_with_max_rewardable_nodes(
                    btreemap! { "type1".to_string() => 10 },
                ))
                .build(),
        )
        .await;

        // Create a new node to join.
        let (payload, node_pks) = prepare_add_node_payload(1, NodeRewardType::Type1);
        let first_node_id = node_pks.node_id();

        // Ensure this node does not already exist.
        let node_record = get_node_record(&registry, first_node_id).await;
        assert!(node_record.is_none());

        // This node should join successfully.
        let response: Result<NodeId, String> = registry
            .update_from_sender(
                "add_node",
                candid,
                (payload,),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_ok());

        // Then, try to add another node.
        // Use the same ID so we can "duplicate" this node.
        let (payload, node_pks) = prepare_add_node_payload(1, NodeRewardType::Type1);
        let second_node_id = node_pks.node_id();

        // Ensure this node does not already exist.
        let node_record = get_node_record(&registry, second_node_id).await;
        assert!(node_record.is_none());

        // This node should join successfully.
        let response: Result<NodeId, String> = registry
            .update_from_sender(
                "add_node",
                candid,
                (payload,),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_ok());

        // The previous record should not be there.
        let node_record = get_node_record(&registry, first_node_id).await;
        assert!(node_record.is_none());

        // But the new record is.
        let node_record = get_node_record(&registry, second_node_id).await;
        assert!(node_record.is_some());

        Ok(())
    });
}

#[test]
fn join_with_duplicate_is_allowed_when_at_capacity() {
    local_test_on_nns_subnet(|runtime| async move {
        // First prepare the registry with a DC record.
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(init_mutation_with_max_rewardable_nodes(
                    btreemap! { "type1".to_string() => 1 },
                ))
                .build(),
        )
        .await;

        // Create a new node to join.
        let (payload, node_pks) = prepare_add_node_payload(1, NodeRewardType::Type1);
        let first_node_id = node_pks.node_id();

        // Ensure this node does not already exist.
        let node_record = get_node_record(&registry, first_node_id).await;
        assert!(node_record.is_none());

        // This node should join successfully.
        let response: Result<NodeId, String> = registry
            .update_from_sender(
                "add_node",
                candid,
                (payload,),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_ok());

        // Then, try to add another node.
        // Use the same ID so we can "duplicate" this node.
        let (payload, node_pks) = prepare_add_node_payload(1, NodeRewardType::Type1);
        let second_node_id = node_pks.node_id();

        // Ensure this node does not already exist.
        let node_record = get_node_record(&registry, second_node_id).await;
        assert!(node_record.is_none());

        // This node should join successfully.
        let response: Result<NodeId, String> = registry
            .update_from_sender(
                "add_node",
                candid,
                (payload,),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_ok());

        // The previous record should not be there.
        let node_record = get_node_record(&registry, first_node_id).await;
        assert!(node_record.is_none());

        // But the new record is.
        let node_record = get_node_record(&registry, second_node_id).await;
        assert!(node_record.is_some());

        Ok(())
    });
}

fn init_mutation_with_max_rewardable_nodes(
    max_rewardable_nodes: BTreeMap<String, u32>,
) -> RegistryAtomicMutateRequest {
    let node_operator_record = NodeOperatorRecord {
        node_operator_principal_id: TEST_NEURON_1_OWNER_PRINCIPAL.to_vec(),
        node_allowance: 0,
        // This doesn't go through Governance validation
        node_provider_principal_id: vec![],
        dc_id: "".into(),
        rewardable_nodes: BTreeMap::new(),
        ipv6: None,
        max_rewardable_nodes,
    };
    RegistryAtomicMutateRequest {
        mutations: vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Insert as i32,
            key: make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL)
                .as_bytes()
                .to_vec(),
            value: node_operator_record.encode_to_vec(),
        }],
        preconditions: vec![],
    }
}
