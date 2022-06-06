use canister_test::Canister;
use dfn_candid::candid;
use ic_base_types::NodeId;
use ic_canister_client::Sender;
use ic_crypto::utils::generate_idkg_dealing_encryption_keys;
use ic_nervous_system_common_test_keys::{
    TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER2_KEYPAIR, TEST_USER2_PRINCIPAL,
};
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::registry::get_value;
use ic_nns_test_utils::{
    itest_helpers::{local_test_on_nns_subnet, set_up_registry_canister},
    registry::{
        get_value_or_panic, invariant_compliant_mutation_as_atomic_req, prepare_add_node_payload,
    },
};
use ic_protobuf::registry::{crypto::v1::PublicKey, node::v1::NodeRecord};
use ic_registry_keys::{make_crypto_node_key, make_node_record_key};
use ic_registry_transport::pb::v1::{
    registry_mutation, RegistryAtomicMutateRequest, RegistryMutation,
};
use ic_test_utilities::crypto::temp_dir::temp_dir;
use ic_types::crypto::KeyPurpose;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_update_node_directly::UpdateNodeDirectlyPayload,
    mutations::node_management::do_add_node::{
        connection_endpoint_from_string, flow_endpoint_from_string, AddNodePayload,
    },
};

#[test]
fn node_is_updated_on_receiving_the_request() {
    local_test_on_nns_subnet(|runtime| async move {
        let (add_node_payload, _, _) = prepare_add_node_payload();
        let node_id = NodeId::from(*TEST_USER2_PRINCIPAL);

        // Prepare the registry with a Node record and make it callable by anyone
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(init_mutation_for_node_with_id(
                    node_id,
                    &add_node_payload,
                ))
                .build(),
        )
        .await;

        let valid_sender = Sender::from_keypair(&TEST_USER2_KEYPAIR);
        let invalid_sender = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        // Generate a new key
        let temp_dir = temp_dir();
        let good_idkg_dealing_encryption_pk =
            generate_idkg_dealing_encryption_keys(temp_dir.path());
        let mut bad_idkg_dealing_encryption_pk = good_idkg_dealing_encryption_pk.clone();
        bad_idkg_dealing_encryption_pk.key_value = b"invalid key".to_vec();

        let bad_payload = UpdateNodeDirectlyPayload {
            idkg_dealing_encryption_pk: Some(encode_or_panic(&bad_idkg_dealing_encryption_pk)),
        };

        let good_payload = UpdateNodeDirectlyPayload {
            idkg_dealing_encryption_pk: Some(encode_or_panic(&good_idkg_dealing_encryption_pk)),
        };

        let empty_payload = UpdateNodeDirectlyPayload {
            idkg_dealing_encryption_pk: Some(vec![]),
        };

        // Issue a request with an unauthorized sender, which should fail.
        let response: Result<(), String> = registry
            .update_from_sender(
                "update_node_directly",
                candid,
                (good_payload.clone(),),
                &invalid_sender,
            )
            .await;
        assert!(matches!(response, Err(message) if message.contains("not found in the registry")));
        assert_no_idkg_mega_encryption_entry(&registry, node_id).await;
        // Issue a request with the correct sender, but a bad key, should fail
        let response: Result<(), String> = registry
            .update_from_sender(
                "update_node_directly",
                candid,
                (bad_payload.clone(),),
                &valid_sender,
            )
            .await;
        assert!(
            matches!(response, Err(message) if message.contains("invalid I-DKG dealing encryption key: verification failed: InvalidPublicKey"))
        );
        assert_no_idkg_mega_encryption_entry(&registry, node_id).await;

        // Issue a request with the correct sender, but a empty key, should fail
        let response: Result<(), String> = registry
            .update_from_sender(
                "update_node_directly",
                candid,
                (empty_payload,),
                &valid_sender,
            )
            .await;
        assert!(
            matches!(response, Err(message) if message.contains("idkg_dealing_encryption_pk is empty"))
        );
        assert_no_idkg_mega_encryption_entry(&registry, node_id).await;

        // Issue a request with the correct sender, and a good key, should succeed
        let response: Result<(), String> = registry
            .update_from_sender(
                "update_node_directly",
                candid,
                (good_payload.clone(),),
                &valid_sender,
            )
            .await;
        assert!(response.is_ok());

        // The pk record has been updated
        let pk_record = get_value_or_panic::<PublicKey>(
            &registry,
            make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption).as_bytes(),
        )
        .await;
        assert_eq!(pk_record, good_idkg_dealing_encryption_pk);

        // Attempt to update the same pk record (should fail as pk records can only be set once)
        let response: Result<(), String> = registry
            .update_from_sender(
                "update_node_directly",
                candid,
                (good_payload,),
                &valid_sender,
            )
            .await;
        assert!(
            matches!(response, Err(message) if message.contains("I-DKG key was already set for this node"))
        );

        Ok(())
    });
}

async fn assert_no_idkg_mega_encryption_entry(registry: &Canister<'_>, node_id: NodeId) {
    // The pk record has not been updated
    let pk_record = get_value::<PublicKey>(
        registry,
        make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption).as_bytes(),
    )
    .await;
    assert!(pk_record.is_none());
}

fn init_mutation_for_node_with_id(
    node_id: NodeId,
    payload: &AddNodePayload,
) -> RegistryAtomicMutateRequest {
    let node_record = NodeRecord {
        xnet: Some(connection_endpoint_from_string(&payload.xnet_endpoint)),
        http: Some(connection_endpoint_from_string(&payload.http_endpoint)),
        p2p_flow_endpoints: payload
            .p2p_flow_endpoints
            .iter()
            .map(|x| flow_endpoint_from_string(x))
            .collect(),
        node_operator_id: TEST_USER1_PRINCIPAL.clone().to_vec(),
        prometheus_metrics_http: Some(connection_endpoint_from_string(
            &payload.prometheus_metrics_endpoint,
        )),
        public_api: vec![],
        private_api: vec![],
        prometheus_metrics: vec![],
        xnet_api: vec![],
    };
    RegistryAtomicMutateRequest {
        mutations: vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Insert as i32,
            key: make_node_record_key(node_id).as_bytes().to_vec(),
            value: encode_or_panic(&node_record),
        }],
        preconditions: vec![],
    }
}
