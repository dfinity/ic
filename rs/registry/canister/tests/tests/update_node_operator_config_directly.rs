use dfn_candid::candid;
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_KEYPAIR,
    TEST_NEURON_2_OWNER_PRINCIPAL, TEST_NEURON_3_OWNER_PRINCIPAL,
};
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::{
    itest_helpers::{local_test_on_nns_subnet, set_up_registry_canister},
    registry::{get_value_or_panic, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::pb::v1::{
    registry_mutation, RegistryAtomicMutateRequest, RegistryMutation,
};
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_update_node_operator_config_directly::UpdateNodeOperatorConfigDirectlyPayload,
};

#[test]
fn node_provider_is_updated_on_receiving_the_request() {
    local_test_on_nns_subnet(|runtime| async move {
        let node_operator_key = make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL);
        let node_operator_record = NodeOperatorRecord {
            node_operator_principal_id: (*TEST_NEURON_1_OWNER_PRINCIPAL).to_vec(),
            node_provider_principal_id: (*TEST_NEURON_2_OWNER_PRINCIPAL).to_vec(),
            ..Default::default()
        };

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![RegistryMutation {
                        mutation_type: registry_mutation::Type::Insert as i32,
                        key: node_operator_key.as_bytes().to_vec(),
                        value: encode_or_panic(&node_operator_record),
                    }],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        let payload = UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            node_provider_id: Some(*TEST_NEURON_3_OWNER_PRINCIPAL),
        };

        // Anonymous call fails
        let response: Result<(), String> = registry
            .update_(
                "update_node_operator_config_directly",
                candid,
                (payload.clone(),),
            )
            .await;
        assert!(response.is_err());

        // Anonymous call fails
        let response: Result<(), String> = registry
            .update_from_sender(
                "update_node_operator_config_directly",
                candid,
                (payload.clone(),),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_err());

        // Call from correct caller succeeds
        let response: Result<(), String> = registry
            .update_from_sender(
                "update_node_operator_config_directly",
                candid,
                (payload,),
                &Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            )
            .await;
        assert!(response.is_ok());

        // Ensure the node operator's NP is set correctly
        let node_operator_record = get_value_or_panic::<NodeOperatorRecord>(
            &registry,
            make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL).as_bytes(),
        )
        .await;
        assert_eq!(
            node_operator_record.node_provider_principal_id,
            TEST_NEURON_3_OWNER_PRINCIPAL.to_vec()
        );

        Ok(())
    })
}
