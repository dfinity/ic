use dfn_candid::candid;
use ic_base_types::PrincipalId;
use ic_canister_client_sender::Sender;
use ic_nns_test_utils::{
    itest_helpers::{set_up_registry_canister, state_machine_test_on_nns_subnet},
    registry::{get_value_or_panic, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::pb::v1::{
    RegistryAtomicMutateRequest, RegistryMutation, registry_mutation,
};
use prost::Message;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_update_node_operator_config_directly::UpdateNodeOperatorConfigDirectlyPayload,
};

#[test]
fn node_provider_is_updated_on_receiving_the_request() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        // The node operator under test, and its node provider.
        let original_node_operator_id = PrincipalId::new_user_test_id(1_000);
        let original_node_provider_id = PrincipalId::new_user_test_id(10_000);
        let original_node_operator_key = make_node_operator_record_key(original_node_operator_id);
        let original_node_operator_record = NodeOperatorRecord {
            node_operator_principal_id: original_node_operator_id.to_vec(),
            node_provider_principal_id: original_node_provider_id.to_vec(),
            ..Default::default()
        };

        // Establish a second node provider. (He employs some other node operator.) This is what
        // makes the new node provider known to the registry.
        let new_node_operator_id = PrincipalId::new_user_test_id(1_001);
        let new_node_provider_id = PrincipalId::new_user_test_id(10_001);
        let new_node_operator_key = make_node_operator_record_key(new_node_operator_id);
        let new_node_operator_record = NodeOperatorRecord {
            node_operator_principal_id: new_node_operator_id.to_vec(),
            node_provider_principal_id: new_node_provider_id.to_vec(),
            ..Default::default()
        };

        // No node operator record names this principal as its node provider.
        let unknown_node_provider_id = PrincipalId::new_user_test_id(10_002);

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![
                        RegistryMutation {
                            mutation_type: registry_mutation::Type::Insert as i32,
                            key: original_node_operator_key.as_bytes().to_vec(),
                            value: original_node_operator_record.encode_to_vec(),
                        },
                        RegistryMutation {
                            mutation_type: registry_mutation::Type::Insert as i32,
                            key: new_node_operator_key.as_bytes().to_vec(),
                            value: new_node_operator_record.encode_to_vec(),
                        },
                    ],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        let payload = UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(original_node_operator_id),
            node_provider_id: Some(new_node_provider_id),
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

        // Call from a principal other than the current node provider (here, the node operator
        // itself) fails
        let response: Result<(), String> = registry
            .update_from_sender(
                "update_node_operator_config_directly",
                candid,
                (payload.clone(),),
                &Sender::PrincipalId(original_node_operator_id),
            )
            .await;
        assert!(response.is_err());

        // Call from the correct caller, but to a principal that is not the node provider of any
        // node operator record, fails
        let payload_with_unknown_node_provider = UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(original_node_operator_id),
            node_provider_id: Some(unknown_node_provider_id),
        };
        let response: Result<(), String> = registry
            .update_from_sender(
                "update_node_operator_config_directly",
                candid,
                (payload_with_unknown_node_provider,),
                &Sender::PrincipalId(original_node_provider_id),
            )
            .await;
        assert!(response.is_err());

        // Ensure the node operator's NP is unchanged
        let node_operator_record = get_value_or_panic::<NodeOperatorRecord>(
            &registry,
            original_node_operator_key.as_bytes(),
        )
        .await;
        assert_eq!(
            node_operator_record.node_provider_principal_id,
            original_node_provider_id.to_vec()
        );

        // Call from correct caller to a known node provider succeeds
        let response: Result<(), String> = registry
            .update_from_sender(
                "update_node_operator_config_directly",
                candid,
                (payload,),
                &Sender::PrincipalId(original_node_provider_id),
            )
            .await;
        assert!(response.is_ok());

        // Ensure the node operator's NP is set correctly
        let node_operator_record = get_value_or_panic::<NodeOperatorRecord>(
            &registry,
            original_node_operator_key.as_bytes(),
        )
        .await;
        assert_eq!(
            node_operator_record.node_provider_principal_id,
            new_node_provider_id.to_vec()
        );

        Ok(())
    })
}
