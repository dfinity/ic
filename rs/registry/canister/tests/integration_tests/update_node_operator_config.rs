use candid::Encode;
use dfn_candid::candid_one;

use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::pb::v1::{
    registry_mutation, RegistryAtomicMutateRequest, RegistryMutation,
};
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_update_node_operator_config::UpdateNodeOperatorConfigPayload,
};

use assert_matches::assert_matches;
use maplit::btreemap;

#[test]
fn test_non_governance_users_cannot_update_node_operator_config() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the proposals
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let node_operator_key = make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL);
        let node_operator_record = NodeOperatorRecord {
            node_operator_principal_id: (*TEST_NEURON_1_OWNER_PRINCIPAL).to_vec(),
            node_allowance: 5,
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

        let payload = UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            node_allowance: Some(10),
            dc_id: None,
            rewardable_nodes: btreemap! {},
            node_provider_id: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
        };

        // The anonymous end-user tries to update a node operator, bypassing
        // governance. This should be rejected.
        let response: Result<(), String> = registry
            .update_("update_node_operator_config", candid_one, payload.clone())
            .await;

        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_node_operator_config"));

        // The attacker canister tries to update the node operator, pretending to be the
        // governance canister. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "update_node_operator_config",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // .. And there should therefore be no change to the node operator record
        assert_eq!(
            get_value::<NodeOperatorRecord>(&registry, node_operator_key.as_bytes()).await,
            node_operator_record
        );

        Ok(())
    });
}

#[test]
fn test_accepted_proposal_mutates_the_registry() {
    local_test_on_nns_subnet(|runtime| async move {
        let node_operator_key = make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL);
        let node_operator_record = NodeOperatorRecord {
            node_operator_principal_id: (*TEST_NEURON_1_OWNER_PRINCIPAL).to_vec(),
            node_allowance: 5,
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

        // Install the universal canister in place of the governance canister
        let governance = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can
        // impersonate it
        assert_eq!(
            governance.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let rewardable_nodes = btreemap! { "default".to_string() => 10 };

        // Try to set node_provider_id == node_operator_id...
        let mut payload = UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            node_allowance: Some(10),
            dc_id: Some("AN1".into()),
            rewardable_nodes: rewardable_nodes.clone(),
            node_provider_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
        };

        // ...causing a panic
        assert!(
            !forward_call_via_universal_canister(
                &governance,
                &registry,
                "update_node_operator_config",
                Encode!(&payload).unwrap()
            )
            .await
        );

        payload = UpdateNodeOperatorConfigPayload {
            node_operator_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            node_allowance: Some(10),
            dc_id: Some("AN1".into()),
            rewardable_nodes: rewardable_nodes.clone(),
            node_provider_id: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
        };

        assert!(
            forward_call_via_universal_canister(
                &governance,
                &registry,
                "update_node_operator_config",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // Now let's check directly in the registry that the mutation actually happened
        // The node operator record should be associated with that ID.
        assert_eq!(
            get_value::<NodeOperatorRecord>(&registry, node_operator_key.as_bytes()).await,
            NodeOperatorRecord {
                node_operator_principal_id: (*TEST_NEURON_1_OWNER_PRINCIPAL).to_vec(),
                node_allowance: 10,
                dc_id: "AN1".into(),
                rewardable_nodes,
                node_provider_principal_id: (*TEST_NEURON_2_OWNER_PRINCIPAL).to_vec(),
            },
        );

        Ok(())
    });
}
