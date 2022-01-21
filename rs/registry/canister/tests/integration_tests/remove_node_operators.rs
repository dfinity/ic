use assert_matches::assert_matches;
use candid::Encode;
use dfn_candid::candid_one;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::invariant_compliant_mutation_as_atomic_req,
};
use ic_protobuf::registry::node_operator::v1::RemoveNodeOperatorsPayload;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;

#[test]
fn test_the_anonymous_user_cannot_remove_node_operators() {
    local_test_on_nns_subnet(|runtime| async move {
        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;

        let payload = RemoveNodeOperatorsPayload {
            node_operators_to_remove: vec![],
        };

        // The anonymous end-user tries to remove node operators, bypassing
        // the Governance canister. This should be rejected.
        let response: Result<(), String> = registry
            .update_("remove_node_operators", candid_one, payload.clone())
            .await;

        assert_matches!(
            response,
            Err(s) if s.contains("is not authorized to call this method: remove_node_operators")
        );

        // Go through an upgrade cycle, and verify that it still works the same
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_("remove_node_operators", candid_one, payload.clone())
            .await;

        assert_matches!(
            response,
            Err(s) if s.contains("is not authorized to call this method: remove_node_operators")
        );

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_remove_node_operators() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the Governance
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;

        let payload = RemoveNodeOperatorsPayload {
            node_operators_to_remove: vec![],
        };

        // The attacker canister tries to remove node operators, pretending
        // to be the Governance canister. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "remove_node_operators",
                Encode!(&payload).unwrap(),
            )
            .await
        );

        Ok(())
    });
}
