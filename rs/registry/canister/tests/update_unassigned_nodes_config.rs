use candid::Encode;
use dfn_candid::candid;

use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value, get_value_or_panic, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::unassigned_nodes_config::v1::UnassignedNodesConfigRecord;
use ic_registry_keys::make_unassigned_nodes_config_record_key;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_update_unassigned_nodes_config::UpdateUnassignedNodesConfigPayload,
};

use assert_matches::assert_matches;

#[test]
fn test_the_anonymous_user_cannot_update_unassigned_nodes_config() {
    local_test_on_nns_subnet(|runtime| async move {
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;

        let payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: Some(vec!["some_key".to_string()]),
            replica_version: Some("some_unblessed_version".to_string()),
        };

        // The anonymous end-user tries to update the config, bypassing the proposals
        // This should be rejected.
        let response: Result<(), String> = registry
            .update_("update_unassigned_nodes_config", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: \
                update_unassigned_nodes_config"));
        assert!(get_value::<UnassignedNodesConfigRecord>(
            &registry,
            make_unassigned_nodes_config_record_key().as_bytes()
        )
        .await
        .is_none(),);

        Ok(())
    });
}

#[test]
fn test_updating_unassigned_nodes_config_does_not_break_invariants() {
    local_test_on_nns_subnet(|runtime| async move {
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister.
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can
        // impersonate it.
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let mut payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: None,
            replica_version: Some("some_unblessed_version".to_string()),
        };

        assert!(
            !forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "update_unassigned_nodes_config",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // New payload with already-blessed version
        payload = UpdateUnassignedNodesConfigPayload {
            ssh_readonly_access: None,
            replica_version: Some("version_42".to_string()),
        };

        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "update_unassigned_nodes_config",
                Encode!(&payload).unwrap()
            )
            .await
        );

        assert_eq!(
            get_value_or_panic::<UnassignedNodesConfigRecord>(
                &registry,
                make_unassigned_nodes_config_record_key().as_bytes()
            )
            .await,
            UnassignedNodesConfigRecord {
                ssh_readonly_access: vec![],
                replica_version: "version_42".to_string(),
            }
        );

        Ok(())
    });
}
