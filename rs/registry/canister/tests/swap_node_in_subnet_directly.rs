use dfn_candid::candid;
use ic_nns_test_utils::itest_helpers::{local_test_on_nns_subnet, set_up_registry_canister};
use ic_types::PrincipalId;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_swap_node_in_subnet_directly::{SwapError, SwapNodeInSubnetDirectlyPayload},
};

// This test ensures that we are not enabling this feature on any network until it
// is fully implemented.
//
// TODO(DRE-551): adapt the logic of the test to not fail if the feature is enabled.
#[test]
fn ensure_feature_is_turned_off() {
    local_test_on_nns_subnet(|runtime| async move {
        let registry =
            set_up_registry_canister(&runtime, RegistryCanisterInitPayloadBuilder::new().build())
                .await;

        let payload = SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(PrincipalId::new_node_test_id(1)),
            old_node_id: Some(PrincipalId::new_node_test_id(2)),
        };

        let response: Result<(), String> = registry
            .update_("swap_node_in_subnet_directly", candid, (payload.clone(),))
            .await;

        assert!(response.is_err_and(|err| err.contains(&format!("{}", SwapError::FeatureDisabled))));

        Ok(())
    });
}
