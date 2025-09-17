use ic_base_types::PrincipalId;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::swap_node_in_subnet_directly;
use pocket_ic::PocketIcBuilder;
use registry_canister::mutations::do_swap_node_in_subnet_directly::{
    SwapError, SwapNodeInSubnetDirectlyPayload,
};

use crate::common::test_helpers::install_registry_canister;
mod common;

// This test ensures that we are not enabling this feature on any network until it
// is fully implemented.
//
// TODO(DRE-551): adapt the logic of the test to not fail if the feature is enabled.
#[tokio::test]
async fn ensure_feature_is_turned_off() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    install_registry_canister(&pocket_ic).await;

    let response = swap_node_in_subnet_directly(
        &pocket_ic,
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(PrincipalId::new_node_test_id(1)),
            old_node_id: Some(PrincipalId::new_node_test_id(2)),
        },
        PrincipalId::new_user_test_id(1),
    )
    .await;

    assert!(response.is_err_and(|err| {
        err.reject_message
            .contains(&format!("{}", SwapError::FeatureDisabled))
    }))
}
