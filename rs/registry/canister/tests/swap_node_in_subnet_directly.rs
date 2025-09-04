use ic_base_types::PrincipalId;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::swap_node_in_subnet_directly;
use ic_nns_test_utils::registry::invariant_compliant_mutation;
use pocket_ic::PocketIcBuilder;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_swap_node_in_subnet_directly::{SwapError, SwapNodeInSubnetDirectlyPayload},
};

use crate::common::test_helpers::{
    install_registry_canister, install_registry_canister_with_payload_builder,
};
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

    assert!(response.is_err_and(|err| err
        .reject_message
        .contains(&format!("{}", SwapError::FeatureDisabled))))
}

#[tokio::test]
async fn caller_not_whitelisted() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let caller = PrincipalId::new_user_test_id(1);

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.enable_swapping_feature_globally();

    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let response = swap_node_in_subnet_directly(
        &pocket_ic,
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(PrincipalId::new_node_test_id(1)),
            old_node_id: Some(PrincipalId::new_node_test_id(2)),
        },
        PrincipalId::new_user_test_id(1),
    )
    .await;

    assert!(
        response.is_err_and(|err| err.reject_message.contains(&format!(
            "{}",
            SwapError::FeatureDisabledForCaller { caller }
        )))
    )
}

#[tokio::test]
async fn caller_whitelisted() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let caller = PrincipalId::new_user_test_id(1);

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    let initial_mutations = invariant_compliant_mutation(1);
    builder.push_init_mutate_request(ic_registry_transport::pb::v1::RegistryAtomicMutateRequest {
        mutations: initial_mutations,
        preconditions: vec![],
    });
    builder.enable_swapping_feature_globally();
    builder.whitelist_swapping_feature_caller(caller);

    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let response = swap_node_in_subnet_directly(
        &pocket_ic,
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(PrincipalId::new_node_test_id(1)),
            old_node_id: Some(PrincipalId::new_node_test_id(2)),
        },
        PrincipalId::new_user_test_id(1),
    )
    .await;

    assert!(
        response.is_err_and(|err| err.reject_message.contains(&format!(
            "{}",
            SwapError::SubnetNotFoundForNode {
                old_node_id: PrincipalId::new_node_test_id(2)
            }
        )))
    )
}
