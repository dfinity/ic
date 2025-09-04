use ic_base_types::PrincipalId;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::swap_node_in_subnet_directly;
use pocket_ic::PocketIcBuilder;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_swap_node_in_subnet_directly::{SwapError, SwapNodeInSubnetDirectlyPayload},
};
use test_registry_builder::registry_builder::CompliantRegistryBuilder;

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

    let compliant_registry = CompliantRegistryBuilder::default()
        .with_operator("operator", "dc", "provider")
        .with_node("operator", "node-1", Some("subnet"))
        .with_node("operator", "node-2", None)
        .build();

    let operator = compliant_registry.operator_id("operator");
    let subnet = compliant_registry.subnet_id("subnet");

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(ic_registry_transport::pb::v1::RegistryAtomicMutateRequest {
        mutations: compliant_registry.mutations(),
        preconditions: vec![],
    });
    builder.enable_swapping_feature_globally();
    builder.enable_swapping_feature_for_subnet(subnet);

    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let response = swap_node_in_subnet_directly(
        &pocket_ic,
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(compliant_registry.node_id("node-2").get()),
            old_node_id: Some(compliant_registry.node_id("node-1").get()),
        },
        operator,
    )
    .await;

    let expected_err = SwapError::FeatureDisabledForCaller { caller: operator };
    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    )
}

#[tokio::test]
async fn subnet_not_whitelisted() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let compliant_registry = CompliantRegistryBuilder::default()
        .with_operator("operator", "dc", "provider")
        .with_node("operator", "node-1", Some("subnet"))
        .with_node("operator", "node-2", None)
        .build();

    let operator = compliant_registry.operator_id("operator");
    let subnet = compliant_registry.subnet_id("subnet");

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(ic_registry_transport::pb::v1::RegistryAtomicMutateRequest {
        mutations: compliant_registry.mutations(),
        preconditions: vec![],
    });
    builder.enable_swapping_feature_globally();
    builder.whitelist_swapping_feature_caller(operator);

    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let response = swap_node_in_subnet_directly(
        &pocket_ic,
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(compliant_registry.node_id("node-2").get()),
            old_node_id: Some(compliant_registry.node_id("node-1").get()),
        },
        operator,
    )
    .await;

    let expected_err = SwapError::FeatureDisabledOnSubnet { subnet_id: subnet };
    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    )
}

#[tokio::test]
async fn e2e() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let compliant_registry = CompliantRegistryBuilder::default()
        .with_operator("operator", "dc", "provider")
        .with_node("operator", "node-1", Some("subnet"))
        .with_node("operator", "node-2", None)
        .build();

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(ic_registry_transport::pb::v1::RegistryAtomicMutateRequest {
        mutations: compliant_registry.mutations(),
        preconditions: vec![],
    });
    builder.enable_swapping_feature_globally();

    let caller = compliant_registry.operator_id("operator");
    let subnet = compliant_registry.subnet_id("subnet");

    builder.whitelist_swapping_feature_caller(caller);
    builder.enable_swapping_feature_for_subnet(subnet);
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let response = swap_node_in_subnet_directly(
        &pocket_ic,
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(compliant_registry.node_id("node-2").get()),
            old_node_id: Some(compliant_registry.node_id("node-1").get()),
        },
        caller,
    )
    .await;

    assert!(
        response.is_ok(),
        "Expected OK response but got {response:?}"
    );
}
