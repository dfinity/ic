use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::decode_registry_value;
use ic_nns_constants::{
    ENGINE_CONTROLLER_CANISTER_ID, GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID,
};
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, set_up_registry_canister, set_up_universal_canister,
    state_machine_test_on_nns_subnet,
};
use ic_nns_test_utils::registry::{
    INITIAL_MUTATION_ID, invariant_compliant_mutation_as_atomic_req,
};
use ic_protobuf::registry::subnet::v1::SubnetListRecord as SubnetListRecordPb;
use ic_registry_keys::make_subnet_list_record_key;
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use pocket_ic::PocketIcBuilder;
use pocket_ic::nonblocking::PocketIc;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder, mutations::do_delete_subnet::DeleteSubnetPayload,
};

mod common;

use common::test_helpers::{
    get_subnet_list_record, install_registry_canister_with_payload_builder,
    prepare_registry_with_application_subnet, prepare_registry_with_cloud_engine_subnet,
    prepare_registry_with_nodes,
};

/// Installs an invariant-compliant registry (which already contains a single,
/// non-CloudEngine subnet) and returns the running `PocketIc` together with the
/// principal of an existing subnet that can be used as a `delete_subnet` target.
async fn setup_with_existing_subnet() -> (PocketIc, Principal) {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0));
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let subnet_list_record =
        decode_registry_value::<SubnetListRecordPb>(&pocket_ic, make_subnet_list_record_key())
            .await;
    let subnet_id = subnet_list_record
        .subnets
        .first()
        .expect("expected the invariant-compliant registry to contain at least one subnet");
    let subnet_id = Principal::try_from(subnet_id.as_slice()).unwrap();

    (pocket_ic, subnet_id)
}

/// Installs an invariant-compliant registry augmented with the subnet described
/// by `subnet_mutate` (e.g. the output of a `prepare_registry_with_*_subnet`
/// helper) and returns the running `PocketIc`.
async fn setup_with_subnet(subnet_mutate: RegistryAtomicMutateRequest) -> PocketIc {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0));
    builder.push_init_mutate_request(subnet_mutate);
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    pocket_ic
}

/// Calls `delete_subnet` on the registry canister as `caller` and returns the
/// decoded result. Panics only if the call itself is rejected, which is never
/// expected for the authorized callers used in these tests.
async fn delete_subnet(
    pocket_ic: &PocketIc,
    caller: PrincipalId,
    subnet_id: Principal,
) -> Result<(), String> {
    let payload = DeleteSubnetPayload { subnet_id };
    let response = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            caller.0,
            "delete_subnet",
            Encode!(&payload).unwrap(),
        )
        .await
        .unwrap();
    Decode!(&response, Result<(), String>).unwrap()
}

/// Returns the current list of subnet IDs (as raw bytes) recorded in the registry.
async fn subnet_ids(pocket_ic: &PocketIc) -> Vec<Vec<u8>> {
    decode_registry_value::<SubnetListRecordPb>(pocket_ic, make_subnet_list_record_key())
        .await
        .subnets
}

#[tokio::test]
async fn test_the_anonymous_user_cannot_delete_a_subnet() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;

    let payload = DeleteSubnetPayload { subnet_id };

    // The anonymous end-user tries to delete a subnet via an ingress message,
    // bypassing governance. This should be rejected by the authorization check.
    let response = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            PrincipalId::new_anonymous().0,
            "delete_subnet",
            Encode!(&payload).unwrap(),
        )
        .await;

    assert!(
        response.as_ref().is_err_and(|err| err
            .reject_message
            .contains("is not authorized to call this method: delete_subnet")),
        "Expected an authorization rejection, but got {response:?}"
    );
}

#[tokio::test]
async fn test_an_unauthorized_principal_cannot_delete_a_subnet() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;

    // A principal that is neither governance nor the engine controller, calling
    // via an ingress message.
    let unauthorized_caller = PrincipalId::new_user_test_id(1);
    assert_ne!(unauthorized_caller, GOVERNANCE_CANISTER_ID.get());
    assert_ne!(unauthorized_caller, ENGINE_CONTROLLER_CANISTER_ID.get());

    let payload = DeleteSubnetPayload { subnet_id };

    let response = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            unauthorized_caller.0,
            "delete_subnet",
            Encode!(&payload).unwrap(),
        )
        .await;

    assert!(
        response.as_ref().is_err_and(|err| err
            .reject_message
            .contains("is not authorized to call this method: delete_subnet")),
        "Expected an authorization rejection, but got {response:?}"
    );
}

#[test]
fn test_a_canister_other_than_governance_or_engine_controller_cannot_delete_a_subnet() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        // An attacker canister tries to delete a subnet via an inter-canister
        // call. Going through a real canister (rather than an ingress message)
        // ensures the access control cannot be bypassed by, e.g., only guarding
        // ingress messages in `inspect_message`.
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but it has neither the governance nor the engine controller ID.
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::ENGINE_CONTROLLER_CANISTER_ID
        );

        let (init_mutate, _node_ids) = prepare_registry_with_nodes(5, INITIAL_MUTATION_ID);
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(
                    5 + INITIAL_MUTATION_ID,
                ))
                .push_init_mutate_request(init_mutate)
                .build(),
        )
        .await;

        let initial_subnet_list_record = get_subnet_list_record(&registry).await;
        let subnet_id = Principal::try_from(
            initial_subnet_list_record
                .subnets
                .first()
                .expect("expected at least one subnet")
                .as_slice(),
        )
        .unwrap();
        let payload = DeleteSubnetPayload { subnet_id };

        // The attacker canister tries to delete a subnet. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "delete_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // .. And the subnet list should be unchanged.
        let subnet_list_record = get_subnet_list_record(&registry).await;
        assert_eq!(subnet_list_record, initial_subnet_list_record);

        Ok(())
    });
}

#[tokio::test]
async fn test_governance_canister_can_delete_a_cloud_engine_subnet() {
    cloud_engine_subnet_can_be_deleted_by(GOVERNANCE_CANISTER_ID.get()).await;
}

#[tokio::test]
async fn test_engine_controller_can_delete_a_cloud_engine_subnet() {
    cloud_engine_subnet_can_be_deleted_by(ENGINE_CONTROLLER_CANISTER_ID.get()).await;
}

#[tokio::test]
async fn test_authorized_callers_cannot_delete_a_system_subnet() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;

    // The existing subnet is a system subnet (the NNS). System subnets may never
    // be deleted, so even authorized callers must fail: the call passes the
    // authorization check but is then rejected by the business logic. Deletion
    // fails, so the subnet is not consumed and both callers can be checked
    // against it.
    for caller in [
        GOVERNANCE_CANISTER_ID.get(),
        ENGINE_CONTROLLER_CANISTER_ID.get(),
    ] {
        let result = delete_subnet(&pocket_ic, caller, subnet_id).await;
        assert_eq!(
            result,
            Err("System subnets may not be deleted".to_string()),
            "caller {caller} should not be able to delete a system subnet"
        );
    }

    // The subnet should still be present.
    assert!(
        subnet_ids(&pocket_ic)
            .await
            .contains(&subnet_id.as_slice().to_vec()),
        "the system subnet should not have been deleted"
    );
}

/// Sets up a registry that contains a CloudEngine subnet (the only subnet type
/// that may be deleted) and verifies that `caller` is authorized to delete it
/// and that the subnet is actually removed from the registry.
async fn cloud_engine_subnet_can_be_deleted_by(caller: PrincipalId) {
    let (cloud_engine_mutate, cloud_engine_subnet_id) =
        prepare_registry_with_cloud_engine_subnet(4, INITIAL_MUTATION_ID);
    let pocket_ic = setup_with_subnet(cloud_engine_mutate).await;

    // Delete the CloudEngine subnet via the caller under test.
    let result = delete_subnet(&pocket_ic, caller, cloud_engine_subnet_id.get().0).await;
    assert_eq!(
        result,
        Ok(()),
        "authorized caller {caller} should be able to delete a cloud engine subnet"
    );

    // The subnet should no longer be in the subnet list.
    assert!(
        !subnet_ids(&pocket_ic)
            .await
            .contains(&cloud_engine_subnet_id.get().to_vec()),
        "the cloud engine subnet should have been removed from the subnet list"
    );
}

#[tokio::test]
async fn test_governance_can_delete_an_application_subnet() {
    let (application_mutate, application_subnet_id) =
        prepare_registry_with_application_subnet(4, INITIAL_MUTATION_ID);
    let pocket_ic = setup_with_subnet(application_mutate).await;

    // Governance may delete any non-System subnet, including Application subnets.
    let result = delete_subnet(
        &pocket_ic,
        GOVERNANCE_CANISTER_ID.get(),
        application_subnet_id.get().0,
    )
    .await;
    assert_eq!(
        result,
        Ok(()),
        "governance should be able to delete an application subnet"
    );

    // The subnet should no longer be in the subnet list.
    assert!(
        !subnet_ids(&pocket_ic)
            .await
            .contains(&application_subnet_id.get().to_vec()),
        "the application subnet should have been removed from the subnet list"
    );
}

#[tokio::test]
async fn test_engine_controller_cannot_delete_an_application_subnet() {
    let (application_mutate, application_subnet_id) =
        prepare_registry_with_application_subnet(4, INITIAL_MUTATION_ID);
    let pocket_ic = setup_with_subnet(application_mutate).await;

    // The engine controller may only delete CloudEngine subnets: the call passes
    // the authorization check but is then rejected by the business logic.
    let result = delete_subnet(
        &pocket_ic,
        ENGINE_CONTROLLER_CANISTER_ID.get(),
        application_subnet_id.get().0,
    )
    .await;
    assert_eq!(
        result,
        Err("The engine controller may only delete CloudEngine subnets".to_string()),
        "the engine controller should not be able to delete an application subnet"
    );

    // The subnet should still be present.
    assert!(
        subnet_ids(&pocket_ic)
            .await
            .contains(&application_subnet_id.get().to_vec()),
        "the application subnet should not have been deleted"
    );
}
