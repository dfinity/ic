use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::decode_registry_value;
use ic_nns_constants::{
    ENGINE_CONTROLLER_CANISTER_ID, GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID,
};
use ic_nns_test_utils::registry::invariant_compliant_mutation_as_atomic_req;
use ic_protobuf::registry::subnet::v1::SubnetListRecord as SubnetListRecordPb;
use ic_registry_keys::make_subnet_list_record_key;
use pocket_ic::PocketIcBuilder;
use pocket_ic::nonblocking::PocketIc;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder, mutations::do_delete_subnet::DeleteSubnetPayload,
};

mod common;

use common::test_helpers::install_registry_canister_with_payload_builder;

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

#[tokio::test]
async fn test_the_anonymous_user_cannot_delete_a_subnet() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;

    let payload = DeleteSubnetPayload { subnet_id };

    // The anonymous end-user tries to delete a subnet, bypassing governance.
    // This should be rejected by the authorization check.
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

    // A principal that is neither governance nor the engine controller.
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

#[tokio::test]
async fn test_governance_and_engine_controller_are_authorized_to_delete_a_subnet() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;

    let payload = DeleteSubnetPayload { subnet_id };

    // Both governance and the engine controller are allowed to call
    // `delete_subnet`. The existing subnet is not a CloudEngine, so the call
    // gets past the authorization check and is then rejected by the business
    // logic. This proves the caller is authorized without depending on a
    // CloudEngine subnet being present.
    for caller in [
        GOVERNANCE_CANISTER_ID.get(),
        ENGINE_CONTROLLER_CANISTER_ID.get(),
    ] {
        let response = pocket_ic
            .update_call(
                REGISTRY_CANISTER_ID.get().0,
                caller.0,
                "delete_subnet",
                Encode!(&payload).unwrap(),
            )
            .await
            .unwrap_or_else(|err| {
                panic!("delete_subnet call by authorized caller {caller} was unexpectedly rejected: {err:?}")
            });

        let result = Decode!(&response, Result<(), String>).unwrap();
        assert_eq!(
            result,
            Err("Only CloudEngines may be deleted".to_string()),
            "caller {caller} should pass authorization and reach the business logic"
        );
    }
}
