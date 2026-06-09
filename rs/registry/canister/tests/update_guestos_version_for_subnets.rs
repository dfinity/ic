use candid::{Encode, Principal};
use ic_base_types::{PrincipalId, SubnetId};
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::decode_registry_value;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, set_up_registry_canister, set_up_universal_canister,
    state_machine_test_on_nns_subnet,
};
use ic_nns_test_utils::registry::invariant_compliant_mutation_as_atomic_req;
use ic_protobuf::registry::subnet::v1::{SubnetListRecord as SubnetListRecordPb, SubnetRecord};
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use pocket_ic::PocketIcBuilder;
use pocket_ic::nonblocking::PocketIc;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        do_revise_elected_replica_versions::ReviseElectedGuestosVersionsPayload,
        do_update_guestos_version_for_subnets::UpdateGuestosVersionForSubnetsPayload,
    },
};

mod common;

use common::test_helpers::install_registry_canister_with_payload_builder;

const MOCK_HASH: &str = "acdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdc";
const NEW_VERSION: &str = "version_43";

/// Installs an invariant-compliant registry (which already contains a single,
/// non-CloudEngine subnet) and returns the running `PocketIc` together with the
/// principal of an existing subnet that can be used as an update target.
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

/// Elects `NEW_VERSION` by submitting a `revise_elected_replica_versions` call
/// as the governance canister.
async fn elect_new_version(pocket_ic: &PocketIc) {
    let payload = ReviseElectedGuestosVersionsPayload {
        replica_version_to_elect: Some(NEW_VERSION.into()),
        release_package_sha256_hex: Some(MOCK_HASH.into()),
        release_package_urls: vec!["http://release_package.tar.zst".into()],
        guest_launch_measurements: None,
        replica_versions_to_unelect: vec![],
    };
    pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            GOVERNANCE_CANISTER_ID.get().0,
            "revise_elected_replica_versions",
            Encode!(&payload).unwrap(),
        )
        .await
        .expect("failed to elect a new replica version");
}

fn subnet_replica_version(record: &SubnetRecord) -> &str {
    &record.replica_version_id
}

#[tokio::test]
async fn test_the_anonymous_user_cannot_update_guestos_version_for_subnets() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;

    let payload = UpdateGuestosVersionForSubnetsPayload {
        subnet_ids: vec![PrincipalId::from(subnet_id)],
        replica_version_id: NEW_VERSION.into(),
    };

    // The anonymous end-user tries to update subnets via an ingress message,
    // bypassing governance. This should be rejected by the authorization check.
    let response = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            PrincipalId::new_anonymous().0,
            "update_guestos_version_for_subnets",
            Encode!(&payload).unwrap(),
        )
        .await;

    assert!(
        response.as_ref().is_err_and(|err| err
            .reject_message
            .contains("is not authorized to call this method: update_guestos_version_for_subnets")),
        "Expected an authorization rejection, but got {response:?}"
    );
}

#[tokio::test]
async fn test_an_unauthorized_principal_cannot_update_guestos_version_for_subnets() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;

    // A principal that is not the governance canister, calling via an ingress
    // message.
    let unauthorized_caller = PrincipalId::new_user_test_id(1);
    assert_ne!(unauthorized_caller, GOVERNANCE_CANISTER_ID.get());

    let payload = UpdateGuestosVersionForSubnetsPayload {
        subnet_ids: vec![PrincipalId::from(subnet_id)],
        replica_version_id: NEW_VERSION.into(),
    };

    let response = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            unauthorized_caller.0,
            "update_guestos_version_for_subnets",
            Encode!(&payload).unwrap(),
        )
        .await;

    assert!(
        response.as_ref().is_err_and(|err| err
            .reject_message
            .contains("is not authorized to call this method: update_guestos_version_for_subnets")),
        "Expected an authorization rejection, but got {response:?}"
    );
}

#[test]
fn test_a_canister_other_than_governance_cannot_update_guestos_version_for_subnets() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        // An attacker canister tries to update subnets via an inter-canister
        // call. Going through a real canister (rather than an ingress message)
        // ensures the access control cannot be bypassed by, e.g., only guarding
        // ingress messages in `inspect_message`.
        let attacker_canister = set_up_universal_canister(&runtime).await;
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        let payload = UpdateGuestosVersionForSubnetsPayload {
            subnet_ids: vec![PrincipalId::new_subnet_test_id(999)],
            replica_version_id: NEW_VERSION.into(),
        };

        // The attacker canister's call should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "update_guestos_version_for_subnets",
                Encode!(&payload).unwrap()
            )
            .await
        );

        Ok(())
    });
}

#[tokio::test]
async fn test_governance_can_update_guestos_version_for_subnets() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;
    let subnet_key = make_subnet_record_key(SubnetId::from(PrincipalId::from(subnet_id)));

    // The subnet must not already be on the new version, otherwise the update
    // would be a no-op and this test would not prove anything.
    let before = decode_registry_value::<SubnetRecord>(&pocket_ic, &subnet_key).await;
    assert_ne!(subnet_replica_version(&before), NEW_VERSION);

    elect_new_version(&pocket_ic).await;

    let payload = UpdateGuestosVersionForSubnetsPayload {
        subnet_ids: vec![PrincipalId::from(subnet_id)],
        replica_version_id: NEW_VERSION.into(),
    };
    pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            GOVERNANCE_CANISTER_ID.get().0,
            "update_guestos_version_for_subnets",
            Encode!(&payload).unwrap(),
        )
        .await
        .expect("governance update_guestos_version_for_subnets call was unexpectedly rejected");

    let after = decode_registry_value::<SubnetRecord>(&pocket_ic, &subnet_key).await;
    assert_eq!(subnet_replica_version(&after), NEW_VERSION);
}

#[tokio::test]
async fn test_unelected_version_is_rejected() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;
    let subnet_key = make_subnet_record_key(SubnetId::from(PrincipalId::from(subnet_id)));
    let before = decode_registry_value::<SubnetRecord>(&pocket_ic, &subnet_key).await;

    let payload = UpdateGuestosVersionForSubnetsPayload {
        subnet_ids: vec![PrincipalId::from(subnet_id)],
        replica_version_id: "unelected".into(),
    };

    let response = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            GOVERNANCE_CANISTER_ID.get().0,
            "update_guestos_version_for_subnets",
            Encode!(&payload).unwrap(),
        )
        .await;

    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains("is NOT elected")),
        "Expected a rejection because the version is not elected, but got {response:?}"
    );

    // The subnet record must be unchanged.
    let after = decode_registry_value::<SubnetRecord>(&pocket_ic, &subnet_key).await;
    assert_eq!(
        subnet_replica_version(&after),
        subnet_replica_version(&before)
    );
}
