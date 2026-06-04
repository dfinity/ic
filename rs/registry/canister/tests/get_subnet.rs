use candid::{Decode, Encode};
use common::test_helpers::install_registry_canister_with_payload_builder;
use ic_base_types::PrincipalId;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_test_utils::registry::{TEST_ID, invariant_compliant_mutation_as_atomic_req};
use ic_registry_subnet_type::SubnetType;
use ic_test_utilities_types::ids::subnet_test_id;
use pocket_ic::PocketIcBuilder;
use registry_canister::{
    get_subnet::{GetSubnetRequest, SubnetRecord},
    init::RegistryCanisterInitPayloadBuilder,
};

mod common;

async fn setup() -> pocket_ic::nonblocking::PocketIc {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0));
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), false).await;
    pocket_ic
}

async fn call_get_subnet(
    pocket_ic: &pocket_ic::nonblocking::PocketIc,
    request: GetSubnetRequest,
) -> Result<SubnetRecord, String> {
    let result = pocket_ic
        .query_call(
            REGISTRY_CANISTER_ID.get().0,
            candid::Principal::anonymous(),
            "get_subnet",
            Encode!(&request).unwrap(),
        )
        .await
        .expect("query_call to get_subnet failed");
    Decode!(&result, Result<SubnetRecord, String>).unwrap()
}

#[tokio::test]
async fn test_get_subnet_returns_correct_record() {
    let pocket_ic = setup().await;

    // invariant_compliant_mutation_as_atomic_req(0) creates a System subnet with subnet_test_id(TEST_ID)
    let subnet_id = subnet_test_id(TEST_ID).get();

    let result = call_get_subnet(
        &pocket_ic,
        GetSubnetRequest {
            subnet_id: Some(subnet_id),
        },
    )
    .await
    .expect("get_subnet should succeed for the NNS subnet");

    assert_eq!(result.subnet_type, SubnetType::System);
    assert_eq!(result.unit_delay_millis, 600);
    assert!(!result.membership.is_empty());
    assert!(!result.is_halted);
}

#[tokio::test]
async fn test_get_subnet_missing_subnet_id() {
    let pocket_ic = setup().await;

    let err = call_get_subnet(&pocket_ic, GetSubnetRequest { subnet_id: None })
        .await
        .expect_err("get_subnet should fail when subnet_id is missing");

    assert!(
        err.contains("No subnet_id supplied"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_get_subnet_unknown_subnet_id() {
    let pocket_ic = setup().await;

    let unknown = PrincipalId::new_subnet_test_id(12345);
    let err = call_get_subnet(
        &pocket_ic,
        GetSubnetRequest {
            subnet_id: Some(unknown),
        },
    )
    .await
    .expect_err("get_subnet should fail for an unknown subnet");

    assert!(
        err.contains("not found in the Registry"),
        "unexpected error: {err}"
    );
}
