use candid::{Decode, Encode};
use ic_interfaces_registry::RegistryValue;
use ic_nervous_system_integration_tests::pocket_ic_helpers::NnsInstaller;
use ic_nns_test_utils::common::build_node_rewards_test_wasm;
use ic_protobuf::registry::subnet::v1::{SubnetRecord, SubnetType};
use ic_registry_keys::make_subnet_record_key;
use ic_types::{PrincipalId, SubnetId};
use pocket_ic::PocketIcBuilder;

#[tokio::test]
async fn test_registry_value_syncing() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build_async()
        .await;

    let mut installer = NnsInstaller::default();
    installer.with_current_nns_canister_versions();
    installer.install(&pocket_ic).await;

    let wasm = build_node_rewards_test_wasm();

    let canister_id = pocket_ic.create_canister().await;
    pocket_ic.add_cycles(canister_id, 100_000_000_000_000).await;
    pocket_ic
        .install_canister(canister_id, wasm.bytes(), Encode!().unwrap(), None)
        .await;

    // This is the value from invariant_compliant_mutation
    let test_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(999));
    let response = pocket_ic
        .query_call(
            canister_id,
            PrincipalId::new_anonymous().0,
            "get_registry_value",
            Encode!(&make_subnet_record_key(test_subnet_id)).unwrap(),
        )
        .await
        .unwrap();

    // Now we are asserting that there is something in this record
    let decoded = Decode!(&response, Result<Option<Vec<u8>>, String>).unwrap();
    let unwrapped = decoded.unwrap().unwrap();
    // Assert that this Registry value is actually a valid sequence of bits
    let subnet_record = SubnetRecord::decode(unwrapped.as_slice()).unwrap();
    assert_eq!(subnet_record.subnet_type(), SubnetType::System);
}
