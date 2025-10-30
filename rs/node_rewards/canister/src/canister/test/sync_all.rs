use crate::canister::NodeRewardsCanister;
use crate::canister::test::test_utils::{CANISTER_TEST, setup_thread_local_canister_for_test};
use crate::metrics::tests::subnet_id;
use futures_util::FutureExt;
use ic_base_types::{RegistryVersion, SubnetId};
use ic_nervous_system_canisters::registry::Registry;
use ic_nervous_system_canisters::registry::fake::FakeRegistry;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::make_subnet_list_record_key;
use std::sync::Arc;

fn add_subnet_list(fake_registry: Arc<FakeRegistry>, subnets: Vec<SubnetId>) {
    let subnets_encoded: Vec<Vec<u8>> = subnets
        .clone()
        .into_iter()
        .map(|s| s.get().to_vec())
        .collect();

    let entry_version = fake_registry
        .get_latest_version()
        .now_or_never()
        .unwrap()
        .unwrap()
        .get();
    fake_registry.encode_value_at_version(
        make_subnet_list_record_key().as_str(),
        entry_version + 1,
        Some(SubnetListRecord {
            subnets: subnets_encoded.to_vec(),
        }),
    );
}

fn sync_all() {
    NodeRewardsCanister::schedule_registry_sync(&CANISTER_TEST)
        .now_or_never()
        .unwrap()
        .unwrap();
    NodeRewardsCanister::schedule_metrics_sync(&CANISTER_TEST)
        .now_or_never()
        .unwrap()
        .unwrap();
}

#[test]
fn test_sync_zero_registry_version() {
    let (fake_registry, _) = setup_thread_local_canister_for_test();
    let subnets: Vec<SubnetId> = vec![
        subnet_id(0),
        subnet_id(1),
        subnet_id(2),
        subnet_id(3),
        subnet_id(4),
    ];
    add_subnet_list(fake_registry.clone(), subnets[..3].to_vec());
    add_subnet_list(fake_registry, subnets[3..].to_vec());
    sync_all();
    let registry_client = CANISTER_TEST.with_borrow(|canister| canister.get_registry_client());
    let metrics_manager = CANISTER_TEST.with_borrow(|canister| canister.get_metrics_manager());

    let expected_version = RegistryVersion::from(2);

    // From ZERO_REGISTRY_VERSION, we expect just the last 2 subnets to be synced.
    let expected_subnets: Vec<SubnetId> = vec![subnet_id(3), subnet_id(4)];
    let got_subnets = metrics_manager
        .subnets_metrics
        .borrow()
        .iter()
        .map(|(k, _)| k.subnet_id.unwrap().into())
        .collect::<Vec<_>>();

    assert_eq!(expected_version, registry_client.get_latest_version());
    assert_eq!(expected_subnets, got_subnets);
}

#[test]
fn test_sync_non_zero_registry_version() {
    let (fake_registry, _) = setup_thread_local_canister_for_test();

    // Set the registry version to 1, which is non-zero.
    let subnets_first_sync: Vec<SubnetId> = vec![
        subnet_id(0),
        subnet_id(1),
        subnet_id(2),
        subnet_id(3),
        subnet_id(4),
    ];
    add_subnet_list(fake_registry.clone(), subnets_first_sync.clone());
    sync_all();

    let subnets_second_sync: Vec<SubnetId> = vec![
        subnet_id(5),
        subnet_id(6),
        subnet_id(7),
        subnet_id(8),
        subnet_id(9),
    ];
    add_subnet_list(fake_registry.clone(), subnets_second_sync.clone());
    sync_all();

    let registry_client = CANISTER_TEST.with_borrow(|canister| canister.get_registry_client());
    let metrics_manager = CANISTER_TEST.with_borrow(|canister| canister.get_metrics_manager());

    let expected_version = RegistryVersion::from(2);
    assert_eq!(expected_version, registry_client.get_latest_version());

    // From NON ZERO_REGISTRY_VERSION, we expect all subnets to be synced.
    let expected_subnets: Vec<SubnetId> = subnets_first_sync
        .into_iter()
        .chain(subnets_second_sync)
        .collect();
    let got_subnets = metrics_manager
        .subnets_metrics
        .borrow()
        .iter()
        .map(|(k, _)| k.subnet_id.unwrap().into())
        .collect::<Vec<_>>();

    assert_eq!(expected_subnets, got_subnets);
}
