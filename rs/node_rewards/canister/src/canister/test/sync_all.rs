use crate::canister::NodeRewardsCanister;
use crate::metrics::tests::subnet_id;
use crate::metrics::MetricsManager;
use futures_util::FutureExt;
use ic_base_types::{RegistryVersion, SubnetId};
use ic_cdk::api::call::CallResult;
use ic_management_canister_types::NodeMetricsHistoryRecord;
use ic_nervous_system_canisters::registry::fake::FakeRegistry;
use ic_nervous_system_canisters::registry::Registry;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_canister_client::{
    test_registry_data_stable_memory_impl, StableCanisterRegistryClient,
};
use ic_registry_canister_client::{
    RegistryDataStableMemory, StorableRegistryKey, StorableRegistryValue,
};
use ic_registry_keys::make_subnet_list_record_key;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

pub type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static STATE: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>> = RefCell::new({
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
        StableBTreeMap::init(mgr.get(MemoryId::new(0)))
    });
    // Dummy value b/c we can't do direct assignment using values defined above.
    static CANISTER: RefCell<NodeRewardsCanister> = {
        let registry_store = Arc::new(StableCanisterRegistryClient::<TestState>::new(Arc::new(FakeRegistry::default())));
        let metrics_manager = Rc::new(MetricsManager::new(crate::metrics::tests::mock::MockCanisterClient::new()));

        RefCell::new(NodeRewardsCanister::new(registry_store, metrics_manager))
    };
}

test_registry_data_stable_memory_impl!(TestState, STATE);

fn setup_thread_local_canister_for_test() -> Arc<FakeRegistry> {
    let fake_registry = Arc::new(FakeRegistry::new());
    let mut mock = crate::metrics::tests::mock::MockCanisterClient::new();
    mock.expect_node_metrics_history()
        .return_const(CallResult::Ok(vec![NodeMetricsHistoryRecord {
            timestamp_nanos: 0,
            node_metrics: vec![],
        }]));
    let canister = NodeRewardsCanister::new(
        Arc::new(StableCanisterRegistryClient::<TestState>::new(
            fake_registry.clone(),
        ))
        .clone(),
        Rc::new(MetricsManager::new(mock)),
    );
    CANISTER.with_borrow_mut(|c| *c = canister);
    // To do thorough tests, this is all we currently need to mock, as everything else
    // interacts through the RegistryClient at present.  Outside of Registry, everything else
    // is internal state (which at present is just a cache of registry).
    fake_registry
}

fn default_for_test(fake_registry: Arc<FakeRegistry>, subnets: Vec<SubnetId>) {
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

#[test]
fn test_sync_zero_registry_version() {
    let fake_registry = setup_thread_local_canister_for_test();
    let subnets: Vec<SubnetId> = vec![
        subnet_id(0),
        subnet_id(1),
        subnet_id(2),
        subnet_id(3),
        subnet_id(4),
    ];
    default_for_test(fake_registry.clone(), subnets[..3].to_vec());
    default_for_test(fake_registry, subnets[3..].to_vec());
    NodeRewardsCanister::sync_all(&CANISTER)
        .now_or_never()
        .unwrap();
    let registry_client = CANISTER.with_borrow(|canister| canister.get_registry_client());
    let metrics_manager = CANISTER.with_borrow(|canister| canister.get_metrics_manager());

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
    let fake_registry = setup_thread_local_canister_for_test();

    // Set the registry version to 1, which is non-zero.
    let subnets_first_sync: Vec<SubnetId> = vec![
        subnet_id(0),
        subnet_id(1),
        subnet_id(2),
        subnet_id(3),
        subnet_id(4),
    ];
    default_for_test(fake_registry.clone(), subnets_first_sync.clone());
    NodeRewardsCanister::sync_all(&CANISTER)
        .now_or_never()
        .unwrap();

    let subnets_second_sync: Vec<SubnetId> = vec![
        subnet_id(5),
        subnet_id(6),
        subnet_id(7),
        subnet_id(8),
        subnet_id(9),
    ];
    default_for_test(fake_registry.clone(), subnets_second_sync[..3].to_vec());
    default_for_test(fake_registry.clone(), subnets_second_sync[3..].to_vec());
    NodeRewardsCanister::sync_all(&CANISTER)
        .now_or_never()
        .unwrap();

    let registry_client = CANISTER.with_borrow(|canister| canister.get_registry_client());
    let metrics_manager = CANISTER.with_borrow(|canister| canister.get_metrics_manager());

    let expected_version = RegistryVersion::from(3);
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

    assert_eq!(expected_version, registry_client.get_latest_version());
    assert_eq!(expected_subnets, got_subnets);
}
