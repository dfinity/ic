#![allow(deprecated)]
use crate::canister::NodeRewardsCanister;
use crate::metrics::MetricsManager;
use crate::storage::{METRICS_MANAGER, NaiveDateStorable};
use ic_management_canister_types::NodeMetricsHistoryRecord;
use ic_nervous_system_canisters::registry::fake::FakeRegistry;
use ic_registry_canister_client::RegistryDataStableMemory;
use ic_registry_canister_client::{
    StableCanisterRegistryClient, StorableRegistryKey, StorableRegistryValue,
    test_registry_data_stable_memory_impl,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

pub type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    pub(crate) static STATE_TEST: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>> = RefCell::new({
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
        StableBTreeMap::init(mgr.get(MemoryId::new(0)))
    });

    pub static LAST_DAY_SYNCED: RefCell<StableCell<Option<NaiveDateStorable>, VM>> = RefCell::new({
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
        StableCell::init(mgr.get(MemoryId::new(1)), None).expect("Could not initialize last_day_synced")
    });

    // Dummy value b/c we can't do direct assignment using values defined above.
    pub(crate) static CANISTER_TEST: RefCell<NodeRewardsCanister> = {
        let registry_store = Arc::new(StableCanisterRegistryClient::<TestState>::new(Arc::new(FakeRegistry::default())));
        let metrics_manager = METRICS_MANAGER.with(|m| m.clone());

        RefCell::new(NodeRewardsCanister::new(registry_store, metrics_manager, &LAST_DAY_SYNCED))
    };
}

test_registry_data_stable_memory_impl!(TestState, STATE_TEST);

pub(crate) fn setup_thread_local_canister_for_test() -> (Arc<FakeRegistry>, Rc<MetricsManager<VM>>)
{
    let fake_registry = Arc::new(FakeRegistry::new());
    let mut mock = crate::metrics::tests::mock::MockCanisterClient::new();
    mock.expect_node_metrics_history()
        .return_const(Ok(vec![NodeMetricsHistoryRecord {
            timestamp_nanos: 0,
            node_metrics: vec![],
        }]));
    let metrics_manager = Rc::new(MetricsManager::new_test(mock));
    let canister = NodeRewardsCanister::new(
        Arc::new(StableCanisterRegistryClient::<TestState>::new(
            fake_registry.clone(),
        ))
        .clone(),
        metrics_manager.clone(),
        &LAST_DAY_SYNCED,
    );
    CANISTER_TEST.with_borrow_mut(|c| *c = canister);
    (fake_registry, metrics_manager)
}
