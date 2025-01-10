use ic_interfaces_registry::RegistryClient;
use ic_registry_canister_client::CanisterRegistryClient;
use ic_registry_canister_data_provider::{
    CanisterDataProvider, StableMemoryBorrower, StorableRegistryKey, StorableRegistryValue,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use std::cell::RefCell;

use ic_cdk::spawn;
use std::sync::Arc;

type Memory = VirtualMemory<DefaultMemoryImpl>;
thread_local! {
    /// Memory manager instance for handling stable memory allocation
    pub static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
    RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// Stores registry data with typed keys and values in canister stable memory
    pub static REGISTRY: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, Memory>> =
        RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))
    ));
}

/// Implements StableMemoryBorrower for mutable and immutable stable memory access to the registry store
#[derive(Default)]
pub struct StableMemoryStore;
impl StableMemoryBorrower for StableMemoryStore {
    fn with_borrow<R>(
        f: impl FnOnce(
            &StableBTreeMap<
                StorableRegistryKey,
                StorableRegistryValue,
                VirtualMemory<DefaultMemoryImpl>,
            >,
        ) -> R,
    ) -> R {
        REGISTRY.with_borrow(|registry_stored| f(registry_stored))
    }
    fn with_borrow_mut<R>(
        f: impl FnOnce(
            &mut StableBTreeMap<
                StorableRegistryKey,
                StorableRegistryValue,
                VirtualMemory<DefaultMemoryImpl>,
            >,
        ) -> R,
    ) -> R {
        REGISTRY.with_borrow_mut(|registry_stored| f(registry_stored))
    }
}

fn main() {
    let local_registry: Arc<CanisterDataProvider<StableMemoryStore>> =
        Arc::new(CanisterDataProvider::new(Default::default()));
    let registry_client: CanisterRegistryClient =
        CanisterRegistryClient::new(local_registry.clone());

    spawn(async move {
        // Update local registry from remote registry canister storing it in stable memory
        local_registry.sync_registry_stored().await.unwrap();

        // Update the cache
        registry_client.update_to_latest_version();

        // Example fetch latest version of the registry
        let _latest_registry_version = registry_client.get_latest_version();
    });
}
