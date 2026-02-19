use crate::providers::SupportedRpcServiceUsage;
use crate::{
    providers::SupportedRpcService,
    types::{ApiKey, Metrics, OverrideProvider, ProviderId, StorableLogFilter},
};
use candid::Principal;
use canhttp::http::json::{ConstantSizeId, Id};
use canhttp::multi::Timestamp;
use canlog::LogFilter;
use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager},
    DefaultMemoryImpl,
};
use ic_stable_structures::{Cell, StableBTreeMap};
use std::cell::RefCell;

const IS_DEMO_ACTIVE_MEMORY_ID: MemoryId = MemoryId::new(4);
const API_KEY_MAP_MEMORY_ID: MemoryId = MemoryId::new(5);
const MANAGE_API_KEYS_MEMORY_ID: MemoryId = MemoryId::new(6);
const LOG_FILTER_MEMORY_ID: MemoryId = MemoryId::new(7);
const OVERRIDE_PROVIDER_MEMORY_ID: MemoryId = MemoryId::new(8);
const NUM_SUBNET_NODES_MEMORY_ID: MemoryId = MemoryId::new(9);

type StableMemory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    // Unstable static data: these are reset when the canister is upgraded.
    pub static UNSTABLE_METRICS: RefCell<Metrics> = RefCell::new(Metrics::default());
    static UNSTABLE_HTTP_REQUEST_COUNTER: RefCell<ConstantSizeId> = const {RefCell::new(ConstantSizeId::ZERO)};
    static UNSTABLE_RPC_SERVICE_OK_RESULTS_TIMESTAMPS: RefCell<SupportedRpcServiceUsage> =  RefCell::new(SupportedRpcServiceUsage::default());

    // Stable static data: these are preserved when the canister is upgraded.
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static IS_DEMO_ACTIVE: RefCell<Cell<bool, StableMemory>> =
        RefCell::new(Cell::init(MEMORY_MANAGER.with_borrow(|m| m.get(IS_DEMO_ACTIVE_MEMORY_ID)), false).expect("Unable to read demo status from stable memory"));
    static API_KEY_MAP: RefCell<StableBTreeMap<ProviderId, ApiKey, StableMemory>> =
        RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with_borrow(|m| m.get(API_KEY_MAP_MEMORY_ID))));
    static MANAGE_API_KEYS: RefCell<ic_stable_structures::Vec<Principal, StableMemory>> =
        RefCell::new(ic_stable_structures::Vec::init(MEMORY_MANAGER.with_borrow(|m| m.get(MANAGE_API_KEYS_MEMORY_ID))).expect("Unable to read API key principals from stable memory"));
    static LOG_FILTER: RefCell<Cell<StorableLogFilter, StableMemory>> =
        RefCell::new(Cell::init(MEMORY_MANAGER.with_borrow(|m| m.get(LOG_FILTER_MEMORY_ID)), StorableLogFilter::default()).expect("Unable to read log message filter from stable memory"));
    static OVERRIDE_PROVIDER: RefCell<Cell<OverrideProvider, StableMemory>> =
        RefCell::new(Cell::init(MEMORY_MANAGER.with_borrow(|m| m.get(OVERRIDE_PROVIDER_MEMORY_ID)), OverrideProvider::default()).expect("Unable to read provider override from stable memory"));
    static NUM_SUBNET_NODES: RefCell<Cell<u32, StableMemory>> =
        RefCell::new(Cell::init(MEMORY_MANAGER.with_borrow(|m| m.get(NUM_SUBNET_NODES_MEMORY_ID)), crate::constants::NODES_IN_SUBNET).expect("Unable to read number of subnet nodes from stable memory"));
}

pub fn get_api_key(provider_id: ProviderId) -> Option<ApiKey> {
    API_KEY_MAP.with_borrow_mut(|map| map.get(&provider_id))
}

pub fn insert_api_key(provider_id: ProviderId, api_key: ApiKey) {
    API_KEY_MAP.with_borrow_mut(|map| map.insert(provider_id, api_key));
}

pub fn remove_api_key(provider_id: ProviderId) {
    API_KEY_MAP.with_borrow_mut(|map| map.remove(&provider_id));
}

pub fn is_api_key_principal(principal: &Principal) -> bool {
    MANAGE_API_KEYS.with_borrow(|principals| principals.iter().any(|other| &other == principal))
}

pub fn set_api_key_principals(new_principals: Vec<Principal>) {
    MANAGE_API_KEYS.with_borrow_mut(|principals| {
        while !principals.is_empty() {
            principals.pop();
        }
        for principal in new_principals {
            principals
                .push(&principal)
                .expect("Error while adding API key principal");
        }
    });
}

pub fn is_demo_active() -> bool {
    IS_DEMO_ACTIVE.with_borrow(|demo| *demo.get())
}

pub fn set_demo_active(is_active: bool) {
    IS_DEMO_ACTIVE.with_borrow_mut(|demo| {
        demo.set(is_active)
            .expect("Error while storing new demo status")
    });
}

pub fn get_log_filter() -> LogFilter {
    LOG_FILTER.with_borrow(|filter| filter.get().clone().into())
}

pub fn set_log_filter(filter: LogFilter) {
    LOG_FILTER.with_borrow_mut(|state| {
        state
            .set(filter.into())
            .expect("Error while updating log message filter")
    });
}

pub fn get_override_provider() -> OverrideProvider {
    OVERRIDE_PROVIDER.with_borrow(|provider| provider.get().clone())
}

pub fn set_override_provider(provider: OverrideProvider) {
    OVERRIDE_PROVIDER.with_borrow_mut(|state| {
        state
            .set(provider)
            .expect("Error while updating override provider")
    });
}

pub fn next_request_id() -> Id {
    UNSTABLE_HTTP_REQUEST_COUNTER.with_borrow_mut(|counter| {
        let current_request_id = counter.get_and_increment();
        Id::from(current_request_id)
    })
}

pub fn get_num_subnet_nodes() -> u32 {
    NUM_SUBNET_NODES.with_borrow(|state| *state.get())
}

pub fn set_num_subnet_nodes(nodes: u32) {
    NUM_SUBNET_NODES.with_borrow_mut(|state| {
        state
            .set(nodes)
            .expect("Error while updating number of subnet nodes")
    });
}

pub fn record_ok_result(service: SupportedRpcService, now: Timestamp) {
    UNSTABLE_RPC_SERVICE_OK_RESULTS_TIMESTAMPS
        .with_borrow_mut(|access| access.record_evict(service, now));
}

pub fn rank_providers(
    services: &[SupportedRpcService],
    now: Timestamp,
) -> Vec<SupportedRpcService> {
    UNSTABLE_RPC_SERVICE_OK_RESULTS_TIMESTAMPS
        .with_borrow_mut(|access| access.rank_ascending_evict(services, now))
}

#[cfg(test)]
mod test {
    use candid::Principal;

    use crate::memory::{is_api_key_principal, set_api_key_principals};

    #[test]
    fn test_api_key_principals() {
        let principal1 =
            Principal::from_text("k5dlc-ijshq-lsyre-qvvpq-2bnxr-pb26c-ag3sc-t6zo5-rdavy-recje-zqe")
                .unwrap();
        let principal2 =
            Principal::from_text("yxhtl-jlpgx-wqnzc-ysego-h6yqe-3zwfo-o3grn-gvuhm-nz3kv-ainub-6ae")
                .unwrap();
        assert!(!is_api_key_principal(&principal1));
        assert!(!is_api_key_principal(&principal2));

        set_api_key_principals(vec![principal1]);
        assert!(is_api_key_principal(&principal1));
        assert!(!is_api_key_principal(&principal2));

        set_api_key_principals(vec![principal2]);
        assert!(!is_api_key_principal(&principal1));
        assert!(is_api_key_principal(&principal2));

        set_api_key_principals(vec![principal1, principal2]);
        assert!(is_api_key_principal(&principal1));
        assert!(is_api_key_principal(&principal2));

        set_api_key_principals(vec![]);
        assert!(!is_api_key_principal(&principal1));
        assert!(!is_api_key_principal(&principal2));
    }
}
