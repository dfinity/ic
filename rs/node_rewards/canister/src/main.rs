use ic_base_types::{RegistryVersion, SubnetId};
#[cfg(any(feature = "test", test))]
use ic_cdk::query;
use ic_cdk::{init, post_upgrade, pre_upgrade, spawn, update};
use ic_interfaces_registry::ZERO_REGISTRY_VERSION;
use ic_nervous_system_canisters::registry::RegistryCanister;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_node_rewards_canister::canister::NodeRewardsCanister;
use ic_node_rewards_canister::registry_querier::RegistryQuerier;
use ic_node_rewards_canister::storage::{RegistryStoreStableMemoryBorrower, METRICS_MANAGER};
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
};
use ic_registry_canister_client::CanisterRegistryClient;
use ic_registry_canister_client::StableCanisterRegistryClient;
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

fn main() {}

thread_local! {
    static REGISTRY_STORE: Arc<StableCanisterRegistryClient<RegistryStoreStableMemoryBorrower>> = {
        let store = StableCanisterRegistryClient::<RegistryStoreStableMemoryBorrower>::new(
            Arc::new(RegistryCanister::new()));
        Arc::new(store)
    };
    static CANISTER: RefCell<NodeRewardsCanister> = {
        RefCell::new(NodeRewardsCanister::new(REGISTRY_STORE.with(|store| {
            store.clone()
        })))
    };
}

#[init]
fn canister_init() {
    schedule_timers();
}

#[pre_upgrade]
fn pre_upgrade() {}

#[post_upgrade]
fn post_upgrade() {
    schedule_timers();
}

// The frequency of regular registry syncs.  This is set to 1 hour to avoid
// making too many requests.  Before meaningful calculations are made, however, the
// registry data should be updated.
const SYNC_INTERVAL_SECONDS: Duration = Duration::from_secs(60 * 60); // 1 hour

fn schedule_timers() {
    ic_cdk_timers::set_timer_interval(SYNC_INTERVAL_SECONDS, move || {
        spawn(sync_all());
    });
}

async fn sync_all() {
    let registry_store = REGISTRY_STORE.with(|s| s.clone());

    let pre_sync_version = registry_store.get_latest_version().await;
    let registry_sync_result = registry_store.sync_registry_stored().await;
    let post_sync_version = registry_store.get_latest_version().await;

    match registry_sync_result {
        Ok(_) => {
            schedule_metrics_sync(pre_sync_version, post_sync_version).await;
            ic_cdk::println!("Successfully synced subnets metrics and local registry");
        }
        Err(e) => {
            ic_cdk::println!("Failed to sync local registry: {:?}", e)
        }
    }
}
async fn schedule_metrics_sync(
    pre_sync_version: RegistryVersion,
    post_sync_version: RegistryVersion,
) {
    let registry_store = REGISTRY_STORE.with(|m| m.clone());
    let registry_querier = RegistryQuerier::new(registry_store.clone());

    let mut subnets_list: HashSet<SubnetId> = HashSet::default();
    let mut version = if pre_sync_version == ZERO_REGISTRY_VERSION {
        // If the pre-sync version is 0, we consider all subnets from the post-sync version
        post_sync_version
    } else {
        pre_sync_version
    };
    while version <= post_sync_version {
        subnets_list.extend(registry_querier.subnets_list(version));

        // Increment the version to sync the next one
        version.increment();
    }

    let metrics_manager = METRICS_MANAGER.with(|m| m.clone());
    metrics_manager
        .update_subnets_metrics(subnets_list.into_iter().collect())
        .await;
    metrics_manager.retry_failed_subnets().await;
}

fn panic_if_caller_not_governance() {
    if ic_cdk::caller() != GOVERNANCE_CANISTER_ID.get().0 {
        panic!("Only the governance canister can call this method");
    }
}

#[cfg(any(feature = "test", test))]
#[query(hidden = true)]
fn get_registry_value(key: String) -> Result<Option<Vec<u8>>, String> {
    CANISTER.with(|canister| canister.borrow().get_registry_value(key))
}

#[update]
async fn get_node_providers_monthly_xdr_rewards(
    request: GetNodeProvidersMonthlyXdrRewardsRequest,
) -> GetNodeProvidersMonthlyXdrRewardsResponse {
    panic_if_caller_not_governance();
    NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(&CANISTER, request).await
}

#[cfg(test)]
mod tests {
    use candid_parser::utils::{service_equal, CandidSource};
    #[test]
    fn test_implemented_interface_matches_declared_interface_exactly() {
        let declared_interface = CandidSource::Text(include_str!("../node-rewards-canister.did"));

        // The line below generates did types and service definition from the
        // methods annotated with `candid_method` above. The definition is then
        // obtained with `__export_service()`.
        candid::export_service!();
        let implemented_interface_str = __export_service();
        let implemented_interface = CandidSource::Text(&implemented_interface_str);

        let result = service_equal(declared_interface, implemented_interface);
        assert!(result.is_ok(), "{:?}\n\n", result.unwrap_err());
    }
}
