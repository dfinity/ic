#[cfg(any(feature = "test", test))]
use ic_cdk::query;
use ic_cdk::{init, post_upgrade, pre_upgrade, spawn, update};
use ic_nervous_system_canisters::registry::RegistryCanister;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_node_rewards_canister::canister::NodeRewardsCanister;
use ic_node_rewards_canister::storage::{RegistryStoreStableMemoryBorrower, METRICS_MANAGER};
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
};
use ic_registry_canister_client::CanisterRegistryClient;
use ic_registry_canister_client::StableCanisterRegistryClient;
use std::cell::RefCell;
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
        let registry_store = REGISTRY_STORE.with(|store| {
            store.clone()
        });
        let metrics_manager = METRICS_MANAGER.with(|m| m.clone());

        RefCell::new(NodeRewardsCanister::new(registry_store, metrics_manager))
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
        spawn(NodeRewardsCanister::sync_all(&CANISTER));
    });
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
    use super::*;
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
