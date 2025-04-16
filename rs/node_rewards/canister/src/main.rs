use candid::Principal;
#[cfg(any(feature = "test", test))]
use ic_cdk::query;
use ic_cdk::{init, post_upgrade, pre_upgrade, spawn, update};
use ic_nervous_system_canisters::registry::RegistryCanister;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_node_rewards_canister::canister::NodeRewardsCanister;
use ic_node_rewards_canister::storage::RegistryStoreStableMemoryBorrower;
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
        RefCell::new(NodeRewardsCanister::new(REGISTRY_STORE.with(|store| {
            store.clone()
        })))
    };
}

#[cfg(any(feature = "test", test))]
thread_local! {
    static TEST_CALLER: RefCell<Principal> = {
        RefCell::new(Principal::from_text("aaaaa-aa").unwrap())
    };
}

#[cfg(any(feature = "test", test))]
fn caller() -> Principal {
    TEST_CALLER.with_borrow(|p| *p)
}

#[cfg(not(any(feature = "test", test)))]
fn caller() -> Principal {
    ic_cdk::caller()
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

fn schedule_timers() {
    schedule_registry_sync();
}

// The frquency of regular registry syncs.  This is set to 1 hour to avoid
// making too many requests.  Before meaningful calculations are made, however, the
// registry data should be updated.
const REGISTRY_SYNC_INTERVAL_SECONDS: Duration = Duration::from_secs(60 * 60); // 1 hour

fn schedule_registry_sync() {
    ic_cdk_timers::set_timer_interval(REGISTRY_SYNC_INTERVAL_SECONDS, move || {
        spawn(async move {
            let store = REGISTRY_STORE.with(|s| s.clone());
            // panicking here is okay because we are using an interval instead of a timer that
            // has to reschedule itself.
            store
                .sync_registry_stored()
                .await
                .expect("Could not sync registry store!");
        });
    });
}

fn panic_if_not_governance() {
    if caller() != GOVERNANCE_CANISTER_ID.get().0 {
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
    panic_if_not_governance();
    NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(&CANISTER, request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid_parser::utils::{service_equal, CandidSource};
    use futures_util::FutureExt;

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
    // Test only governance can call get_monthly_xdr_rewards
    #[test]
    #[should_panic(expected = "Only the governance canister can call this method")]
    fn test_get_monthly_xdr_rewards_not_governance_panics() {
        let request = GetNodeProvidersMonthlyXdrRewardsRequest {
            registry_version: None,
        };
        get_node_providers_monthly_xdr_rewards(request)
            .now_or_never()
            .unwrap();
    }

    #[test]
    fn test_get_monthly_xdr_rewards_is_callable_by_governance() {
        TEST_CALLER.with_borrow_mut(|p| {
            *p = GOVERNANCE_CANISTER_ID.get().0;
        });

        let request = GetNodeProvidersMonthlyXdrRewardsRequest {
            registry_version: None,
        };
        let response = get_node_providers_monthly_xdr_rewards(request)
            .now_or_never()
            .unwrap();

        assert!(response.error.is_some());
    }
}
