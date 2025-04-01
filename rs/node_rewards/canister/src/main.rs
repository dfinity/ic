#[cfg(any(test, feature = "test"))]
use ic_cdk::query;
use ic_cdk::{init, post_upgrade, pre_upgrade, spawn};
use ic_nervous_system_canisters::registry::RegistryCanister;
use ic_node_rewards_canister::canister::NodeRewardsCanister;
use ic_node_rewards_canister::storage::RegistryStoreStableMemoryBorrower;
use ic_node_rewards_canister_api::lifecycle_args::{InitArgs, UpgradeArgs};
use ic_registry_canister_client::CanisterRegistryClient;
use ic_registry_canister_client::StableCanisterRegistryClient;
use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

fn main() {}

thread_local! {
    static REGISTRY_STORE: Arc<StableCanisterRegistryClient<RegistryStoreStableMemoryBorrower>> = {
        let store = StableCanisterRegistryClient::<RegistryStoreStableMemoryBorrower>::new(
            Box::new(RegistryCanister::new()));
        Arc::new(store)
    };
    static CANISTER: RefCell<NodeRewardsCanister> = {
        RefCell::new(NodeRewardsCanister::new(REGISTRY_STORE.with(|store| {
            store.clone()
        })))
    };
}

#[init]
fn canister_init(_args: InitArgs) {
    schedule_timers();
}

#[pre_upgrade]
fn pre_upgrade() {}

#[post_upgrade]
fn post_upgrade(_args: Option<UpgradeArgs>) {
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

#[cfg(any(feature = "test", test))]
#[query(hidden = true)]
fn get_registry_value(key: String) -> Result<Option<Vec<u8>>, String> {
    CANISTER.with(|canister| canister.borrow().get_registry_value(key))
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
