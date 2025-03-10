use ic_cdk::{init, post_upgrade, pre_upgrade, query};
use ic_node_rewards_canister::canister::NodeRewardsCanister;
use ic_node_rewards_canister::storage::RegistryStoreStableMemoryBorrower;
use ic_node_rewards_canister_api::lifecycle_args::{InitArgs, UpgradeArgs};
use ic_registry_canister_client::CanisterRegistryClient;
use ic_registry_canister_data_provider::CanisterDataProvider;
use ic_types::registry::RegistryClientError;
use std::cell::RefCell;
use std::sync::Arc;

fn main() {}

thread_local! {
    static CANISTER_DATA_PROVIDER: Arc<CanisterDataProvider<RegistryStoreStableMemoryBorrower>> = {
        let data_provider = CanisterDataProvider::new(None);
        Arc::new(data_provider)
    };

    static CANISTER: RefCell<NodeRewardsCanister> = {
        let client = CanisterRegistryClient::new(CANISTER_DATA_PROVIDER.with(|dp| dp.clone()));
        RefCell::new(NodeRewardsCanister::new(Arc::new(client)))
    };
}

#[init]
fn canister_init(_args: InitArgs) {}

#[pre_upgrade]
fn pre_upgrade() {}

#[post_upgrade]
fn post_upgrade(_args: Option<UpgradeArgs>) {}

#[query(hidden = true)]
fn hello() -> String {
    "Hello, world!".to_string()
}

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
