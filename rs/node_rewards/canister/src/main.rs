use ic_cdk::{init, post_upgrade, pre_upgrade, query};
use node_rewards_canister_api::lifecycle_args::{InitArgs, UpgradeArgs};

fn main() {
    println!("Hello, world!");
}

#[init]
fn canister_init(_args: InitArgs) {}

#[pre_upgrade]
fn pre_upgrade() {}

#[post_upgrade]
fn post_upgrade(args: Option<UpgradeArgs>) {}

#[query]
fn hello() -> String {
    "Hello, world!".to_string()
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
