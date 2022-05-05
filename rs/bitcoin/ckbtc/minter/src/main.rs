use crate::metrics::encode_metrics;
use ic_cdk_macros::{init, post_upgrade, pre_upgrade};
use ic_ckbtc_minter::runtime::CanisterRuntime;
use ic_ckbtc_minter::types::{InitArgs, UpgradeArgs};

mod lifecycle;
mod metrics;

#[init]
fn init(args: InitArgs) {
    lifecycle::init(args, &mut CanisterRuntime {})
}

#[pre_upgrade]
fn pre_upgrade() {
    lifecycle::pre_upgrade(&mut CanisterRuntime {})
}

#[post_upgrade]
fn post_upgrade(args: UpgradeArgs) {
    lifecycle::post_upgrade(args, &mut CanisterRuntime {})
}

#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(encode_metrics);
}

/// Main prints out the candid interface of the ckBTC Minter canister.
fn main() {
    candid::export_service!();

    let new_interface = __export_service();

    println!("{}", new_interface);
}

#[cfg(test)]
mod tests {
    use candid::utils::{service_compatible, CandidSource};
    use std::path::PathBuf;

    /// Checks the real candid interface against the one declared in the did file
    #[test]
    fn check_candid_interface_compatibility() {
        candid::export_service!();

        let new_interface = __export_service();

        // check the public interface against the actual one
        let old_interface =
            PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("ckbtc_minter.did");

        service_compatible(
            CandidSource::Text(&new_interface),
            CandidSource::File(old_interface.as_path()),
        )
        .expect("The CMC canister interface is not compatible with the cmc.did file");
    }
}
