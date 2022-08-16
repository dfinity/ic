use candid::candid_method;
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, update};
use ic_ckbtc_minter::lifecycle::{self, init::InitArgs, upgrade::UpgradeArgs};
use ic_ckbtc_minter::metrics::encode_metrics;
use ic_ckbtc_minter::updates::{
    self,
    get_btc_address::{GetBtcAddressArgs, GetBtcAddressResult},
    get_withdrawal_account::GetWithdrawalAccountResult,
};

#[init]
fn init(args: InitArgs) {
    lifecycle::init::init(args)
}

#[pre_upgrade]
fn pre_upgrade() {
    lifecycle::upgrade::pre_upgrade()
}

#[post_upgrade]
fn post_upgrade(args: UpgradeArgs) {
    lifecycle::upgrade::post_upgrade(args)
}

#[candid_method(update)]
#[update]
async fn get_btc_address(args: GetBtcAddressArgs) -> GetBtcAddressResult {
    updates::get_btc_address::get_btc_address(args).await
}

#[candid_method(update)]
#[update]
async fn get_withdrawal_account() -> GetWithdrawalAccountResult {
    updates::get_withdrawal_account::get_withdrawal_account().await
}

#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(encode_metrics);
}

fn main() {}

/// Checks the real candid interface against the one declared in the did file
#[test]
fn check_candid_interface_compatibility() {
    fn source_to_str(source: &candid::utils::CandidSource) -> String {
        match source {
            candid::utils::CandidSource::File(f) => {
                std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
            }
            candid::utils::CandidSource::Text(t) => t.to_string(),
        }
    }

    fn check_service_compatible(
        new_name: &str,
        new: candid::utils::CandidSource,
        old_name: &str,
        old: candid::utils::CandidSource,
    ) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);
        match candid::utils::service_compatible(new, old) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{} is not compatible with {}!\n\n\
            {}:\n\
            {}\n\n\
            {}:\n\
            {}\n",
                    new_name, old_name, new_name, new_str, old_name, old_str
                );
                panic!("{:?}", e);
            }
        }
    }

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("ckbtc_minter.did");

    check_service_compatible(
        "actual ledger candid interface",
        candid::utils::CandidSource::Text(&new_interface),
        "declared candid interface in ckbtc_minter.did file",
        candid::utils::CandidSource::File(old_interface.as_path()),
    );
}
