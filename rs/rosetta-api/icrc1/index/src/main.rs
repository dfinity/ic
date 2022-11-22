use candid::candid_method;
use dfn_core::CanisterId;
use ic_cdk_macros::{heartbeat, init, post_upgrade, pre_upgrade, query, update};
use ic_icrc1::Subaccount;
use ic_icrc1_index::{
    GetAccountTransactionsArgs, GetTransactionsResult, InitArgs, ListSubaccountsArgs,
};

fn main() {}

#[init]
fn init(args: InitArgs) {
    ic_icrc1_index::init(args);
}

#[heartbeat]
async fn heartbeat() {
    ic_icrc1_index::heartbeat().await;
}

#[update]
#[candid_method(update)]
async fn get_account_transactions(args: GetAccountTransactionsArgs) -> GetTransactionsResult {
    ic_icrc1_index::get_account_transactions(args).await
}

#[query]
#[candid_method(query)]
fn list_subaccounts(args: ListSubaccountsArgs) -> Vec<Subaccount> {
    ic_icrc1_index::list_subaccounts(args)
}

#[query]
#[candid_method(query)]
fn ledger_id() -> CanisterId {
    ic_icrc1_index::ledger_id()
}

#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(ic_icrc1_index::encode_metrics);
}

#[pre_upgrade]
fn pre_upgrade() {
    ic_icrc1_index::pre_upgrade()
}

#[post_upgrade]
fn post_upgrade() {
    ic_icrc1_index::post_upgrade()
}

#[query]
fn __get_candid_interface_tmp_hack() -> &'static str {
    include_str!(env!("INDEX_DID_PATH"))
}

#[test]
fn check_candid_interface() {
    use candid::utils::{service_compatible, CandidSource};
    use std::path::PathBuf;

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("index.did");

    service_compatible(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .expect("the index interface is not compatible with index.did");
}
