use ic_cdk_macros::{heartbeat, init, query, update};
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
async fn get_account_transactions(args: GetAccountTransactionsArgs) -> GetTransactionsResult {
    ic_icrc1_index::get_account_transactions(args).await
}

#[query]
fn list_subaccounts(args: ListSubaccountsArgs) -> Vec<Subaccount> {
    ic_icrc1_index::list_subaccounts(args)
}

#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(ic_icrc1_index::encode_metrics);
}
