use candid::candid_method;
use ic_base_types::CanisterId;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_icrc1_index::{
    encode_metrics, GetAccountTransactionsArgs, GetTransactionsResult, InitArgs,
    ListSubaccountsArgs,
};
use icrc_ledger_types::icrc1::account::Subaccount;
use std::time::Duration;

fn main() {}

#[init]
#[candid_method(init)]
fn init(args: InitArgs) {
    ic_icrc1_index::init(args);
    ic_cdk_timers::set_timer(Duration::from_secs(1), || {
        ic_cdk::spawn(async {
            let _ = ic_icrc1_index::build_index().await;
        })
    });
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

#[query(hidden = true, decoding_quota = 10000)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err))
                    .build()
            }
        }
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

#[pre_upgrade]
fn pre_upgrade() {
    ic_icrc1_index::pre_upgrade()
}

#[post_upgrade]
fn post_upgrade() {
    ic_icrc1_index::post_upgrade();
    ic_cdk_timers::set_timer(Duration::from_secs(1), || {
        ic_cdk::spawn(async {
            let _ = ic_icrc1_index::build_index().await;
        })
    });
}

#[query(hidden = true)]
fn __get_candid_interface_tmp_hack() -> &'static str {
    include_str!(env!("INDEX_DID_PATH"))
}

#[test]
fn check_candid_interface() {
    use candid_parser::utils::{service_equal, CandidSource};
    use std::path::PathBuf;

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("index.did");

    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .expect("the index interface is not compatible with index.did");
}
