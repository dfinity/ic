use candid::candid_method;
use ic_cdk_macros::{init, update};
use ic_icrc1_benchmark_generator::{InitArgs, RunScenarioResult, Scenario};
use serde_bytes::ByteBuf;

fn main() {}

// NB: init is only called at first installation, not while upgrading canister.
#[init]
fn init(args: InitArgs) {
    ic_icrc1_benchmark_generator::init(args);
}

#[update]
#[candid_method(update)]
async fn run_scenario(scenario: Scenario) -> RunScenarioResult {
    ic_icrc1_benchmark_generator::run_scenario(scenario).await
}

#[update]
#[candid_method(update)]
async fn upload_index_wasm(blob: ByteBuf) -> bool {
    ic_icrc1_benchmark_generator::upload_index_wasm(&blob.into_vec()).await
}

#[update]
#[candid_method(update)]
async fn upload_worker_wasm(blob: ByteBuf) -> bool {
    ic_icrc1_benchmark_generator::upload_worker_wasm(&blob.into_vec()).await
}

#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(ic_icrc1_benchmark_generator::encode_metrics);
}
