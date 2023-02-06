use candid::candid_method;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_tvl_canister::metrics::encode_metrics;
use ic_tvl_canister::types::{
    InitArgs, TimeseriesResult, TvlResult, TvlResultError, TvlTimeseriesResult,
};

fn main() {}

// NB: init is only called at first installation, not while upgrading canister.
#[init]
fn init(args: InitArgs) {
    ic_tvl_canister::init(args);
}

#[post_upgrade]
async fn post_upgrade(upgrade_args: Option<InitArgs>) {
    ic_tvl_canister::post_upgrade(upgrade_args).await
}

#[update]
#[candid_method(update)]
async fn get_tvl() -> Result<TvlResult, TvlResultError> {
    ic_tvl_canister::get_tvl().await
}

#[update]
#[candid_method(update)]
async fn get_tvl_timeseries() -> TvlTimeseriesResult {
    ic_tvl_canister::get_tvl_timeseries().await
}

#[update]
#[candid_method(update)]
async fn get_xr_timeseries() -> TimeseriesResult {
    ic_tvl_canister::get_xr_timeseries().await
}

#[update]
#[candid_method(update)]
async fn get_locked_e8s_timeseries() -> TimeseriesResult {
    ic_tvl_canister::get_locked_e8s_timeseries().await
}

#[query]
#[candid_method(query)]
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
