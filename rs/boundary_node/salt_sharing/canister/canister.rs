use crate::helpers::init_async;
use crate::logs::export_logs_as_http_response;
use crate::metrics::{export_metrics_as_http_response, METRICS};
use crate::storage::SALT;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::{api::time, spawn};
use ic_cdk_macros::{init, post_upgrade, query};
use ic_cdk_timers::set_timer;
use salt_api::{GetSaltError, GetSaltResponse, InitArg, SaltResponse};
use std::time::Duration;

// Runs when canister is first installed
#[init]
fn init(init_arg: InitArg) {
    set_timer(Duration::ZERO, || {
        spawn(async { init_async(init_arg).await });
    });
    // Update metric.
    let current_time = time() as i64;
    METRICS.with(|cell| {
        cell.borrow_mut()
            .last_canister_change_time
            .set(current_time);
    });
}

// Runs on every canister upgrade
#[post_upgrade]
fn post_upgrade(init_arg: InitArg) {
    // Run the same initialization logic
    init(init_arg);
}

#[query]
fn get_salt() -> GetSaltResponse {
    let stored_salt = SALT
        .with(|cell| cell.borrow().get(&()))
        .ok_or(GetSaltError::SaltNotInitialized)?;

    Ok(SaltResponse {
        salt: stored_salt.salt,
        salt_id: stored_salt.salt_id,
    })
}

#[query(decoding_quota = 10000)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => export_metrics_as_http_response(),
        "/logs" => export_logs_as_http_response(request),
        _ => HttpResponseBuilder::not_found().build(),
    }
}
