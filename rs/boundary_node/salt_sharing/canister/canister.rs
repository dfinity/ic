#![allow(unused_imports)]
#![allow(deprecated)]

use crate::helpers::{init_async, is_api_boundary_node_principal};
use crate::logs::export_logs_as_http_response;
use crate::metrics::{METRICS, export_metrics_as_http_response};
use crate::storage::SALT;
use ic_cdk::api::call::{accept_message, method_name};
use ic_cdk::{api::time, spawn};
use ic_cdk::{caller, trap};
use ic_cdk::{init, inspect_message, post_upgrade, query};
use ic_cdk_timers::set_timer;
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use salt_sharing_api::{GetSaltError, GetSaltResponse, InitArg, SaltResponse};
use std::time::Duration;

const REPLICATED_QUERY_METHOD: &str = "get_salt";

// Inspect the ingress messages in the pre-consensus phase and reject early, if the conditions are not met
#[inspect_message]
fn inspect_message() {
    let caller_id = caller();
    let called_method = method_name();

    if called_method == REPLICATED_QUERY_METHOD && is_api_boundary_node_principal(&caller_id) {
        accept_message();
    } else {
        trap("message_inspection_failed: method call is prohibited in the current context");
    }
}

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
    let caller_id = caller();
    if is_api_boundary_node_principal(&caller_id) {
        let stored_salt = SALT
            .with(|cell| cell.borrow().get(&()))
            .ok_or(GetSaltError::SaltNotInitialized)?;

        return Ok(SaltResponse {
            salt: stored_salt.salt,
            salt_id: stored_salt.salt_id,
        });
    }
    Err(GetSaltError::Unauthorized)
}

#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<100000,_>"
)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => export_metrics_as_http_response(),
        "/logs" => export_logs_as_http_response(request),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

// Manually add a dummy method so that the Candid interface can be properly generated:
//   `http_request: (HttpRequest) -> (HttpResponse) query;`
// Without this dummy method, it will be `http_request: (blob) -> (HttpResponse) query;`
// because of the `decode_with` option used above.
#[::candid::candid_method(query, rename = "http_request")]
#[allow(unused_variables)]
fn __candid_method_http_request(request: HttpRequest) -> HttpResponse {
    panic!("candid dummy function called")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_candid_interface_compatibility() {
        use candid_parser::utils::{CandidSource, service_equal};

        fn source_to_str(source: &CandidSource) -> String {
            match source {
                CandidSource::File(f) => {
                    std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
                }
                CandidSource::Text(t) => t.to_string(),
            }
        }

        fn check_service_equal(
            new_name: &str,
            new: CandidSource,
            old_name: &str,
            old: CandidSource,
        ) {
            let new_str = source_to_str(&new);
            let old_str = source_to_str(&old);
            match service_equal(new, old) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "{new_name} is not compatible with {old_name}!\n\n\
                {new_name}:\n\
                {new_str}\n\n\
                {old_name}:\n\
                {old_str}\n"
                    );
                    panic!("{e:?}");
                }
            }
        }

        candid::export_service!();

        let new_interface = __export_service();

        // check the public interface against the actual one
        let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("canister/salt_sharing_canister.did");

        check_service_equal(
            "actual rate-limit candid interface",
            candid_parser::utils::CandidSource::Text(&new_interface),
            "declared candid interface in interface.did file",
            candid_parser::utils::CandidSource::File(old_interface.as_path()),
        );
    }
}
