use std::time::Duration;

use crate::logs::{self, Log, LogEntry, Priority, P0};
use crate::storage::{StorableSalt, SALT, SALT_SIZE};
use crate::time::delay_till_next_month;
use candid::Principal;
use ic_canister_log::{export as export_logs, log};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::{api::time, spawn};
use ic_cdk_macros::{init, post_upgrade, query};
use ic_cdk_timers::set_timer;
use salt_api::{GetSaltError, GetSaltResponse, InitArg, SaltGenerationStrategy, SaltResponse};
use std::str::FromStr;

// Runs when canister is first installed
#[init]
fn init(init_arg: InitArg) {
    set_timer(Duration::ZERO, || {
        spawn(async { init_async(init_arg).await });
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
    get_salt_response()
}

#[query(decoding_quota = 10000)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/logs" => {
            use serde_json;

            let max_skip_timestamp = match request.raw_query_param("time") {
                Some(arg) => match u64::from_str(arg) {
                    Ok(value) => value,
                    Err(_) => {
                        return HttpResponseBuilder::bad_request()
                            .with_body_and_content_length("failed to parse the 'time' parameter")
                            .build()
                    }
                },
                None => 0,
            };

            let mut entries: Log = Default::default();

            for entry in export_logs(&logs::P0) {
                entries.entries.push(LogEntry {
                    timestamp: entry.timestamp,
                    counter: entry.counter,
                    priority: Priority::P0,
                    file: entry.file.to_string(),
                    line: entry.line,
                    message: entry.message,
                });
            }

            for entry in export_logs(&logs::P1) {
                entries.entries.push(LogEntry {
                    timestamp: entry.timestamp,
                    counter: entry.counter,
                    priority: Priority::P1,
                    file: entry.file.to_string(),
                    line: entry.line,
                    message: entry.message,
                });
            }

            entries
                .entries
                .retain(|entry| entry.timestamp >= max_skip_timestamp);

            HttpResponseBuilder::ok()
                .header("Content-Type", "application/json; charset=utf-8")
                .with_body_and_content_length(serde_json::to_string(&entries).unwrap_or_default())
                .build()
        }
        _ => HttpResponseBuilder::not_found().build(),
    }
}

async fn init_async(init_arg: InitArg) {
    if !is_salt_init() || init_arg.regenerate_now {
        if let Err(err) = try_regenerate_salt().await {
            log!(P0, "[init_regenerate_salt_failed]: {err}");
        }
    }
    // Start salt generation schedule based on the argument.
    match init_arg.salt_generation_strategy {
        SaltGenerationStrategy::StartOfMonth => schedule_monthly_salt_generation(),
    }
}

// Sets an execution timer (delayed future task) and returns immediately.
fn schedule_monthly_salt_generation() {
    let delay = delay_till_next_month(time());
    set_timer(delay, || {
        spawn(async {
            if let Err(err) = try_regenerate_salt().await {
                log!(P0, "[scheduled_regenerate_salt_failed]: {err}");
            }
            // Function is called recursively to schedule next execution
            schedule_monthly_salt_generation();
        });
    });
}

fn is_salt_init() -> bool {
    SALT.with(|cell| cell.borrow().get(&())).is_some()
}

fn get_salt_response() -> Result<SaltResponse, GetSaltError> {
    let stored_salt = SALT
        .with(|cell| cell.borrow().get(&()))
        .ok_or(GetSaltError::SaltNotInitialized)?;

    Ok(SaltResponse {
        salt: stored_salt.salt,
        salt_id: stored_salt.salt_id,
    })
}

// Regenerate salt and store it in the stable memory
// Can only fail, if the calls to management canister fail.
async fn try_regenerate_salt() -> Result<(), String> {
    // Closure for getting random bytes from the IC.
    let rnd_call = |attempt: u32| async move {
        ic_cdk::call(Principal::management_canister(), "raw_rand", ())
            .await
            .map_err(|err| {
                format!(
                    "Call {attempt} to raw_rand failed: code={:?}, err={}",
                    err.0, err.1
                )
            })
    };

    let (rnd_bytes_1,): ([u8; 32],) = rnd_call(1).await?;
    let (rnd_bytes_2,): ([u8; 32],) = rnd_call(2).await?;

    // Concatenate arrays to form an array of 64 random bytes.
    let mut salt = [rnd_bytes_1, rnd_bytes_2].concat();
    salt.truncate(SALT_SIZE);

    let stored_salt = StorableSalt {
        salt,
        salt_id: time(),
    };

    SALT.with(|cell| {
        cell.borrow_mut().insert((), stored_salt);
    });

    Ok(())
}
