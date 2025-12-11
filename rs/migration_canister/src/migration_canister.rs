//! This module contains the public interface of the migration canister.
//!
//!

use std::fmt::Display;

use candid::{CandidType, Principal, Reserved};
use ic_cdk::{api::msg_caller, init, post_upgrade, println, query, update};
use serde::Deserialize;
use strum::Display;

use crate::{
    RequestState, ValidationError,
    canister_state::{
        ValidationGuard, caller_allowed,
        events::{find_last_event, history_len},
        limiter::num_successes_in_past_24_h,
        migrations_disabled, num_validations,
        requests::{find_request, insert_request, num_requests},
        set_allowlist,
    },
    rate_limited, start_timers,
    validation::validate_request,
};

#[derive(CandidType, Deserialize)]
pub(crate) struct MigrationCanisterInitArgs {
    allowlist: Option<Vec<Principal>>,
}

#[init]
fn init(args: MigrationCanisterInitArgs) {
    start_timers();
    set_allowlist(args.allowlist);
}

#[post_upgrade]
fn post_upgrade(args: MigrationCanisterInitArgs) {
    start_timers();
    set_allowlist(args.allowlist);
}

#[derive(Clone, CandidType, Deserialize)]
pub struct MigrateCanisterArgs {
    pub canister_id: Principal,
    pub replace_canister_id: Principal,
}

impl Display for MigrateCanisterArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MigrateCanisterArgs {{ canister_id: {}, replace_canister_id: {} }}",
            self.canister_id, self.replace_canister_id
        )
    }
}

#[update]
async fn migrate_canister(args: MigrateCanisterArgs) -> Result<(), Option<ValidationError>> {
    if migrations_disabled() {
        return Err(Some(ValidationError::MigrationsDisabled(Reserved)));
    }
    // Prevent too many interleaved validations.
    let Ok(_guard) = ValidationGuard::new() else {
        return Err(Some(ValidationError::RateLimited(Reserved)));
    };
    if rate_limited() {
        return Err(Some(ValidationError::RateLimited(Reserved)));
    }
    let caller = msg_caller();
    // For soft rollout purposes
    if !caller_allowed(&caller) {
        return Err(Some(ValidationError::MigrationsDisabled(Reserved)));
    }
    match validate_request(args.canister_id, args.replace_canister_id, caller).await {
        Err(e) => {
            println!("Failed to validate request {}: {}", args, e);
            return Err(Some(e));
        }
        Ok((request, _guards)) => {
            // Need to check the rate limit again
            if rate_limited() {
                return Err(Some(ValidationError::RateLimited(Reserved)));
            }
            println!("Accepted request {}", request);
            insert_request(RequestState::Accepted { request });
        }
    }
    Ok(())
}

#[derive(Clone, Display, CandidType, Deserialize)]
pub enum MigrationStatus {
    #[strum(to_string = "MigrationStatus::InProgress {{ status: {status} }}")]
    InProgress { status: String },
    #[strum(to_string = "MigrationStatus::Failed {{ reason: {reason}, time: {time} }}")]
    Failed { reason: String, time: u64 },
    #[strum(to_string = "MigrationStatus::Succeeded {{ time: {time} }}")]
    Succeeded { time: u64 },
}

#[query]
fn migration_status(args: MigrateCanisterArgs) -> Option<MigrationStatus> {
    if let Some(request_status) = find_request(args.canister_id, args.replace_canister_id) {
        let migration_status = MigrationStatus::InProgress {
            status: request_status.name().to_string(),
        };
        Some(migration_status)
    } else if let Some(event) = find_last_event(args.canister_id, args.replace_canister_id) {
        let migration_status = match event.event {
            crate::EventType::Succeeded { .. } => MigrationStatus::Succeeded { time: event.time },
            crate::EventType::Failed { reason, .. } => MigrationStatus::Failed {
                reason,
                time: event.time,
            },
        };
        Some(migration_status)
    } else {
        None
    }
}

fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "migration_canister_requests_in_flight",
        num_requests() as f64,
        "Number of currently ongoing migration requests.",
    )?;

    w.encode_gauge(
        "migration_canister_num_successes_in_past_24_h",
        num_successes_in_past_24_h() as f64,
        "Number of successful migrations in the past 24 hours.",
    )?;

    w.encode_gauge(
        "migration_canister_history_len",
        history_len() as f64,
        "Number of entries in the history.",
    )?;

    w.encode_gauge(
        "migration_canister_migrations_enabled",
        !migrations_disabled() as u32 as f64,
        "Whether canister migrations are currently enabled.",
    )?;

    w.encode_gauge(
        "migration_canister_validations_in_flight",
        num_validations() as f64,
        "Number of currently ongoing validations.",
    )?;

    let stable_size_pages = ic_cdk::stable::stable_size();
    let stable_size_bytes = stable_size_pages * ic_cdk::stable::WASM_PAGE_SIZE_IN_BYTES;

    w.encode_gauge(
        "migration_canister_stable_memory_size_bytes",
        stable_size_bytes as f64,
        "Size of the stable memory in bytes.",
    )?;

    Ok(())
}

#[unsafe(export_name = "canister_query http_request")]
fn http_request() {
    if ic_cdk::api::in_replicated_execution() {
        ic_cdk::api::trap("Metrics can only be fetched via non-replicated query calls.");
    }

    dfn_http_metrics::serve_metrics(encode_metrics);
}
