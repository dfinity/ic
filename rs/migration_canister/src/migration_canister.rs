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
        events::find_event,
        migrations_disabled,
        requests::{find_request, insert_request},
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
        Ok(request) => {
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
/// The same (canister_id, replace_canister_id) pair might be present in the `HISTORY`, and valid to process again, so
/// we return a vector.
fn migration_status(args: MigrateCanisterArgs) -> Vec<MigrationStatus> {
    let mut active: Vec<MigrationStatus> = find_request(args.canister_id, args.replace_canister_id)
        .into_iter()
        .map(|r| MigrationStatus::InProgress {
            status: r.name().to_string(),
        })
        .collect();
    let events: Vec<MigrationStatus> = find_event(args.canister_id, args.replace_canister_id)
        .into_iter()
        .map(|event| match event.event {
            crate::EventType::Succeeded { .. } => MigrationStatus::Succeeded { time: event.time },
            crate::EventType::Failed { reason, .. } => MigrationStatus::Failed {
                reason,
                time: event.time,
            },
        })
        .collect();
    active.extend(events);
    active
}

#[derive(Clone, CandidType, Deserialize)]
pub(crate) struct ListEventsArgs {
    page_index: u64,
    page_size: u64,
}

#[query]
fn list_events(args: ListEventsArgs) -> Vec<MigrationStatus> {
    crate::canister_state::events::list_events(args.page_index, args.page_size)
        .into_iter()
        .map(|e| match e.event {
            crate::EventType::Succeeded { .. } => MigrationStatus::Succeeded { time: e.time },
            crate::EventType::Failed { reason, .. } => MigrationStatus::Failed {
                reason,
                time: e.time,
            },
        })
        .collect()
}
