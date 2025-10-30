//! This module contains the public interface of the migration canister.
//!
//!

use std::fmt::Display;

use candid::{CandidType, Principal};
use ic_cdk::{
    api::{instruction_counter, msg_caller},
    init, post_upgrade, println, query, update,
};
use serde::Deserialize;
use strum::Display;

use crate::{
    EventType, Request, RequestState, ValidationError,
    canister_state::{
        ValidationGuard, caller_allowed,
        events::{find_event, insert_random_event, num_events},
        migrations_disabled,
        requests::{find_request, insert_request},
        set_allowlist,
    },
    rate_limited, start_timers,
    validation::validate_request,
};

#[derive(CandidType, Deserialize)]
struct MigrationCanisterInitArgs {
    allowlist: Option<Vec<Principal>>,
}

#[init]
fn init(args: MigrationCanisterInitArgs) {
    start_timers();
    set_allowlist(args.allowlist);
    // some random events for performance measurements
    for i in 0..100000 {
        let event = if i % 2 == 0 {
            EventType::Succeeded {
                request: Request::low_bound(),
            }
        } else {
            EventType::Failed {
                request: Request::low_bound(),
                reason: "Yesn't".to_string(),
            }
        };
        insert_random_event(event, (i + 1) * 1_000_000_000 * 60 * 60 * 24 + 1);
    }
}

#[post_upgrade]
fn post_upgrade(args: MigrationCanisterInitArgs) {
    start_timers();
    set_allowlist(args.allowlist);
}

#[derive(Clone, CandidType, Deserialize)]
pub struct MigrateCanisterArgs {
    pub source: Principal,
    pub target: Principal,
}

impl Display for MigrateCanisterArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MigrateCanisterArgs {{ source: {}, target: {} }}",
            self.source, self.target
        )
    }
}

#[update]
async fn migrate_canister(args: MigrateCanisterArgs) -> Result<(), ValidationError> {
    if migrations_disabled() {
        return Err(ValidationError::MigrationsDisabled);
    }
    // Prevent too many interleaved validations.
    let Ok(_guard) = ValidationGuard::new() else {
        return Err(ValidationError::RateLimited);
    };
    println!("num events: {}", num_events());
    let start = instruction_counter();
    if rate_limited() {
        println!(
            "### instructions for checking rate limit: {}",
            instruction_counter() - start
        );
        return Err(ValidationError::RateLimited);
    }
    println!(
        "### instructions for checking rate limit: {}",
        instruction_counter() - start
    );
    let caller = msg_caller();
    // For soft rollout purposes
    if !caller_allowed(&caller) {
        return Err(ValidationError::MigrationsDisabled);
    }
    let start = instruction_counter();
    match validate_request(args.source, args.target, caller).await {
        Err(e) => {
            println!(
                "### instructions for failed validation: {}",
                instruction_counter() - start
            );
            println!("Failed to validate request {}: {}", args, e);
            return Err(e);
        }
        Ok(request) => {
            // Need to check the rate limit again
            if rate_limited() {
                return Err(ValidationError::RateLimited);
            }
            println!(
                "### instructions for successful validation: {}",
                instruction_counter() - start
            );
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
/// The same (source, target) pair might be present in the `HISTORY`, and valid to process again, so
/// we return a vector.
fn migration_status(args: MigrateCanisterArgs) -> Vec<MigrationStatus> {
    let mut active: Vec<MigrationStatus> = find_request(args.source, args.target)
        .into_iter()
        .map(|r| MigrationStatus::InProgress {
            status: r.name().to_string(),
        })
        .collect();
    let events: Vec<MigrationStatus> = find_event(args.source, args.target)
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
struct ListEventsArgs {
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
